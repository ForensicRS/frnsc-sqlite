//! Abstract over how raw page bytes are read from a SQLite database source.
//!
//! Mirrors `frnsc-esedb::ese::reader`: three implementations, all
//! `Send + Sync` because `SqliteDb` implements
//! `forensic_rs::traits::db::ForensicDb`, which the framework caches and
//! shares across parallel pipeline workers.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs::File;
use std::sync::{Arc, Mutex};

use forensic_rs::ensure_buffer_size;
use forensic_rs::err::ForensicResult;

pub trait PageReader: Send + Sync {
    /// Return `size` bytes starting at byte `offset`.
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>>;

    /// Total byte length of the database source.
    fn total_size(&self) -> usize;
}

// ─── SliceReader ─────────────────────────────────────────────────────────────

pub struct SliceReader(pub(crate) Vec<u8>);

impl SliceReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self(data)
    }
}

impl PageReader for SliceReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        ensure_buffer_size!(self.0, offset, size, "SQLite page");
        Ok(Cow::Borrowed(&self.0[offset..offset + size]))
    }

    fn total_size(&self) -> usize {
        self.0.len()
    }
}

// ─── FileReader ───────────────────────────────────────────────────────────────

/// Seek-free reader backed by an open file, using positioned reads — only
/// the requested page is loaded per call.
pub struct FileReader {
    file: File,
    size: usize,
}

impl FileReader {
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(path.as_ref())?;
        let size = file.metadata()?.len() as usize;
        Ok(Self { file, size })
    }
}

impl PageReader for FileReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        check_range(offset, size, self.size)?;
        let mut buf = vec![0u8; size];
        read_exact_at(&self.file, offset as u64, &mut buf)
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "SQLite page read"))?;
        Ok(Cow::Owned(buf))
    }

    fn total_size(&self) -> usize {
        self.size
    }
}

fn check_range(offset: usize, size: usize, total: usize) -> ForensicResult<()> {
    let required = offset.saturating_add(size);
    if required > total {
        return Err(forensic_rs::err::ForensicError::buffer_too_small(
            required,
            total,
            "SQLite page",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !buf.is_empty() {
        let n = file.read_at(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading SQLite page",
            ));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn read_exact_at(file: &File, mut offset: u64, mut buf: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_read(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "unexpected EOF while reading SQLite page",
            ));
        }
        buf = &mut buf[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn read_exact_at(file: &File, offset: u64, buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    static FALLBACK_LOCK: Mutex<()> = Mutex::new(());
    let _guard = FALLBACK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(buf)
}

// ─── VirtualFileReader ───────────────────────────────────────────────────────

/// Page reader over a `forensic_rs::traits::vfs::VirtualFile`. `VirtualFile`
/// is `Send` but not `Sync`, and its `Read`/`Seek` methods need `&mut self`,
/// so a `Mutex` is unavoidable here.
pub struct VirtualFileReader {
    inner: Mutex<Box<dyn forensic_rs::traits::vfs::VirtualFile>>,
    size: usize,
}

impl VirtualFileReader {
    pub fn new(file: Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Self> {
        let size = file.metadata()?.size as usize;
        Ok(Self {
            inner: Mutex::new(file),
            size,
        })
    }
}

impl PageReader for VirtualFileReader {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        check_range(offset, size, self.size)?;
        use std::io::{Read, Seek, SeekFrom};
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut buf = vec![0u8; size];
        guard
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "SQLite VFS seek"))?;
        guard
            .read_exact(&mut buf)
            .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "SQLite VFS read"))?;
        Ok(Cow::Owned(buf))
    }

    fn total_size(&self) -> usize {
        self.size
    }
}

// ─── CachedReader ───────────────────────────────────────────────────────────

/// Wraps another [`PageReader`] with a small, bounded page cache, keyed by
/// `(offset, size)` (not `offset` alone -- the same offset is read at more
/// than one size over a `SqliteDb`'s lifetime, e.g. the initial 100-byte
/// header read vs. a full-page-size read of page 1's b-tree header, and
/// serving the wrong-length bytes for a cache hit would silently corrupt
/// the read rather than error).
///
/// Exists because interior b-tree pages get re-read from the underlying
/// source on every `Table::iter_rows()` call (each call re-walks the tree
/// from the root -- see `db.rs`'s own doc comment on why rows are decoded
/// once per `next_row()` rather than lazily, a related but distinct
/// tradeoff), which is one syscall/VFS round trip per interior page for
/// `FileReader`/`VirtualFileReader`. `SliceReader` is not wrapped in
/// practice -- its `read_page` is already a zero-copy slice into memory
/// already resident, so caching it would only add a lock for no benefit.
///
/// Deliberately simple rather than a true LRU: once `capacity` distinct
/// `(offset, size)` keys are cached, further distinct reads are served
/// uncached (not evicted-and-replaced). SQLite catalogs and interior
/// b-tree levels are small and read repeatedly across the *same* small set
/// of pages, so a cache that just remembers "the first `capacity` pages
/// seen" already captures the actual hot set in practice, without the
/// bookkeeping of real LRU eviction.
/// `(offset, size) -> cached page bytes`, guarded by a `Mutex` since
/// [`PageReader::read_page`] takes `&self`.
type PageCache = Mutex<HashMap<(usize, usize), Arc<[u8]>>>;

pub struct CachedReader<R> {
    inner: R,
    cache: PageCache,
    capacity: usize,
}

/// Default cache capacity: enough distinct `(offset, size)` reads to cover
/// a `sqlite_schema` catalog plus several levels of interior b-tree pages
/// for a browser-history-scale database, at a worst-case bound of
/// `capacity * 65536` bytes (SQLite's maximum page size) -- well under
/// `forensic_rs::core::limits::Limits::default().materialize_in_memory_limit`
/// (32 MiB) for realistic page sizes (4-64 KiB).
pub const DEFAULT_PAGE_CACHE_CAPACITY: usize = 256;

impl<R: PageReader> CachedReader<R> {
    pub fn new(inner: R, capacity: usize) -> Self {
        Self {
            inner,
            cache: Mutex::new(HashMap::new()),
            capacity,
        }
    }
}

impl<R: PageReader> PageReader for CachedReader<R> {
    fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
        let key = (offset, size);
        if let Some(bytes) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            return Ok(Cow::Owned(bytes.to_vec()));
        }
        let page = self.inner.read_page(offset, size)?;
        let bytes: Arc<[u8]> = Arc::from(page.as_ref());
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() < self.capacity {
            cache.insert(key, bytes.clone());
        }
        Ok(Cow::Owned(bytes.to_vec()))
    }

    fn total_size(&self) -> usize {
        self.inner.total_size()
    }
}

#[cfg(test)]
mod tst {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn readers_are_send_sync() {
        assert_send_sync::<SliceReader>();
        assert_send_sync::<FileReader>();
        assert_send_sync::<VirtualFileReader>();
    }

    #[test]
    fn slice_reader_rejects_overflowing_range() {
        let r = SliceReader::new(vec![1, 2, 3, 4]);
        assert!(r.read_page(usize::MAX - 1, 4).is_err());
        assert!(r.read_page(2, 4).is_err());
        assert_eq!(&*r.read_page(1, 2).unwrap(), &[2, 3]);
    }

    /// Wraps a [`PageReader`] and counts every call that reaches it, so a
    /// test can assert a [`CachedReader`] actually avoids re-reading the
    /// wrapped source.
    struct CountingReader<R> {
        inner: R,
        reads: std::sync::atomic::AtomicUsize,
    }

    impl<R: PageReader> PageReader for CountingReader<R> {
        fn read_page<'a>(&'a self, offset: usize, size: usize) -> ForensicResult<Cow<'a, [u8]>> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.read_page(offset, size)
        }

        fn total_size(&self) -> usize {
            self.inner.total_size()
        }
    }

    #[test]
    fn cached_reader_serves_a_repeated_offset_and_size_without_re_reading() {
        let counting = CountingReader {
            inner: SliceReader::new(vec![7u8; 64]),
            reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let cached = CachedReader::new(counting, 8);

        assert_eq!(&*cached.read_page(0, 16).unwrap(), &[7u8; 16][..]);
        assert_eq!(&*cached.read_page(0, 16).unwrap(), &[7u8; 16][..]);
        assert_eq!(&*cached.read_page(0, 16).unwrap(), &[7u8; 16][..]);
        assert_eq!(cached.inner.reads.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn cached_reader_does_not_confuse_the_same_offset_at_a_different_size() {
        let counting = CountingReader {
            inner: SliceReader::new(vec![7u8; 64]),
            reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let cached = CachedReader::new(counting, 8);

        assert_eq!(cached.read_page(0, 8).unwrap().len(), 8);
        assert_eq!(cached.read_page(0, 16).unwrap().len(), 16);
        assert_eq!(cached.inner.reads.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn cached_reader_stops_caching_past_capacity_but_stays_correct() {
        let counting = CountingReader {
            inner: SliceReader::new(vec![7u8; 64]),
            reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let cached = CachedReader::new(counting, 1);

        assert_eq!(cached.read_page(0, 8).unwrap().len(), 8);
        assert_eq!(cached.read_page(8, 8).unwrap().len(), 8); // evicts nothing, but exceeds capacity: not cached
        assert_eq!(cached.read_page(8, 8).unwrap().len(), 8); // re-read, still correct
        assert_eq!(cached.read_page(0, 8).unwrap().len(), 8); // still cached from the first call
        assert_eq!(cached.inner.reads.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
}
