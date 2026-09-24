//! `forensic_rs::traits::format::FormatFactory` for SQLite databases.
//!
//! Lets a triage pipeline discover and mount any `.db`/`.sqlite` file (a
//! browser `History`, `Cookies`, `places.sqlite`, `ActivitiesCache.db`, ...)
//! as a [`forensic_rs::traits::db::ForensicDb`] without the caller needing
//! to know in advance which artifact it is -- the higher-level
//! `ArtifactParserFactory`s in `crate::artifacts` are what tell "a SQLite
//! database" apart from "a Chromium history database" (see the doc comment
//! on `forensic_rs::traits::forensic::Requirement`).

use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use forensic_rs::core::locator::LocatorSegment;
use forensic_rs::err::ForensicResult;
use forensic_rs::traits::format::{FileSet, FileSetRole, FormatFactory, MountContext, MountKind, Mounted, ProbeScore};
use forensic_rs::traits::vfs::VirtualFile;

use crate::sqlite::db::SqliteDb;
use crate::sqlite::format::is_sqlite_magic;

/// Mounts SQLite databases as a `ForensicDb`.
pub struct SqliteFormatFactory;

impl FormatFactory for SqliteFormatFactory {
    fn name(&self) -> &'static str {
        "sqlite"
    }

    fn yields(&self) -> MountKind {
        MountKind::Database
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        let start = file.stream_position()?;
        let result = probe_inner(file);
        file.seek(SeekFrom::Start(start))?;
        result
    }

    fn mount(&self, file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let size = file.metadata()?.size as usize;
        let limit = ctx.limits().materialize_in_memory_limit;
        let db = if size <= limit {
            // Small enough to slurp: regains zero-copy page reads via
            // `SliceReader`, which a `VirtualFileReader` cannot offer (it
            // always returns `Cow::Owned`). Every browser-history-scale
            // artifact this crate targets falls in this branch.
            let mut file = file;
            let mut buf = Vec::with_capacity(size);
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut buf)
                .map_err(|e| forensic_rs::err::ForensicError::io_error_with_source(e, "SQLite mount: read_to_end"))?;
            SqliteDb::from_bytes(buf)
        } else {
            // Large file (e.g. a multi-GiB browser profile database):
            // stream pages on demand instead, respecting the resolver's
            // in-memory budget. `from_virtual_file` wraps the source in a
            // bounded page cache (see `reader::CachedReader`), so repeated
            // interior-page reads across `Table::iter_rows()` calls don't
            // each re-read from the VFS.
            SqliteDb::from_virtual_file(file)
        };
        let db = db.map_err(|e| e.with_path(ctx.locator().to_string()))?;
        Ok(Mounted::Database(Arc::new(db)))
    }

    fn extensions(&self) -> &[&'static str] {
        &["db", "sqlite", "sqlite3"]
    }
}

/// Groups a SQLite database with the write-ahead-log (`-wal`), shared-memory
/// (`-shm`), and rollback-journal (`-journal`) companions beside it, purely
/// by filename shape -- mirrors `frnsc-esedb::ese::format::EseLogSetFactory`
/// (see its own doc comment for why this is deliberately lighter than a
/// signature-verified grouping: it reports filename-shape membership only,
/// addresses rather than open handles, per
/// [`forensic_rs::traits::format::FileSet`]'s contract that a FileSet mount
/// is terminal).
///
/// Reporting only: this factory does **not** replay a `-wal`/`-journal`
/// into the primary database, so a caller reading only
/// [`SqliteFormatFactory`]'s `Mounted::Database` silently misses whatever
/// transactions live in an unreplayed WAL -- which of these companions
/// exist (and which are missing) is itself evidence this FileSet surfaces,
/// tracked as planned work (WAL awareness) in this crate's `ROADMAP.md`.
pub struct SqliteWalSetFactory;

impl FormatFactory for SqliteWalSetFactory {
    fn name(&self) -> &'static str {
        "sqlite_wal_set"
    }

    fn yields(&self) -> MountKind {
        MountKind::FileSet
    }

    fn probe(&self, file: &mut dyn VirtualFile, _ctx: &MountContext<'_>) -> ForensicResult<ProbeScore> {
        // The candidate for grouping is the database itself -- same sniff as
        // `SqliteFormatFactory`, so a directory is only ever offered as a
        // FileSet when it actually contains a SQLite database to group
        // around.
        let start = file.stream_position()?;
        let result = probe_inner(file);
        file.seek(SeekFrom::Start(start))?;
        result
    }

    fn mount(&self, _file: Box<dyn VirtualFile>, ctx: &MountContext<'_>) -> ForensicResult<Mounted> {
        let mut set = FileSet::new(ctx.locator().clone());
        // SQLite's sidecar naming appends a suffix directly to the primary
        // file's own name (`History-wal`), not to its extension
        // (`History.wal`) -- unlike ESE's `.log`/`.chk` -- so matching needs
        // the primary's exact file name, not just a suffix check.
        let Some(LocatorSegment::Path(primary_path)) = ctx.locator().last() else {
            return Ok(Mounted::FileSet(set));
        };
        let Some(primary_name) = primary_path.as_path().file_name() else {
            return Ok(Mounted::FileSet(set));
        };

        let companions: [(&str, FileSetRole); 3] = [
            ("-wal", FileSetRole::Log),
            ("-journal", FileSetRole::Log),
            ("-shm", FileSetRole::Sidecar),
        ];
        // Determinism is the caller's job, not the filesystem's.
        let mut names: Vec<String> =
            ctx.siblings()?.into_iter().filter_map(|e| e.file_name().map(str::to_string)).collect();
        names.sort();
        for name in names {
            let Some((_, role)) = companions.iter().find(|(suffix, _)| name == format!("{primary_name}{suffix}"))
            else {
                continue;
            };
            if let Some(locator) = ctx.sibling_locator(&name) {
                set.push_mut(role.clone(), locator);
            }
        }
        Ok(Mounted::FileSet(set))
    }
}

fn probe_inner(file: &mut dyn VirtualFile) -> ForensicResult<ProbeScore> {
    file.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; 16];
    if file.read_exact(&mut head).is_err() {
        return Ok(ProbeScore::No);
    }
    if !is_sqlite_magic(&head) {
        return Ok(ProbeScore::No);
    }
    // Magic matched; also validate the rest of the header (page size,
    // encoding) to distinguish a genuine SQLite file from something that
    // merely starts with the same 16 bytes.
    file.seek(SeekFrom::Start(0))?;
    let mut header_region = [0u8; crate::sqlite::format::HEADER_SIZE];
    if file.read_exact(&mut header_region).is_ok() && crate::sqlite::format::Header::from_bytes(&header_region).is_ok()
    {
        return Ok(ProbeScore::Exact);
    }
    // Magic matched but the header didn't fully validate -- still very
    // likely SQLite (a truncated or partially-overwritten database should
    // still be offered for mounting rather than rejected outright).
    Ok(ProbeScore::Strong)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct BytesFile(Cursor<Vec<u8>>);
    impl Read for BytesFile {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl Seek for BytesFile {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(pos)
        }
    }
    impl VirtualFile for BytesFile {
        fn metadata(&self) -> ForensicResult<forensic_rs::traits::vfs::VMetadata> {
            Ok(forensic_rs::traits::vfs::VMetadata {
                file_type: forensic_rs::traits::vfs::VFileType::File,
                size: self.0.get_ref().len() as u64,
                allocated_size: None,
                times: forensic_rs::traits::vfs::MacbTimes::default(),
                id: None,
                attributes: forensic_rs::traits::vfs::FileAttributes::empty(),
            })
        }
    }

    #[test]
    fn probe_rejects_non_sqlite_bytes() {
        let mut file = BytesFile(Cursor::new(vec![0u8; 128]));
        assert_eq!(probe_inner(&mut file).unwrap(), ProbeScore::No);
    }

    #[test]
    fn probe_scores_exact_on_a_well_formed_header() {
        let mut buf = vec![0u8; crate::sqlite::format::HEADER_SIZE];
        buf[0..16].copy_from_slice(crate::sqlite::format::MAGIC);
        buf[16..18].copy_from_slice(&4096u16.to_be_bytes());
        buf[56..60].copy_from_slice(&1u32.to_be_bytes());
        let mut file = BytesFile(Cursor::new(buf));
        let start = file.stream_position().unwrap();
        assert_eq!(probe_inner(&mut file).unwrap(), ProbeScore::Exact);
        assert_ne!(start, file.stream_position().unwrap());
    }

    #[test]
    fn extensions_are_advisory_hints() {
        let factory = SqliteFormatFactory;
        assert_eq!(factory.yields(), MountKind::Database);
        assert!(factory.extensions().contains(&"sqlite"));
    }

    #[test]
    fn probe_then_mount_round_trip_lists_tables() {
        use std::sync::Arc;

        let Ok(bytes) = std::fs::read("./artifacts/chrome_history_sample/History") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let factory = SqliteFormatFactory;
        let fs: Arc<dyn forensic_rs::traits::vfs::FileSystem> =
            Arc::new(forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new());
        let locator = forensic_rs::prelude::EvidenceLocator::root();
        let limits = forensic_rs::prelude::Limits::default();
        let spill = forensic_rs::prelude::MemorySpillStore::default();
        let cancellation = forensic_rs::prelude::CancellationToken::new();
        let ctx = MountContext::new(&fs, &locator, &limits, 0, &spill, None, &cancellation);

        let mut file: Box<dyn VirtualFile> = Box::new(BytesFile(Cursor::new(bytes)));
        let score = factory.probe(file.as_mut(), &ctx).unwrap();
        assert_eq!(ProbeScore::Exact, score);

        let mounted = factory.mount(file, &ctx).unwrap();
        let Mounted::Database(db) = mounted else {
            panic!("expected Mounted::Database");
        };
        let mut tables = db.list_tables().unwrap();
        tables.sort();
        assert_eq!(tables, vec!["urls", "visits"]);
    }

    #[test]
    fn wal_set_factory_groups_wal_and_journal_siblings_by_exact_name() {
        use forensic_rs::prelude::{EvidenceLocator, FPathBuf};

        let vfs = forensic_rs::prelude::testing::InMemoryVirtualFileSystem::new()
            .with_file("Default/History", vec![0u8; 16])
            .with_file("Default/History-wal", vec![1u8; 4])
            .with_file("Default/History-journal", vec![2u8; 4])
            .with_file("Default/History-shm", vec![3u8; 4])
            // Decoys: neither must be picked up.
            .with_file("Default/History.bak", vec![4u8; 4]) // wrong suffix shape
            .with_file("Default/OtherHistory-wal", vec![5u8; 4]); // different primary name
        let fs: Arc<dyn forensic_rs::traits::vfs::FileSystem> = Arc::new(vfs);

        let locator = EvidenceLocator::root().push(LocatorSegment::Path(FPathBuf::from("Default/History")));
        let limits = forensic_rs::prelude::Limits::default();
        let spill = forensic_rs::prelude::MemorySpillStore::default();
        let cancellation = forensic_rs::prelude::CancellationToken::new();
        let ctx = MountContext::new(&fs, &locator, &limits, 0, &spill, None, &cancellation);

        let factory = SqliteWalSetFactory;
        assert_eq!(factory.yields(), MountKind::FileSet);

        let dummy_file: Box<dyn VirtualFile> = Box::new(BytesFile(Cursor::new(Vec::new())));
        let Mounted::FileSet(set) = factory.mount(dummy_file, &ctx).unwrap() else {
            panic!("expected Mounted::FileSet");
        };

        assert_eq!(set.by_role(&FileSetRole::Log).count(), 2); // -wal, -journal
        assert_eq!(set.by_role(&FileSetRole::Sidecar).count(), 1); // -shm
        assert_eq!(set.len(), 4); // primary + wal + journal + shm; decoys excluded
    }
}
