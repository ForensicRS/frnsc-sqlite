//! High-level entry point for reading SQLite databases.
//!
//! # Example
//!
//! ```rust,no_run
//! use frnsc_sqlite::sqlite::db::SqliteDb;
//!
//! let db = SqliteDb::open("path/to/History").unwrap();
//! for name in db.table_names() {
//!     println!("{name}");
//! }
//! if let Ok(table) = db.table("urls") {
//!     let mut rows = table.iter_rows().unwrap();
//!     while rows.next_row().unwrap() {
//!         println!("{:?}", rows.current_row());
//!     }
//! }
//! ```

use std::path::Path;

use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::traits::db::{ForensicColumnDef, ForensicValue};

use crate::sqlite::btree::{leaf_pages, read_leaf_cells, LeafCell};
use crate::sqlite::format::{Header, HEADER_SIZE};
use crate::sqlite::reader::{CachedReader, FileReader, PageReader, SliceReader, VirtualFileReader, DEFAULT_PAGE_CACHE_CAPACITY};
use crate::sqlite::record::{decode_record, decode_text, RecordValue};
use crate::sqlite::schema::{parse_create_table, ColumnDef};

/// `sqlite_schema` (formerly `sqlite_master`) is always the b-tree rooted
/// at page 1, with this fixed, hardcoded column layout -- it is not itself
/// described by a row of its own `sql` text.
const SCHEMA_ROOT_PAGE: u32 = 1;

pub struct TableDef {
    pub name: String,
    root_page: u32,
    /// Internal column metadata (affinity + rowid-alias flag), used to
    /// decode rows.
    columns: Vec<ColumnDef>,
    /// The same columns, pre-converted to `forensic_rs`'s type -- cached so
    /// `ForensicTable::columns()` can return a slice without allocating on
    /// every call (mirrors `frnsc-esedb::ese::db::TableDef`).
    forensic_columns: Vec<ForensicColumnDef>,
}

fn to_forensic_columns(columns: &[ColumnDef]) -> Vec<ForensicColumnDef> {
    columns
        .iter()
        .map(|c| ForensicColumnDef {
            name: c.name.clone(),
            col_type: c.col_type,
            nullable: c.nullable,
        })
        .collect()
}

/// `sql` ends (ignoring trailing whitespace/semicolons) in `WITHOUT ROWID`.
/// Such a table's b-tree is an *index* b-tree (page types 2/10), which
/// [`crate::sqlite::btree`] deliberately doesn't walk (see its own module
/// doc comment) -- detected here so the table is skipped with a clear,
/// logged reason instead of failing opaquely the first time a row is read.
fn is_without_rowid(sql: &str) -> bool {
    sql.trim_end_matches([';', ' ', '\t', '\n', '\r'])
        .to_ascii_uppercase()
        .ends_with("WITHOUT ROWID")
}

struct Catalog {
    tables: Vec<TableDef>,
    /// `sqlite_schema` rows that failed to decode, had an out-of-range
    /// root page, or otherwise couldn't be turned into a usable
    /// [`TableDef`] -- each one is also logged (`forensic_rs::debug!`) at
    /// the point it's skipped; this is a cheap summary for a caller that
    /// wants to know a scan wasn't perfectly clean without trawling logs.
    skipped_rows: usize,
    /// The `sqlite_schema` b-tree walk itself stopped early (a cyclic or
    /// out-of-range page reference) -- some tables may be missing
    /// entirely, not just individually malformed.
    truncated: bool,
}

impl Catalog {
    fn from_reader(reader: &dyn PageReader, header: &Header) -> ForensicResult<Self> {
        let walk = leaf_pages(reader, header.page_size, SCHEMA_ROOT_PAGE)?;
        if walk.truncated {
            forensic_rs::warn!(
                "SQLite: sqlite_schema b-tree walk stopped early (cyclic or invalid page reference); \
                 some tables may be missing"
            );
        }
        // `page_count_hint` is the header's own claim; fall back to the
        // source's actual size when it's absent (`0`), same convention
        // `format::Header`'s own doc comment describes for that field.
        let page_count: u64 = if header.page_count_hint > 0 {
            header.page_count_hint as u64
        } else {
            (reader.total_size() / header.page_size as usize) as u64
        };

        let mut tables = Vec::new();
        let mut skipped_rows = 0usize;
        for leaf in walk.leaves {
            // One unreadable leaf page must not take down the whole
            // catalog -- skip it and keep reading the rest, same
            // "skip and continue" convention every other scan in this
            // crate follows.
            let page_cells = match read_leaf_cells(reader, header.page_size, header.usable_page_size(), leaf) {
                Ok(pc) => pc,
                Err(e) => {
                    forensic_rs::debug!("SQLite: sqlite_schema leaf page {leaf} unreadable, skipping: {e}");
                    skipped_rows += 1;
                    continue;
                }
            };
            skipped_rows += page_cells.skipped;
            for cell in page_cells.cells {
                // A single malformed catalog row should not take down the
                // whole database -- skip it and keep reading the rest,
                // same convention `frnsc-amcache` uses per-category.
                let Ok(values) = decode_record(&cell.payload) else {
                    skipped_rows += 1;
                    continue;
                };
                if values.len() < 5 {
                    skipped_rows += 1;
                    continue;
                }
                let RecordValue::Text(type_bytes) = &values[0] else {
                    continue;
                };
                if decode_text(type_bytes, header.text_encoding) != "table" {
                    // Not a table row (an index/view/trigger catalog
                    // entry) -- not an error, just not one of ours.
                    continue;
                }
                let RecordValue::Text(name_bytes) = &values[1] else {
                    skipped_rows += 1;
                    continue;
                };
                let name = decode_text(name_bytes, header.text_encoding);
                let RecordValue::Integer(root_page) = &values[3] else {
                    skipped_rows += 1;
                    continue;
                };
                // `0` means the table is a view/virtual table with no
                // b-tree of its own; anything else out of `1..=page_count`
                // is not a page this database actually has.
                if *root_page <= 0 || *root_page as u64 > page_count {
                    forensic_rs::debug!(
                        "SQLite: table '{name}' has an out-of-range root page ({root_page}), skipping"
                    );
                    skipped_rows += 1;
                    continue;
                }
                let sql = match &values[4] {
                    RecordValue::Text(sql_bytes) => decode_text(sql_bytes, header.text_encoding),
                    _ => String::new(),
                };
                if is_without_rowid(&sql) {
                    forensic_rs::debug!(
                        "SQLite: table '{name}' is WITHOUT ROWID (an index b-tree), which this crate \
                         doesn't read; skipping"
                    );
                    skipped_rows += 1;
                    continue;
                }
                let columns = match parse_create_table(&sql) {
                    Ok(columns) => columns,
                    Err(e) => {
                        forensic_rs::warn!("SQLite: table '{name}': CREATE TABLE could not be parsed ({e}); columns unknown");
                        skipped_rows += 1;
                        Vec::new()
                    }
                };
                let forensic_columns = to_forensic_columns(&columns);
                tables.push(TableDef {
                    name,
                    root_page: *root_page as u32,
                    columns,
                    forensic_columns,
                });
            }
        }
        Ok(Catalog {
            tables,
            skipped_rows,
            truncated: walk.truncated,
        })
    }

    fn table(&self, name: &str) -> Option<&TableDef> {
        self.tables.iter().find(|t| t.name.eq_ignore_ascii_case(name))
    }
}

/// An open SQLite database. Holds a page reader, parsed header, and the
/// table catalog read from `sqlite_schema`.
///
/// `Send + Sync`: `forensic_rs::traits::db::ForensicDb` requires it, since a
/// mounted database is cached and shared across parallel pipeline workers.
/// `PageReader` implementations are `Send + Sync` (see `reader.rs`);
/// `Header`/`Catalog` are plain data.
pub struct SqliteDb {
    reader: Box<dyn PageReader>,
    header: Header,
    catalog: Catalog,
}

impl SqliteDb {
    /// Open a SQLite database file from disk. Pages are read on demand --
    /// the entire file is never loaded into memory. A bounded page cache
    /// (see [`CachedReader`]) sits in front of the file, since interior
    /// b-tree pages are otherwise re-read from disk on every
    /// `Table::iter_rows()` call.
    pub fn open(path: impl AsRef<Path>) -> ForensicResult<Self> {
        let reader = FileReader::open(path.as_ref())
            .map_err(|e| ForensicError::io_error_with_source(e, "Cannot open SQLite file"))?;
        Self::from_reader(Box::new(CachedReader::new(reader, DEFAULT_PAGE_CACHE_CAPACITY)))
    }

    /// Parse a SQLite database from an in-memory byte vector. Not wrapped
    /// in a [`CachedReader`]: `SliceReader`'s own reads are already
    /// zero-copy slices into memory already resident, so a cache would
    /// only add a lock for no benefit.
    pub fn from_bytes(data: Vec<u8>) -> ForensicResult<Self> {
        Self::from_reader(Box::new(SliceReader::new(data)))
    }

    /// Parse a SQLite database from an already-open `forensic_rs`
    /// `VirtualFile` (used by [`crate::sqlite::factory::SqliteFormatFactory`]).
    /// Page-cached for the same reason as [`Self::open`].
    pub fn from_virtual_file(file: Box<dyn forensic_rs::traits::vfs::VirtualFile>) -> ForensicResult<Self> {
        let reader = VirtualFileReader::new(file)?;
        Self::from_reader(Box::new(CachedReader::new(reader, DEFAULT_PAGE_CACHE_CAPACITY)))
    }

    /// Shared constructor, also used directly by
    /// [`crate::sqlite::factory::SqliteFormatFactory::mount`] for the
    /// large-file (stream-pages-on-demand) path.
    pub(crate) fn from_reader(reader: Box<dyn PageReader>) -> ForensicResult<Self> {
        let header = {
            let buf = reader.read_page(0, HEADER_SIZE.min(reader.total_size()))?;
            Header::from_bytes(&buf)?
        };
        let catalog = Catalog::from_reader(reader.as_ref(), &header)?;
        Ok(Self {
            reader,
            header,
            catalog,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Names of every user table found in `sqlite_schema`.
    pub fn table_names(&self) -> Vec<&str> {
        self.catalog.tables.iter().map(|t| t.name.as_str()).collect()
    }

    /// Whether the `sqlite_schema` b-tree walk stopped early (a cyclic or
    /// out-of-range page reference). When `true`, [`Self::table_names`] may
    /// be missing tables that exist elsewhere in the schema b-tree.
    pub fn schema_scan_truncated(&self) -> bool {
        self.catalog.truncated
    }

    /// Number of `sqlite_schema` rows that were skipped while building the
    /// catalog (malformed rows, out-of-range root pages, `WITHOUT ROWID`
    /// tables, unparsable `CREATE TABLE` text, ...). Each skip is also
    /// logged at the point it happens; this is a cheap summary for a caller
    /// that wants to know the scan wasn't perfectly clean.
    pub fn schema_rows_skipped(&self) -> usize {
        self.catalog.skipped_rows
    }

    /// Get a table by name (case-insensitive).
    pub fn table(&self, name: &str) -> ForensicResult<Table<'_>> {
        let def = self.catalog.table(name).ok_or_else(|| {
            ForensicError::missing_data("table", format!("table '{name}' not found in SQLite database").into())
        })?;
        Ok(Table { db: self, def })
    }

    /// This database's page source. Used by [`crate::sqlite::recovery`] to
    /// walk the freelist and scan live-page slack, alongside the ordinary
    /// live-row read path.
    pub(crate) fn reader(&self) -> &dyn PageReader {
        self.reader.as_ref()
    }
}

pub struct Table<'db> {
    db: &'db SqliteDb,
    def: &'db TableDef,
}

impl<'db> Table<'db> {
    pub fn name(&self) -> &str {
        &self.def.name
    }

    pub fn forensic_columns(&self) -> &[ForensicColumnDef] {
        &self.def.forensic_columns
    }

    /// This table's root b-tree page. Used by
    /// [`crate::sqlite::recovery::slack`] to walk the same live leaf pages
    /// [`Self::iter_rows`] does, to scan their trailing slack.
    pub(crate) fn root_page(&self) -> u32 {
        self.def.root_page
    }

    /// Internal column metadata (affinity + rowid-alias flag), for callers
    /// that need it outside `db.rs` -- currently only
    /// [`crate::sqlite::recovery`], which decodes recovered rows through
    /// the same [`decode_row`] helper [`RowIter::next_row`] uses.
    pub(crate) fn internal_columns(&self) -> &'db [ColumnDef] {
        &self.def.columns
    }

    /// Start a fresh cursor over every row, in rowid order.
    pub fn iter_rows(&self) -> ForensicResult<RowIter<'db>> {
        let walk = leaf_pages(self.db.reader.as_ref(), self.db.header.page_size, self.def.root_page)?;
        Ok(RowIter {
            db: self.db,
            columns: &self.def.columns,
            leaves: walk.leaves,
            leaf_idx: 0,
            current_leaf_page: 0,
            current_cells: Vec::new(),
            cell_idx: 0,
            current_row: None,
            current_locus: None,
            truncated: walk.truncated,
            skipped: 0,
        })
    }
}

/// Row cursor for one table. Reads leaf pages lazily, one at a time, as the
/// cursor advances past the previous page's cells; each row's record is
/// decoded once, at [`Self::next_row`] time, into fully-owned
/// [`ForensicValue`]s (see the module-level rationale in `forensic_db.rs`)
/// so repeated [`Self::current_row`]/`read` calls are cheap.
pub struct RowIter<'db> {
    db: &'db SqliteDb,
    columns: &'db [ColumnDef],
    leaves: Vec<u32>,
    leaf_idx: usize,
    current_leaf_page: u32,
    current_cells: Vec<LeafCell>,
    cell_idx: usize,
    current_row: Option<(i64, Vec<ForensicValue>)>,
    /// `(leaf page, cell slot)` of the row `next_row` last positioned on --
    /// the address [`crate::sqlite::forensic_db`] reports as a
    /// [`forensic_rs::provenance::Locus::Record`].
    current_locus: Option<(u32, u32)>,
    /// The b-tree walk that produced [`Self::leaves`] stopped early (see
    /// [`crate::sqlite::btree::LeafWalk::truncated`]): rows after the break
    /// are missing from this scan entirely, not just individually skipped.
    truncated: bool,
    /// Leaf pages that failed to read, plus cells/rows on readable pages
    /// that failed to decode -- each also logged at the point it's
    /// skipped (`forensic_rs::debug!`).
    skipped: usize,
}

impl<'db> RowIter<'db> {
    /// Advance to the next row. Returns `false` once every leaf page has
    /// been exhausted.
    pub fn next_row(&mut self) -> ForensicResult<bool> {
        loop {
            if self.cell_idx >= self.current_cells.len() {
                if self.leaf_idx >= self.leaves.len() {
                    self.current_row = None;
                    self.current_locus = None;
                    return Ok(false);
                }
                let leaf_page = self.leaves[self.leaf_idx];
                self.leaf_idx += 1;
                // One unreadable leaf page must not abort the whole table
                // scan -- skip it and move on to the next, same
                // "skip and continue" rule every other scan in this crate
                // follows.
                let page_cells = match read_leaf_cells(
                    self.db.reader.as_ref(),
                    self.db.header.page_size,
                    self.db.header.usable_page_size(),
                    leaf_page,
                ) {
                    Ok(pc) => pc,
                    Err(e) => {
                        forensic_rs::debug!("SQLite: leaf page {leaf_page} unreadable, skipping: {e}");
                        self.skipped += 1;
                        self.current_cells = Vec::new();
                        self.cell_idx = 0;
                        continue;
                    }
                };
                self.current_leaf_page = leaf_page;
                self.skipped += page_cells.skipped;
                self.current_cells = page_cells.cells;
                self.cell_idx = 0;
                continue;
            }
            let idx = self.cell_idx;
            let cell = &self.current_cells[idx];
            self.cell_idx += 1;
            // A single malformed row (bad record header, truncated value)
            // is skipped rather than aborting the whole table scan.
            let Ok(values) = decode_record(&cell.payload) else {
                self.skipped += 1;
                continue;
            };
            let rowid = cell.rowid;
            let row = decode_row(&values, self.columns, self.db.header.text_encoding, rowid);
            self.current_row = Some((rowid, row));
            self.current_locus = Some((self.current_leaf_page, idx as u32));
            return Ok(true);
        }
    }

    /// The rowid and decoded column values of the row `next_row` last
    /// positioned on. `None` before the first call or after exhaustion.
    pub fn current_row(&self) -> Option<&(i64, Vec<ForensicValue>)> {
        self.current_row.as_ref()
    }

    /// `(leaf page, cell slot)` of the row `next_row` last positioned on.
    /// `None` before the first call or after exhaustion.
    pub fn current_locus(&self) -> Option<(u32, u32)> {
        self.current_locus
    }

    /// This table's b-tree walk stopped early -- rows after the break are
    /// missing from this scan entirely (see [`crate::sqlite::btree::LeafWalk`]).
    pub fn scan_truncated(&self) -> bool {
        self.truncated
    }

    /// Leaf pages or individual rows skipped so far because they failed to
    /// read or decode.
    pub fn skipped(&self) -> usize {
        self.skipped
    }

    /// This table's column definitions, in the same order as
    /// [`Self::current_row`]'s values.
    pub fn columns(&self) -> &'db [ColumnDef] {
        self.columns
    }
}

/// Decode a whole record's already-parsed [`RecordValue`]s into one row of
/// owned [`ForensicValue`]s, in `columns` order. Shared by
/// [`RowIter::next_row`] and [`crate::sqlite::recovery`] -- a recovered row
/// (from a freelist page or a live page's slack) is decoded through exactly
/// this same path, not a parallel one, so it can never diverge from how a
/// live row's columns are typed.
pub(crate) fn decode_row(
    values: &[RecordValue<'_>],
    columns: &[ColumnDef],
    encoding: crate::sqlite::format::TextEncoding,
    rowid: i64,
) -> Vec<ForensicValue> {
    let mut row = Vec::with_capacity(columns.len());
    for (i, column) in columns.iter().enumerate() {
        let value = match values.get(i) {
            Some(v) => record_value_to_forensic(v, encoding, column, rowid),
            // Table was `ALTER TABLE ... ADD COLUMN`-ed after this row was
            // written: older rows simply lack the value.
            None => ForensicValue::Null,
        };
        row.push(value);
    }
    row
}

fn record_value_to_forensic(
    value: &RecordValue<'_>,
    encoding: crate::sqlite::format::TextEncoding,
    column: &ColumnDef,
    rowid: i64,
) -> ForensicValue {
    if column.is_rowid_alias && matches!(value, RecordValue::Null) {
        return ForensicValue::I64(rowid);
    }
    match value {
        RecordValue::Null => ForensicValue::Null,
        RecordValue::Integer(n) => ForensicValue::I64(*n),
        RecordValue::Real(f) => ForensicValue::F64(*f),
        RecordValue::Text(b) => ForensicValue::Text(decode_text(b, encoding)),
        RecordValue::Blob(b) => ForensicValue::Binary(b.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny but complete SQLite database (page size 512, one user table
    /// `t(id INTEGER PRIMARY KEY, name TEXT)` with two rows), built by hand
    /// to test the engine without a filesystem fixture. Mirrors the
    /// `sqlite_schema` + user-table layout a real `sqlite3`-authored file
    /// would produce, at a scale small enough to hand-encode.
    fn two_page_db() -> Vec<u8> {
        let page_size = 512u16;
        let mut file = vec![0u8; page_size as usize * 2];

        // --- Page 1: file header + sqlite_schema leaf, root page = 2 ---
        file[0..16].copy_from_slice(crate::sqlite::format::MAGIC);
        file[16..18].copy_from_slice(&page_size.to_be_bytes());
        file[56..60].copy_from_slice(&1u32.to_be_bytes());

        let sql = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)";
        let schema_record = encode_record(&[
            Value::Text("table"),
            Value::Text("t"),
            Value::Text("t"),
            Value::Int(2),
            Value::Text(sql),
        ]);
        write_leaf_page(&mut file[0..page_size as usize], HEADER_SIZE, &[(1, schema_record)]);

        // --- Page 2: the user table's own leaf, two rows ---
        // id is a rowid alias -> stored as NULL in the record.
        let row1 = encode_record(&[Value::Null, Value::Text("alice")]);
        let row2 = encode_record(&[Value::Null, Value::Text("bob")]);
        let page2 = &mut file[page_size as usize..page_size as usize * 2];
        write_leaf_page(page2, 0, &[(1, row1), (2, row2)]);

        file
    }

    enum Value<'a> {
        Null,
        Int(i64),
        Text(&'a str),
    }

    fn encode_varint(mut v: i64) -> Vec<u8> {
        if v == 0 {
            return vec![0];
        }
        let mut bytes = Vec::new();
        while v > 0 {
            bytes.push((v & 0x7f) as u8);
            v >>= 7;
        }
        bytes.reverse();
        let last = bytes.len() - 1;
        for b in bytes.iter_mut().take(last) {
            *b |= 0x80;
        }
        bytes
    }

    fn encode_record(values: &[Value]) -> Vec<u8> {
        let mut serials = Vec::new();
        let mut body = Vec::new();
        for v in values {
            match v {
                Value::Null => serials.push(0i64),
                Value::Int(n) => {
                    serials.push(6); // always encode as 64-bit int for simplicity
                    body.extend_from_slice(&n.to_be_bytes());
                }
                Value::Text(s) => {
                    serials.push(13 + 2 * s.len() as i64);
                    body.extend_from_slice(s.as_bytes());
                }
            }
        }
        let mut header_body = Vec::new();
        for s in &serials {
            header_body.extend(encode_varint(*s));
        }
        // Every fixture used by this test module has a header short enough
        // that the leading "header length" varint is itself always 1 byte
        // -- so header_len = 1 (for that byte) + header_body.len().
        let header_len = 1 + header_body.len();
        debug_assert!(
            header_len < 128,
            "test fixture header too large for the 1-byte varint this helper assumes"
        );
        let mut record = vec![header_len as u8];
        record.extend(header_body);
        record.extend(body);
        record
    }

    /// Write a leaf table page's cells (each already an encoded record) at
    /// `header_offset` within `page`, growing cell storage from the end of
    /// the page backward, same layout `sqlite/btree.rs`'s own test helper
    /// uses.
    fn write_leaf_page(page: &mut [u8], header_offset: usize, rows: &[(i64, Vec<u8>)]) {
        const PAGE_TYPE_LEAF_TABLE: u8 = 13;
        let ho = header_offset;
        page[ho] = PAGE_TYPE_LEAF_TABLE;
        page[ho + 3..ho + 5].copy_from_slice(&(rows.len() as u16).to_be_bytes());

        let mut cursor = page.len();
        let mut ptrs = Vec::new();
        for (rowid, payload) in rows {
            let mut cell = Vec::new();
            cell.extend(encode_varint(payload.len() as i64));
            cell.extend(encode_varint(*rowid));
            cell.extend_from_slice(payload);
            cursor -= cell.len();
            page[cursor..cursor + cell.len()].copy_from_slice(&cell);
            ptrs.push(cursor as u16);
        }
        page[ho + 5..ho + 7].copy_from_slice(&(cursor as u16).to_be_bytes());
        let ptr_start = ho + 8;
        for (i, ptr) in ptrs.iter().enumerate() {
            page[ptr_start + i * 2..ptr_start + i * 2 + 2].copy_from_slice(&ptr.to_be_bytes());
        }
    }

    #[test]
    fn opens_and_lists_tables() {
        let db = SqliteDb::from_bytes(two_page_db()).unwrap();
        assert_eq!(db.table_names(), vec!["t"]);
    }

    #[test]
    fn reads_rows_with_rowid_alias_and_text() {
        let db = SqliteDb::from_bytes(two_page_db()).unwrap();
        let table = db.table("t").unwrap();
        assert_eq!(table.forensic_columns().len(), 2);
        assert_eq!(table.forensic_columns()[0].name, "id");

        let mut rows = table.iter_rows().unwrap();
        assert!(rows.next_row().unwrap());
        let (rowid, values) = rows.current_row().unwrap();
        assert_eq!(*rowid, 1);
        assert_eq!(values[0], ForensicValue::I64(1)); // rowid alias substituted
        assert_eq!(values[1], ForensicValue::Text("alice".into()));

        assert!(rows.next_row().unwrap());
        let (rowid, values) = rows.current_row().unwrap();
        assert_eq!(*rowid, 2);
        assert_eq!(values[0], ForensicValue::I64(2));
        assert_eq!(values[1], ForensicValue::Text("bob".into()));

        assert!(!rows.next_row().unwrap());
    }

    #[test]
    fn table_lookup_is_case_insensitive() {
        let db = SqliteDb::from_bytes(two_page_db()).unwrap();
        assert!(db.table("T").is_ok());
        assert!(db.table("missing").is_err());
    }

    #[test]
    fn row_iter_reports_locus() {
        let db = SqliteDb::from_bytes(two_page_db()).unwrap();
        let table = db.table("t").unwrap();
        let mut rows = table.iter_rows().unwrap();
        assert!(rows.next_row().unwrap());
        assert_eq!(rows.current_locus(), Some((2, 0)));
        assert!(rows.next_row().unwrap());
        assert_eq!(rows.current_locus(), Some((2, 1)));
        assert!(!rows.next_row().unwrap());
        assert_eq!(rows.current_locus(), None);
        assert_eq!(rows.skipped(), 0);
        assert!(!rows.scan_truncated());
    }

    /// A one-table database (schema root at page 1, one user table's own
    /// leaf at page 2), with the schema row's declared `sql` and root-page
    /// field both overridable -- used to test catalog validation (P0/P1)
    /// without a filesystem fixture.
    fn one_table_db(page_size: u16, sql: &str, root_page_field: i64) -> Vec<u8> {
        let mut file = vec![0u8; page_size as usize * 2];
        file[0..16].copy_from_slice(crate::sqlite::format::MAGIC);
        file[16..18].copy_from_slice(&page_size.to_be_bytes());
        file[56..60].copy_from_slice(&1u32.to_be_bytes());

        let schema_record = encode_record(&[
            Value::Text("table"),
            Value::Text("t"),
            Value::Text("t"),
            Value::Int(root_page_field),
            Value::Text(sql),
        ]);
        write_leaf_page(&mut file[0..page_size as usize], HEADER_SIZE, &[(1, schema_record)]);

        let row = encode_record(&[Value::Null, Value::Text("x")]);
        let page2 = &mut file[page_size as usize..page_size as usize * 2];
        write_leaf_page(page2, 0, &[(1, row)]);
        file
    }

    #[test]
    fn valid_table_is_not_skipped_regression() {
        let sql = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)";
        let db = SqliteDb::from_bytes(one_table_db(512, sql, 2)).unwrap();
        assert_eq!(db.table_names(), vec!["t"]);
        assert_eq!(db.schema_rows_skipped(), 0);
        assert!(!db.schema_scan_truncated());
    }

    #[test]
    fn out_of_range_root_page_is_skipped_not_fatal() {
        let sql = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)";
        // Only 2 pages exist in this database; page 99 does not.
        let db = SqliteDb::from_bytes(one_table_db(512, sql, 99)).unwrap();
        assert!(db.table_names().is_empty());
        assert!(db.schema_rows_skipped() > 0);
    }

    #[test]
    fn zero_root_page_is_skipped_not_fatal() {
        let sql = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)";
        let db = SqliteDb::from_bytes(one_table_db(512, sql, 0)).unwrap();
        assert!(db.table_names().is_empty());
        assert!(db.schema_rows_skipped() > 0);
    }

    #[test]
    fn without_rowid_table_is_skipped_not_fatal() {
        let sql = "CREATE TABLE t(id INTEGER, name TEXT) WITHOUT ROWID";
        let db = SqliteDb::from_bytes(one_table_db(512, sql, 2)).unwrap();
        assert!(db.table_names().is_empty());
        assert!(db.schema_rows_skipped() > 0);
    }
}
