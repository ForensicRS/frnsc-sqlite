# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ForensicRows::locus()` on the `forensic_rs::traits::db` bridge, returning
  `Locus::Record { page, slot }` for every row read from a `SqliteDb` table.
- `BrowserHistoryParserFactory` now declares a
  `Requirement::Database(SchemaFingerprint)` for the `urls`/`visits` columns
  it reads, and validates it against every discovered database before
  trusting it as Chromium history.
- Discovery globs for Brave and Vivaldi, alongside Chrome and Edge.
- `sqlite::schema::parse_create_table` now recognizes a table-level
  `PRIMARY KEY(col)` rowid alias (previously only the inline
  `id INTEGER PRIMARY KEY` form), a multi-word declared type (`UNSIGNED BIG
  INT`, `DOUBLE PRECISION`) for affinity, and `NOT NULL`.
- Scan diagnostics: `SqliteDb::{schema_scan_truncated, schema_rows_skipped}`
  and `sqlite::db::RowIter::{scan_truncated, skipped, current_locus}`.
- `SqliteDb::header::from_bytes` now rejects a `reserved_space` that shrinks
  the usable page size below SQLite's own documented 480-byte floor.
- `sqlite::factory::SqliteWalSetFactory`, a second `FormatFactory` yielding
  `MountKind::FileSet`: groups a SQLite database with its
  `-wal`/`-journal`/`-shm` companions by exact filename match, mirroring
  `frnsc-esedb::ese::format::EseLogSetFactory` (reporting only — does not
  replay a WAL).
- CI workflow (`cargo test`/`cargo clippy` on Linux/Windows/macOS) and this
  changelog.
- `sqlite::reader::CachedReader`, a small bounded `(offset, size) -> bytes`
  page cache wrapping `FileReader`/`VirtualFileReader`. Used by default in
  `SqliteDb::open`/`from_virtual_file`, so `Table::iter_rows()` no longer
  re-reads the same interior b-tree pages from disk/VFS on every call.
- **Deleted-row recovery**: `forensic_rs::traits::db::RecoverRows`
  implemented on `SqliteDb` (`ForensicDb::as_recovery()` now returns
  `Some(self)`). Two sources, both decoded through the exact same record
  path ordinary iteration uses:
  - `recovered_rows(table)` — a table-leaf page SQLite's freelist marks as
    freed but whose bytes haven't been overwritten yet (`Recovery::DeletedMetadata`).
  - `slack_rows(table)` — candidate cells found in the trailing,
    never-allocated gap on a live leaf page (`Recovery::Slack`, a stricter
    admission bar, no overflow-page chains trusted).
  See `sqlite::recovery`'s module doc comment for the full soundness
  rationale and this first pass's known limitations.

### Fixed

- A crafted cell `payload_len` could drive an unbounded allocation before
  any bounds check ran; it is now capped against the source's total size.
- One malformed leaf page or cell could abort the entire table scan (or the
  whole `sqlite_schema` catalog); `leaf_pages`/`read_leaf_cells` now report
  `truncated`/`skipped` instead of failing outright, and every caller
  (`Catalog::from_reader`, `RowIter::next_row`) skips and continues.
- A table's root page was trusted without validating it against the
  database's actual page count, and a `WITHOUT ROWID` table (an index
  b-tree) was read as if it were an ordinary table b-tree, failing
  opaquely on first row read. Both are now detected and skipped at catalog
  build time, with the skip logged.
- `BrowserHistoryParserFactory::open` silently dropped a discovered
  `History` file that failed to open or parse, and discarded a file's
  `urls` records entirely if its `visits` table failed to read (or vice
  versa). Both are now reported independently as `Err` entries in the
  parser's record stream, surfacing in `PipelineResult.errors`, without
  affecting any other discovered profile.
- `ColumnDef.nullable` (and the `ForensicColumnDef` derived from it) was
  hardcoded to `true`; it now reflects a parsed `NOT NULL` constraint.

### Changed

- Edition bumped to 2024, `rust-version = "1.87"` (matching `frnsc-esedb`).
