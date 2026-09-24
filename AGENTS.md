# Agent notes: frnsc-sqlite

A pure-Rust SQLite database reader, part of the [ForensicRS](https://github.com/ForensicRS)
ecosystem. It depends only on `forensic-rs` (the trait framework). This file
is for anyone (human or agent) extending or reviewing the crate; see
[README.md](README.md) for user-facing usage and [ROADMAP.md](ROADMAP.md) for
what's shipped vs. planned.

## Layering

Mirrors `frnsc-esedb::ese`: a generic engine layer, a `forensic_rs::traits::db`
bridge on top of it, a `FormatFactory` for auto-mounting, and typed
per-artifact readers layered on top of *that* — never the other way around.
`crate::artifacts::browser_history` is written entirely against the generic
`ForensicDb` trait, not against `crate::sqlite` directly (see its own doc
comment, and the "a SQLite parser is not a Chromium parser" note on
`forensic_rs::traits::forensic::Requirement`).

## Module map

- [src/sqlite/format.rs](src/sqlite/format.rs) — the 100-byte file header
  (magic, page size, reserved space, text encoding, freelist pointers).
- [src/sqlite/reader.rs](src/sqlite/reader.rs) — `PageReader` trait +
  `SliceReader`/`FileReader`/`VirtualFileReader`, page-at-a-time access
  (pages read on demand, never the whole file slurped except in
  `factory.rs`'s small-file fast path). Lifted near-verbatim from
  `frnsc-esedb::ese::reader` — keep the two in sync if one gets a bugfix the
  other would also need (e.g. the positioned-read EOF handling).
  `CachedReader<R>` wraps `FileReader`/`VirtualFileReader` (not
  `SliceReader`, whose reads are already zero-copy) with a small bounded
  `(offset, size) -> bytes` cache — `SqliteDb::open`/`from_virtual_file` use
  it by default (`DEFAULT_PAGE_CACHE_CAPACITY`) so `Table::iter_rows()`
  doesn't re-read the same interior b-tree pages from disk/VFS on every
  call.
- [src/sqlite/varint.rs](src/sqlite/varint.rs) — SQLite's 1-9 byte varint
  encoding.
- [src/sqlite/record.rs](src/sqlite/record.rs) — record header (serial
  types) + value decoding, and `decode_text` (UTF-8/16LE/16BE per the header's
  declared encoding).
- [src/sqlite/btree.rs](src/sqlite/btree.rs) — table b-tree page header
  parsing, non-recursive cycle-guarded interior descent (`leaf_pages`), leaf
  cell extraction with overflow-page reassembly (`read_leaf_cells`). Only
  table b-trees (page types 5/13); this crate never needs an index b-tree,
  since every artifact is read by table name, not index lookup. Neither
  function returns a hard `Err` for a malformed page graph or cell — `leaf_pages`
  returns a [`LeafWalk`] (`leaves` collected so far, `truncated: bool`) and
  `read_leaf_cells` returns a [`LeafPageCells`] (`cells`, `skipped: usize`);
  a claimed cell payload length is also capped at the source's total size
  before it drives an allocation (an evidence-controlled length is otherwise
  unbounded up to `i64::MAX`).
- [src/sqlite/schema.rs](src/sqlite/schema.rs) — turns a `sqlite_schema` row's
  `sql` text (`CREATE TABLE ...`) into column definitions, via a small
  quote/paren-aware scanner rather than a real SQL grammar. Detects both the
  inline (`id INTEGER PRIMARY KEY`) and table-level (`..., PRIMARY KEY(id)`)
  forms of a rowid-aliasing key (single column, declared type exactly
  `INTEGER`; `... PRIMARY KEY DESC` is documented to *not* alias), a
  multi-word declared type (`UNSIGNED BIG INT`, `DOUBLE PRECISION`) for
  affinity, and `NOT NULL`.
- [src/sqlite/db.rs](src/sqlite/db.rs) — `SqliteDb` (open a database, parse
  its catalog from `sqlite_schema`), `Table`, `RowIter`. `RowIter` decodes a
  whole row into owned `ForensicValue`s once per `next_row()` call (not
  lazily per-column) — see its doc comment for why. `Catalog::from_reader`
  validates each table's root page (`1..=page_count`) and excludes `WITHOUT
  ROWID` tables (an index b-tree, which `btree.rs` doesn't walk) rather than
  failing opaquely on first read. Both `SqliteDb` (`schema_scan_truncated`/
  `schema_rows_skipped`) and `RowIter` (`scan_truncated`/`skipped`/
  `current_locus`) expose scan diagnostics; every skip is also logged via
  `forensic_rs::debug!`/`warn!`.
- [src/sqlite/forensic_db.rs](src/sqlite/forensic_db.rs) — implements
  `ForensicDb`/`ForensicTable`/`ForensicRows`, including `ForensicRows::locus()`
  (from `RowIter::current_locus`, as `Locus::Record { page, slot }`), and
  `RecoverRows` (`as_recovery()` returns `Some(self)`) — see
  [src/sqlite/recovery/mod.rs](src/sqlite/recovery/mod.rs). Deliberately
  does **not** implement `SqlCapable` (same rationale as `frnsc-esedb`).
  `row_count()` stays at the trait's `None` default — a real count would
  mean an eager full scan on table open. `RecoverRows::row_history` stays
  at the trait's `EmptyRows` default too: it's documented as
  log-replay-derived, which this crate doesn't do (no WAL replay yet).
- [src/sqlite/recovery/mod.rs](src/sqlite/recovery/mod.rs) — deleted-row
  recovery, behind `ForensicDb::as_recovery()`/`RecoverRows`. Two sources,
  both decoding through the exact same `decode_record`/`db::decode_row`
  path live iteration uses (never a speculative reconstruction):
  - [src/sqlite/recovery/freelist.rs](src/sqlite/recovery/freelist.rs) —
    walks the freelist trunk chain (`Header::freelist_trunk_page`); a freed
    *leaf* page (SQLite doesn't zero a page when freeing it) is, byte for
    byte, an ordinary table-leaf page until overwritten, so it's decoded by
    reusing `btree::read_leaf_cells` unmodified. Governed by real database
    metadata (trunk-chain membership), so admitted at
    `Recovery::DeletedMetadata` with a light admission bar (1 meaningful
    column).
  - [src/sqlite/recovery/slack.rs](src/sqlite/recovery/slack.rs) — scans
    the trailing, never-allocated gap on a *live* leaf page (between the
    cell-pointer array's current end and the cell-content area's current
    start), byte-by-byte, for a plausible leaf-cell shape. No governing
    marker at all, so admitted at `Recovery::Slack` with a stricter bar (2
    meaningful columns) and never follows an overflow-page pointer (a
    slack candidate's claimed length is trusted only up to the slack
    region's own end, never past it).
  - [src/sqlite/recovery/validate.rs](src/sqlite/recovery/validate.rs) —
    the shared admission gate both sources call:
    `meaningful_column_count`, forensic-rs's checklist rule 2 ("not `Nil`"
    is not an admission bar, via `forensic_rs::recovery::looks_like_padding`)
    applied to `ForensicValue`.
  - Known limitations (freeblocks not walked, a freed page validated only
    against the table the caller asked for, no WAL awareness) are spelled
    out in the module's own doc comment — read it before extending this
    area.
- [src/sqlite/factory.rs](src/sqlite/factory.rs) — `SqliteFormatFactory`:
  magic sniff (`probe`) + full header validation for `ProbeScore::Exact` vs.
  `Strong`, small-file-slurp-vs-stream `mount()` split on
  `Limits::materialize_in_memory_limit`. `SqliteWalSetFactory`: a second
  factory over the same candidate file, yielding `MountKind::FileSet` —
  groups `-wal`/`-journal`/`-shm` companions beside the database by exact
  filename match (mirrors `frnsc-esedb::ese::format::EseLogSetFactory`;
  reporting only, does not replay a WAL).
- [src/artifacts/browser_history.rs](src/artifacts/browser_history.rs) —
  `UrlRecord`/`VisitRecord` + `read_urls`/`read_visits`, against `dyn
  ForensicDb`.
- [src/artifacts/parser.rs](src/artifacts/parser.rs) —
  `BrowserHistoryParserFactory`: glob-discovers every Chrome/Edge/Brave/Vivaldi
  `History` file under `Users/*`, checks each one against a
  `Requirement::Database(SchemaFingerprint)` before trusting it as Chromium
  history (a same-named, differently-shaped file is skipped, not misread),
  reads eagerly (`ParserRun::pull`, not `push` — see its doc comment), emits
  one `ForensicData` per `urls` row and per `visits` row
  (`browser_history.record_type` = `"Url"`/`"Visit"`). A file that fails to
  open, fails to parse as SQLite, or fails a `read_urls`/`read_visits` call
  is reported as an `Err` in the record stream (surfaces in
  `PipelineResult.errors`), not silently dropped — and `urls`/`visits` are
  read independently, so one failing doesn't discard the other's records
  from the same file.

## Adding a new typed artifact reader

Follow `browser_history.rs` + `parser.rs` as the template (per ROADMAP.md,
`Cookies` is the next one, same schema family and discovery pattern):

1. A record struct per table + a `read_<table>(db: &dyn ForensicDb) -> ForensicResult<Vec<T>>`
   function in a new `src/artifacts/<name>.rs`, written against `dyn
   ForensicDb`/`ForensicRows`, never `crate::sqlite` directly.
2. A `<Name>ParserFactory` in the same file or a sibling `parser.rs`:
   `discover()` via `FileSystemExt::glob` (forward-slash patterns — see
   `forensic_rs::core::fs::glob`'s own doc comment), `can_parse` = "did
   discovery find anything", `open()` opens each discovered file via
   `SqliteDb::from_virtual_file`, reads eagerly, maps to `ForensicData` with
   fields namespaced `"<artifact>.<record>.<field>"` plus a
   `"<artifact>.record_type"` discriminator.
3. Register the new module in [src/artifacts/mod.rs](src/artifacts/mod.rs).
4. Move the item from "Planned" to "Shipped" in [ROADMAP.md](ROADMAP.md).

## Conventions

- **A single malformed row, cell, or page never aborts a whole scan.**
  `leaf_pages`/`read_leaf_cells` themselves never hard-fail on a bad page
  graph or cell (see `btree.rs` above); `Catalog::from_reader` skips a
  catalog row that fails to decode, has an out-of-range root page, or is
  `WITHOUT ROWID`; `RowIter::next_row` skips a row whose record fails to
  decode or a leaf page that fails to read. Keep this "skip and continue"
  shape (same convention `frnsc-amcache` uses per-category) when adding new
  read paths — and prefer counting the skip (`skipped`/`schema_rows_skipped`)
  plus a `forensic_rs::debug!`/`warn!` log over a bare silent `continue`, so
  a caller and an examiner both have a way to tell a clean scan from one
  that quietly dropped rows.
- **`BrowserHistoryParserFactory::open` never silently drops a discovered
  file.** A file that fails to open/parse, or fails schema validation, is
  either logged (schema mismatch — legitimately not our data) or reported
  as an `Err` in the record stream (a real read failure) — never a bare
  `continue` that would also be indistinguishable from "no `History` files
  existed at all". Apply the same shape to a new artifact reader's parser
  factory.
- **Page bytes vs. header bytes.** `page[0]` inside `btree.rs`'s functions is
  always the page-relative header offset (`0` for every page except page 1,
  which is `100` because the 100-byte file header sits in front of the
  b-tree header there) — never assume offset 0 is the b-tree header without
  checking `header_offset(page_no)`.
- **All test fixtures that hand-encode a page** (in `btree.rs`'s and
  `db.rs`'s own `#[cfg(test)]` modules) assume small varint values (<128, so
  single-byte) for simplicity; a `debug_assert!` in `db.rs`'s `encode_record`
  test helper documents this. Real files exercise the general N-byte varint
  path through `tests/real_fixture.rs` instead (see below).
- **Prefer the real fixture over another hand-built one** for anything
  touching interior-page descent or overflow reassembly — those are exactly
  the two things a hand-built single-page buffer can't exercise.
  `artifacts/chrome_history_sample/History` (~30 pages, one overflow row) and
  `tests/real_fixture.rs` exist for this reason; extend that test file rather
  than adding a third hand-built multi-page buffer.

## Testing

```bash
cargo test                          # engine unit tests + tests/real_fixture.rs
cargo run --example pipeline
```

Depends on the fixture at `artifacts/chrome_history_sample/History` (see its
own [README.md](artifacts/chrome_history_sample/README.md) for how it's
generated) and its copy under `artifacts/pipeline_fixture/`. Tests that need
it skip (print `SKIP: fixture unavailable`, do not fail) if it's absent.

`artifacts/parser_error_fixture/` is a second, small pipeline fixture: a
real Chrome `History` next to a deliberately corrupt Edge one (200 zero
bytes). It backs
`artifacts::parser::tests::a_corrupt_history_file_is_reported_not_silently_dropped`,
the regression test for "one bad discovered file must not silently drop
every other profile's records" — extend it rather than mutating
`pipeline_fixture/` (whose own test asserts a *clean* run with zero
errors).
