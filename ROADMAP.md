# Roadmap

## Shipped

- Generic SQLite engine: header (validates the usable page size stays
  above SQLite's own 480-byte floor), page reader
  (`FileReader`/`SliceReader`/`VirtualFileReader`, plus `CachedReader` — a
  small bounded page cache in front of `FileReader`/`VirtualFileReader`,
  used by default, so repeated interior-page reads across
  `Table::iter_rows()` calls don't each re-read from disk/VFS), varint
  decoding, table
  b-tree walking (interior + leaf, non-recursive, cycle-guarded — a bad
  page graph or cell is reported (`LeafWalk::truncated`,
  `LeafPageCells::skipped`) rather than aborting the whole scan, and a
  claimed cell payload length is capped at the source's total size before
  it can drive an allocation), overflow-page reassembly, `CREATE TABLE` →
  column definitions (affinity, including multi-word declared types;
  rowid-alias detection for both the inline and table-level
  `PRIMARY KEY` forms; `NOT NULL`).
- `Catalog::from_reader` validates each table's root page and excludes
  `WITHOUT ROWID` tables (an index b-tree this crate doesn't walk) instead
  of failing opaquely on first read; every skip (catalog row, leaf page,
  individual row) is logged and counted
  (`SqliteDb::{schema_scan_truncated,schema_rows_skipped}`,
  `RowIter::{scan_truncated,skipped}`).
- `forensic_rs::traits::db::{ForensicDb, ForensicTable, ForensicRows}` bridge,
  including `ForensicRows::locus()` (`Locus::Record { page, slot }`, from
  `RowIter::current_locus`).
- `forensic_rs::traits::format::FormatFactory` (auto-mount any `.db`/`.sqlite`
  file as a `ForensicDb`, magic-sniffed) — `SqliteFormatFactory`.
- `SqliteWalSetFactory` — a second `FormatFactory` over the same candidate
  file, yielding `MountKind::FileSet`: groups a SQLite database with its
  `-wal`/`-journal`/`-shm` companions by filename shape, mirroring
  `frnsc-esedb::ese::format::EseLogSetFactory`. Reporting only (addresses,
  not open handles, per `FileSet`'s contract) — does not replay a WAL, see
  "WAL / rollback-journal awareness" below.
- `crate::artifacts::browser_history` — Chrome/Edge/Brave/Vivaldi `History`
  (`urls` + `visits`), with a `BrowserHistoryParserFactory` that discovers
  every profile under `Users/*/AppData/Local/<vendor path>/User Data/*/History`,
  validates each discovered database against a
  `Requirement::Database(SchemaFingerprint)` before trusting it as Chromium
  history, and reports (rather than silently drops) a file that fails to
  open, parse, or read.
- **`RecoverRows` (deleted-row recovery)** — `forensic_rs::traits::db::RecoverRows`
  implemented on `SqliteDb`, two sources (`sqlite::recovery::freelist`/
  `sqlite::recovery::slack`), both decoded through the exact same record
  path live iteration uses: a freed table-leaf page still readable via the
  freelist trunk chain (`Recovery::DeletedMetadata`), and a candidate found
  in a live leaf page's trailing never-allocated slack
  (`Recovery::Slack`, stricter admission bar, no overflow-page trust). See
  `sqlite::recovery`'s own module doc comment for the full soundness
  rationale and this pass's known limitations (freeblocks not walked, a
  freed page validated only against the table the caller asked for, no WAL
  awareness).

## Planned

Roughly in priority order — see the workspace-level roadmap for how this
crate fits into the broader ForensicRS plan.

- **Mount through `ParseContext::mount`/the resolver's own cache, and
  `ParserRun::push` streaming** for the browser-history parser, to bound
  peak memory on unusually large history databases (`reader::CachedReader`
  already addresses the *repeated interior-page read* half of this — see
  Shipped, above). Deferred out of the crate's first correctness/soundness
  pass to keep it reviewable as its own change.
- **Chrome/Edge `Cookies`** — same schema family and discovery pattern as
  `History`; low incremental cost once a `Cookies` glob is added.
- **Firefox `places.sqlite`** (`moz_places`, `moz_historyvisits`,
  `moz_bookmarks`) — `frnsc-triage` already collects whole Firefox profile
  directories, so only the typed reader + parser factory are missing.
- **Windows Timeline** (`ActivitiesCache.db` — `Activity`,
  `Activity_PackageId`). Not currently in `frnsc-triage`'s default
  collection paths; add a collection path there in the same pass.
- **`wpndatabase.db`** (Windows push notifications) — smaller, same
  schema-reading machinery as the above.
- **Freeblock walking** for `sqlite::recovery::slack` — a deleted cell's
  bytes *within* the already-used cell-content area, unlinked from the
  cell pointer array via SQLite's own freeblock chain but not physically
  moved, is real, structured evidence of its own (unlike the trailing-gap
  scan shipped today, it has an exact governing chain to follow rather than
  needing a byte-by-byte plausibility scan).
- **WAL / rollback-journal replay** (`-wal`/`-journal` sidecar files) —
  reading not-yet-checkpointed pages, relevant for reconstructing very
  recent history. `SqliteWalSetFactory` (shipped) reports that these
  companions exist; actually replaying their frames onto the primary
  database is the remaining, larger piece of work.
