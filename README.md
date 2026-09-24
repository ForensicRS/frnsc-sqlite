# frnsc-sqlite

Pure-Rust SQLite database reader for the [ForensicRS](https://github.com/ForensicRS) ecosystem.

Implements `forensic_rs`'s generic `ForensicDb`/`ForensicTable`/`ForensicRows`
traits (`forensic_rs::traits::db`) and its `FormatFactory` mount contract
(`forensic_rs::traits::format`) directly against the SQLite file format —
header, table b-trees, varints, record decoding, overflow pages — with no
dependency on `libsqlite3`/`rusqlite`. That matters for forensic use:
page-level access is what lets a deleted row (unlinked from the b-tree but
still sitting in a freelist page or a live page's slack) be recovered at
all, something a wrapper around the real SQLite engine cannot offer —
`RecoverRows` (`db.as_recovery().recovered_rows("urls")` /
`.slack_rows("urls")`) does exactly that; see
[`crate::sqlite::recovery`](src/sqlite/recovery/mod.rs)'s module doc
comment for the two sources and their soundness rationale.

On top of the generic engine, `crate::artifacts` has typed readers for
specific SQLite-backed artifacts, each with a `forensic_rs`
`ArtifactParserFactory` pipeline adapter:

- **Browser history** (`crate::artifacts::browser_history`) — Chrome/Edge
  `History` databases (`urls`, `visits` tables). `BrowserHistoryParserFactory`
  discovers every profile under `Users/*/AppData/Local/{Google/Chrome,Microsoft/Edge}/User Data/*/History`.

See [ROADMAP.md](ROADMAP.md) for what's shipped vs. planned (Cookies, Firefox
`places.sqlite`, Windows Timeline, WAL replay), and [AGENTS.md](AGENTS.md)
for the module map and conventions.

## Usage

```rust,no_run
use frnsc_sqlite::sqlite::db::SqliteDb;

let db = SqliteDb::open("History").unwrap();
for name in db.table_names() {
    println!("{name}");
}
```

Or through the generic trait, so the same code works against any
`ForensicDb` backend:

```rust,no_run
use forensic_rs::traits::db::ForensicDb;
use frnsc_sqlite::sqlite::db::SqliteDb;

let db = SqliteDb::open("History").unwrap();
let dyn_db: &dyn ForensicDb = &db;
let table = dyn_db.table("urls").unwrap();
let mut rows = table.iter_rows().unwrap();
while rows.next().unwrap() {
    println!("{}", rows.read_named("url").unwrap());
}
```

Deleted rows, recovered from the freelist and from live-page slack:

```rust,no_run
use forensic_rs::traits::db::ForensicDb;
use frnsc_sqlite::sqlite::db::SqliteDb;

let db = SqliteDb::open("History").unwrap();
let dyn_db: &dyn ForensicDb = &db;
let recovery = dyn_db.as_recovery().unwrap();

let mut rows = recovery.recovered_rows("urls").unwrap();
while rows.next().unwrap() {
    // `rows.allocated()` is `false`; `rows.recovery()` and `rows.locus()`
    // say how and where each row was found.
    println!("recovered: {}", rows.read_named("url").unwrap());
}
```

## Testing

```bash
cargo test                # engine unit tests + tests/real_fixture.rs
cargo run --example pipeline
```

`tests/real_fixture.rs` and the browser-history/pipeline tests run against a
real, multi-page (~30 pages, 4096-byte page size) `sqlite3`-authored fixture
at `artifacts/chrome_history_sample/History` — including one deliberately
oversized title that forces an overflow-page chain — to validate interior
b-tree descent and overflow reassembly against real SQLite output, not just
hand-built single-page test buffers. See
[artifacts/chrome_history_sample/README.md](artifacts/chrome_history_sample/README.md)
for how it was generated. Tests skip (rather than fail) if the fixture is
absent.
