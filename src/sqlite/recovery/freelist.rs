//! Recovers rows from a table-leaf page SQLite's freelist marks as no
//! longer part of any b-tree, but whose bytes have not yet been
//! overwritten.
//!
//! SQLite does not zero a page when freeing it
//! (<https://www.sqlite.org/fileformat2.html#the_freelist>): a freelist
//! *trunk* page has its first 8 bytes overwritten (next-trunk pointer +
//! leaf-pointer count), but a freelist *leaf* page -- the page a trunk's
//! own pointer array names, and the far more common case, since most freed
//! pages are leaves rather than trunks -- is left exactly as it was. If
//! that page last held a table b-tree leaf (the ordinary result of a page
//! becoming fully empty after enough rows were deleted, or of `DROP
//! TABLE`), its cells are still sitting there, addressable the same way a
//! live leaf page's are.

use std::collections::HashSet;

use forensic_rs::err::ForensicResult;
use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::recovery::Recovered;

use crate::sqlite::btree::read_leaf_cells;
use crate::sqlite::db::{decode_row, SqliteDb};
use crate::sqlite::record::decode_record;
use crate::sqlite::recovery::validate::meaningful_column_count;
use crate::sqlite::recovery::{RecoveredRow, RecoveryStats};

/// A freelist page is governed by real database metadata (its membership
/// in the trunk chain), not found by plausibility alone -- so, unlike
/// [`super::slack`], one meaningful column is enough to admit a row.
const MIN_MEANINGFUL_COLUMNS: usize = 1;

/// Every page number the freelist trunk chain names. Trunk pages
/// themselves are walked for their pointers, not treated as row
/// candidates -- their content is trunk metadata (a next-pointer and a
/// leaf-pointer array), not row data.
///
/// Cycle-guarded and capped at the database's own page count, the same
/// convention [`crate::sqlite::btree::leaf_pages`] follows: a malformed
/// chain stops the walk rather than looping forever, and what was found
/// before the break is still returned rather than discarded.
fn freelist_leaf_pages(db: &SqliteDb) -> (Vec<u32>, RecoveryStats) {
    let mut stats = RecoveryStats::default();
    let reader = db.reader();
    let header = db.header();
    let page_size = header.page_size as usize;
    let max_pages = (reader.total_size() / page_size).saturating_add(1);

    let mut leaves = Vec::new();
    let mut trunk = header.freelist_trunk_page;
    let mut visited = HashSet::new();
    while trunk != 0 {
        if !visited.insert(trunk) || visited.len() > max_pages {
            break; // cyclic or runaway chain -- stop, keep what was found
        }
        stats.pages_scanned += 1;
        let offset = (trunk as usize - 1) * page_size;
        let Ok(page) = reader.read_page(offset, page_size) else {
            stats.pages_unreadable += 1;
            break;
        };
        if page.len() < 8 {
            stats.pages_unreadable += 1;
            break;
        }
        let next = u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
        let count = u32::from_be_bytes([page[4], page[5], page[6], page[7]]) as usize;
        // A crafted/corrupt count could claim far more entries than the
        // page can physically hold -- clamp to what's actually there
        // rather than reading past it.
        let max_entries = (page.len() - 8) / 4;
        for i in 0..count.min(max_entries) {
            let off = 8 + i * 4;
            leaves.push(u32::from_be_bytes([page[off], page[off + 1], page[off + 2], page[off + 3]]));
        }
        trunk = next;
    }
    (leaves, stats)
}

/// Recovers every row that decodes cleanly, against `table`'s own schema,
/// from a table-leaf page the freelist marks as freed.
///
/// Reuses [`read_leaf_cells`] unmodified: a freed leaf page is, byte for
/// byte, an ordinary table-leaf page until something overwrites it, so the
/// exact same header/cell-pointer-array/overflow-chain handling the live
/// read path relies on (including its own per-cell skip-and-continue and
/// payload-length sanity check) applies without changes.
pub(crate) fn recover_freelist_rows(db: &SqliteDb, table: &str) -> ForensicResult<(Vec<RecoveredRow>, RecoveryStats)> {
    let handle = SqliteDb::table(db, table)?;
    let columns = handle.internal_columns();
    let header = db.header();
    let page_size = header.page_size;
    let usable_size = header.usable_page_size();
    let reader = db.reader();

    let (candidate_pages, mut stats) = freelist_leaf_pages(db);
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    for page_no in candidate_pages {
        // A well-formed freelist never lists the same leaf page twice, but
        // a crafted file could, to inflate the scan -- dedupe defensively.
        // Page 1 (the schema root) is always live, so it can never
        // legitimately appear here either.
        if page_no == 0 || page_no == 1 || !seen.insert(page_no) {
            continue;
        }
        // Not every freed page was a table-leaf page before it was freed
        // (it could have been an interior page, an index page, or an
        // overflow page) -- `read_leaf_cells` itself is the check for
        // that; a page that fails it just isn't a candidate for *this*
        // recovery source, not an error.
        let Ok(page_cells) = read_leaf_cells(reader, page_size, usable_size, page_no) else {
            continue;
        };
        stats.candidates_found += page_cells.cells.len();
        for (slot, cell) in page_cells.cells.iter().enumerate() {
            let Ok(values) = decode_record(&cell.payload) else {
                stats.rows_rejected += 1;
                continue;
            };
            let rowid = cell.rowid;
            let row = decode_row(&values, columns, header.text_encoding, rowid);
            if meaningful_column_count(&row, columns) < MIN_MEANINGFUL_COLUMNS {
                stats.rows_rejected += 1;
                continue;
            }
            stats.rows_recovered += 1;
            rows.push(Recovered::new(
                (rowid, row),
                Recovery::DeletedMetadata,
                Locus::Record {
                    page: page_no as u64,
                    slot: slot as u32,
                },
            ));
        }
    }
    Ok((rows, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_freelist_yields_no_candidates() {
        // `header.freelist_trunk_page == 0` for any database with an empty
        // freelist -- `chrome_history_sample/History` fits (see the real
        // fixture's own conformance tests), but this crate's hand-built
        // `two_page_db` test fixture in `db.rs` also has one, so a minimal
        // in-crate check doesn't need the file fixture.
        use crate::sqlite::db::SqliteDb;
        let Ok(db) = SqliteDb::open("artifacts/chrome_history_sample/History") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        assert_eq!(db.header().freelist_trunk_page, 0);
        let (rows, stats) = recover_freelist_rows(&db, "urls").unwrap();
        assert!(rows.is_empty());
        assert_eq!(stats.pages_scanned, 0);
    }

    // ---- hand-built fixture: a genuinely freed page still holding a row ----

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

    enum Value<'a> {
        Null,
        Text(&'a str),
    }

    fn encode_record(values: &[Value]) -> Vec<u8> {
        let mut header_body = Vec::new();
        let mut body = Vec::new();
        for v in values {
            match v {
                Value::Null => header_body.push(0u8),
                Value::Text(s) => {
                    header_body.extend(encode_varint(13 + 2 * s.len() as i64));
                    body.extend_from_slice(s.as_bytes());
                }
            }
        }
        let header_len = 1 + header_body.len();
        let mut record = vec![header_len as u8];
        record.extend(header_body);
        record.extend(body);
        record
    }

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

    /// A 4-page database: page 1 = schema (`t(id INTEGER PRIMARY KEY, name
    /// TEXT)`, root page 2), page 2 = table `t`'s own *live* leaf page
    /// (empty -- every row has since been deleted), page 3 = a *freed*
    /// leaf page still holding one old row (`rowid = 99, name = "ghost"`),
    /// page 4 = the freelist trunk page naming page 3 as its one leaf.
    fn db_with_one_freed_row() -> Vec<u8> {
        use crate::sqlite::format::{HEADER_SIZE, MAGIC};
        let page_size = 512u16;
        let mut file = vec![0u8; page_size as usize * 4];

        file[0..16].copy_from_slice(MAGIC);
        file[16..18].copy_from_slice(&page_size.to_be_bytes());
        file[28..32].copy_from_slice(&4u32.to_be_bytes()); // page_count_hint
        file[32..36].copy_from_slice(&4u32.to_be_bytes()); // freelist_trunk_page
        file[36..40].copy_from_slice(&2u32.to_be_bytes()); // freelist_page_count
        file[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8

        // `sqlite_schema`'s row shape is fixed: (type, name, tbl_name,
        // rootpage, sql) -- `rootpage` is the one INTEGER column among
        // four TEXT columns, so it needs its own serial type rather than
        // `encode_record`'s text-only `Value` helper.
        let sql = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)";
        let mut header_body = Vec::new();
        let mut body = Vec::new();
        for text in ["table", "t", "t"] {
            header_body.extend(encode_varint(13 + 2 * text.len() as i64));
            body.extend_from_slice(text.as_bytes());
        }
        header_body.extend(encode_varint(1)); // serial type 1: 1-byte int
        body.push(2u8); // root_page = 2
        header_body.extend(encode_varint(13 + 2 * sql.len() as i64));
        body.extend_from_slice(sql.as_bytes());
        let header_len = 1 + header_body.len();
        let mut schema_record = vec![header_len as u8];
        schema_record.extend(header_body);
        schema_record.extend(body);

        write_leaf_page(&mut file[0..page_size as usize], HEADER_SIZE, &[(1, schema_record)]);

        // Page 2: table t's own live leaf, currently empty (0 cells).
        let page2_start = page_size as usize;
        file[page2_start] = 13; // PAGE_TYPE_LEAF_TABLE, 0 cells, content area = end of page
        file[page2_start + 5..page2_start + 7].copy_from_slice(&(page_size).to_be_bytes());

        // Page 3: a freed leaf page still holding one old row.
        let ghost_row = encode_record(&[Value::Null, Value::Text("ghost")]);
        let page3 = &mut file[page_size as usize * 2..page_size as usize * 3];
        write_leaf_page(page3, 0, &[(99, ghost_row)]);

        // Page 4: the freelist trunk page: next = 0, count = 1, leaf = [3].
        let page4_start = page_size as usize * 3;
        file[page4_start..page4_start + 4].copy_from_slice(&0u32.to_be_bytes());
        file[page4_start + 4..page4_start + 8].copy_from_slice(&1u32.to_be_bytes());
        file[page4_start + 8..page4_start + 12].copy_from_slice(&3u32.to_be_bytes());

        file
    }

    #[test]
    fn recovers_a_row_from_a_genuinely_freed_page() {
        use crate::sqlite::db::SqliteDb;
        let db = SqliteDb::from_bytes(db_with_one_freed_row()).unwrap();

        // The live table really is empty -- the row only exists in the
        // freed page.
        let table = db.table("t").unwrap();
        let mut live = table.iter_rows().unwrap();
        assert!(!live.next_row().unwrap());

        let (rows, stats) = recover_freelist_rows(&db, "t").unwrap();
        assert_eq!(stats.pages_scanned, 1); // the one trunk page
        assert_eq!(rows.len(), 1);
        let recovered = &rows[0];
        assert_eq!(recovered.recovery(), forensic_rs::provenance::Recovery::DeletedMetadata);
        assert_eq!(
            recovered.locus(),
            forensic_rs::provenance::Locus::Record { page: 3, slot: 0 }
        );
        let (rowid, values) = recovered.value();
        assert_eq!(*rowid, 99);
        assert_eq!(values[0], forensic_rs::traits::db::ForensicValue::I64(99)); // rowid alias
        assert_eq!(
            values[1],
            forensic_rs::traits::db::ForensicValue::Text("ghost".to_string())
        );
    }
}
