//! Recovers candidate rows from the trailing, never-allocated gap on a
//! *live* table-leaf page: the span between where the cell-pointer array
//! currently ends and where the cell-content area currently begins (the
//! b-tree page header's own "cell content area start" field,
//! <https://www.sqlite.org/fileformat2.html#b_tree_pages>).
//!
//! Unlike [`super::freelist`]'s source, nothing marks this span as ever
//! having held a row -- a candidate here is admitted purely on structural
//! plausibility (does a leaf-cell-shaped varint pair, followed by a record
//! that decodes cleanly, happen to sit at this offset). Two consequences
//! follow directly from that:
//!
//! - The admission bar is stricter than [`super::freelist`]'s
//!   ([`MIN_MEANINGFUL_COLUMNS`] vs. its `MIN_MEANINGFUL_COLUMNS`).
//! - No overflow-page chain is ever followed. A live cell's overflow
//!   pointer is trustworthy because the cell itself is currently addressed
//!   by a live pointer in the page's own cell-pointer array; a slack
//!   candidate has no such address; nothing but its own claimed length
//!   attests to how large it once was, so a claim that reaches past the
//!   *slack region itself* (not just past the page) is rejected outright
//!   rather than followed into what is, from this scan's perspective,
//!   unrelated bytes -- possibly live cell content, possibly another
//!   table's overflow page.
//!
//! **Not covered by this pass**: SQLite's own freeblock chain (a deleted
//! cell's bytes *within* the already-used cell-content area, unlinked from
//! the cell pointer array but not physically moved) -- see `mod.rs`'s own
//! "known limitations" section.

use forensic_rs::err::ForensicResult;
use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::recovery::{slack_regions, Recovered};
use forensic_rs::traits::vfs::Region;

use crate::sqlite::btree::leaf_pages;
use crate::sqlite::db::{decode_row, SqliteDb};
use crate::sqlite::format::{TextEncoding, HEADER_SIZE};
use crate::sqlite::record::decode_record;
use crate::sqlite::recovery::validate::meaningful_column_count;
use crate::sqlite::recovery::{RecoveredRow, RecoveryStats};
use crate::sqlite::schema::ColumnDef;
use crate::sqlite::varint::read_varint;

/// A slack candidate has no governing marker at all (unlike a freelist
/// page's trunk-chain membership), so it must clear a higher bar than
/// [`super::freelist::recover_freelist_rows`]'s: at least this many
/// non-rowid-alias columns carrying real content. Matches
/// `frnsc-esedb::ese::recovery::slack`'s own stricter-than-defunct bar for
/// the same reason.
const MIN_MEANINGFUL_COLUMNS: usize = 2;

fn header_offset(page_no: u32) -> usize {
    if page_no == 1 {
        HEADER_SIZE
    } else {
        0
    }
}

/// Recovers candidate rows from every live leaf page of `table`, scanning
/// each page's trailing never-allocated gap.
pub(crate) fn recover_slack_rows(db: &SqliteDb, table: &str) -> ForensicResult<(Vec<RecoveredRow>, RecoveryStats)> {
    let handle = SqliteDb::table(db, table)?;
    let columns = handle.internal_columns();
    let header = db.header();
    let page_size = header.page_size;
    let reader = db.reader();

    let mut stats = RecoveryStats::default();
    // Walks the exact same live b-tree `Table::iter_rows()` does -- a
    // slack candidate is only ever looked for on a page this table's own
    // schema still claims, never on a page reached by any other means.
    let walk = leaf_pages(reader, page_size, handle.root_page())?;
    if walk.truncated {
        // Not fatal to the rest of this scan -- the pages found before the
        // break are still real, still-live pages, so still worth scanning.
        stats.pages_unreadable += 1;
    }

    let mut rows = Vec::new();
    for page_no in walk.leaves {
        stats.pages_scanned += 1;
        let ho = header_offset(page_no);
        let offset = (page_no as usize - 1) * page_size as usize;
        let Ok(page) = reader.read_page(offset, page_size as usize) else {
            stats.pages_unreadable += 1;
            continue;
        };
        if page.len() < ho + 8 {
            stats.pages_unreadable += 1;
            continue;
        }
        let num_cells = u16::from_be_bytes([page[ho + 3], page[ho + 4]]) as usize;
        let raw_content_start = u16::from_be_bytes([page[ho + 5], page[ho + 6]]) as usize;
        // `0` on-disk is the spec's encoding for 65536 (a page holding no
        // cells at all, content area collapsed to the very end) -- treated
        // the same as "content starts at the end of the page" regardless
        // of this page's actual size, which is always a safe (if
        // occasionally too conservative) reading.
        let content_start = if raw_content_start == 0 { page.len() } else { raw_content_start };
        let ptr_array_end = ho + 8 + num_cells * 2;
        if ptr_array_end >= content_start || ptr_array_end >= page.len() || content_start > page.len() {
            continue; // no gap, or a header too corrupt to trust -- nothing to scan
        }

        let slack = slack_regions(
            Region {
                offset: ptr_array_end as u64,
                length: (page.len() - ptr_array_end) as u64,
            },
            &[Region {
                offset: content_start as u64,
                length: (page.len() - content_start) as u64,
            }],
        );
        for region in slack {
            scan_region(&page, region, page_no, columns, header.text_encoding, &mut rows, &mut stats);
        }
    }
    Ok((rows, stats))
}

#[allow(clippy::too_many_arguments)]
fn scan_region(
    page: &[u8],
    region: Region,
    page_no: u32,
    columns: &[ColumnDef],
    encoding: TextEncoding,
    rows: &mut Vec<RecoveredRow>,
    stats: &mut RecoveryStats,
) {
    let start = region.offset as usize;
    let end = (region.offset + region.length) as usize;
    let mut pos = start;
    while pos < end {
        let Some((consumed, rowid, values)) = try_slack_cell(page, pos, end) else {
            pos += 1;
            continue;
        };
        stats.candidates_found += 1;
        let row = decode_row(&values, columns, encoding, rowid);
        if meaningful_column_count(&row, columns) >= MIN_MEANINGFUL_COLUMNS {
            stats.rows_recovered += 1;
            rows.push(Recovered::new(
                (rowid, row),
                Recovery::Slack,
                Locus::PageOffset {
                    page: page_no as u64,
                    offset: pos as u32,
                },
            ));
        } else {
            stats.rows_rejected += 1;
        }
        pos += consumed.max(1);
    }
}

/// Attempts to decode one leaf cell starting at `pos`, wholly contained
/// within `[pos, end)` -- `end` is the slack region's own end, not the
/// page's (see the module doc comment on why an overflow chain is never
/// trusted here). Returns the number of bytes consumed, the rowid, and the
/// decoded record values on success.
fn try_slack_cell<'a>(page: &'a [u8], pos: usize, end: usize) -> Option<(usize, i64, Vec<crate::sqlite::record::RecordValue<'a>>)> {
    let cell = page.get(pos..end)?;
    let (payload_len, n1) = read_varint(cell)?;
    let (rowid, n2) = read_varint(cell.get(n1..)?)?;
    if payload_len < 0 {
        return None;
    }
    let body_start = pos.checked_add(n1)?.checked_add(n2)?;
    let body_end = body_start.checked_add(payload_len as usize)?;
    if body_end > end {
        return None; // would need an overflow page, or runs past the slack region -- not trusted
    }
    let payload = page.get(body_start..body_end)?;
    let values = decode_record(payload).ok()?;
    Some((body_end - pos, rowid, values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::db::SqliteDb;

    #[test]
    fn scans_the_real_fixture_without_panicking_and_reports_a_report() {
        let Ok(db) = SqliteDb::open("artifacts/chrome_history_sample/History") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let (rows, stats) = recover_slack_rows(&db, "urls").unwrap();
        // The fixture is a freshly-generated, unmodified database (no
        // deletes) -- no assertion on `rows` being empty or not, since a
        // trailing gap can coincidentally exist even with no prior
        // deletion, but the scan itself must complete cleanly.
        assert!(stats.pages_scanned > 0);
        let _ = rows;
    }

    // ---- hand-built fixture: a candidate planted in the trailing gap ----

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
        let ho = header_offset;
        page[ho] = 13; // PAGE_TYPE_LEAF_TABLE
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

    /// A 2-page database: page 1 = schema (`t(id INTEGER PRIMARY KEY, name
    /// TEXT, note TEXT)`, root page 2), page 2 = table `t`'s live leaf --
    /// one genuine live cell (`rowid = 1`) placed normally, plus a second,
    /// fully cell-shaped candidate (`rowid = 77`) hand-planted in the
    /// trailing gap between the cell-pointer array and the cell-content
    /// area, exactly the span [`recover_slack_rows`] scans. `num_cells` is
    /// left at `1`, so nothing but that scan will ever see the planted
    /// bytes -- ordinary iteration only sees the live cell.
    fn db_with_one_slack_candidate() -> Vec<u8> {
        use crate::sqlite::format::{HEADER_SIZE, MAGIC};
        let page_size = 512u16;
        let mut file = vec![0u8; page_size as usize * 2];

        file[0..16].copy_from_slice(MAGIC);
        file[16..18].copy_from_slice(&page_size.to_be_bytes());
        file[28..32].copy_from_slice(&2u32.to_be_bytes()); // page_count_hint
        file[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8

        let sql = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, note TEXT)";
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

        let page2 = &mut file[page_size as usize..page_size as usize * 2];
        let live_record = encode_record(&[Value::Null, Value::Text("alice"), Value::Text("hello")]);
        let mut live_cell = Vec::new();
        live_cell.extend(encode_varint(live_record.len() as i64));
        live_cell.extend(encode_varint(1));
        live_cell.extend_from_slice(&live_record);
        let cursor = page2.len() - live_cell.len();
        page2[cursor..cursor + live_cell.len()].copy_from_slice(&live_cell);

        page2[0] = 13; // PAGE_TYPE_LEAF_TABLE
        page2[3..5].copy_from_slice(&1u16.to_be_bytes()); // num_cells = 1
        page2[5..7].copy_from_slice(&(cursor as u16).to_be_bytes()); // cell content area start
        page2[8..10].copy_from_slice(&(cursor as u16).to_be_bytes()); // the one live pointer

        // Two meaningful text columns (clears `MIN_MEANINGFUL_COLUMNS`),
        // planted right after the cell-pointer array ends (offset 10).
        let ghost_record = encode_record(&[Value::Null, Value::Text("ghost2"), Value::Text("secret")]);
        let mut ghost_cell = Vec::new();
        ghost_cell.extend(encode_varint(ghost_record.len() as i64));
        ghost_cell.extend(encode_varint(77));
        ghost_cell.extend_from_slice(&ghost_record);
        assert!(
            10 + ghost_cell.len() <= cursor,
            "test fixture bug: the planted cell must fit before the live cell begins"
        );
        page2[10..10 + ghost_cell.len()].copy_from_slice(&ghost_cell);

        file
    }

    #[test]
    fn recovers_a_row_planted_in_a_live_pages_trailing_slack() {
        use crate::sqlite::db::SqliteDb;
        let db = SqliteDb::from_bytes(db_with_one_slack_candidate()).unwrap();

        // Confirm ordinary iteration only ever sees the one live row.
        let table = db.table("t").unwrap();
        let mut live = table.iter_rows().unwrap();
        assert!(live.next_row().unwrap());
        assert!(!live.next_row().unwrap());

        let (rows, stats) = recover_slack_rows(&db, "t").unwrap();
        assert_eq!(stats.pages_scanned, 1);
        assert_eq!(rows.len(), 1, "expected exactly the one planted candidate, found: {rows:?}");
        let recovered = &rows[0];
        assert_eq!(recovered.recovery(), forensic_rs::provenance::Recovery::Slack);
        let forensic_rs::provenance::Locus::PageOffset { page, offset } = recovered.locus() else {
            panic!("expected Locus::PageOffset");
        };
        assert_eq!(page, 2);
        assert_eq!(offset, 10);
        let (rowid, values) = recovered.value();
        assert_eq!(*rowid, 77);
        assert_eq!(values[1], forensic_rs::traits::db::ForensicValue::Text("ghost2".to_string()));
        assert_eq!(values[2], forensic_rs::traits::db::ForensicValue::Text("secret".to_string()));
    }
}
