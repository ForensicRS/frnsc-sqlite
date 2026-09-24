//! Table b-tree walking: page header parsing, interior-page descent, leaf
//! cell extraction, and overflow-page reassembly.
//! <https://www.sqlite.org/fileformat2.html#b_tree_pages>
//!
//! Only *table* b-trees (page types 5/13) are handled — this crate never
//! needs an index b-tree (2/10), since every artifact is read by table name
//! through [`crate::sqlite::db::SqliteDb`], not by index lookup.

use std::collections::HashSet;

use forensic_rs::err::{ForensicError, ForensicResult};

use crate::sqlite::format::HEADER_SIZE;
use crate::sqlite::reader::PageReader;
use crate::sqlite::varint::read_varint;

const PAGE_TYPE_INTERIOR_TABLE: u8 = 5;
const PAGE_TYPE_LEAF_TABLE: u8 = 13;

/// A leaf table cell: the rowid and its fully reassembled payload (record
/// bytes), with any overflow pages already stitched in.
#[derive(Debug)]
pub struct LeafCell {
    pub rowid: i64,
    pub payload: Vec<u8>,
}

fn page_offset(page_no: u32, page_size: u32) -> usize {
    (page_no as usize - 1) * page_size as usize
}

fn header_offset(page_no: u32) -> usize {
    if page_no == 1 {
        HEADER_SIZE
    } else {
        0
    }
}

/// Parse one page's b-tree header and, for an interior page, its ordered
/// child page numbers (cell child pointers left-to-right, then the
/// right-most pointer last). Returns `(page_type, children)`; `children` is
/// empty for a leaf page.
fn read_page_children(reader: &dyn PageReader, page_size: u32, page_no: u32) -> ForensicResult<(u8, Vec<u32>)> {
    let ho = header_offset(page_no);
    let page = reader.read_page(page_offset(page_no, page_size), page_size as usize)?;
    if page.len() < ho + 8 {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite b-tree page: too short for header",
        ));
    }
    let page_type = page[ho];
    let num_cells = u16::from_be_bytes([page[ho + 3], page[ho + 4]]) as usize;
    match page_type {
        PAGE_TYPE_LEAF_TABLE => Ok((page_type, Vec::new())),
        PAGE_TYPE_INTERIOR_TABLE => {
            if page.len() < ho + 12 {
                return Err(ForensicError::invalid_format(
                    "SQLite",
                    "SQLite b-tree page: interior header truncated",
                ));
            }
            let right_pointer = u32::from_be_bytes([page[ho + 8], page[ho + 9], page[ho + 10], page[ho + 11]]);
            let cell_ptr_start = ho + 12;
            let mut children = Vec::with_capacity(num_cells + 1);
            for i in 0..num_cells {
                let entry = cell_ptr_start + i * 2;
                if entry + 2 > page.len() {
                    return Err(ForensicError::invalid_format(
                        "SQLite",
                        "SQLite b-tree page: cell pointer array truncated",
                    ));
                }
                let cell_off = u16::from_be_bytes([page[entry], page[entry + 1]]) as usize;
                if cell_off + 4 > page.len() {
                    return Err(ForensicError::invalid_format(
                        "SQLite",
                        "SQLite b-tree page: interior cell truncated",
                    ));
                }
                let child_page = u32::from_be_bytes([
                    page[cell_off],
                    page[cell_off + 1],
                    page[cell_off + 2],
                    page[cell_off + 3],
                ]);
                children.push(child_page);
            }
            children.push(right_pointer);
            Ok((page_type, children))
        }
        other => Err(ForensicError::invalid_format(
            "SQLite",
            format!("SQLite b-tree page: unsupported page type {other} in table walk"),
        )),
    }
}

/// Result of walking a table b-tree down to its leaves.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeafWalk {
    /// Leaf page numbers found before the walk stopped, in row order.
    pub leaves: Vec<u32>,
    /// The walk stopped early -- a cyclic/invalid page reference, more
    /// distinct pages visited than the database claims to have, or an
    /// interior page whose header couldn't be read. The leaves already
    /// collected are still real rows and are returned rather than
    /// discarded; only the pages *after* the break are missing.
    pub truncated: bool,
}

/// Depth-first, left-to-right walk from `root_page` down to every leaf
/// table page, returning their page numbers in row order. Non-recursive
/// (an explicit stack) and cycle-guarded, since the page graph comes from
/// evidence and cannot be trusted to be well-formed.
///
/// Never fails outright: a malformed page graph stops the walk and sets
/// [`LeafWalk::truncated`] instead of discarding every leaf already found
/// (the crate's "one bad page never aborts a whole scan" rule -- see
/// `AGENTS.md`).
pub fn leaf_pages(reader: &dyn PageReader, page_size: u32, root_page: u32) -> ForensicResult<LeafWalk> {
    let max_pages = (reader.total_size() / page_size as usize).saturating_add(1);
    let mut result = Vec::new();
    let mut stack = vec![root_page];
    let mut visited = HashSet::new();
    while let Some(page_no) = stack.pop() {
        if page_no == 0 || !visited.insert(page_no) || visited.len() > max_pages {
            return Ok(LeafWalk {
                leaves: result,
                truncated: true,
            });
        }
        let Ok((page_type, children)) = read_page_children(reader, page_size, page_no) else {
            return Ok(LeafWalk {
                leaves: result,
                truncated: true,
            });
        };
        if page_type == PAGE_TYPE_LEAF_TABLE {
            result.push(page_no);
        } else {
            for &child in children.iter().rev() {
                stack.push(child);
            }
        }
    }
    Ok(LeafWalk {
        leaves: result,
        truncated: false,
    })
}

/// Number of local (on-page) payload bytes for a table-leaf cell, per
/// <https://www.sqlite.org/fileformat2.html#overflow_pages>. `usable_size`
/// and `payload_len` are both taken as `i64` to match the spec's own
/// arithmetic (which can transiently exceed `u32`).
fn local_payload_len(usable_size: i64, payload_len: i64) -> i64 {
    let max_local = usable_size - 35;
    if payload_len <= max_local {
        return payload_len;
    }
    let m = ((usable_size - 12) * 32 / 255) - 23;
    let k = m + ((payload_len - m) % (usable_size - 4));
    if k <= max_local {
        k
    } else {
        m
    }
}

/// Follow an overflow-page chain, collecting `remaining` more payload bytes
/// beyond what a cell already holds locally.
fn read_overflow_chain(
    reader: &dyn PageReader,
    page_size: u32,
    usable_size: u32,
    first_page: u32,
    mut remaining: usize,
) -> ForensicResult<Vec<u8>> {
    // `remaining` is derived from an evidence-controlled payload length
    // (see `read_one_cell`'s own sanity check on it), but cap the up-front
    // allocation at the source's total size regardless -- belt and braces
    // against a crafted length slipping past that check.
    let mut out = Vec::with_capacity(remaining.min(reader.total_size()));
    let mut page_no = first_page;
    let mut visited = HashSet::new();
    let chunk = usable_size as usize - 4;
    while remaining > 0 {
        if page_no == 0 || !visited.insert(page_no) {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite overflow chain: truncated or cyclic",
            ));
        }
        let page = reader.read_page(page_offset(page_no, page_size), page_size as usize)?;
        if page.len() < 4 {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite overflow page: too short",
            ));
        }
        let next = u32::from_be_bytes([page[0], page[1], page[2], page[3]]);
        let take = remaining.min(chunk).min(page.len() - 4);
        out.extend_from_slice(&page[4..4 + take]);
        remaining -= take;
        page_no = next;
    }
    Ok(out)
}

/// Result of parsing a leaf table page's cells.
#[derive(Debug, Default)]
pub struct LeafPageCells {
    pub cells: Vec<LeafCell>,
    /// Cells on this page that failed to decode (truncated varint, cell
    /// offset pointing outside the page or into the header/pointer array,
    /// an overflow chain that ran off the end of the source, ...) and were
    /// skipped rather than aborting the rest of the page.
    pub skipped: usize,
}

/// Decode one leaf cell at pointer-array slot `i`, reassembling any
/// overflow so its `payload` is the complete record. A page-relative
/// helper for [`read_leaf_cells`]; every error here is per-cell, not
/// per-page.
#[allow(clippy::too_many_arguments)]
fn read_one_cell(
    reader: &dyn PageReader,
    page_size: u32,
    usable_size: u32,
    page: &[u8],
    cell_ptr_start: usize,
    cell_ptr_end: usize,
    i: usize,
) -> ForensicResult<LeafCell> {
    let entry = cell_ptr_start + i * 2;
    if entry + 2 > page.len() {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite b-tree page: cell pointer array truncated",
        ));
    }
    let cell_off = u16::from_be_bytes([page[entry], page[entry + 1]]) as usize;
    // A well-formed cell can never start inside the page header or the
    // cell-pointer array itself -- accepting that would let an
    // evidence-controlled offset make later arithmetic read overlapping,
    // attacker-chosen bytes as if they were this cell's varints.
    if cell_off < cell_ptr_end || cell_off >= page.len() {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite b-tree page: cell offset out of range",
        ));
    }
    let cell = &page[cell_off..];
    let (payload_len, n1) = read_varint(cell)
        .ok_or_else(|| ForensicError::invalid_format("SQLite", "SQLite leaf cell: truncated payload length"))?;
    let (rowid, n2) = read_varint(&cell[n1..])
        .ok_or_else(|| ForensicError::invalid_format("SQLite", "SQLite leaf cell: truncated rowid"))?;
    if payload_len < 0 {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite leaf cell: negative payload length",
        ));
    }
    // A record can never legitimately be larger than the source it lives
    // in -- reject the claim outright instead of letting it drive a
    // multi-gigabyte allocation below (`payload_len` comes straight off
    // the evidence and is otherwise unbounded up to i64::MAX).
    if payload_len as u64 > reader.total_size() as u64 {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite leaf cell: payload length exceeds source size",
        ));
    }
    let local_len = local_payload_len(usable_size as i64, payload_len) as usize;
    let body_start = cell_off + n1 + n2;
    if body_start + local_len > page.len() {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite leaf cell: local payload runs past page end",
        ));
    }
    let local = &page[body_start..body_start + local_len];

    let payload = if local_len as i64 == payload_len {
        local.to_vec()
    } else {
        let overflow_ptr_off = body_start + local_len;
        if overflow_ptr_off + 4 > page.len() {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite leaf cell: missing overflow page pointer",
            ));
        }
        let overflow_page = u32::from_be_bytes([
            page[overflow_ptr_off],
            page[overflow_ptr_off + 1],
            page[overflow_ptr_off + 2],
            page[overflow_ptr_off + 3],
        ]);
        let remaining = (payload_len as usize) - local_len;
        let mut full = Vec::with_capacity((payload_len as usize).min(reader.total_size()));
        full.extend_from_slice(local);
        full.extend(read_overflow_chain(
            reader,
            page_size,
            usable_size,
            overflow_page,
            remaining,
        )?);
        full
    };
    Ok(LeafCell { rowid, payload })
}

/// Parse every cell on a leaf table page, reassembling any overflow so each
/// cell's `payload` is the complete record.
///
/// Only the page header itself is a hard failure (`Err`): a page that
/// doesn't even parse as a leaf table page can't be scanned at all. A bad
/// individual cell is counted in [`LeafPageCells::skipped`] and the rest of
/// the page is still read -- one corrupt cell must not hide every other row
/// on the same page.
pub fn read_leaf_cells(
    reader: &dyn PageReader,
    page_size: u32,
    usable_size: u32,
    leaf_page_no: u32,
) -> ForensicResult<LeafPageCells> {
    let ho = header_offset(leaf_page_no);
    let page = reader.read_page(page_offset(leaf_page_no, page_size), page_size as usize)?;
    if page.len() < ho + 8 || page[ho] != PAGE_TYPE_LEAF_TABLE {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite b-tree page: expected a leaf table page",
        ));
    }
    let num_cells = u16::from_be_bytes([page[ho + 3], page[ho + 4]]) as usize;
    let cell_ptr_start = ho + 8;
    let cell_ptr_end = cell_ptr_start + num_cells * 2;

    let mut cells = Vec::with_capacity(num_cells.min(page.len()));
    let mut skipped = 0usize;
    for i in 0..num_cells {
        match read_one_cell(reader, page_size, usable_size, &page, cell_ptr_start, cell_ptr_end, i) {
            Ok(cell) => cells.push(cell),
            Err(_) => skipped += 1,
        }
    }
    Ok(LeafPageCells { cells, skipped })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::reader::SliceReader;

    /// Build a single-page (page 1) database: file header (100 bytes) +
    /// a leaf table b-tree page holding the given raw record payloads
    /// (already-encoded record bytes, one per row, rowid = index+1).
    fn single_leaf_page_db(page_size: u16, payloads: &[Vec<u8>]) -> Vec<u8> {
        let mut buf = vec![0u8; page_size as usize];
        buf[0..16].copy_from_slice(crate::sqlite::format::MAGIC);
        buf[16..18].copy_from_slice(&page_size.to_be_bytes());
        buf[56..60].copy_from_slice(&1u32.to_be_bytes());

        let ho = HEADER_SIZE;
        buf[ho] = PAGE_TYPE_LEAF_TABLE;
        buf[ho + 3..ho + 5].copy_from_slice(&(payloads.len() as u16).to_be_bytes());
        // no freeblocks fragmentation for this synthetic fixture.

        // Cells grow from the end of the page backward; pointer array
        // follows the 8-byte leaf header.
        let mut cursor = page_size as usize;
        let mut ptrs = Vec::new();
        for (i, payload) in payloads.iter().enumerate() {
            let rowid = (i + 1) as i64;
            let mut cell = Vec::new();
            cell.extend(encode_varint(payload.len() as i64));
            cell.extend(encode_varint(rowid));
            cell.extend_from_slice(payload);
            cursor -= cell.len();
            buf[cursor..cursor + cell.len()].copy_from_slice(&cell);
            ptrs.push(cursor as u16);
        }
        buf[ho + 5..ho + 7].copy_from_slice(&(cursor as u16).to_be_bytes());
        let ptr_start = ho + 8;
        for (i, ptr) in ptrs.iter().enumerate() {
            buf[ptr_start + i * 2..ptr_start + i * 2 + 2].copy_from_slice(&ptr.to_be_bytes());
        }
        buf
    }

    fn encode_varint(mut v: i64) -> Vec<u8> {
        // Minimal single/multi-byte varint encoder sufficient for small
        // test values (payload lengths, rowids) -- not the general 9-byte
        // form, which the reader-side already has dedicated tests for.
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

    #[test]
    fn leaf_pages_finds_the_single_root_leaf() {
        let db = single_leaf_page_db(512, &[vec![1, 2, 3]]);
        let reader = SliceReader::new(db);
        let walk = leaf_pages(&reader, 512, 1).unwrap();
        assert_eq!(walk.leaves, vec![1]);
        assert!(!walk.truncated);
    }

    #[test]
    fn leaf_pages_reports_truncation_on_a_cycle() {
        let db = single_leaf_page_db(512, &[vec![1, 2, 3]]);
        let reader = SliceReader::new(db);
        // Page 1 is a leaf, so "root page 99" (out of range) can't be
        // descended into -- the very first iteration already can't read a
        // page there, which is exactly the truncation path this exercises.
        let walk = leaf_pages(&reader, 512, 99).unwrap();
        assert!(walk.leaves.is_empty());
        assert!(walk.truncated);
    }

    #[test]
    fn reads_leaf_cells_without_overflow() {
        let payloads = vec![vec![0xAAu8; 10], vec![0xBBu8; 20]];
        let db = single_leaf_page_db(512, &payloads);
        let reader = SliceReader::new(db);
        let result = read_leaf_cells(&reader, 512, 512, 1).unwrap();
        assert_eq!(result.skipped, 0);
        let cells = result.cells;
        assert_eq!(cells.len(), 2);
        assert_eq!(cells[0].rowid, 1);
        assert_eq!(cells[0].payload, payloads[0]);
        assert_eq!(cells[1].rowid, 2);
        assert_eq!(cells[1].payload, payloads[1]);
    }

    #[test]
    fn a_bad_cell_offset_is_skipped_not_fatal() {
        // Two good cells plus one whose pointer-array entry is hand-corrupted
        // to point back into the page header -- must be skipped, not abort
        // the whole page.
        let payloads = vec![vec![0xAAu8; 4], vec![0xBBu8; 4], vec![0xCCu8; 4]];
        let mut db = single_leaf_page_db(512, &payloads);
        let ptr_start = HEADER_SIZE + 8;
        // Corrupt the second cell's pointer-array entry to point at offset
        // 0 (inside the file header), which is `< cell_ptr_end`.
        db[ptr_start + 2..ptr_start + 4].copy_from_slice(&0u16.to_be_bytes());
        let reader = SliceReader::new(db);
        let result = read_leaf_cells(&reader, 512, 512, 1).unwrap();
        assert_eq!(result.skipped, 1);
        assert_eq!(result.cells.len(), 2);
    }

    #[test]
    fn a_payload_length_larger_than_the_source_is_rejected_not_a_huge_allocation() {
        // A crafted `payload_len` varint claiming far more bytes than the
        // whole source holds must be rejected before it ever reaches
        // `Vec::with_capacity` -- this is a regression test for a crash
        // path (an attempted multi-exabyte allocation), not just a decode
        // error, so it deliberately doesn't inspect the error itself.
        let payloads = vec![vec![0xAAu8; 20]];
        let mut db = single_leaf_page_db(4096, &payloads);
        let ptr_start = HEADER_SIZE + 8;
        let cell_off = u16::from_be_bytes([db[ptr_start], db[ptr_start + 1]]) as usize;
        let huge_len_varint = encode_varint(50_000_000); // far bigger than the 4096-byte source
        db[cell_off..cell_off + huge_len_varint.len()].copy_from_slice(&huge_len_varint);
        let reader = SliceReader::new(db);
        let result = read_leaf_cells(&reader, 4096, 4096, 1).unwrap();
        assert_eq!(result.skipped, 1);
        assert!(result.cells.is_empty());
    }

    #[test]
    fn local_payload_len_matches_spec_small_case() {
        // usable=4096: max_local = 4096-35=4061; anything <= that is fully local.
        assert_eq!(local_payload_len(4096, 100), 100);
        assert_eq!(local_payload_len(4096, 4061), 4061);
    }

    #[test]
    fn local_payload_len_spills_when_too_large() {
        let usable = 4096i64;
        let payload_len = 10_000i64;
        let local = local_payload_len(usable, payload_len);
        assert!(local < payload_len);
        assert!(local > 0);
    }
}
