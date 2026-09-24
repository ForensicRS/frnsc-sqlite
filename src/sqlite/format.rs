//! The 100-byte SQLite database file header.
//!
//! Layout: <https://www.sqlite.org/fileformat2.html#the_database_header>

use forensic_rs::err::{ForensicError, ForensicResult};

pub const MAGIC: &[u8; 16] = b"SQLite format 3\0";
pub const HEADER_SIZE: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Parsed database header. Only the fields the engine and forensic readers
/// actually need are kept; the rest of the 100 bytes is not retained.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// Bytes per page. Always a power of two between 512 and 65536
    /// (the on-disk `1` meaning 65536 is normalized away here).
    pub page_size: u32,
    /// Bytes reserved at the end of every page for extensions. Usable page
    /// size is `page_size - reserved_space`.
    pub reserved_space: u8,
    /// Database size in pages, as claimed by the header. `0` means "not
    /// recorded here" — callers should fall back to `file_size / page_size`.
    pub page_count_hint: u32,
    pub text_encoding: TextEncoding,
    /// Page number of the first freelist trunk page, `0` if the freelist is
    /// empty.
    pub freelist_trunk_page: u32,
    pub freelist_page_count: u32,
}

impl Header {
    pub fn usable_page_size(&self) -> u32 {
        self.page_size - self.reserved_space as u32
    }

    pub fn from_bytes(buf: &[u8]) -> ForensicResult<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(ForensicError::buffer_too_small(HEADER_SIZE, buf.len(), "SQLite header"));
        }
        if &buf[0..16] != MAGIC {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "Not a SQLite database: magic header mismatch",
            ));
        }
        let raw_page_size = u16::from_be_bytes([buf[16], buf[17]]);
        let page_size: u32 = match raw_page_size {
            1 => 65536,
            n if n.is_power_of_two() && n >= 512 => n as u32,
            _ => {
                return Err(ForensicError::invalid_format(
                    "SQLite",
                    "SQLite header: invalid page size",
                ));
            }
        };
        let reserved_space = buf[20];
        // Usable size must stay above SQLite's own documented floor (480
        // bytes -- the smallest a b-tree page can be and still hold at
        // least one cell plus its overflow pointer); a `reserved_space`
        // that eats more than that is not a value real `sqlite3` ever
        // writes, and would make `btree::local_payload_len`'s arithmetic
        // (which assumes `usable_size - 35 > 0`) produce nonsense.
        if (page_size.saturating_sub(reserved_space as u32)) < 480 {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite header: reserved space leaves too little usable page size",
            ));
        }
        let page_count_hint = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]);
        let freelist_trunk_page = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let freelist_page_count = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let text_encoding = match u32::from_be_bytes([buf[56], buf[57], buf[58], buf[59]]) {
            2 => TextEncoding::Utf16Le,
            3 => TextEncoding::Utf16Be,
            // 1 is the documented value for UTF-8; treat anything else the
            // same way rather than reject a file over a cosmetic field.
            _ => TextEncoding::Utf8,
        };
        Ok(Header {
            page_size,
            reserved_space,
            page_count_hint,
            text_encoding,
            freelist_trunk_page,
            freelist_page_count,
        })
    }
}

/// Sniff the 16-byte magic without parsing the rest of the header — cheap
/// enough for a [`forensic_rs::traits::format::FormatFactory::probe`] call.
pub fn is_sqlite_magic(buf: &[u8]) -> bool {
    buf.len() >= 16 && &buf[0..16] == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header(page_size_field: u16) -> Vec<u8> {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0..16].copy_from_slice(MAGIC);
        buf[16..18].copy_from_slice(&page_size_field.to_be_bytes());
        buf[56..60].copy_from_slice(&1u32.to_be_bytes());
        buf
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = sample_header(4096);
        buf[0] = b'X';
        assert!(Header::from_bytes(&buf).is_err());
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(Header::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn parses_ordinary_page_size() {
        let header = Header::from_bytes(&sample_header(4096)).unwrap();
        assert_eq!(header.page_size, 4096);
        assert_eq!(header.usable_page_size(), 4096);
        assert_eq!(header.text_encoding, TextEncoding::Utf8);
    }

    #[test]
    fn page_size_one_means_65536() {
        let header = Header::from_bytes(&sample_header(1)).unwrap();
        assert_eq!(header.page_size, 65536);
    }

    #[test]
    fn rejects_non_power_of_two_page_size() {
        assert!(Header::from_bytes(&sample_header(4097)).is_err());
    }

    #[test]
    fn reserved_space_shrinks_usable_size() {
        let mut buf = sample_header(4096);
        buf[20] = 8;
        let header = Header::from_bytes(&buf).unwrap();
        assert_eq!(header.usable_page_size(), 4088);
    }

    #[test]
    fn rejects_reserved_space_that_leaves_too_little_usable_size() {
        let mut buf = sample_header(512);
        buf[20] = 100; // usable = 412, below the 480-byte floor
        assert!(Header::from_bytes(&buf).is_err());
    }
}
