//! SQLite's variable-length integer encoding.
//!
//! A varint is 1-9 bytes; each of the first 8 bytes has its high bit set if
//! another byte follows and carries 7 bits of payload, big-endian order. The
//! 9th byte (if present) carries all 8 of its bits.
//! <https://www.sqlite.org/fileformat2.html#varint>

/// Decode one varint starting at `buf[0]`. Returns the decoded value and the
/// number of bytes consumed (1-9). `None` if `buf` runs out before a
/// terminating byte is found.
pub fn read_varint(buf: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    for i in 0..8 {
        let byte = *buf.get(i)?;
        result = (result << 7) | (byte & 0x7f) as i64;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
    }
    // 9th byte: all 8 bits are payload, no continuation flag.
    let byte = *buf.get(8)?;
    result = (result << 8) | byte as i64;
    Some((result, 9))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_values() {
        assert_eq!(read_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_varint(&[0x7f]), Some((127, 1)));
    }

    #[test]
    fn two_byte_value() {
        // 0x81 0x00 -> (1 << 7) | 0 = 128
        assert_eq!(read_varint(&[0x81, 0x00]), Some((128, 2)));
    }

    #[test]
    fn nine_byte_value_uses_full_last_byte() {
        let buf = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let (value, len) = read_varint(&buf).unwrap();
        assert_eq!(len, 9);
        assert_eq!(value, -1i64);
    }

    #[test]
    fn truncated_buffer_returns_none() {
        assert_eq!(read_varint(&[0x81]), None);
        assert_eq!(read_varint(&[]), None);
    }

    #[test]
    fn stops_at_first_non_continuation_byte() {
        // 0x81 0x02 0xFF (trailing garbage must be ignored)
        let (value, len) = read_varint(&[0x81, 0x02, 0xff]).unwrap();
        assert_eq!(len, 2);
        assert_eq!(value, 130);
    }
}
