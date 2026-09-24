//! Decodes a table b-tree leaf cell's payload (a "record") into column
//! values, per SQLite's record format.
//! <https://www.sqlite.org/fileformat2.html#record_format>
//!
//! Takes an already-reassembled payload (overflow pages, if any, already
//! stitched together by [`crate::sqlite::btree`]) — this module only knows
//! about the record header/serial-type/value layout, never about pages.

use forensic_rs::err::{ForensicError, ForensicResult};

use crate::sqlite::format::TextEncoding;
use crate::sqlite::varint::read_varint;

/// Decode a TEXT value's raw bytes per the database header's text encoding.
/// Never fails: invalid sequences are replaced (`char::REPLACEMENT_CHARACTER`
/// / `String::from_utf8_lossy`) rather than erroring out an otherwise
/// well-formed row over one bad string field.
pub fn decode_text(bytes: &[u8], encoding: TextEncoding) -> String {
    match encoding {
        TextEncoding::Utf8 => String::from_utf8_lossy(bytes).into_owned(),
        TextEncoding::Utf16Le => {
            let units = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]));
            char::decode_utf16(units)
                .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
        TextEncoding::Utf16Be => {
            let units = bytes.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]]));
            char::decode_utf16(units)
                .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
    }
}

/// One column's decoded value, borrowing from the record payload where
/// possible (`Text`/`Blob`).
#[derive(Debug, Clone, PartialEq)]
pub enum RecordValue<'a> {
    /// Serial type 0, or an INTEGER PRIMARY KEY column (its value lives in
    /// the cell's rowid, not the record body — callers substitute it).
    Null,
    Integer(i64),
    Real(f64),
    /// Raw bytes; text-encoding conversion (UTF-8/16LE/16BE, per the
    /// database header) is the caller's job — this module has no header.
    Text(&'a [u8]),
    Blob(&'a [u8]),
}

/// Decode a serial type's storage class and on-disk content length, per the
/// table at <https://www.sqlite.org/fileformat2.html#record_format>.
fn serial_type_len(serial_type: i64) -> ForensicResult<usize> {
    Ok(match serial_type {
        0 | 8 | 9 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 6,
        6 | 7 => 8,
        10 | 11 => {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite record: reserved serial type",
            ));
        }
        n if n >= 12 && n % 2 == 0 => ((n - 12) / 2) as usize,
        n if n >= 13 => ((n - 13) / 2) as usize,
        _ => {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite record: negative serial type",
            ));
        }
    })
}

fn decode_value(serial_type: i64, bytes: &[u8]) -> RecordValue<'_> {
    match serial_type {
        0 => RecordValue::Null,
        1 => RecordValue::Integer(bytes[0] as i8 as i64),
        2 => RecordValue::Integer(i16::from_be_bytes([bytes[0], bytes[1]]) as i64),
        3 => {
            let sign_extend = if bytes[0] & 0x80 != 0 { 0xffu8 } else { 0x00 };
            RecordValue::Integer(i32::from_be_bytes([sign_extend, bytes[0], bytes[1], bytes[2]]) as i64)
        }
        4 => RecordValue::Integer(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64),
        5 => {
            let sign_extend = if bytes[0] & 0x80 != 0 {
                [0xffu8, 0xff]
            } else {
                [0x00, 0x00]
            };
            RecordValue::Integer(i64::from_be_bytes([
                sign_extend[0],
                sign_extend[1],
                bytes[0],
                bytes[1],
                bytes[2],
                bytes[3],
                bytes[4],
                bytes[5],
            ]))
        }
        6 => RecordValue::Integer(i64::from_be_bytes(bytes[0..8].try_into().unwrap())),
        7 => RecordValue::Real(f64::from_be_bytes(bytes[0..8].try_into().unwrap())),
        8 => RecordValue::Integer(0),
        9 => RecordValue::Integer(1),
        n if n >= 12 && n % 2 == 0 => RecordValue::Blob(bytes),
        _ => RecordValue::Text(bytes),
    }
}

/// Parse a record's header (the leading varint run naming each column's
/// serial type) and body into one [`RecordValue`] per column, in column
/// order.
pub fn decode_record(payload: &[u8]) -> ForensicResult<Vec<RecordValue<'_>>> {
    let (header_len, header_len_size) = read_varint(payload)
        .ok_or_else(|| ForensicError::invalid_format("SQLite", "SQLite record: truncated header length"))?;
    let header_len = header_len as usize;
    if header_len > payload.len() {
        return Err(ForensicError::invalid_format(
            "SQLite",
            "SQLite record: header length exceeds payload",
        ));
    }

    let mut serial_types = Vec::new();
    let mut pos = header_len_size;
    while pos < header_len {
        let (serial_type, consumed) = read_varint(&payload[pos..])
            .ok_or_else(|| ForensicError::invalid_format("SQLite", "SQLite record: truncated serial type"))?;
        serial_types.push(serial_type);
        pos += consumed;
    }

    let mut values = Vec::with_capacity(serial_types.len());
    let mut body_pos = header_len;
    for serial_type in serial_types {
        let len = serial_type_len(serial_type)?;
        let end = body_pos
            .checked_add(len)
            .ok_or_else(|| ForensicError::invalid_format("SQLite", "SQLite record: value length overflow"))?;
        if end > payload.len() {
            return Err(ForensicError::invalid_format(
                "SQLite",
                "SQLite record: value runs past payload end",
            ));
        }
        values.push(decode_value(serial_type, &payload[body_pos..end]));
        body_pos = end;
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal record payload: one INTEGER(1) column holding `7`,
    /// one TEXT column holding `"hi"`.
    fn sample_payload() -> Vec<u8> {
        // header: header_len varint, then serial types 1 (int8), 15 (text len 1: (15-13)/2=1)
        // wait: text "hi" has length 2 -> serial type = 13 + 2*len = 13+4=17
        let mut buf = vec![0u8; 0];
        let serials = [1i64, 17i64]; // int8, text(len=2)
        let mut header_body = Vec::new();
        for s in serials {
            header_body.push(s as u8); // fits in one byte for these small values
        }
        let header_len = 1 + header_body.len(); // +1 for header_len varint itself (1 byte, since small)
        buf.push(header_len as u8);
        buf.extend_from_slice(&header_body);
        buf.push(7u8); // int8 value
        buf.extend_from_slice(b"hi"); // text value
        buf
    }

    #[test]
    fn decodes_int_and_text_columns() {
        let payload = sample_payload();
        let values = decode_record(&payload).unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], RecordValue::Integer(7));
        assert_eq!(values[1], RecordValue::Text(b"hi"));
    }

    #[test]
    fn null_and_constant_zero_one() {
        // serial types 0 (NULL), 8 (int 0), 9 (int 1) -- all zero-length bodies.
        let header_body = [0u8, 8u8, 9u8];
        let header_len = 1 + header_body.len();
        let mut buf = vec![header_len as u8];
        buf.extend_from_slice(&header_body);
        let values = decode_record(&buf).unwrap();
        assert_eq!(
            values,
            vec![RecordValue::Null, RecordValue::Integer(0), RecordValue::Integer(1)]
        );
    }

    #[test]
    fn rejects_truncated_value() {
        // Claims an 8-byte real but supplies none.
        let buf = vec![2u8, 7u8];
        assert!(decode_record(&buf).is_err());
    }

    #[test]
    fn decodes_utf8_text() {
        assert_eq!(decode_text("hello".as_bytes(), TextEncoding::Utf8), "hello");
    }

    #[test]
    fn decodes_utf16le_text() {
        let bytes: Vec<u8> = "hi".encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        assert_eq!(decode_text(&bytes, TextEncoding::Utf16Le), "hi");
    }

    #[test]
    fn f64_round_trip() {
        let mut buf = vec![2u8, 7u8];
        buf.extend_from_slice(&std::f64::consts::PI.to_be_bytes());
        let values = decode_record(&buf).unwrap();
        assert_eq!(values, vec![RecordValue::Real(std::f64::consts::PI)]);
    }
}
