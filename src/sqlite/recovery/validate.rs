//! Shared admission gate for recovered SQLite rows: forensic-rs's checklist
//! rule 2 ("not `Nil`" is not an admission bar) applied to `ForensicValue`.
//! <https://docs.rs/forensic-rs> `recovery` module doc comment has the full
//! checklist; this is rule 2 as code.

use forensic_rs::recovery::looks_like_padding;
use forensic_rs::traits::db::ForensicValue;

use crate::sqlite::schema::ColumnDef;

/// Whether `value` carries content distinguishable from unwritten padding.
/// A decoded zero, empty string, or all-`0xFF` blob is indistinguishable
/// from padding that merely happens to parse -- see
/// [`forensic_rs::recovery::looks_like_padding`]'s own doc comment.
fn is_meaningful(value: &ForensicValue) -> bool {
    match value {
        ForensicValue::Null => false,
        ForensicValue::Bool(b) => *b,
        ForensicValue::I64(n) => *n != 0,
        ForensicValue::U64(n) => *n != 0,
        ForensicValue::F64(f) => *f != 0.0,
        // A `DateTime` is a WebKit/Unix timestamp decoded from a non-zero
        // `INTEGER` cell value (see `crate::sqlite::record`); this crate
        // never itself produces a "zero" `DateTime` variant to worry about
        // conflating with padding.
        ForensicValue::DateTime(_) => true,
        ForensicValue::Guid(g) => g.iter().any(|&b| b != 0),
        ForensicValue::Text(s) => !looks_like_padding(s.as_bytes(), 1),
        ForensicValue::Binary(b) => !looks_like_padding(b, 1),
    }
}

/// Count of columns -- excluding a rowid-alias column, whose value is
/// synthesized from the cell header rather than stored as bytes -- carrying
/// content distinguishable from unwritten padding.
pub(crate) fn meaningful_column_count(row: &[ForensicValue], columns: &[ColumnDef]) -> usize {
    row.iter()
        .zip(columns)
        .filter(|(value, column)| !column.is_rowid_alias && is_meaningful(value))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use forensic_rs::traits::db::ForensicColumnType;

    fn col(name: &str, rowid_alias: bool) -> ColumnDef {
        ColumnDef {
            name: name.to_string(),
            col_type: ForensicColumnType::Text,
            is_rowid_alias: rowid_alias,
            nullable: true,
        }
    }

    #[test]
    fn all_zero_and_empty_row_has_no_meaningful_columns() {
        let columns = [col("id", true), col("url", false), col("hidden", false)];
        let row = [ForensicValue::I64(0), ForensicValue::Text(String::new()), ForensicValue::I64(0)];
        assert_eq!(meaningful_column_count(&row, &columns), 0);
    }

    #[test]
    fn a_real_url_counts_as_meaningful_but_the_rowid_alias_never_does() {
        let columns = [col("id", true), col("url", false)];
        let row = [ForensicValue::I64(42), ForensicValue::Text("https://example.test".into())];
        assert_eq!(meaningful_column_count(&row, &columns), 1);
    }

    #[test]
    fn an_all_zero_byte_string_is_treated_as_padding() {
        let columns = [col("url", false)];
        let row = [ForensicValue::Text("\0\0\0\0".to_string())];
        assert_eq!(meaningful_column_count(&row, &columns), 0);
    }

    #[test]
    fn an_all_0xff_blob_is_treated_as_padding() {
        let columns = [col("data", false)];
        let row = [ForensicValue::Binary(vec![0xFFu8; 8])];
        assert_eq!(meaningful_column_count(&row, &columns), 0);
    }
}
