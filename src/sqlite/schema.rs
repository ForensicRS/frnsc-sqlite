//! Turns a `sqlite_schema`/`sqlite_master` row's `sql` text (a `CREATE
//! TABLE ...` statement) into column definitions, without a real SQL
//! parser or grammar -- SQLite's own type system barely needs one:
//! storage is dynamically typed per value (see
//! [`crate::sqlite::record`]), so a declared column type only matters for
//! *affinity* (a hint) and for detecting the one case that changes how a
//! row decodes: a single `INTEGER PRIMARY KEY` column aliases the cell's
//! rowid instead of storing its own value.
//! <https://www.sqlite.org/datatype3.html>
//!
//! Recognizes both the inline (`id INTEGER PRIMARY KEY`) and table-level
//! (`..., PRIMARY KEY(id)`) forms of a rowid-aliasing single-column integer
//! key, per <https://www.sqlite.org/lang_createtable.html#rowid>. In both
//! forms the aliasing column's declared type must be exactly `INTEGER`
//! (not `INT`, `BIGINT`, ...) and, for the inline form, not qualified
//! `DESC` (a documented SQLite quirk: `INTEGER PRIMARY KEY DESC` does *not*
//! alias the rowid).

use forensic_rs::err::{ForensicError, ForensicResult};
use forensic_rs::traits::db::ForensicColumnType;

#[derive(Debug, Clone)]
pub struct ColumnDef {
    pub name: String,
    pub col_type: ForensicColumnType,
    /// This column is `INTEGER PRIMARY KEY`: its stored serial type is
    /// always NULL and the real value is the cell's rowid.
    pub is_rowid_alias: bool,
    /// `false` when the column declaration includes `NOT NULL`. SQLite
    /// columns are nullable by default, so this defaults to `true`.
    pub nullable: bool,
}

/// Scans `s` for the top-level (paren-depth 0, outside any quoting) index
/// of the first occurrence of `target`, honoring `'`/`"`/`` ` ``/`[]`
/// quoting and `()` nesting the same way SQL itself does.
fn find_top_level(s: &str, target: char) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        if let Some(q) = quote {
            if c == q || (q == '[' && c == ']') {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '[' => quote = Some('['),
            // Checked before the literal '('/')' arms below: when `target`
            // is itself '(' or ')', those arms would otherwise intercept
            // every match and this branch would never fire.
            _ if depth == 0 && c == target => return Some(i),
            '(' => depth += 1,
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Split `s` on top-level commas (depth 0, outside quoting) -- the same
/// scanner as [`find_top_level`], generalized to collect every match
/// instead of just the first.
fn split_top_level_commas(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    let mut start = 0usize;
    for (i, c) in s.char_indices() {
        if let Some(q) = quote {
            if c == q || (q == '[' && c == ']') {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '[' => quote = Some('['),
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

fn strip_quotes(token: &str) -> String {
    let t = token.trim();
    let quoted = [('"', '"'), ('`', '`'), ('[', ']'), ('\'', '\'')];
    for (open, close) in quoted {
        if t.len() >= 2 && t.starts_with(open) && t.ends_with(close) {
            return t[1..t.len() - 1].to_string();
        }
    }
    t.to_string()
}

/// SQLite type-affinity rules: <https://www.sqlite.org/datatype3.html#determination_of_column_affinity>
fn affinity_of(declared_type: &str) -> ForensicColumnType {
    let t = declared_type.to_ascii_uppercase();
    if t.is_empty() || t.contains("BLOB") {
        ForensicColumnType::Binary
    } else if t.contains("INT") {
        ForensicColumnType::I64
    } else if t.contains("CHAR") || t.contains("CLOB") || t.contains("TEXT") {
        ForensicColumnType::Text
    } else if t.contains("REAL") || t.contains("FLOA") || t.contains("DOUB") {
        ForensicColumnType::F64
    } else {
        // NUMERIC affinity: could hold either at runtime; F64 covers both
        // without truncating an integer value read back through it (real
        // typing per row still comes from the record's own serial type,
        // this is metadata only).
        ForensicColumnType::F64
    }
}

const CONSTRAINT_KEYWORDS: [&str; 5] = ["PRIMARY", "UNIQUE", "CHECK", "FOREIGN", "CONSTRAINT"];

/// Tokens that end a column's *type* spec and begin its constraint
/// clauses. A declared type can be multiple words (`UNSIGNED BIG INT`,
/// `DOUBLE PRECISION`) -- everything from the column name's second token up
/// to the first of these is part of the type, not the type's own first
/// word only.
const TYPE_END_KEYWORDS: [&str; 9] = [
    "NOT",
    "NULL",
    "PRIMARY",
    "DEFAULT",
    "UNIQUE",
    "CHECK",
    "REFERENCES",
    "COLLATE",
    "GENERATED",
];

/// Extract the column names named by a table-level constraint's
/// parenthesized list, e.g. `PRIMARY KEY(a, b DESC)` -> `["a", "b"]`
/// (sort/collation qualifiers on each are ignored -- only the name is
/// needed to match it back up with a [`ColumnDef`]).
fn parse_constraint_columns(segment: &str) -> Option<Vec<String>> {
    let open = segment.find('(')?;
    let close = find_matching_close(segment, open)?;
    let inner = &segment[open + 1..close];
    Some(
        split_top_level_commas(inner)
            .into_iter()
            .filter_map(|part| tokenize(part.trim()).into_iter().next().map(|t| strip_quotes(&t)))
            .collect(),
    )
}

/// Parse a `CREATE TABLE` statement's column list into [`ColumnDef`]s, in
/// declaration order.
pub fn parse_create_table(sql: &str) -> ForensicResult<Vec<ColumnDef>> {
    let open = find_top_level(sql, '(')
        .ok_or_else(|| ForensicError::invalid_format("SQLite", "CREATE TABLE: no column list found"))?;
    let close = find_matching_close(sql, open)
        .ok_or_else(|| ForensicError::invalid_format("SQLite", "CREATE TABLE: unbalanced parentheses"))?;
    let body = &sql[open + 1..close];

    let mut columns = Vec::new();
    // Parallel to `columns`: whether that column's declared type is
    // *exactly* `INTEGER` (not just INTEGER-affinity) -- the requirement
    // for a table-level `PRIMARY KEY(col)` to alias the rowid, resolved
    // once every column has been seen.
    let mut exact_integer = Vec::new();
    let mut table_level_pk_cols: Option<Vec<String>> = None;

    for segment in split_top_level_commas(body) {
        let segment = segment.trim();
        if segment.is_empty() {
            continue;
        }
        let tokens = tokenize(segment);
        let Some(first) = tokens.first() else { continue };
        if CONSTRAINT_KEYWORDS.contains(&first.to_ascii_uppercase().as_str()) {
            if first.eq_ignore_ascii_case("PRIMARY") {
                table_level_pk_cols = parse_constraint_columns(segment);
            }
            continue; // table-level constraint, not a column
        }
        let name = strip_quotes(first);
        let type_tokens: Vec<&str> = tokens[1..]
            .iter()
            .map(String::as_str)
            .take_while(|t| !TYPE_END_KEYWORDS.contains(&t.to_ascii_uppercase().as_str()))
            .collect();
        let declared_type = type_tokens.join(" ");
        // Only the part before an optional length/precision spec, e.g.
        // "VARCHAR(255)" -> "VARCHAR".
        let type_name = declared_type.split('(').next().unwrap_or("").trim();
        let is_integer_exact = type_name.eq_ignore_ascii_case("INTEGER");

        let mut has_primary_key = false;
        for (i, w) in tokens.windows(2).enumerate() {
            if w[0].eq_ignore_ascii_case("PRIMARY") && w[1].eq_ignore_ascii_case("KEY") {
                // "INTEGER PRIMARY KEY DESC" is documented to *not* alias
                // the rowid, unlike the bare or "... ASC" forms.
                let followed_by_desc = tokens.get(i + 2).is_some_and(|t| t.eq_ignore_ascii_case("DESC"));
                has_primary_key = !followed_by_desc;
                break;
            }
        }
        let not_null = tokens
            .windows(2)
            .any(|w| w[0].eq_ignore_ascii_case("NOT") && w[1].eq_ignore_ascii_case("NULL"));

        exact_integer.push(is_integer_exact);
        columns.push(ColumnDef {
            name,
            col_type: affinity_of(type_name),
            is_rowid_alias: is_integer_exact && has_primary_key,
            nullable: !not_null,
        });
    }

    // A table-level `PRIMARY KEY(col)` aliases the rowid under the same
    // rule as the inline form: exactly one column, declared type exactly
    // `INTEGER`. A composite key (more than one column) never aliases.
    if let Some(pk_cols) = table_level_pk_cols {
        if let [only] = pk_cols.as_slice() {
            if let Some(idx) = columns.iter().position(|c| c.name.eq_ignore_ascii_case(only)) {
                if exact_integer[idx] {
                    columns[idx].is_rowid_alias = true;
                }
            }
        }
    }

    Ok(columns)
}

fn find_matching_close(s: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices().skip(open_idx) {
        if let Some(q) = quote {
            if c == q || (q == '[' && c == ']') {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => quote = Some(c),
            '[' => quote = Some('['),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Whitespace tokenizer that keeps a quoted identifier (`"..."`, `` `...` ``,
/// `[...]`) as a single token with its quotes intact (stripped later by
/// [`strip_quotes`]), and keeps a `NAME(len)` type spec joined as one token.
fn tokenize(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut paren_depth = 0i32;
    for c in segment.chars() {
        if let Some(q) = quote {
            current.push(c);
            if c == q || (q == '[' && c == ']') {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' | '`' => {
                quote = Some(c);
                current.push(c);
            }
            '[' => {
                quote = Some('[');
                current.push(c);
            }
            '(' => {
                paren_depth += 1;
                current.push(c);
            }
            ')' => {
                paren_depth -= 1;
                current.push(c);
            }
            c if c.is_whitespace() && paren_depth == 0 => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chromium_urls_style_table() {
        let sql = "CREATE TABLE urls(id INTEGER PRIMARY KEY,url LONGVARCHAR,title LONGVARCHAR,visit_count INTEGER DEFAULT 0,hidden INTEGER DEFAULT 0)";
        let cols = parse_create_table(sql).unwrap();
        assert_eq!(cols.len(), 5);
        assert_eq!(cols[0].name, "id");
        assert!(cols[0].is_rowid_alias);
        assert_eq!(cols[0].col_type, ForensicColumnType::I64);
        assert_eq!(cols[1].name, "url");
        assert_eq!(cols[1].col_type, ForensicColumnType::Text);
        assert!(!cols[1].is_rowid_alias);
    }

    #[test]
    fn skips_table_level_constraints() {
        let sql = "CREATE TABLE t (a INTEGER, b TEXT, PRIMARY KEY(a, b))";
        let cols = parse_create_table(sql).unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].name, "a");
        // Composite key: neither column is a rowid alias.
        assert!(!cols[0].is_rowid_alias);
    }

    #[test]
    fn handles_quoted_column_names() {
        let sql = r#"CREATE TABLE "my table" ("my col" TEXT, [other] BLOB)"#;
        let cols = parse_create_table(sql).unwrap();
        assert_eq!(cols[0].name, "my col");
        assert_eq!(cols[1].name, "other");
        assert_eq!(cols[1].col_type, ForensicColumnType::Binary);
    }

    #[test]
    fn comma_inside_default_expression_is_not_a_split_point() {
        let sql = "CREATE TABLE t (a TEXT DEFAULT 'x,y', b INTEGER)";
        let cols = parse_create_table(sql).unwrap();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[1].name, "b");
    }

    #[test]
    fn rejects_missing_column_list() {
        assert!(parse_create_table("CREATE TABLE t").is_err());
    }

    #[test]
    fn multi_word_type_names_get_the_right_affinity() {
        let sql = "CREATE TABLE t (a UNSIGNED BIG INT, b DOUBLE PRECISION)";
        let cols = parse_create_table(sql).unwrap();
        assert_eq!(cols[0].col_type, ForensicColumnType::I64);
        assert_eq!(cols[1].col_type, ForensicColumnType::F64);
    }

    #[test]
    fn table_level_single_column_integer_primary_key_aliases_the_rowid() {
        let sql = "CREATE TABLE t (id INTEGER, name TEXT, PRIMARY KEY(id))";
        let cols = parse_create_table(sql).unwrap();
        assert!(cols[0].is_rowid_alias);
        assert!(!cols[1].is_rowid_alias);
    }

    #[test]
    fn table_level_primary_key_on_a_non_integer_column_does_not_alias() {
        let sql = "CREATE TABLE t (id TEXT, PRIMARY KEY(id))";
        let cols = parse_create_table(sql).unwrap();
        assert!(!cols[0].is_rowid_alias);
    }

    #[test]
    fn integer_primary_key_desc_does_not_alias_the_rowid() {
        let sql = "CREATE TABLE t (id INTEGER PRIMARY KEY DESC, name TEXT)";
        let cols = parse_create_table(sql).unwrap();
        assert!(!cols[0].is_rowid_alias, "DESC-qualified INTEGER PRIMARY KEY must not alias the rowid");
    }

    #[test]
    fn not_null_columns_are_reported_as_non_nullable() {
        let sql = "CREATE TABLE t (a TEXT NOT NULL, b TEXT)";
        let cols = parse_create_table(sql).unwrap();
        assert!(!cols[0].nullable);
        assert!(cols[1].nullable);
    }
}
