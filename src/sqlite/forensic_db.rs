//! `forensic_rs::traits::db` bridge for SQLite databases.
//!
//! Implements `ForensicDb`/`ForensicTable`/`ForensicRows` on top of
//! [`SqliteDb`], the same role `frnsc-esedb::ese::forensic_db` plays for
//! ESE. `SqlCapable` (real `SELECT` execution) is deliberately **not**
//! implemented, for the same reason `frnsc-esedb` skips it: named-table
//! access via `ForensicDb::table(name)` is enough for every artifact this
//! crate targets, and a hand-rolled SQL subset parser is a liability, not a
//! feature.
//!
//! `RecoverRows` **is** implemented (`recovered_rows`/`slack_rows`) -- see
//! [`crate::sqlite::recovery`] for the two sources and their soundness
//! rationale. `row_history` stays at the trait's `EmptyRows` default: it
//! is documented as rows recovered by *replaying a transaction log*, which
//! this crate does not do (no WAL replay yet -- see `ROADMAP.md`).

use forensic_rs::err::ForensicResult;
use forensic_rs::provenance::{Locus, Recovery};
use forensic_rs::recovery::RecoveryReport;
use forensic_rs::traits::db::{
    ForensicColumnDef, ForensicColumnType, ForensicDb, ForensicRows, ForensicTable, ForensicValueRef, RecoverRows,
};

use crate::sqlite::db::{RowIter, SqliteDb, Table};
use crate::sqlite::recovery::{freelist, slack, RecoveredRow, RecoveryStats};
use crate::sqlite::schema::ColumnDef;

impl ForensicDb for SqliteDb {
    fn list_tables(&self) -> ForensicResult<Vec<String>> {
        Ok(self.table_names().into_iter().map(str::to_owned).collect())
    }

    fn table(&self, name: &str) -> ForensicResult<Box<dyn ForensicTable + '_>> {
        Ok(Box::new(SqliteDb::table(self, name)?))
    }

    fn as_recovery(&self) -> Option<&dyn RecoverRows> {
        Some(self)
    }
}

impl RecoverRows for SqliteDb {
    /// Rows recovered from a table-leaf page SQLite's freelist marks as
    /// freed. See [`freelist::recover_freelist_rows`] for the soundness
    /// rationale (governed by real database metadata, so
    /// `Recovery::DeletedMetadata`).
    fn recovered_rows(&self, table: &str) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        let columns = SqliteDb::table(self, table)?.internal_columns();
        let (rows, stats) = freelist::recover_freelist_rows(self, table)?;
        Ok(Box::new(RecoveredSqliteRows::new(rows, columns, Recovery::DeletedMetadata, stats)))
    }

    /// Candidate rows found in a live page's unallocated slack. See
    /// [`slack::recover_slack_rows`] for why this source applies a
    /// stricter admission bar than [`Self::recovered_rows`].
    fn slack_rows(&self, table: &str) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        let columns = SqliteDb::table(self, table)?.internal_columns();
        let (rows, stats) = slack::recover_slack_rows(self, table)?;
        Ok(Box::new(RecoveredSqliteRows::new(rows, columns, Recovery::Slack, stats)))
    }
}

impl<'db> ForensicTable for Table<'db> {
    fn name(&self) -> &str {
        Table::name(self)
    }

    fn columns(&self) -> &[ForensicColumnDef] {
        Table::forensic_columns(self)
    }

    fn iter_rows(&self) -> ForensicResult<Box<dyn ForensicRows + '_>> {
        Ok(Box::new(SqliteRows {
            inner: Table::iter_rows(self)?,
        }))
    }

    // `row_count()` intentionally stays at the trait's `None` default:
    // getting a real count means walking every leaf page up front, which
    // would turn this crate's lazy, page-at-a-time table open into an
    // eager full scan for a number most callers never ask for.
}

/// Wraps [`RowIter`] to implement [`ForensicRows`]. `RowIter` already
/// decodes each row into owned `ForensicValue`s at `next_row()` time (see
/// its doc comment in `db.rs`), so `read_ref` here is just an index into
/// that row via `ForensicValue::as_ref()` -- zero-copy relative to the
/// decoded row, though not relative to the original page bytes.
struct SqliteRows<'db> {
    inner: RowIter<'db>,
}

impl<'db> ForensicRows for SqliteRows<'db> {
    fn column_count(&self) -> usize {
        self.inner.columns().len()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        self.inner.columns().get(i).map(|c| c.name.as_str())
    }

    fn column_names(&self) -> Vec<&str> {
        self.inner.columns().iter().map(|c| c.name.as_str()).collect()
    }

    fn column_type(&self, i: usize) -> ForensicColumnType {
        self.inner
            .columns()
            .get(i)
            .map(|c| c.col_type)
            .unwrap_or(ForensicColumnType::Null)
    }

    fn next(&mut self) -> ForensicResult<bool> {
        self.inner.next_row()
    }

    fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>> {
        let (_, values) = self
            .inner
            .current_row()
            .ok_or_else(forensic_rs::err::ForensicError::no_more_data)?;
        let value = values.get(i).ok_or_else(|| {
            forensic_rs::err::ForensicError::missing_data("column", format!("column index {i} out of range").into())
        })?;
        Ok(value.as_ref())
    }

    /// The current row's `(leaf page, cell slot)` address, so a recovered
    /// or disputed row can be pointed back at its exact bytes instead of
    /// collapsing onto [`Locus::Api`].
    fn locus(&self) -> Option<Locus> {
        self.inner
            .current_locus()
            .map(|(page, slot)| Locus::Record { page: page as u64, slot })
    }
}

/// Wraps a `Vec<RecoveredRow>` (already fully computed by
/// [`freelist::recover_freelist_rows`]/[`slack::recover_slack_rows`] before
/// this cursor is even constructed) to implement [`ForensicRows`]. Every
/// row this cursor yields comes from the *same* recovery source, so
/// `allocated()`/`recovery()` are one constant value for the whole cursor
/// rather than varying per row.
struct RecoveredSqliteRows<'db> {
    columns: &'db [ColumnDef],
    rows: std::vec::IntoIter<RecoveredRow>,
    recovery: Recovery,
    /// How much ground the scan behind this cursor's rows covered -- see
    /// [`Self::scan_report`]. Unlike `recovery`, this is diagnostic, not
    /// part of any one row's own trustworthiness.
    stats: RecoveryStats,
    current: Option<RecoveredRow>,
}

impl<'db> RecoveredSqliteRows<'db> {
    fn new(rows: Vec<RecoveredRow>, columns: &'db [ColumnDef], recovery: Recovery, stats: RecoveryStats) -> Self {
        Self {
            columns,
            rows: rows.into_iter(),
            recovery,
            stats,
            current: None,
        }
    }
}

impl<'db> ForensicRows for RecoveredSqliteRows<'db> {
    fn column_count(&self) -> usize {
        self.columns.len()
    }

    fn column_name(&self, i: usize) -> Option<&str> {
        self.columns.get(i).map(|c| c.name.as_str())
    }

    fn column_names(&self) -> Vec<&str> {
        self.columns.iter().map(|c| c.name.as_str()).collect()
    }

    fn column_type(&self, i: usize) -> ForensicColumnType {
        self.columns.get(i).map(|c| c.col_type).unwrap_or(ForensicColumnType::Null)
    }

    fn next(&mut self) -> ForensicResult<bool> {
        self.current = self.rows.next();
        Ok(self.current.is_some())
    }

    fn read_ref(&self, i: usize) -> ForensicResult<ForensicValueRef<'_>> {
        let recovered = self
            .current
            .as_ref()
            .ok_or_else(forensic_rs::err::ForensicError::no_more_data)?;
        let (_, values) = recovered.value();
        let value = values.get(i).ok_or_else(|| {
            forensic_rs::err::ForensicError::missing_data("column", format!("column index {i} out of range").into())
        })?;
        Ok(value.as_ref())
    }

    fn allocated(&self) -> bool {
        false
    }

    fn recovery(&self) -> Recovery {
        self.recovery
    }

    fn locus(&self) -> Option<Locus> {
        self.current.as_ref().map(RecoveredRow::locus)
    }

    fn scan_report(&self) -> Option<RecoveryReport> {
        Some(self.stats.to_report())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::db::SqliteDb;

    /// Drives recovery through the actual public entry point
    /// (`ForensicDb::as_recovery`), not the `sqlite::recovery` module
    /// functions directly -- that module's own tests already exercise the
    /// recovery logic itself (including a hand-built fixture with a
    /// genuinely freed/slack-planted row); this one is about the trait
    /// wiring above staying correct.
    #[test]
    fn recover_rows_is_reachable_through_the_forensic_db_trait() {
        let Ok(db) = SqliteDb::open("artifacts/chrome_history_sample/History") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let dyn_db: &dyn ForensicDb = &db;
        let recovery = dyn_db.as_recovery().expect("SqliteDb must report recovery support");

        let mut rows = recovery.recovered_rows("urls").unwrap();
        assert!(!rows.allocated());
        assert_eq!(rows.recovery(), Recovery::DeletedMetadata);
        assert!(rows.scan_report().is_some());
        // The fixture is freshly generated with an empty freelist (see
        // `sqlite::recovery::freelist`'s own tests), so no rows are
        // expected here -- this test is about the trait wiring, not the
        // recovery logic itself.
        assert!(!rows.next().unwrap());

        let mut slack_rows = recovery.slack_rows("urls").unwrap();
        assert_eq!(slack_rows.recovery(), Recovery::Slack);
        assert!(slack_rows.scan_report().is_some());
        // Don't assert on how many (if any) candidates a real-world page's
        // incidental trailing gap turns up -- just exercise the read path
        // without panicking.
        while slack_rows.next().unwrap() {
            let _ = slack_rows.read(0);
        }
    }
}
