//! Deleted-row recovery: bytes SQLite has not yet overwritten but that no
//! longer show up in ordinary iteration.
//!
//! Two independent sources, both read-only inspection of already-on-disk
//! bytes, decoded through the exact same
//! [`crate::sqlite::record::decode_record`] +
//! [`crate::sqlite::db::decode_row`] path live iteration uses -- never a
//! speculative reconstruction:
//!
//! - [`freelist::recover_freelist_rows`] -- a whole table-leaf page that
//!   SQLite's own freelist marks as no longer part of any b-tree, but whose
//!   bytes have not been overwritten yet. Governed by real database
//!   metadata (the freelist trunk chain), so admitted at
//!   `Recovery::DeletedMetadata`.
//! - [`slack::recover_slack_rows`] -- candidate cells found in the trailing,
//!   never-allocated gap on a *live* leaf page (the span between where the
//!   cell-pointer array currently ends and where the cell-content area
//!   currently begins). No governing marker at all, so admitted at
//!   `Recovery::Slack` with a stricter admission bar (see its own module
//!   doc comment).
//!
//! Both share the admission gate in [`validate`]: forensic-rs's checklist
//! rule 2 ("not `Nil`" is not an admission bar) applied to `ForensicValue`.
//!
//! # Known limitations of this first pass (tracked in `ROADMAP.md`)
//!
//! - **Freeblocks are not walked.** A deleted cell's bytes *within* the
//!   already-used cell-content area (unlinked from the cell pointer array
//!   via SQLite's own freeblock chain, but not physically moved) are real,
//!   structured evidence of their own -- a natural follow-up to
//!   [`slack`], which today only scans the trailing never-allocated gap.
//! - **A freed page is validated only against the table the caller asked
//!   for.** There is no way to know, from a freed page's bytes alone,
//!   which table it originally belonged to (SQLite doesn't tag pages with
//!   an owning table). A page that coincidentally decodes cleanly against
//!   more than one table's schema is reported once per matching table a
//!   caller checks -- an examiner correlating `recovered_rows` results
//!   across every table should be aware a single freed page can surface
//!   more than once.
//! - **Overflow chains are trusted from a freelist page, not from slack.**
//!   [`freelist`] reuses [`crate::sqlite::btree::read_leaf_cells`]
//!   unmodified, so a freed cell's overflow chain is followed exactly like
//!   a live cell's (and an overflow page that has itself been reused since
//!   is caught by that function's own per-cell skip, not specially
//!   detected here). [`slack`] never follows one at all -- see its own
//!   module doc comment for why.
//! - **No WAL awareness.** A row deleted, then checkpointed, only ever
//!   shows up here if the freed/slack bytes in the *main* database file
//!   still hold it; a deletion recorded only in an unreplayed `-wal` is
//!   invisible to this pass (see `sqlite::factory::SqliteWalSetFactory`'s
//!   own doc comment and `ROADMAP.md`).

pub(crate) mod freelist;
pub(crate) mod slack;
mod validate;

use forensic_rs::traits::db::ForensicValue;

/// One row recovered from a source other than ordinary, live iteration.
/// [`forensic_rs::recovery::Recovered`] carries the two things a recovered
/// value must never travel without: *how* it was located
/// ([`forensic_rs::provenance::Recovery`]) and *exactly which bytes* it
/// came from ([`forensic_rs::provenance::Locus`]). Deliberately no
/// `Deref` -- reach the row through `value()`/`into_value()`, so dropping
/// the recovery mode is visible in review rather than implicit.
pub(crate) type RecoveredRow = forensic_rs::recovery::Recovered<(i64, Vec<ForensicValue>)>;

/// Scan-level counters for one recovery pass, converted to the framework's
/// [`forensic_rs::recovery::RecoveryReport`] via [`RecoveryStats::to_report`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RecoveryStats {
    pub pages_scanned: usize,
    pub candidates_found: usize,
    pub rows_recovered: usize,
    /// A candidate that failed the admission gate ([`validate`]) --
    /// silently dropped, not reported at lower confidence.
    pub rows_rejected: usize,
    pub pages_unreadable: usize,
}

impl RecoveryStats {
    /// Convert to the framework's scan-level diagnostics shape, for
    /// `ForensicRows::scan_report()`. Field-for-field: `pages_scanned` is
    /// "units walked" (this crate's unit is a page), `candidates_found` is
    /// candidates, `rows_recovered`/`rows_rejected` are admitted/rejected,
    /// and `pages_unreadable` is unreadable.
    pub(crate) fn to_report(self) -> forensic_rs::recovery::RecoveryReport {
        forensic_rs::recovery::RecoveryReport {
            units_scanned: self.pages_scanned as u64,
            candidates_found: self.candidates_found as u64,
            admitted: self.rows_recovered as u64,
            rejected: self.rows_rejected as u64,
            unreadable: self.pages_unreadable as u64,
        }
    }
}
