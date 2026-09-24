//! Chromium-schema (Chrome/Edge) `History` database: `urls` and `visits`
//! tables.
//!
//! Written entirely against the generic
//! [`forensic_rs::traits::db::ForensicDb`] trait, never against
//! [`crate::sqlite`] directly -- the same split
//! `forensic_rs::traits::forensic`'s own doc comment describes: "a SQLite
//! parser is not a Chromium parser." Any `ForensicDb` backend with a
//! schema-compatible `urls`/`visits` table pair would work here, not just
//! this crate's SQLite engine.
//!
//! Schema reference (stable across Chrome/Edge/Chromium versions for the
//! columns read here): `chromium/src/components/history/core/browser/history_database.cc`.

use forensic_rs::err::ForensicResult;
use forensic_rs::traits::db::{ForensicDb, ForensicRows};
use forensic_rs::utils::time::ForensicTimestamp;

#[derive(Debug, Clone, Default)]
pub struct UrlRecord {
    /// `urls.id` -- referenced by [`VisitRecord::url_id`].
    pub id: i64,
    pub url: String,
    pub title: String,
    pub visit_count: i64,
    pub typed_count: i64,
    /// `None` when the stored value is `0` (Chromium's "never visited"
    /// sentinel), not a real WebKit-epoch timestamp.
    pub last_visit_time: Option<ForensicTimestamp>,
    pub hidden: bool,
}

#[derive(Debug, Clone, Default)]
pub struct VisitRecord {
    pub id: i64,
    /// Foreign key into `urls.id`.
    pub url_id: i64,
    pub visit_time: Option<ForensicTimestamp>,
    /// The visit that navigated to this one, if any (`0`/absent = none).
    pub from_visit: Option<i64>,
    /// Raw Chromium `PageTransition` bitmask -- left undecoded here; the
    /// core type (navigation kind + qualifier flags) is caller-specific
    /// enough that decoding it belongs at the point of use, not baked into
    /// this record.
    pub transition: i64,
    /// Microseconds.
    pub visit_duration: i64,
}

fn read_i64(rows: &dyn ForensicRows, name: &str) -> i64 {
    rows.read_named(name).ok().and_then(|v| v.as_i64()).unwrap_or(0)
}

fn read_str(rows: &dyn ForensicRows, name: &str) -> String {
    rows.read_named(name)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn read_bool(rows: &dyn ForensicRows, name: &str) -> bool {
    rows.read_named(name).ok().and_then(|v| v.as_bool()).unwrap_or(false)
}

fn webkit_timestamp(micros: i64) -> Option<ForensicTimestamp> {
    if micros == 0 {
        None
    } else {
        Some(ForensicTimestamp::from_webkit(micros))
    }
}

/// Read every row of the `urls` table.
pub fn read_urls(db: &dyn ForensicDb) -> ForensicResult<Vec<UrlRecord>> {
    let table = db.table("urls")?;
    let mut rows = table.iter_rows()?;
    let mut out = Vec::new();
    while rows.next()? {
        out.push(UrlRecord {
            id: read_i64(rows.as_ref(), "id"),
            url: read_str(rows.as_ref(), "url"),
            title: read_str(rows.as_ref(), "title"),
            visit_count: read_i64(rows.as_ref(), "visit_count"),
            typed_count: read_i64(rows.as_ref(), "typed_count"),
            last_visit_time: webkit_timestamp(read_i64(rows.as_ref(), "last_visit_time")),
            hidden: read_bool(rows.as_ref(), "hidden"),
        });
    }
    Ok(out)
}

/// Read every row of the `visits` table.
pub fn read_visits(db: &dyn ForensicDb) -> ForensicResult<Vec<VisitRecord>> {
    let table = db.table("visits")?;
    let mut rows = table.iter_rows()?;
    let mut out = Vec::new();
    while rows.next()? {
        let from_visit = read_i64(rows.as_ref(), "from_visit");
        out.push(VisitRecord {
            id: read_i64(rows.as_ref(), "id"),
            url_id: read_i64(rows.as_ref(), "url"),
            visit_time: webkit_timestamp(read_i64(rows.as_ref(), "visit_time")),
            from_visit: if from_visit == 0 { None } else { Some(from_visit) },
            transition: read_i64(rows.as_ref(), "transition"),
            visit_duration: read_i64(rows.as_ref(), "visit_duration"),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::db::SqliteDb;

    #[test]
    fn reads_urls_and_visits_from_the_real_fixture() {
        let Ok(db) = SqliteDb::open("artifacts/chrome_history_sample/History") else {
            eprintln!("SKIP: fixture unavailable");
            return;
        };
        let urls = read_urls(&db).unwrap();
        assert_eq!(urls.len(), 800);
        assert_eq!(urls[0].id, 1);
        assert_eq!(urls[0].url, "https://example0.test/path/0?q=0");
        assert!(urls[0].last_visit_time.is_some());
        assert!(!urls[0].hidden);

        let visits = read_visits(&db).unwrap();
        assert_eq!(visits.len(), 800);
        assert_eq!(visits[0].url_id, 1);
        assert!(visits[0].from_visit.is_none());
    }
}
