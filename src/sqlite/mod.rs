//! Pure-Rust SQLite file-format engine: header, page reader, varint/record
//! decoding, table b-tree walking, schema (`CREATE TABLE`) parsing, and the
//! `forensic_rs::traits::db`/`traits::format` bridges on top.
//!
//! Layering mirrors `frnsc-esedb::ese`: [`db`] is the engine entry point
//! ([`db::SqliteDb`]), [`forensic_db`] implements the generic
//! `ForensicDb`/`ForensicTable`/`ForensicRows` traits, and [`factory`]
//! implements `FormatFactory` so a triage pipeline can auto-mount any
//! SQLite file without artifact-specific code.

pub mod btree;
pub mod db;
pub mod factory;
pub mod forensic_db;
pub mod format;
pub mod reader;
pub mod record;
pub(crate) mod recovery;
pub mod schema;
pub mod varint;
