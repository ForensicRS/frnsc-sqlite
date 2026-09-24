//! Pure-Rust SQLite database reader for the [ForensicRS](https://github.com/ForensicRS)
//! ecosystem, implementing `forensic_rs`'s `ForensicDb`/`FormatFactory`
//! traits, with typed browser-artifact readers on top.
//!
//! See [`sqlite`] for the generic engine and [`artifacts`] for the typed
//! readers.

pub mod artifacts;
pub mod sqlite;
