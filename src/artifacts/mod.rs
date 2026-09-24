//! Typed readers for specific SQLite-backed artifacts, layered on top of
//! [`crate::sqlite`]'s generic engine -- one module per artifact, each
//! exposing a record struct + iterator plus an `ArtifactParserFactory`
//! pipeline adapter, following `frnsc-amcache`'s
//! `src/common/<name>.rs` + `src/parser.rs` pattern.

pub mod browser_history;
pub mod parser;
