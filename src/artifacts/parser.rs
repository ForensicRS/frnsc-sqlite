use forensic_rs::prelude::*;

use crate::artifacts::browser_history::{read_urls, read_visits, UrlRecord, VisitRecord};
use crate::sqlite::db::SqliteDb;

/// Glob patterns (forward-slash, per `forensic_rs::core::fs::glob`'s
/// convention -- see its own doc comment) for known Chromium-family
/// `History` database locations under a Windows user-profile tree. `*`
/// covers both the username and the profile directory (`Default`,
/// `Profile 1`, ...), since neither is fixed.
const HISTORY_GLOBS: [&str; 4] = [
    "Users/*/AppData/Local/Google/Chrome/User Data/*/History",
    "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History",
    "Users/*/AppData/Local/BraveSoftware/Brave-Browser/User Data/*/History",
    "Users/*/AppData/Local/Vivaldi/User Data/*/History",
];

/// The subset of the `urls`/`visits` schema [`crate::artifacts::browser_history`]
/// actually reads. Checked against every discovered database before it's
/// trusted as Chromium history -- the concrete answer to "a SQLite parser
/// is not a Chromium parser" (see `forensic_rs::traits::forensic::Requirement`'s
/// own doc comment): a same-named file with a different schema is a
/// detectable, reportable non-match instead of a silent all-zero/empty
/// read of columns that don't exist.
fn history_schema() -> SchemaFingerprint {
    SchemaFingerprint::new()
        .require_table(
            "urls",
            ["id", "url", "title", "visit_count", "typed_count", "last_visit_time", "hidden"],
        )
        .require_table("visits", ["id", "url", "visit_time", "from_visit", "transition", "visit_duration"])
}

/// Adapts [`crate::artifacts::browser_history`] to forensic-rs's
/// [`ArtifactParserFactory`] pipeline: discovers every Chrome/Edge
/// `History` database under `Users/*`, and emits one [`ForensicData`] per
/// `urls` row and per `visits` row, each carrying real provenance minted
/// from a source registered per discovered file.
///
/// Stateless (`&self`): all per-run state lives in a local inside
/// [`Self::open`], never in `self`, so one instance behind an `Arc` serves
/// the serial pipeline, every parallel worker, and every `AnalysisModule`
/// that needs it.
///
/// Everything is read eagerly into owned `Vec`s before `open()` returns
/// (`ParserRun::pull`, not `push`) -- simpler than a lazy per-row stream,
/// and a fair tradeoff at browser-history scale (thousands, not millions,
/// of rows per profile). A follow-up wanting lower peak memory on very
/// large history databases would switch to `ParserRun::push` and drive
/// `SqliteDb`'s row cursors directly instead.
pub struct BrowserHistoryParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for BrowserHistoryParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.browser_history",
                "Browser History",
                "Parses Chromium-family (Chrome/Edge) History SQLite databases: urls and visits",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![Artifact::Common(CommonArtifact::WebBrowsing(
                WebBrowsingArtifact::BrowserHistory,
            ))])
            .with_requirements(vec![Requirement::Database(history_schema())]),
        }
    }
}

impl BrowserHistoryParserFactory {
    pub fn new() -> Self {
        Self::default()
    }

    fn discover(ctx: &ParseContext<'_>) -> ForensicResult<Vec<FPathBuf>> {
        let fs = ctx.vfs().ok_or_else(|| {
            ForensicError::missing_data(
                "FileSystem source required",
                CompactString::const_new("BrowserHistoryParserFactory"),
            )
        })?;
        let mut found = Vec::new();
        for pattern in HISTORY_GLOBS {
            found.extend(fs.glob(pattern)?);
        }
        Ok(found)
    }
}

impl ArtifactParserFactory for BrowserHistoryParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        Self::discover(ctx).map(|paths| !paths.is_empty()).unwrap_or(false)
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let fs = ctx
            .vfs()
            .ok_or_else(|| {
                ForensicError::missing_data(
                    "FileSystem source required",
                    CompactString::const_new("BrowserHistoryParserFactory"),
                )
            })?
            .clone();
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let paths = Self::discover(ctx)?;
        let schema = history_schema();

        let mut records: Vec<ForensicResult<ForensicData>> = Vec::new();
        for path in paths {
            if ctx.is_cancelled() {
                break;
            }
            let path_str = path.to_string();
            let source = ctx.register_source(SourceKey::Path(path_str.clone()));

            // A profile directory matching the glob but not holding a
            // readable file (a locked live file, a partially-collected
            // triage artifact) or a well-formed SQLite database is a real
            // failure for *that* file, not a reason to silently discard it
            // -- it's reported via `records` so it surfaces in
            // `PipelineResult.errors`, while every other discovered
            // profile is still processed.
            let file = match fs.open(path.as_path()) {
                Ok(file) => file,
                Err(e) => {
                    records.push(Err(e.with_path(path_str)));
                    continue;
                }
            };
            let db = match SqliteDb::from_virtual_file(file) {
                Ok(db) => db,
                Err(e) => {
                    records.push(Err(e.with_path(path_str)));
                    continue;
                }
            };

            // A same-named file that isn't actually shaped like Chromium
            // history (a different app, a decoy) is not this parser's
            // data -- skip it quietly rather than reading absent columns
            // as silent zeros/empty strings.
            match schema.matches(&db) {
                Ok(true) => {}
                Ok(false) => {
                    forensic_rs::debug!(
                        "BrowserHistoryParserFactory: '{path_str}' does not match the Chromium History schema, skipping"
                    );
                    continue;
                }
                Err(e) => {
                    records.push(Err(e.with_path(path_str)));
                    continue;
                }
            }

            // Read independently: a failure in `visits` must not throw
            // away the `urls` this same file already yielded, and
            // vice versa.
            match read_urls(&db) {
                Ok(urls) => records.extend(urls.into_iter().map(|url| Ok(map_url(&host, &source, acquisition, url)))),
                Err(e) => records.push(Err(e.with_path(path_str.clone()))),
            }
            match read_visits(&db) {
                Ok(visits) => {
                    records.extend(visits.into_iter().map(|visit| Ok(map_visit(&host, &source, acquisition, visit))))
                }
                Err(e) => records.push(Err(e.with_path(path_str))),
            }
        }
        Ok(ParserRun::pull(records.into_iter()))
    }
}

fn map_url(host: &str, source: &SourceHandle, acquisition: Acquisition, url: UrlRecord) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(
        host,
        Artifact::Common(CommonArtifact::WebBrowsing(WebBrowsingArtifact::BrowserHistory)),
        provenance,
    );
    data.set("browser_history.record_type", "Url");
    data.set("browser_history.url.id", url.id);
    data.set("browser_history.url.url", url.url);
    data.set("browser_history.url.title", url.title);
    data.set("browser_history.url.visit_count", url.visit_count);
    data.set("browser_history.url.typed_count", url.typed_count);
    if let Some(ts) = url.last_visit_time {
        data.set("browser_history.url.last_visit_time", ts);
    }
    data.set("browser_history.url.hidden", url.hidden as u64);
    data
}

fn map_visit(host: &str, source: &SourceHandle, acquisition: Acquisition, visit: VisitRecord) -> ForensicData {
    let provenance = source.mint(acquisition, Recovery::Allocated);
    let mut data = ForensicData::new(
        host,
        Artifact::Common(CommonArtifact::WebBrowsing(WebBrowsingArtifact::BrowserHistory)),
        provenance,
    );
    data.set("browser_history.record_type", "Visit");
    data.set("browser_history.visit.id", visit.id);
    data.set("browser_history.visit.url_id", visit.url_id);
    if let Some(ts) = visit.visit_time {
        data.set("browser_history.visit.visit_time", ts);
    }
    if let Some(from_visit) = visit.from_visit {
        data.set("browser_history.visit.from_visit", from_visit);
    }
    data.set("browser_history.visit.transition", visit.transition);
    data.set("browser_history.visit.visit_duration", visit.visit_duration);
    data
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use forensic_rs::prelude::*;

    use super::BrowserHistoryParserFactory;

    fn load_vfs() -> Arc<dyn FileSystem> {
        Arc::new(ChRootFileSystem::new(
            "./artifacts/pipeline_fixture",
            Arc::new(StdVirtualFS::new()),
        ))
    }

    #[derive(Clone, Default)]
    struct RecordCollector(Arc<Mutex<Vec<ForensicData>>>);

    impl TriageSink for RecordCollector {
        fn name(&self) -> &str {
            "record_collector"
        }
        fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
            self.0.lock().unwrap().push(data.clone());
            Ok(())
        }
        fn on_finding(&mut self, _finding: &Finding) -> ForensicResult<()> {
            Ok(())
        }
    }

    #[test]
    fn discovers_and_parses_history_under_a_user_profile() {
        let fs = load_vfs();

        let context = TriageContext::new("TEST-HOST", "default");
        let store = context.provenance_store();
        let collector = RecordCollector::default();

        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Arc::new(BrowserHistoryParserFactory::new()))
            .sink(Box::new(collector.clone()))
            .build()
            .unwrap();

        let sources = TriageSources::builder()
            .vfs(fs)
            .acquisition(Acquisition::ImageRead)
            .build();
        let result = pipeline.run(&sources).unwrap();

        assert!(result.items_processed > 0);
        assert!(result.errors.is_empty());

        let records = collector.0.lock().unwrap();
        assert!(!records.is_empty());

        let mut record_types = std::collections::BTreeSet::new();
        for data in records.iter() {
            let confidence = data.confidence(&store);
            assert_ne!(confidence, Confidence::Unknown);
            if let Some(record_type) = data.field_as_str("browser_history.record_type") {
                record_types.insert(record_type.to_string());
            }
        }
        assert_eq!(
            record_types,
            std::collections::BTreeSet::from(["Url".to_string(), "Visit".to_string()])
        );
    }

    /// `artifacts/parser_error_fixture` has a real Chrome `History` next to
    /// a corrupt Edge one (200 zero bytes -- not a SQLite file at all).
    /// The corrupt file must surface as a `PipelineResult.errors` entry
    /// instead of silently vanishing, and must not stop the good Chrome
    /// profile from being parsed. Regression test for the "one bad file
    /// silently drops every other discovered profile" bug.
    #[test]
    fn a_corrupt_history_file_is_reported_not_silently_dropped() {
        let fs: Arc<dyn FileSystem> = Arc::new(ChRootFileSystem::new(
            "./artifacts/parser_error_fixture",
            Arc::new(StdVirtualFS::new()),
        ));

        let context = TriageContext::new("TEST-HOST", "default");
        let collector = RecordCollector::default();

        let mut pipeline = TriagePipeline::builder()
            .context(context)
            .parser(Arc::new(BrowserHistoryParserFactory::new()))
            .sink(Box::new(collector.clone()))
            .build()
            .unwrap();

        let sources = TriageSources::builder()
            .vfs(fs)
            .acquisition(Acquisition::ImageRead)
            .build();
        let result = pipeline.run(&sources).unwrap();

        assert!(
            !result.errors.is_empty(),
            "the corrupt Edge History must surface as a pipeline error"
        );

        let records = collector.0.lock().unwrap();
        assert!(
            !records.is_empty(),
            "the good Chrome History must still be parsed despite the corrupt Edge one"
        );
    }
}
