//! Project knowledge base backed by `hf-knowledge` (BM25 retrieval).
//!
//! Indexes a project's source files into a per-project [`HybridRetriever`] so
//! the GUI Knowledge view and the agent's `KnowledgeSearch` tool can search the
//! codebase. The index is held in a process-global cache keyed by project path;
//! changed entries refresh on demand via [`index_project`] and [`search_project_ensured`].
//!
//! hf-knowledge's tokenizer targets natural language: it strips code punctuation
//! without splitting on it (so `copy_chunk(const` becomes one mangled token). We
//! therefore index a *code-normalized* copy of each chunk (punctuation -> spaces)
//! and normalize queries the same way, while keeping the original text for the
//! snippet shown to the user.

mod indexing;
#[cfg(test)]
mod refresh_tests;
mod storage;
pub(crate) use storage::KnowledgeOperation;

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use hf_core::embedding::EmbeddingProvider;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetCandidate;
use hf_knowledge::chunking::{Chunk, ChunkLevel, ChunkMetadata, ChunkingStrategy};
use hf_knowledge::config::KnowledgeConfig;
use hf_knowledge::retrieval::{HybridRetriever, RetrievalConfig, RetrievalFilter, SearchStrategy};
use hf_knowledge::tokenizer::AutoTokenizer;
use hf_prompt::RelatedContext;
use serde::Serialize;

/// A built per-project index: the BM25 retriever (over normalized text) plus a
/// map from chunk id to the original source text for display.
#[derive(Clone)]
struct ProjectIndex {
    retriever: HybridRetriever<AutoTokenizer>,
    originals: HashMap<String, String>,
    /// Source-file count at index time, reported by [`stats_project`].
    files: usize,
    /// Chunk count at index time.
    chunks: usize,
    /// When this index was built.
    indexed_at: chrono::DateTime<chrono::Utc>,
    generation: String,
    entries: std::collections::BTreeMap<String, indexing::IndexedEntry>,
    config_digest: String,
    effective: KnowledgeConfiguration,
    embedder: Option<Arc<dyn EmbeddingProvider>>,
    warnings: Vec<String>,
    embedding_warning: Option<String>,
    query_warning: Arc<Mutex<Option<String>>>,
}

/// Process-global per-project index cache.
fn cache() -> &'static Mutex<HashMap<PathBuf, Arc<ProjectIndex>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<ProjectIndex>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Source/document extensions worth indexing for a fuzzing project.
const KNOWLEDGE_EXTS: &[&str] = &[
    "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "rs", "go", "py", "md", "txt",
];

/// Stats returned after (re)indexing a project.
#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeStats {
    pub files: usize,
    pub chunks: usize,
    /// Source/document entries rechunked during this refresh.
    pub updated_entries: usize,
    /// Entries retained without rechunking or re-embedding.
    pub reused_entries: usize,
    /// Entries removed from this snapshot.
    pub removed_entries: usize,
}

/// Non-secret retrieval settings for configured or indexed data.
#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeConfiguration {
    /// Resolved keyword, hybrid or semantic retrieval strategy.
    pub retrieval_strategy: String,
    /// Effective L2 token cap, including the embedding model's limit.
    pub chunk_max_tokens: u32,
    /// Configured model, or the model whose vectors are retained.
    pub embedding_model: Option<String>,
    /// Embedding dimensionality when vectors are configured or retained.
    pub embedding_dimensions: Option<usize>,
}

impl KnowledgeConfiguration {
    fn from_config(config: &KnowledgeConfig) -> Self {
        Self {
            retrieval_strategy: config.retrieval_strategy.clone(),
            chunk_max_tokens: config.effective_l2_max_tokens(),
            embedding_model: config
                .embedding_enabled
                .then(|| config.embedding_model.clone()),
            embedding_dimensions: config
                .embedding_enabled
                .then_some(config.embedding_dimensions),
        }
    }
}

/// Read-only status of a project's knowledge base: whether this process holds
/// an in-memory index, its size and build time, the ingested documents on
/// disk, and the retrieval config a (re)index applies. Powers the Knowledge
/// view's management card without triggering a reindex.
#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeIndexStatus {
    /// Whether this process has indexed the project.
    pub indexed: bool,
    /// Source files in the current index (0 when not indexed).
    pub files: usize,
    /// Chunks in the current index (0 when not indexed).
    pub chunks: usize,
    /// Ingested documents on disk, indexed into the retriever alongside the
    /// source `files` (counted separately, never folded into `files`).
    pub documents: usize,
    /// Older documents whose project ownership cannot be established; re-ingest to use them.
    pub legacy_documents_preserved: bool,
    /// RFC3339 build time of the current index, when one exists.
    pub indexed_at: Option<String>,
    /// Current settings that a refresh will apply.
    pub configured: KnowledgeConfiguration,
    /// Settings actually used by the retained snapshot.
    pub effective: Option<KnowledgeConfiguration>,
    /// True for changed sources/configuration; absent if not indexed or inspection failed.
    pub stale: Option<bool>,
    /// Bounded diagnostics for skipped inputs or explicit keyword fallback.
    pub warnings: Vec<String>,
}

/// A single search hit from the project knowledge base.
#[derive(Debug, Clone, Serialize)]
pub struct KnowledgeHit {
    /// Source file (relative to the project root).
    pub file: String,
    /// Blended relevance score.
    pub score: f64,
    /// A short snippet of the matched chunk (original source text).
    pub snippet: String,
}

/// Replace every character that is not alphanumeric or `_` with a space, so the
/// natural-language tokenizer splits code tokens on punctuation while keeping
/// identifiers (incl. `snake_case`) intact.
fn code_normalize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' {
                c
            } else {
                ' '
            }
        })
        .collect()
}

/// Refresh source/document entries, reusing unchanged chunks and vectors.
///
/// # Errors
/// Returns `ClassifiedError` if the project tree cannot be walked.
pub fn index_project(project: &Path) -> Result<KnowledgeStats, ClassifiedError> {
    index_project_with_config(project, &crate::config::effective_knowledge_config())
}

fn retrieval_config(config: &KnowledgeConfig) -> RetrievalConfig {
    let strategy = match config
        .retrieval_strategy
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "keyword" => SearchStrategy::KeywordSearch,
        "semantic" => SearchStrategy::SemanticSearch,
        _ => SearchStrategy::Hybrid,
    };
    RetrievalConfig {
        strategy,
        min_similarity_threshold: config.min_similarity_threshold,
        bm25_weight: config.bm25_weight,
        vector_weight: config.vector_weight,
        ..Default::default()
    }
}

fn index_project_with_config(
    project: &Path,
    config: &KnowledgeConfig,
) -> Result<KnowledgeStats, ClassifiedError> {
    refresh_project(project, config, true)
}

fn refresh_project(
    project: &Path,
    config: &KnowledgeConfig,
    retry_degraded: bool,
) -> Result<KnowledgeStats, ClassifiedError> {
    refresh_project_snapshot(project, config, retry_degraded).map(|(stats, _)| stats)
}

fn refresh_project_snapshot(
    project: &Path,
    config: &KnowledgeConfig,
    retry_degraded: bool,
) -> Result<(KnowledgeStats, Arc<ProjectIndex>), ClassifiedError> {
    let gate = indexing::refresh_gate(&docs_dir(project))?;
    let _guard = gate
        .lock()
        .map_err(|_| ClassifiedError::Internal("knowledge refresh lock poisoned".into()))?;
    let operation = KnowledgeOperation::acquire(project)?;
    let embedder = build_embedder(config);
    indexing::refresh(&operation, config, embedder, retry_degraded)
}

pub(crate) fn index_in_operation(
    operation: &KnowledgeOperation,
    config: &KnowledgeConfig,
) -> Result<KnowledgeStats, ClassifiedError> {
    let embedder = build_embedder(config);
    index_in_operation_with_embedder(operation, config, embedder, true)
}

fn index_in_operation_with_embedder(
    operation: &KnowledgeOperation,
    config: &KnowledgeConfig,
    embedder: Option<Arc<dyn EmbeddingProvider>>,
    retry_degraded: bool,
) -> Result<KnowledgeStats, ClassifiedError> {
    indexing::refresh(operation, config, embedder, retry_degraded).map(|(stats, _)| stats)
}

/// Bound retained project snapshots in a long-running service.
const MAX_CACHED_PROJECT_INDEXES: usize = 8;

/// The per-project directory holding ingested documents (converted to Markdown
/// by markitdown). Kept under the app data dir, not in the user's repo, so
/// ingested specs/RFCs persist and are picked up by [`index_project`].
#[must_use]
pub fn docs_dir(project: &Path) -> PathBuf {
    docs_dir_from(project, std::env::var_os("HF_WORKSPACE_DIR"))
}

fn docs_dir_from(project: &Path, workspace_override: Option<OsString>) -> PathBuf {
    docs_root_from(workspace_override)
        .join("v2")
        .join(storage::identity(project))
}

fn docs_root_from(workspace_override: Option<OsString>) -> PathBuf {
    if let Some(dir) = workspace_override {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("knowledge");
        }
    }

    let root = crate::init::user_app_dir().join("knowledge");
    if crate::init::writable_dir(&root) {
        root
    } else {
        std::env::temp_dir().join("oxfuzz").join("knowledge")
    }
}

/// Build the embedding provider for a config, or `None` when embedding is
/// disabled (the guaranteed-offline BM25-only default).
fn build_embedder(config: &KnowledgeConfig) -> Option<Arc<dyn EmbeddingProvider>> {
    if !config.embedding_enabled {
        return None;
    }
    let api_key = if config.embedding_api_key.is_empty() {
        std::env::var(&config.embedding_api_key_env).unwrap_or_default()
    } else {
        config.embedding_api_key.clone()
    };
    Some(Arc::new(hf_provider::OpenAiEmbedding::new(
        &config.embedding_base_url,
        &api_key,
        &config.embedding_model,
        config.embedding_dimensions,
    )))
}

/// Execute embedding work off the caller's runtime thread and validate foreign vectors.
fn embed_blocking(
    embedder: &Arc<dyn EmbeddingProvider>,
    texts: &[String],
) -> Result<Vec<Vec<f32>>, &'static str> {
    let handle = tokio::runtime::Handle::try_current()
        .map_err(|_| "Embedding runtime unavailable; using keyword retrieval")?;
    let results = std::thread::scope(|scope| {
        scope
            .spawn(|| handle.block_on(embedder.embed_batch(texts)))
            .join()
    })
    .map_err(|_| "Embedding worker failed; using keyword retrieval")?
    .map_err(|_| "Embedding request failed; using keyword retrieval")?;
    if results.len() != texts.len()
        || results.iter().any(|result| {
            result.dimensions != embedder.dimensions()
                || result.vector.len() != embedder.dimensions()
                || result.vector.is_empty()
                || result.vector.iter().any(|value| !value.is_finite())
        })
    {
        return Err("Embedding response count or dimensions are invalid; using keyword retrieval");
    }
    Ok(results.into_iter().map(|result| result.vector).collect())
}

fn finalize_index(
    retriever: &mut HybridRetriever<AutoTokenizer>,
    collected: Vec<Chunk>,
    embedder: Option<&Arc<dyn EmbeddingProvider>>,
) -> Option<String> {
    if collected.is_empty() {
        return None;
    }
    let mut warning = None;
    if let Some(embedder) = embedder {
        let texts: Vec<_> = collected
            .iter()
            .map(|chunk| chunk.content.clone())
            .collect();
        match embed_blocking(embedder, &texts) {
            Ok(vectors) => {
                for (chunk, vector) in collected.into_iter().zip(vectors) {
                    retriever.index_with_embedding(chunk, vector, 1.0);
                }
                return None;
            }
            Err(reason) => {
                tracing::warn!(reason, "knowledge embedding degraded");
                warning = Some(reason.to_owned());
            }
        }
    }
    for chunk in collected {
        retriever.index(chunk);
    }
    warning
}

fn current_index(project: &Path) -> Option<Arc<ProjectIndex>> {
    let key = docs_dir(project);
    let mut map = match cache().lock() {
        Ok(map) => map,
        Err(error) => {
            tracing::error!(%error, "knowledge cache poisoned");
            return None;
        }
    };
    let index = map.get(&key)?;
    match std::fs::read_to_string(key.join(".generation")) {
        Ok(generation) if generation == index.generation => Some(Arc::clone(index)),
        // Deleted/recreated storage or unreadable generation makes a cached result unusable.
        _ => {
            map.remove(&key);
            None
        }
    }
}

/// Whether a project has an index built this session.
#[must_use]
pub fn is_indexed(project: &Path) -> bool {
    current_index(project).is_some()
}

/// Read-only status of a project's knowledge base. Never builds an index: an
/// unindexed project reports `indexed: false` with zero counts plus the config
/// a future `index_project` would apply.
#[must_use]
pub fn stats_project(project: &Path) -> KnowledgeIndexStatus {
    stats_project_with_config(project, &crate::config::effective_knowledge_config())
}

fn stats_project_with_config(project: &Path, config: &KnowledgeConfig) -> KnowledgeIndexStatus {
    let cached = current_index(project);
    let configured = KnowledgeConfiguration::from_config(config);
    let mut warnings = cached
        .as_ref()
        .map_or_else(Vec::new, |index| index.warnings.clone());
    if let Some(index) = &cached {
        match index.query_warning.lock() {
            Ok(warning) => warnings.extend(warning.iter().cloned()),
            Err(_) => warnings.push("Last query diagnostics unavailable".into()),
        }
    }
    let stale = cached.as_ref().and_then(|index| {
        if let (Ok(scan), Ok(digest)) = (indexing::scan(project), indexing::config_digest(config)) {
            let complete = scan.warnings.is_empty();
            warnings.extend(scan.warnings);
            complete.then(|| {
                index.config_digest != digest
                    || !indexing::same_entries(&index.entries, &scan.entries)
            })
        } else {
            warnings.push("Could not inspect current knowledge sources or configuration".into());
            None
        }
    });
    warnings.sort();
    warnings.dedup();
    warnings.truncate(5);
    KnowledgeIndexStatus {
        indexed: cached.is_some(),
        files: cached.as_ref().map_or(0, |i| i.files),
        chunks: cached.as_ref().map_or(0, |i| i.chunks),
        documents: count_docs(project),
        legacy_documents_preserved: storage::legacy_documents_preserved(project),
        indexed_at: cached.as_ref().map(|i| i.indexed_at.to_rfc3339()),
        configured,
        effective: cached.as_ref().map(|index| index.effective.clone()),
        stale,
        warnings,
    }
}

/// Number of ingested Markdown/text documents on disk for a project.
fn count_docs(project: &Path) -> usize {
    std::fs::read_dir(docs_dir(project)).map_or(0, |entries| {
        entries
            .flatten()
            .filter(|e| {
                let path = e.path();
                path.is_file()
                    && matches!(
                        path.extension().and_then(|x| x.to_str()),
                        Some("md" | "txt")
                    )
            })
            .count()
    })
}

/// Refresh changed or deleted entries and search the resulting snapshot.
///
/// The BM25 index is an in-memory, process-local cache, so [`search_project`]
/// (a pure lookup) silently returns nothing in a process that has not indexed
/// the project -- e.g. a `hf-web`/GUI server restarted between an `index` call
/// and a later `search`. This guarantees a usable result by indexing on demand.
/// The index build walks the source tree (blocking), so async callers should
/// run this on a blocking thread.
#[must_use]
pub fn search_project_ensured(project: &Path, query: &str, limit: usize) -> Vec<KnowledgeHit> {
    match refresh_project_snapshot(project, &crate::config::effective_knowledge_config(), false) {
        Ok((_, index)) => search_snapshot(&index, query, limit),
        Err(error) => {
            tracing::warn!(%error, "knowledge refresh failed");
            Vec::new()
        }
    }
}

/// Search a project's knowledge base. Returns an empty list if the project has
/// not been indexed yet.
#[must_use]
pub fn search_project(project: &Path, query: &str, limit: usize) -> Vec<KnowledgeHit> {
    let index = current_index(project);
    let Some(index) = index else {
        return Vec::new();
    };
    search_snapshot(&index, query, limit)
}

fn search_snapshot(index: &ProjectIndex, query: &str, limit: usize) -> Vec<KnowledgeHit> {
    let filter = RetrievalFilter {
        limit,
        ..Default::default()
    };
    let normalized = code_normalize(query);
    // Query with the snapshot's provider so model changes cannot mix vector spaces.
    let vectors = index
        .embedder
        .as_ref()
        .map(|embedder| embed_blocking(embedder, std::slice::from_ref(&normalized)));
    let query_warning = match &vectors {
        Some(Err(reason)) => Some(format!("Last embedding query: {reason}")),
        _ => None,
    };
    match index.query_warning.lock() {
        Ok(mut warning) => *warning = query_warning,
        Err(error) => tracing::warn!(%error, "could not retain knowledge query diagnostics"),
    }
    let results = match vectors {
        Some(Ok(vectors)) => index.retriever.search_with_embedding(
            &normalized,
            vectors.first().map(Vec::as_slice),
            &filter,
        ),
        Some(Err(reason)) => {
            tracing::warn!(reason, "knowledge query embedding degraded");
            index.retriever.search_with_strategy(
                SearchStrategy::KeywordSearch,
                &normalized,
                None,
                &filter,
            )
        }
        None => index.retriever.search(&normalized, &filter),
    };

    results
        .into_iter()
        .map(|r| {
            let snippet = index
                .originals
                .get(&r.chunk.id)
                .unwrap_or(&r.chunk.content)
                .chars()
                .take(240)
                .collect();
            KnowledgeHit {
                file: r.chunk.metadata.source,
                score: r.relevance,
                snippet,
            }
        })
        .collect()
}

/// Number of related knowledge chunks injected into a harness/triage prompt.
/// Kept small (AGENTS.md 2.4): the prompt already carries the target details,
/// so this is supporting usage context, not a code dump. The section renderer
/// (`hf_prompt::render_related_context_section`) applies the hard char budget.
const PROMPT_CONTEXT_TOP_K: usize = 4;

/// Cap on the crash-summary text mixed into a triage retrieval query, so a
/// verbose sanitizer summary cannot drown out the target symbol.
const TRIAGE_QUERY_SUMMARY_CHARS: usize = 120;

/// Retrieve the most relevant project chunks for a harness-generation prompt:
/// the target's symbol plus its signature keywords as the query, excluding the
/// chunk that defines the target itself (the prompt already identifies the
/// target -- the value of this context is in call sites and related code).
///
/// Pure in-memory lookup over the cached index: returns an empty vec when the
/// project has not been indexed, so prompt assembly degrades to the
/// un-augmented prompt instead of failing harness generation.
#[must_use]
pub fn harness_related_context(project: &Path, target: &TargetCandidate) -> Vec<RelatedContext> {
    let query = target.signature.as_deref().map_or_else(
        || target.symbol.clone(),
        |sig| format!("{} {sig}", target.symbol),
    );
    // `location.file` is relative to the project root, matching hit.file.
    let self_file = target.location.file.to_string_lossy();
    // Fetch one extra hit so dropping the target's own definition still
    // leaves a full page of related chunks.
    search_project(project, &query, PROMPT_CONTEXT_TOP_K + 1)
        .into_iter()
        .filter(|hit| !(hit.file == self_file && hit.snippet.contains(&target.symbol)))
        .take(PROMPT_CONTEXT_TOP_K)
        .map(|hit| RelatedContext {
            file: hit.file,
            snippet: hit.snippet,
        })
        .collect()
}

/// Retrieve related project chunks for a crash-triage prompt: the target
/// symbol plus the leading crash-summary keywords as the query. Unlike the
/// harness path there is no own-definition chunk to exclude -- the triage
/// prompt carries the harness source, not the target body.
///
/// Same degradation contract as [`harness_related_context`].
#[must_use]
pub fn triage_related_context(
    project: &Path,
    target: &str,
    crash_summary: &str,
) -> Vec<RelatedContext> {
    let summary: String = crash_summary
        .chars()
        .take(TRIAGE_QUERY_SUMMARY_CHARS)
        .collect();
    search_project(
        project,
        &format!("{target} {summary}"),
        PROMPT_CONTEXT_TOP_K,
    )
    .into_iter()
    .map(|hit| RelatedContext {
        file: hit.file,
        snippet: hit.snippet,
    })
    .collect()
}

#[cfg(test)]
fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static TESTS: Mutex<()> = Mutex::new(());
    TESTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::engine::EngineKind;
    use hf_core::target::{
        InputSurface, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
    };

    /// A C parser target defined in `parse.c`, matching the fixture project
    /// built by [`index_fixture_project`].
    fn fixture_target() -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::nil(),
            project_root: PathBuf::from("/proj"),
            language: TargetLanguage::C,
            symbol: "parse_header".to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from("parse.c"),
                line: 1,
                col: 1,
                end_line: None,
                end_col: None,
            },
            signature: Some("int parse_header(const char *buf, unsigned long len)".to_owned()),
            input_surface: InputSurface::Bytes,
            complexity: 3,
            fit_score: 0.5,
            sanitizers: Vec::new(),
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 3,
        }
    }

    /// A two-file project: the target's definition in `parse.c` and a call
    /// site in `caller.c`, indexed with the production config.
    fn index_fixture_project(dir: &Path) {
        std::fs::write(
            dir.join("parse.c"),
            "int parse_header(const char *buf, unsigned long len) {\n\
             \x20   return buf == 0 || len == 0;\n\
             }",
        )
        .unwrap();
        std::fs::write(
            dir.join("caller.c"),
            "void handle_request(const char *buf, unsigned long len) {\n\
             \x20   if (parse_header(buf, len)) { accept(buf); }\n\
             }",
        )
        .unwrap();
        index_project(dir).unwrap();
    }

    #[test]
    fn index_and_search_finds_code_symbol() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("chunk.c"),
            "int copy_chunk(const unsigned char *data, unsigned long len) { return 0; }",
        )
        .unwrap();

        let stats = index_project(dir.path()).unwrap();
        assert_eq!(stats.files, 1);
        assert!(stats.chunks >= 1);

        let hits = search_project(dir.path(), "copy_chunk", 10);
        assert!(!hits.is_empty(), "expected a hit for copy_chunk");
        assert_eq!(hits[0].file, "chunk.c");
        // The snippet preserves the original source (punctuation intact).
        assert!(hits[0].snippet.contains("copy_chunk(const"));
    }

    #[test]
    fn source_labels_are_slash_separated_on_every_host() {
        let _guard = super::test_guard();
        // The chunk source label is presented to users and matched against
        // queries, so a nested file must be labeled `sub/inner.c` even where
        // the host walker yields `sub\inner.c`.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(
            dir.path().join("sub").join("inner.c"),
            "int nested_symbol(const unsigned char *data, unsigned long len) { return 0; }",
        )
        .unwrap();

        index_project(dir.path()).unwrap();

        let hits = search_project(dir.path(), "nested_symbol", 10);
        assert!(!hits.is_empty(), "expected a hit for nested_symbol");
        assert_eq!(hits[0].file, "sub/inner.c");
    }

    #[test]
    fn search_unindexed_project_is_empty() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        assert!(search_project(dir.path(), "anything", 10).is_empty());
    }

    #[test]
    fn stats_unindexed_project_reports_not_indexed() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();

        let status = stats_project(dir.path());

        assert!(!status.indexed);
        assert_eq!(status.files, 0);
        assert_eq!(status.chunks, 0);
        assert_eq!(status.indexed_at, None);
    }

    #[test]
    fn stats_after_index_reports_counts_time_and_config() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("chunk.c"),
            "int copy_chunk(const unsigned char *data, unsigned long len) { return 0; }",
        )
        .unwrap();
        let indexed = index_project(dir.path()).unwrap();

        let status = stats_project(dir.path());

        assert!(status.indexed);
        assert_eq!(status.files, indexed.files);
        assert_eq!(status.chunks, indexed.chunks);
        assert!(
            status.indexed_at.is_some(),
            "an index build records its time"
        );
        assert!(
            !status.configured.retrieval_strategy.is_empty(),
            "config summary carries the active strategy"
        );
        assert!(status.configured.chunk_max_tokens > 0);
    }

    #[test]
    fn stats_counts_ingested_documents_on_disk() {
        let _guard = super::test_guard();
        // A unique tempdir project gives a unique (and isolated) docs dir.
        let dir = tempfile::tempdir().unwrap();
        let docs = docs_dir(dir.path());
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("spec.md"), "# Spec\nBody.").unwrap();

        let status = stats_project(dir.path());

        assert_eq!(status.documents, 1);

        let _ = std::fs::remove_dir_all(&docs);
    }

    #[test]
    fn docs_dir_honors_workspace_override() {
        let _guard = super::test_guard();
        let project = Path::new("/tmp/example-project");
        let root = std::ffi::OsString::from("/tmp/hf-test-workspace");

        assert_eq!(
            docs_dir_from(project, Some(root)),
            Path::new("/tmp/hf-test-workspace")
                .join("knowledge")
                .join("v2")
                .join(storage::identity(project))
        );
    }

    #[test]
    fn ensured_search_indexes_on_demand() {
        let _guard = super::test_guard();
        // Fresh project, never indexed (mirrors a server restarted between an
        // index call and a search). The plain lookup is empty; the ensured
        // variant indexes on demand and finds the symbol.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("target.c"),
            "int parse_packet(const char *buf) { return 0; }",
        )
        .unwrap();
        assert!(!is_indexed(dir.path()));
        assert!(search_project(dir.path(), "parse_packet", 10).is_empty());
        let hits = search_project_ensured(dir.path(), "parse_packet", 10);
        assert!(is_indexed(dir.path()));
        assert!(
            !hits.is_empty(),
            "on-demand index should surface the symbol"
        );
    }

    #[test]
    fn retrieval_config_applies_strategy_threshold_and_weights() {
        let _guard = super::test_guard();
        let knowledge = KnowledgeConfig {
            retrieval_strategy: "hybrid".to_owned(),
            min_similarity_threshold: 0.42,
            bm25_weight: 2.5,
            vector_weight: 0.25,
            ..KnowledgeConfig::default()
        };

        let retrieval = retrieval_config(&knowledge);

        assert_eq!(retrieval.strategy, SearchStrategy::Hybrid);
        assert!((retrieval.min_similarity_threshold - 0.42).abs() < f64::EPSILON);
        assert!((retrieval.bm25_weight - 2.5).abs() < f64::EPSILON);
        assert!((retrieval.vector_weight - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn configured_chunk_limit_reaches_project_index() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("limited.c"),
            "alpha hidden_token_that_must_be_truncated",
        )
        .unwrap();
        let config = KnowledgeConfig {
            l2_max_tokens: 2,
            retrieval_strategy: "keyword".to_owned(),
            min_similarity_threshold: 0.0,
            ..KnowledgeConfig::default()
        };

        index_project_with_config(dir.path(), &config).unwrap();

        assert!(!search_project(dir.path(), "alpha", 10).is_empty());
        assert!(
            search_project(dir.path(), "hidden_token_that_must_be_truncated", 10).is_empty(),
            "configured L2 token budget was ignored"
        );
    }

    #[test]
    fn ingested_documents_are_indexed_and_searchable() {
        let _guard = super::test_guard();
        // A unique tempdir project gives a unique (and isolated) docs dir.
        let dir = tempfile::tempdir().unwrap();
        let docs = docs_dir(dir.path());
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(
            docs.join("spec.md"),
            "# Protocol Spec\nThe frobnicate opcode triggers a reticulation handshake.",
        )
        .unwrap();

        let stats = index_project(dir.path()).unwrap();
        // The doc is indexed (produces chunks) but is counted as a `document`,
        // not folded into source `files` (which stays 0 for a docs-only project).
        assert_eq!(stats.files, 0, "an ingested doc is not a source file");
        assert!(
            stats.chunks >= 1,
            "the ingested doc produced indexed chunks"
        );

        let hits = search_project(dir.path(), "frobnicate", 10);
        assert!(!hits.is_empty(), "ingested doc is searchable");
        assert!(hits[0].file.starts_with("doc:"), "labelled as a document");

        let _ = std::fs::remove_dir_all(&docs);
    }

    #[test]
    fn harness_related_context_surfaces_call_sites_and_excludes_own_definition() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        index_fixture_project(dir.path());
        let target = fixture_target();

        let related = harness_related_context(dir.path(), &target);

        assert!(!related.is_empty(), "expected related chunks: {related:?}");
        assert!(
            related.iter().any(|c| c.file == "caller.c"),
            "the call site should be surfaced: {related:?}"
        );
        assert!(
            related
                .iter()
                .all(|c| !(c.file == "parse.c" && c.snippet.contains("parse_header"))),
            "the target's own definition chunk should be excluded: {related:?}"
        );
    }

    #[test]
    fn harness_related_context_empty_when_unindexed() {
        let _guard = super::test_guard();
        // Never indexed: retrieval degrades to no context rather than failing.
        let dir = tempfile::tempdir().unwrap();
        assert!(harness_related_context(dir.path(), &fixture_target()).is_empty());
    }

    #[test]
    fn harness_prompt_unchanged_without_index() {
        let _guard = super::test_guard();
        // Composition as container.rs performs it: without an index the
        // assembled prompt is byte-identical to the base prompt.
        let dir = tempfile::tempdir().unwrap();
        let target = fixture_target();
        let related = harness_related_context(dir.path(), &target);
        let prompt = hf_prompt::render_harness_prompt_with_context(
            &target,
            EngineKind::LibFuzzer,
            &related,
            None,
        );
        assert_eq!(
            prompt,
            hf_prompt::render_harness_prompt(&target, EngineKind::LibFuzzer)
        );
    }

    #[test]
    fn harness_prompt_carries_related_context_when_indexed() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        index_fixture_project(dir.path());
        let target = fixture_target();

        let related = harness_related_context(dir.path(), &target);
        let prompt = hf_prompt::render_harness_prompt_with_context(
            &target,
            EngineKind::LibFuzzer,
            &related,
            None,
        );

        assert!(prompt.contains("Related project context"), "{prompt}");
        assert!(prompt.contains("caller.c"), "{prompt}");
        assert!(prompt.contains("handle_request"), "{prompt}");
    }

    #[test]
    fn triage_related_context_finds_target_references() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        index_fixture_project(dir.path());

        let related = triage_related_context(
            dir.path(),
            "parse_header",
            "heap-buffer-overflow in parse_header read of size 4",
        );

        assert!(
            related.iter().any(|c| c.snippet.contains("parse_header")),
            "triage context should reference the crashing target: {related:?}"
        );
    }

    #[test]
    fn triage_related_context_empty_when_unindexed() {
        let _guard = super::test_guard();
        let dir = tempfile::tempdir().unwrap();
        assert!(triage_related_context(dir.path(), "parse_header", "asan").is_empty());
    }
}
