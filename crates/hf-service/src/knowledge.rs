//! Project knowledge base backed by `hf-knowledge` (BM25 retrieval).
//!
//! Indexes a project's source files into a per-project [`HybridRetriever`] so
//! the GUI Knowledge view and the agent's `KnowledgeSearch` tool can search the
//! codebase. The index is held in a process-global cache keyed by project path;
//! it is rebuilt on demand via [`index_project`].
//!
//! hf-knowledge's tokenizer targets natural language: it strips code punctuation
//! without splitting on it (so `copy_chunk(const` becomes one mangled token). We
//! therefore index a *code-normalized* copy of each chunk (punctuation -> spaces)
//! and normalize queries the same way, while keeping the original text for the
//! snippet shown to the user.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use hf_core::error::ClassifiedError;
use hf_core::target::TargetCandidate;
use hf_knowledge::chunking::{ChunkLevel, ChunkMetadata, ChunkingStrategy};
use hf_knowledge::config::KnowledgeConfig;
use hf_knowledge::retrieval::{HybridRetriever, RetrievalConfig, RetrievalFilter, SearchStrategy};
use hf_knowledge::tokenizer::AutoTokenizer;
use hf_prompt::RelatedContext;
use ignore::WalkBuilder;
use serde::Serialize;

/// A built per-project index: the BM25 retriever (over normalized text) plus a
/// map from chunk id to the original source text for display.
struct ProjectIndex {
    retriever: HybridRetriever<AutoTokenizer>,
    originals: HashMap<String, String>,
    /// Source-file count at index time, reported by [`stats_project`].
    files: usize,
    /// Chunk count at index time.
    chunks: usize,
    /// When this index was built.
    indexed_at: chrono::DateTime<chrono::Utc>,
}

/// Process-global per-project index cache.
fn cache() -> &'static Mutex<HashMap<String, Arc<ProjectIndex>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Arc<ProjectIndex>>>> = OnceLock::new();
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
    /// Ingested documents on disk (picked up by the next reindex).
    pub documents: usize,
    /// RFC3339 build time of the current index, when one exists.
    pub indexed_at: Option<String>,
    /// Retrieval strategy a (re)index applies ("hybrid" or "keyword").
    pub retrieval_strategy: String,
    /// Token budget per indexed chunk (L2).
    pub chunk_max_tokens: u32,
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

/// Index a project's source files into a BM25 knowledge base, replacing any
/// existing index for that project.
///
/// # Errors
/// Returns `ClassifiedError` if the project tree cannot be walked.
pub fn index_project(project: &Path) -> Result<KnowledgeStats, ClassifiedError> {
    Ok(index_project_with_config(
        project,
        crate::config::effective_knowledge_config(),
    ))
}

fn retrieval_config(config: &KnowledgeConfig) -> RetrievalConfig {
    let strategy = match config
        .retrieval_strategy
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "keyword" => SearchStrategy::KeywordSearch,
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

fn index_project_with_config(project: &Path, config: KnowledgeConfig) -> KnowledgeStats {
    let retrieval = retrieval_config(&config);
    let chunker = ChunkingStrategy::new(config);
    let mut retriever = HybridRetriever::with_config(AutoTokenizer::new(), retrieval);
    let mut originals: HashMap<String, String> = HashMap::new();
    let mut files = 0usize;
    let mut chunks = 0usize;

    for entry in WalkBuilder::new(project)
        .hidden(true)
        .git_ignore(true)
        .build()
    {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !KNOWLEDGE_EXTS.contains(&ext) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(path) else {
            continue;
        };
        if content.trim().is_empty() {
            continue;
        }
        files += 1;
        let rel = path
            .strip_prefix(project)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();
        let meta = ChunkMetadata {
            source: rel.clone(),
            title: rel.clone(),
            ..Default::default()
        };
        for mut chunk in chunker.chunk(&rel, &content, ChunkLevel::L2, &meta) {
            // Keep the original text for the snippet; index a normalized copy.
            originals.insert(chunk.id.clone(), chunk.content.clone());
            chunk.content = code_normalize(&chunk.content);
            retriever.index(chunk);
            chunks += 1;
        }
    }

    // Also index any documents ingested for this project (markitdown output).
    index_docs_dir(
        &docs_dir(project),
        &chunker,
        &mut retriever,
        &mut originals,
        &mut files,
        &mut chunks,
    );

    let index = Arc::new(ProjectIndex {
        retriever,
        originals,
        files,
        chunks,
        indexed_at: chrono::Utc::now(),
    });
    let key = project.to_string_lossy().to_string();
    if let Ok(mut map) = cache().lock() {
        map.insert(key, index);
    }
    KnowledgeStats { files, chunks }
}

/// The per-project directory holding ingested documents (converted to Markdown
/// by markitdown). Kept under the app data dir, not in the user's repo, so
/// ingested specs/RFCs persist and are picked up by [`index_project`].
#[must_use]
pub fn docs_dir(project: &Path) -> PathBuf {
    docs_dir_from(project, std::env::var_os("HF_WORKSPACE_DIR"))
}

fn docs_dir_from(project: &Path, workspace_override: Option<OsString>) -> PathBuf {
    let key: String = project
        .to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    docs_root_from(workspace_override).join(key)
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
        std::env::temp_dir().join("hobot_fuzz").join("knowledge")
    }
}

/// Index Markdown/text files from a directory into the retriever, labelled
/// `doc:<filename>`. Used for ingested documents that live outside the project.
fn index_docs_dir(
    dir: &Path,
    chunker: &ChunkingStrategy,
    retriever: &mut HybridRetriever<AutoTokenizer>,
    originals: &mut HashMap<String, String>,
    files: &mut usize,
    chunks: &mut usize,
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "md" && ext != "txt" {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if content.trim().is_empty() {
            continue;
        }
        *files += 1;
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("doc");
        let source = format!("doc:{name}");
        let meta = ChunkMetadata {
            source: source.clone(),
            title: source.clone(),
            ..Default::default()
        };
        for mut chunk in chunker.chunk(&source, &content, ChunkLevel::L2, &meta) {
            originals.insert(chunk.id.clone(), chunk.content.clone());
            chunk.content = code_normalize(&chunk.content);
            retriever.index(chunk);
            *chunks += 1;
        }
    }
}

/// Whether a project has an index built this session.
#[must_use]
pub fn is_indexed(project: &Path) -> bool {
    let key = project.to_string_lossy().to_string();
    cache().lock().is_ok_and(|m| m.contains_key(&key))
}

/// Read-only status of a project's knowledge base. Never builds an index: an
/// unindexed project reports `indexed: false` with zero counts plus the config
/// a future `index_project` would apply.
#[must_use]
pub fn stats_project(project: &Path) -> KnowledgeIndexStatus {
    let key = project.to_string_lossy().to_string();
    let cached = cache().lock().ok().and_then(|m| m.get(&key).cloned());
    let config = crate::config::effective_knowledge_config();
    KnowledgeIndexStatus {
        indexed: cached.is_some(),
        files: cached.as_ref().map_or(0, |i| i.files),
        chunks: cached.as_ref().map_or(0, |i| i.chunks),
        documents: count_docs(project),
        indexed_at: cached.as_ref().map(|i| i.indexed_at.to_rfc3339()),
        retrieval_strategy: config.retrieval_strategy,
        chunk_max_tokens: config.l2_max_tokens,
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

/// Search a project, building the index first if this process has not indexed
/// it yet.
///
/// The BM25 index is an in-memory, process-local cache, so [`search_project`]
/// (a pure lookup) silently returns nothing in a process that has not indexed
/// the project -- e.g. a `hf-web`/GUI server restarted between an `index` call
/// and a later `search`. This guarantees a usable result by indexing on demand.
/// The index build walks the source tree (blocking), so async callers should
/// run this on a blocking thread.
#[must_use]
pub fn search_project_ensured(project: &Path, query: &str, limit: usize) -> Vec<KnowledgeHit> {
    if !is_indexed(project) {
        if let Err(e) = index_project(project) {
            tracing::warn!(error = %e, "knowledge: on-demand index failed");
            return Vec::new();
        }
    }
    search_project(project, query, limit)
}

/// Search a project's knowledge base. Returns an empty list if the project has
/// not been indexed yet.
#[must_use]
pub fn search_project(project: &Path, query: &str, limit: usize) -> Vec<KnowledgeHit> {
    let key = project.to_string_lossy().to_string();
    let index = cache().lock().ok().and_then(|m| m.get(&key).cloned());
    let Some(index) = index else {
        return Vec::new();
    };
    let filter = RetrievalFilter {
        limit,
        ..Default::default()
    };
    let normalized = code_normalize(query);
    index
        .retriever
        .search(&normalized, &filter)
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
    fn search_unindexed_project_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(search_project(dir.path(), "anything", 10).is_empty());
    }

    #[test]
    fn stats_unindexed_project_reports_not_indexed() {
        let dir = tempfile::tempdir().unwrap();

        let status = stats_project(dir.path());

        assert!(!status.indexed);
        assert_eq!(status.files, 0);
        assert_eq!(status.chunks, 0);
        assert_eq!(status.indexed_at, None);
    }

    #[test]
    fn stats_after_index_reports_counts_time_and_config() {
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
            !status.retrieval_strategy.is_empty(),
            "config summary carries the active strategy"
        );
        assert!(status.chunk_max_tokens > 0);
    }

    #[test]
    fn stats_counts_ingested_documents_on_disk() {
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
        let project = Path::new("/tmp/example-project");
        let root = std::ffi::OsString::from("/tmp/hf-test-workspace");

        assert_eq!(
            docs_dir_from(project, Some(root)),
            Path::new("/tmp/hf-test-workspace")
                .join("knowledge")
                .join("_tmp_example_project")
        );
    }

    #[test]
    fn ensured_search_indexes_on_demand() {
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

        index_project_with_config(dir.path(), config);

        assert!(!search_project(dir.path(), "alpha", 10).is_empty());
        assert!(
            search_project(dir.path(), "hidden_token_that_must_be_truncated", 10).is_empty(),
            "configured L2 token budget was ignored"
        );
    }

    #[test]
    fn ingested_documents_are_indexed_and_searchable() {
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
        assert!(stats.files >= 1, "ingested doc counted");

        let hits = search_project(dir.path(), "frobnicate", 10);
        assert!(!hits.is_empty(), "ingested doc is searchable");
        assert!(hits[0].file.starts_with("doc:"), "labelled as a document");

        let _ = std::fs::remove_dir_all(&docs);
    }

    #[test]
    fn harness_related_context_surfaces_call_sites_and_excludes_own_definition() {
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
        // Never indexed: retrieval degrades to no context rather than failing.
        let dir = tempfile::tempdir().unwrap();
        assert!(harness_related_context(dir.path(), &fixture_target()).is_empty());
    }

    #[test]
    fn harness_prompt_unchanged_without_index() {
        // Composition as container.rs performs it: without an index the
        // assembled prompt is byte-identical to the base prompt.
        let dir = tempfile::tempdir().unwrap();
        let target = fixture_target();
        let related = harness_related_context(dir.path(), &target);
        let prompt =
            hf_prompt::render_harness_prompt_with_context(&target, EngineKind::LibFuzzer, &related);
        assert_eq!(
            prompt,
            hf_prompt::render_harness_prompt(&target, EngineKind::LibFuzzer)
        );
    }

    #[test]
    fn harness_prompt_carries_related_context_when_indexed() {
        let dir = tempfile::tempdir().unwrap();
        index_fixture_project(dir.path());
        let target = fixture_target();

        let related = harness_related_context(dir.path(), &target);
        let prompt =
            hf_prompt::render_harness_prompt_with_context(&target, EngineKind::LibFuzzer, &related);

        assert!(prompt.contains("Related project context"), "{prompt}");
        assert!(prompt.contains("caller.c"), "{prompt}");
        assert!(prompt.contains("handle_request"), "{prompt}");
    }

    #[test]
    fn triage_related_context_finds_target_references() {
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
        let dir = tempfile::tempdir().unwrap();
        assert!(triage_related_context(dir.path(), "parse_header", "asan").is_empty());
    }
}
