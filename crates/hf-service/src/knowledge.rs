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
use hf_knowledge::chunking::{ChunkLevel, ChunkMetadata, ChunkingStrategy};
use hf_knowledge::config::KnowledgeConfig;
use hf_knowledge::retrieval::{HybridRetriever, RetrievalConfig, RetrievalFilter, SearchStrategy};
use hf_knowledge::tokenizer::AutoTokenizer;
use ignore::WalkBuilder;
use serde::Serialize;

/// A built per-project index: the BM25 retriever (over normalized text) plus a
/// map from chunk id to the original source text for display.
struct ProjectIndex {
    retriever: HybridRetriever<AutoTokenizer>,
    originals: HashMap<String, String>,
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
    let chunker = ChunkingStrategy::new(KnowledgeConfig::default());
    // Pure keyword (BM25) retrieval -- no embeddings here -- with the similarity
    // threshold disabled, since raw BM25 scores are not on the 0..1 scale the
    // default 0.65 threshold assumes (which would discard every keyword hit).
    let mut retriever = HybridRetriever::with_config(
        AutoTokenizer::new(),
        RetrievalConfig {
            strategy: SearchStrategy::KeywordSearch,
            min_similarity_threshold: 0.0,
            ..Default::default()
        },
    );
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
    });
    let key = project.to_string_lossy().to_string();
    if let Ok(mut map) = cache().lock() {
        map.insert(key, index);
    }
    Ok(KnowledgeStats { files, chunks })
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
