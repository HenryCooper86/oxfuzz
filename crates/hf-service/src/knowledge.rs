//! Project knowledge base backed by `hf-knowledge` (BM25 retrieval).
//!
//! Indexes a project's source files into a per-project [`HybridRetriever`] so
//! the GUI Knowledge view (and, later, the agent) can search the codebase. The
//! index is held in a process-global cache keyed by project path; it is rebuilt
//! on demand via [`index_project`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use hf_core::error::ClassifiedError;
use hf_knowledge::chunking::{ChunkLevel, ChunkMetadata, ChunkingStrategy};
use hf_knowledge::config::KnowledgeConfig;
use hf_knowledge::retrieval::{HybridRetriever, RetrievalFilter};
use hf_knowledge::tokenizer::AutoTokenizer;
use ignore::WalkBuilder;
use serde::Serialize;

type Index = Arc<HybridRetriever<AutoTokenizer>>;

/// Process-global per-project BM25 index cache.
fn cache() -> &'static Mutex<HashMap<String, Index>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Index>>> = OnceLock::new();
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
    /// A short snippet of the matched chunk.
    pub snippet: String,
}

/// Index a project's source files into a BM25 knowledge base, replacing any
/// existing index for that project.
///
/// # Errors
/// Returns `ClassifiedError` if the project tree cannot be walked.
pub fn index_project(project: &Path) -> Result<KnowledgeStats, ClassifiedError> {
    let chunker = ChunkingStrategy::new(KnowledgeConfig::default());
    let mut retriever = HybridRetriever::new(AutoTokenizer::new());
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
        for chunk in chunker.chunk(&rel, &content, ChunkLevel::L2, &meta) {
            retriever.index(chunk);
            chunks += 1;
        }
    }

    let key = project.to_string_lossy().to_string();
    if let Ok(mut map) = cache().lock() {
        map.insert(key, Arc::new(retriever));
    }
    Ok(KnowledgeStats { files, chunks })
}

/// Whether a project has an index built this session.
#[must_use]
pub fn is_indexed(project: &Path) -> bool {
    let key = project.to_string_lossy().to_string();
    cache().lock().is_ok_and(|m| m.contains_key(&key))
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
    index
        .search(query, &filter)
        .into_iter()
        .map(|r| KnowledgeHit {
            file: r.chunk.metadata.source,
            score: r.relevance,
            snippet: r.chunk.content.chars().take(240).collect(),
        })
        .collect()
}
