//! Content fingerprints, refresh exclusion, and atomic index publication.
use std::collections::BTreeMap;
use std::sync::Weak;

use ignore::WalkBuilder;
use sha2::{Digest, Sha256};

use super::{
    cache, code_normalize, current_index, docs_dir, finalize_index, retrieval_config, Arc,
    AutoTokenizer, Chunk, ChunkLevel, ChunkMetadata, ChunkingStrategy, ClassifiedError,
    EmbeddingProvider, HashMap, HybridRetriever, KnowledgeConfig, KnowledgeConfiguration,
    KnowledgeOperation, KnowledgeStats, Mutex, OnceLock, Path, PathBuf, ProjectIndex,
    SearchStrategy, KNOWLEDGE_EXTS, MAX_CACHED_PROJECT_INDEXES,
};

#[derive(Clone)]
pub(super) struct IndexedEntry {
    digest: String,
    chunk_ids: Vec<String>,
}

pub(super) struct SourceEntry {
    digest: String,
    content: String,
    label: String,
    source_file: bool,
}

pub(super) struct SourceSnapshot {
    pub entries: BTreeMap<String, SourceEntry>,
    pub warnings: Vec<String>,
}

pub(super) fn refresh_gate(key: &Path) -> Result<Arc<Mutex<()>>, ClassifiedError> {
    static GATES: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();
    let mut gates = GATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| ClassifiedError::Internal("knowledge refresh registry poisoned".into()))?;
    gates.retain(|_, gate| gate.strong_count() > 0);
    if let Some(gate) = gates.get(key).and_then(Weak::upgrade) {
        return Ok(gate);
    }
    let gate = Arc::new(Mutex::new(()));
    gates.insert(key.to_path_buf(), Arc::downgrade(&gate));
    Ok(gate)
}

pub(super) fn config_digest(config: &KnowledgeConfig) -> Result<String, ClassifiedError> {
    let bytes = serde_json::to_vec(config)
        .map_err(|error| ClassifiedError::Internal(format!("knowledge configuration: {error}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

impl SourceSnapshot {
    fn warning(&mut self, message: String) {
        if self.warnings.len() < 5 {
            self.warnings.push(message);
        }
    }

    fn read_entry(&mut self, id: String, label: String, path: &Path, source_file: bool) {
        match std::fs::read_to_string(path) {
            Ok(content) if !content.trim().is_empty() => {
                self.entries.insert(
                    id,
                    SourceEntry {
                        digest: format!("{:x}", Sha256::digest(content.as_bytes())),
                        content,
                        label,
                        source_file,
                    },
                );
            }
            Ok(_) => {}
            Err(_) => self.warning(format!("Unreadable knowledge entry: {label}")),
        }
    }
}

pub(super) fn scan(project: &Path) -> Result<SourceSnapshot, ClassifiedError> {
    let canonical = crate::container::project_lookup_identity(project);
    let project = canonical.as_path();
    if !project.is_dir() {
        return Err(ClassifiedError::Validation(
            "knowledge project directory is unavailable".into(),
        ));
    }
    let mut snapshot = SourceSnapshot {
        entries: BTreeMap::new(),
        warnings: Vec::new(),
    };
    for entry in WalkBuilder::new(project)
        .hidden(true)
        .git_ignore(true)
        .build()
    {
        let Ok(entry) = entry else {
            snapshot.warning("Could not read part of the project tree".into());
            continue;
        };
        if !entry.file_type().is_some_and(|kind| kind.is_file()) {
            continue;
        }
        let path = entry.path();
        if !path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| KNOWLEDGE_EXTS.contains(&ext))
        {
            continue;
        }
        let label = hf_core::runtime::posix_relative(
            path.strip_prefix(project)
                .map_err(|error| ClassifiedError::Internal(error.to_string()))?,
        );
        snapshot.read_entry(format!("source:{label}"), label, path, true);
    }
    match std::fs::read_dir(docs_dir(project)) {
        Ok(entries) => {
            for entry in entries {
                let Ok(entry) = entry else {
                    snapshot.warning("Could not list an ingested document".into());
                    continue;
                };
                let path = entry.path();
                if !matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("md" | "txt")
                ) {
                    continue;
                }
                match entry.file_type() {
                    Ok(kind) if kind.is_file() => {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        snapshot.read_entry(
                            format!("document:{name}"),
                            format!("doc:{name}"),
                            &path,
                            false,
                        );
                    }
                    Ok(_) => {}
                    Err(_) => snapshot.warning("Could not inspect an ingested document".into()),
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => snapshot.warning("Could not read ingested documents".into()),
    }
    Ok(snapshot)
}

pub(super) fn same_entries(
    indexed: &BTreeMap<String, IndexedEntry>,
    current: &BTreeMap<String, SourceEntry>,
) -> bool {
    indexed.len() == current.len()
        && indexed.iter().all(|(id, entry)| {
            current
                .get(id)
                .is_some_and(|value| value.digest == entry.digest)
        })
}

fn empty_index(
    config: &KnowledgeConfig,
    generation: String,
    config_digest: String,
) -> ProjectIndex {
    ProjectIndex {
        retriever: HybridRetriever::with_config(AutoTokenizer::new(), retrieval_config(config)),
        originals: HashMap::new(),
        entries: BTreeMap::new(),
        files: 0,
        chunks: 0,
        indexed_at: chrono::Utc::now(),
        generation,
        config_digest,
        effective: KnowledgeConfiguration::from_config(config),
        embedder: None,
        warnings: Vec::new(),
        embedding_warning: None,
        query_warning: Arc::new(Mutex::new(None)),
    }
}

fn update_entries(
    index: &mut ProjectIndex,
    sources: &SourceSnapshot,
    config: &KnowledgeConfig,
) -> (KnowledgeStats, Vec<Chunk>) {
    let mut stats = KnowledgeStats {
        files: sources
            .entries
            .values()
            .filter(|entry| entry.source_file)
            .count(),
        chunks: 0,
        updated_entries: 0,
        reused_entries: 0,
        removed_entries: 0,
    };
    let removed: Vec<_> = index
        .entries
        .keys()
        .filter(|id| !sources.entries.contains_key(*id))
        .cloned()
        .collect();
    for id in removed {
        remove_entry(index, &id);
        stats.removed_entries += 1;
    }
    let chunker = ChunkingStrategy::new(config.clone());
    let mut chunks = Vec::new();
    for (id, entry) in &sources.entries {
        if index
            .entries
            .get(id)
            .is_some_and(|old| old.digest == entry.digest)
        {
            stats.reused_entries += 1;
            continue;
        }
        remove_entry(index, id);
        let metadata = ChunkMetadata {
            source: entry.label.clone(),
            title: entry.label.clone(),
            ..Default::default()
        };
        let mut chunk_ids = Vec::new();
        for mut chunk in chunker.chunk(id, &entry.content, ChunkLevel::L2, &metadata) {
            chunk_ids.push(chunk.id.clone());
            index
                .originals
                .insert(chunk.id.clone(), chunk.content.clone());
            chunk.content = code_normalize(&chunk.content);
            chunks.push(chunk);
        }
        index.entries.insert(
            id.clone(),
            IndexedEntry {
                digest: entry.digest.clone(),
                chunk_ids,
            },
        );
        stats.updated_entries += 1;
    }
    stats.chunks = index.originals.len();
    (stats, chunks)
}

fn remove_entry(index: &mut ProjectIndex, id: &str) {
    if let Some(entry) = index.entries.remove(id) {
        for chunk_id in entry.chunk_ids {
            index.retriever.remove(&chunk_id);
            index.originals.remove(&chunk_id);
        }
    }
}

pub(super) fn refresh(
    operation: &KnowledgeOperation,
    config: &KnowledgeConfig,
    embedder: Option<Arc<dyn EmbeddingProvider>>,
    retry_degraded: bool,
) -> Result<(KnowledgeStats, Arc<ProjectIndex>), ClassifiedError> {
    let generation = operation.generation()?;
    let digest = config_digest(config)?;
    let sources = scan(&operation.project)?;
    let previous = current_index(&operation.project).filter(|index| {
        index.generation == generation
            && index.config_digest == digest
            && (!retry_degraded || index.embedding_warning.is_none())
    });
    if let Some(index) = previous.as_ref().filter(|index| {
        let mut warnings = sources.warnings.clone();
        if let Some(warning) = &index.embedding_warning {
            warnings.push(warning.clone());
        }
        warnings.truncate(5);
        same_entries(&index.entries, &sources.entries) && index.warnings == warnings
    }) {
        return Ok((
            KnowledgeStats {
                files: index.files,
                chunks: index.chunks,
                updated_entries: 0,
                reused_entries: index.entries.len(),
                removed_entries: 0,
            },
            Arc::clone(index),
        ));
    }
    let mut index = previous.map_or_else(
        || empty_index(config, generation, digest),
        |old| (*old).clone(),
    );
    let (stats, chunks) = update_entries(&mut index, &sources, config);
    if let Some(warning) = finalize_index(&mut index.retriever, chunks, embedder.as_ref()) {
        index.embedding_warning = Some(warning);
    }
    index.files = stats.files;
    index.chunks = stats.chunks;
    index.indexed_at = chrono::Utc::now();
    index.warnings = sources.warnings;
    if let Some(warning) = &index.embedding_warning {
        index.warnings.push(warning.clone());
    }
    index.warnings.truncate(5);
    let mut retrieval = retrieval_config(config);
    index.effective = KnowledgeConfiguration::from_config(config);
    if embedder.is_none() || index.embedding_warning.is_some() || !index.retriever.has_embeddings()
    {
        if config.embedding_enabled {
            retrieval.strategy = SearchStrategy::KeywordSearch;
            index.effective.retrieval_strategy = "keyword".into();
        }
        index.effective.embedding_model = None;
        index.effective.embedding_dimensions = None;
        index.embedder = None;
    } else {
        index.effective.embedding_model = embedder
            .as_ref()
            .map(|provider| provider.model_name().to_owned());
        index.effective.embedding_dimensions =
            embedder.as_ref().map(|provider| provider.dimensions());
        index.embedder = embedder;
    }
    index.retriever.set_config(retrieval);
    let index = publish(operation.docs.clone(), index)?;
    Ok((stats, index))
}

fn publish(key: PathBuf, mut index: ProjectIndex) -> Result<Arc<ProjectIndex>, ClassifiedError> {
    let mut map = cache()
        .lock()
        .map_err(|_| ClassifiedError::Internal("knowledge cache poisoned".into()))?;
    if !map.contains_key(&key) && map.len() >= MAX_CACHED_PROJECT_INDEXES {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, index)| index.indexed_at)
            .map(|(key, _)| key.clone())
        {
            map.remove(&oldest);
        }
    }
    index.query_warning = Arc::new(Mutex::new(None));
    let index = Arc::new(index);
    map.insert(key, Arc::clone(&index));
    Ok(index)
}
