//! hf-corpus: Corpus management -- seed, grow, prune, merge, list.

use std::collections::HashSet;
use std::path::Path;

use hf_core::corpus::{Corpus, CorpusEntry, CorpusSource};
use hf_core::error::ClassifiedError;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Seed a corpus with initial inputs.
///
/// Each input is written to `corpus_root/<name>` with `CorpusSource::Seed`.
///
/// # Errors
/// Returns `ClassifiedError` if files cannot be written.
pub async fn seed(
    target_id: Uuid,
    corpus_root: &Path,
    inputs: Vec<(Vec<u8>, String)>,
) -> Result<Corpus, ClassifiedError> {
    tokio::fs::create_dir_all(corpus_root)
        .await
        .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
    let mut entries = Vec::new();
    for (data, name) in inputs {
        let path = corpus_root.join(&name);
        tokio::fs::write(&path, &data)
            .await
            .map_err(|e| ClassifiedError::Internal(format!("write: {e}")))?;
        entries.push(make_entry(&path, &data, CorpusSource::Seed));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id,
        root: corpus_root.to_path_buf(),
        entries,
    })
}

/// Grow the corpus by pulling new coverage-inducing inputs from the engine
/// output directory.
///
/// Files already present (by sha256) are skipped.
///
/// # Errors
/// Returns `ClassifiedError` if the directories cannot be read.
pub fn grow(corpus_root: &Path, engine_out: &Path) -> Result<Corpus, ClassifiedError> {
    let existing = list(corpus_root)?;
    let existing_hashes: HashSet<String> =
        existing.entries.iter().map(|e| e.sha256.clone()).collect();

    let mut entries = existing.entries;
    let engine_dir = engine_out
        .read_dir()
        .map_err(|e| ClassifiedError::Internal(format!("read engine_out: {e}")))?;
    for entry in engine_dir {
        let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let data = std::fs::read(&path)
            .map_err(|e| ClassifiedError::Internal(format!("read input: {e}")))?;
        let hash = sha256_hex(&data);
        if existing_hashes.contains(&hash) {
            continue;
        }
        let dest = corpus_root.join(entry.file_name());
        std::fs::copy(&path, &dest).map_err(|e| ClassifiedError::Internal(format!("copy: {e}")))?;
        entries.push(make_entry(&dest, &data, CorpusSource::Fuzzer));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: Uuid::nil(),
        root: corpus_root.to_path_buf(),
        entries,
    })
}

/// Prune redundant corpus entries, deleting their files.
///
/// An entry is redundant when another kept entry already covers it. The dedup
/// key is the `coverage_hash` when the engine has populated one (true
/// coverage-based merge); otherwise it falls back to the content `sha256`, so
/// byte-for-byte duplicate inputs are removed. The returned corpus contains
/// only the surviving entries.
///
/// # Errors
/// Returns `ClassifiedError` if files cannot be removed.
pub fn prune(mut corpus: Corpus) -> Result<Corpus, ClassifiedError> {
    let mut seen = HashSet::new();
    let mut keep = Vec::new();
    for entry in corpus.entries.drain(..) {
        // Coverage hash is the strongest signal; the content hash guarantees we
        // at least collapse identical files even when coverage data is absent.
        let key = entry
            .coverage_hash
            .clone()
            .unwrap_or_else(|| entry.sha256.clone());
        if seen.insert(key) {
            keep.push(entry);
        } else {
            let _ = std::fs::remove_file(&entry.path);
        }
    }
    corpus.entries = keep;
    Ok(corpus)
}

/// Merge two corpora, deduplicating by sha256.
pub fn merge(a: Corpus, b: Corpus) -> Result<Corpus, ClassifiedError> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    for entry in a.entries.into_iter().chain(b.entries) {
        if seen.insert(entry.sha256.clone()) {
            entries.push(entry);
        }
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: a.target_id,
        root: a.root,
        entries,
    })
}

/// List all entries in a corpus directory.
///
/// # Errors
/// Returns `ClassifiedError` if the directory cannot be read.
pub fn list(corpus_root: &Path) -> Result<Corpus, ClassifiedError> {
    let mut entries = Vec::new();
    if !corpus_root.is_dir() {
        return Ok(Corpus {
            id: Uuid::new_v4(),
            target_id: Uuid::nil(),
            root: corpus_root.to_path_buf(),
            entries,
        });
    }
    let dir = corpus_root
        .read_dir()
        .map_err(|e| ClassifiedError::Internal(format!("read dir: {e}")))?;
    for entry in dir {
        let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let data =
            std::fs::read(&path).map_err(|e| ClassifiedError::Internal(format!("read: {e}")))?;
        entries.push(make_entry(&path, &data, CorpusSource::Manual));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: Uuid::nil(),
        root: corpus_root.to_path_buf(),
        entries,
    })
}

fn make_entry(path: &Path, data: &[u8], source: CorpusSource) -> CorpusEntry {
    CorpusEntry {
        path: path.to_path_buf(),
        sha256: sha256_hex(data),
        size: data.len() as u64,
        source,
        coverage_hash: None,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
