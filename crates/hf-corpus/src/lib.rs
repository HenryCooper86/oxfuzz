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

/// Absorb crash reproducer inputs back into the corpus.
///
/// Each path in `inputs` is a crash-triggering input surfaced by triage. Inputs
/// whose content is not already in the corpus (by sha256) are copied into
/// `corpus_root` tagged `CorpusSource::Fuzzer` -- they are exactly the inputs
/// the harness should keep exercising, closing the run -> triage -> corpus
/// loop. Returns the full corpus and the number of newly added entries.
///
/// # Errors
/// Returns `ClassifiedError` if the corpus cannot be read or an input cannot be
/// copied.
pub fn absorb(
    corpus_root: &Path,
    inputs: &[std::path::PathBuf],
) -> Result<(Corpus, usize), ClassifiedError> {
    std::fs::create_dir_all(corpus_root)
        .map_err(|e| ClassifiedError::Internal(format!("mkdir corpus: {e}")))?;
    let existing = list(corpus_root)?;
    let mut seen: HashSet<String> = existing.entries.iter().map(|e| e.sha256.clone()).collect();
    let mut entries = existing.entries;
    let mut added = 0usize;
    for input in inputs {
        if !input.is_file() {
            continue;
        }
        let data = std::fs::read(input)
            .map_err(|e| ClassifiedError::Internal(format!("read crash input: {e}")))?;
        let hash = sha256_hex(&data);
        if !seen.insert(hash) {
            continue;
        }
        // Name absorbed entries distinctly so they never collide with an
        // existing corpus file of the same basename.
        let stem = input
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("crash");
        let dest = corpus_root.join(format!("crash_{stem}"));
        std::fs::write(&dest, &data)
            .map_err(|e| ClassifiedError::Internal(format!("write absorbed: {e}")))?;
        entries.push(make_entry(&dest, &data, CorpusSource::Fuzzer));
        added += 1;
    }
    Ok((
        Corpus {
            id: Uuid::new_v4(),
            target_id: Uuid::nil(),
            root: corpus_root.to_path_buf(),
            entries,
        },
        added,
    ))
}

/// Adopt a coverage-minimized input set as the live corpus.
///
/// `minimized_dir` holds the survivors of an out-of-band coverage-guided merge
/// (e.g. libFuzzer `-merge=1`). Every file in `corpus_root` that is not part of
/// the minimized set is deleted, the minimized inputs are written into
/// `corpus_root`, and the returned `Corpus` tags each survivor
/// `CorpusSource::Minimized`. Inputs already present (by content) are left in
/// place; only redundant ones are dropped.
///
/// # Errors
/// Returns `ClassifiedError` if the directories cannot be read or written.
pub fn minimize(corpus_root: &Path, minimized_dir: &Path) -> Result<Corpus, ClassifiedError> {
    // Hashes of the inputs the merge decided to keep.
    let kept = list(minimized_dir)?;
    let kept_hashes: HashSet<String> = kept.entries.iter().map(|e| e.sha256.clone()).collect();

    // Drop any live input whose content is not in the minimized set.
    for entry in list(corpus_root)?.entries {
        if !kept_hashes.contains(&entry.sha256) {
            let _ = std::fs::remove_file(&entry.path);
        }
    }

    // Make sure every kept input exists in the live corpus directory.
    let mut entries = Vec::new();
    for entry in kept.entries {
        let dest = corpus_root.join(entry.path.file_name().unwrap_or(entry.path.as_os_str()));
        if !dest.exists() {
            std::fs::copy(&entry.path, &dest)
                .map_err(|e| ClassifiedError::Internal(format!("copy minimized: {e}")))?;
        }
        let data = std::fs::read(&dest)
            .map_err(|e| ClassifiedError::Internal(format!("read minimized: {e}")))?;
        entries.push(make_entry(&dest, &data, CorpusSource::Minimized));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: Uuid::nil(),
        root: corpus_root.to_path_buf(),
        entries,
    })
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
