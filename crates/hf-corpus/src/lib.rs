//! `hf-corpus` provides bounded, no-follow corpus I/O.
//!
//! | Area | API |
//! | --- | --- |
//! | Retained inputs | [`seed`], [`list`], [`prune`] |
//! | Engine discoveries | [`grow`], [`absorb`], [`minimize`] |
//! | Run isolation | [`snapshot`], [`merge_snapshot`] |

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{DirEntry, File};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};

use hf_core::corpus::{Corpus, CorpusEntry, CorpusSource};
use hf_core::error::ClassifiedError;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Maximum bounded I/O accepted by corpus operations.
///
/// Callers of explicit-limit APIs may lower these fields relative to
/// [`DEFAULT_CORPUS_LIMITS`], but may not raise them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorpusLimits {
    /// Maximum number of directory entries inspected in one operation.
    pub max_entries: usize,
    /// Maximum bytes accepted from one corpus input.
    pub max_input_bytes: u64,
    /// Maximum aggregate bytes accepted across one corpus.
    pub max_total_bytes: u64,
}

/// Default corpus I/O budget: 100,000 entries, 16 MiB per input, 512 MiB total.
pub const DEFAULT_CORPUS_LIMITS: CorpusLimits = CorpusLimits {
    max_entries: 100_000,
    max_input_bytes: 16 * 1024 * 1024,
    max_total_bytes: 512 * 1024 * 1024,
};

#[derive(Debug)]
struct PreparedInput {
    name: OsString,
    data: Vec<u8>,
    sha256: String,
}

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
    seed_with_limits(target_id, corpus_root, inputs, DEFAULT_CORPUS_LIMITS).await
}

/// Seed a corpus under an explicit I/O budget.
///
/// Existing regular entries and replacements are included in the resulting
/// entry and aggregate-byte checks before the first payload is written.
///
/// # Errors
/// Returns `ClassifiedError` if validation, bounded listing, or writing fails.
pub async fn seed_with_limits(
    target_id: Uuid,
    corpus_root: &Path,
    inputs: Vec<(Vec<u8>, String)>,
    limits: CorpusLimits,
) -> Result<Corpus, ClassifiedError> {
    let corpus_root = corpus_root.to_path_buf();
    tokio::task::spawn_blocking(move || seed_blocking(target_id, &corpus_root, inputs, limits))
        .await
        .map_err(|error| ClassifiedError::Internal(format!("seed task failed: {error}")))?
}

fn seed_blocking(
    target_id: Uuid,
    corpus_root: &Path,
    inputs: Vec<(Vec<u8>, String)>,
    limits: CorpusLimits,
) -> Result<Corpus, ClassifiedError> {
    validate_limits(limits)?;
    validate_seed_inputs(&inputs, limits)?;
    ensure_regular_directory(corpus_root)?;
    validate_seed_result(corpus_root, &inputs, limits)?;
    let mut entries = Vec::new();
    for (data, name) in inputs {
        let name = safe_entry_name(&name)?;
        let path = corpus_root.join(name);
        atomic_write(&path, &data)?;
        entries.push(make_entry(&path, &data, CorpusSource::Seed));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id,
        root: corpus_root.to_path_buf(),
        entries,
    })
}

fn validate_seed_result(
    corpus_root: &Path,
    inputs: &[(Vec<u8>, String)],
    limits: CorpusLimits,
) -> Result<(), ClassifiedError> {
    let existing = list_with_limits(corpus_root, limits)?;
    let mut sizes_by_name: HashMap<OsString, u64> = existing
        .entries
        .iter()
        .filter_map(|entry| {
            entry
                .path
                .file_name()
                .map(|name| (name.to_owned(), entry.size))
        })
        .collect();
    let mut total_bytes = corpus_size(&existing.entries, limits)?;
    for (data, name) in inputs {
        let name = safe_entry_name(name)?.to_owned();
        if let Some(replaced_size) = sizes_by_name.insert(name, data_len_u64(data)?) {
            total_bytes = total_bytes.saturating_sub(replaced_size);
        }
        enforce_entry_limit(sizes_by_name.len(), limits)?;
        total_bytes = checked_total(total_bytes, data_len_u64(data)?, limits)?;
    }
    Ok(())
}

fn validate_seed_inputs(
    inputs: &[(Vec<u8>, String)],
    limits: CorpusLimits,
) -> Result<(), ClassifiedError> {
    enforce_entry_limit(inputs.len(), limits)?;
    let mut names = HashSet::new();
    let mut total_bytes = 0_u64;
    for (data, name) in inputs {
        let name = safe_entry_name(name)?;
        if !names.insert(name.to_owned()) {
            return Err(ClassifiedError::Validation(format!(
                "duplicate corpus entry name: {}",
                name.to_string_lossy()
            )));
        }
        let size = u64::try_from(data.len()).map_err(|_| {
            ClassifiedError::Validation("corpus input size does not fit in u64".to_owned())
        })?;
        enforce_input_size(size, limits, name.to_string_lossy().as_ref())?;
        total_bytes = checked_total(total_bytes, size, limits)?;
    }
    Ok(())
}

/// Grow the corpus by pulling new coverage-inducing inputs from the engine
/// output directory.
///
/// New inputs live in different places per engine: AFL++ writes them to a
/// `queue/` directory (nested under an instance dir for single-instance runs,
/// e.g. `out/default/queue/`), while libFuzzer writes them in place into the
/// corpus directory itself -- so its `out/` holds only crash artifacts. This
/// pulls from the queue directories and any plausible top-level inputs, while
/// excluding crash artifacts (`crash-*`, `SIG*.PC.*`, ...) and engine
/// bookkeeping (`fuzzer_stats`, `plot_data`, ...) that must not enter the
/// corpus. Files already present (by sha256) are skipped.
///
/// # Errors
/// Returns `ClassifiedError` if a pulled input cannot be copied.
pub fn grow(corpus_root: &Path, engine_out: &Path) -> Result<Corpus, ClassifiedError> {
    let limits = DEFAULT_CORPUS_LIMITS;
    ensure_regular_directory(corpus_root)?;
    let existing = list_with_limits(corpus_root, limits)?;
    let mut seen: HashSet<String> = existing.entries.iter().map(|e| e.sha256.clone()).collect();
    let mut entries = existing.entries;
    let mut total_bytes = corpus_size(&entries, limits)?;

    for path in collect_candidate_inputs(engine_out, limits)? {
        let Some(data) = read_regular_file_bounded(&path, limits)? else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        let hash = sha256_hex(&data);
        if !seen.insert(hash.clone()) {
            continue;
        }
        enforce_entry_limit(entries.len().saturating_add(1), limits)?;
        total_bytes = checked_total(total_bytes, data_len_u64(&data)?, limits)?;
        let dest = grow_dest_path(corpus_root, &path, &hash);
        atomic_write(&dest, &data)?;
        entries.push(make_entry(&dest, &data, CorpusSource::Fuzzer));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: Uuid::nil(),
        root: corpus_root.to_path_buf(),
        entries,
    })
}

/// Copy a retained flat corpus into an empty run-local directory.
///
/// The source is fully preflighted before the first destination write. Any
/// symlink or non-regular source entry fails closed. Files are copied in
/// deterministic filename order through fresh-inode atomic writes.
///
/// # Errors
/// Returns `ClassifiedError` when either directory is unsafe, the destination
/// is not empty, an I/O limit is exceeded, or a file cannot be copied.
pub fn snapshot(corpus_root: &Path, run_root: &Path) -> Result<Corpus, ClassifiedError> {
    snapshot_with_limits(corpus_root, run_root, DEFAULT_CORPUS_LIMITS)
}

/// Copy a retained flat corpus under an explicit I/O budget.
///
/// See [`snapshot`] for safety and ordering guarantees.
///
/// # Errors
/// Returns `ClassifiedError` when validation, bounded reading, or copying
/// fails.
pub fn snapshot_with_limits(
    corpus_root: &Path,
    run_root: &Path,
    limits: CorpusLimits,
) -> Result<Corpus, ClassifiedError> {
    validate_limits(limits)?;
    let prepared = prepare_flat_directory(corpus_root, limits)?;
    ensure_regular_directory(run_root)?;
    ensure_distinct_directories(corpus_root, run_root)?;
    ensure_empty_directory(run_root, limits)?;

    let mut entries = Vec::with_capacity(prepared.len());
    for input in prepared {
        let destination = run_root.join(&input.name);
        atomic_write(&destination, &input.data)?;
        entries.push(make_entry(&destination, &input.data, CorpusSource::Manual));
    }
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: Uuid::nil(),
        root: run_root.to_path_buf(),
        entries,
    })
}

/// Merge new inputs from a run-local snapshot into the retained corpus.
///
/// Both flat directories are fully preflighted before the first retained
/// corpus write. Symlinks and non-regular entries fail closed. Content already
/// present in the retained corpus is skipped by SHA-256; unique inputs are
/// added through fresh-inode atomic writes and tagged [`CorpusSource::Fuzzer`].
/// The returned count is the number of newly retained inputs.
///
/// # Errors
/// Returns `ClassifiedError` when a directory is unsafe, the combined corpus
/// exceeds a limit, or an atomic write fails.
pub fn merge_snapshot(
    corpus_root: &Path,
    run_root: &Path,
) -> Result<(Corpus, usize), ClassifiedError> {
    merge_snapshot_with_limits(corpus_root, run_root, DEFAULT_CORPUS_LIMITS)
}

/// Merge a run-local snapshot under an explicit I/O budget.
///
/// See [`merge_snapshot`] for safety, deduplication, and ordering guarantees.
///
/// # Errors
/// Returns `ClassifiedError` when preflight, bounded reading, or copying fails.
pub fn merge_snapshot_with_limits(
    corpus_root: &Path,
    run_root: &Path,
    limits: CorpusLimits,
) -> Result<(Corpus, usize), ClassifiedError> {
    validate_limits(limits)?;
    ensure_regular_directory(corpus_root)?;
    ensure_distinct_directories(corpus_root, run_root)?;
    let retained = list_flat_directory(corpus_root, limits)?;
    let discovered = prepare_flat_directory(run_root, limits)?;

    let mut seen: HashSet<String> = retained.iter().map(|entry| entry.sha256.clone()).collect();
    let mut names: HashSet<OsString> = retained
        .iter()
        .filter_map(|entry| entry.path.file_name().map(std::ffi::OsStr::to_owned))
        .collect();
    let mut total_bytes = corpus_size(&retained, limits)?;
    let mut additions = Vec::new();
    for mut input in discovered {
        if !seen.insert(input.sha256.clone()) {
            continue;
        }
        enforce_entry_limit(retained.len().saturating_add(additions.len() + 1), limits)?;
        total_bytes = checked_total(total_bytes, data_len_u64(&input.data)?, limits)?;
        input.name = unique_input_name(&input.name, &input.sha256, &mut names);
        additions.push(input);
    }

    let mut entries = retained;
    for input in &additions {
        let destination = corpus_root.join(&input.name);
        atomic_write(&destination, &input.data)?;
        entries.push(make_entry(&destination, &input.data, CorpusSource::Fuzzer));
    }
    let added = additions.len();
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

/// Collect candidate coverage-input files from an engine output directory:
/// every file directly under a `queue/` dir (AFL++, including the nested
/// `out/<instance>/queue/` layout) plus top-level files that look like inputs
/// rather than crash artifacts or bookkeeping.
fn collect_candidate_inputs(
    engine_out: &Path,
    limits: CorpusLimits,
) -> Result<Vec<PathBuf>, ClassifiedError> {
    let mut candidates = Vec::new();
    if !is_regular_directory(engine_out) {
        return Ok(candidates);
    }

    let mut queue_dirs = vec![engine_out.join("queue")];
    let mut inspected = 0_usize;
    let top_entries = sorted_directory_entries(engine_out, &mut inspected, limits)?;
    for entry in &top_entries {
        let file_type = entry.file_type().map_err(|error| {
            ClassifiedError::Internal(format!("inspect engine output entry: {error}"))
        })?;
        if file_type.is_dir() {
            let queue = entry.path().join("queue");
            if is_regular_directory(&queue) {
                queue_dirs.push(queue);
            }
        } else if file_type.is_file()
            && is_coverage_input_name(&entry.file_name().to_string_lossy())
        {
            candidates.push(entry.path());
        }
    }
    queue_dirs.sort();
    queue_dirs.dedup();
    for dir in queue_dirs {
        if !is_regular_directory(&dir) {
            continue;
        }
        for entry in sorted_directory_entries(&dir, &mut inspected, limits)? {
            let file_type = entry.file_type().map_err(|error| {
                ClassifiedError::Internal(format!("inspect engine queue entry: {error}"))
            })?;
            if file_type.is_file() {
                candidates.push(entry.path());
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    enforce_entry_limit(candidates.len(), limits)?;
    Ok(candidates)
}

/// Whether a top-level engine-output filename is a coverage input rather than a
/// crash artifact or engine bookkeeping file.
fn is_coverage_input_name(name: &str) -> bool {
    const ARTIFACT_PREFIXES: &[&str] = &["crash-", "leak-", "timeout-", "oom-"];
    const BOOKKEEPING: &[&str] = &[
        "fuzzer_stats",
        "fuzzer_setup",
        "cmdline",
        "plot_data",
        "fastresume.bin",
        ".cur_input",
        "README.txt",
        "HONGGFUZZ.REPORT.TXT",
    ];
    if ARTIFACT_PREFIXES.iter().any(|p| name.starts_with(p)) || BOOKKEEPING.contains(&name) {
        return false;
    }
    // honggfuzz crash files: SIG<signal>.PC.<...>.
    !(name.starts_with("SIG") && name.contains(".PC."))
}

/// Whether `path` is a real directory rather than a symlink to one.
fn is_regular_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// Create a directory if needed, then reject symlinks and non-directories.
fn ensure_regular_directory(path: &Path) -> Result<(), ClassifiedError> {
    std::fs::create_dir_all(path)
        .map_err(|e| ClassifiedError::Internal(format!("mkdir {}: {e}", path.display())))?;
    if is_regular_directory(path) {
        Ok(())
    } else {
        Err(ClassifiedError::Validation(format!(
            "corpus path is not a regular directory: {}",
            path.display()
        )))
    }
}

/// Accept one filename component only; absolute paths and traversal escape the
/// corpus boundary and are never valid seed names.
fn safe_entry_name(name: &str) -> Result<&std::ffi::OsStr, ClassifiedError> {
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(name)), None) => Ok(name),
        _ => Err(ClassifiedError::Validation(format!(
            "corpus entry name must be one path component: {name}"
        ))),
    }
}

/// Replace a corpus entry through a fresh inode so an attacker-planted
/// destination symlink is replaced rather than followed.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), ClassifiedError> {
    use std::io::Write as _;

    let parent = path.parent().ok_or_else(|| {
        ClassifiedError::Validation(format!("corpus entry has no parent: {}", path.display()))
    })?;
    if !is_regular_directory(parent) {
        return Err(ClassifiedError::Validation(format!(
            "corpus entry parent is not a regular directory: {}",
            parent.display()
        )));
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".hobot-fuzz-corpus-")
        .tempfile_in(parent)
        .map_err(|e| ClassifiedError::Internal(format!("create corpus temp: {e}")))?;
    temporary
        .write_all(data)
        .map_err(|e| ClassifiedError::Internal(format!("write corpus temp: {e}")))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| ClassifiedError::Internal(format!("sync corpus temp: {e}")))?;
    temporary
        .persist(path)
        .map_err(|e| ClassifiedError::Internal(format!("commit corpus entry: {}", e.error)))?;
    Ok(())
}

/// Destination path for a pulled input: keep the source filename, falling back
/// to a content-hash suffix if a different file already occupies that name.
fn grow_dest_path(corpus_root: &Path, src: &Path, hash: &str) -> std::path::PathBuf {
    let name = src
        .file_name()
        .map_or_else(|| hash.to_owned(), |n| n.to_string_lossy().into_owned());
    let dest = corpus_root.join(&name);
    if dest.exists() {
        corpus_root.join(format!("{name}-{}", &hash[..8.min(hash.len())]))
    } else {
        dest
    }
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
    let corpus_root = corpus.root.clone();
    for entry in corpus.entries.drain(..) {
        // Coverage hash is the strongest signal; the content hash guarantees we
        // at least collapse identical files even when coverage data is absent.
        let key = entry
            .coverage_hash
            .clone()
            .unwrap_or_else(|| entry.sha256.clone());
        if seen.insert(key) {
            keep.push(entry);
        } else if is_direct_regular_entry(&corpus_root, &entry.path) {
            let _ = std::fs::remove_file(&entry.path);
        }
    }
    corpus.entries = keep;
    Ok(corpus)
}

fn is_direct_regular_entry(corpus_root: &Path, path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    path == corpus_root.join(name)
        && std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
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
    let limits = DEFAULT_CORPUS_LIMITS;
    enforce_entry_limit(inputs.len(), limits)?;
    ensure_regular_directory(corpus_root)?;
    let existing = list_with_limits(corpus_root, limits)?;
    let mut seen: HashSet<String> = existing.entries.iter().map(|e| e.sha256.clone()).collect();
    let mut entries = existing.entries;
    let mut total_bytes = corpus_size(&entries, limits)?;
    let mut added = 0usize;
    let mut ordered_inputs = inputs.to_vec();
    ordered_inputs.sort();
    for input in &ordered_inputs {
        let Some(data) = read_regular_file_bounded(input, limits)? else {
            continue;
        };
        let hash = sha256_hex(&data);
        if !seen.insert(hash.clone()) {
            continue;
        }
        enforce_entry_limit(entries.len().saturating_add(1), limits)?;
        total_bytes = checked_total(total_bytes, data_len_u64(&data)?, limits)?;
        // Name absorbed entries distinctly so they never collide with an
        // existing corpus file of the same basename. Two distinct crash inputs
        // that share a basename (e.g. `crash-abc` pulled from different run
        // dirs) must not overwrite each other, so fall back to a content-hash
        // suffix when the preferred name is already taken -- mirroring `grow`.
        let stem = input
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("crash");
        let base = format!("crash_{stem}");
        let preferred = corpus_root.join(&base);
        let dest = if preferred.exists() {
            corpus_root.join(format!("{base}-{}", &hash[..8.min(hash.len())]))
        } else {
            preferred
        };
        atomic_write(&dest, &data)?;
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
    let limits = DEFAULT_CORPUS_LIMITS;
    ensure_regular_directory(corpus_root)?;
    let kept = prepare_flat_directory(minimized_dir, limits)?;
    let live = list_with_limits(corpus_root, limits)?.entries;
    let mut live_by_hash: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut reserved_names: HashSet<OsString> = HashSet::new();
    for entry in &live {
        live_by_hash
            .entry(entry.sha256.clone())
            .or_default()
            .push(entry.path.clone());
        if let Some(name) = entry.path.file_name() {
            reserved_names.insert(name.to_owned());
        }
    }

    // Prefer one existing path for each surviving content hash. A merge tool
    // may rename an input, but writing that second name would leave duplicate
    // bytes in the retained corpus and make the returned inventory inexact.
    let mut seen_hashes = HashSet::new();
    let mut selected_existing = HashSet::new();
    let mut entries = Vec::new();
    let mut additions = Vec::new();
    for mut input in kept {
        if !seen_hashes.insert(input.sha256.clone()) {
            continue;
        }
        if let Some(paths) = live_by_hash.get_mut(&input.sha256) {
            if let Some(path) = paths.first().cloned() {
                selected_existing.insert(path.clone());
                entries.push(make_entry(&path, &input.data, CorpusSource::Minimized));
                continue;
            }
        }
        input.name = unique_input_name(&input.name, &input.sha256, &mut reserved_names);
        additions.push(input);
    }

    // Write new survivors before deleting redundant live inputs. Names are
    // reserved against every regular live entry, so these writes cannot replace
    // an existing input. `atomic_write` also replaces a same-name symlink rather
    // than following it.
    for input in additions {
        let destination = corpus_root.join(&input.name);
        atomic_write(&destination, &input.data)?;
        entries.push(make_entry(
            &destination,
            &input.data,
            CorpusSource::Minimized,
        ));
    }
    for entry in live {
        if !selected_existing.contains(&entry.path) {
            std::fs::remove_file(&entry.path).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "remove redundant corpus input {}: {error}",
                    entry.path.display()
                ))
            })?;
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
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
    list_with_limits(corpus_root, DEFAULT_CORPUS_LIMITS)
}

/// List corpus entries under an explicit I/O budget.
///
/// Entries are returned in filename order. Symlinks and non-regular files are
/// ignored for compatibility with existing retained corpora, but every
/// directory entry is counted against `limits.max_entries`.
///
/// # Errors
/// Returns `ClassifiedError` if the root is not a regular directory, a limit
/// is exceeded, or a regular input cannot be read safely.
pub fn list_with_limits(
    corpus_root: &Path,
    limits: CorpusLimits,
) -> Result<Corpus, ClassifiedError> {
    validate_limits(limits)?;
    match std::fs::symlink_metadata(corpus_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(ClassifiedError::Validation(format!(
                "corpus path is not a regular directory: {}",
                corpus_root.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Corpus {
                id: Uuid::new_v4(),
                target_id: Uuid::nil(),
                root: corpus_root.to_path_buf(),
                entries: Vec::new(),
            });
        }
        Err(error) => {
            return Err(ClassifiedError::Internal(format!(
                "inspect corpus: {error}"
            )));
        }
    }
    let entries = list_directory_entries(corpus_root, limits, false)?;
    Ok(Corpus {
        id: Uuid::new_v4(),
        target_id: Uuid::nil(),
        root: corpus_root.to_path_buf(),
        entries,
    })
}

fn list_flat_directory(
    corpus_root: &Path,
    limits: CorpusLimits,
) -> Result<Vec<CorpusEntry>, ClassifiedError> {
    ensure_existing_regular_directory(corpus_root)?;
    list_directory_entries(corpus_root, limits, true)
}

fn list_directory_entries(
    corpus_root: &Path,
    limits: CorpusLimits,
    strict: bool,
) -> Result<Vec<CorpusEntry>, ClassifiedError> {
    let mut inspected = 0_usize;
    let dir = sorted_directory_entries(corpus_root, &mut inspected, limits)?;
    let mut entries = Vec::with_capacity(dir.len());
    let mut total_bytes = 0_u64;
    for entry in dir {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            ClassifiedError::Internal(format!("inspect corpus entry {}: {error}", path.display()))
        })?;
        if !file_type.is_file() {
            if strict {
                return Err(ClassifiedError::Validation(format!(
                    "flat corpus contains a non-regular entry: {}",
                    path.display()
                )));
            }
            continue;
        }
        let data = read_regular_file_bounded(&path, limits)?;
        let Some(data) = data else {
            if strict {
                return Err(ClassifiedError::Validation(format!(
                    "corpus entry changed during preflight: {}",
                    path.display()
                )));
            }
            continue;
        };
        total_bytes = checked_total(total_bytes, data_len_u64(&data)?, limits)?;
        entries.push(make_entry(&path, &data, CorpusSource::Manual));
    }
    Ok(entries)
}

fn make_entry(path: &Path, data: &[u8], source: CorpusSource) -> CorpusEntry {
    CorpusEntry {
        path: path.to_path_buf(),
        sha256: sha256_hex(data),
        size: u64::try_from(data.len()).unwrap_or(u64::MAX),
        source,
        coverage_hash: None,
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn prepare_flat_directory(
    directory: &Path,
    limits: CorpusLimits,
) -> Result<Vec<PreparedInput>, ClassifiedError> {
    ensure_existing_regular_directory(directory)?;
    let mut inspected = 0_usize;
    let entries = sorted_directory_entries(directory, &mut inspected, limits)?;
    let mut prepared = Vec::with_capacity(entries.len());
    let mut total_bytes = 0_u64;
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            ClassifiedError::Internal(format!("inspect corpus entry {}: {error}", path.display()))
        })?;
        if !file_type.is_file() {
            return Err(ClassifiedError::Validation(format!(
                "flat corpus contains a non-regular entry: {}",
                path.display()
            )));
        }
        let data = read_regular_file_bounded(&path, limits)?.ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "corpus entry changed during preflight: {}",
                path.display()
            ))
        })?;
        total_bytes = checked_total(total_bytes, data_len_u64(&data)?, limits)?;
        prepared.push(PreparedInput {
            name: entry.file_name(),
            sha256: sha256_hex(&data),
            data,
        });
    }
    Ok(prepared)
}

fn ensure_existing_regular_directory(path: &Path) -> Result<(), ClassifiedError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(ClassifiedError::Validation(format!(
            "corpus path is not a regular directory: {}",
            path.display()
        ))),
        Err(error) => Err(ClassifiedError::Internal(format!(
            "inspect corpus directory {}: {error}",
            path.display()
        ))),
    }
}

fn ensure_empty_directory(path: &Path, limits: CorpusLimits) -> Result<(), ClassifiedError> {
    let mut inspected = 0_usize;
    if let Some(entry) = sorted_directory_entries(path, &mut inspected, limits)?.first() {
        return Err(ClassifiedError::Validation(format!(
            "run corpus destination is not empty: {}",
            entry.path().display()
        )));
    }
    Ok(())
}

fn ensure_distinct_directories(left: &Path, right: &Path) -> Result<(), ClassifiedError> {
    let left = std::fs::canonicalize(left).map_err(|error| {
        ClassifiedError::Internal(format!(
            "resolve corpus directory {}: {error}",
            left.display()
        ))
    })?;
    let right = std::fs::canonicalize(right).map_err(|error| {
        ClassifiedError::Internal(format!(
            "resolve corpus directory {}: {error}",
            right.display()
        ))
    })?;
    if left == right {
        return Err(ClassifiedError::Validation(
            "retained and run-local corpus directories must differ".to_owned(),
        ));
    }
    Ok(())
}

fn unique_input_name(
    preferred: &std::ffi::OsStr,
    sha256: &str,
    names: &mut HashSet<OsString>,
) -> OsString {
    if names.insert(preferred.to_owned()) {
        return preferred.to_owned();
    }
    let hash_name = OsString::from(format!("hf-{sha256}"));
    if names.insert(hash_name.clone()) {
        return hash_name;
    }
    let mut suffix = 1_u64;
    loop {
        let candidate = OsString::from(format!("hf-{sha256}-{suffix}"));
        if names.insert(candidate.clone()) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

fn data_len_u64(data: &[u8]) -> Result<u64, ClassifiedError> {
    u64::try_from(data.len()).map_err(|_| {
        ClassifiedError::Validation("corpus input size does not fit in u64".to_owned())
    })
}

fn validate_limits(limits: CorpusLimits) -> Result<(), ClassifiedError> {
    if limits.max_entries > DEFAULT_CORPUS_LIMITS.max_entries
        || limits.max_input_bytes > DEFAULT_CORPUS_LIMITS.max_input_bytes
        || limits.max_total_bytes > DEFAULT_CORPUS_LIMITS.max_total_bytes
    {
        return Err(ClassifiedError::Validation(
            "corpus I/O limits may be lowered but not raised above the safety defaults".to_owned(),
        ));
    }
    Ok(())
}

fn enforce_entry_limit(count: usize, limits: CorpusLimits) -> Result<(), ClassifiedError> {
    if count > limits.max_entries {
        return Err(ClassifiedError::Validation(format!(
            "corpus entry limit exceeded: {count} > {}",
            limits.max_entries
        )));
    }
    Ok(())
}

fn enforce_input_size(
    size: u64,
    limits: CorpusLimits,
    display_name: &str,
) -> Result<(), ClassifiedError> {
    if size > limits.max_input_bytes {
        return Err(ClassifiedError::Validation(format!(
            "corpus input exceeds {} bytes: {display_name} ({size} bytes)",
            limits.max_input_bytes
        )));
    }
    Ok(())
}

fn checked_total(current: u64, added: u64, limits: CorpusLimits) -> Result<u64, ClassifiedError> {
    let total = current
        .checked_add(added)
        .ok_or_else(|| ClassifiedError::Validation("corpus aggregate size overflow".to_owned()))?;
    if total > limits.max_total_bytes {
        return Err(ClassifiedError::Validation(format!(
            "corpus aggregate limit exceeded: {total} > {} bytes",
            limits.max_total_bytes
        )));
    }
    Ok(total)
}

fn corpus_size(entries: &[CorpusEntry], limits: CorpusLimits) -> Result<u64, ClassifiedError> {
    entries.iter().try_fold(0_u64, |total, entry| {
        checked_total(total, entry.size, limits)
    })
}

fn sorted_directory_entries(
    directory: &Path,
    inspected: &mut usize,
    limits: CorpusLimits,
) -> Result<Vec<DirEntry>, ClassifiedError> {
    let mut entries = Vec::new();
    let read_dir = std::fs::read_dir(directory).map_err(|error| {
        ClassifiedError::Internal(format!("read directory {}: {error}", directory.display()))
    })?;
    for entry in read_dir {
        *inspected = inspected
            .checked_add(1)
            .ok_or_else(|| ClassifiedError::Validation("corpus entry count overflow".to_owned()))?;
        enforce_entry_limit(*inspected, limits)?;
        entries.push(entry.map_err(|error| {
            ClassifiedError::Internal(format!(
                "read directory entry in {}: {error}",
                directory.display()
            ))
        })?);
    }
    entries.sort_by_key(DirEntry::file_name);
    Ok(entries)
}

fn read_regular_file_bounded(
    path: &Path,
    limits: CorpusLimits,
) -> Result<Option<Vec<u8>>, ClassifiedError> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(ClassifiedError::Internal(format!(
                "inspect corpus input {}: {error}",
                path.display()
            )));
        }
    };
    enforce_input_size(before.len(), limits, &path.display().to_string())?;

    let mut file = File::open(path).map_err(|error| {
        ClassifiedError::Internal(format!("open corpus input {}: {error}", path.display()))
    })?;
    let opened = file.metadata().map_err(|error| {
        ClassifiedError::Internal(format!(
            "inspect open corpus input {}: {error}",
            path.display()
        ))
    })?;
    if !opened.file_type().is_file() || !same_file(&before, &opened) {
        return Err(ClassifiedError::Validation(format!(
            "corpus input changed while opening: {}",
            path.display()
        )));
    }
    enforce_input_size(opened.len(), limits, &path.display().to_string())?;

    let read_limit = limits.max_input_bytes.saturating_add(1);
    let mut data = Vec::new();
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut data)
        .map_err(|error| {
            ClassifiedError::Internal(format!("read corpus input {}: {error}", path.display()))
        })?;
    let size = u64::try_from(data.len()).map_err(|_| {
        ClassifiedError::Validation("corpus input size does not fit in u64".to_owned())
    })?;
    enforce_input_size(size, limits, &path.display().to_string())?;
    Ok(Some(data))
}

#[cfg(unix)]
fn same_file(before: &std::fs::Metadata, opened: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() == opened.dev() && before.ino() == opened.ino()
}

#[cfg(not(unix))]
fn same_file(_before: &std::fs::Metadata, _opened: &std::fs::Metadata) -> bool {
    true
}
