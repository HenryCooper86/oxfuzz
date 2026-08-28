//! Crash ingestion: scan a run output directory for engine-owned crash artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use hf_core::crash::{Crash, CrashKind, CrashOrigin};
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use uuid::Uuid;

use crate::classify::classify;

/// Maximum number of crash artifacts returned by one ingestion pass.
pub const MAX_CRASH_ARTIFACTS: usize = 1_024;

/// Maximum sanitizer report bytes read from one file.
pub const MAX_SANITIZER_REPORT_BYTES: usize = 256 * 1_024;

/// Maximum sanitizer report bytes read across one ingestion pass.
pub const MAX_AGGREGATE_REPORT_BYTES: usize = 2 * 1_024 * 1_024;

const MAX_REPORT_FILES: usize = MAX_CRASH_ARTIFACTS;

/// Crash artifacts and the resource-limit state observed while ingesting them.
#[derive(Debug, Clone)]
pub struct CrashIngestResult {
    /// Engine-owned crash artifacts, ordered deterministically by path.
    pub crashes: Vec<Crash>,
    /// Whether additional matching artifacts were excluded by the entry limit.
    pub artifact_limit_reached: bool,
    /// Whether report discovery, per-file reads, or aggregate reads hit a limit.
    pub report_limit_reached: bool,
    /// Total sanitizer report bytes retained for classification.
    pub report_bytes_read: usize,
}

impl CrashIngestResult {
    /// Whether any ingestion limit prevented a complete scan.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.artifact_limit_reached || self.report_limit_reached
    }
}

/// Scan a run output directory using the producing engine's artifact contract.
///
/// Artifact traversal is deterministic and bounded. Only regular files are
/// accepted; symlinked roots, artifact directories, artifacts, and reports are
/// never followed.
///
/// # Errors
/// Returns `ClassifiedError` when the run directory is invalid or cannot be
/// enumerated.
pub fn ingest_for_engine(
    run_dir: &Path,
    engine: EngineKind,
    run_id: Uuid,
    target_id: Uuid,
) -> Result<CrashIngestResult, ClassifiedError> {
    ingest_with_mode(run_dir, IngestMode::Engine(engine), run_id, target_id)
}

/// Scan a run output directory for crash artifacts using legacy mixed-engine
/// filename detection.
///
/// New callers should use [`ingest_for_engine`] so coverage files from one
/// engine cannot be mistaken for another engine's crash artifacts. This
/// compatibility API is still bounded and does not follow symlinks.
///
/// # Errors
/// Returns `ClassifiedError` when the run directory is invalid or cannot be
/// enumerated.
pub fn ingest(
    run_dir: &Path,
    run_id: Uuid,
    target_id: Uuid,
) -> Result<Vec<Crash>, ClassifiedError> {
    let result = ingest_with_mode(run_dir, IngestMode::Legacy, run_id, target_id)?;
    if result.is_truncated() {
        tracing::warn!(
            artifact_limit_reached = result.artifact_limit_reached,
            report_limit_reached = result.report_limit_reached,
            "legacy crash ingestion reached a safety limit"
        );
    }
    Ok(result.crashes)
}

#[derive(Debug, Clone, Copy)]
enum IngestMode {
    Engine(EngineKind),
    Legacy,
}

fn ingest_with_mode(
    run_dir: &Path,
    mode: IngestMode,
    run_id: Uuid,
    target_id: Uuid,
) -> Result<CrashIngestResult, ClassifiedError> {
    if !is_regular_directory(run_dir) {
        return Err(ClassifiedError::Validation(format!(
            "crash output is not a regular directory: {}",
            run_dir.display()
        )));
    }

    let artifacts = collect_artifacts(run_dir, mode)?;
    let artifact_limit_reached = artifacts.limit_reached;
    let artifact_paths: Vec<_> = artifacts.paths.into_iter().collect();
    let mut reports = ReportReader::default();
    let mut crashes = Vec::with_capacity(artifact_paths.len());

    for path in &artifact_paths {
        // Re-check after discovery to avoid following an artifact that was
        // replaced with a symlink between directory enumeration and use.
        if !is_regular_file(path) {
            continue;
        }
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let log = find_sanitizer_log_bounded(path, run_dir, &name, &artifact_paths, &mut reports);
        let (kind, sig, summary) = log
            .as_deref()
            .map_or((CrashKind::Other, String::new(), String::new()), classify);
        // Same report text, one read: the layer the fault lies in comes from
        // the stack the classifier already looked at.
        let origin = log
            .as_deref()
            .map_or(CrashOrigin::Unknown, crate::frames::crash_origin);
        crashes.push(Crash {
            id: Uuid::new_v4(),
            run_id,
            target_id,
            input_path: path.clone(),
            stack_signature: sig,
            kind,
            summary,
            minimized: false,
            bug_report: None,
            casr: None,
            origin,
        });
    }

    Ok(CrashIngestResult {
        crashes,
        artifact_limit_reached,
        report_limit_reached: reports.limit_reached,
        report_bytes_read: reports.bytes_read,
    })
}

#[derive(Debug, Default)]
struct BoundedPaths {
    paths: BTreeSet<PathBuf>,
    limit_reached: bool,
}

impl BoundedPaths {
    fn insert(&mut self, path: PathBuf) {
        self.paths.insert(path);
        if self.paths.len() > MAX_CRASH_ARTIFACTS {
            self.limit_reached = true;
            self.paths.pop_last();
        }
    }
}

/// Ingest a syzkaller campaign's retained kernel crash evidence.
///
/// `syz-manager` writes one directory per distinct bug under
/// `<run_dir>/crashes/<hash>/`, holding a one-line `description`, one or more
/// `reportN` bodies, and -- only when it managed to reproduce the bug --
/// `repro.prog` / `repro.cprog`. That nested shape is the documented exception
/// to the flat userspace artifact layout (`ENGINE_ADAPTER_STANDARD.md`), and
/// the reports are kernel oops text rather than sanitizer logs, so this walks
/// and classifies on its own terms instead of reusing [`ingest_for_engine`].
///
/// A directory whose report does not parse as a kernel report is skipped rather
/// than ingested as an unclassified crash: without a signature it would defeat
/// dedup, and a syzkaller crash directory always carries a report.
///
/// # Errors
/// Returns [`ClassifiedError::Internal`] if the crash root cannot be read.
pub fn ingest_syzkaller(
    run_dir: &Path,
    run_id: Uuid,
    target_id: Uuid,
) -> Result<CrashIngestResult, ClassifiedError> {
    let crashes_root = run_dir.join("crashes");
    let mut result = CrashIngestResult {
        crashes: Vec::new(),
        artifact_limit_reached: false,
        report_limit_reached: false,
        report_bytes_read: 0,
    };
    if !crashes_root.is_dir() {
        return Ok(result);
    }

    // Deterministic order: a run's crash list must not depend on readdir order.
    let mut bug_dirs: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(&crashes_root).map_err(|error| {
        ClassifiedError::Internal(format!(
            "read syzkaller crash directory {}: {error}",
            crashes_root.display()
        ))
    })?;
    for entry in entries.flatten() {
        // `symlink_metadata` so a symlinked bug directory cannot redirect the
        // walk outside the retained evidence tree.
        if entry
            .path()
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_dir())
        {
            bug_dirs.push(entry.path());
        }
    }
    bug_dirs.sort();
    if bug_dirs.len() > MAX_CRASH_ARTIFACTS {
        bug_dirs.truncate(MAX_CRASH_ARTIFACTS);
        result.artifact_limit_reached = true;
    }

    for bug_dir in bug_dirs {
        let Some((report_path, report)) = read_kernel_report(&bug_dir, &mut result) else {
            continue;
        };
        let Some(parsed) = crate::kernel::parse_kernel_report(&report) else {
            continue;
        };
        // The reproducer is the actionable input when syz-manager captured one;
        // otherwise the report is the only evidence the crash can point at.
        let input_path = ["repro.prog", "repro.cprog"]
            .iter()
            .map(|name| bug_dir.join(name))
            .find(|path| is_regular_file(path))
            .unwrap_or(report_path);
        let summary = read_description(&bug_dir).unwrap_or_else(|| parsed.title.clone());
        result.crashes.push(Crash {
            id: Uuid::new_v4(),
            run_id,
            target_id,
            input_path,
            stack_signature: parsed.signature,
            kind: CrashKind::KernelBug,
            summary,
            minimized: false,
            bug_report: None,
            casr: None,
            // The fault is in the kernel under test, never in a harness: a
            // syzkaller campaign has no harness.
            origin: CrashOrigin::Target,
        });
    }
    Ok(result)
}

/// The first `report*` body in a bug directory, bounded like every other report
/// read on this path.
fn read_kernel_report(bug_dir: &Path, result: &mut CrashIngestResult) -> Option<(PathBuf, String)> {
    let mut reports: Vec<PathBuf> = std::fs::read_dir(bug_dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            is_regular_file(path)
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("report"))
        })
        .collect();
    reports.sort();
    let path = reports.into_iter().next()?;
    let text = read_bounded(&path, MAX_SANITIZER_REPORT_BYTES)?;
    result.report_bytes_read = result.report_bytes_read.saturating_add(text.len());
    if result.report_bytes_read > MAX_AGGREGATE_REPORT_BYTES {
        result.report_limit_reached = true;
        return None;
    }
    Some((path, text))
}

/// syz-manager's own one-line title for the bug, when present.
fn read_description(bug_dir: &Path) -> Option<String> {
    let text = read_bounded(&bug_dir.join("description"), 4 * 1_024)?;
    let line = text.lines().next()?.trim();
    (!line.is_empty()).then(|| line.to_owned())
}

fn read_bounded(path: &Path, limit: usize) -> Option<String> {
    if !is_regular_file(path) {
        return None;
    }
    let mut buffer = Vec::new();
    File::open(path)
        .ok()?
        .take(limit as u64)
        .read_to_end(&mut buffer)
        .ok()?;
    Some(String::from_utf8_lossy(&buffer).into_owned())
}

fn collect_artifacts(run_dir: &Path, mode: IngestMode) -> Result<BoundedPaths, ClassifiedError> {
    let mut artifacts = BoundedPaths::default();

    if matches!(mode, IngestMode::Legacy)
        || matches!(mode, IngestMode::Engine(engine) if matches!(engine, EngineKind::Honggfuzz | EngineKind::LibFuzzer))
    {
        collect_files(run_dir, &mut artifacts, |name| match mode {
            IngestMode::Legacy => is_libfuzzer_crash(name) || is_honggfuzz_crash(name),
            IngestMode::Engine(EngineKind::Honggfuzz) => is_honggfuzz_crash(name),
            IngestMode::Engine(EngineKind::LibFuzzer) => is_libfuzzer_crash(name),
            IngestMode::Engine(EngineKind::AflPlusPlus | EngineKind::Syzkaller) => false,
        })?;
    }

    if matches!(
        mode,
        IngestMode::Legacy | IngestMode::Engine(EngineKind::AflPlusPlus)
    ) {
        collect_afl_artifacts(run_dir, &mut artifacts)?;
    }

    Ok(artifacts)
}

fn collect_afl_artifacts(
    run_dir: &Path,
    artifacts: &mut BoundedPaths,
) -> Result<(), ClassifiedError> {
    collect_files(&run_dir.join("crashes"), artifacts, is_afl_crash)?;

    let entries = read_directory(run_dir)?;
    for entry in entries {
        let entry = entry.map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        if !file_type.is_dir() {
            continue;
        }
        collect_files(&entry.path().join("crashes"), artifacts, is_afl_crash)?;
    }
    Ok(())
}

fn collect_files(
    dir: &Path,
    artifacts: &mut BoundedPaths,
    accepts: impl Fn(&str) -> bool,
) -> Result<(), ClassifiedError> {
    if !is_regular_directory(dir) {
        return Ok(());
    }
    for entry in read_directory(dir)? {
        let entry = entry.map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name();
        if accepts(&name.to_string_lossy()) {
            artifacts.insert(entry.path());
        }
    }
    Ok(())
}

fn read_directory(path: &Path) -> Result<std::fs::ReadDir, ClassifiedError> {
    std::fs::read_dir(path).map_err(|error| {
        ClassifiedError::Internal(format!("read crash directory {}: {error}", path.display()))
    })
}

/// Whether `path` is a real directory rather than a symlink to one.
fn is_regular_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

/// Whether `path` is a real file rather than a symlink to one.
fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
}

fn is_libfuzzer_crash(name: &str) -> bool {
    name.starts_with("crash-")
        || name.starts_with("leak-")
        || name.starts_with("timeout-")
        || name.starts_with("oom-")
}

fn is_honggfuzz_crash(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("SIG") else {
        return false;
    };
    let Some((signal, detail)) = rest.split_once(".PC.") else {
        return false;
    };
    !signal.is_empty()
        && signal
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && !detail.is_empty()
}

fn is_afl_crash(name: &str) -> bool {
    !name.eq_ignore_ascii_case("README.txt")
}

#[derive(Debug, Default)]
struct ReportReader {
    bytes_read: usize,
    files_seen: usize,
    limit_reached: bool,
    contents: BTreeMap<PathBuf, Option<String>>,
    directory_entries: BTreeMap<PathBuf, Vec<PathBuf>>,
}

impl ReportReader {
    fn read_sanitizer_report(&mut self, path: &Path) -> Option<String> {
        if let Some(cached) = self.contents.get(path) {
            return cached.clone();
        }
        if !is_regular_file(path) {
            self.contents.insert(path.to_path_buf(), None);
            return None;
        }

        let remaining = MAX_AGGREGATE_REPORT_BYTES.saturating_sub(self.bytes_read);
        if remaining == 0 {
            self.limit_reached = true;
            self.contents.insert(path.to_path_buf(), None);
            return None;
        }
        let keep = remaining.min(MAX_SANITIZER_REPORT_BYTES);
        let mut bytes = Vec::with_capacity(keep.min(8 * 1_024));
        let result =
            File::open(path).and_then(|file| file.take((keep + 1) as u64).read_to_end(&mut bytes));
        if let Err(error) = result {
            tracing::warn!(path = %path.display(), %error, "failed to read crash report");
            self.contents.insert(path.to_path_buf(), None);
            return None;
        }
        if bytes.len() > keep {
            self.limit_reached = true;
            bytes.truncate(keep);
        }
        self.bytes_read += bytes.len();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let report = looks_like_sanitizer_report(&text).then_some(text);
        self.contents.insert(path.to_path_buf(), report.clone());
        report
    }

    fn candidates(&mut self, dir: &Path) -> Vec<PathBuf> {
        if let Some(cached) = self.directory_entries.get(dir) {
            return cached.clone();
        }
        if !is_regular_directory(dir) {
            self.directory_entries.insert(dir.to_path_buf(), Vec::new());
            return Vec::new();
        }

        let remaining = MAX_REPORT_FILES.saturating_sub(self.files_seen);
        let mut paths = BTreeSet::new();
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    let Ok(entry) = entry else {
                        continue;
                    };
                    if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
                        continue;
                    }
                    let name = entry.file_name();
                    if !is_report_filename(&name.to_string_lossy()) {
                        continue;
                    }
                    if remaining == 0 {
                        self.limit_reached = true;
                        continue;
                    }
                    paths.insert(entry.path());
                    if paths.len() > remaining {
                        self.limit_reached = true;
                        paths.pop_last();
                    }
                }
            }
            Err(error) => {
                tracing::warn!(path = %dir.display(), %error, "failed to enumerate crash reports");
            }
        }

        let paths: Vec<_> = paths.into_iter().collect();
        self.files_seen += paths.len();
        self.directory_entries
            .insert(dir.to_path_buf(), paths.clone());
        paths
    }
}

fn find_sanitizer_log_bounded(
    crash_path: &Path,
    run_dir: &Path,
    crash_name: &str,
    artifacts: &[PathBuf],
    reports: &mut ReportReader,
) -> Option<String> {
    let stem = crash_name
        .split_once('-')
        .map_or(crash_name, |(_, stem)| stem);
    let stem_lower = stem.to_ascii_lowercase();
    let mut dirs = Vec::with_capacity(2);
    if let Some(parent) = crash_path.parent() {
        dirs.push(parent.to_path_buf());
    }
    if !dirs.iter().any(|dir| dir == run_dir) {
        dirs.push(run_dir.to_path_buf());
    }

    for dir in &dirs {
        let conventional = dir.join(format!("log-{stem}.txt"));
        if let Some(report) = reports.read_sanitizer_report(&conventional) {
            return Some(report);
        }
    }

    for dir in dirs {
        let candidates = reports.candidates(&dir);
        for path in &candidates {
            let name = path
                .file_name()
                .map(|value| value.to_string_lossy().to_ascii_lowercase());
            if name.is_some_and(|name| name_contains_stem(&name, &stem_lower)) {
                if let Some(report) = reports.read_sanitizer_report(path) {
                    return Some(report);
                }
            }
        }

        let artifacts_in_scope = if dir == run_dir {
            artifacts.len()
        } else {
            artifacts
                .iter()
                .filter(|path| path.parent() == Some(dir.as_path()))
                .count()
        };
        if artifacts_in_scope == 1 {
            for path in &candidates {
                if let Some(report) = reports.read_sanitizer_report(path) {
                    return Some(report);
                }
            }
        }
    }
    None
}

/// Whether `stem` appears in `name` as a delimiter-bounded token rather than an
/// incidental substring. A short crash stem (`abc`) must not claim a longer
/// unrelated report (`log-abcdef.txt`), so every match must sit against a
/// boundary character (`-`, `.`, `_`) or the start/end of the name. Both
/// arguments are expected pre-lowercased by the caller.
fn name_contains_stem(name: &str, stem: &str) -> bool {
    if stem.is_empty() {
        return false;
    }
    let is_boundary = |c: char| matches!(c, '-' | '.' | '_');
    let mut search_start = 0;
    while let Some(offset) = name[search_start..].find(stem) {
        let start = search_start + offset;
        let end = start + stem.len();
        let before_ok = start == 0 || name[..start].chars().next_back().is_some_and(is_boundary);
        let after_ok = end == name.len() || name[end..].chars().next().is_some_and(is_boundary);
        if before_ok && after_ok {
            return true;
        }
        // Advance past this occurrence's first byte to find any later match.
        search_start = start + 1;
    }
    false
}

fn is_report_filename(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.contains("coverage") || lower.contains("profraw") || lower == "fuzzer_stats" {
        return false;
    }
    lower == "report.txt"
        || lower == "sanitizer.txt"
        || lower == "sanitizer.log"
        || lower == "stderr.txt"
        || lower == "stderr.log"
        || lower == "honggfuzz.report.txt"
        || [
            "log-",
            "report-",
            "sanitizer-",
            "asan-",
            "ubsan-",
            "lsan-",
            "msan-",
        ]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Whether a file's contents resemble a sanitizer/engine crash report worth
/// classifying (rather than, say, a stats or README file).
fn looks_like_sanitizer_report(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.contains("addresssanitizer")
        || lower.contains("undefinedbehaviorsanitizer")
        || lower.contains("leaksanitizer")
        || lower.contains("sanitizer")
        || lower.contains("runtime error")
        || lower.contains("summary:")
        || lower.contains("asan")
        || lower.contains("ubsan")
        // honggfuzz HONGGFUZZ.REPORT.TXT field markers.
        || lower.contains("stack hash")
        || lower.contains("fault address")
}

#[cfg(test)]
fn find_sanitizer_log(crash_path: &Path, run_dir: &Path, crash_name: &str) -> Option<String> {
    let artifacts = collect_artifacts(run_dir, IngestMode::Legacy).ok()?;
    let artifact_paths: Vec<_> = artifacts.paths.into_iter().collect();
    let mut reports = ReportReader::default();
    find_sanitizer_log_bounded(
        crash_path,
        run_dir,
        crash_name,
        &artifact_paths,
        &mut reports,
    )
}

/// The raw report text retained beside one crash input, if the run kept any.
///
/// Ingest pairs a crash artifact with its report to classify the crash, but
/// only when the text looks like a sanitizer report, and it retains just the
/// distilled kind, signature, and summary on the [`Crash`]. A caller looking
/// for evidence the summary does not carry -- and which need not be a sanitizer
/// report at all -- needs the text itself, so this reuses the same
/// `log-<stem>.txt` naming convention without that filter.
///
/// The read is bounded. Returns `None` when no paired file was retained or it
/// cannot be read.
#[must_use]
pub fn crash_log_for_input(input_path: &Path, run_dir: &Path) -> Option<String> {
    let name = input_path.file_name()?.to_string_lossy().into_owned();
    let stem = name.split_once('-').map_or(name.as_str(), |(_, stem)| stem);

    let mut dirs: Vec<PathBuf> = Vec::with_capacity(2);
    if let Some(parent) = input_path.parent() {
        dirs.push(parent.to_path_buf());
    }
    if !dirs.iter().any(|dir| dir == run_dir) {
        dirs.push(run_dir.to_path_buf());
    }
    for dir in dirs {
        let candidate = dir.join(format!("log-{stem}.txt"));
        if !is_regular_file(&candidate) {
            continue;
        }
        let mut bytes = Vec::new();
        let read = File::open(&candidate).and_then(|file| {
            file.take(MAX_SANITIZER_REPORT_BYTES as u64)
                .read_to_end(&mut bytes)
        });
        if read.is_ok() {
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ASAN: &str = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n";

    fn tmp() -> PathBuf {
        // Unique-ish directory without Math.random/time: use a static counter.
        static N: AtomicUsize = AtomicUsize::new(0);
        let mut base = std::env::temp_dir();
        base.push(format!(
            "hf-ingest-test-{}",
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::remove_dir_all(&base).ok();
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn a_fault_inside_the_harness_is_ingested_as_harness_origin() {
        let dir = tmp();
        std::fs::write(dir.join("crash-aaa"), b"x").unwrap();
        std::fs::write(dir.join("report.txt"), crate::frames::tests::HARNESS_FAULT).unwrap();

        let result =
            ingest_for_engine(&dir, EngineKind::LibFuzzer, Uuid::nil(), Uuid::nil()).unwrap();

        assert_eq!(result.crashes.len(), 1, "{:?}", result.crashes);
        assert_eq!(result.crashes[0].origin, CrashOrigin::Harness);
    }

    #[test]
    fn a_fault_inside_the_target_is_ingested_as_target_origin() {
        let dir = tmp();
        std::fs::write(dir.join("crash-aaa"), b"x").unwrap();
        std::fs::write(dir.join("report.txt"), crate::frames::tests::TARGET_FAULT).unwrap();

        let result =
            ingest_for_engine(&dir, EngineKind::LibFuzzer, Uuid::nil(), Uuid::nil()).unwrap();

        assert_eq!(result.crashes[0].origin, CrashOrigin::Target);
    }

    #[test]
    fn a_crash_without_symbolized_frames_has_unknown_origin() {
        let dir = tmp();
        std::fs::write(dir.join("crash-aaa"), b"x").unwrap();
        std::fs::write(dir.join("report.txt"), ASAN).unwrap();

        let result =
            ingest_for_engine(&dir, EngineKind::LibFuzzer, Uuid::nil(), Uuid::nil()).unwrap();

        assert_eq!(result.crashes[0].origin, CrashOrigin::Unknown);
    }

    #[test]
    fn a_crash_persisted_before_this_field_decodes_as_unknown() {
        // Exactly the JSON shape `crashes.data_json` holds for rows written
        // before this field existed. If this fails, the field lost its
        // `#[serde(default)]` and every stored crash stops decoding.
        let json = r#"{"id":"00000000-0000-0000-0000-000000000000",
          "run_id":"00000000-0000-0000-0000-000000000000",
          "target_id":"00000000-0000-0000-0000-000000000000",
          "input_path":"/tmp/x","stack_signature":"abc","kind":"Asan",
          "summary":"s","minimized":false,"bug_report":null}"#;
        let crash: hf_core::crash::Crash = serde_json::from_str(json).unwrap();
        assert_eq!(crash.origin, CrashOrigin::Unknown);
    }

    #[test]
    fn generic_report_ignored_when_multiple_crashes_share_a_dir() {
        let dir = tmp();
        std::fs::write(dir.join("crash-aaa"), b"x").unwrap();
        std::fs::write(dir.join("crash-bbb"), b"y").unwrap();
        // One generic sanitizer report that names neither crash.
        std::fs::write(dir.join("report.txt"), ASAN).unwrap();

        // Ambiguous: the shared report must not be attributed to either crash,
        // otherwise both get the same signature and dedup collapses them.
        let got = find_sanitizer_log(&dir.join("crash-aaa"), &dir, "crash-aaa");
        assert!(got.is_none(), "shared report must not be misattributed");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn generic_report_used_when_it_is_the_sole_crash() {
        let dir = tmp();
        std::fs::write(dir.join("crash-aaa"), b"x").unwrap();
        std::fs::write(dir.join("report.txt"), ASAN).unwrap();

        let got = find_sanitizer_log(&dir.join("crash-aaa"), &dir, "crash-aaa");
        assert!(got.is_some(), "sole crash may claim the generic report");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stem_named_report_wins_even_with_multiple_crashes() {
        let dir = tmp();
        std::fs::write(dir.join("crash-aaa"), b"x").unwrap();
        std::fs::write(dir.join("crash-bbb"), b"y").unwrap();
        // A report whose name references crash-aaa's stem ("aaa"), but not via
        // the step-1 `log-<stem>.txt` convention -- this exercises step 2.
        std::fs::write(dir.join("sanitizer-aaa.log"), ASAN).unwrap();

        let got = find_sanitizer_log(&dir.join("crash-aaa"), &dir, "crash-aaa");
        assert!(got.is_some(), "stem-named report is an unambiguous match");
        // The other crash has no stem-named report and cannot claim the shared
        // one, so it stays unclassified from a sibling log.
        let other = find_sanitizer_log(&dir.join("crash-bbb"), &dir, "crash-bbb");
        assert!(other.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn short_stem_does_not_claim_a_longer_stems_report() {
        let dir = tmp();
        std::fs::write(dir.join("crash-abc"), b"x").unwrap();
        std::fs::write(dir.join("crash-abcdef"), b"y").unwrap();
        // A report named for crash-abcdef's stem only.
        std::fs::write(dir.join("log-abcdef.txt"), ASAN).unwrap();

        // crash-abcdef claims its own report...
        let owner = find_sanitizer_log(&dir.join("crash-abcdef"), &dir, "crash-abcdef");
        assert!(owner.is_some(), "crash-abcdef must claim its own report");
        // ...but crash-abc must not, because "abc" is only an incidental prefix
        // of "abcdef", not a delimiter-bounded token in the report name.
        let intruder = find_sanitizer_log(&dir.join("crash-abc"), &dir, "crash-abc");
        assert!(
            intruder.is_none(),
            "short stem must not claim a longer stem's report"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_crash_artifact_is_ignored() {
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = dir.join("outside-input");
        std::fs::write(&outside, b"host data").unwrap();
        symlink(&outside, dir.join("crash-linked")).unwrap();

        let crashes = ingest(&dir, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert!(
            crashes.is_empty(),
            "crash ingestion followed a symlinked artifact"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_run_directory_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tmp();
        let outside = dir.join("outside-run");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("crash-external"), b"host data").unwrap();
        let linked = dir.join("linked-run");
        symlink(&outside, &linked).unwrap();

        assert!(
            ingest(&linked, Uuid::new_v4(), Uuid::new_v4()).is_err(),
            "crash ingestion followed its root symlink"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
