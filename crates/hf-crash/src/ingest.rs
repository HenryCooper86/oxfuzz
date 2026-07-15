//! Crash ingestion: scan a run output directory for engine-owned crash artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use hf_core::crash::{Crash, CrashKind};
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

fn collect_artifacts(run_dir: &Path, mode: IngestMode) -> Result<BoundedPaths, ClassifiedError> {
    let mut artifacts = BoundedPaths::default();

    if matches!(mode, IngestMode::Legacy)
        || matches!(mode, IngestMode::Engine(engine) if matches!(engine, EngineKind::Honggfuzz | EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite))
    {
        collect_files(run_dir, &mut artifacts, |name| match mode {
            IngestMode::Legacy => is_libfuzzer_crash(name) || is_honggfuzz_crash(name),
            IngestMode::Engine(EngineKind::Honggfuzz) => is_honggfuzz_crash(name),
            IngestMode::Engine(EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite) => {
                is_libfuzzer_crash(name)
            }
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
            if name.is_some_and(|name| name.contains(&stem.to_ascii_lowercase())) {
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
