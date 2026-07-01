//! Crash ingestion: scan a run output directory for crash artifacts.

use std::path::{Path, PathBuf};

use hf_core::crash::{Crash, CrashKind};
use hf_core::error::ClassifiedError;
use uuid::Uuid;

use crate::classify::classify;

/// Scan a run output directory for crash artifacts.
///
/// libFuzzer writes `crash-*`, `leak-*`, `timeout-*` files.
/// AFL++ writes to a `crashes/` subdirectory.
/// honggfuzz writes `SIG<signal>.PC.*` crash files plus a `HONGGFUZZ.REPORT.TXT`
/// alongside them in the run directory.
///
/// # Errors
/// Returns `ClassifiedError` if the directory cannot be read.
pub fn ingest(
    run_dir: &Path,
    run_id: Uuid,
    target_id: Uuid,
) -> Result<Vec<Crash>, ClassifiedError> {
    let mut crashes = Vec::new();

    // libFuzzer-style: files matching crash-*, leak-*, timeout-*.
    let entries = std::fs::read_dir(run_dir)
        .map_err(|e| ClassifiedError::Internal(format!("read dir: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if is_crash_artifact(&name) {
            let log = find_sanitizer_log(&path, run_dir, &name);
            let (kind, sig, summary) = log
                .as_deref()
                .map_or((CrashKind::Other, String::new(), String::new()), classify);
            crashes.push(Crash {
                id: Uuid::new_v4(),
                run_id,
                target_id,
                input_path: path,
                stack_signature: sig,
                kind,
                summary,
                minimized: false,
                bug_report: None,
                casr: None,
            });
        }
    }

    // AFL++-style: a crashes/ subdirectory. A single-instance run (no -M/-S)
    // nests it under an instance directory, e.g. out/default/crashes, so scan
    // both the direct crashes/ dir and one level of instance subdirectories.
    let mut afl_dirs = vec![run_dir.join("crashes")];
    if let Ok(entries) = std::fs::read_dir(run_dir) {
        for entry in entries.flatten() {
            let nested = entry.path().join("crashes");
            if nested.is_dir() {
                afl_dirs.push(nested);
            }
        }
    }
    for afl_crashes in afl_dirs {
        ingest_afl_crash_dir(&afl_crashes, run_id, target_id, &mut crashes)?;
    }

    Ok(crashes)
}

/// Ingest every crash file in one AFL++ `crashes/` directory into `crashes`.
fn ingest_afl_crash_dir(
    dir: &Path,
    run_id: Uuid,
    target_id: Uuid,
    crashes: &mut Vec<Crash>,
) -> Result<(), ClassifiedError> {
    if !dir.is_dir() {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| ClassifiedError::Internal(format!("read crashes dir: {e}")))?;
    for entry in entries {
        let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // AFL++ drops a `README.txt` in the crashes dir; it is not a crash.
        if name == "README.txt" {
            continue;
        }
        // AFL++ does not embed a sanitizer trace in the crash file itself, but a
        // sibling report may exist (e.g. when the harness was built with ASan).
        // Classify from it when present; otherwise leave the crash unclassified
        // for the service-layer replay pass.
        let log = find_sanitizer_log(&path, dir, &name);
        let (kind, sig, summary) = log
            .as_deref()
            .map_or((CrashKind::Other, String::new(), String::new()), classify);
        crashes.push(Crash {
            id: Uuid::new_v4(),
            run_id,
            target_id,
            input_path: path,
            stack_signature: sig,
            kind,
            summary,
            minimized: false,
            bug_report: None,
            casr: None,
        });
    }
    Ok(())
}

fn is_crash_artifact(name: &str) -> bool {
    name.starts_with("crash-")
        || name.starts_with("leak-")
        || name.starts_with("timeout-")
        || name.starts_with("oom-")
        // honggfuzz names crash files after the fatal signal, e.g.
        // `SIGSEGV.PC.<...>.fuzz` / `SIGABRT.PC.<...>.fuzz`.
        || is_honggfuzz_crash(name)
}

/// Whether `name` looks like a honggfuzz crash artifact (`SIG<signal>.*`).
fn is_honggfuzz_crash(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("SIG") else {
        return false;
    };
    // A signal name (uppercase letters/digits) followed by honggfuzz's
    // `.PC.`/`.STACK.` detail fields -- not, say, a `SIGNALS.md` doc.
    rest.starts_with(|c: char| c.is_ascii_uppercase()) && name.contains(".PC.")
}

/// Find a sanitizer report to classify a crash artifact from.
///
/// Tries, in order:
/// 1. The libFuzzer `log-<stem>.txt` convention next to the artifact.
/// 2. Any sibling `.txt`/`.log` file (in the artifact's directory or the run
///    directory) whose contents look like a sanitizer/UBSan trace.
///
/// Read failures are logged rather than silently swallowed, so a real I/O
/// error (e.g. permissions) is visible instead of masquerading as "no log".
fn find_sanitizer_log(crash_path: &Path, run_dir: &Path, crash_name: &str) -> Option<String> {
    // 1. libFuzzer convention: log-<stem>.txt alongside the crash.
    let stem = crash_name.split('-').nth(1).unwrap_or(crash_name);
    let conventional = run_dir.join(format!("log-{stem}.txt"));
    if conventional.is_file() {
        match std::fs::read_to_string(&conventional) {
            Ok(s) => return Some(s),
            Err(e) => {
                tracing::warn!(path = %conventional.display(), error = %e, "failed to read crash log");
            }
        }
    }

    // 2. A sibling .txt/.log carrying a sanitizer trace. Look both next to the
    // artifact and in the run directory (AFL++ keeps crashes in a subdir).
    //
    // A shared report must not be attached to the wrong crash: if several crash
    // artifacts sit beside a single generic report, mapping all of them to that
    // report gives them identical stack signatures and `dedup` collapses
    // genuinely distinct crashes into one. So we only accept a report that is
    // unambiguously this crash's: either its filename references the crash stem,
    // or it is the sole crash artifact in the directory.
    let mut dirs = vec![run_dir.to_path_buf()];
    if let Some(parent) = crash_path.parent() {
        if parent != run_dir {
            dirs.push(parent.to_path_buf());
        }
    }
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut reports: Vec<PathBuf> = Vec::new();
        let mut crash_artifacts = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if is_crash_artifact(&name) {
                crash_artifacts += 1;
            }
            if path == *crash_path {
                continue;
            }
            // honggfuzz writes an uppercase `HONGGFUZZ.REPORT.TXT`, so match the
            // extension case-insensitively.
            let is_text = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("txt") || e.eq_ignore_ascii_case("log"));
            if is_text {
                reports.push(path);
            }
        }

        // First, a report whose name references this crash's stem -- a strong,
        // per-crash association that holds even when many crashes share a dir.
        for path in &reports {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if name.is_some_and(|n| n.contains(stem)) {
                if let Some(s) = read_if_sanitizer_report(path) {
                    return Some(s);
                }
            }
        }
        // Otherwise, a generic report only if it cannot belong to another crash.
        if crash_artifacts <= 1 {
            for path in &reports {
                if let Some(s) = read_if_sanitizer_report(path) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// Read `path` and return its contents only if they resemble a sanitizer
/// report. Read failures are logged rather than silently swallowed.
fn read_if_sanitizer_report(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(s) if looks_like_sanitizer_report(&s) => Some(s),
        Ok(_) => None,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "failed to read crash log");
            None
        }
    }
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
}
