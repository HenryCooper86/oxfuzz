//! Crash ingestion: scan a run output directory for crash artifacts.

use std::path::Path;

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

    // AFL++-style: crashes/ subdirectory.
    let afl_crashes = run_dir.join("crashes");
    if afl_crashes.is_dir() {
        let entries = std::fs::read_dir(&afl_crashes)
            .map_err(|e| ClassifiedError::Internal(format!("read crashes dir: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| ClassifiedError::Internal(e.to_string()))?;
            let name = entry.file_name().to_string_lossy().to_string();
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            // AFL++ does not embed a sanitizer trace in the crash file itself,
            // but a sibling report may exist (e.g. when the harness was built
            // with ASan). Classify from it when present; otherwise leave the
            // crash unclassified for the service-layer replay pass.
            let log = find_sanitizer_log(&path, &afl_crashes, &name);
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

    Ok(crashes)
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

    // 2. Any sibling .txt/.log carrying a sanitizer trace. Look both next to the
    // artifact and in the run directory (AFL++ keeps crashes in a subdir).
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
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() || path == *crash_path {
                continue;
            }
            let is_text = path
                .extension()
                .and_then(|e| e.to_str())
                // honggfuzz writes an uppercase `HONGGFUZZ.REPORT.TXT`, so match
                // the extension case-insensitively.
                .is_some_and(|e| e.eq_ignore_ascii_case("txt") || e.eq_ignore_ascii_case("log"));
            if !is_text {
                continue;
            }
            match std::fs::read_to_string(&path) {
                Ok(s) if looks_like_sanitizer_report(&s) => return Some(s),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "failed to read crash log");
                }
            }
        }
    }
    None
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
