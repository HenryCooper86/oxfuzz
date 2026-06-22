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
/// honggfuzz writes to `HF_WORKSPACE`.
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
            let log = find_log_for(run_dir, &name);
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
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let (kind, sig, summary) = (CrashKind::Other, String::new(), String::new());
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
}

fn find_log_for(run_dir: &Path, crash_name: &str) -> Option<String> {
    // libFuzzer may write a log file alongside the crash.
    let stem = crash_name.split('-').nth(1).unwrap_or(crash_name);
    let log_name = format!("log-{stem}.txt");
    let log_path = run_dir.join(&log_name);
    if log_path.is_file() {
        std::fs::read_to_string(&log_path).ok()
    } else {
        None
    }
}
