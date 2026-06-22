//! Crash classification: parse sanitizer/engine logs into kind + signature.

use hf_core::crash::CrashKind;
use sha2::{Digest, Sha256};

/// Classify a crash log.
///
/// Returns `(CrashKind, stack_signature, summary)` where `stack_signature`
/// is a sha256 hex digest of the top-3 stack frames.
#[must_use]
pub fn classify(log: &str) -> (CrashKind, String, String) {
    let kind = detect_kind(log);
    let frames = extract_top_frames(log, 3);
    let mut hasher = Sha256::new();
    for frame in &frames {
        hasher.update(frame.as_bytes());
        hasher.update(b"\n");
    }
    let sig = hex::encode(hasher.finalize());
    let summary = extract_summary(log, kind);
    (kind, sig, summary)
}

fn detect_kind(log: &str) -> CrashKind {
    let lower = log.to_ascii_lowercase();
    if lower.contains("addresssanitizer") || lower.contains("asan") {
        if lower.contains("timeout") || lower.contains("alarm") {
            return CrashKind::Timeout;
        }
        CrashKind::Asan
    } else if lower.contains("undefinedbehaviorsanitizer") || lower.contains("ubsan") {
        CrashKind::Ubsan
    } else if lower.contains("segv") || lower.contains("sigsegv") {
        CrashKind::Segv
    } else if lower.contains("sigabrt") || lower.contains("abort") {
        CrashKind::Abort
    } else if lower.contains("timeout") || lower.contains("alarm") {
        CrashKind::Timeout
    } else {
        CrashKind::Other
    }
}

fn extract_top_frames(log: &str, n: usize) -> Vec<String> {
    let mut frames = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            // Extract the function + location part after the address.
            // Format: "#0 0xADDR in FUNCTION FILE:LINE:COL"
            if let Some(pos) = trimmed.find(" in ") {
                let rest = &trimmed[pos + 4..];
                frames.push(rest.to_owned());
            } else {
                frames.push(trimmed.to_owned());
            }
        }
        if frames.len() >= n {
            break;
        }
    }
    frames
}

fn extract_summary(log: &str, kind: CrashKind) -> String {
    for line in log.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("error") || lower.contains("asan") || lower.contains("ubsan") {
            return line.trim().to_owned();
        }
    }
    format!("{kind:?} crash detected")
}
