//! Crash classification: parse sanitizer/engine logs into kind + signature.

use hf_core::crash::CrashKind;
use sha2::{Digest, Sha256};

/// Classify a crash log.
///
/// Returns `(CrashKind, stack_signature, summary)` where `stack_signature`
/// is a sha256 hex digest of the top-3 stack frames, or an empty string when
/// the log carries no stack frames. An empty signature is deliberate: hashing
/// zero frames would yield the constant empty-input digest, which `dedup`
/// would then treat as a real key and collapse every distinct frameless crash
/// into one. Emitting an empty signature routes such crashes through dedup's
/// "no signature -> keep all" path instead.
#[must_use]
pub fn classify(log: &str) -> (CrashKind, String, String) {
    let kind = detect_kind(log);
    let frames = extract_top_frames(log, 3);
    let sig = if frames.is_empty() {
        String::new()
    } else {
        let mut hasher = Sha256::new();
        for frame in &frames {
            hasher.update(frame.as_bytes());
            hasher.update(b"\n");
        }
        hex::encode(hasher.finalize())
    };
    let summary = extract_summary(log, kind);
    (kind, sig, summary)
}

/// Whether a sandbox replay trace indicates the input still crashes.
///
/// Used by regression rerun ("does this crash still fire?"): a fixed target
/// replays cleanly (no sanitizer/abort markers), a regressed one prints the
/// usual sanitizer/`SUMMARY`/deadly-signal lines.
#[must_use]
pub fn looks_like_crash(log: &str) -> bool {
    let l = log.to_ascii_lowercase();
    l.contains("sanitizer")
        || l.contains("runtime error")
        || l.contains("summary:")
        || l.contains("deadly signal")
        || l.contains("sigsegv")
        || l.contains("sigabrt")
        || l.contains("segv on")
        || l.contains("==error")
        || l.contains("== error")
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

#[cfg(test)]
mod tests {
    use super::looks_like_crash;

    #[test]
    fn frameless_classified_crashes_are_not_deduped() {
        use crate::dedup::dedup;
        use hf_core::crash::{Crash, CrashKind};
        use std::path::PathBuf;
        use uuid::Uuid;

        // Two distinct classified logs that carry no "#"-prefixed stack frames.
        let ubsan = "src/parse.c:12: runtime error: signed integer overflow";
        let honggfuzz = "STACK: <0x000055f0deadbeef>";

        let (_, sig_a, _) = super::classify(ubsan);
        let (_, sig_b, _) = super::classify(honggfuzz);

        // A frameless log must not collapse to the constant empty-input digest;
        // it yields an empty signature so dedup keeps each such crash.
        assert!(
            sig_a.is_empty(),
            "frameless log must have an empty signature, got {sig_a}"
        );
        assert!(
            sig_b.is_empty(),
            "frameless log must have an empty signature, got {sig_b}"
        );

        let make = |sig: String| Crash {
            id: Uuid::new_v4(),
            run_id: Uuid::nil(),
            target_id: Uuid::nil(),
            input_path: PathBuf::from("in"),
            stack_signature: sig,
            kind: CrashKind::Other,
            summary: String::new(),
            minimized: false,
            bug_report: None,
            casr: None,
        };

        let kept = dedup(vec![make(sig_a), make(sig_b)]);
        assert_eq!(
            kept.len(),
            2,
            "distinct frameless crashes must not be collapsed by dedup"
        );
    }

    #[test]
    fn detects_a_still_firing_crash() {
        let trace = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer: heap-buffer-overflow";
        assert!(looks_like_crash(trace));
        assert!(looks_like_crash("==42==ERROR: libFuzzer: deadly signal"));
        assert!(looks_like_crash(
            "src/x.c:3:5: runtime error: signed integer overflow"
        ));
    }

    #[test]
    fn clean_replay_is_not_a_crash() {
        assert!(!looks_like_crash(""));
        assert!(!looks_like_crash("Executed crash-abc in 2 ms\nDone 1 runs"));
    }
}
