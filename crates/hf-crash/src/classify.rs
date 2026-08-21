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
    let frames = extract_frames(log, 3);
    let sig = if frames.is_empty() {
        String::new()
    } else {
        let mut hasher = Sha256::new();
        // Fold the crash kind into the hash so two distinct bugs that happen to
        // share the same top-3 frames (e.g. a heap-overflow and a UBSan integer
        // overflow reported at the same call site) do not collapse to one
        // signature. Frameless logs still yield an empty signature above, so the
        // dedup "no signature -> keep all" path is preserved.
        hasher.update(format!("{kind:?}").as_bytes());
        hasher.update(b"\n");
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
        // Go panic / Rust panic / Python (Atheris) uncaught exception.
        || l.contains("panic:")
        || l.contains("panicked at")
        || l.contains("traceback (most recent call last)")
        || l.contains("uncaught python exception")
}

fn detect_kind(log: &str) -> CrashKind {
    let lower = log.to_ascii_lowercase();
    // A genuine timeout is reported as an error class ("libFuzzer: timeout",
    // a "SUMMARY: ... timeout"), so key on that rather than any "timeout"/
    // "alarm" substring -- a frame like `connect_timeout` or an incidental
    // "alarm" elsewhere in the log must not reclassify an ASan/SEGV crash.
    if reports_timeout(&lower) {
        return CrashKind::Timeout;
    }
    // A managed-runtime fault (Go panic, Rust panic, or an uncaught Python
    // exception under Atheris) is checked before the native sanitizer/signal
    // classes: a Go nil-pointer panic mentions "SIGSEGV" but is a runtime panic,
    // not a native SEGV.
    if reports_panic(&lower) {
        return CrashKind::Panic;
    }
    if lower.contains("addresssanitizer") || lower.contains("asan") {
        CrashKind::Asan
    } else if lower.contains("undefinedbehaviorsanitizer") || lower.contains("ubsan") {
        CrashKind::Ubsan
    } else if lower.contains("segv") || lower.contains("sigsegv") {
        CrashKind::Segv
    } else if lower.contains("sigabrt") || lower.contains("abort") {
        CrashKind::Abort
    } else {
        CrashKind::Other
    }
}

/// Whether the log reports a *timeout* as its error class, as opposed to merely
/// containing the substring "timeout"/"alarm" somewhere (a frame name, a symbol
/// like `connect_timeout`, a `Timeouts : 0` status counter, a `net/timeout.c`
/// path). Conservative on purpose: a timeout report is either the leading label
/// of a line (libFuzzer's "ALARM: ..." and "timeout: N" lines) or the engine's
/// own verdict on a diagnostic line ("libFuzzer: timeout after 60s"). A plain
/// "timeout" substring on a `SUMMARY`/`ERROR` line is NOT enough -- an `ASan` summary
/// can name a timeout-flavored source path there.
fn reports_timeout(lower: &str) -> bool {
    lower.lines().any(|raw| {
        let line = raw.trim_start();
        line.starts_with("alarm:")
            || line.starts_with("timeout:")
            || line.contains("libfuzzer: timeout")
            || ((line.contains("summary:") || line.contains("error:"))
                && line.contains("timeout after"))
    })
}

/// Whether the log reports a managed-runtime fault: a Go `panic:` line, a Rust
/// `panicked at`, or a Python/Atheris uncaught exception. Distinct from a native
/// abort so a Go/Python crash is not misfiled as `Abort`/`Segv`/`Other`.
fn reports_panic(lower: &str) -> bool {
    lower.lines().any(|raw| {
        let line = raw.trim_start();
        line.starts_with("panic:")
            || line.contains("panicked at")
            || line.contains("uncaught python exception")
            || line.starts_with("traceback (most recent call last)")
    })
}

/// Pick the frame extractor matching the log's runtime: Go stack traces and
/// Python tracebacks use their own frame formats (not sanitizer `#N` frames), so
/// without language-aware extraction they would yield an empty signature and
/// every distinct Go/Python crash would route through dedup's "keep all" path.
fn extract_frames(log: &str, n: usize) -> Vec<String> {
    let lower = log.to_ascii_lowercase();
    if lower.contains("goroutine ") && lower.contains("panic:") {
        return extract_go_frames(log, n);
    }
    if lower.contains("traceback (most recent call last)") {
        return extract_python_frames(log, n);
    }
    extract_top_frames(log, n)
}

/// Extract the top `n` Go stack frames as `pkg.Func` names. Go prints a function
/// line (`main.Fuzz(0x...)`) followed by an indented `\t/file.go:line +0xNN`; the
/// function names are ASLR-independent, so hashing them gives a stable signature.
fn extract_go_frames(log: &str, n: usize) -> Vec<String> {
    let mut frames = Vec::new();
    for line in log.lines() {
        if line.starts_with('\t') || line.starts_with(' ') {
            continue;
        }
        let trimmed = line.trim_end();
        if let Some(open) = trimmed.find('(') {
            let name = &trimmed[..open];
            if !name.is_empty() && name.contains('.') && !name.contains(' ') {
                frames.push(name.to_owned());
                if frames.len() >= n {
                    break;
                }
            }
        }
    }
    frames
}

/// Extract the deepest `n` Python traceback frames (`func (path:line)`). A
/// traceback is most-recent-call-last, so the deepest frames sit closest to the
/// raise site and best identify the bug; paths/lines are ASLR-independent.
fn extract_python_frames(log: &str, n: usize) -> Vec<String> {
    let mut frames: Vec<String> = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim();
        // `File "path", line N, in func`
        if let Some(rest) = trimmed.strip_prefix("File ") {
            frames.push(rest.replace('"', ""));
        }
    }
    frames.reverse();
    frames.truncate(n);
    frames
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
                // Unsymbolized frame ("#0 0xADDR (module+0xOFFSET)"). Strip the
                // leading ASLR runtime address so the same crash hashes
                // identically across runs; keep the module+offset (or any)
                // tail, mirroring the " in " path which also drops the address.
                frames.push(strip_leading_frame_address(trimmed));
            }
        }
        if frames.len() >= n {
            break;
        }
    }
    frames
}

/// Strip the leading frame marker (`#N`) and the ASLR runtime address that
/// follows it from an unsymbolized frame, returning the remaining tail (e.g.
/// `(module+0xOFFSET)`). Only the first `0x...` token -- the runtime address --
/// is removed; a module-relative offset in the tail is preserved. Falls back to
/// the trimmed frame when the expected shape is absent.
fn strip_leading_frame_address(frame: &str) -> String {
    let mut tokens = frame.split_whitespace();
    let _marker = tokens.next(); // "#N"
    let rest: Vec<&str> = tokens.collect();
    let tail = if rest.first().is_some_and(|t| t.starts_with("0x")) {
        &rest[1..]
    } else {
        &rest[..]
    };
    if tail.is_empty() {
        frame.trim().to_owned()
    } else {
        tail.join(" ")
    }
}

fn extract_summary(log: &str, kind: CrashKind) -> String {
    if kind == CrashKind::Panic {
        // A Go panic leads with `panic: <message>`; a Python traceback ends with
        // the exception line (`ExcType: <message>`), which is the last non-empty
        // line. Prefer these over a generic "error"-bearing line.
        for line in log.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("panic:") {
                return trimmed.to_owned();
            }
        }
        if let Some(last) = log.lines().map(str::trim).rev().find(|t| !t.is_empty()) {
            return last.to_owned();
        }
    }
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
    use super::{classify, detect_kind, looks_like_crash};
    use hf_core::crash::CrashKind;

    #[test]
    fn unsymbolized_frames_ignore_the_aslr_address() {
        // Two runs of the same crash: identical unsymbolized frames, only the
        // leading ASLR runtime addresses differ. The stack signature must match,
        // otherwise every run of one bug looks like a new distinct crash.
        let run_a = "==1==ERROR: AddressSanitizer: SEGV on unknown address\n\
                     #0 0x000055f0deadbeef (/lib/libz.so+0x1234)\n\
                     #1 0x000055f0cafebabe (/lib/libz.so+0x5678)\n\
                     #2 0x000055f0feedface (/bin/app+0x9abc)\n";
        let run_b = "==1==ERROR: AddressSanitizer: SEGV on unknown address\n\
                     #0 0x00007fabc0000111 (/lib/libz.so+0x1234)\n\
                     #1 0x00007fabc0000222 (/lib/libz.so+0x5678)\n\
                     #2 0x00007fabc0000333 (/bin/app+0x9abc)\n";
        let (_, sig_a, _) = classify(run_a);
        let (_, sig_b, _) = classify(run_b);
        assert!(
            !sig_a.is_empty(),
            "a frame-bearing log must have a signature"
        );
        assert_eq!(
            sig_a, sig_b,
            "identical crashes must hash the same regardless of ASLR address"
        );
    }

    #[test]
    fn same_frames_different_kinds_do_not_collapse() {
        // Two distinct bugs reported at the same top-3 frames but with different
        // crash kinds must not share a signature.
        let frames = "#0 0xaaa in foo /a.c:1:1\n\
                      #1 0xbbb in bar /b.c:2:2\n\
                      #2 0xccc in baz /c.c:3:3\n";
        let asan = format!("==1==ERROR: AddressSanitizer: heap-buffer-overflow\n{frames}");
        let ubsan = format!("==1==ERROR: UndefinedBehaviorSanitizer: signed overflow\n{frames}");
        let (kind_a, sig_a, _) = classify(&asan);
        let (kind_u, sig_u, _) = classify(&ubsan);
        assert_eq!(kind_a, CrashKind::Asan);
        assert_eq!(kind_u, CrashKind::Ubsan);
        assert_ne!(
            sig_a, sig_u,
            "distinct crash kinds sharing frames must not collapse to one signature"
        );
    }

    #[test]
    fn timeout_is_only_the_reported_error_class() {
        // An ASan crash whose stack merely mentions a `connect_timeout` frame is
        // an ASan finding, not a timeout.
        let asan_with_timeout_frame = "==1==ERROR: AddressSanitizer: SEGV on unknown address\n\
                                       #0 0xdead in connect_timeout /net.c:10:5\n\
                                       SUMMARY: AddressSanitizer: SEGV /net.c:10:5\n";
        assert_eq!(detect_kind(asan_with_timeout_frame), CrashKind::Asan);

        // A genuine libFuzzer timeout is classified as a timeout.
        let real_timeout = "==1== ERROR: libFuzzer: timeout after 60 seconds\n\
                            SUMMARY: libFuzzer: timeout\n";
        assert_eq!(detect_kind(real_timeout), CrashKind::Timeout);
    }

    #[test]
    fn frameless_classified_crashes_are_not_deduped() {
        use crate::dedup::dedup;
        use hf_core::crash::Crash;
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
            origin: hf_core::crash::CrashOrigin::Unknown,
        };

        let kept = dedup(vec![make(sig_a), make(sig_b)]);
        assert_eq!(
            kept.len(),
            2,
            "distinct frameless crashes must not be collapsed by dedup"
        );
    }

    #[test]
    fn go_panic_classifies_and_signs_stably_across_addresses() {
        let run_a = "panic: runtime error: index out of range [5] with length 3\n\n\
                     goroutine 17 [running]:\n\
                     main.parseHeader(0xc0000b4000, 0x3)\n\t/src/parse.go:42 +0x1d\n\
                     main.FuzzParse(0xc0000a2000)\n\t/src/harness.go:10 +0x40\n";
        let run_b = "panic: runtime error: index out of range [5] with length 3\n\n\
                     goroutine 42 [running]:\n\
                     main.parseHeader(0xdeadbeef0000, 0x3)\n\t/src/parse.go:42 +0x99\n\
                     main.FuzzParse(0xcafebabe0000)\n\t/src/harness.go:10 +0xaa\n";
        let (kind, sig_a, summary) = classify(run_a);
        let (_, sig_b, _) = classify(run_b);
        assert_eq!(
            kind,
            CrashKind::Panic,
            "a Go panic is a managed-runtime fault"
        );
        assert!(!sig_a.is_empty(), "Go frames must yield a signature");
        assert_eq!(
            sig_a, sig_b,
            "func-name signature is stable across addresses"
        );
        assert!(
            summary.starts_with("panic:"),
            "summary is the panic line: {summary}"
        );
    }

    #[test]
    fn python_traceback_classifies_and_signs() {
        let log = " === Uncaught Python exception: ===\n\
                    ValueError: invalid literal\n\
                    Traceback (most recent call last):\n\
                    \x20 File \"/src/harness.py\", line 12, in TestOneInput\n\
                    \x20   parse(data)\n\
                    \x20 File \"/src/parser.py\", line 88, in parse\n\
                    \x20   raise ValueError(\"invalid literal\")\n\
                    ValueError: invalid literal\n";
        let (kind, sig, summary) = classify(log);
        assert_eq!(
            kind,
            CrashKind::Panic,
            "an uncaught Python exception is a Panic"
        );
        assert!(
            !sig.is_empty(),
            "Python traceback frames must yield a signature"
        );
        assert_eq!(
            summary, "ValueError: invalid literal",
            "summary is the exception line"
        );
        assert!(
            looks_like_crash(log),
            "a Python traceback still reads as a crash"
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
