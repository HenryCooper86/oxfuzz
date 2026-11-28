//! Crash classification: parse sanitizer/engine logs into kind + signature.

use hf_core::crash::CrashKind;
use sha2::{Digest, Sha256};

/// The line a sandbox replay appends when the target was killed at the
/// sandbox memory limit (exit 137) without printing a sanitizer report. A
/// cgroup kill leaves no output of its own, so without it such inputs look
/// like replays that showed nothing.
pub const OOM_KILL_MARKER: &str = "oxfuzz: killed at the sandbox memory limit (out of memory)";

/// The one signature every memory-limit kill shares: they carry no frames, and
/// one finding per input would list the same resource-exhaustion class many
/// times over.
const OOM_KILL_SIGNATURE: &str = "out-of-memory-kill";

/// Whether a log holds a sanitizer report, which outranks the kill marker.
fn reports_sanitizer(log: &str) -> bool {
    log.contains("ERROR: AddressSanitizer")
        || log.contains("ERROR: MemorySanitizer")
        || log.contains("WARNING: ThreadSanitizer")
        || log.contains("runtime error:")
        || log.contains("ERROR: libFuzzer")
}

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
    if log.contains(OOM_KILL_MARKER) && !reports_sanitizer(log) {
        return (
            CrashKind::Other,
            OOM_KILL_SIGNATURE.to_owned(),
            "out of memory: the input drove the target past the sandbox memory limit and \
             the kernel killed it before any sanitizer report"
                .to_owned(),
        );
    }
    let kind = detect_kind(log);
    let frames = extract_frames(log, 3);
    let sig = if frames.is_empty() {
        String::new()
    } else {
        let mut hasher = Sha256::new();
        // Fold the crash kind into the hash so two distinct bugs that happen to
        // share the same top-3 frames (e.g. a heap-overflow and a `UBSan` integer
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
    // Atheris prints, on every start, that the libFuzzer it embeds found no
    // sanitizer runtime hooks. Those lines name a sanitizer without one
    // having reported anything.
    let l = log
        .lines()
        .filter(|line| !line.starts_with(MISSING_SANITIZER_HOOK_WARNING))
        .filter(|line| !is_jazzer_hook_note(line))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    l.contains("sanitizer")
        || log.contains(OOM_KILL_MARKER)
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
        || l.contains("== java exception:")
        || log.lines().any(|line| jazzer_js_report(line).is_some())
}

/// Jazzer's startup note for each bug-detector class it loads. The classes
/// live in a package named `sanitizers`; the note reports nothing.
fn is_jazzer_hook_note(line: &str) -> bool {
    line.starts_with("INFO: Loaded ") && line.contains(" hooks from com.code_intelligence.jazzer.")
}

/// libFuzzer's startup note for a sanitizer interface function the process
/// does not export.
const MISSING_SANITIZER_HOOK_WARNING: &str = "WARNING: Failed to find function \"__sanitizer_";

fn detect_kind(log: &str) -> CrashKind {
    let lower = log.to_ascii_lowercase();
    // A genuine timeout is reported as an error class ("libFuzzer: timeout",
    // a "SUMMARY: ... timeout"), so key on that rather than any "timeout"/
    // "alarm" substring -- a frame like `connect_timeout` or an incidental
    // "alarm" elsewhere in the log must not reclassify an `ASan`/SEGV crash.
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
    // Each sanitizer is keyed on the name it writes about itself, never on a
    // token that can appear anywhere in the log. `-fsanitize=address,undefined`
    // is the standard fuzzing build, so an `ASan` runtime frame (`__asan_memcpy`)
    // or a linked `libasan.so` turns up in reports `ASan` did not author; keying
    // on the bare token `asan` filed each of those as an `ASan` finding, and the
    // kind is part of the dedup signature. `UBSan` is checked first because it is
    // the one whose reports routinely carry the other's name.
    if reports_undefined_behavior(&lower) {
        CrashKind::Ubsan
    } else if lower.contains("leaksanitizer") || lower.contains("detected memory leak") {
        // Ahead of the `ASan` check for the same reason: `LSan` is reported by the
        // `ASan` runtime, so a real leak report carries a
        // `SUMMARY: AddressSanitizer:` line and allocates through
        // `asan_malloc_linux.cpp`.
        CrashKind::Leak
    } else if lower.contains("memorysanitizer") {
        CrashKind::Msan
    } else if lower.contains("threadsanitizer") {
        CrashKind::Tsan
    } else if lower.contains("addresssanitizer") {
        CrashKind::Asan
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

/// Whether the log reports undefined behavior.
///
/// `UBSan` names itself only on a `SUMMARY:` line, which a halt-on-first-error or
/// truncated log never reaches. Its per-finding form names no sanitizer at all:
/// `<file>:<line>:<col>: runtime error: <description>`. Matched per line rather
/// than as a bare `contains`, so an unrelated program printing the words
/// "runtime error" in prose does not reclassify a crash.
fn reports_undefined_behavior(lower: &str) -> bool {
    lower.lines().any(|raw| {
        let line = raw.trim_start();
        line.contains("undefinedbehaviorsanitizer") || line.contains("runtime error:")
    })
}

/// Whether the log reports a managed-runtime fault: a Go `panic:` line, a Rust
/// `panicked at`, or a Python/Atheris uncaught exception. Distinct from a native
/// abort so a Go/Python crash is not misfiled as `Abort`/`Segv`/`Other`.
fn reports_panic(lower: &str) -> bool {
    lower.lines().any(|raw| {
        let line = raw.trim_start();
        line.starts_with("panic:")
            || is_go_test_panic_line(line)
            || line.contains("panicked at")
            || line.contains("uncaught python exception")
            || line.starts_with("traceback (most recent call last)")
            || line.starts_with(&JAVA_EXCEPTION_MARK.to_ascii_lowercase())
            || jazzer_js_report(line).is_some()
    })
}

/// What Jazzer.js prints after its process mark when a fuzz callback ended
/// with an exception: `==<pid>== Uncaught Exception: <name>: <text>`.
const JAZZER_JS_EXCEPTION_MARK: &str = "Uncaught Exception: ";

/// The text of a Jazzer.js report line: `==<pid>== ` followed by an uncaught
/// exception or by the title of a bug-detector finding. libFuzzer and the
/// sanitizers use the same process mark for lines that begin with a label
/// and a colon (`ERROR:`, `libFuzzer:`), which are theirs.
fn jazzer_js_report(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("==")?;
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let text = rest[digits..].strip_prefix("== ")?;
    let label = text.split_whitespace().next()?;
    let own = text
        .get(..JAZZER_JS_EXCEPTION_MARK.len())
        .is_some_and(|start| start.eq_ignore_ascii_case(JAZZER_JS_EXCEPTION_MARK));
    (own || !label.ends_with(':')).then_some(text)
}

/// The line Jazzer prints before the exception (or its own bug-detector
/// report) a fuzz callback ended with: `== Java Exception: <class>: <text>`.
const JAVA_EXCEPTION_MARK: &str = "== Java Exception: ";

/// Whether a line is a panic as `go test` reports it from inside a test or
/// fuzz function: prefixed with the `testing` source position that recovered
/// it (`testing.go:1927: panic: runtime error: ...`). Without this the line's
/// `runtime error:` text would file a Go panic under `UBSan`.
fn is_go_test_panic_line(line: &str) -> bool {
    line.split_once(": panic:").is_some_and(|(position, _)| {
        position.rsplit_once(".go:").is_some_and(|(file, number)| {
            !file.is_empty()
                && !file.contains(' ')
                && !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
        })
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
    if log.contains(JAVA_EXCEPTION_MARK) {
        return extract_java_frames(log, n);
    }
    if log.lines().any(|line| jazzer_js_report(line).is_some()) {
        return extract_javascript_frames(log, n);
    }
    extract_top_frames(log, n)
}

/// Extract the top `n` Go stack frames as `pkg.Func` names. Go prints a function
/// line (`main.Fuzz(0x...)`) followed by an indented `\t/file.go:line +0xNN`; the
/// function names are ASLR-independent, so hashing them gives a stable signature.
///
/// `go test` indents the whole trace under the failing test, so lines are read
/// trimmed: a function line carries `(`, a location line starts with a path.
/// Frames of the Go runtime and of the `testing` and `reflect` machinery that
/// every fuzz failure passes through are left out, so the signature names the
/// code under test.
fn extract_go_frames(log: &str, n: usize) -> Vec<String> {
    const MACHINERY: [&str; 4] = ["runtime.", "runtime/", "testing.", "reflect."];
    let mut frames = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('/') {
            continue;
        }
        if let Some(open) = trimmed.find('(') {
            let name = &trimmed[..open];
            if !name.is_empty()
                && name.contains('.')
                && !name.contains(' ')
                && !MACHINERY.iter().any(|prefix| name.starts_with(prefix))
            {
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
/// The directory a run's retained project sources are imported from, and the
/// sandbox mount of the harness workspace. A frame's file is reported below
/// one of them depending on whether the run or a later replay raised it.
const RETAINED_SOURCES_MARK: &str = "/source-context/";
const WORKSPACE_MOUNT: &str = "/work/";

/// A Python frame without where its file happened to be installed: the same
/// module reads `pkg/frames.py` whether it was imported from a run's retained
/// sources or from the workspace.
fn normalize_python_frame(frame: &str) -> String {
    let frame = frame.replace('"', "");
    if let Some((_, relative)) = frame.split_once(RETAINED_SOURCES_MARK) {
        return relative.to_owned();
    }
    frame
        .strip_prefix(WORKSPACE_MOUNT)
        .unwrap_or(&frame)
        .to_owned()
}

/// Extract the top `n` Java stack frames as qualified method names, from the
/// `at pkg.Class.method(File.java:N)` lines that follow Jazzer's exception
/// line. Line numbers are left out so a recompiled class signs the same. The
/// generated harness class, Jazzer's own frames, and the JDK's reflection
/// machinery are not the code under test and are skipped.
fn extract_java_frames(log: &str, n: usize) -> Vec<String> {
    const MACHINERY: [&str; 5] = [
        "OxfuzzFuzzTarget.",
        "com.code_intelligence.jazzer.",
        "java.base/jdk.internal.reflect.",
        "java.base/java.lang.reflect.",
        "java.base/java.lang.invoke.",
    ];
    let mut frames = Vec::new();
    let mut in_report = false;
    for line in log.lines() {
        if line.starts_with(JAVA_EXCEPTION_MARK) {
            in_report = true;
            continue;
        }
        if !in_report {
            continue;
        }
        let trimmed = line.trim();
        let Some(frame) = trimmed.strip_prefix("at ") else {
            // `Caused by:` and `... N more` lines continue a report; anything
            // else ends it.
            if trimmed.starts_with("Caused by:") || trimmed.starts_with("...") {
                continue;
            }
            break;
        };
        let name = frame.split('(').next().unwrap_or(frame);
        if MACHINERY.iter().any(|prefix| name.starts_with(prefix)) {
            continue;
        }
        frames.push(name.to_owned());
        if frames.len() >= n {
            break;
        }
    }
    frames
}

/// Extract the top `n` JavaScript stack frames as `function (file)`, from
/// the `at function (file:line:column)` lines that follow a Jazzer.js
/// report. The file is the module's path below the project, whether a run
/// loaded it from its retained sources or a replay from the workspace, and
/// whether Node.js printed a path or a `file://` URL. Positions are left
/// out: an instrumented ES module reports its own. The generated harness,
/// Jazzer.js, and Node.js internals are not the code under test and are
/// skipped, as is a frame with no file.
fn extract_javascript_frames(log: &str, n: usize) -> Vec<String> {
    const MACHINERY: [&str; 3] = ["/tmp/oxfuzz-harness.", "/opt/jazzerjs/", "node:"];
    let mut frames = Vec::new();
    let mut in_report = false;
    for line in log.lines() {
        if jazzer_js_report(line).is_some() {
            in_report = true;
            continue;
        }
        if !in_report {
            continue;
        }
        let trimmed = line.trim();
        let Some(frame) = trimmed.strip_prefix("at ") else {
            // A bug-detector report names the call on a line of its own.
            if trimmed.starts_with("in ") {
                continue;
            }
            break;
        };
        let frame = frame.strip_prefix("async ").unwrap_or(frame);
        let (name, location) = match frame.rsplit_once(" (") {
            Some((name, location)) => (name, location.trim_end_matches(')')),
            None => ("<anonymous>", frame),
        };
        let location = location.strip_prefix("file://").unwrap_or(location);
        if !location.starts_with('/') || MACHINERY.iter().any(|skip| location.starts_with(skip)) {
            continue;
        }
        // `path:line:column`: drop the two positions.
        let file = location.rsplitn(3, ':').last().unwrap_or(location);
        let file = file.split_once(RETAINED_SOURCES_MARK).map_or_else(
            || file.strip_prefix(WORKSPACE_MOUNT).unwrap_or(file),
            |(_, relative)| relative,
        );
        frames.push(format!("{name} ({file})"));
        if frames.len() >= n {
            break;
        }
    }
    frames
}

fn extract_python_frames(log: &str, n: usize) -> Vec<String> {
    let mut frames: Vec<String> = Vec::new();
    for line in log.lines() {
        let trimmed = line.trim();
        // `File "path", line N, in func`. The Atheris callback is the
        // harness, not the code under test, and its file is named after the
        // place the script was installed, so it is not part of the identity.
        if let Some(rest) = trimmed.strip_prefix("File ") {
            if rest.ends_with(", in TestOneInput") {
                continue;
            }
            frames.push(normalize_python_frame(rest));
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
                frames.push(strip_module_suffix(&strip_leading_frame_address(trimmed)));
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

/// Drop the trailing `(module+0xOFFSET)` and `(BuildId: ...)` groups `TSan`
/// prints after a symbolized frame (`w /work/t.c:5:35 (t+0x1294f8) (BuildId:
/// ...)`): both change when the harness is rebuilt, and neither identifies the
/// bug. A frame that is nothing but such a group (an unsymbolized `ASan` frame)
/// is returned unchanged, so its signature stays what it was.
fn strip_module_suffix(frame: &str) -> String {
    if frame.starts_with('(') {
        return frame.to_owned();
    }
    let mut rest = frame.trim_end();
    while rest.ends_with(')') {
        let Some(open) = rest.rfind(" (") else {
            break;
        };
        let group = &rest[open + 2..];
        if !(group.starts_with("BuildId:") || group.contains("+0x")) {
            break;
        }
        rest = rest[..open].trim_end();
    }
    rest.to_owned()
}

/// The line Atheris prints before the exception a fuzz callback raised.
const ATHERIS_EXCEPTION_MARK: &str = "=== Uncaught Python exception: ===";

/// The `HONGGFUZZ.REPORT.TXT` field that carries the crash headline.
const HONGGFUZZ_DESCRIPTION_FIELD: &str = "DESCRIPTION:";

fn extract_summary(log: &str, kind: CrashKind) -> String {
    // libFuzzer's resource limits are reported as its own error, not a
    // sanitizer's; name them instead of falling through to "Other".
    if let Some(detail) = log.lines().find_map(|line| {
        line.split_once("ERROR: libFuzzer: out-of-memory")
            .map(|(_, rest)| {
                let rest = rest.trim();
                rest.strip_prefix('(')
                    .and_then(|inner| inner.strip_suffix(')'))
                    .unwrap_or(rest)
                    .to_owned()
            })
    }) {
        return if detail.is_empty() {
            "out of memory".to_owned()
        } else {
            format!("out of memory: {detail}")
        };
    }
    if kind == CrashKind::Panic {
        // A Go panic leads with `panic: <message>`; a Python traceback ends with
        // the exception line (`ExcType: <message>`), which is the last non-empty
        // line. Prefer these over a generic "error"-bearing line.
        for line in log.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("panic:") {
                return trimmed.to_owned();
            }
            if is_go_test_panic_line(&trimmed.to_ascii_lowercase()) {
                if let Some(at) = trimmed.find("panic:") {
                    return trimmed[at..].to_owned();
                }
            }
        }
        // Jazzer names the exception on its marker line.
        if let Some(exception) = log
            .lines()
            .find_map(|line| line.strip_prefix(JAVA_EXCEPTION_MARK))
        {
            return exception.trim().to_owned();
        }
        // Jazzer.js names the exception, or the bug detector's finding, on
        // its report line; a detector puts the call on the next one.
        let mut lines = log.lines();
        if let Some(report) = lines.by_ref().find_map(jazzer_js_report) {
            let report = report
                .strip_prefix(JAZZER_JS_EXCEPTION_MARK)
                .unwrap_or(report)
                .trim();
            return match lines.next().map(str::trim) {
                Some(call) if call.starts_with("in ") => format!("{report} {call}"),
                _ => report.to_owned(),
            };
        }
        // Atheris names the exception on the line after its marker; the
        // libFuzzer lines it prints afterwards say only that the target
        // exited.
        let mut lines = log.lines().map(str::trim);
        if lines.any(|line| line == ATHERIS_EXCEPTION_MARK) {
            if let Some(exception) = lines.find(|line| !line.is_empty()) {
                return exception.to_owned();
            }
        }
        if let Some(last) = log.lines().map(str::trim).rev().find(|t| !t.is_empty()) {
            return last.to_owned();
        }
    }
    // honggfuzz copies the sanitizer's headline into the `DESCRIPTION` field
    // of its report, without the `ERROR:` prefix the scan below keys on.
    if let Some(description) = log
        .lines()
        .find_map(|line| line.strip_prefix(HONGGFUZZ_DESCRIPTION_FIELD))
        .map(str::trim)
        .filter(|description| !description.is_empty())
    {
        return description.to_owned();
    }
    for line in log.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("error")
            || lower.contains("asan")
            || lower.contains("ubsan")
            || lower.contains("memorysanitizer")
            || lower.contains("threadsanitizer")
        {
            return line.trim().to_owned();
        }
    }
    format!("{kind:?} crash detected")
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_libfuzzer_out_of_memory_report_is_named_as_such() {
        // libpng under libFuzzer: an oom- artifact replayed to "Other crash
        // detected", which said nothing about what happened.
        let log = "==1== ERROR: libFuzzer: out-of-memory (malloc(4294967296))\n\
                   To change the out-of-memory limit use -rss_limit_mb=<N>\n\
                       #0 0x5d in malloc\n\
                       #1 0x7f in png_malloc_base /work/pngmem.c:76:11\n\
                   SUMMARY: libFuzzer: out-of-memory\n";
        let (_, _, summary) = super::classify(log);
        assert_eq!(summary, "out of memory: malloc(4294967296)");
    }

    #[test]
    fn a_replay_killed_at_the_memory_limit_is_one_out_of_memory_finding() {
        // LibTIFF 4.0.4 under AFL++: 19 inputs allocate past the sandbox's
        // memory and are killed with no sanitizer report. Frameless, each
        // kept its own empty signature and became a separate finding.
        let log = format!("\n{}\n", super::OOM_KILL_MARKER);
        let (kind, sig, summary) = super::classify(&log);
        assert_eq!(kind, hf_core::crash::CrashKind::Other);
        assert_eq!(sig, "out-of-memory-kill");
        assert!(summary.contains("out of memory"), "{summary}");
        assert!(super::looks_like_crash(&log));
    }

    use super::{classify, detect_kind, looks_like_crash};
    use hf_core::crash::CrashKind;

    /// The report the binary-only replay shim prints: no sanitizer, module
    /// offsets instead of symbols. The kind comes from the signal name and the
    /// signature from the offsets, whatever addresses the loader picked.
    #[test]
    fn a_binary_only_replay_report_is_signed_by_module_offsets() {
        let report = |base: &str, top: &str, name: &str, signal: u32| {
            format!(
                "==ERROR: oxfuzz-crashinfo: {name} (signal {signal}) at (/work/target+{top}), \
                 fault address 0x0\n    \
                 #0 0x{base}0934 (/work/target+{top})\n    \
                 #1 0x{base}098c (/work/target+0x98c)\n    \
                 #2 0x{base}84c4 (/lib/aarch64-linux-gnu/libc.so.6+0x284c4)\n    \
                 #3 0x{base}8598 in __libc_start_main (/lib/aarch64-linux-gnu/libc.so.6+0x28598)\n\
                 SUMMARY: oxfuzz-crashinfo: {name} (signal {signal}) at (/work/target+{top})\n"
            )
        };
        let (kind, signature, summary) = classify(&report("55000", "0x934", "SEGV", 11));
        assert_eq!(kind, CrashKind::Segv);
        assert_eq!(signature.len(), 64);
        assert!(summary.contains("oxfuzz-crashinfo: SEGV"), "{summary}");
        assert!(looks_like_crash(&report("55000", "0x934", "SEGV", 11)));

        // Another load address, the same fault.
        assert_eq!(classify(&report("7f000", "0x934", "SEGV", 11)).1, signature);
        // Another faulting instruction is another finding.
        assert_ne!(classify(&report("55000", "0x7a0", "SEGV", 11)).1, signature);

        let (kind, aborted, _) = classify(&report("55000", "0x934", "ABORT", 6));
        assert_eq!(kind, CrashKind::Abort);
        assert_ne!(aborted, signature, "the kind is part of the signature");
        assert_eq!(
            classify(&report("55000", "0x934", "FPE", 8)).0,
            CrashKind::Other
        );
    }

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

    /// A sanitizer report is attributed to the sanitizer that wrote it, not to
    /// any sanitizer runtime whose name appears somewhere in the log.
    ///
    /// `-fsanitize=address,undefined` is the standard fuzzing build, so a `UBSan`
    /// finding whose stack passes through an `ASan` interceptor (`__asan_memcpy`)
    /// or whose modules include `libasan.so` is the common case. Keying on the
    /// bare token `asan` -- checked first -- filed every one of those as `Asan`.
    /// The kind is part of the dedup signature, so the mislabel also split and
    /// merged the wrong crashes.
    #[test]
    fn a_ubsan_report_is_not_relabelled_by_an_asan_runtime_frame() {
        let ubsan_through_an_asan_interceptor = "\
==2451==ERROR: UndefinedBehaviorSanitizer: undefined-behavior
src/parse.c:12:5: runtime error: signed integer overflow: 2147483647 + 1
    #0 0x5581aa in parse_header /src/parse.c:12:5
    #1 0x5581bb in __asan_memcpy /llvm/compiler-rt/lib/asan/asan_interceptors.cpp:22
SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow /src/parse.c:12:5
";
        assert_eq!(
            detect_kind(ubsan_through_an_asan_interceptor),
            CrashKind::Ubsan,
            "the sanitizer that reported the bug owns the classification"
        );

        let ubsan_from_an_asan_linked_binary = "\
src/parse.c:12:5: runtime error: load of misaligned address
    #0 0x44 in decode /src/parse.c:12:5
    #1 0x55 in main /usr/lib/x86_64-linux-gnu/libasan.so.6
";
        assert_eq!(
            detect_kind(ubsan_from_an_asan_linked_binary),
            CrashKind::Ubsan,
            "a linked ASan runtime does not make a UBSan finding an ASan finding"
        );
    }

    /// `UBSan`'s per-finding output names no sanitizer at all.
    ///
    /// `runtime error:` is what it prints for each finding;
    /// `UndefinedBehaviorSanitizer` appears only on a `SUMMARY:` line, which a
    /// halt-on-first-error or truncated log never reaches. `looks_like_crash`
    /// already accepts such a log as a crash, so it was ingested and then filed
    /// as `Other`.
    #[test]
    fn a_bare_runtime_error_line_is_a_ubsan_finding() {
        let runtime_error_only =
            "src/parse.c:12:5: runtime error: signed integer overflow: 2147483647 + 1 \
             cannot be represented in type 'int'\n";
        assert_eq!(detect_kind(runtime_error_only), CrashKind::Ubsan);
    }

    /// A `LeakSanitizer` report is a leak, not an out-of-bounds write.
    ///
    /// `LSan` is reported by the `ASan` runtime, so a real leak report ends with a
    /// `SUMMARY: AddressSanitizer:` line and allocates through
    /// `asan_malloc_linux.cpp`. Attributing it to `ASan` would give every leak
    /// CWE-787 ("Out-of-bounds Write") and a memory-safety severity in SARIF and
    /// the `DefectDojo` export, so the leak check has to precede the `ASan` one --
    /// for the same reason the `UBSan` check does.
    #[test]
    fn a_leak_report_is_not_an_address_safety_finding() {
        let leak = "\
=================================================================
==1==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 4 byte(s) in 1 object(s) allocated from:
    #0 0x4f1b in malloc /llvm/compiler-rt/lib/asan/asan_malloc_linux.cpp:69
    #1 0x5581aa in parse_header /src/parse.c:12:5
SUMMARY: AddressSanitizer: 4 byte(s) leaked in 1 allocation(s).
";
        assert_eq!(detect_kind(leak), CrashKind::Leak);
        assert_eq!(
            detect_kind("==1==ERROR: LeakSanitizer: detected memory leaks"),
            CrashKind::Leak
        );
    }

    /// The `ASan` cases the fix must not cost us.
    ///
    /// (`LeakSanitizer` reports are deliberately absent: they classify as
    /// `Other` today, which is a separate gap from the `UBSan` edges this fixes.)
    #[test]
    fn asan_reports_still_classify_as_asan() {
        for log in [
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff4",
            "AddressSanitizer:DEADLYSIGNAL",
            "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000",
        ] {
            let kind = detect_kind(log);
            assert!(
                matches!(kind, CrashKind::Asan),
                "{log:?} must stay an ASan-family finding, got {kind:?}"
            );
        }
    }

    #[test]
    fn timeout_is_only_the_reported_error_class() {
        // An `ASan` crash whose stack merely mentions a `connect_timeout` frame is
        // an `ASan` finding, not a timeout.
        let asan_with_timeout_frame = "==1==ERROR: AddressSanitizer: SEGV on unknown address\n\
                                       #0 0xdead in connect_timeout /net.c:10:5\n\
                                       SUMMARY: AddressSanitizer: SEGV /net.c:10:5\n";
        assert_eq!(detect_kind(asan_with_timeout_frame), CrashKind::Asan);

        // A genuine libFuzzer timeout is classified as a timeout.
        let real_timeout = "==1== ERROR: libFuzzer: timeout after 60 seconds\n\
                            SUMMARY: libFuzzer: timeout\n";
        assert_eq!(detect_kind(real_timeout), CrashKind::Timeout);
    }

    /// The failure text Go 1.26.5 printed in the sandbox image for a planted
    /// out-of-range read found by `-test.fuzz`.
    const GO_FUZZ_FAILURE: &str = "\
--- FAIL: FuzzParse (0.54s)
    --- FAIL: FuzzParse (0.00s)
        testing.go:1927: panic: runtime error: index out of range [235] with length 21
            goroutine 41213 [running]:
            runtime/debug.Stack()
            \t/usr/local/go/src/runtime/debug/stack.go:26 +0xc4
            testing.tRunner.func1()
            \t/usr/local/go/src/testing/testing.go:1927 +0x218
            panic({0x235320?, 0x6d8f820c0060?})
            \t/usr/local/go/src/runtime/panic.go:860 +0x12c
            example.com/probe.Parse(...)
            \t/work/parse.go:10
            example.com/probe.FuzzParse.func1(0x6d8f7ba6a7a8?, {0x6d8f7bb80000, 0x15, 0x0?})
            \t/work/fuzz_harness_test.go:8 +0x24c
            reflect.Value.call({0x209c80?, 0x25aee0?, 0x6d8f7ba6ae28?}, {0x2495de, 0x4}, {0x6d8f8705a030, 0x2, 0x0?})
            \t/usr/local/go/src/reflect/value.go:586 +0xac8
            testing.(*F).Fuzz.func1.1(0x6d8f87058488?)
            \t/usr/local/go/src/testing/fuzz.go:341 +0x25c
            created by testing.(*F).Fuzz.func1 in goroutine 6
            \t/usr/local/go/src/testing/fuzz.go:328 +0x4ac

    Failing input written to testdata/fuzz/FuzzParse/4f85edf10c3c3e2c
FAIL
";

    #[test]
    fn a_go_fuzz_failure_is_a_panic_signed_by_the_code_under_test() {
        let (kind, signature, summary) = super::classify(GO_FUZZ_FAILURE);
        assert_eq!(kind, CrashKind::Panic, "not UBSan despite 'runtime error:'");
        assert_eq!(
            summary,
            "panic: runtime error: index out of range [235] with length 21"
        );
        assert_eq!(
            super::extract_go_frames(GO_FUZZ_FAILURE, 3),
            [
                "example.com/probe.Parse",
                "example.com/probe.FuzzParse.func1"
            ]
        );
        assert!(super::looks_like_crash(GO_FUZZ_FAILURE));
        // Addresses and goroutine numbers differ per run; the signature must not.
        let again = GO_FUZZ_FAILURE
            .replace("41213", "7")
            .replace("0x6d8f7ba6a7a8", "0x1")
            .replace("[235] with length 21", "[9] with length 4");
        assert_eq!(super::classify(&again).1, signature);
        assert!(!signature.is_empty());
        // A UBSan finding in a file whose name ends in .go-like text stays UBSan.
        let ubsan = "src/parse.c:12:3: runtime error: signed integer overflow";
        assert_eq!(super::classify(ubsan).0, CrashKind::Ubsan);
        assert!(!super::is_go_test_panic_line("note: panic: not a position"));
        assert!(super::is_go_test_panic_line("testing.go:1927: panic: boom"));
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
            control_replay: None,
            reproduction: None,
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
    fn a_python_exception_signs_the_same_from_a_run_and_from_a_replay() {
        let traceback = |harness: &str, module: &str| {
            format!(
                " === Uncaught Python exception: ===\n\
                 IndexError: list index out of range\n\
                 Traceback (most recent call last):\n\
                 \x20 File \"{harness}\", line 17, in TestOneInput\n\
                 \x20   oxfuzz_target.parse(data)\n\
                 \x20 File \"{module}\", line 4, in parse\n\
                 \x20   return table[data[2]]\n\
                 IndexError: list index out of range\n\
                 \n\
                 ==6== ERROR: libFuzzer: fuzz target exited\n\
                 SUMMARY: libFuzzer: fuzz target exited\n"
            )
        };
        let run = classify(&traceback(
            "/work/runs/7d0c/input/harness",
            "/work/runs/7d0c/input/source-context/pkg/frames.py",
        ));
        let replay = classify(&traceback("/work/fuzz_parse", "/work/pkg/frames.py"));
        assert_eq!(run.1, replay.1, "one defect, one signature");
        assert_eq!(run.2, "IndexError: list index out of range");
        let elsewhere = classify(&traceback("/work/fuzz_parse", "/work/pkg/other.py"));
        assert_ne!(elsewhere.1, replay.1, "another module is another defect");
        assert_eq!(
            super::extract_python_frames(&traceback("/work/fuzz_parse", "/work/pkg/frames.py"), 5),
            ["pkg/frames.py, line 4, in parse"]
        );
    }

    /// Captured from Jazzer 0.30.0 in sandbox image 0.2.3.
    const JAZZER_FINDING: &str = "INFO: Instrumented com.example.Frames (took 4 ms, size +64%)\n\
        \n\
        == Java Exception: java.lang.ArrayIndexOutOfBoundsException: Index 90 out of bounds for length 3\n\
        \tat com.example.Frames.parse(Frames.java:8)\n\
        \tat OxfuzzFuzzTarget.fuzzerTestOneInput(OxfuzzFuzzTarget.java:3)\n\
        DEDUP_TOKEN: 3be24d4548a2ca66\n\
        == libFuzzer crashing input ==\n\
        reproducer_path='/tmp'; Java reproducer written to /tmp/Crash_c87c.java\n";

    #[test]
    fn a_clean_jazzer_replay_is_not_a_crash() {
        let log = "INFO: Loaded 31 hooks from com.code_intelligence.jazzer.sanitizers.FilePathTraversal\n\
INFO: Loaded 63 hooks from com.code_intelligence.jazzer.sanitizers.UnsafeSanitizer\n\
INFO: Instrumented OxfuzzFuzzTarget (took 61 ms, size +29%)\n\
INFO: using inputs from: /work/out/crash-b084b39be118ed218c2cf935548563d2f01c05f6\n\
jazzer: Running 1 inputs 1 time(s) each.\n\
Executed /work/out/crash-b084b39be118ed218c2cf935548563d2f01c05f6 in 5 ms\n";
        assert!(!looks_like_crash(log));
        let finding = format!(
            "{log}== Java Exception: java.lang.ArrayIndexOutOfBoundsException: Index 128 out of bounds for length 3\n"
        );
        assert!(looks_like_crash(&finding));
    }

    #[test]
    fn a_java_exception_classifies_and_signs_by_the_frames_under_test() {
        let (kind, signature, summary) = classify(JAZZER_FINDING);
        assert_eq!(kind, CrashKind::Panic);
        assert_eq!(
            summary,
            "java.lang.ArrayIndexOutOfBoundsException: Index 90 out of bounds for length 3"
        );
        assert!(looks_like_crash(JAZZER_FINDING));
        assert_eq!(
            super::extract_frames(JAZZER_FINDING, 3),
            ["com.example.Frames.parse"]
        );
        // A different message or line of the same frames is the same defect;
        // a different frame is another one.
        let other_index = JAZZER_FINDING
            .replace("Index 90", "Index 77")
            .replace("Frames.java:8", "Frames.java:9");
        assert_eq!(classify(&other_index).1, signature);
        let elsewhere = JAZZER_FINDING.replace("Frames.parse", "Frames.decode");
        assert_ne!(classify(&elsewhere).1, signature);
        // A clean Jazzer replay is not a crash.
        assert!(!looks_like_crash(
            "INFO: Instrumented com.example.Frames (took 4 ms, size +64%)\n\
             jazzer: Running 1 inputs 1 time(s) each.\nExecuted /work/in in 2 ms\n"
        ));
    }

    /// Captured from Jazzer.js 4.0.0 on Node.js 24.22.3 in the sandbox.
    const JAZZER_JS_FINDING: &str = "INFO: Using generated seed: 1094029775\n\
        #2\tINITED cov: 4 ft: 4 corp: 1/1b exec/s: 0 rss: 176Mb\n\
        ==7== Uncaught Exception: TypeError: Cannot read properties of undefined (reading 'toString')\n\
        \x20   at header (/work/src/frames.js:5:25)\n\
        \x20   at Module.parse (/work/src/frames.js:13:12)\n\
        \x20   at fuzz (file:///tmp/oxfuzz-harness.mjs:19:17)\n\
        MS: 3 CopyPart-CopyPart-EraseBytes-; base unit: 11ec412a9136c59be4e4e1f7cb89d28ee98d160c\n\
        0x7b,0x36,0x7b,0x1a,0xa,\n\
        artifact_prefix='/work/o1/'; Test unit written to /work/o1/crash-f6a8e64792ace4675416351477eefbfa5711fec8\n";

    #[test]
    fn a_javascript_exception_classifies_and_signs_by_the_frames_under_test() {
        let (kind, signature, summary) = classify(JAZZER_JS_FINDING);
        assert_eq!(kind, CrashKind::Panic);
        assert_eq!(
            summary,
            "TypeError: Cannot read properties of undefined (reading 'toString')"
        );
        assert!(looks_like_crash(JAZZER_JS_FINDING));
        // The harness frame is not the code under test.
        assert_eq!(
            super::extract_frames(JAZZER_JS_FINDING, 5),
            ["header (src/frames.js)", "Module.parse (src/frames.js)"]
        );
        // A run loads the module from its retained sources and a replay from
        // the workspace; an ES module's frames are URLs; a later line or
        // message of the same frames is the same defect.
        let from_a_run = JAZZER_JS_FINDING
            .replace(
                "(/work/src/frames.js:5:25)",
                "(file:///work/run/inputs/source-context/src/frames.js:9:1)",
            )
            .replace(
                "(/work/src/frames.js:13:12)",
                "(file:///work/run/inputs/source-context/src/frames.js:14:3)",
            )
            .replace("reading 'toString'", "reading 'length'")
            .replace("==7==", "==4021==");
        assert_eq!(classify(&from_a_run).1, signature);
        let elsewhere = JAZZER_JS_FINDING.replace("at header", "at trailer");
        assert_ne!(classify(&elsewhere).1, signature);
    }

    #[test]
    fn javascript_frames_keep_what_names_the_code_under_test() {
        let log = "==22== Uncaught Exception: RangeError: bad prefix 4\n\
                   \x20   at async Module.decode (file:///work/esm/codec.js:13:13)\n\
                   \x20   at /work/src/table.js:3:53\n\
                   \x20   at new Promise (<anonymous>)\n\
                   \x20   at Object.lookup (/work/node_modules/dep/index.js:7:1)\n\
                   \x20   at fuzz (file:///tmp/oxfuzz-harness.mjs:19:17)\n\
                   \x20   at /opt/jazzerjs/node_modules/@jazzer.js/core/core.ts:403:15\n\
                   \x20   at processTicksAndRejections (node:internal/process/task_queues:104:5)\n\
                   Executed /work/out/crash-ed69 in 0 ms\n\
                   \x20   at not.a.frame (/work/after.js:1:1)\n";
        assert_eq!(
            super::extract_frames(log, 8),
            [
                "Module.decode (esm/codec.js)",
                "<anonymous> (src/table.js)",
                "Object.lookup (node_modules/dep/index.js)",
            ]
        );
        assert_eq!(
            super::extract_frames(log, 1),
            ["Module.decode (esm/codec.js)"]
        );
        assert_eq!(classify(log).2, "RangeError: bad prefix 4");
    }

    #[test]
    fn a_jazzer_js_bug_detector_report_is_a_finding_with_its_own_summary() {
        let log = "Running: /work/corpus/seed\n\
                   ==78== Command Injection\n\
                   \x20   in execSync(): called with 'ls jaz_zer'\n\
                   \x20   at Module.run (/work/src/frames.js:23:37)\n\
                   \x20   at fuzz (file:///tmp/oxfuzz-harness.mjs:19:17)\n\
                   Executed /work/corpus/seed in 3 ms\n";
        let (kind, _, summary) = classify(log);
        assert_eq!(kind, CrashKind::Panic);
        assert_eq!(
            summary,
            "Command Injection in execSync(): called with 'ls jaz_zer'"
        );
        assert!(looks_like_crash(log));
        assert_eq!(
            super::extract_frames(log, 5),
            ["Module.run (src/frames.js)"]
        );
    }

    #[test]
    fn a_clean_jazzer_js_replay_is_not_a_crash_and_a_timeout_is_a_timeout() {
        let clean = "INFO: Using generated seed: 795174003\n\
                     INFO: using inputs from: /tmp/benign\n\
                     Dictionary: 4 entries\n\
                     INFO: Loaded 1 modules   (512 inline 8-bit counters): 512 [0xffffbc10f010, 0xffffbc10f210), \n\
                     unused_arg0_report_a_bug_if_you_see_this: Running 1 inputs 1 time(s) each.\n\
                     Running: /tmp/benign\n\
                     Executed /tmp/benign in 0 ms\n\
                     ***\n\
                     *** NOTE: fuzzing was not performed, you have only\n\
                     ***       executed the target code on a fixed set of inputs.\n\
                     ***\n\
                     \n\
                     == Jazzer.js:\n\
                     \x20 Exclusively observed synchronous return values from fuzzed function. Fuzzing in synchronous mode seems beneficial!\n\
                     \x20 To enable it, append a `--sync` to your Jazzer.js invocation.\n";
        assert!(!looks_like_crash(clean));
        // libFuzzer's own lines carry the same process mark and are not
        // Jazzer.js reports.
        let timeout = "==9== ERROR: libFuzzer: timeout after 2 seconds\n\
                       SUMMARY: libFuzzer: timeout\n";
        assert_eq!(classify(timeout).0, CrashKind::Timeout);
        assert!(
            super::jazzer_js_report("==9== ERROR: libFuzzer: timeout after 2 seconds").is_none()
        );
        assert!(super::jazzer_js_report("==9== libFuzzer: run interrupted; exiting").is_none());
        assert!(
            super::jazzer_js_report("==9==ERROR: AddressSanitizer: heap-use-after-free").is_none()
        );
        assert!(super::jazzer_js_report("== Jazzer.js:").is_none());
        assert!(super::jazzer_js_report("== Java Exception: java.lang.Error").is_none());
        assert_eq!(
            super::jazzer_js_report("==9== Uncaught Exception: Error: x"),
            Some("Uncaught Exception: Error: x")
        );
    }

    #[test]
    fn a_clean_atheris_replay_is_not_a_crash() {
        let log = "INFO: Instrumenting pkg.frames\n\
                   INFO: Using built-in libfuzzer\n\
                   WARNING: Failed to find function \"__sanitizer_acquire_crash_state\".\n\
                   WARNING: Failed to find function \"__sanitizer_print_stack_trace\".\n\
                   WARNING: Failed to find function \"__sanitizer_set_death_callback\".\n\
                   /work/fuzz_parse: Running 1 inputs 1 time(s) each.\n\
                   Executed /work/out/crash-4456 in 0 ms\n";
        assert!(!looks_like_crash(log));
        assert!(looks_like_crash(&format!(
            "{log} === Uncaught Python exception: ===\nIndexError: x\n"
        )));
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

    /// The fields of a honggfuzz 2.6 `HONGGFUZZ.REPORT.TXT` entry for an
    /// `ASan` abort (captured in sandbox image 0.2.3). honggfuzz copies the
    /// sanitizer's headline into `DESCRIPTION`, without the `ERROR:` prefix
    /// the sanitizer itself prints.
    const HONGGFUZZ_ASAN_REPORT: &str = "\
CRASH:
DESCRIPTION: AddressSanitizer: use-after-poison on address 0xffff91b00001 at pc 0xaaaac3242320
SIGNAL: SIGABRT (6)
FAULT ADDRESS: 0x0
STACK HASH: 000000017966f6a6
STACK:
 <0x0000aaaac324231c> [func:decode_utf8 file:/work/utf8.c line:31 module:]
";

    #[test]
    fn a_honggfuzz_report_is_summarized_by_its_description() {
        let (kind, _, summary) = classify(HONGGFUZZ_ASAN_REPORT);
        assert_eq!(kind, CrashKind::Asan);
        assert_eq!(
            summary,
            "AddressSanitizer: use-after-poison on address 0xffff91b00001 at pc 0xaaaac3242320"
        );
    }

    #[test]
    fn clean_replay_is_not_a_crash() {
        assert!(!looks_like_crash(""));
        assert!(!looks_like_crash("Executed crash-abc in 2 ms\nDone 1 runs"));
    }

    /// Captured from a libFuzzer `-fsanitize=memory` run in sandbox image 0.2.2.
    const MSAN_REPORT: &str = "\
==14==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0xaaaae5438f4c in parse /work/msan.c:9:7
    #1 0xaaaae5438978 in LLVMFuzzerTestOneInput /work/msan.c:13:58
SUMMARY: MemorySanitizer: use-of-uninitialized-value /work/msan.c:9:7 in parse
";

    #[test]
    fn memory_sanitizer_reports_classify_as_msan() {
        let (kind, signature, summary) = classify(MSAN_REPORT);
        assert_eq!(kind, CrashKind::Msan);
        assert!(!signature.is_empty());
        assert_eq!(
            summary,
            "==14==WARNING: MemorySanitizer: use-of-uninitialized-value"
        );
    }

    #[test]
    fn thread_sanitizer_reports_classify_as_tsan() {
        let report = crate::frames::tests::TSAN_RACE;
        let (kind, signature, summary) = classify(report);
        assert_eq!(kind, CrashKind::Tsan);
        assert!(!signature.is_empty());
        assert_eq!(summary, "WARNING: ThreadSanitizer: data race (pid=45)");
    }

    /// `TSan` prints the module offset and build id on every frame. Neither
    /// identifies the bug, and both change when the harness is rebuilt.
    #[test]
    fn tsan_signature_survives_a_rebuild() {
        let report = crate::frames::tests::TSAN_RACE;
        let rebuilt = report
            .replace(
                "62f281dae895bb4a0d88cec48fa7e02ce30ba699",
                "0000000000000000000000000000000000000000",
            )
            .replace("t+0x1294f8", "t+0x1300a0")
            .replace("pid=45", "pid=46");
        assert_eq!(classify(report).1, classify(&rebuilt).1);
    }
}
