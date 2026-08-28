//! Tests for progress and coverage parsing.

use hf_core::engine::FuzzProgress;
use hf_engine::progress::parse_progress;

#[test]
fn parse_libfuzzer_execs_line() {
    let events = parse_progress("INFO: 1024 edges covered.\n#512: 5000 execs/sec\n");
    assert!(
        events.iter().any(|e| matches!(
            e,
            FuzzProgress::ExecsPerSec(n) if (*n - 5000.0).abs() < 1.0
        )),
        "should find 5000 execs/sec: {events:?}"
    );
}

#[test]
fn parse_libfuzzer_edges_line() {
    let events = parse_progress("INFO: 1024 edges covered.\n");
    assert!(
        events.iter().any(|e| matches!(
            e,
            FuzzProgress::EdgesCovered(n) if *n == 1024
        )),
        "should find 1024 edges: {events:?}"
    );
}

#[test]
fn parse_libfuzzer_cov_line() {
    let events = parse_progress("#2\tINITED cov: 10 ft: 11 corp: 1/3b exec/s: 0 rss: 32Mb\n");
    assert!(
        events.iter().any(|e| matches!(
            e,
            FuzzProgress::EdgesCovered(n) if *n == 10
        )),
        "should find 10 edges from libFuzzer cov: {events:?}"
    );
}

#[test]
fn parse_afl_cov_line() {
    // AFL++ output: "cov: 1234"
    let events = parse_progress("cov: 1234");
    assert!(
        events.iter().any(|e| matches!(
            e,
            FuzzProgress::EdgesCovered(n) if *n == 1234
        )),
        "should find 1234 edges from AFL cov: {events:?}"
    );
}

#[test]
fn parse_crash_line() {
    let events = parse_progress("==12345==ERROR: AddressSanitizer: heap-buffer-overflow\n");
    assert!(
        events
            .iter()
            .any(|e| matches!(e, FuzzProgress::CrashesFound(_))),
        "should detect crash: {events:?}"
    );
}

/// `ASan`'s own benign warnings are not findings.
///
/// The runtime prints these on healthy runs -- `__asan_handle_no_return` fires
/// on longjmp and deep recursion, and the makecontext notice on any program
/// using ucontext -- and neither reports a bug. Every real `ASan` *error* names
/// itself in full (`ERROR: AddressSanitizer: ...`, `AddressSanitizer:DEADLYSIGNAL`),
/// so matching the bare token `asan` adds no detection and counts these as
/// crashes. The service floors a run's crash count at one whenever a finding
/// line was seen, so a single warning reports a phantom crash for the campaign.
#[test]
fn benign_sanitizer_warnings_are_not_findings() {
    for line in [
        "==1234==WARNING: ASan is ignoring requested __asan_handle_no_return: \
         stack top: 0x7ffd0000; bottom 0x7ffc0000; size: 0x10000 (65536)",
        "==1234==WARNING: ASan doesn't fully support makecontext/swapcontext \
         functions and may produce false positives in some cases!",
        "INFO: Running with libasan.so.6 preloaded",
    ] {
        let events = parse_progress(line);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, FuzzProgress::CrashesFound(_))),
            "a benign ASan line must not be counted as a finding: {line:?} -> {events:?}"
        );
    }
}

/// Every sanitizer report this tool must not miss still registers.
#[test]
fn real_sanitizer_reports_are_findings() {
    for line in [
        "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff4",
        "==1234==ERROR: LeakSanitizer: detected memory leaks",
        "AddressSanitizer:DEADLYSIGNAL",
        "runtime error: signed integer overflow -- SUMMARY: UBSan: undefined-behavior",
        "==1234==ERROR: AddressSanitizer: SEGV on unknown address",
        "Test unit written to /work/out/crash-deadbeef",
    ] {
        let events = parse_progress(line);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, FuzzProgress::CrashesFound(_))),
            "a real sanitizer report must register as a finding: {line:?} -> {events:?}"
        );
    }
}

#[test]
fn parse_done_line() {
    let events = parse_progress("DONE\n");
    assert!(
        events.iter().any(|e| matches!(e, FuzzProgress::Done)),
        "should detect done: {events:?}"
    );
}
