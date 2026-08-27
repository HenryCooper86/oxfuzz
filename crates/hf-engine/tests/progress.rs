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

#[test]
fn parse_done_line() {
    let events = parse_progress("DONE\n");
    assert!(
        events.iter().any(|e| matches!(e, FuzzProgress::Done)),
        "should detect done: {events:?}"
    );
}
