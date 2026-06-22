//! Tests for progress and coverage parsing.

use hf_core::engine::FuzzProgress;
use hf_engine::progress::{parse_coverage, parse_progress};
use uuid::Uuid;

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

#[test]
fn coverage_report_extracts_max_edges() {
    let stdout = "INFO: 100 edges covered.\nINFO: 500 edges covered.\nINFO: 250 edges covered.\n";
    let run_id = Uuid::new_v4();
    let report = parse_coverage(stdout, run_id);
    assert_eq!(report.edges, 500, "should pick max edge count");
    assert_eq!(report.run_id, run_id);
}

#[test]
fn coverage_report_counts_crashes() {
    let stdout = "INFO: 100 edges covered.\n==ERROR: crash\n==ERROR: crash\n";
    let report = parse_coverage(stdout, Uuid::new_v4());
    assert_eq!(report.edges, 100);
}
