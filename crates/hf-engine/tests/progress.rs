//! Tests for progress and coverage parsing.

use hf_core::engine::FuzzProgress;
use hf_engine::progress::{parse_progress, parse_progress_events};

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

#[test]
fn live_throughput_preserves_fractional_executions_per_second() {
    for line in ["exec speed : 0.5/sec", "Speed : 1234.5/sec [avg: 1000]"] {
        let expected = if line.starts_with("exec") {
            0.5
        } else {
            1234.5
        };
        let events = hf_engine::progress::parse_progress_events(line);
        assert!(
            events.iter().any(|event| matches!(event,
                FuzzProgress::ExecsPerSec(rate) if (*rate - expected).abs() < f64::EPSILON
            )),
            "{line}: {events:?}"
        );
    }
}

#[test]
fn throughput_before_execs_label_does_not_read_later_counters() {
    let events = hf_engine::progress::parse_progress_events("5000 execs/sec, 3 crashes");
    assert!(
        events.iter().any(|event| matches!(event,
            FuzzProgress::ExecsPerSec(rate) if (*rate - 5000.0).abs() < f64::EPSILON
        )),
        "{events:?}"
    );
}

#[test]
fn fork_mode_status_line_reports_the_aggregate_rate() {
    // The printed exec/s is the parent's current-window rate; the cumulative
    // counter over elapsed time is the campaign's aggregate throughput.
    let events = parse_progress_events(
        "#37851418: cov: 60 ft: 60 corp: 38 exec/s: 695057 oom/timeout/crash: 0/0/0 time: 18s job: 9 dft_time: 0",
    );
    let rates: Vec<f64> = events
        .iter()
        .filter_map(|event| match event {
            FuzzProgress::ExecsPerSec(rate) => Some(*rate),
            _ => None,
        })
        .collect();
    assert!(
        rates.iter().any(|rate| (*rate - 2_102_856.6).abs() < 1.0),
        "expected the 37851418/18s aggregate among {rates:?}"
    );
    assert!(
        rates.contains(&695_057.0),
        "the window rate stays available: {rates:?}"
    );
}

#[test]
fn single_process_pulse_lines_carry_no_aggregate_candidate() {
    let events = parse_progress_events("#2048: pulse cov: 6 exec/s: 1000");
    let rates: Vec<f64> = events
        .iter()
        .filter_map(|event| match event {
            FuzzProgress::ExecsPerSec(rate) => Some(*rate),
            _ => None,
        })
        .collect();
    assert_eq!(rates, vec![1000.0], "no time: field means no aggregate");
}

#[test]
fn sub_second_fork_lines_produce_no_unstable_aggregate() {
    let events = parse_progress_events("#5000: cov: 10 exec/s: 9000 time: 0s job: 1");
    assert!(
        !events.iter().any(|event| matches!(
            event,
            FuzzProgress::ExecsPerSec(rate) if *rate > 9000.0
        )),
        "{events:?}"
    );
}

#[test]
fn go_native_status_lines_report_rate_and_coverage_total() {
    let events = parse_progress_events(
        "fuzz: elapsed: 3s, execs: 12345 (4115/sec), new interesting: 5 (total: 8)",
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, FuzzProgress::ExecsPerSec(r) if (*r - 4115.0).abs() < 0.5)),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, FuzzProgress::EdgesCovered(8))),
        "the cumulative interesting-input total is the coverage proxy: {events:?}"
    );
    // The cumulative execution counter must not be mistaken for a rate.
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, FuzzProgress::ExecsPerSec(r) if (*r - 12345.0).abs() < 0.5)),
        "{events:?}"
    );
}

#[test]
fn go_native_baseline_lines_report_nothing() {
    let events =
        parse_progress_events("fuzz: elapsed: 0s, gathering baseline coverage: 0/3 completed");
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn go_native_failures_are_finding_signals() {
    for line in [
        "--- FAIL: FuzzParseFrame (0.00s)",
        "    fuzz_test.go:12: panic: runtime error: index out of range",
        "fuzz: elapsed: 1s, minimizing 8-byte input to 3 bytes",
        "fuzz: failing input written to testdata/fuzz/FuzzParseFrame/4e6c",
    ] {
        assert!(hf_engine::progress::line_reports_finding(line), "{line}");
    }
    // Passing tests and normal status lines are not findings.
    for line in [
        "--- PASS: FuzzParseFrame (0.01s)",
        "fuzz: elapsed: 3s, execs: 12345 (4115/sec), new interesting: 5 (total: 8)",
        "PASS",
    ] {
        assert!(!hf_engine::progress::line_reports_finding(line), "{line}");
    }
}

/// Extract the single stats snapshot from an event stream, if present.
fn stats_event(events: &[FuzzProgress]) -> Option<hf_core::engine::EngineStats> {
    events.iter().find_map(|event| match event {
        FuzzProgress::Stats(stats) => Some(stats.clone()),
        _ => None,
    })
}

#[test]
fn libfuzzer_pulse_line_yields_a_full_stats_snapshot() {
    // A captured single-process pulse line: counter, coverage, corpus, rate.
    let events = parse_progress_events(
        "#131072 pulse cov: 58 ft: 406 corp: 215/64Kb lim: 4096 exec/s: 43690 rss: 546Mb",
    );
    let stats = stats_event(&events).expect("a pulse line carries a stats snapshot");
    assert_eq!(stats.execs_total, Some(131_072));
    assert_eq!(stats.edges_covered, Some(58));
    assert_eq!(stats.corpus_count, Some(215));
    assert_eq!(stats.execs_per_sec, Some(43_690.0));
    assert_eq!(stats.cycles_done, None, "libFuzzer has no queue cycles");
    // The dedicated scalar events keep flowing for aggregation.
    assert!(events
        .iter()
        .any(|e| matches!(e, FuzzProgress::EdgesCovered(58))));
}

#[test]
fn libfuzzer_new_and_inited_lines_yield_stats_snapshots() {
    let new_line = parse_progress_events(
        "#262144 NEW    cov: 60 ft: 420 corp: 216/65Kb lim: 4096 exec/s: 52428 rss: 549Mb L: 31/4096 MS: 2 Shuffle-ChangeUnits-",
    );
    let stats = stats_event(&new_line).expect("a NEW line carries a stats snapshot");
    assert_eq!(stats.execs_total, Some(262_144));
    assert_eq!(stats.edges_covered, Some(60));
    assert_eq!(stats.corpus_count, Some(216));

    let inited = parse_progress_events("#2\tINITED cov: 10 ft: 11 corp: 1/3b exec/s: 0 rss: 32Mb");
    let stats = stats_event(&inited).expect("an INITED line carries a stats snapshot");
    assert_eq!(stats.execs_total, Some(2));
    assert_eq!(stats.edges_covered, Some(10));
    assert_eq!(stats.corpus_count, Some(1));
    assert_eq!(stats.execs_per_sec, Some(0.0));
}

#[test]
fn libfuzzer_fork_mode_line_includes_uptime() {
    let events = parse_progress_events(
        "#37851418: cov: 60 ft: 60 corp: 38 exec/s: 695057 oom/timeout/crash: 0/0/0 time: 18s job: 9 dft_time: 0",
    );
    let stats = stats_event(&events).expect("a fork-mode status line carries a stats snapshot");
    assert_eq!(stats.execs_total, Some(37_851_418));
    assert_eq!(stats.edges_covered, Some(60));
    assert_eq!(stats.corpus_count, Some(38));
    assert_eq!(stats.execs_per_sec, Some(695_057.0));
    // The standalone `time:` field is the run's uptime; `dft_time:` must not
    // be misread for it.
    assert_eq!(stats.uptime_secs, Some(18));
}

#[test]
fn libfuzzer_final_stat_lines_yield_terminal_counters() {
    let total = parse_progress_events("stat::number_of_executed_units: 128934");
    let stats = stats_event(&total).expect("the final unit count is a stats snapshot");
    assert_eq!(stats.execs_total, Some(128_934));
    assert_eq!(stats.execs_per_sec, None);

    let rate = parse_progress_events("stat::average_exec_per_sec: 842");
    let stats = stats_event(&rate).expect("the final average rate is a stats snapshot");
    assert_eq!(stats.execs_per_sec, Some(842.0));
    assert_eq!(stats.execs_total, None);
}

#[test]
fn lines_without_stats_fields_yield_no_snapshot() {
    for line in [
        // A libFuzzer NEW_FUNC line has a `#N` counter but no stats fields.
        "#7\tNEW_FUNC[1/2]: 0xdeadbeef in parse_value /src/parser.c:12",
        // A bare comment marker.
        "#42",
        // Plain engine prose.
        "INFO: Seed: 1234",
        "DONE",
    ] {
        let events = parse_progress_events(line);
        assert!(
            stats_event(&events).is_none(),
            "{line:?} must not produce a stats snapshot: {events:?}"
        );
    }
}

#[test]
fn honggfuzz_status_lines_yield_stats_snapshots() {
    let iterations = parse_progress_events("  Iterations : 136534 [mode: 'DYNAMIC']");
    let stats = stats_event(&iterations).expect("Iterations carries execs_total");
    assert_eq!(stats.execs_total, Some(136_534));
    assert_eq!(stats.execs_per_sec, None);

    let corpus = parse_progress_events("  Corpus Size : 91");
    let stats = stats_event(&corpus).expect("Corpus Size carries corpus_count");
    assert_eq!(stats.corpus_count, Some(91));

    let timeouts = parse_progress_events("  Timeouts : 2 [10 seconds]");
    let stats = stats_event(&timeouts).expect("Timeouts carries hangs");
    assert_eq!(stats.hangs, Some(2));
}

#[test]
fn honggfuzz_counter_and_speed_lines_keep_their_scalar_only_events() {
    // Crash counters come from ingesting the crash directory, not the status
    // tick, and Speed/Coverage already emit their dedicated scalar events;
    // none of these lines may additionally emit a stats snapshot.
    for line in [
        "Crashes : 7 (unique: 3, blacklist: 0, verified: 0)",
        "Speed : 246/sec [avg: 246]",
        "Coverage : edge: 123/4567 [2%] pc: 0 cmp: 0",
    ] {
        let events = parse_progress_events(line);
        assert!(
            stats_event(&events).is_none(),
            "{line:?} must not produce a stats snapshot: {events:?}"
        );
    }
}
