//! Tests for dedup, minimize args, and bug-report response parsing.

use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::EngineKind;
use hf_crash::{bug_report_from_response, build_minimize_args, dedup};
use std::path::PathBuf;
use uuid::Uuid;

fn crash(sig: &str, kind: CrashKind) -> Crash {
    Crash {
        reproduction: None,
        id: Uuid::new_v4(),
        run_id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        input_path: PathBuf::from("/work/crash-1"),
        stack_signature: sig.to_owned(),
        kind,
        summary: "test crash".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
        origin: hf_core::crash::CrashOrigin::Unknown,
    }
}

#[test]
fn dedup_collapses_same_signature() {
    let crashes = vec![
        crash("abc123", CrashKind::Asan),
        crash("abc123", CrashKind::Asan),
        crash("def456", CrashKind::Segv),
    ];
    let result = dedup(crashes);
    assert_eq!(result.len(), 2, "should dedup to 2");
    let sigs: Vec<&str> = result.iter().map(|c| c.stack_signature.as_str()).collect();
    assert!(sigs.contains(&"abc123"));
    assert!(sigs.contains(&"def456"));
}

#[test]
fn dedup_keeps_empty_signatures() {
    let crashes = vec![crash("", CrashKind::Other), crash("", CrashKind::Other)];
    let result = dedup(crashes);
    assert_eq!(result.len(), 2, "empty signatures should not be deduped");
}

#[test]
fn dedup_empty_input() {
    let result = dedup(Vec::new());
    assert!(result.is_empty());
}

#[test]
fn minimize_args_libfuzzer() {
    let args = build_minimize_args(
        EngineKind::LibFuzzer,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/out",
    )
    .expect("libFuzzer should have a minimizer");
    // The binary must be argv[0], the crash file must be the positional input
    // (last arg, not a flag value), and the minimized result goes to
    // -exact_artifact_path (the output, never the crash itself).
    assert_eq!(args.first().map(String::as_str), Some("/work/fuzz_bin"));
    assert_eq!(args.last().map(String::as_str), Some("/work/crash-1"));
    assert!(args.iter().any(|a| a == "-minimize_crash=1"));
    assert!(args.iter().any(|a| a == "-exact_artifact_path=/work/out"));
    assert!(
        !args
            .iter()
            .any(|a| a.contains("-exact_artifact_path=/work/crash-1")),
        "crash input must not be used as the output path"
    );
}

#[test]
fn minimize_args_afl() {
    let args = build_minimize_args(
        EngineKind::AflPlusPlus,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/minimized",
    )
    .expect("AFL++ should have a minimizer");
    assert_eq!(args.first().map(String::as_str), Some("afl-tmin"));
    // afl-tmin needs the target after `--` with a `@@` file placeholder, or it
    // has no program to run.
    let sep = args
        .iter()
        .position(|a| a == "--")
        .expect("must have -- separator");
    assert_eq!(
        args.get(sep + 1).map(String::as_str),
        Some("/work/fuzz_bin")
    );
    assert_eq!(args.get(sep + 2).map(String::as_str), Some("@@"));
    // Input/output flags precede the separator.
    let i = args.iter().position(|a| a == "-i").expect("-i");
    assert_eq!(args.get(i + 1).map(String::as_str), Some("/work/crash-1"));
    let o = args.iter().position(|a| a == "-o").expect("-o");
    assert_eq!(args.get(o + 1).map(String::as_str), Some("/work/minimized"));
}

#[test]
fn minimize_args_honggfuzz_none() {
    let args = build_minimize_args(
        EngineKind::Honggfuzz,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/out",
    );
    assert!(args.is_none(), "honggfuzz has no built-in minimizer");
}

#[test]
fn minimize_args_thread_the_resolved_per_input_timeout() {
    use std::time::Duration;

    // afl-tmin takes the per-execution timeout in exact milliseconds via
    // `-t`, the same granularity afl-fuzz/afl-cmin take: a crash that needs
    // longer than the pinned 1000 ms default to reproduce would otherwise
    // make afl-tmin FATAL ("Target binary times out").
    let afl = hf_crash::build_minimize_args_with_timeout(
        EngineKind::AflPlusPlus,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/minimized",
        Duration::from_millis(2500),
    )
    .expect("AFL++ should have a minimizer");
    let flag = afl.iter().position(|a| a == "-t").expect("-t flag");
    assert_eq!(afl.get(flag + 1).map(String::as_str), Some("2500"));

    // libFuzzer takes whole seconds via `-timeout=`; a sub-second budget
    // rounds up so the flag never reads as "no timeout".
    let libfuzzer = hf_crash::build_minimize_args_with_timeout(
        EngineKind::LibFuzzer,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/out",
        Duration::from_millis(2500),
    )
    .expect("libFuzzer should have a minimizer");
    assert!(
        libfuzzer.contains(&"-timeout=3".to_owned()),
        "2500 ms must round up to 3 s: {libfuzzer:?}"
    );
    // The crash file stays the positional input.
    assert_eq!(libfuzzer.last().map(String::as_str), Some("/work/crash-1"));
}

#[test]
fn minimize_args_default_to_the_afl_tmin_pinned_timeout() {
    // Without a resolved policy budget the argv pins afl-tmin's own default
    // (EXEC_TIMEOUT = 1000 ms in AFL++ 4.09c) instead of leaving it implicit,
    // and libFuzzer gets the same budget in its whole-second form.
    let afl = build_minimize_args(
        EngineKind::AflPlusPlus,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/minimized",
    )
    .expect("AFL++ should have a minimizer");
    let flag = afl.iter().position(|a| a == "-t").expect("-t flag");
    assert_eq!(afl.get(flag + 1).map(String::as_str), Some("1000"));

    let libfuzzer = build_minimize_args(
        EngineKind::LibFuzzer,
        "/work/fuzz_bin",
        "/work/crash-1",
        "/work/out",
    )
    .expect("libFuzzer should have a minimizer");
    assert!(
        libfuzzer.contains(&"-timeout=1".to_owned()),
        "the 1000 ms default is 1 s: {libfuzzer:?}"
    );
}

#[test]
fn a_model_response_becomes_a_bug_report() {
    let response = r##"{
        "title": "heap-buffer-overflow in parse_string",
        "summary": "parse_string reads past buffer end on truncated input.",
        "repro_steps": "clang -fsanitize=fuzzer,address fuzz.c && ./fuzz_bin crash-1",
        "stack": "#0 parse_string #1 parse_value",
        "severity_guess": "high",
        "root_cause": "the length check runs after the read",
        "suggested_fix": "--- a/parse.c\n+++ b/parse.c\n"
    }"##;
    let report = bug_report_from_response(&crash("sig", CrashKind::Asan), response);
    assert_eq!(report.title, "heap-buffer-overflow in parse_string");
    assert_eq!(report.severity_guess, "high");
    assert!(report.repro_steps.contains("clang"));
    assert_eq!(
        report.root_cause.as_deref(),
        Some("the length check runs after the read")
    );
}

#[test]
fn an_unparseable_response_falls_back_to_the_crash_evidence() {
    let mut framed = crash("sig", CrashKind::Asan);
    framed.casr = Some(hf_core::crash::CasrReport {
        severity: hf_core::crash::CrashSeverity::NotExploitable,
        severity_short: "abort".to_owned(),
        crashline: "src/a.c:3".to_owned(),
        stack: vec!["#0 abort".to_owned(), "#1 match_magic src/a.c:3".to_owned()],
        cluster: None,
    });
    let report = bug_report_from_response(&framed, "not json");
    assert!(report.title.contains("Asan"));
    assert_eq!(report.severity_guess, "uncertain");
    assert_eq!(
        report.stack, "#0 abort\n#1 match_magic src/a.c:3",
        "the fallback stack is the normalized frames, not the dedup hash"
    );
    assert_eq!(
        bug_report_from_response(&crash("sig", CrashKind::Asan), "not json").stack,
        "",
        "without frames the fallback leaves the stack empty"
    );
}
