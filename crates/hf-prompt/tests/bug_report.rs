//! The bug-report drafting prompt: what evidence reaches the model and how
//! it is labelled.

use hf_core::crash::{CasrReport, Crash, CrashKind, CrashOrigin, CrashSeverity};
use hf_prompt::{render_bug_report_prompt, BugReportEvidence};
use std::path::PathBuf;

fn crash() -> Crash {
    Crash {
        reproduction: None,
        id: uuid::Uuid::new_v4(),
        run_id: uuid::Uuid::new_v4(),
        target_id: uuid::Uuid::new_v4(),
        input_path: PathBuf::from("/work/out/crash-1"),
        stack_signature: "a".repeat(64),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow in parse_header".to_owned(),
        minimized: false,
        bug_report: None,
        casr: Some(CasrReport {
            severity: CrashSeverity::Exploitable,
            severity_short: "heap-buffer-overflow(write)".to_owned(),
            crashline: "/work/src/parse.c:42:7".to_owned(),
            stack: vec![
                "#0 parse_header /work/src/parse.c:42:7".to_owned(),
                "#1 LLVMFuzzerTestOneInput /work/harness.c:9:3".to_owned(),
            ],
            cluster: None,
        }),
        origin: CrashOrigin::Target,
    }
}

fn evidence<'a>() -> BugReportEvidence<'a> {
    BugReportEvidence {
        log: "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
        harness_source: Some(
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { return parse_header(d, n); }",
        ),
        target_definition: None,
        crash_site: None,
        related_context: None,
    }
}

#[test]
fn the_prompt_carries_the_casr_frames_and_crash_line_not_the_signature_hash() {
    let prompt = render_bug_report_prompt(&crash(), &evidence());
    assert!(
        prompt.contains("#0 parse_header /work/src/parse.c:42:7"),
        "{prompt}"
    );
    assert!(prompt.contains("/work/src/parse.c:42:7"), "{prompt}");
    assert!(prompt.contains("heap-buffer-overflow(write)"), "{prompt}");
    assert!(
        !prompt.contains(&"a".repeat(64)),
        "a dedup hash tells the model nothing: {prompt}"
    );
}

#[test]
fn the_harness_is_never_labelled_as_target_source() {
    let prompt = render_bug_report_prompt(&crash(), &evidence());
    assert!(!prompt.contains("Target source"), "{prompt}");
    assert!(prompt.contains("Fuzz harness"), "{prompt}");
    assert!(prompt.contains("not the code under test"), "{prompt}");
}

#[test]
fn target_and_crash_site_sections_are_included_verbatim() {
    let mut evidence = evidence();
    evidence.target_definition = Some("\n\nTarget definition (src/parse.c, line 30): ...");
    evidence.crash_site = Some("\n\nCrash site (src/parse.c, lines 32-52): ...");
    let prompt = render_bug_report_prompt(&crash(), &evidence);
    assert!(
        prompt.contains("Target definition (src/parse.c, line 30)"),
        "{prompt}"
    );
    assert!(
        prompt.contains("Crash site (src/parse.c, lines 32-52)"),
        "{prompt}"
    );
}

#[test]
fn the_log_is_fenced_untrusted_and_bounded() {
    let mut evidence = evidence();
    let flood = "x".repeat(hf_prompt::MAX_BUG_REPORT_LOG_CHARS * 2);
    evidence.log = &flood;
    let prompt = render_bug_report_prompt(&crash(), &evidence);
    assert!(prompt.contains("untrusted"), "{prompt}");
    assert!(!prompt.contains(&flood), "the log must be bounded");
    assert!(
        prompt.contains("(log truncated)"),
        "the cut must be visible"
    );
}

#[test]
fn the_origin_reaches_the_model() {
    let mut harness_fault = crash();
    harness_fault.origin = CrashOrigin::Harness;
    let prompt = render_bug_report_prompt(&harness_fault, &evidence());
    assert!(prompt.contains("Fault origin: Harness"), "{prompt}");
}

#[test]
fn a_crash_without_casr_says_the_frames_are_unavailable() {
    let mut plain = crash();
    plain.casr = None;
    let prompt = render_bug_report_prompt(&plain, &evidence());
    assert!(
        prompt.contains("(no normalized stack available)"),
        "{prompt}"
    );
}

#[test]
fn crash_site_section_names_the_window_and_marks_the_faulting_line() {
    let section = hf_prompt::render_crash_site_section(
        "src/parse.c",
        40,
        42,
        "int a;\nint b;\nbuf[n] = 0;\nint c;",
    );
    assert!(section.contains("src/parse.c"), "{section}");
    assert!(section.contains("lines 40-43"), "{section}");
    assert!(section.contains("42 >| buf[n] = 0;"), "{section}");
    assert!(section.contains("untrusted"), "{section}");
    assert!(hf_prompt::render_crash_site_section("a.c", 1, 1, " \n").is_empty());
}
