//! Weakness classification and remediation guidance for findings.

use std::path::PathBuf;

use hf_core::crash::{CasrReport, Crash, CrashKind, CrashSeverity};
use hf_service::report::ReportLanguage;
use hf_service::sarif::{cwe_for, security_severity};
use hf_service::weakness::{classify, guidance, WeaknessClass};
use uuid::Uuid;

fn crash(kind: CrashKind, severity: CrashSeverity, short: &str) -> Crash {
    Crash {
        reproduction: None,
        id: Uuid::nil(),
        run_id: Uuid::nil(),
        target_id: Uuid::nil(),
        input_path: PathBuf::from("/work/out/crash-1"),
        stack_signature: "/work/utf8.c:31:27".to_owned(),
        kind,
        summary: format!("{short} at /work/utf8.c:31:27"),
        minimized: false,
        bug_report: None,
        casr: Some(CasrReport {
            severity,
            severity_short: short.to_owned(),
            crashline: "/work/utf8.c:31:27".to_owned(),
            stack: vec![],
            cluster: None,
        }),
        origin: hf_core::crash::CrashOrigin::Target,
    }
}

/// CASR short descriptions as CASR prints them, mapped to the weakness a
/// reader should fix. `stack-overflow` is stack exhaustion through unbounded
/// recursion, not a stack buffer overflow; it used to be reported as CWE-121.
#[test]
fn casr_classes_map_to_the_weakness_they_name() {
    let cases = [
        ("heap-buffer-overflow(read)", "CWE-125"),
        ("heap-buffer-overflow(write)", "CWE-787"),
        ("global-buffer-overflow(read)", "CWE-125"),
        ("stack-buffer-overflow(write)", "CWE-121"),
        ("stack-buffer-overflow(read)", "CWE-125"),
        ("stack-overflow", "CWE-674"),
        ("heap-use-after-free(read)", "CWE-416"),
        ("double-free", "CWE-415"),
        ("bad-free", "CWE-590"),
        ("alloc-dealloc-mismatch", "CWE-762"),
        ("stack-use-after-return(read)", "CWE-562"),
        ("use-after-poison(read)", "CWE-119"),
        ("SourceAvNearNull", "CWE-476"),
        ("FPE", "CWE-369"),
        ("allocation-size-too-big", "CWE-789"),
        ("out-of-memory", "CWE-400"),
        ("memory-leaks", "CWE-401"),
    ];
    for (short, expected) in cases {
        let finding = crash(CrashKind::Asan, CrashSeverity::NotExploitable, short);
        assert_eq!(cwe_for(&finding).id, expected, "{short}");
    }
}

#[test]
fn a_crash_without_casr_falls_back_to_its_kind() {
    let mut finding = crash(CrashKind::Timeout, CrashSeverity::Undefined, "");
    finding.casr = None;
    assert_eq!(classify(&finding), WeaknessClass::ExcessiveIteration);
    assert_eq!(cwe_for(&finding).id, "CWE-834");
}

/// CASR rates code-execution exploitability. An out-of-bounds read it calls
/// not exploitable still discloses memory, so it is not reported at the
/// lowest band next to a leak.
#[test]
fn memory_safety_findings_are_at_least_medium_severity() {
    let read = crash(
        CrashKind::Asan,
        CrashSeverity::NotExploitable,
        "heap-buffer-overflow(read)",
    );
    assert!(security_severity(&read) >= 4.0);
    let mut leak = crash(
        CrashKind::Leak,
        CrashSeverity::NotExploitable,
        "memory-leaks",
    );
    leak.casr = None;
    assert!(security_severity(&leak) < 4.0);
    let exploitable = crash(
        CrashKind::Asan,
        CrashSeverity::Exploitable,
        "heap-buffer-overflow(write)",
    );
    assert!(security_severity(&exploitable) >= 9.0);
}

#[test]
fn every_class_has_actionable_guidance_in_both_languages() {
    for class in WeaknessClass::ALL {
        for language in [ReportLanguage::En, ReportLanguage::Zh] {
            let text = guidance(class, language);
            assert!(!text.impact.trim().is_empty(), "{class:?} {language:?}");
            assert!(text.remediation.len() >= 2, "{class:?} {language:?}");
            assert!(text.remediation.iter().all(|step| !step.trim().is_empty()));
        }
    }
}

#[test]
fn out_of_bounds_read_guidance_names_the_bounds_check() {
    let text = guidance(WeaknessClass::OutOfBoundsRead, ReportLanguage::En);
    let joined = text.remediation.join(" ").to_ascii_lowercase();
    assert!(joined.contains("length"), "{joined}");
    assert!(joined.contains("before"), "{joined}");
}
