//! Tests for SARIF + CWE/CVSS export.

use std::path::PathBuf;

use hf_core::crash::{CasrReport, Crash, CrashKind, CrashSeverity};
use hf_service::sarif::{crashes_to_sarif, cwe_for, security_severity};
use uuid::Uuid;

fn crash(kind: CrashKind, severity: CrashSeverity, short: &str, crashline: &str) -> Crash {
    Crash {
        id: Uuid::nil(),
        run_id: Uuid::nil(),
        target_id: Uuid::nil(),
        input_path: PathBuf::from("/work/out/crash-1"),
        stack_signature: "sig-abc".to_owned(),
        kind,
        summary: format!("{short} crash"),
        minimized: false,
        bug_report: None,
        casr: Some(CasrReport {
            severity,
            severity_short: short.to_owned(),
            crashline: crashline.to_owned(),
            stack: vec![],
            cluster: None,
        }),
    }
}

#[test]
fn cwe_mapping_is_specific() {
    assert_eq!(
        cwe_for(&crash(CrashKind::Asan, CrashSeverity::Exploitable, "heap-buffer-overflow(write)", "")).id,
        "CWE-787"
    );
    assert_eq!(
        cwe_for(&crash(CrashKind::Asan, CrashSeverity::Undefined, "heap-buffer-overflow(read)", "")).id,
        "CWE-125"
    );
    assert_eq!(
        cwe_for(&crash(CrashKind::Asan, CrashSeverity::Exploitable, "heap-use-after-free", "")).id,
        "CWE-416"
    );
    assert_eq!(
        cwe_for(&crash(CrashKind::Segv, CrashSeverity::Undefined, "", "")).id,
        "CWE-476"
    );
}

#[test]
fn severity_tracks_exploitability() {
    let exploitable = crash(CrashKind::Asan, CrashSeverity::Exploitable, "x", "");
    let not = crash(CrashKind::Asan, CrashSeverity::NotExploitable, "x", "");
    assert!(security_severity(&exploitable) > security_severity(&not));
    assert!((security_severity(&exploitable) - 9.0).abs() < 0.001);
}

#[test]
fn sarif_document_is_well_formed() {
    let crashes = vec![
        crash(CrashKind::Asan, CrashSeverity::Exploitable, "heap-buffer-overflow(write)", "src/parse.c:42:5"),
        crash(CrashKind::Segv, CrashSeverity::Undefined, "SEGV", ""),
    ];
    let doc = crashes_to_sarif(&crashes, "9.9.9");

    assert_eq!(doc["version"], "2.1.0");
    assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "hobot_fuzz");
    assert_eq!(doc["runs"][0]["tool"]["driver"]["version"], "9.9.9");
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    // First result anchors to the CASR crash line.
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/parse.c"
    );
    assert_eq!(results[0]["locations"][0]["physicalLocation"]["region"]["startLine"], 42);
    assert_eq!(results[0]["ruleId"], "CWE-787");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["properties"]["security-severity"], "9.0");
    // Rules are deduped per CWE (787 + 476 = 2 rules).
    assert_eq!(doc["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
}

#[test]
fn empty_crashes_yield_empty_results() {
    let doc = crashes_to_sarif(&[], "0.1.0");
    assert!(doc["runs"][0]["results"].as_array().unwrap().is_empty());
    assert_eq!(doc["version"], "2.1.0");
}
