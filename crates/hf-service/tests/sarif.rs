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
        origin: hf_core::crash::CrashOrigin::Unknown,
    }
}

#[test]
fn cwe_mapping_is_specific() {
    assert_eq!(
        cwe_for(&crash(
            CrashKind::Asan,
            CrashSeverity::Exploitable,
            "heap-buffer-overflow(write)",
            ""
        ))
        .id,
        "CWE-787"
    );
    assert_eq!(
        cwe_for(&crash(
            CrashKind::Asan,
            CrashSeverity::Undefined,
            "heap-buffer-overflow(read)",
            ""
        ))
        .id,
        "CWE-125"
    );
    assert_eq!(
        cwe_for(&crash(
            CrashKind::Asan,
            CrashSeverity::Exploitable,
            "heap-use-after-free",
            ""
        ))
        .id,
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
        crash(
            CrashKind::Asan,
            CrashSeverity::Exploitable,
            "heap-buffer-overflow(write)",
            "src/parse.c:42:5",
        ),
        crash(CrashKind::Segv, CrashSeverity::Undefined, "SEGV", ""),
    ];
    let doc = crashes_to_sarif(&crashes, "9.9.9", std::path::Path::new("/work"));

    assert_eq!(doc["version"], "2.1.0");
    assert_eq!(doc["runs"][0]["tool"]["driver"]["name"], "oxfuzz");
    assert_eq!(doc["runs"][0]["tool"]["driver"]["version"], "9.9.9");
    assert_eq!(
        doc["runs"][0]["tool"]["driver"]["informationUri"],
        "https://github.com/HenryCooper86/oxfuzz"
    );
    let results = doc["runs"][0]["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    // First result anchors to the CASR crash line (relative, passes through).
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "src/parse.c"
    );
    assert_eq!(
        results[0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        42
    );
    assert_eq!(results[0]["ruleId"], "CWE-787");
    assert_eq!(results[0]["level"], "error");
    assert_eq!(results[0]["properties"]["security-severity"], "9.0");
    // Second result falls back to the crash input path, made project-relative.
    assert_eq!(
        results[1]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "out/crash-1"
    );
    // Rules are deduped per CWE (787 + 476 = 2 rules).
    assert_eq!(
        doc["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn rule_security_severity_reflects_most_severe_finding_for_a_cwe() {
    // Two crashes with the SAME CWE (787) but different exploitability: the
    // less-severe one is processed first. GitHub reads the rule-level severity,
    // so it must reflect the MAX (9.0), not the first-seen (lower) score.
    let crashes = vec![
        crash(
            CrashKind::Asan,
            CrashSeverity::NotExploitable,
            "heap-buffer-overflow(write)",
            "",
        ),
        crash(
            CrashKind::Asan,
            CrashSeverity::Exploitable,
            "heap-buffer-overflow(write)",
            "",
        ),
    ];
    let doc = crashes_to_sarif(&crashes, "1.0.0", std::path::Path::new("/work"));
    let rules = doc["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .unwrap();
    assert_eq!(rules.len(), 1, "same CWE collapses to one rule");
    assert_eq!(rules[0]["id"], "CWE-787");
    assert_eq!(rules[0]["properties"]["security-severity"], "9.0");
}

#[test]
fn absolute_host_paths_outside_project_are_redacted() {
    // A CASR crashline with an absolute build path outside the project must not
    // leak into the SARIF uri.
    let crashes = vec![crash(
        CrashKind::Asan,
        CrashSeverity::Exploitable,
        "heap-buffer-overflow(write)",
        "/home/builder/secret/parse.c:10:1",
    )];
    let doc = crashes_to_sarif(&crashes, "1.0.0", std::path::Path::new("/work"));
    assert_eq!(
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "<redacted-host-path>"
    );
}

#[test]
fn sarif_uris_use_forward_slashes_for_native_input_paths() {
    // The input path is built with the host's native separator; the SARIF uri
    // must still come out `/`-separated (on Windows, `out\crash-1` is not a
    // valid artifactLocation.uri and would not anchor in code scanning).
    let project = tempfile::tempdir().unwrap();
    let mut nested = crash(CrashKind::Segv, CrashSeverity::Undefined, "SEGV", "");
    nested.input_path = project.path().join("out").join("crash-1");
    let doc = crashes_to_sarif(&[nested], "1.0.0", project.path());
    assert_eq!(
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "out/crash-1"
    );
}

#[test]
fn empty_crashes_yield_empty_results() {
    let doc = crashes_to_sarif(&[], "0.1.0", std::path::Path::new("/work"));
    assert!(doc["runs"][0]["results"].as_array().unwrap().is_empty());
    assert_eq!(doc["version"], "2.1.0");
}
