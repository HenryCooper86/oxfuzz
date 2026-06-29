//! SARIF + CWE/CVSS export of triaged crashes.
//!
//! Emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//! so findings flow into `GitHub` code scanning, `DefectDojo`, and other
//! security dashboards. Each crash maps to a result with a CWE-tagged rule and a
//! `security-severity` score (the 0-10 value `GitHub` uses to rank findings),
//! derived from the crash kind and CASR's exploitability classification.

use hf_core::crash::{Crash, CrashKind, CrashSeverity};

/// A CWE classification for a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cwe {
    pub id: &'static str,
    pub name: &'static str,
}

/// Map a crash to its most specific CWE, preferring the CASR short description
/// (e.g. `heap-buffer-overflow(write)`) and falling back to the crash kind.
#[must_use]
pub fn cwe_for(crash: &Crash) -> Cwe {
    let short = crash
        .casr
        .as_ref()
        .map(|c| c.severity_short.to_ascii_lowercase())
        .unwrap_or_default();

    let cwe = |id, name| Cwe { id, name };

    if short.contains("use-after-free") {
        return cwe("CWE-416", "Use After Free");
    }
    if short.contains("double-free") {
        return cwe("CWE-415", "Double Free");
    }
    if short.contains("stack-buffer-overflow") || short.contains("stack-overflow") {
        return cwe("CWE-121", "Stack-based Buffer Overflow");
    }
    if short.contains("heap-buffer-overflow") || short.contains("global-buffer-overflow") {
        // Distinguish write (787) from read (125) when CASR says so.
        if short.contains("read") {
            return cwe("CWE-125", "Out-of-bounds Read");
        }
        return cwe("CWE-787", "Out-of-bounds Write");
    }
    if short.contains("out-of-bounds") || short.contains("buffer-overflow") {
        return cwe("CWE-787", "Out-of-bounds Write");
    }
    if short.contains("integer-overflow") || short.contains("signed integer overflow") {
        return cwe("CWE-190", "Integer Overflow or Wraparound");
    }
    if short.contains("memory-leak") || short.contains("leak") {
        return cwe("CWE-401", "Missing Release of Memory");
    }
    if short.contains("null") {
        return cwe("CWE-476", "NULL Pointer Dereference");
    }

    match crash.kind {
        CrashKind::Asan => cwe("CWE-787", "Out-of-bounds Write"),
        CrashKind::Ubsan => cwe("CWE-758", "Reliance on Undefined Behavior"),
        CrashKind::Segv => cwe("CWE-476", "NULL Pointer Dereference"),
        CrashKind::Abort => cwe("CWE-617", "Reachable Assertion"),
        CrashKind::Timeout => cwe("CWE-834", "Excessive Iteration"),
        CrashKind::Other => cwe("CWE-noinfo", "Uncategorized Crash"),
    }
}

/// The GitHub `security-severity` score (0.0-10.0) for a crash, from CASR
/// exploitability when available, else the crash kind.
#[must_use]
pub fn security_severity(crash: &Crash) -> f64 {
    if let Some(casr) = &crash.casr {
        match casr.severity {
            CrashSeverity::Exploitable => return 9.0,
            CrashSeverity::ProbablyExploitable => return 7.0,
            CrashSeverity::NotExploitable => return 3.5,
            CrashSeverity::Undefined => {}
        }
    }
    match crash.kind {
        CrashKind::Asan | CrashKind::Segv => 6.0,
        CrashKind::Ubsan | CrashKind::Other => 5.0,
        CrashKind::Abort => 4.0,
        CrashKind::Timeout => 3.0,
    }
}

/// SARIF result level from the security-severity score.
#[must_use]
fn sarif_level(score: f64) -> &'static str {
    if score >= 7.0 {
        "error"
    } else if score >= 4.0 {
        "warning"
    } else {
        "note"
    }
}

/// Parse a CASR crashline (`file:line:col` or `file:line`) into a (uri, line).
fn parse_location(crashline: &str) -> Option<(String, u32)> {
    if crashline.is_empty() {
        return None;
    }
    let mut parts = crashline.splitn(3, ':');
    let file = parts.next()?.trim();
    let line = parts.next().and_then(|l| l.trim().parse::<u32>().ok())?;
    if file.is_empty() {
        return None;
    }
    Some((file.to_owned(), line))
}

/// Render triaged crashes as a SARIF 2.1.0 document.
#[must_use]
pub fn crashes_to_sarif(crashes: &[Crash], tool_version: &str) -> serde_json::Value {
    use serde_json::json;

    // One rule per distinct CWE, with the security-severity of its findings.
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_ids: Vec<&str> = Vec::new();
    let mut results: Vec<serde_json::Value> = Vec::new();

    for crash in crashes {
        let cwe = cwe_for(crash);
        let score = security_severity(crash);
        if !rule_ids.contains(&cwe.id) {
            rule_ids.push(cwe.id);
            rules.push(json!({
                "id": cwe.id,
                "name": cwe.name,
                "shortDescription": { "text": cwe.name },
                "helpUri": format!("https://cwe.mitre.org/data/definitions/{}.html",
                    cwe.id.trim_start_matches("CWE-")),
                "properties": {
                    "tags": ["security", "fuzzing", cwe.id],
                    "security-severity": format!("{score:.1}"),
                },
            }));
        }

        let message = if crash.summary.is_empty() {
            format!("{:?} crash", crash.kind)
        } else {
            crash.summary.clone()
        };
        let mut result = json!({
            "ruleId": cwe.id,
            "level": sarif_level(score),
            "message": { "text": message },
            "partialFingerprints": { "crashSignature/v1": crash.stack_signature },
            "properties": {
                "security-severity": format!("{score:.1}"),
                "cwe": cwe.id,
                "crashKind": format!("{:?}", crash.kind),
                "exploitability": crash.casr.as_ref()
                    .map_or_else(|| "Undefined".to_owned(), |c| format!("{:?}", c.severity)),
            },
        });

        // Physical location from the CASR crash line when present; otherwise the
        // crash input file, so the result always anchors somewhere.
        let location = crash
            .casr
            .as_ref()
            .and_then(|c| parse_location(&c.crashline));
        let phys = if let Some((uri, line)) = location {
            json!({ "artifactLocation": { "uri": uri }, "region": { "startLine": line } })
        } else {
            json!({ "artifactLocation": { "uri": crash.input_path.to_string_lossy() } })
        };
        result["locations"] = json!([{ "physicalLocation": phys }]);
        results.push(result);
    }

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "hobot_fuzz",
                    "version": tool_version,
                    "informationUri": "https://github.com/hobot/hobot_fuzz",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    })
}
