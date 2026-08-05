//! SARIF + CWE/CVSS export of triaged crashes.
//!
//! Emits [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
//! so findings flow into `GitHub` code scanning, `DefectDojo`, and other
//! security dashboards. Each crash maps to a result with a CWE-tagged rule and a
//! `security-severity` score (the 0-10 value `GitHub` uses to rank findings),
//! derived from the crash kind and CASR's exploitability classification.

use std::path::Path;

use hf_core::crash::{Crash, CrashKind, CrashSeverity};
use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::error::ClassifiedError;
use hf_guardrails::Guardrails;

use crate::container::ServiceContainer;

/// Input for the service-owned CI fuzzing gate.
#[derive(Debug, Clone)]
pub struct CiGateRequest<'a> {
    /// Project whose promoted harness is executed.
    pub project: &'a Path,
    /// Promoted target symbol.
    pub target: &'a str,
    /// Fuzzing engine selected for this gate.
    pub engine: EngineKind,
    /// Bounded fuzz duration in seconds.
    pub duration_secs: u64,
}

/// Presentation-safe crash summary emitted by a CI gate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CiGateFinding {
    /// Crash category rendered without exposing domain-crate types.
    pub kind: String,
    /// Human-readable triage summary.
    pub summary: String,
}

/// Complete CI-gate result. SARIF is returned even when no crash is present so
/// scanners can clear stale alerts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CiGateOutcome {
    /// Triaged findings that decide the gate.
    pub findings: Vec<CiGateFinding>,
    /// Serialized SARIF 2.1.0 document.
    pub sarif: String,
    /// Non-fatal seed-generation warning, if seed enrichment failed.
    pub seed_warning: Option<String>,
}

impl CiGateOutcome {
    /// Whether the gate found no crashing inputs.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }
}

impl ServiceContainer {
    /// Run the non-interactive CI fuzzing gate under an operation-local
    /// permissive guardrail policy.
    ///
    /// The normal promoted-harness and sandbox requirements remain enforced by
    /// [`ServiceContainer::run_fuzzer`]. Only interactive approval is waived;
    /// no process-global environment is changed.
    ///
    /// # Errors
    /// Returns a classified service error if the fuzz run, triage, or SARIF
    /// export fails.
    pub async fn run_ci_gate(
        &self,
        request: CiGateRequest<'_>,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<CiGateOutcome, ClassifiedError> {
        let ci = self.clone().with_guardrails(Guardrails::permissive());
        let seed_warning = ci
            .generate_seeds(request.project, request.target)
            .await
            .err()
            .map(|error| error.to_string());

        ci.run_fuzzer(
            request.project,
            request.target,
            request.engine,
            request.duration_secs,
            on_progress,
        )
        .await?;
        let crashes = ci.triage(request.project, request.target).await?;
        let sarif = ci.export_sarif(request.project, request.target).await?;
        let findings = crashes
            .into_iter()
            .map(|crash| CiGateFinding {
                kind: format!("{:?}", crash.kind),
                summary: crash.summary,
            })
            .collect();
        Ok(CiGateOutcome {
            findings,
            sarif,
            seed_warning,
        })
    }
}

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
        CrashKind::Panic => cwe("CWE-248", "Uncaught Exception"),
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
        CrashKind::Ubsan | CrashKind::Other | CrashKind::Panic => 5.0,
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
pub(crate) fn parse_location(crashline: &str) -> Option<(String, u32)> {
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

/// Map an absolute host path to a SARIF `artifactLocation.uri`.
///
/// GitHub code scanning anchors alerts using repo-relative URIs, and an absolute
/// build path (e.g. `/home/builder/src/parse.c`) both fails to anchor and leaks
/// the operator's host layout into a shared dashboard. So a path under
/// `project_root` is made project-relative, and any other absolute path is
/// redacted. Relative paths (already repo-relative) keep their components.
/// Every emitted uri is `/`-separated: a Windows-host `out\crash-1` is not a
/// valid SARIF uri and would not anchor.
fn sarif_uri(raw: &str, project_root: &std::path::Path) -> String {
    let path = std::path::Path::new(raw);
    // Crash input paths and CASR crashlines originate in the Linux sandbox,
    // so absoluteness is judged by POSIX rules on every host first: std::path
    // alone would answer for the host and let `/home/builder/...` through the
    // relative branch on Windows. Host-absolute paths still count as absolute.
    if !raw.starts_with('/') && !path.is_absolute() {
        return hf_core::runtime::posix_relative(path);
    }
    match path.strip_prefix(project_root) {
        Ok(relative) => hf_core::runtime::posix_relative(relative),
        Err(_) => "<redacted-host-path>".to_owned(),
    }
}

/// Render triaged crashes as a SARIF 2.1.0 document.
///
/// `project_root` is used to make absolute source/crash paths repo-relative (and
/// to redact absolute paths outside the project) so the export anchors in GitHub
/// code scanning without disclosing host build paths.
#[must_use]
pub fn crashes_to_sarif(
    crashes: &[Crash],
    tool_version: &str,
    project_root: &std::path::Path,
) -> serde_json::Value {
    use serde_json::json;

    // Rule-level `security-severity` must reflect the MOST severe finding for a
    // CWE, not whichever crash was processed first: GitHub code scanning (and
    // most SARIF dashboards) read the numeric severity from the rule, so an
    // Exploitable crash sharing a CWE with an earlier NotExploitable one would
    // otherwise be surfaced at the lower score. Compute the max per CWE up front.
    let mut max_score: std::collections::BTreeMap<&str, f64> = std::collections::BTreeMap::new();
    for crash in crashes {
        let score = security_severity(crash);
        max_score
            .entry(cwe_for(crash).id)
            .and_modify(|current| *current = current.max(score))
            .or_insert(score);
    }

    // One rule per distinct CWE, carrying the max security-severity of its findings.
    let mut rules: Vec<serde_json::Value> = Vec::new();
    let mut rule_ids: Vec<&str> = Vec::new();
    let mut results: Vec<serde_json::Value> = Vec::new();

    for crash in crashes {
        let cwe = cwe_for(crash);
        let score = security_severity(crash);
        if !rule_ids.contains(&cwe.id) {
            rule_ids.push(cwe.id);
            let rule_score = max_score.get(cwe.id).copied().unwrap_or(score);
            let mut rule = json!({
                "id": cwe.id,
                "name": cwe.name,
                "shortDescription": { "text": cwe.name },
                "properties": {
                    "tags": ["security", "fuzzing", cwe.id],
                    "security-severity": format!("{rule_score:.1}"),
                },
            });
            // `CWE-noinfo` is a sentinel, not a real CWE entry: pointing helpUri
            // at cwe.mitre.org/.../noinfo.html would 404, so omit it there.
            if cwe.id != "CWE-noinfo" {
                rule["helpUri"] = json!(format!(
                    "https://cwe.mitre.org/data/definitions/{}.html",
                    cwe.id.trim_start_matches("CWE-")
                ));
            }
            rules.push(rule);
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
            json!({
                "artifactLocation": { "uri": sarif_uri(&uri, project_root) },
                "region": { "startLine": line }
            })
        } else {
            json!({
                "artifactLocation": {
                    "uri": sarif_uri(&crash.input_path.to_string_lossy(), project_root)
                }
            })
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
                    "name": "oxfuzz",
                    "version": tool_version,
                    "informationUri": "https://github.com/HenryCooper86/-oxfuzz",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    })
}
