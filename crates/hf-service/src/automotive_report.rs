//! Deterministic automotive campaign reporting and grounded AI composition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use hf_storage::AutomotiveOperationStatus;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::automotive::{AutomotiveStateCorpusEntry, StateSignature};
use crate::config::AutomotiveSettings;

/// Shareable safety-policy snapshot used by an automotive campaign report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomotiveReportSafetyPosture {
    /// Current runtime policy state.
    pub runtime_policy: AutomotivePolicyPosture,
    /// Protocol identifiers admitted by the current policy.
    pub allowed_protocols: Vec<String>,
    /// Mode identifiers admitted by the current policy.
    pub allowed_modes: Vec<String>,
    /// Number of allowlisted virtual interfaces, without exposing host names.
    pub virtual_interface_count: usize,
    /// Current exceptional physical-bench posture.
    pub physical_bench: AutomotivePhysicalBenchPosture,
    /// Number of allowlisted physical interfaces, without exposing host names.
    pub physical_interface_count: usize,
    /// Current dangerous-diagnostic-service posture.
    pub dangerous_services: AutomotiveDangerousServicesPosture,
    /// Maximum decoded or replayed events per operation.
    pub max_packets: u32,
    /// Maximum wall-clock duration per operation.
    pub max_duration_secs: u64,
    /// Maximum transmitted events per second.
    pub max_rate_per_second: u32,
}

/// Enabled/disabled posture for the optional runtime policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomotivePolicyPosture {
    /// Runtime operations are disabled.
    Disabled,
    /// Runtime operations may proceed through normal preflight.
    Enabled,
}

/// Physical-bench posture, including its mandatory approval invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomotivePhysicalBenchPosture {
    /// Physical-bench requests are disabled.
    Disabled,
    /// Requests are enabled but still require exact, fresh human approval.
    EnabledApprovalRequired,
    /// Invalid policy state retained only for honest reporting.
    EnabledApprovalMissing,
}

/// Exceptional dangerous-diagnostic-service posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutomotiveDangerousServicesPosture {
    /// Dangerous services remain denied.
    Denied,
    /// The exceptional policy allows separately approved requests.
    ExceptionallyAllowed,
}

impl AutomotiveReportSafetyPosture {
    /// Build a redacted report snapshot from the effective automotive policy.
    #[must_use]
    pub fn from_settings(settings: &AutomotiveSettings) -> Self {
        Self {
            runtime_policy: if settings.enabled {
                AutomotivePolicyPosture::Enabled
            } else {
                AutomotivePolicyPosture::Disabled
            },
            allowed_protocols: settings.allowed_protocols.clone(),
            allowed_modes: settings.allowed_modes.clone(),
            virtual_interface_count: settings.virtual_interfaces.len(),
            physical_bench: if !settings.physical_bench.enabled {
                AutomotivePhysicalBenchPosture::Disabled
            } else if settings.physical_bench.require_approval {
                AutomotivePhysicalBenchPosture::EnabledApprovalRequired
            } else {
                AutomotivePhysicalBenchPosture::EnabledApprovalMissing
            },
            physical_interface_count: settings.physical_bench.interfaces.len(),
            dangerous_services: if settings.physical_bench.allow_dangerous_services {
                AutomotiveDangerousServicesPosture::ExceptionallyAllowed
            } else {
                AutomotiveDangerousServicesPosture::Denied
            },
            max_packets: settings.limits.max_packets,
            max_duration_secs: settings.limits.max_duration_secs,
            max_rate_per_second: settings.limits.max_rate_per_second,
        }
    }
}

/// One durable automotive operation projected into a shareable report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomotiveReportOperation {
    /// Service-owned evidence identifier.
    pub id: Uuid,
    /// Stable operation name.
    pub operation: String,
    /// Stable execution mode.
    pub mode: String,
    /// Selected protocol, when applicable.
    pub protocol: Option<String>,
    /// Durable lifecycle status.
    pub status: AutomotiveOperationStatus,
    /// Admission timestamp.
    pub started_at: DateTime<Utc>,
    /// Terminal timestamp, when available.
    pub ended_at: Option<DateTime<Utc>>,
    /// Digest of the exact retained request envelope.
    pub request_sha256: String,
    /// Digest of the validated sidecar transcript, when available.
    pub transcript_sha256: Option<String>,
    /// Workspace-relative evidence directory.
    pub artifact_dir: String,
    /// Redacted terminal failure, when present.
    pub error: Option<String>,
    /// Validated protocol-state observations.
    pub state_signatures: Vec<StateSignature>,
    /// Bounded, shareable summary derived from the validated typed result.
    pub result_summary: Option<String>,
    /// Whether the typed result completed its intended work, when applicable.
    pub result_complete: Option<bool>,
}

/// Complete owned snapshot consumed by the pure automotive report renderer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutomotiveReportData {
    /// RFC3339 report-generation timestamp.
    pub generated_at: String,
    /// Shareable project display name, never a canonical host path.
    pub project_name: String,
    /// `hobot_fuzz` version that generated the report.
    pub tool_version: String,
    /// Effective, redacted safety posture.
    pub safety: AutomotiveReportSafetyPosture,
    /// Bounded retained operation snapshot.
    pub operations: Vec<AutomotiveReportOperation>,
    /// Bounded promoted protocol-state evidence snapshot.
    pub state_corpus: Vec<AutomotiveStateCorpusEntry>,
}

/// Result of the optional provider-assisted report stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomotiveReportAiStatus {
    /// The caller requested the deterministic report only.
    NotRequested,
    /// AI was requested, but no provider is configured.
    NotConfigured,
    /// AI was requested, but no retained evidence exists to interpret.
    NotApplicable,
    /// A grounded, citation-validated interpretation was appended.
    Applied,
    /// Provider generation or citation validation failed; facts were retained.
    Fallback,
}

/// Compact metrics returned alongside the composed Markdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutomotiveReportMetrics {
    /// Number of retained operations in the bounded snapshot.
    pub operation_count: usize,
    /// Number of retained terminal failures.
    pub failed_operation_count: usize,
    /// Number of unique protocol and state-digest pairs.
    pub unique_state_count: usize,
    /// Number of promoted protocol-state artifacts.
    pub promoted_state_count: usize,
}

impl AutomotiveReportData {
    /// Compute stable summary metrics for transport and UI status.
    #[must_use]
    pub fn metrics(&self) -> AutomotiveReportMetrics {
        AutomotiveReportMetrics {
            operation_count: self.operations.len(),
            failed_operation_count: self
                .operations
                .iter()
                .filter(|operation| operation.status == AutomotiveOperationStatus::Failed)
                .count(),
            unique_state_count: unique_state_digests(self).len(),
            promoted_state_count: self.state_corpus.len(),
        }
    }
}

/// Presentation-neutral result shared by REST, CLI, Tauri, and the GUI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomotiveCampaignReport {
    /// RFC3339 generation timestamp.
    pub generated_at: String,
    /// Shareable project display name.
    pub project_name: String,
    /// Outcome of the optional AI interpretation stage.
    pub ai_status: AutomotiveReportAiStatus,
    /// Provider-reported model when an interpretation was accepted.
    pub ai_model: Option<String>,
    /// Number of retained operations in the report window.
    pub operation_count: usize,
    /// Number of terminal operation failures.
    pub failed_operation_count: usize,
    /// Number of unique validated protocol states.
    pub unique_state_count: usize,
    /// Number of promoted protocol-state artifacts.
    pub promoted_state_count: usize,
    /// Complete deterministic report plus optional advisory interpretation.
    pub markdown: String,
}

/// Render an auditable, deterministic automotive campaign report.
#[must_use]
pub fn render_automotive_report(data: &AutomotiveReportData) -> String {
    let mut report = String::with_capacity(8192);
    let counts = operation_status_counts(&data.operations);
    let unique_states = unique_state_digests(data);
    let protocols = observed_protocols(data);

    let _ = writeln!(
        report,
        "# Automotive Fuzzing Campaign Report: `{}`\n",
        escape_inline(&data.project_name)
    );
    let _ = writeln!(report, "| | |");
    let _ = writeln!(report, "|---|---|");
    let _ = writeln!(
        report,
        "| Project | `{}` |",
        escape_inline(&data.project_name)
    );
    let _ = writeln!(report, "| Generated | {} |", data.generated_at);
    let _ = writeln!(report, "| Tool | hobot_fuzz {} |", data.tool_version);
    let _ = writeln!(
        report,
        "| Evidence window | {} retained operation(s) |\n",
        data.operations.len()
    );

    let _ = writeln!(report, "## Executive Summary\n");
    let _ = writeln!(
        report,
        "This report synthesizes **{} retained automotive operation(s)**: **{} completed**, \
         **{} partial**, **{} failed**, **{} running**, and **{} cancelled**. The bounded \
         snapshot contains **{} unique protocol-state digest(s)** and **{} promoted \
         state-corpus artifact(s)** across **{} observed protocol(s)**.\n",
        data.operations.len(),
        counts.done,
        counts.partial,
        counts.failed,
        counts.running,
        counts.cancelled,
        unique_states.len(),
        data.state_corpus.len(),
        protocols.len(),
    );
    if counts.failed > 0 {
        let _ = writeln!(
            report,
            "Retained failures are reported as operational evidence and should be resolved before \
             the corresponding workflow stage is repeated."
        );
    } else {
        let _ = writeln!(
            report,
            "No terminal operation failure is present in this retained evidence window."
        );
    }
    let _ = writeln!(
        report,
        "\nProtocol-state novelty is **not source coverage** and does not by itself prove a vulnerability."
    );

    render_safety_posture(&mut report, &data.safety);
    render_workflow(&mut report, &data.operations);
    render_state_exploration(&mut report, data, &unique_states);
    render_findings(&mut report, data, counts.failed);
    render_evidence_manifest(&mut report, data);
    render_limitations(&mut report);
    render_recommendations(&mut report, data);

    let _ = writeln!(report, "---\n");
    let _ = writeln!(
        report,
        "_Deterministic evidence report generated by hobot_fuzz {} on {}._",
        data.tool_version, data.generated_at
    );
    report
}

fn render_safety_posture(report: &mut String, safety: &AutomotiveReportSafetyPosture) {
    let _ = writeln!(report, "\n## Scope and Safety Posture\n");
    let _ = writeln!(report, "| Control | Effective posture |");
    let _ = writeln!(report, "|---|---|");
    let _ = writeln!(
        report,
        "| Runtime automotive policy | {} |",
        match safety.runtime_policy {
            AutomotivePolicyPosture::Disabled => "disabled",
            AutomotivePolicyPosture::Enabled => "enabled",
        }
    );
    let _ = writeln!(
        report,
        "| Allowed protocols | {} |",
        joined_or_none(&safety.allowed_protocols)
    );
    let _ = writeln!(
        report,
        "| Allowed modes | {} |",
        joined_or_none(&safety.allowed_modes)
    );
    let _ = writeln!(
        report,
        "| Virtual interfaces | {} allowlisted |",
        safety.virtual_interface_count
    );
    let _ = writeln!(
        report,
        "| Physical bench | {}; {} allowlisted interface(s) |",
        match safety.physical_bench {
            AutomotivePhysicalBenchPosture::Disabled => "disabled",
            AutomotivePhysicalBenchPosture::EnabledApprovalRequired => {
                "enabled; fresh approval required"
            }
            AutomotivePhysicalBenchPosture::EnabledApprovalMissing => {
                "invalid: enabled without required approval"
            }
        },
        safety.physical_interface_count,
    );
    let _ = writeln!(
        report,
        "| Dangerous diagnostic services | {} |",
        match safety.dangerous_services {
            AutomotiveDangerousServicesPosture::Denied => "denied",
            AutomotiveDangerousServicesPosture::ExceptionallyAllowed => {
                "exceptionally allowed by policy"
            }
        }
    );
    let _ = writeln!(
        report,
        "| Per-operation bounds | {} events; {} seconds; {} transmitted events/second |",
        safety.max_packets, safety.max_duration_secs, safety.max_rate_per_second
    );
    let _ = writeln!(
        report,
        "\nAll captured, mutation, planning, and replay evidence remains subject to service validation, \
         sandbox isolation, typed limits, guardrails, and the human-approval boundary."
    );
}

fn render_workflow(report: &mut String, operations: &[AutomotiveReportOperation]) {
    let stages = [
        ("Adapter capability inspection", "capabilities", None),
        ("Immutable capture analysis", "analyze_capture", None),
        (
            "Deterministic mutation generation",
            "generate_mutations",
            None,
        ),
        ("Typed replay-plan construction", "build_replay_plan", None),
        (
            "Supervised virtual replay",
            "execute_replay",
            Some("virtual_can"),
        ),
    ];
    let _ = writeln!(report, "\n## Campaign Workflow\n");
    let _ = writeln!(report, "| Stage | Status | Completed | Failed |");
    let _ = writeln!(report, "|---|---|---:|---:|");
    for (label, operation, mode) in stages {
        let matching = operations.iter().filter(|entry| {
            entry.operation == operation && mode.is_none_or(|expected| entry.mode == expected)
        });
        let mut completed = 0_usize;
        let mut failed = 0_usize;
        for entry in matching {
            match entry.status {
                AutomotiveOperationStatus::Done if entry.result_complete != Some(false) => {
                    completed += 1;
                }
                AutomotiveOperationStatus::Done => failed += 1,
                AutomotiveOperationStatus::Failed | AutomotiveOperationStatus::Cancelled => {
                    failed += 1;
                }
                AutomotiveOperationStatus::Running => {}
            }
        }
        let status = if completed > 0 {
            "Complete"
        } else if failed > 0 {
            "Attention"
        } else {
            "Not recorded"
        };
        let _ = writeln!(report, "| {label} | {status} | {completed} | {failed} |");
    }
    let _ = writeln!(
        report,
        "\nPhysical-bench validation is intentionally excluded from campaign-completeness scoring. \
         It remains a separately approved activity after the exact plan and budgets are known."
    );
}

fn render_state_exploration(
    report: &mut String,
    data: &AutomotiveReportData,
    unique_states: &BTreeSet<(String, String)>,
) {
    let mut per_protocol = BTreeMap::<String, (usize, usize)>::new();
    for (protocol, _) in unique_states {
        per_protocol.entry(protocol.clone()).or_default().0 += 1;
    }
    for entry in &data.state_corpus {
        per_protocol
            .entry(protocol_name(entry.protocol))
            .or_default()
            .1 += 1;
    }

    let _ = writeln!(report, "\n## Protocol-State Exploration\n");
    if per_protocol.is_empty() {
        let _ = writeln!(
            report,
            "No validated protocol-state signature is present in the retained evidence window."
        );
        return;
    }
    let _ = writeln!(report, "| Protocol | Unique states | Promoted artifacts |");
    let _ = writeln!(report, "|---|---:|---:|");
    for (protocol, (states, promoted)) in per_protocol {
        let _ = writeln!(report, "| `{protocol}` | {states} | {promoted} |");
    }
    let _ = writeln!(report, "\n### State Evidence\n");
    for (protocol, digest) in unique_states {
        let sources = data
            .operations
            .iter()
            .filter(|operation| {
                operation.state_signatures.iter().any(|signature| {
                    protocol_name(signature.protocol) == *protocol
                        && signature.digest.as_str() == digest
                })
            })
            .map(|operation| format!("[OP:{}]", operation.id))
            .collect::<Vec<_>>();
        let _ = writeln!(
            report,
            "- `[STATE:{digest}]` (`{protocol}`), observed by {}.",
            sources.join(", ")
        );
    }
    for entry in &data.state_corpus {
        let _ = writeln!(
            report,
            "- Promoted `[STATE:{}]` from [OP:{}], artifact digest `{}` at `{}`.",
            entry.state_digest,
            entry.source_operation_id,
            entry.artifact_sha256,
            escape_inline(&entry.artifact_path)
        );
    }
}

fn render_findings(report: &mut String, data: &AutomotiveReportData, failed: usize) {
    let _ = writeln!(report, "\n## Findings\n");
    if failed == 0 {
        let _ = writeln!(
            report,
            "No retained terminal operation failure requires triage in this evidence window."
        );
    } else {
        for operation in data
            .operations
            .iter()
            .filter(|operation| operation.status == AutomotiveOperationStatus::Failed)
        {
            let _ = writeln!(
                report,
                "### Operational failure: `{}`\n\n- Evidence: [OP:{}]\n- Mode: `{}`\n- Protocol: `{}`\n- Retained error: {}\n",
                operation.operation,
                operation.id,
                operation.mode,
                operation.protocol.as_deref().unwrap_or("not selected"),
                shareable_error(operation.error.as_deref().unwrap_or("no error detail retained")),
            );
        }
    }
    for operation in data.operations.iter().filter(|operation| {
        operation.status == AutomotiveOperationStatus::Done
            && operation.result_complete == Some(false)
    }) {
        let _ = writeln!(
            report,
            "### Partial result: `{}`\n\n- Evidence: [OP:{}]\n- Result: {}\n- Required action: review the retained transcript and limits before retrying.\n",
            operation.operation,
            operation.id,
            operation
                .result_summary
                .as_deref()
                .unwrap_or("typed operation did not complete"),
        );
    }
    let _ = writeln!(
        report,
        "### Interpretation Boundary\n\nObserved states, successful decoding, and completed replay steps are campaign \
         evidence. They do not by themselves prove exploitability, security impact, or unsafe vehicle behavior."
    );
}

fn render_evidence_manifest(report: &mut String, data: &AutomotiveReportData) {
    let _ = writeln!(report, "\n## Evidence Manifest\n");
    if data.operations.is_empty() {
        let _ = writeln!(
            report,
            "No automotive operation evidence is retained for this project."
        );
        return;
    }
    let _ = writeln!(
        report,
        "| Operation evidence | Stage | Mode / protocol | Status | Validated result | Request digest | Transcript evidence | Artifact directory |"
    );
    let _ = writeln!(report, "|---|---|---|---|---|---|---|---|");
    let mut operations = data.operations.iter().collect::<Vec<_>>();
    operations.sort_by_key(|operation| (operation.started_at, operation.id));
    for operation in operations {
        let transcript = operation.transcript_sha256.as_ref().map_or_else(
            || "not retained".to_owned(),
            |digest| format!("[TRANSCRIPT:{digest}]"),
        );
        let _ = writeln!(
            report,
            "| [OP:{}] | `{}` | `{}` / `{}` | {} | {} | `{}` | {} | `{}` |",
            operation.id,
            operation.operation,
            operation.mode,
            operation.protocol.as_deref().unwrap_or("n/a"),
            status_name(operation.status),
            escape_inline(
                operation
                    .result_summary
                    .as_deref()
                    .unwrap_or("not retained")
            ),
            operation.request_sha256,
            transcript,
            escape_inline(&operation.artifact_dir),
        );
    }
}

fn render_limitations(report: &mut String) {
    let _ = writeln!(report, "\n## Limitations\n");
    let _ = writeln!(
        report,
        "- The report covers only the bounded retained evidence snapshot and cannot infer events that were not persisted.\n\
         - Protocol-state digests are not source-code line, function, region, or edge coverage.\n\
         - A completed operation confirms contract-valid execution, not absence of security defects.\n\
         - Offline and virtual evidence does not validate a physical ECU, vehicle network, timing behavior, or bench wiring.\n\
         - AI-assisted interpretation, when appended, is advisory and cannot authorize execution or establish a finding."
    );
}

fn render_recommendations(report: &mut String, data: &AutomotiveReportData) {
    let _ = writeln!(report, "\n## Recommendations\n");
    let failed = data
        .operations
        .iter()
        .filter(|operation| operation.status == AutomotiveOperationStatus::Failed)
        .count();
    if failed > 0 {
        let _ = writeln!(
            report,
            "1. Triage the {failed} retained operational failure(s) by operation id before repeating those stages."
        );
    } else {
        let _ = writeln!(
            report,
            "1. Preserve the current operation evidence and compare future campaign snapshots for regressions."
        );
    }
    let stages = [
        ("capabilities", "inspect the pinned adapter capabilities"),
        (
            "analyze_capture",
            "analyze an immutable representative capture",
        ),
        (
            "generate_mutations",
            "generate a deterministic, reviewable mutation set",
        ),
        (
            "build_replay_plan",
            "build and review a typed replay plan without contacting an interface",
        ),
    ];
    let mut number = 2;
    for (operation, recommendation) in stages {
        if !data.operations.iter().any(|entry| {
            entry.operation == operation && entry.status == AutomotiveOperationStatus::Done
        }) {
            let _ = writeln!(report, "{number}. Next, {recommendation}.");
            number += 1;
        }
    }
    let unpromoted = unique_state_digests(data)
        .iter()
        .filter(|(protocol, digest)| {
            !data.state_corpus.iter().any(|entry| {
                protocol_name(entry.protocol) == *protocol && entry.state_digest == *digest
            })
        })
        .count();
    if unpromoted > 0 {
        let _ = writeln!(
            report,
            "{number}. Review and promote suitable artifacts for the {unpromoted} observed state(s) without retained corpus evidence."
        );
        number += 1;
    }
    if !data.operations.iter().any(|entry| {
        entry.operation == "execute_replay"
            && entry.mode == "virtual_can"
            && entry.status == AutomotiveOperationStatus::Done
    }) {
        let _ = writeln!(
            report,
            "{number}. If policy and runtime readiness permit, conduct a separately confirmed supervised virtual-CAN replay."
        );
    }
}

/// System prompt for provider-neutral automotive evidence interpretation.
#[must_use]
pub fn automotive_report_system_prompt() -> &'static str {
    "You are a senior automotive security engineer interpreting a deterministic campaign fact sheet. \
     You NEVER invent operations, protocol states, digests, vulnerabilities, vehicle effects, or test \
     results. State novelty is not source coverage and is not proof of a vulnerability. Your output is \
     advisory: it cannot authorize traffic, change a replay plan, relax policy, or replace retained evidence."
}

/// Build the grounded provider prompt for an automotive report interpretation.
#[must_use]
pub fn automotive_report_user_prompt(facts: &str, data: &AutomotiveReportData) -> String {
    format!(
        "Interpret the automotive campaign fact sheet below for a professional engineering and security \
         audience. Use only its retained facts. Cite claims with the exact evidence forms `[OP:<uuid>]`, \
         `[STATE:<sha256>]`, and `[TRANSCRIPT:<sha256>]` already present in the sheet. Do not create a \
         citation, path, number, protocol, vehicle effect, vulnerability, or result. Clearly label inference \
         as a hypothesis and absence as missing evidence. Recommendations may cover additional offline \
         analysis, deterministic mutation, plan review, or supervised virtual validation, but cannot authorize \
         execution or physical traffic. Do not emit code, shell commands, replay payloads, or a top-level title.\n\n\
         Return exactly these Markdown headings:\n\
         ### Evidence-backed interpretation\n\
         ### Hypotheses\n\
         ### Missing evidence\n\
         ### Recommended next actions\n\n\
         Project: `{}`\n\n---\n# DETERMINISTIC FACT SHEET (ground truth)\n\n{}",
        escape_inline(&data.project_name),
        facts
    )
}

/// Validate the evidence citations and bounded structure of provider output.
///
/// # Errors
/// Returns a human-readable validation error for malformed, uncited, or
/// ungrounded provider output.
pub fn validate_ai_interpretation(
    interpretation: &str,
    data: &AutomotiveReportData,
) -> Result<(), String> {
    let trimmed = interpretation.trim();
    if trimmed.is_empty() {
        return Err("AI interpretation is empty".to_owned());
    }
    if trimmed.len() > 24_000 {
        return Err("AI interpretation exceeds the 24000-byte limit".to_owned());
    }
    if trimmed.contains("```") {
        return Err("AI interpretation must not contain executable code or data fences".to_owned());
    }
    for heading in [
        "### Evidence-backed interpretation",
        "### Hypotheses",
        "### Missing evidence",
        "### Recommended next actions",
    ] {
        if !trimmed.contains(heading) {
            return Err(format!("AI interpretation is missing heading '{heading}'"));
        }
    }

    let known_operations = data
        .operations
        .iter()
        .map(|operation| operation.id.to_string())
        .collect::<BTreeSet<_>>();
    let known_states = unique_state_digests(data)
        .into_iter()
        .map(|(_, digest)| digest)
        .collect::<BTreeSet<_>>();
    let known_transcripts = data
        .operations
        .iter()
        .filter_map(|operation| operation.transcript_sha256.clone())
        .collect::<BTreeSet<_>>();

    let operation_citations = citations(trimmed, "[OP:")?;
    let state_citations = citations(trimmed, "[STATE:")?;
    let transcript_citations = citations(trimmed, "[TRANSCRIPT:")?;
    for citation in &operation_citations {
        if !known_operations.contains(citation) {
            return Err(format!(
                "AI interpretation cites unknown operation {citation}"
            ));
        }
    }
    for citation in &state_citations {
        if !known_states.contains(citation) {
            return Err(format!("AI interpretation cites unknown state {citation}"));
        }
    }
    for citation in &transcript_citations {
        if !known_transcripts.contains(citation) {
            return Err(format!(
                "AI interpretation cites unknown transcript {citation}"
            ));
        }
    }
    if !data.operations.is_empty()
        && operation_citations.is_empty()
        && state_citations.is_empty()
        && transcript_citations.is_empty()
    {
        return Err(
            "AI interpretation requires at least one retained evidence citation".to_owned(),
        );
    }
    Ok(())
}

/// Append validated AI prose after the complete deterministic fact sheet.
#[must_use]
pub fn append_ai_interpretation(facts: &str, interpretation: &str, model: &str) -> String {
    format!(
        "{}\n\n## AI-Assisted Interpretation\n\n> This provider-generated interpretation is advisory. \
         Retained evidence and service validation remain authoritative. Model: `{}`.\n\n{}\n",
        facts.trim_end(),
        escape_inline(model),
        interpretation.trim()
    )
}

#[derive(Debug, Clone, Copy, Default)]
struct StatusCounts {
    running: usize,
    done: usize,
    partial: usize,
    failed: usize,
    cancelled: usize,
}

fn operation_status_counts(operations: &[AutomotiveReportOperation]) -> StatusCounts {
    let mut counts = StatusCounts::default();
    for operation in operations {
        match operation.status {
            AutomotiveOperationStatus::Running => counts.running += 1,
            // A `Done` operation that did not produce a complete result is
            // counted as `partial`, not `done`, so the Executive Summary agrees
            // with the Campaign Workflow table (which treats it as "Attention")
            // and the Findings section (which lists it as "Partial result").
            AutomotiveOperationStatus::Done if operation.result_complete == Some(false) => {
                counts.partial += 1;
            }
            AutomotiveOperationStatus::Done => counts.done += 1,
            AutomotiveOperationStatus::Failed => counts.failed += 1,
            AutomotiveOperationStatus::Cancelled => counts.cancelled += 1,
        }
    }
    counts
}

fn unique_state_digests(data: &AutomotiveReportData) -> BTreeSet<(String, String)> {
    let mut states = BTreeSet::new();
    for operation in &data.operations {
        for state in &operation.state_signatures {
            states.insert((
                protocol_name(state.protocol),
                state.digest.as_str().to_owned(),
            ));
        }
    }
    for entry in &data.state_corpus {
        states.insert((protocol_name(entry.protocol), entry.state_digest.clone()));
    }
    states
}

fn observed_protocols(data: &AutomotiveReportData) -> BTreeSet<String> {
    let mut protocols = data
        .operations
        .iter()
        .filter_map(|operation| operation.protocol.clone())
        .collect::<BTreeSet<_>>();
    protocols.extend(
        data.state_corpus
            .iter()
            .map(|entry| protocol_name(entry.protocol)),
    );
    protocols
}

fn citations(text: &str, prefix: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut remainder = text;
    while let Some(index) = remainder.find(prefix) {
        let after_prefix = &remainder[index + prefix.len()..];
        let end = after_prefix.find(']').ok_or_else(|| {
            format!("AI interpretation contains an unterminated {prefix} citation")
        })?;
        let value = &after_prefix[..end];
        if value.is_empty()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(format!(
                "AI interpretation contains an invalid {prefix} citation"
            ));
        }
        values.push(value.to_owned());
        remainder = &after_prefix[end + 1..];
    }
    Ok(values)
}

fn protocol_name(protocol: crate::automotive::AutomotiveProtocol) -> String {
    serde_json::to_value(protocol)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned())
}

fn joined_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        values
            .iter()
            .map(|value| format!("`{}`", escape_inline(value)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn status_name(status: AutomotiveOperationStatus) -> &'static str {
    match status {
        AutomotiveOperationStatus::Running => "running",
        AutomotiveOperationStatus::Done => "done",
        AutomotiveOperationStatus::Failed => "failed",
        AutomotiveOperationStatus::Cancelled => "cancelled",
    }
}

fn escape_inline(value: &str) -> String {
    value
        .replace(['\n', '\r'], " ")
        .replace('`', "'")
        .replace('|', "\\|")
}

fn shareable_error(value: &str) -> String {
    value
        .split_whitespace()
        .map(|token| {
            if contains_host_path(token) {
                "[redacted-path]"
            } else {
                token
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_host_path(token: &str) -> bool {
    let trimmed = token.trim_matches(['(', ')', '[', ']', '{', '}', ',', ';', '\'', '"']);
    let bytes = trimmed.as_bytes();

    for (index, byte) in bytes.iter().enumerate() {
        let begins_component = index == 0
            || matches!(
                bytes[index - 1],
                b'=' | b':' | b'"' | b'\'' | b'(' | b'[' | b'{'
            );
        if begins_component && *byte == b'/' {
            return true;
        }
        if begins_component
            && *byte == b'~'
            && bytes
                .get(index + 1)
                .is_some_and(|separator| matches!(separator, b'/' | b'\\'))
        {
            return true;
        }
        if begins_component
            && byte.is_ascii_alphabetic()
            && bytes.get(index + 1) == Some(&b':')
            && bytes
                .get(index + 2)
                .is_some_and(|separator| matches!(separator, b'/' | b'\\'))
        {
            return true;
        }
    }
    false
}
