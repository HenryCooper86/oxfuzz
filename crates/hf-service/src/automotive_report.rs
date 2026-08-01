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
    /// `oxfuzz` version that generated the report.
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

/// Every user-facing literal the automotive report renderer emits.
///
/// This is the automotive counterpart of [`crate::report::Labels`], and is
/// deliberately a separate type: the two documents share almost no vocabulary,
/// so a union struct would make the compiler's completeness check meaningless
/// for both.
///
/// Two rules govern what is here and what stays inline in the renderer:
///
/// - **Technical tokens are never fields.** Evidence citations (`[OP:<id>]`,
///   `[STATE:<digest>]`, `[TRANSCRIPT:<sha256>]`), pipeline stage identifiers
///   (`capabilities`, `analyze_capture`, and siblings), protocol, bus, ECU and
///   adapter names, SHA-256 digests, file paths and every figure render
///   byte-identical in any language. Citations in particular are validated
///   against known identifiers, so translating one would discard the
///   interpretation carrying it. Markdown scaffolding (table pipes, alignment
///   rows, `**` emphasis, list markers) is formatting, not prose, and likewise
///   stays inline.
/// - **Terminal punctuation lives in the field** when the field is the last
///   thing before it, so a whole sentence stays translatable as a sentence.
///   The `narrative_*` punctuation fields are used only where the renderer
///   assembles a sentence around a figure or an emphasis marker and the
///   punctuation therefore cannot sit inside any one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutomotiveLabels {
    // Document header.
    pub title_prefix: &'static str,
    pub row_project: &'static str,
    pub row_generated: &'static str,
    pub row_tool: &'static str,
    pub row_evidence_window: &'static str,
    pub evidence_window_unit: &'static str,
    // Punctuation the renderer joins around label and value slots. Each field
    // carries its own spacing so a language whose full-width marks supply their
    // own spacing (Chinese ",（）。：；") needs no ASCII space beside them.
    // `label_colon` is the single ": " joiner used by the document title, the
    // "### Heading: `value`" finding headings and every "- Label: value"
    // bullet -- one field, reused wherever the mark serves the same purpose.
    // `narrative_sentence_break` is distinct from `narrative_full_stop`: it
    // separates two sentences that share a line, where a language supplies the
    // separator itself rather than an ASCII space after the stop.
    pub label_colon: &'static str,
    pub narrative_comma: &'static str,
    pub narrative_semicolon: &'static str,
    pub narrative_open_paren: &'static str,
    pub narrative_close_paren: &'static str,
    pub narrative_full_stop: &'static str,
    pub narrative_sentence_break: &'static str,
    pub narrative_and: &'static str,
    // Executive summary.
    pub executive_summary: &'static str,
    pub summary_lead: &'static str,
    pub summary_operation_unit: &'static str,
    pub summary_completed: &'static str,
    pub summary_partial: &'static str,
    pub summary_failed: &'static str,
    pub summary_running: &'static str,
    pub summary_cancelled: &'static str,
    pub summary_bounded_lead: &'static str,
    pub summary_state_digest_unit: &'static str,
    pub summary_promoted_artifact_unit: &'static str,
    pub summary_across: &'static str,
    pub summary_protocol_unit: &'static str,
    pub summary_failures_present: &'static str,
    pub summary_no_failures: &'static str,
    // A guardrail sentence, not decoration: it carries its own `**` emphasis
    // because the emphasized span sits mid-sentence, and splitting the sentence
    // into three fragments to hoist the markers out would fix the emphasis to
    // English word order.
    pub summary_novelty_disclaimer: &'static str,
    // Footer.
    pub footer_generated_by: &'static str,
    pub footer_on: &'static str,
    // Scope and safety posture.
    pub safety_section: &'static str,
    pub col_control: &'static str,
    pub col_effective_posture: &'static str,
    pub row_runtime_policy: &'static str,
    // `posture_disabled` is shared by the runtime-policy row and the
    // physical-bench row: same word, same meaning (the control is off).
    pub posture_disabled: &'static str,
    pub posture_enabled: &'static str,
    pub row_allowed_protocols: &'static str,
    pub row_allowed_modes: &'static str,
    pub row_virtual_interfaces: &'static str,
    pub virtual_interface_unit: &'static str,
    pub row_physical_bench: &'static str,
    pub bench_approval_required: &'static str,
    pub bench_approval_missing: &'static str,
    pub physical_interface_unit: &'static str,
    pub row_dangerous_services: &'static str,
    pub dangerous_denied: &'static str,
    pub dangerous_exceptionally_allowed: &'static str,
    pub row_per_operation_bounds: &'static str,
    pub bounds_event_unit: &'static str,
    pub bounds_second_unit: &'static str,
    pub bounds_rate_unit: &'static str,
    pub safety_validation_notice: &'static str,
    pub value_none: &'static str,
    // Campaign workflow. The stage *identifiers* stay inline in the renderer;
    // only these human stage descriptions are fields.
    pub workflow_section: &'static str,
    pub col_stage: &'static str,
    pub col_status: &'static str,
    pub col_completed: &'static str,
    pub col_failed: &'static str,
    pub stage_capabilities: &'static str,
    pub stage_analyze_capture: &'static str,
    pub stage_generate_mutations: &'static str,
    pub stage_build_replay_plan: &'static str,
    pub stage_execute_replay: &'static str,
    pub workflow_complete: &'static str,
    pub workflow_attention: &'static str,
    pub workflow_not_recorded: &'static str,
    pub workflow_physical_bench_notice: &'static str,
    // Protocol-state exploration.
    pub state_section: &'static str,
    pub state_none: &'static str,
    pub col_protocol: &'static str,
    pub col_unique_states: &'static str,
    pub col_promoted_artifacts: &'static str,
    pub state_evidence_heading: &'static str,
    pub state_observed_by: &'static str,
    pub state_promoted: &'static str,
    pub state_promoted_from: &'static str,
    pub state_promoted_digest: &'static str,
    pub state_promoted_at: &'static str,
    // Findings.
    pub findings_section: &'static str,
    pub findings_none: &'static str,
    pub finding_operational_failure: &'static str,
    pub bullet_evidence: &'static str,
    pub bullet_mode: &'static str,
    pub bullet_protocol: &'static str,
    pub bullet_retained_error: &'static str,
    pub value_protocol_not_selected: &'static str,
    pub value_no_error_detail: &'static str,
    pub finding_partial_result: &'static str,
    pub bullet_result: &'static str,
    pub bullet_required_action: &'static str,
    pub value_result_incomplete: &'static str,
    pub partial_required_action: &'static str,
    pub interpretation_boundary_heading: &'static str,
    pub interpretation_boundary_body: &'static str,
    // Evidence manifest. The status words are a separate vocabulary from the
    // executive summary's count words: the summary distinguishes "completed"
    // from "partial", while the durable lifecycle has "done" and no partial.
    pub manifest_section: &'static str,
    pub manifest_none: &'static str,
    pub col_operation_evidence: &'static str,
    pub col_mode_protocol: &'static str,
    pub col_validated_result: &'static str,
    pub col_request_digest: &'static str,
    pub col_transcript_evidence: &'static str,
    pub col_artifact_directory: &'static str,
    pub value_not_retained: &'static str,
    pub value_not_applicable: &'static str,
    pub status_running: &'static str,
    pub status_done: &'static str,
    pub status_failed: &'static str,
    pub status_cancelled: &'static str,
    // Limitations. These five bullets exist to stop a reader concluding more
    // than the retained evidence supports; they are the report's strongest
    // guardrail and each must keep its full force in every language.
    pub limitations_section: &'static str,
    pub limitation_bounded_snapshot: &'static str,
    pub limitation_not_coverage: &'static str,
    pub limitation_completed_not_absence: &'static str,
    pub limitation_virtual_not_physical: &'static str,
    pub limitation_ai_advisory: &'static str,
    // Recommendations.
    pub recommendations_section: &'static str,
    pub recommendation_triage_lead: &'static str,
    pub recommendation_triage_tail: &'static str,
    pub recommendation_preserve: &'static str,
    pub recommendation_next: &'static str,
    pub recommendation_capabilities: &'static str,
    pub recommendation_analyze_capture: &'static str,
    pub recommendation_generate_mutations: &'static str,
    pub recommendation_build_replay_plan: &'static str,
    pub recommendation_promote_lead: &'static str,
    pub recommendation_promote_tail: &'static str,
    // `virtual-CAN` is a bus name and must survive translation verbatim inside
    // this sentence.
    pub recommendation_virtual_replay: &'static str,
}

impl AutomotiveLabels {
    /// The English label set. These strings reproduce the renderer's original
    /// hardcoded literals exactly.
    #[must_use]
    pub const fn english() -> Self {
        Self {
            title_prefix: "Automotive Fuzzing Campaign Report",
            row_project: "Project",
            row_generated: "Generated",
            row_tool: "Tool",
            row_evidence_window: "Evidence window",
            evidence_window_unit: "retained operation(s)",
            label_colon: ": ",
            narrative_comma: ", ",
            narrative_semicolon: "; ",
            narrative_open_paren: " (",
            narrative_close_paren: ")",
            narrative_full_stop: ".",
            narrative_sentence_break: ". ",
            narrative_and: "and",
            executive_summary: "Executive Summary",
            summary_lead: "This report synthesizes",
            summary_operation_unit: "retained automotive operation(s)",
            summary_completed: "completed",
            summary_partial: "partial",
            summary_failed: "failed",
            summary_running: "running",
            summary_cancelled: "cancelled",
            summary_bounded_lead: "The bounded snapshot contains",
            summary_state_digest_unit: "unique protocol-state digest(s)",
            summary_promoted_artifact_unit: "promoted state-corpus artifact(s)",
            summary_across: "across",
            summary_protocol_unit: "observed protocol(s)",
            summary_failures_present: "Retained failures are reported as operational evidence and \
                                       should be resolved before the corresponding workflow stage \
                                       is repeated.",
            summary_no_failures: "No terminal operation failure is present in this retained \
                                  evidence window.",
            summary_novelty_disclaimer: "Protocol-state novelty is **not source coverage** and \
                                         does not by itself prove a vulnerability.",
            footer_generated_by: "Deterministic evidence report generated by oxfuzz",
            footer_on: "on",
            safety_section: "Scope and Safety Posture",
            col_control: "Control",
            col_effective_posture: "Effective posture",
            row_runtime_policy: "Runtime automotive policy",
            posture_disabled: "disabled",
            posture_enabled: "enabled",
            row_allowed_protocols: "Allowed protocols",
            row_allowed_modes: "Allowed modes",
            row_virtual_interfaces: "Virtual interfaces",
            virtual_interface_unit: "allowlisted",
            row_physical_bench: "Physical bench",
            bench_approval_required: "enabled; fresh approval required",
            bench_approval_missing: "invalid: enabled without required approval",
            physical_interface_unit: "allowlisted interface(s)",
            row_dangerous_services: "Dangerous diagnostic services",
            dangerous_denied: "denied",
            dangerous_exceptionally_allowed: "exceptionally allowed by policy",
            row_per_operation_bounds: "Per-operation bounds",
            bounds_event_unit: "events",
            bounds_second_unit: "seconds",
            bounds_rate_unit: "transmitted events/second",
            safety_validation_notice: "All captured, mutation, planning, and replay evidence \
                                       remains subject to service validation, sandbox isolation, \
                                       typed limits, guardrails, and the human-approval boundary.",
            value_none: "none",
            workflow_section: "Campaign Workflow",
            col_stage: "Stage",
            col_status: "Status",
            col_completed: "Completed",
            col_failed: "Failed",
            stage_capabilities: "Adapter capability inspection",
            stage_analyze_capture: "Immutable capture analysis",
            stage_generate_mutations: "Deterministic mutation generation",
            stage_build_replay_plan: "Typed replay-plan construction",
            stage_execute_replay: "Supervised virtual replay",
            workflow_complete: "Complete",
            workflow_attention: "Attention",
            workflow_not_recorded: "Not recorded",
            workflow_physical_bench_notice: "Physical-bench validation is intentionally excluded \
                                             from campaign-completeness scoring. It remains a \
                                             separately approved activity after the exact plan \
                                             and budgets are known.",
            state_section: "Protocol-State Exploration",
            state_none: "No validated protocol-state signature is present in the retained \
                         evidence window.",
            col_protocol: "Protocol",
            col_unique_states: "Unique states",
            col_promoted_artifacts: "Promoted artifacts",
            state_evidence_heading: "State Evidence",
            state_observed_by: "observed by",
            state_promoted: "Promoted",
            state_promoted_from: "from",
            state_promoted_digest: "artifact digest",
            state_promoted_at: "at",
            findings_section: "Findings",
            findings_none: "No retained terminal operation failure requires triage in this \
                            evidence window.",
            finding_operational_failure: "Operational failure",
            bullet_evidence: "Evidence",
            bullet_mode: "Mode",
            bullet_protocol: "Protocol",
            bullet_retained_error: "Retained error",
            value_protocol_not_selected: "not selected",
            value_no_error_detail: "no error detail retained",
            finding_partial_result: "Partial result",
            bullet_result: "Result",
            bullet_required_action: "Required action",
            value_result_incomplete: "typed operation did not complete",
            partial_required_action: "review the retained transcript and limits before retrying.",
            interpretation_boundary_heading: "Interpretation Boundary",
            interpretation_boundary_body: "Observed states, successful decoding, and completed \
                                           replay steps are campaign evidence. They do not by \
                                           themselves prove exploitability, security impact, or \
                                           unsafe vehicle behavior.",
            manifest_section: "Evidence Manifest",
            manifest_none: "No automotive operation evidence is retained for this project.",
            col_operation_evidence: "Operation evidence",
            col_mode_protocol: "Mode / protocol",
            col_validated_result: "Validated result",
            col_request_digest: "Request digest",
            col_transcript_evidence: "Transcript evidence",
            col_artifact_directory: "Artifact directory",
            value_not_retained: "not retained",
            value_not_applicable: "n/a",
            status_running: "running",
            status_done: "done",
            status_failed: "failed",
            status_cancelled: "cancelled",
            limitations_section: "Limitations",
            limitation_bounded_snapshot: "The report covers only the bounded retained evidence \
                                          snapshot and cannot infer events that were not \
                                          persisted.",
            limitation_not_coverage: "Protocol-state digests are not source-code line, function, \
                                      region, or edge coverage.",
            limitation_completed_not_absence: "A completed operation confirms contract-valid \
                                               execution, not absence of security defects.",
            limitation_virtual_not_physical: "Offline and virtual evidence does not validate a \
                                              physical ECU, vehicle network, timing behavior, or \
                                              bench wiring.",
            limitation_ai_advisory: "AI-assisted interpretation, when appended, is advisory and \
                                     cannot authorize execution or establish a finding.",
            recommendations_section: "Recommendations",
            recommendation_triage_lead: "Triage the",
            recommendation_triage_tail: "retained operational failure(s) by operation id before \
                                         repeating those stages.",
            recommendation_preserve: "Preserve the current operation evidence and compare future \
                                      campaign snapshots for regressions.",
            recommendation_next: "Next",
            recommendation_capabilities: "inspect the pinned adapter capabilities",
            recommendation_analyze_capture: "analyze an immutable representative capture",
            recommendation_generate_mutations: "generate a deterministic, reviewable mutation set",
            recommendation_build_replay_plan: "build and review a typed replay plan without \
                                               contacting an interface",
            recommendation_promote_lead: "Review and promote suitable artifacts for the",
            recommendation_promote_tail: "observed state(s) without retained corpus evidence.",
            recommendation_virtual_replay: "If policy and runtime readiness permit, conduct a \
                                            separately confirmed supervised virtual-CAN replay.",
        }
    }
}

/// Render an auditable, deterministic automotive campaign report.
#[must_use]
pub fn render_automotive_report(data: &AutomotiveReportData, labels: &AutomotiveLabels) -> String {
    let mut report = String::with_capacity(8192);
    let counts = operation_status_counts(&data.operations);
    let unique_states = unique_state_digests(data);
    let protocols = observed_protocols(data);

    let _ = writeln!(
        report,
        "# {}{}`{}`\n",
        labels.title_prefix,
        labels.label_colon,
        escape_inline(&data.project_name)
    );
    let _ = writeln!(report, "| | |");
    let _ = writeln!(report, "|---|---|");
    let _ = writeln!(
        report,
        "| {} | `{}` |",
        labels.row_project,
        escape_inline(&data.project_name)
    );
    let _ = writeln!(
        report,
        "| {} | {} |",
        labels.row_generated, data.generated_at
    );
    let _ = writeln!(
        report,
        "| {} | oxfuzz {} |",
        labels.row_tool, data.tool_version
    );
    let _ = writeln!(
        report,
        "| {} | {} {} |\n",
        labels.row_evidence_window,
        data.operations.len(),
        labels.evidence_window_unit
    );

    let _ = writeln!(report, "## {}\n", labels.executive_summary);
    let _ = writeln!(
        report,
        "{lead} **{total} {operation_unit}**{colon}**{done} {done_word}**{comma}\
         **{partial} {partial_word}**{comma}**{failed} {failed_word}**{comma}\
         **{running} {running_word}**{comma}{and} **{cancelled} {cancelled_word}**{sentence_break}\
         {bounded} **{states} {state_unit}** {and} **{promoted} {promoted_unit}** \
         {across} **{protocols} {protocol_unit}**{stop}\n",
        lead = labels.summary_lead,
        total = data.operations.len(),
        operation_unit = labels.summary_operation_unit,
        colon = labels.label_colon,
        done = counts.done,
        done_word = labels.summary_completed,
        comma = labels.narrative_comma,
        partial = counts.partial,
        partial_word = labels.summary_partial,
        failed = counts.failed,
        failed_word = labels.summary_failed,
        running = counts.running,
        running_word = labels.summary_running,
        and = labels.narrative_and,
        cancelled = counts.cancelled,
        cancelled_word = labels.summary_cancelled,
        sentence_break = labels.narrative_sentence_break,
        bounded = labels.summary_bounded_lead,
        states = unique_states.len(),
        state_unit = labels.summary_state_digest_unit,
        promoted = data.state_corpus.len(),
        promoted_unit = labels.summary_promoted_artifact_unit,
        across = labels.summary_across,
        protocols = protocols.len(),
        protocol_unit = labels.summary_protocol_unit,
        stop = labels.narrative_full_stop,
    );
    if counts.failed > 0 {
        let _ = writeln!(report, "{}", labels.summary_failures_present);
    } else {
        let _ = writeln!(report, "{}", labels.summary_no_failures);
    }
    let _ = writeln!(report, "\n{}", labels.summary_novelty_disclaimer);

    render_safety_posture(&mut report, &data.safety, labels);
    render_workflow(&mut report, &data.operations, labels);
    render_state_exploration(&mut report, data, &unique_states, labels);
    render_findings(&mut report, data, counts.failed, labels);
    render_evidence_manifest(&mut report, data, labels);
    render_limitations(&mut report, labels);
    render_recommendations(&mut report, data, labels);

    let _ = writeln!(report, "---\n");
    let _ = writeln!(
        report,
        "_{} {} {} {}{}_",
        labels.footer_generated_by,
        data.tool_version,
        labels.footer_on,
        data.generated_at,
        labels.narrative_full_stop
    );
    report
}

fn render_safety_posture(
    report: &mut String,
    safety: &AutomotiveReportSafetyPosture,
    labels: &AutomotiveLabels,
) {
    let _ = writeln!(report, "\n## {}\n", labels.safety_section);
    let _ = writeln!(
        report,
        "| {} | {} |",
        labels.col_control, labels.col_effective_posture
    );
    let _ = writeln!(report, "|---|---|");
    let _ = writeln!(
        report,
        "| {} | {} |",
        labels.row_runtime_policy,
        match safety.runtime_policy {
            AutomotivePolicyPosture::Disabled => labels.posture_disabled,
            AutomotivePolicyPosture::Enabled => labels.posture_enabled,
        }
    );
    let _ = writeln!(
        report,
        "| {} | {} |",
        labels.row_allowed_protocols,
        joined_or_none(&safety.allowed_protocols, labels)
    );
    let _ = writeln!(
        report,
        "| {} | {} |",
        labels.row_allowed_modes,
        joined_or_none(&safety.allowed_modes, labels)
    );
    let _ = writeln!(
        report,
        "| {} | {} {} |",
        labels.row_virtual_interfaces,
        safety.virtual_interface_count,
        labels.virtual_interface_unit
    );
    let _ = writeln!(
        report,
        "| {} | {}{}{} {} |",
        labels.row_physical_bench,
        match safety.physical_bench {
            AutomotivePhysicalBenchPosture::Disabled => labels.posture_disabled,
            AutomotivePhysicalBenchPosture::EnabledApprovalRequired => {
                labels.bench_approval_required
            }
            AutomotivePhysicalBenchPosture::EnabledApprovalMissing => {
                labels.bench_approval_missing
            }
        },
        labels.narrative_semicolon,
        safety.physical_interface_count,
        labels.physical_interface_unit,
    );
    let _ = writeln!(
        report,
        "| {} | {} |",
        labels.row_dangerous_services,
        match safety.dangerous_services {
            AutomotiveDangerousServicesPosture::Denied => labels.dangerous_denied,
            AutomotiveDangerousServicesPosture::ExceptionallyAllowed => {
                labels.dangerous_exceptionally_allowed
            }
        }
    );
    let _ = writeln!(
        report,
        "| {row} | {packets} {event_unit}{semicolon}{duration} {second_unit}{semicolon}\
         {rate} {rate_unit} |",
        row = labels.row_per_operation_bounds,
        packets = safety.max_packets,
        event_unit = labels.bounds_event_unit,
        semicolon = labels.narrative_semicolon,
        duration = safety.max_duration_secs,
        second_unit = labels.bounds_second_unit,
        rate = safety.max_rate_per_second,
        rate_unit = labels.bounds_rate_unit,
    );
    let _ = writeln!(report, "\n{}", labels.safety_validation_notice);
}

fn render_workflow(
    report: &mut String,
    operations: &[AutomotiveReportOperation],
    labels: &AutomotiveLabels,
) {
    let stages = [
        (labels.stage_capabilities, "capabilities", None),
        (labels.stage_analyze_capture, "analyze_capture", None),
        (labels.stage_generate_mutations, "generate_mutations", None),
        (labels.stage_build_replay_plan, "build_replay_plan", None),
        (
            labels.stage_execute_replay,
            "execute_replay",
            Some("virtual_can"),
        ),
    ];
    let _ = writeln!(report, "\n## {}\n", labels.workflow_section);
    let _ = writeln!(
        report,
        "| {} | {} | {} | {} |",
        labels.col_stage, labels.col_status, labels.col_completed, labels.col_failed
    );
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
            labels.workflow_complete
        } else if failed > 0 {
            labels.workflow_attention
        } else {
            labels.workflow_not_recorded
        };
        let _ = writeln!(report, "| {label} | {status} | {completed} | {failed} |");
    }
    let _ = writeln!(report, "\n{}", labels.workflow_physical_bench_notice);
}

fn render_state_exploration(
    report: &mut String,
    data: &AutomotiveReportData,
    unique_states: &BTreeSet<(String, String)>,
    labels: &AutomotiveLabels,
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

    let _ = writeln!(report, "\n## {}\n", labels.state_section);
    if per_protocol.is_empty() {
        let _ = writeln!(report, "{}", labels.state_none);
        return;
    }
    let _ = writeln!(
        report,
        "| {} | {} | {} |",
        labels.col_protocol, labels.col_unique_states, labels.col_promoted_artifacts
    );
    let _ = writeln!(report, "|---|---:|---:|");
    for (protocol, (states, promoted)) in per_protocol {
        let _ = writeln!(report, "| `{protocol}` | {states} | {promoted} |");
    }
    let _ = writeln!(report, "\n### {}\n", labels.state_evidence_heading);
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
            "- `[STATE:{digest}]`{open}`{protocol}`{close}{comma}{observed} {sources}{stop}",
            open = labels.narrative_open_paren,
            close = labels.narrative_close_paren,
            comma = labels.narrative_comma,
            observed = labels.state_observed_by,
            sources = sources.join(labels.narrative_comma),
            stop = labels.narrative_full_stop,
        );
    }
    for entry in &data.state_corpus {
        let _ = writeln!(
            report,
            "- {promoted} `[STATE:{}]` {from} [OP:{}]{comma}{digest_word} `{}` {at} `{}`{stop}",
            entry.state_digest,
            entry.source_operation_id,
            entry.artifact_sha256,
            escape_inline(&entry.artifact_path),
            promoted = labels.state_promoted,
            from = labels.state_promoted_from,
            comma = labels.narrative_comma,
            digest_word = labels.state_promoted_digest,
            at = labels.state_promoted_at,
            stop = labels.narrative_full_stop,
        );
    }
}

fn render_findings(
    report: &mut String,
    data: &AutomotiveReportData,
    failed: usize,
    labels: &AutomotiveLabels,
) {
    let _ = writeln!(report, "\n## {}\n", labels.findings_section);
    if failed == 0 {
        let _ = writeln!(report, "{}", labels.findings_none);
    } else {
        for operation in data
            .operations
            .iter()
            .filter(|operation| operation.status == AutomotiveOperationStatus::Failed)
        {
            let _ = writeln!(
                report,
                "### {failure}{colon}`{}`\n\n- {evidence}{colon}[OP:{}]\n- {mode}{colon}`{}`\n\
                 - {protocol}{colon}`{}`\n- {error}{colon}{}\n",
                operation.operation,
                operation.id,
                operation.mode,
                operation
                    .protocol
                    .as_deref()
                    .unwrap_or(labels.value_protocol_not_selected),
                shareable_error(
                    operation
                        .error
                        .as_deref()
                        .unwrap_or(labels.value_no_error_detail)
                ),
                failure = labels.finding_operational_failure,
                colon = labels.label_colon,
                evidence = labels.bullet_evidence,
                mode = labels.bullet_mode,
                protocol = labels.bullet_protocol,
                error = labels.bullet_retained_error,
            );
        }
    }
    for operation in data.operations.iter().filter(|operation| {
        operation.status == AutomotiveOperationStatus::Done
            && operation.result_complete == Some(false)
    }) {
        let _ = writeln!(
            report,
            "### {partial}{colon}`{}`\n\n- {evidence}{colon}[OP:{}]\n- {result}{colon}{}\n\
             - {action}{colon}{required}\n",
            operation.operation,
            operation.id,
            operation
                .result_summary
                .as_deref()
                .unwrap_or(labels.value_result_incomplete),
            partial = labels.finding_partial_result,
            colon = labels.label_colon,
            evidence = labels.bullet_evidence,
            result = labels.bullet_result,
            action = labels.bullet_required_action,
            required = labels.partial_required_action,
        );
    }
    let _ = writeln!(
        report,
        "### {}\n\n{}",
        labels.interpretation_boundary_heading, labels.interpretation_boundary_body
    );
}

fn render_evidence_manifest(
    report: &mut String,
    data: &AutomotiveReportData,
    labels: &AutomotiveLabels,
) {
    let _ = writeln!(report, "\n## {}\n", labels.manifest_section);
    if data.operations.is_empty() {
        let _ = writeln!(report, "{}", labels.manifest_none);
        return;
    }
    let _ = writeln!(
        report,
        "| {} | {} | {} | {} | {} | {} | {} | {} |",
        labels.col_operation_evidence,
        labels.col_stage,
        labels.col_mode_protocol,
        labels.col_status,
        labels.col_validated_result,
        labels.col_request_digest,
        labels.col_transcript_evidence,
        labels.col_artifact_directory
    );
    let _ = writeln!(report, "|---|---|---|---|---|---|---|---|");
    let mut operations = data.operations.iter().collect::<Vec<_>>();
    operations.sort_by_key(|operation| (operation.started_at, operation.id));
    for operation in operations {
        let transcript = operation.transcript_sha256.as_ref().map_or_else(
            || labels.value_not_retained.to_owned(),
            |digest| format!("[TRANSCRIPT:{digest}]"),
        );
        let _ = writeln!(
            report,
            "| [OP:{}] | `{}` | `{}` / `{}` | {} | {} | `{}` | {} | `{}` |",
            operation.id,
            operation.operation,
            operation.mode,
            operation
                .protocol
                .as_deref()
                .unwrap_or(labels.value_not_applicable),
            status_name(operation.status, labels),
            escape_inline(
                operation
                    .result_summary
                    .as_deref()
                    .unwrap_or(labels.value_not_retained)
            ),
            operation.request_sha256,
            transcript,
            escape_inline(&operation.artifact_dir),
        );
    }
}

fn render_limitations(report: &mut String, labels: &AutomotiveLabels) {
    let _ = writeln!(report, "\n## {}\n", labels.limitations_section);
    let _ = writeln!(
        report,
        "- {}\n- {}\n- {}\n- {}\n- {}",
        labels.limitation_bounded_snapshot,
        labels.limitation_not_coverage,
        labels.limitation_completed_not_absence,
        labels.limitation_virtual_not_physical,
        labels.limitation_ai_advisory
    );
}

fn render_recommendations(
    report: &mut String,
    data: &AutomotiveReportData,
    labels: &AutomotiveLabels,
) {
    let _ = writeln!(report, "\n## {}\n", labels.recommendations_section);
    let failed = data
        .operations
        .iter()
        .filter(|operation| operation.status == AutomotiveOperationStatus::Failed)
        .count();
    if failed > 0 {
        let _ = writeln!(
            report,
            "1. {lead} {failed} {tail}",
            lead = labels.recommendation_triage_lead,
            tail = labels.recommendation_triage_tail
        );
    } else {
        let _ = writeln!(report, "1. {}", labels.recommendation_preserve);
    }
    let stages = [
        ("capabilities", labels.recommendation_capabilities),
        ("analyze_capture", labels.recommendation_analyze_capture),
        (
            "generate_mutations",
            labels.recommendation_generate_mutations,
        ),
        ("build_replay_plan", labels.recommendation_build_replay_plan),
    ];
    let mut number = 2;
    for (operation, recommendation) in stages {
        if !data.operations.iter().any(|entry| {
            entry.operation == operation && entry.status == AutomotiveOperationStatus::Done
        }) {
            let _ = writeln!(
                report,
                "{number}. {next}{comma}{recommendation}{stop}",
                next = labels.recommendation_next,
                comma = labels.narrative_comma,
                stop = labels.narrative_full_stop
            );
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
            "{number}. {lead} {unpromoted} {tail}",
            lead = labels.recommendation_promote_lead,
            tail = labels.recommendation_promote_tail
        );
        number += 1;
    }
    if !data.operations.iter().any(|entry| {
        entry.operation == "execute_replay"
            && entry.mode == "virtual_can"
            && entry.status == AutomotiveOperationStatus::Done
    }) {
        let _ = writeln!(report, "{number}. {}", labels.recommendation_virtual_replay);
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

fn joined_or_none(values: &[String], labels: &AutomotiveLabels) -> String {
    if values.is_empty() {
        labels.value_none.to_owned()
    } else {
        values
            .iter()
            .map(|value| format!("`{}`", escape_inline(value)))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Resolve a durable lifecycle status to its label.
///
/// These are a separate vocabulary from the executive summary's count words:
/// the summary distinguishes "completed" from "partial", while the durable
/// lifecycle has "done" and no partial state at all.
const fn status_name(status: AutomotiveOperationStatus, labels: &AutomotiveLabels) -> &'static str {
    match status {
        AutomotiveOperationStatus::Running => labels.status_running,
        AutomotiveOperationStatus::Done => labels.status_done,
        AutomotiveOperationStatus::Failed => labels.status_failed,
        AutomotiveOperationStatus::Cancelled => labels.status_cancelled,
    }
}

fn escape_inline(value: &str) -> String {
    value
        .replace(['\n', '\r'], " ")
        .replace('`', "'")
        .replace('|', "\\|")
}

pub(crate) fn shareable_error(value: &str) -> String {
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
