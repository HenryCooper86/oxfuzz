//! Deterministic automotive campaign reporting and grounded AI composition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use hf_storage::AutomotiveOperationStatus;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::automotive::{AutomotiveStateCorpusEntry, StateSignature};
use crate::config::AutomotiveSettings;
use crate::report::ReportLanguage;

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
    // own spacing (Chinese "，（）。：；") needs no ASCII space beside them.
    // `label_colon` is the single ": " joiner used by the document title, the
    // "### Heading: `value`" finding headings and every "- Label: value"
    // bullet -- one field, reused wherever the mark serves the same purpose.
    // `narrative_sentence_break` is distinct from `narrative_full_stop`: it
    // separates two sentences that share a line, where a language supplies the
    // separator itself rather than an ASCII space after the stop.
    pub label_colon: &'static str,
    // `narrative_comma` separates *clauses*: the comma after a parenthetical
    // in the state-evidence bullet, the one before "artifact digest" in the
    // promoted bullet, and the one after "Next". `list_separator` joins *items
    // of a list*: the executive summary's run of status counts, the evidence
    // citations after "observed by", and the allowed-protocol and allowed-mode
    // cells. The two are the same ", " in English and must not be merged:
    // Chinese writes a clause comma as the fullwidth "，" and a list comma as
    // the enumeration mark "、", so a single field would be wrong in one of the
    // two roles whichever mark it held.
    pub narrative_comma: &'static str,
    pub list_separator: &'static str,
    // Closes the executive summary's enumeration: ", and " in English, where
    // the serial comma and the conjunction are both wanted, and the bare
    // conjunction in Chinese, which writes "A、B、C和D" and never repeats the
    // enumeration mark before the last item. It is a field of its own rather
    // than `list_separator` followed by `narrative_and` because that pairing
    // renders "、和" -- correct in neither language that uses "、".
    pub list_final_separator: &'static str,
    // Also fills the separator slot beside `bench_approval_detail` -- see the
    // physical-bench fields below. Nothing is embedded inside that field; the
    // cell is assembled from three separate slots precisely so no mark is.
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
    // `oxfuzz` is the product name and must survive translation verbatim
    // inside this sentence, exactly as `virtual-CAN` must inside
    // `recommendation_virtual_replay`. It is embedded rather than a separate
    // slot so the sentence stays translatable as a sentence, matching the main
    // report's `generated_by`.
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
    // The physical-bench cell is assembled as head + separator + tail so that
    // the marks inside it come from the same fields as the marks around it.
    // The enabled-but-unapproved posture used to be one field reading
    // "enabled; fresh approval required", which put a literal "; " next to the
    // `narrative_semicolon` that follows it in the same cell, and a second copy
    // of `posture_enabled`'s word inside it. Both could drift under
    // translation. The `Disabled` arm has no tail and passes an empty
    // separator, which is structure rather than prose and stays inline.
    pub bench_approval_detail: &'static str,
    pub bench_invalid: &'static str,
    // This one still carries its own copy of the word `posture_enabled` holds,
    // and stays whole on purpose: "enabled without required approval" is one
    // participial phrase, and splitting it to reuse the field would pin the
    // word order to English -- Chinese renders the same posture as a clause
    // whose verb is not in the same place. The duplication is therefore a
    // translation obligation rather than a structural one: whatever word
    // `posture_enabled` takes must appear inside this phrase too, so the same
    // posture is not spelled two ways in one table.
    pub bench_approval_missing_detail: &'static str,
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
    // Every language must keep them apart. A `Done` operation whose typed
    // result did not complete is counted `partial` and never `completed`, so a
    // `status_done` that reads as "completed" would have the manifest call an
    // operation complete on the same page the summary counts zero of them.
    pub manifest_section: &'static str,
    pub manifest_none: &'static str,
    pub col_operation_evidence: &'static str,
    // The " / " inside this header joins two translated words and so belongs to
    // the field. The visually matching " / " in the data cell below joins two
    // backticked technical tokens (`offline_pcap` / `can`) and stays inline
    // with them: it is part of the token region, and hoisting it into a shared
    // field would mean splitting this header into two fields whose casing
    // conflicts with the existing `bullet_mode` and `col_protocol`. The two
    // slashes are allowed to differ; neither is prose a reader parses.
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
    // AI-assisted interpretation. This block is not part of the deterministic
    // document: `render_automotive_report` never emits it. It is the section
    // `append_ai_interpretation` puts above provider prose, plus the four
    // headings that provider prose must carry.
    //
    // The four heading fields are a single vocabulary shared by
    // `automotive_report_user_prompt`, which asks the model for them, and
    // `validate_ai_interpretation`, which rejects an interpretation missing any
    // of them. They must be resolved from the same label set on both sides: a
    // prompt asking for one language's headings while validation requires
    // another's discards every interpretation the model returns, and the report
    // falls back to the deterministic document with nothing said about why.
    //
    // The `###` prefix is Markdown scaffolding and stays in the two call sites,
    // by the same rule that keeps `##` out of the section fields above.
    //
    // `ai_advisory_notice` is a guardrail, not a caption. It is what tells a
    // reader that the prose below it is not evidence and cannot displace the
    // fact sheet above it, so it must keep its full force in every language --
    // the same standard as the Limitations bullets.
    pub ai_interpretation_section: &'static str,
    pub ai_advisory_notice: &'static str,
    // Names the provider model that wrote the interpretation. The identifier
    // itself is a technical token, so it is never translated -- but it is
    // provider-supplied text landing inside a Markdown code span, so a backtick
    // or pipe in it is neutralized before it is written.
    pub ai_model: &'static str,
    pub ai_heading_evidence_backed: &'static str,
    pub ai_heading_hypotheses: &'static str,
    pub ai_heading_missing_evidence: &'static str,
    pub ai_heading_next_actions: &'static str,
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
            list_separator: ", ",
            list_final_separator: ", and ",
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
            bench_approval_detail: "fresh approval required",
            bench_invalid: "invalid",
            bench_approval_missing_detail: "enabled without required approval",
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
            ai_interpretation_section: "AI-Assisted Interpretation",
            // Carries no terminal stop: `narrative_sentence_break` supplies it,
            // so the mark between this notice and the model line comes from the
            // same field in both languages.
            ai_advisory_notice: "This provider-generated interpretation is advisory. Retained \
                                 evidence and service validation remain authoritative",
            ai_model: "Model",
            ai_heading_evidence_backed: "Evidence-backed interpretation",
            ai_heading_hypotheses: "Hypotheses",
            ai_heading_missing_evidence: "Missing evidence",
            ai_heading_next_actions: "Recommended next actions",
        }
    }

    /// Resolve the label set for `language`.
    #[must_use]
    pub const fn for_language(language: ReportLanguage) -> Self {
        match language {
            ReportLanguage::En => Self::english(),
            ReportLanguage::Zh => Self::chinese(),
        }
    }
}

impl AutomotiveLabels {
    /// The Simplified Chinese label set.
    ///
    /// Terminology follows what the product already ships rather than being
    /// coined here: the desktop app carries 320 translated `automotive.*` keys
    /// in `crates/hf-gui/src/i18n.extra.ts`, and the main report's
    /// [`crate::report::Labels::chinese`] settles the vocabulary the two
    /// documents share. Bindings taken from there and used throughout:
    /// campaign 测试活动, findings 发现项, corpus 语料库, artifact 产物,
    /// digest 摘要, transcript 记录, replay 重放, mutation 变异,
    /// physical bench 物理台架, allowlist 允许列表, sandbox 沙箱,
    /// guardrails 安全护栏, triage 分类定级, novelty 新颖性.
    ///
    /// Every full-width mark supplies its own spacing, so a field holding
    /// `", "` in English holds `"，"` here with no ASCII space beside it.
    /// Technical tokens are absent from this function by construction: they are
    /// never fields, so there is nothing here to leave untranslated.
    #[must_use]
    pub const fn chinese() -> Self {
        Self {
            title_prefix: "汽车协议模糊测试活动报告",
            row_project: "项目",
            row_generated: "生成时间",
            row_tool: "工具",
            row_evidence_window: "证据窗口",
            evidence_window_unit: "个保留的操作",
            label_colon: "：",
            narrative_comma: "，",
            list_separator: "、",
            list_final_separator: "和",
            narrative_semicolon: "；",
            narrative_open_paren: "（",
            narrative_close_paren: "）",
            narrative_full_stop: "。",
            // The full stop already separates the two sentences that share this
            // line; an ASCII space after it would be a stray mark.
            narrative_sentence_break: "。",
            narrative_and: "和",
            executive_summary: "摘要",
            summary_lead: "本报告汇总",
            summary_operation_unit: "个保留的汽车协议操作",
            // The measure word belongs to the counted noun, not to the figure
            // beside it, so each count word carries its own.
            summary_completed: "个已完成",
            summary_partial: "个部分完成",
            summary_failed: "个失败",
            summary_running: "个运行中",
            summary_cancelled: "个已取消",
            summary_bounded_lead: "受限快照包含",
            summary_state_digest_unit: "个唯一协议状态摘要",
            summary_promoted_artifact_unit: "个已提升的状态语料库产物",
            // Reads as one clause with the noun phrase before it, where a bare
            // "涉及" would leave the sentence looking as though a comma had
            // been dropped: the template puts no mark in this slot.
            summary_across: "共涉及",
            summary_protocol_unit: "个观察到的协议",
            summary_failures_present: "保留的失败会作为操作证据予以报告，应在重复相应工作流阶段\
                                       之前解决。",
            summary_no_failures: "此保留证据窗口中不存在终态操作失败。",
            summary_novelty_disclaimer: "协议状态新颖性**不是源代码覆盖率**，其本身也不能证明存在\
                                         漏洞。",
            footer_generated_by: "确定性证据报告由 oxfuzz 生成，版本",
            footer_on: "于",
            safety_section: "范围与安全策略",
            col_control: "控制项",
            col_effective_posture: "生效状态",
            row_runtime_policy: "运行时汽车协议策略",
            posture_disabled: "已禁用",
            posture_enabled: "已启用",
            row_allowed_protocols: "允许的协议",
            row_allowed_modes: "允许的模式",
            row_virtual_interfaces: "虚拟接口",
            virtual_interface_unit: "个在允许列表中",
            row_physical_bench: "物理台架",
            bench_approval_detail: "需要新的人工批准",
            bench_invalid: "无效",
            // Carries `posture_enabled`'s word, as its comment on the struct
            // requires, so one posture is not spelled two ways in one table.
            bench_approval_missing_detail: "已启用但缺少必需的批准",
            physical_interface_unit: "个允许列表接口",
            row_dangerous_services: "危险诊断服务",
            dangerous_denied: "已拒绝",
            dangerous_exceptionally_allowed: "按策略例外允许",
            row_per_operation_bounds: "单次操作上限",
            bounds_event_unit: "个事件",
            bounds_second_unit: "秒",
            bounds_rate_unit: "个发送事件/秒",
            safety_validation_notice: "所有捕获、变异、计划和重放证据均须接受服务校验、沙箱隔离、\
                                       类型化限额、安全护栏以及人工批准边界的约束。",
            value_none: "无",
            workflow_section: "测试活动工作流",
            col_stage: "阶段",
            col_status: "状态",
            // Count columns, unlike `workflow_complete` beside them, which is a
            // status word.
            col_completed: "完成数",
            col_failed: "失败数",
            stage_capabilities: "适配器能力检查",
            stage_analyze_capture: "不可变捕获文件分析",
            stage_generate_mutations: "确定性变异生成",
            stage_build_replay_plan: "类型化重放计划构建",
            stage_execute_replay: "受监督的虚拟重放",
            workflow_complete: "已完成",
            workflow_attention: "需关注",
            workflow_not_recorded: "无记录",
            workflow_physical_bench_notice: "物理台架验证被有意排除在测试活动完整度评分之外。\
                                             它仍是一项单独批准的活动，只有在确切的计划和预算\
                                             明确之后才能进行。",
            state_section: "协议状态探索",
            state_none: "保留的证据窗口中不存在经过验证的协议状态签名。",
            col_protocol: "协议",
            col_unique_states: "唯一状态",
            col_promoted_artifacts: "已提升产物",
            state_evidence_heading: "状态证据",
            state_observed_by: "观察来源",
            state_promoted: "已提升",
            state_promoted_from: "来自",
            state_promoted_digest: "产物摘要",
            state_promoted_at: "位于",
            findings_section: "发现项",
            findings_none: "此证据窗口中没有需要分类定级的保留终态操作失败。",
            finding_operational_failure: "操作失败",
            bullet_evidence: "证据",
            bullet_mode: "模式",
            bullet_protocol: "协议",
            bullet_retained_error: "保留的错误",
            value_protocol_not_selected: "未选择",
            value_no_error_detail: "未保留错误详情",
            finding_partial_result: "部分结果",
            bullet_result: "结果",
            bullet_required_action: "必要行动",
            value_result_incomplete: "类型化操作未完成",
            partial_required_action: "重试前请检查保留的记录和限额。",
            interpretation_boundary_heading: "解读边界",
            interpretation_boundary_body: "观察到的状态、成功的解码和已完成的重放步骤都属于测试\
                                           活动证据。它们本身并不能证明可利用性、安全影响或不\
                                           安全的车辆行为。",
            manifest_section: "证据清单",
            manifest_none: "此项目没有保留任何汽车协议操作证据。",
            col_operation_evidence: "操作证据",
            col_mode_protocol: "模式 / 协议",
            col_validated_result: "已验证结果",
            col_request_digest: "请求摘要",
            col_transcript_evidence: "记录证据",
            col_artifact_directory: "产物目录",
            value_not_retained: "未保留",
            value_not_applicable: "不适用",
            status_running: "运行中",
            // "已结束", not "已完成": this is the durable lifecycle reaching a
            // terminal state, which says nothing about whether the typed result
            // completed. "已完成" belongs to `workflow_complete` and
            // `summary_completed`, and a `Done` operation with an incomplete
            // result is counted "个部分完成" there -- reusing the word here
            // would have the manifest contradict the summary about the same
            // operation, a contradiction the English "done" cannot express.
            status_done: "已结束",
            status_failed: "失败",
            status_cancelled: "已取消",
            limitations_section: "限制",
            limitation_bounded_snapshot: "本报告仅覆盖受限的保留证据快照，无法推断未被持久化的\
                                          事件。",
            limitation_not_coverage: "协议状态摘要不是源代码的行覆盖率、函数覆盖率、区域覆盖率\
                                      或边覆盖率。",
            limitation_completed_not_absence: "操作完成只能确认执行符合契约，并不代表不存在安全\
                                               缺陷。",
            limitation_virtual_not_physical: "离线证据和虚拟证据不能验证物理 ECU、车辆网络、\
                                              时序行为或台架接线。",
            limitation_ai_advisory: "附加的 AI 辅助解读仅供参考，既不能授权执行，也不能确立发现\
                                     项。",
            recommendations_section: "建议",
            recommendation_triage_lead: "请对",
            recommendation_triage_tail: "个保留的操作失败按操作 id 进行分类定级，然后再重复相应\
                                         阶段。",
            recommendation_preserve: "保留当前操作证据，并与未来的测试活动快照比对以发现回归。",
            recommendation_next: "下一步",
            recommendation_capabilities: "检查固定版本适配器声明的能力",
            recommendation_analyze_capture: "分析一份具有代表性的不可变捕获文件",
            recommendation_generate_mutations: "生成一组确定性且可审阅的变异",
            recommendation_build_replay_plan: "在不接触任何接口的前提下构建并审阅类型化重放计划",
            recommendation_promote_lead: "请为",
            recommendation_promote_tail: "个尚无保留语料库证据的观察状态审阅并提升合适的产物。",
            recommendation_virtual_replay: "如果策略和运行时就绪状态允许，请执行一次单独确认的\
                                            受监督 virtual-CAN 重放。",
            // "AI 辅助解读", matching `limitation_ai_advisory`, which names the
            // same section from inside the Limitations list. The desktop app
            // ships 解读 for "interpretation" (automotive.report.aiApplied).
            ai_interpretation_section: "AI 辅助解读",
            // Assessed claim by claim against the English, which reads "This
            // provider-generated interpretation is advisory. Retained evidence
            // and service validation remain authoritative".
            //
            // 1. "is advisory" -> 仅供参考, the shipped rendering of the same
            //    word in automotive.report.description and the word
            //    `limitation_ai_advisory` already uses, so a reader meets one
            //    vocabulary. It is stronger than the English: "advisory" only
            //    withholds authority, while 仅供参考 restricts the text to
            //    reference and excludes every other use.
            // 2. "remain authoritative" -> 任何情况下均以...为准. 以...为准 is
            //    the standard formula for what controls in a conflict, which is
            //    what "authoritative" means here and is more directive than the
            //    English adjective. 任何情况下均 renders the persistence in
            //    "remain" as the absence of exceptions, so the notice cannot be
            //    read as holding only until the model says otherwise.
            //
            // Terminal stop omitted, as in `english()`.
            ai_advisory_notice: "本解读由模型提供方生成，仅供参考。任何情况下均以保留的证据和\
                                 服务校验为准",
            ai_model: "模型",
            // 基于证据 is the shipped binding (automotive.report.evidenceBacked)
            // and 后续行动 the shipped rendering of "next actions"
            // (automotive.report.description). Both are quoted from the
            // interface a reader of this report already uses.
            ai_heading_evidence_backed: "基于证据的解读",
            ai_heading_hypotheses: "假设",
            ai_heading_missing_evidence: "缺失的证据",
            ai_heading_next_actions: "建议的后续行动",
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
        "{lead} **{total} {operation_unit}**{colon}**{done} {done_word}**{item}\
         **{partial} {partial_word}**{item}**{failed} {failed_word}**{item}\
         **{running} {running_word}**{last_item}**{cancelled} {cancelled_word}**{sentence_break}\
         {bounded} **{states} {state_unit}** {and} **{promoted} {promoted_unit}** \
         {across} **{protocols} {protocol_unit}**{stop}\n",
        lead = labels.summary_lead,
        total = data.operations.len(),
        operation_unit = labels.summary_operation_unit,
        colon = labels.label_colon,
        done = counts.done,
        done_word = labels.summary_completed,
        // The status counts are an enumerated list, not a run of clauses.
        item = labels.list_separator,
        partial = counts.partial,
        partial_word = labels.summary_partial,
        failed = counts.failed,
        failed_word = labels.summary_failed,
        running = counts.running,
        running_word = labels.summary_running,
        // The last item of the enumeration takes the conjunction, not another
        // separator: ", and " reads as one joint in English, and Chinese drops
        // the enumeration mark entirely before the final item.
        last_item = labels.list_final_separator,
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
    // Assembled from three label slots so that the mark inside the posture and
    // the `narrative_semicolon` that follows it cannot diverge under
    // translation. The empty separator on the `Disabled` arm is structure, not
    // prose.
    let (bench_posture, bench_separator, bench_detail) = match safety.physical_bench {
        AutomotivePhysicalBenchPosture::Disabled => (labels.posture_disabled, "", ""),
        AutomotivePhysicalBenchPosture::EnabledApprovalRequired => (
            labels.posture_enabled,
            labels.narrative_semicolon,
            labels.bench_approval_detail,
        ),
        AutomotivePhysicalBenchPosture::EnabledApprovalMissing => (
            labels.bench_invalid,
            labels.label_colon,
            labels.bench_approval_missing_detail,
        ),
    };
    let _ = writeln!(
        report,
        "| {} | {bench_posture}{bench_separator}{bench_detail}{}{} {} |",
        labels.row_physical_bench,
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
            sources = sources.join(labels.list_separator),
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
///
/// The grounding rules are identical in both languages. Only the output
/// language is added, because every clause here exists to stop the model
/// inventing evidence and none of them is about English.
#[must_use]
pub fn automotive_report_system_prompt(language: ReportLanguage) -> String {
    let base = "You are a senior automotive security engineer interpreting a deterministic campaign fact sheet. \
     You NEVER invent operations, protocol states, digests, vulnerabilities, vehicle effects, or test \
     results. State novelty is not source coverage and is not proof of a vulnerability. Your output is \
     advisory: it cannot authorize traffic, change a replay plan, relax policy, or replace retained evidence.";
    match language {
        ReportLanguage::En => base.to_owned(),
        ReportLanguage::Zh => format!(
            "{base} You write the interpretation in Simplified Chinese for a Chinese-reading \
             engineering audience."
        ),
    }
}

/// Build the grounded provider prompt for an automotive report interpretation.
///
/// The four requested headings are resolved from the same label set
/// [`validate_ai_interpretation`] checks against, so what the model is asked
/// for and what it is judged by cannot drift apart.
#[must_use]
pub fn automotive_report_user_prompt(
    facts: &str,
    data: &AutomotiveReportData,
    language: ReportLanguage,
) -> String {
    let labels = AutomotiveLabels::for_language(language);
    // The token rule is load-bearing beyond readability here. A citation is
    // matched against the known operation ids, state digests and transcript
    // hashes, so a translated or transliterated one does not merely puzzle a
    // reader -- it fails validation and discards the whole interpretation.
    let language_rules = match language {
        ReportLanguage::En => String::new(),
        ReportLanguage::Zh => "Write the entire interpretation in Simplified Chinese, including \
             every heading and all prose.\n\n\
             Keep the following verbatim in their original form, never translated or \
             transliterated: the evidence citations `[OP:<uuid>]`, `[STATE:<sha256>]` and \
             `[TRANSCRIPT:<sha256>]` together with the identifiers inside them, pipeline stage \
             identifiers, protocol, bus, ECU and adapter names, SHA-256 digests, file paths, and \
             every figure. A translated citation no longer matches the retained evidence it names, \
             and an interpretation carrying one is rejected in full.\n\n"
            .to_owned(),
    };
    format!(
        "Interpret the automotive campaign fact sheet below for a professional engineering and security \
         audience. Use only its retained facts. Cite claims with the exact evidence forms `[OP:<uuid>]`, \
         `[STATE:<sha256>]`, and `[TRANSCRIPT:<sha256>]` already present in the sheet. Do not create a \
         citation, path, number, protocol, vehicle effect, vulnerability, or result. Clearly label inference \
         as a hypothesis and absence as missing evidence. Recommendations may cover additional offline \
         analysis, deterministic mutation, plan review, or supervised virtual validation, but cannot authorize \
         execution or physical traffic. Do not emit code, shell commands, replay payloads, or a top-level title.\n\n\
         Return exactly these Markdown headings:\n\
         ### {evidence_backed}\n\
         ### {hypotheses}\n\
         ### {missing_evidence}\n\
         ### {next_actions}\n\n\
         {language_rules}\
         Project: `{project}`\n\n---\n# DETERMINISTIC FACT SHEET (ground truth)\n\n{facts}",
        evidence_backed = labels.ai_heading_evidence_backed,
        hypotheses = labels.ai_heading_hypotheses,
        missing_evidence = labels.ai_heading_missing_evidence,
        next_actions = labels.ai_heading_next_actions,
        project = escape_inline(&data.project_name),
    )
}

/// Validate the evidence citations and bounded structure of provider output.
///
/// `language` selects which four headings are required, and nothing else. Every
/// other check -- the size bound, the code-fence rejection, the operation, state
/// and transcript citation checks, and the requirement that an interpretation
/// cite at least one piece of retained evidence when operations exist -- is
/// language-independent and applies identically to every interpretation. A
/// Chinese interpretation citing an operation that does not exist is rejected
/// exactly as an English one is.
///
/// # Errors
/// Returns a human-readable validation error for malformed, uncited, or
/// ungrounded provider output. The message is diagnostic text for an operator
/// log, not report body content, and stays English in both languages.
pub fn validate_ai_interpretation(
    interpretation: &str,
    data: &AutomotiveReportData,
    language: ReportLanguage,
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
    let labels = AutomotiveLabels::for_language(language);
    for heading in [
        labels.ai_heading_evidence_backed,
        labels.ai_heading_hypotheses,
        labels.ai_heading_missing_evidence,
        labels.ai_heading_next_actions,
    ] {
        let heading = format!("### {heading}");
        if !trimmed.contains(&heading) {
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
///
/// The advisory notice above the prose is a guardrail: it is what tells a reader
/// that the section is not evidence and does not displace the fact sheet it
/// follows. It is rendered from `labels` so a reader of the Chinese report meets
/// it in the language the rest of the document is in. The model identifier is a
/// technical token, so it is never translated -- but it is provider-supplied
/// text landing inside a Markdown code span, so a backtick or pipe in it is
/// escaped before it is written, in either language.
#[must_use]
pub fn append_ai_interpretation(
    facts: &str,
    interpretation: &str,
    model: &str,
    labels: &AutomotiveLabels,
) -> String {
    format!(
        "{facts}\n\n## {section}\n\n> {notice}{sentence_break}{model_label}{colon}`{model}`{stop}\
         \n\n{interpretation}\n",
        facts = facts.trim_end(),
        section = labels.ai_interpretation_section,
        notice = labels.ai_advisory_notice,
        sentence_break = labels.narrative_sentence_break,
        model_label = labels.ai_model,
        colon = labels.label_colon,
        model = escape_inline(model),
        stop = labels.narrative_full_stop,
        interpretation = interpretation.trim()
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
            .join(labels.list_separator)
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
