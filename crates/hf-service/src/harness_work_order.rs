//! Deterministic Harness Work Order v2 packets.
//!
//! Packets carry retained authoring evidence only. Constructing, verifying, and
//! rendering a packet never invokes a provider, build, runtime, or fuzzer.

use std::{error::Error, fmt, fmt::Write as _, path::Path};

use chrono::{DateTime, Utc};
use hf_core::{
    engine::EngineKind,
    error::ClassifiedError,
    runtime::{classify_fixed_sandbox_include_path, FixedSandboxIncludePath},
    target::TargetLanguage,
};
use hf_harness::{harness_rules, HarnessRuleSummary, LintSeverity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::VerdictLevel;

/// Current serialized Harness Work Order schema.
pub const HARNESS_WORK_ORDER_SCHEMA_VERSION: u32 = 2;

/// Maximum serialized packet size retained by storage.
pub const MAX_WORK_ORDER_PACKET_BYTES: usize = 262_144;
/// Maximum source excerpt size carried by a packet.
pub const MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES: usize = 65_536;
/// Maximum source excerpt line count carried by a packet.
pub const MAX_WORK_ORDER_SOURCE_EXCERPT_LINES: usize = 60;
/// Maximum retained seed references carried by a packet.
pub const MAX_WORK_ORDER_SEEDS: usize = 20;

/// One deterministic, content-addressed authoring packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessWorkOrder {
    /// Serialization version for this packet.
    pub schema_version: u32,
    /// Lowercase SHA-256 of the canonical payload JSON.
    pub id: String,
    /// Evidence consumed by an authoring tool or a human.
    pub payload: HarnessWorkOrderPayload,
}

/// Provenance supplied by the authoring party for one imported submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOrderSubmissionOrigin {
    /// A submission written directly by a person.
    Human,
    /// A submission returned by an external authoring tool.
    ExternalTool {
        /// Label for the external tool.
        tool: String,
        /// Optional model label reported by the external tool.
        model: Option<String>,
        /// Optional response identifier reported by the external tool.
        response_id: Option<String>,
    },
}

/// Request to retain one immutable externally authored harness submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportHarnessWorkOrderSubmissionRequest {
    /// Content-addressed parent work-order identifier.
    pub work_order_id: String,
    /// UTF-8 harness source, preserved exactly as supplied.
    pub source: String,
    /// Unverified authoring provenance.
    pub origin: WorkOrderSubmissionOrigin,
    /// Optional earlier submission repaired by this submission.
    pub parent_submission_id: Option<Uuid>,
}

/// One immutable imported harness submission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessWorkOrderSubmission {
    /// Durable submission identifier.
    pub id: Uuid,
    /// Content-addressed parent work-order identifier.
    pub work_order_id: String,
    /// UTF-8 harness source as originally supplied.
    pub source: String,
    /// Lowercase SHA-256 of `source` bytes.
    pub source_sha256: String,
    /// Unverified authoring provenance.
    pub origin: WorkOrderSubmissionOrigin,
    /// Optional earlier submission repaired by this submission.
    pub parent_submission_id: Option<Uuid>,
    /// Deterministic lint findings recorded at import.
    pub lint: Vec<hf_harness::LintFinding>,
    /// First durable submission timestamp.
    pub submitted_at: DateTime<Utc>,
}

/// Bounded terminal evidence retained for one qualification attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessWorkOrderAttemptResult {
    /// Whether sandbox compilation completed successfully.
    pub compiled: bool,
    /// Deterministic smoke assessment when smoke produced an outcome.
    pub smoke_verdict: Option<VerdictLevel>,
    /// Immutable repair ancestry depth used by later ranking.
    pub repair_depth: u32,
    /// SHA-256 of the exact reviewed source when review reached that evidence.
    pub source_sha256: Option<String>,
    /// SHA-256 of the exact reviewed executable when review reached that evidence.
    pub binary_sha256: Option<String>,
    /// Observed smoke throughput when smoke completed.
    pub execs_per_sec: Option<f64>,
    /// Observed smoke crash count when smoke completed.
    pub crashes: Option<u32>,
}

/// Public view of one durable harness qualification attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarnessWorkOrderAttempt {
    /// Durable attempt identifier.
    pub id: Uuid,
    /// Immutable submission being qualified.
    pub submission_id: Uuid,
    /// Current or terminal durable outcome.
    pub status: hf_storage::HarnessWorkOrderAttemptStatus,
    /// Current service-owned qualification stage.
    pub current_stage: hf_storage::HarnessWorkOrderAttemptStage,
    /// Persisted compiled harness revision, when compilation succeeded.
    pub harness_id: Option<Uuid>,
    /// Persisted smoke-run identity once smoke allocated its durable run row.
    pub smoke_run_id: Option<Uuid>,
    /// Bounded terminal evidence.
    pub result: Option<HarnessWorkOrderAttemptResult>,
    /// Stable terminal failure category.
    pub failure_code: Option<String>,
    /// Sanitized bounded terminal failure detail.
    pub failure_message: Option<String>,
    /// First durable attempt timestamp.
    pub started_at: DateTime<Utc>,
    /// Latest durable transition timestamp.
    pub updated_at: DateTime<Utc>,
    /// Terminal timestamp, absent only while running.
    pub ended_at: Option<DateTime<Utc>>,
}

/// Deterministic ordering of retained qualification attempts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessWorkOrderRanking {
    /// Attempt identifiers ordered from strongest to weakest evidence.
    pub attempt_ids: Vec<Uuid>,
    /// Highest-ranked attempt that compiled, or `None` when none compiled.
    pub winner_attempt_id: Option<Uuid>,
}

/// The evidence covered by a Harness Work Order identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessWorkOrderPayload {
    /// Stable discovery evidence for the selected target.
    pub target: WorkOrderTargetEvidence,
    /// Selected fuzzing engine.
    pub engine: EngineKind,
    /// Bounded source evidence for the target.
    pub source: WorkOrderSourceEvidence,
    /// Normalized compilation evidence.
    pub compile_context: WorkOrderCompileContext,
    /// Lowercase SHA-256 of canonical compilation evidence JSON.
    pub compile_context_sha256: String,
    /// Harness lint rules the author must follow.
    pub harness_rules: Vec<WorkOrderRule>,
    /// Content-addressed seed references.
    pub seeds: Vec<WorkOrderSeedReference>,
    /// Semantic validation operations in execution order.
    pub validation_steps: Vec<WorkOrderStep>,
}

/// Stable discovery evidence for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderTargetEvidence {
    /// Discovered function or entrypoint name.
    pub symbol: String,
    /// Discovered signature when available.
    pub signature: Option<String>,
    /// Language used by the target and harness.
    pub language: TargetLanguage,
    /// Source path relative to the project root.
    pub relative_source: String,
    /// One-based source line containing the target.
    pub line: u32,
    /// Discovery reason retained for the target selection.
    pub rationale: String,
}

/// Bounded source evidence for one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderSourceEvidence {
    /// Candidate declaration and body excerpt.
    pub excerpt: String,
    /// Whether the excerpt was cut by a configured bound.
    pub excerpt_truncated: bool,
    /// Lowercase SHA-256 of the complete candidate source file.
    pub sha256: String,
}

/// Normalized compilation evidence for the target translation unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderCompileContext {
    /// Project-relative include directories.
    pub include_dirs: Vec<String>,
    /// Preprocessor definitions without their compiler spelling.
    pub defines: Vec<String>,
    /// Language-standard compiler flag when recorded.
    pub std_flag: Option<String>,
    /// Additional retained compiler flags.
    pub extra_flags: Vec<String>,
    /// Number of compile-database units contributing this context.
    pub compile_units: usize,
    /// Compile flags excluded from the portable context.
    pub dropped_flags: Vec<String>,
}

/// One harness lint rule rendered with the packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderRule {
    /// Stable harness-lint identifier.
    pub id: String,
    /// Whether violating this rule blocks qualification.
    pub blocking: bool,
    /// Explanation displayed to the author.
    pub message: String,
}

/// One content-addressed seed candidate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkOrderSeedReference {
    /// Lowercase SHA-256 of the seed content.
    pub sha256: String,
    /// Seed content size in bytes.
    pub size: u64,
}

/// A semantic validation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOrderStep {
    /// Import an externally authored candidate.
    Import,
    /// Qualify one immutable submission.
    Qualify,
    /// Rank retained qualification attempts.
    Rank,
    /// Promote one active, smoke-passed attempt.
    Promote,
    /// Run a post-promotion campaign for the given duration.
    RunCampaign { duration_secs: u64 },
    /// Collect post-promotion coverage evidence.
    Coverage,
}

/// A value deliberately absent from an argv array until an operator supplies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOrderPlaceholder {
    /// Project root supplied by the operator running the packet locally.
    Project,
    /// Path to the authored source file.
    SourceFile,
    /// Provenance label accepted by `work-order import`.
    SubmissionOrigin,
    /// Identifier of one imported submission.
    SubmissionId,
    /// Identifiers of the attempts to rank.
    AttemptIds,
    /// Identifier of one qualification attempt.
    AttemptId,
}

/// One argv item in a validation command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOrderArg {
    /// A concrete, packet-derived argument.
    Literal(String),
    /// An operator-supplied value with declared meaning.
    Placeholder(WorkOrderPlaceholder),
}

/// A rendered command description for one semantic validation operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkOrderCommand {
    /// Operation represented by this argv array.
    pub step: WorkOrderStep,
    /// Arguments for a JSON client or a POSIX renderer.
    pub argv: Vec<WorkOrderArg>,
    /// Whether the service requires a human approval event before execution.
    pub approval_required: bool,
}

/// Category used by clients to decide whether an operation can be retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkOrderErrorKind {
    /// Packet or request evidence is invalid.
    Validation,
    /// A durable record is absent.
    NotFound,
    /// A durable record conflicts with an immutable value.
    Conflict,
    /// A required service dependency is unavailable.
    Unavailable,
    /// A provider operation failed.
    Provider,
    /// Sandboxed build or execution failed.
    Sandbox,
    /// Durable storage failed.
    Storage,
    /// An unexpected service failure occurred.
    Internal,
}

/// Stable detail code returned by Harness Work Order service operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkOrderErrorCode {
    /// The operation requires durable storage.
    StorageRequired,
    /// A presentation input is not valid for its declared request field.
    InvalidRequest,
    /// A UUID presentation input is malformed.
    InvalidIdentifier,
    /// Packet or compile-context digest verification failed.
    InvalidWorkOrderDigest,
    /// The packet schema is unsupported.
    UnsupportedWorkOrderSchema,
    /// Submitted source is empty.
    SourceEmpty,
    /// Source or packet evidence exceeds its configured size bound.
    SourceTooLarge,
    /// Submitted provenance is malformed.
    InvalidProvenance,
    /// A declared submission parent does not exist.
    ParentNotFound,
    /// A declared submission parent belongs to another work order.
    ParentWorkOrderMismatch,
    /// A work order already has its maximum number of submissions.
    SubmissionLimitReached,
    /// Qualification cannot run while lint has blocking findings.
    SubmissionHasBlockingLint,
    /// Retained source or compile evidence no longer matches the project.
    StaleWorkOrder,
    /// A recovery operation interrupted a running qualification attempt.
    AttemptInterrupted,
    /// Promotion requires a smoke-passed qualification attempt.
    AttemptNotSmokePassed,
    /// Promotion requires the exact active workspace revision.
    AttemptNotActive,
    /// A requested work order was not found.
    WorkOrderNotFound,
    /// A requested submission was not found.
    SubmissionNotFound,
    /// A requested qualification attempt was not found.
    AttemptNotFound,
    /// A durable attempt transition is invalid.
    InvalidTransition,
    /// Ranking accepts no more than the configured number of attempts.
    RankingLimitExceeded,
    /// A project-relative path was absolute or escaped the project root.
    InvalidProjectPath,
    /// The packet has more retained seed references than the schema allows.
    SeedLimitExceeded,
    /// The packet exceeds the durable packet size limit.
    WorkOrderTooLarge,
}

impl HarnessWorkOrderErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::StorageRequired => "storage_required",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::InvalidWorkOrderDigest => "invalid_work_order_digest",
            Self::UnsupportedWorkOrderSchema => "unsupported_work_order_schema",
            Self::SourceEmpty => "source_empty",
            Self::SourceTooLarge => "source_too_large",
            Self::InvalidProvenance => "invalid_provenance",
            Self::ParentNotFound => "parent_not_found",
            Self::ParentWorkOrderMismatch => "parent_work_order_mismatch",
            Self::SubmissionLimitReached => "submission_limit_reached",
            Self::SubmissionHasBlockingLint => "submission_has_blocking_lint",
            Self::StaleWorkOrder => "stale_work_order",
            Self::AttemptInterrupted => "attempt_interrupted",
            Self::AttemptNotSmokePassed => "attempt_not_smoke_passed",
            Self::AttemptNotActive => "attempt_not_active",
            Self::WorkOrderNotFound => "work_order_not_found",
            Self::SubmissionNotFound => "submission_not_found",
            Self::AttemptNotFound => "attempt_not_found",
            Self::InvalidTransition => "invalid_transition",
            Self::RankingLimitExceeded => "ranking_limit_exceeded",
            Self::InvalidProjectPath => "invalid_project_path",
            Self::SeedLimitExceeded => "seed_limit_exceeded",
            Self::WorkOrderTooLarge => "work_order_too_large",
        }
    }
}

/// Error returned by Harness Work Order service operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessWorkOrderError {
    /// Stable machine-readable detail code.
    pub code: HarnessWorkOrderErrorCode,
    /// Retry and presentation category.
    pub kind: HarnessWorkOrderErrorKind,
    /// Bounded human-readable explanation.
    pub message: String,
}

impl HarnessWorkOrderError {
    pub(crate) fn validation(code: HarnessWorkOrderErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            kind: HarnessWorkOrderErrorKind::Validation,
            message: message.into(),
        }
    }

    pub(crate) fn storage(message: impl Into<String>) -> Self {
        Self {
            code: HarnessWorkOrderErrorCode::StorageRequired,
            kind: HarnessWorkOrderErrorKind::Storage,
            message: message.into(),
        }
    }

    pub(crate) fn not_found(code: HarnessWorkOrderErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            kind: HarnessWorkOrderErrorKind::NotFound,
            message: message.into(),
        }
    }

    pub(crate) fn conflict(code: HarnessWorkOrderErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            kind: HarnessWorkOrderErrorKind::Conflict,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            kind: HarnessWorkOrderErrorKind::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for HarnessWorkOrderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl Error for HarnessWorkOrderError {}

impl From<HarnessWorkOrderError> for ClassifiedError {
    fn from(error: HarnessWorkOrderError) -> Self {
        let message = error.to_string();
        match error.kind {
            HarnessWorkOrderErrorKind::Provider => Self::Provider(message),
            HarnessWorkOrderErrorKind::Sandbox => Self::Sandbox(message),
            HarnessWorkOrderErrorKind::Storage => Self::Storage(message),
            HarnessWorkOrderErrorKind::Internal | HarnessWorkOrderErrorKind::Unavailable => {
                Self::Internal(message)
            }
            HarnessWorkOrderErrorKind::Validation
            | HarnessWorkOrderErrorKind::NotFound
            | HarnessWorkOrderErrorKind::Conflict => Self::Validation(message),
        }
    }
}

/// Build a canonical, content-addressed v2 packet from retained evidence.
pub fn build_work_order(
    payload: HarnessWorkOrderPayload,
) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
    let payload = canonical_payload(payload)?;
    let payload_json = canonical_json(&payload)?;
    let work_order = HarnessWorkOrder {
        schema_version: HARNESS_WORK_ORDER_SCHEMA_VERSION,
        id: sha256_hex(&payload_json),
        payload,
    };
    ensure_packet_size(&work_order)?;
    Ok(work_order)
}

/// Verify a retained packet's schema, canonicalization, and digest evidence.
pub fn verify_work_order(work_order: &HarnessWorkOrder) -> Result<(), HarnessWorkOrderError> {
    if work_order.schema_version != HARNESS_WORK_ORDER_SCHEMA_VERSION {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::UnsupportedWorkOrderSchema,
            format!(
                "schema {} is not supported; expected {HARNESS_WORK_ORDER_SCHEMA_VERSION}",
                work_order.schema_version
            ),
        ));
    }

    let canonical = canonical_payload(work_order.payload.clone())?;
    if canonical != work_order.payload {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "packet payload is not canonical",
        ));
    }
    let payload_json = canonical_json(&canonical)?;
    ensure_packet_size(work_order)?;
    if work_order.id != sha256_hex(&payload_json) {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "packet identifier does not match canonical payload",
        ));
    }
    Ok(())
}

/// Return semantic commands for the packet's declared validation operations.
#[must_use]
pub fn work_order_commands(work_order: &HarnessWorkOrder) -> Vec<WorkOrderCommand> {
    work_order
        .payload
        .validation_steps
        .iter()
        .cloned()
        .map(|step| command_for_step(work_order, step))
        .collect()
}

/// Remove credentials and absolute host paths from one bounded public
/// diagnostic.
#[must_use]
pub fn sanitize_work_order_diagnostic(message: &str, maximum_bytes: usize) -> String {
    let mut redact_next = false;
    let sanitized = message
        .split_whitespace()
        .map(|token| sanitize_diagnostic_token(token, &mut redact_next))
        .collect::<Vec<_>>()
        .join(" ");
    bounded_utf8(&sanitized, maximum_bytes)
        .trim_end()
        .to_owned()
}

fn sanitize_diagnostic_token(token: &str, redact_next: &mut bool) -> String {
    if *redact_next {
        *redact_next = false;
        return "<redacted>".to_owned();
    }

    let significant_end = token
        .trim_end_matches(|character: char| character.is_ascii_punctuation())
        .len();
    let normalized = token[..significant_end]
        .trim_start_matches(|character: char| character.is_ascii_punctuation());
    if normalized.eq_ignore_ascii_case("bearer") {
        *redact_next = true;
        return "Bearer".to_owned();
    }
    if secret_key(normalized) {
        *redact_next = true;
        return token.to_owned();
    }
    if secret_value_starts(normalized) {
        return "<redacted>".to_owned();
    }

    let mut at_word_start = true;
    for (index, character) in token.char_indices() {
        if at_word_start {
            if let Some(redacted) = redact_marker_at(token, index, significant_end, redact_next) {
                return redacted;
            }
        }
        at_word_start = !character.is_alphanumeric();
    }
    redact_absolute_path(token).unwrap_or_else(|| token.to_owned())
}

fn redact_marker_at(
    token: &str,
    index: usize,
    significant_end: usize,
    redact_next: &mut bool,
) -> Option<String> {
    let suffix = &token[index..];
    if marker_is_complete(token, index, significant_end, "bearer") {
        *redact_next = true;
        return Some(format!("{}Bearer", &token[..index]));
    }
    if let Some(key) = secret_key_at(suffix) {
        if marker_is_complete(token, index, significant_end, key) {
            *redact_next = true;
            return Some(token.to_owned());
        }
        if let Some(delimiter_end) = assignment_delimiter(suffix, key.len()) {
            let value = &suffix[delimiter_end..];
            if value.is_empty() || trim_ascii_punctuation(value).eq_ignore_ascii_case("bearer") {
                *redact_next = true;
            }
            return Some(format!(
                "{}{}<redacted>",
                &token[..index],
                &suffix[..delimiter_end]
            ));
        }
    }
    if ascii_case_prefix(suffix, "authorization") {
        if let Some(delimiter_end) = assignment_delimiter(suffix, "authorization".len()) {
            if trim_ascii_punctuation(&suffix[delimiter_end..]).eq_ignore_ascii_case("bearer") {
                *redact_next = true;
            }
            return Some(format!(
                "{}{}<redacted>",
                &token[..index],
                &suffix[..delimiter_end]
            ));
        }
    }
    secret_value_starts(suffix).then(|| format!("{}<redacted>", &token[..index]))
}

fn assignment_delimiter(value: &str, marker_bytes: usize) -> Option<usize> {
    for (index, character) in value[marker_bytes..].char_indices() {
        if matches!(character, '=' | ':') {
            return Some(marker_bytes + index + character.len_utf8());
        }
        if !character.is_ascii_punctuation() {
            return None;
        }
    }
    None
}

fn marker_is_complete(token: &str, index: usize, significant_end: usize, marker: &str) -> bool {
    index + marker.len() == significant_end && ascii_case_prefix(&token[index..], marker)
}

fn ascii_case_prefix(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn trim_ascii_punctuation(value: &str) -> &str {
    value.trim_matches(|character: char| character.is_ascii_punctuation())
}

const DIAGNOSTIC_SECRET_KEYS: [&str; 6] = [
    "password", "secret", "token", "api_key", "api-key", "apikey",
];

fn secret_key(value: &str) -> bool {
    DIAGNOSTIC_SECRET_KEYS
        .into_iter()
        .any(|key| value.eq_ignore_ascii_case(key))
}

fn secret_key_at(value: &str) -> Option<&'static str> {
    DIAGNOSTIC_SECRET_KEYS
        .into_iter()
        .find(|key| ascii_case_prefix(value, key))
}

const DIAGNOSTIC_SECRET_PREFIXES: [&str; 7] = [
    "sk-",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "hf_",
];

fn secret_value_starts(value: &str) -> bool {
    DIAGNOSTIC_SECRET_PREFIXES
        .into_iter()
        .any(|prefix| ascii_case_prefix(value, prefix))
        || (value.len() > 8 && ascii_case_prefix(value, "akia"))
}

fn redact_absolute_path(token: &str) -> Option<String> {
    let bytes = token.as_bytes();
    for index in 0..bytes.len() {
        let starts_after_non_word =
            index == 0 || (!bytes[index - 1].is_ascii_alphanumeric() && bytes[index - 1] != b'_');
        let unix = bytes[index] == b'/';
        let windows = bytes.get(index..index + 3).is_some_and(|part| {
            part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
        });
        if starts_after_non_word && (unix || windows) {
            return Some(format!("{}<redacted-path>", &token[..index]));
        }
    }
    None
}

fn bounded_utf8(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Quote one concrete argument for a POSIX shell command display.
#[must_use]
pub fn quote_posix_arg(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"@%_+=:,./-".contains(&byte))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Render a packet for a human author without executing any operation.
#[must_use]
pub fn render_work_order(work_order: &HarnessWorkOrder) -> String {
    let payload = &work_order.payload;
    let mut output = String::new();
    let line = |output: &mut String, text: &str| {
        output.push_str(text);
        output.push('\n');
    };

    line(&mut output, "# Harness Work Order v2");
    line(&mut output, "");
    line(&mut output, &format!("- Identifier: `{}`", work_order.id));
    line(
        &mut output,
        &format!("- Engine: `{}`", payload.engine.as_str()),
    );
    line(&mut output, "");
    line(&mut output, "## Target evidence");
    line(&mut output, "");
    line(
        &mut output,
        &format!("- Symbol: `{}`", payload.target.symbol),
    );
    match &payload.target.signature {
        Some(signature) => line(&mut output, &format!("- Signature: `{signature}`")),
        None => line(&mut output, "- Signature: not recorded"),
    }
    line(
        &mut output,
        &format!("- Language: `{}`", payload.target.language.as_str()),
    );
    line(
        &mut output,
        &format!(
            "- Source: `{}:{}`",
            payload.target.relative_source, payload.target.line
        ),
    );
    line(
        &mut output,
        &format!("- Rationale: {}", payload.target.rationale),
    );
    line(&mut output, "");
    line(&mut output, "## Source evidence");
    line(&mut output, "");
    line(
        &mut output,
        &format!("- SHA-256: `{}`", payload.source.sha256),
    );
    line(
        &mut output,
        &format!("- Truncated: {}", payload.source.excerpt_truncated),
    );
    line(&mut output, "```text");
    line(&mut output, payload.source.excerpt.trim_end());
    line(&mut output, "```");
    line(&mut output, "");
    line(&mut output, "## Compile context");
    line(&mut output, "");
    line(
        &mut output,
        &format!("- SHA-256: `{}`", payload.compile_context_sha256),
    );
    line(
        &mut output,
        &format!(
            "- Translation units: {}",
            payload.compile_context.compile_units
        ),
    );
    render_values(
        &mut output,
        "Include directories",
        &payload.compile_context.include_dirs,
    );
    render_values(&mut output, "Defines", &payload.compile_context.defines);
    match &payload.compile_context.std_flag {
        Some(std_flag) => line(&mut output, &format!("- Language standard: `{std_flag}`")),
        None => line(&mut output, "- Language standard: not recorded"),
    }
    render_values(
        &mut output,
        "Extra flags",
        &payload.compile_context.extra_flags,
    );
    render_values(
        &mut output,
        "Dropped flags",
        &payload.compile_context.dropped_flags,
    );
    line(&mut output, "");
    line(&mut output, "## Harness rules");
    line(&mut output, "");
    for rule in &payload.harness_rules {
        let severity = if rule.blocking {
            "blocking"
        } else {
            "advisory"
        };
        line(
            &mut output,
            &format!("- `{}` ({severity}): {}", rule.id, rule.message),
        );
    }
    line(&mut output, "");
    line(&mut output, "## Seed references");
    line(&mut output, "");
    if payload.seeds.is_empty() {
        line(&mut output, "- None retained");
    } else {
        for seed in &payload.seeds {
            line(
                &mut output,
                &format!("- `{}` ({} bytes)", seed.sha256, seed.size),
            );
        }
    }
    line(&mut output, "");
    line(&mut output, "## Validation steps");
    line(&mut output, "");
    for command in work_order_commands(work_order) {
        line(&mut output, &format!("### {}", step_label(&command.step)));
        if command.approval_required {
            line(&mut output, "Approval required before execution.");
        }
        line(&mut output, "```sh");
        line(&mut output, &render_command(&command));
        line(&mut output, "```");
        line(&mut output, "");
    }
    output
}

/// Return the lint rules applicable to one target language.
#[must_use]
pub fn work_order_rules(language: TargetLanguage) -> Vec<WorkOrderRule> {
    let mut rules = harness_rules()
        .into_iter()
        .filter(|rule: &HarnessRuleSummary| rule.languages.contains(&language.as_str()))
        .map(|rule| WorkOrderRule {
            id: rule.id,
            blocking: rule.severity == LintSeverity::Error,
            message: rule.message,
        })
        .collect::<Vec<_>>();
    normalize_rules(&mut rules);
    rules
}

fn canonical_payload(
    mut payload: HarnessWorkOrderPayload,
) -> Result<HarnessWorkOrderPayload, HarnessWorkOrderError> {
    validate_source_evidence(&payload.source)?;
    validate_project_relative_path(&payload.target.relative_source)?;
    for include_dir in &payload.compile_context.include_dirs {
        validate_compile_include_path(include_dir)?;
    }
    normalize_strings(&mut payload.compile_context.include_dirs);
    normalize_strings(&mut payload.compile_context.defines);
    normalize_strings(&mut payload.compile_context.extra_flags);
    normalize_strings(&mut payload.compile_context.dropped_flags);
    normalize_rules(&mut payload.harness_rules);
    normalize_seeds(&mut payload.seeds)?;
    normalize_steps(&mut payload.validation_steps);
    payload.compile_context_sha256 = sha256_hex(&canonical_json(&payload.compile_context)?);
    Ok(payload)
}

fn validate_source_evidence(source: &WorkOrderSourceEvidence) -> Result<(), HarnessWorkOrderError> {
    if source.excerpt.is_empty() {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceEmpty,
            "source excerpt is empty",
        ));
    }
    if source.excerpt.len() > MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES
        || source.excerpt.lines().count() > MAX_WORK_ORDER_SOURCE_EXCERPT_LINES
    {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceTooLarge,
            format!(
                "source excerpt exceeds {MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES} bytes or \
                 {MAX_WORK_ORDER_SOURCE_EXCERPT_LINES} lines"
            ),
        ));
    }
    validate_sha256(&source.sha256, "source SHA-256")
}

fn validate_project_relative_path(value: &str) -> Result<(), HarnessWorkOrderError> {
    let windows_drive = value.len() >= 3
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'/' | b'\\');
    if value.is_empty()
        || value.starts_with('/')
        || Path::new(value).is_absolute()
        || value.starts_with('\\')
        || windows_drive
        || value.split(['/', '\\']).any(|component| component == "..")
    {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "packet paths must be project-relative and must not escape the project",
        ));
    }
    Ok(())
}

fn validate_compile_include_path(value: &str) -> Result<(), HarnessWorkOrderError> {
    match classify_fixed_sandbox_include_path(value) {
        FixedSandboxIncludePath::Canonical => Ok(()),
        FixedSandboxIncludePath::Invalid => Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "packet path is a noncanonical fixed sandbox include path",
        )),
        FixedSandboxIncludePath::Outside => validate_project_relative_path(value),
    }
}

fn validate_sha256(value: &str, subject: &str) -> Result<(), HarnessWorkOrderError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            format!("{subject} must be a lowercase SHA-256 digest"),
        ));
    }
    Ok(())
}

fn normalize_strings(values: &mut Vec<String>) {
    values.sort_unstable();
    values.dedup();
}

fn normalize_rules(rules: &mut Vec<WorkOrderRule>) {
    rules.sort_by(|left, right| {
        (&left.id, left.blocking, &left.message).cmp(&(&right.id, right.blocking, &right.message))
    });
    rules.dedup();
}

fn normalize_seeds(seeds: &mut Vec<WorkOrderSeedReference>) -> Result<(), HarnessWorkOrderError> {
    for seed in &*seeds {
        validate_sha256(&seed.sha256, "seed SHA-256")?;
    }
    seeds.sort_unstable();
    seeds.dedup();
    if seeds.len() > MAX_WORK_ORDER_SEEDS {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SeedLimitExceeded,
            format!("packet has more than {MAX_WORK_ORDER_SEEDS} seed references"),
        ));
    }
    Ok(())
}

fn normalize_steps(steps: &mut Vec<WorkOrderStep>) {
    steps.sort_by_key(step_sort_key);
    steps.dedup();
}

fn step_sort_key(step: &WorkOrderStep) -> (u8, u64) {
    match step {
        WorkOrderStep::Import => (0, 0),
        WorkOrderStep::Qualify => (1, 0),
        WorkOrderStep::Rank => (2, 0),
        WorkOrderStep::Promote => (3, 0),
        WorkOrderStep::RunCampaign { duration_secs } => (4, *duration_secs),
        WorkOrderStep::Coverage => (5, 0),
    }
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, HarnessWorkOrderError> {
    serde_json::to_vec(value).map_err(|error| {
        HarnessWorkOrderError::internal(format!("serialize canonical packet evidence: {error}"))
    })
}

fn ensure_packet_size(work_order: &HarnessWorkOrder) -> Result<(), HarnessWorkOrderError> {
    let packet_json = canonical_json(work_order)?;
    if packet_json.len() > MAX_WORK_ORDER_PACKET_BYTES {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::WorkOrderTooLarge,
            format!("packet exceeds {MAX_WORK_ORDER_PACKET_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn command_for_step(work_order: &HarnessWorkOrder, step: WorkOrderStep) -> WorkOrderCommand {
    let literal = |value: &str| WorkOrderArg::Literal(value.to_owned());
    let value = |value: String| WorkOrderArg::Literal(value);
    let placeholder = WorkOrderArg::Placeholder;
    let (argv, approval_required) = match &step {
        WorkOrderStep::Import => (
            vec![
                literal("oxfuzz"),
                literal("work-order"),
                literal("import"),
                literal("--work-order"),
                value(work_order.id.clone()),
                literal("--source"),
                placeholder(WorkOrderPlaceholder::SourceFile),
                literal("--origin"),
                placeholder(WorkOrderPlaceholder::SubmissionOrigin),
            ],
            false,
        ),
        WorkOrderStep::Qualify => (
            vec![
                literal("oxfuzz"),
                literal("work-order"),
                literal("qualify"),
                literal("--submission"),
                placeholder(WorkOrderPlaceholder::SubmissionId),
            ],
            true,
        ),
        WorkOrderStep::Rank => (
            vec![
                literal("oxfuzz"),
                literal("work-order"),
                literal("rank"),
                literal("--attempt"),
                placeholder(WorkOrderPlaceholder::AttemptIds),
            ],
            false,
        ),
        WorkOrderStep::Promote => (
            vec![
                literal("oxfuzz"),
                literal("work-order"),
                literal("promote"),
                literal("--attempt"),
                placeholder(WorkOrderPlaceholder::AttemptId),
            ],
            true,
        ),
        WorkOrderStep::RunCampaign { duration_secs } => (
            vec![
                literal("oxfuzz"),
                literal("run"),
                placeholder(WorkOrderPlaceholder::Project),
                literal("--target"),
                value(work_order_target_selector(work_order)),
                literal("--engine"),
                literal(work_order.payload.engine.as_str()),
                literal("--lang"),
                literal(work_order.payload.target.language.as_str()),
                literal("--duration"),
                value(format!("{duration_secs}s")),
            ],
            true,
        ),
        WorkOrderStep::Coverage => (
            vec![
                literal("oxfuzz"),
                literal("coverage"),
                placeholder(WorkOrderPlaceholder::Project),
                literal("--target"),
                value(work_order_target_selector(work_order)),
            ],
            false,
        ),
    };
    WorkOrderCommand {
        step,
        argv,
        approval_required,
    }
}

fn work_order_target_selector(work_order: &HarnessWorkOrder) -> String {
    format!(
        "{}::{}",
        work_order.payload.target.relative_source, work_order.payload.target.symbol
    )
}

fn render_values(output: &mut String, label: &str, values: &[String]) {
    if values.is_empty() {
        writeln!(output, "- {label}: none recorded").expect("writing to String cannot fail");
        return;
    }
    writeln!(output, "- {label}:").expect("writing to String cannot fail");
    for value in values {
        writeln!(output, "  - `{value}`").expect("writing to String cannot fail");
    }
}

fn render_command(command: &WorkOrderCommand) -> String {
    command
        .argv
        .iter()
        .map(|argument| match argument {
            WorkOrderArg::Literal(value) => quote_posix_arg(value),
            WorkOrderArg::Placeholder(placeholder) => match placeholder {
                WorkOrderPlaceholder::Project => "<project>".to_owned(),
                WorkOrderPlaceholder::SourceFile => "<source-file>".to_owned(),
                WorkOrderPlaceholder::SubmissionOrigin => "<submission-origin>".to_owned(),
                WorkOrderPlaceholder::SubmissionId => "<submission-id>".to_owned(),
                WorkOrderPlaceholder::AttemptIds => "<attempt-id>...".to_owned(),
                WorkOrderPlaceholder::AttemptId => "<attempt-id>".to_owned(),
            },
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn step_label(step: &WorkOrderStep) -> &'static str {
    match step {
        WorkOrderStep::Import => "Import",
        WorkOrderStep::Qualify => "Qualify",
        WorkOrderStep::Rank => "Rank",
        WorkOrderStep::Promote => "Promote",
        WorkOrderStep::RunCampaign { .. } => "Run campaign",
        WorkOrderStep::Coverage => "Coverage",
    }
}
