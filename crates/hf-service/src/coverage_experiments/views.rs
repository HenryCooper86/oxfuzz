//! Public evidence DTOs redact every environment value and preserve integer precision.
use super::{
    serialize_time, CoverageExperimentBuildComparison, CoverageExperimentCursor,
    CoverageExperimentEdgeUnavailableReason, CoverageExperimentInputChange, CoverageExperimentKind,
    CoverageExperimentLimitation, CoverageExperimentStatus, CoverageExperimentTargetEntry,
    DateTime, Serialize, Utc, Uuid,
};
use hf_core::{engine::EngineKind, target::Sanitizer};
use hf_storage::{RunKind, RunStatus};

fn decimal<S: serde::Serializer, T: std::fmt::Display>(value: &T, s: S) -> Result<S::Ok, S::Error> {
    s.collect_str(value)
}
fn optional_decimal<S: serde::Serializer>(
    value: impl std::borrow::Borrow<Option<u64>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    value.borrow().map(|value| value.to_string()).serialize(s)
}
fn optional_time<S: serde::Serializer>(
    value: impl std::borrow::Borrow<Option<DateTime<Utc>>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    value
        .borrow()
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
        .serialize(s)
}

/// Public retained evidence with redacted environment values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageExperimentRunView {
    /// Exact durable evidence version, currently 1.
    pub schema_version: u32,
    /// Retained campaign identifier.
    pub run_id: Uuid,
    /// Persisted target identity.
    pub target_id: Uuid,
    /// Harness used by the retained campaign.
    pub harness_id: Uuid,
    /// Normalized absolute project owner, without filesystem resolution.
    pub project_root: String,
    /// Target label captured from its persisted row.
    pub target_symbol: String,
    /// Recorded active fuzzing engine.
    pub engine: EngineKind,
    /// Retained lifecycle status.
    pub status: RunStatus,
    /// Recorded proposal or campaign kind.
    pub kind: RunKind,
    /// Campaign allocation time.
    #[serde(serialize_with = "serialize_time")]
    pub started_at: DateTime<Utc>,
    /// First terminal time.
    #[serde(serialize_with = "serialize_time")]
    pub ended_at: DateTime<Utc>,
    /// Explicit whole-second duration, from 1 through 604800.
    pub duration_secs: u64,
    /// Recorded positive memory limit in MiB.
    #[serde(serialize_with = "decimal")]
    pub max_mem_mb: u64,
    /// Recorded positive CPU limit.
    pub max_cpus: u32,
    /// Recorded harness and campaign sanitizer.
    pub sanitizer: Sanitizer,
    /// Ordered environment keys, including duplicates; every value is redacted.
    pub engine_env: Vec<(String, String)>,
    /// Exact ordered engine arguments, including empty entries.
    pub engine_args: Vec<String>,
    /// Retained seed; absence does not resolve a replacement.
    #[serde(serialize_with = "optional_decimal")]
    pub seed: Option<u64>,
    /// Retained UTF-8 corpus path; display provenance only.
    pub seed_corpus: Option<String>,
    /// Optional replay parent; display provenance only.
    pub replay_of: Option<Uuid>,
    /// SHA-256 of exact retained harness source.
    pub harness_rev: String,
    /// SHA-256 of the executed harness artifact.
    pub binary_rev: String,
    /// SHA-256 of staged target inputs.
    pub source_rev: String,
    /// SHA-256 of the starting corpus snapshot.
    pub corpus_rev: String,
    /// Exact typed immutable Docker image revision.
    pub sandbox_rev: String,
    /// Optional composite context digest; retained without comparison.
    pub context_rev: Option<String>,
    /// Optional nonnegative recorded peak count.
    #[serde(serialize_with = "optional_decimal")]
    pub edges: Option<u64>,
    /// Exact Phase 6 compilation inputs, or explicit legacy absence.
    pub build_inputs: Option<CoverageExperimentBuildInputsView>,
}
impl From<hf_storage::CoverageExperimentRunEvidenceV1> for CoverageExperimentRunView {
    fn from(value: hf_storage::CoverageExperimentRunEvidenceV1) -> Self {
        Self {
            schema_version: value.schema_version,
            run_id: value.run_id,
            target_id: value.target_id,
            harness_id: value.harness_id,
            project_root: value.project_root,
            target_symbol: value.target_symbol,
            engine: value.engine,
            status: value.status,
            kind: value.kind,
            started_at: value.started_at,
            ended_at: value.ended_at,
            duration_secs: value.duration_secs,
            max_mem_mb: value.max_mem_mb,
            max_cpus: value.max_cpus,
            sanitizer: value.sanitizer,
            engine_env: value
                .engine_env
                .into_iter()
                .map(|(key, _)| (key, "[REDACTED]".to_owned()))
                .collect(),
            engine_args: value.engine_args,
            seed: value.seed,
            seed_corpus: value.seed_corpus,
            replay_of: value.replay_of,
            harness_rev: value.harness_rev,
            binary_rev: value.binary_rev,
            source_rev: value.source_rev,
            corpus_rev: value.corpus_rev,
            sandbox_rev: value.sandbox_rev,
            context_rev: value.context_rev,
            edges: value.edges,
            build_inputs: value.build_inputs.map(Into::into),
        }
    }
}

/// Public retained evidence with redacted environment values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageExperimentResultView {
    /// Exact durable evidence version, currently 1.
    pub schema_version: u32,
    /// Exact attached campaign snapshot.
    pub run: CoverageExperimentRunView,
    /// Descriptive intended-input difference.
    pub input_change: CoverageExperimentInputChange,
    /// Availability of captured build comparison.
    pub build_comparison: CoverageExperimentBuildComparison,
    /// Descriptive peak-count delta or reason for absence.
    pub edge_comparison: CoverageExperimentEdgeView,
    /// Explicit absence of exact run-scoped function coverage.
    pub target_entry: CoverageExperimentTargetEntry,
    /// Sorted unique stable limitation codes.
    pub limitations: Vec<CoverageExperimentLimitation>,
}
impl From<hf_storage::CoverageExperimentResultEvidenceV1> for CoverageExperimentResultView {
    fn from(value: hf_storage::CoverageExperimentResultEvidenceV1) -> Self {
        Self {
            schema_version: value.schema_version,
            run: value.run.into(),
            input_change: value.input_change,
            build_comparison: value.build_comparison,
            edge_comparison: value.edge_comparison.into(),
            target_entry: value.target_entry,
            limitations: value.limitations,
        }
    }
}

/// Public retained evidence with redacted environment values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageExperimentView {
    /// Immutable proposal identifier.
    pub id: Uuid,
    /// Exact durable evidence version, currently 1.
    pub schema_version: u32,
    /// Normalized absolute project owner, without filesystem resolution.
    pub project_root: String,
    /// Persisted target identity.
    pub target_id: Uuid,
    /// Target label captured from its persisted row.
    pub target_symbol: String,
    /// Retained baseline campaign identifier.
    pub baseline_run_id: Uuid,
    /// Recorded proposal or campaign kind.
    pub kind: CoverageExperimentKind,
    /// Operator-reviewed goal function text.
    pub goal_function: String,
    /// Operator-written hypothesis.
    pub hypothesis: String,
    /// Explicit whole-second duration, from 1 through 604800.
    pub duration_secs: u64,
    /// Immutable baseline campaign snapshot.
    pub baseline: CoverageExperimentRunView,
    /// Retained lifecycle status.
    pub status: CoverageExperimentStatus,
    /// One terminal attachment, if completed.
    pub result: Option<CoverageExperimentResultView>,
    /// Exact retained reason, if cancelled.
    pub cancellation_reason: Option<String>,
    /// Immutable proposal creation time.
    #[serde(serialize_with = "serialize_time")]
    pub created_at: DateTime<Utc>,
    /// Creation time or first terminal time.
    #[serde(serialize_with = "serialize_time")]
    pub updated_at: DateTime<Utc>,
    /// First terminal time.
    #[serde(serialize_with = "optional_time")]
    pub ended_at: Option<DateTime<Utc>>,
    /// Hypotheses are operator-supplied intent, never observed facts.
    pub hypothesis_origin: CoverageExperimentHypothesisOrigin,
}
impl From<hf_storage::CoverageExperimentRecord> for CoverageExperimentView {
    fn from(value: hf_storage::CoverageExperimentRecord) -> Self {
        Self {
            id: value.id,
            schema_version: value.schema_version,
            project_root: value.project_root,
            target_id: value.target_id,
            target_symbol: value.target_symbol,
            baseline_run_id: value.baseline_run_id,
            kind: value.kind,
            goal_function: value.goal_function,
            hypothesis: value.hypothesis,
            duration_secs: value.duration_secs,
            baseline: value.baseline.into(),
            status: value.status,
            result: value.result.map(Into::into),
            cancellation_reason: value.cancellation_reason,
            created_at: value.created_at,
            updated_at: value.updated_at,
            ended_at: value.ended_at,
            hypothesis_origin: CoverageExperimentHypothesisOrigin::OperatorSupplied,
        }
    }
}

/// Author of the proposal's hypothesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageExperimentHypothesisOrigin {
    /// Operator-reviewed free text, not a measured finding.
    OperatorSupplied,
}
/// Exact retained build inputs; timestamps have the canonical presentation encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageExperimentBuildInputsView {
    pub harness_id: Uuid,
    pub project_root: String,
    pub profile_sha256: Option<String>,
    pub compile_database_sha256: Option<String>,
    pub compile_flags_sha256: String,
    pub sandbox_image_id: String,
    pub build_input_sha256: String,
    #[serde(serialize_with = "serialize_time")]
    pub created_at: DateTime<Utc>,
}
impl From<hf_storage::HarnessBuildInputsRecord> for CoverageExperimentBuildInputsView {
    fn from(value: hf_storage::HarnessBuildInputsRecord) -> Self {
        Self {
            harness_id: value.harness_id,
            project_root: value.project_root,
            profile_sha256: value.profile_sha256,
            compile_database_sha256: value.compile_database_sha256,
            compile_flags_sha256: value.compile_flags_sha256,
            sandbox_image_id: value.sandbox_image_id,
            build_input_sha256: value.build_input_sha256,
            created_at: value.created_at,
        }
    }
}
/// Recorded aggregate counts and their descriptive signed difference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CoverageExperimentEdgeView {
    /// No causal or function-entry claim is implied by these counts.
    Observed {
        #[serde(serialize_with = "decimal")]
        baseline_edges: u64,
        #[serde(serialize_with = "decimal")]
        result_edges: u64,
        #[serde(serialize_with = "decimal")]
        delta: i64,
    },
    /// A required measurement or build snapshot is absent.
    Unavailable {
        reason_code: CoverageExperimentEdgeUnavailableReason,
    },
}
impl From<hf_storage::CoverageExperimentEdgeComparison> for CoverageExperimentEdgeView {
    fn from(value: hf_storage::CoverageExperimentEdgeComparison) -> Self {
        match value {
            hf_storage::CoverageExperimentEdgeComparison::Observed {
                baseline_edges,
                result_edges,
                delta,
            } => Self::Observed {
                baseline_edges,
                result_edges,
                delta,
            },
            hf_storage::CoverageExperimentEdgeComparison::Unavailable { reason_code } => {
                Self::Unavailable { reason_code }
            }
        }
    }
}
/// Bounded history with an explicit continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageExperimentPage {
    pub schema_version: u32,
    pub items: Vec<CoverageExperimentView>,
    pub next_cursor: Option<CoverageExperimentCursor>,
}
