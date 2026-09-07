//! Immutable proposals, retained campaign evidence, and experiment lifecycle.
mod lifecycle;
mod source;
mod validation;

use crate::{HarnessBuildInputsRecord, RunKind, RunStatus};
use chrono::{DateTime, Utc};
use hf_core::{engine::EngineKind, target::Sanitizer};
pub(crate) use lifecycle::run_reference;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! experiment_enum {
    ($name:ident, $doc:literal, [$($variant:ident),+ $(,)?]) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $(#[doc = stringify!($variant)] $variant),+ }
    }
}
experiment_enum!(
    CoverageExperimentKind,
    "Reviewed intervention kind.",
    [GrowCorpus, RefineHarness]
);
experiment_enum!(
    CoverageExperimentStatus,
    "Durable experiment lifecycle.",
    [Prepared, Completed, Cancelled]
);
experiment_enum!(
    CoverageExperimentInputChange,
    "Service interpretation of intended input changes.",
    [NoObservedInputChange, CorpusChanged, HarnessSourceChanged]
);
experiment_enum!(
    CoverageExperimentBuildComparison,
    "Availability of matching retained build inputs.",
    [Matched, UnavailableLegacy]
);
experiment_enum!(
    CoverageExperimentEdgeUnavailableReason,
    "Why no descriptive edge delta is retained.",
    [
        LegacyBuildInputsUnavailable,
        BaselineEdgesUnavailable,
        ResultEdgesUnavailable
    ]
);
experiment_enum!(
    CoverageExperimentTargetEntryReason,
    "Limit on retained target entry evidence.",
    [NoExactRunScopedFunctionCoverage]
);
experiment_enum!(
    CoverageExperimentLimitation,
    "Stable limitations, stored sorted by serialized code.",
    [
        AggregateEdgesNotFunctionEntry,
        NoObservedInputChange,
        LegacyBuildInputsUnavailable,
        BaselineFailed,
        BaselineCancelled,
        ResultFailed,
        ResultCancelled,
        BaselineEdgesUnavailable,
        ResultEdgesUnavailable,
        RandomSeedUnrecorded,
        EngineIgnoresRetainedSeed,
        HarnessInstrumentationMayDiffer
    ]
);
experiment_enum!(
    CoverageExperimentRunRole,
    "Role of a retained campaign reference.",
    [Baseline, Result]
);

/// Descriptive difference in recorded peak counts; never function coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageExperimentEdgeComparison {
    /// Both retained measurements are available.
    Observed {
        baseline_edges: u64,
        result_edges: u64,
        delta: i64,
    },
    /// A required measurement or build snapshot is unavailable.
    Unavailable {
        reason_code: CoverageExperimentEdgeUnavailableReason,
    },
}
/// Exact function-entry evidence is unavailable in this schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoverageExperimentTargetEntry {
    /// The experiment has no exact run-scoped function measurement.
    Unavailable {
        reason_code: CoverageExperimentTargetEntryReason,
    },
}
/// Complete bounded snapshot of one retained terminal campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageExperimentRunEvidenceV1 {
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
    pub started_at: DateTime<Utc>,
    /// First terminal time.
    pub ended_at: DateTime<Utc>,
    /// Explicit whole-second duration, from 1 through 604800.
    pub duration_secs: u64,
    /// Recorded positive memory limit in MiB.
    pub max_mem_mb: u64,
    /// Recorded positive CPU limit.
    pub max_cpus: u32,
    /// Recorded harness and campaign sanitizer.
    pub sanitizer: Sanitizer,
    /// Exact ordered environment pairs, including duplicates.
    pub engine_env: Vec<(String, String)>,
    /// Exact ordered engine arguments, including empty entries.
    pub engine_args: Vec<String>,
    /// Retained seed; absence does not resolve a replacement.
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
    pub edges: Option<u64>,
    /// Exact Phase 6 compilation inputs, or explicit legacy absence.
    pub build_inputs: Option<HarnessBuildInputsRecord>,
}
/// Service-computed interpretation and exact attached campaign snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageExperimentResultEvidenceV1 {
    /// Exact durable evidence version, currently 1.
    pub schema_version: u32,
    /// Exact attached campaign snapshot.
    pub run: CoverageExperimentRunEvidenceV1,
    /// Descriptive intended-input difference.
    pub input_change: CoverageExperimentInputChange,
    /// Availability of captured build comparison.
    pub build_comparison: CoverageExperimentBuildComparison,
    /// Descriptive peak-count delta or reason for absence.
    pub edge_comparison: CoverageExperimentEdgeComparison,
    /// Explicit absence of exact run-scoped function coverage.
    pub target_entry: CoverageExperimentTargetEntry,
    /// Sorted unique stable limitation codes.
    pub limitations: Vec<CoverageExperimentLimitation>,
}
/// Immutable proposal and its one durable lifecycle outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageExperimentRecord {
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
    pub baseline: CoverageExperimentRunEvidenceV1,
    /// Retained lifecycle status.
    pub status: CoverageExperimentStatus,
    /// One terminal attachment, if completed.
    pub result: Option<CoverageExperimentResultEvidenceV1>,
    /// Exact retained reason, if cancelled.
    pub cancellation_reason: Option<String>,
    /// Immutable proposal creation time.
    pub created_at: DateTime<Utc>,
    /// Creation time or first terminal time.
    pub updated_at: DateTime<Utc>,
    /// First terminal time.
    pub ended_at: Option<DateTime<Utc>>,
}
/// Exact position in descending creation-time and UUID history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageExperimentCursor {
    /// Immutable proposal creation time.
    pub created_at: DateTime<Utc>,
    /// Immutable proposal identifier.
    pub id: Uuid,
}
/// Bounded retained history, with an optional continuation position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageExperimentPageRecord {
    /// At most the explicitly requested number of retained records.
    pub items: Vec<CoverageExperimentRecord>,
    /// Last returned position when further history exists.
    pub next_cursor: Option<CoverageExperimentCursor>,
}
/// Access-only owner projection; does not read evidence JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageExperimentOwnerRecord {
    /// Normalized absolute project owner, without filesystem resolution.
    pub project_root: String,
    /// Persisted target identity.
    pub target_id: Uuid,
}
/// Deterministically selected experiment retaining a campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverageExperimentRunReference {
    /// Experiment retaining the referenced campaign.
    pub experiment_id: Uuid,
    /// Baseline or attached-result reference.
    pub role: CoverageExperimentRunRole,
}

impl CoverageExperimentBuildComparison {
    /// Derive build-evidence availability; setup equality remains service policy.
    #[must_use]
    pub fn from_snapshots(
        baseline: &CoverageExperimentRunEvidenceV1,
        result: &CoverageExperimentRunEvidenceV1,
    ) -> Self {
        if baseline.build_inputs.is_some() && result.build_inputs.is_some() {
            Self::Matched
        } else {
            Self::UnavailableLegacy
        }
    }
}
impl CoverageExperimentInputChange {
    /// Describe the intended digest difference; does not admit setup changes.
    #[must_use]
    pub fn from_snapshots(
        kind: CoverageExperimentKind,
        baseline: &CoverageExperimentRunEvidenceV1,
        result: &CoverageExperimentRunEvidenceV1,
    ) -> Self {
        match kind {
            CoverageExperimentKind::GrowCorpus if baseline.corpus_rev != result.corpus_rev => {
                Self::CorpusChanged
            }
            CoverageExperimentKind::RefineHarness if baseline.harness_rev != result.harness_rev => {
                Self::HarnessSourceChanged
            }
            _ => Self::NoObservedInputChange,
        }
    }
}
impl CoverageExperimentEdgeComparison {
    /// Derive descriptive counts and their difference with the documented missing-evidence precedence.
    ///
    /// # Errors
    /// Returns invalid-data if a supplied count exceeds `SQLite`'s retained integer range.
    pub fn from_snapshots(
        baseline: &CoverageExperimentRunEvidenceV1,
        result: &CoverageExperimentRunEvidenceV1,
    ) -> Result<Self, crate::StorageError> {
        if baseline.build_inputs.is_none() || result.build_inputs.is_none() {
            return Ok(Self::Unavailable {
                reason_code: CoverageExperimentEdgeUnavailableReason::LegacyBuildInputsUnavailable,
            });
        }
        match (baseline.edges, result.edges) {
            (None, _) => Ok(Self::Unavailable {
                reason_code: CoverageExperimentEdgeUnavailableReason::BaselineEdgesUnavailable,
            }),
            (_, None) => Ok(Self::Unavailable {
                reason_code: CoverageExperimentEdgeUnavailableReason::ResultEdgesUnavailable,
            }),
            (Some(baseline_edges), Some(result_edges)) => {
                let baseline_count = i64::try_from(baseline_edges)
                    .map_err(|_| validation::invalid("baseline edges"))?;
                let result_count =
                    i64::try_from(result_edges).map_err(|_| validation::invalid("result edges"))?;
                Ok(Self::Observed {
                    baseline_edges,
                    result_edges,
                    delta: result_count - baseline_count,
                })
            }
        }
    }
}
