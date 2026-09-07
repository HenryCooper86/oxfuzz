//! Durable operator-reviewed experiments; reads and mutations never execute a campaign.
#[cfg(feature = "coverage-experiments")]
mod lifecycle;
mod views;
pub use views::*;

use crate::ServiceContainer;
use chrono::{DateTime, Utc};
use hf_storage::{StorageError, Store};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

pub use hf_storage::{
    CoverageExperimentBuildComparison, CoverageExperimentEdgeUnavailableReason,
    CoverageExperimentInputChange, CoverageExperimentKind, CoverageExperimentLimitation,
    CoverageExperimentRunRole, CoverageExperimentStatus, CoverageExperimentTargetEntry,
    CoverageExperimentTargetEntryReason,
};

/// Request size ceiling for REST and native JSON decoding.
pub const MAX_COVERAGE_EXPERIMENT_REQUEST_BYTES: usize = 16_384;
/// Stable unavailable message shared by both transports.
pub const COVERAGE_EXPERIMENT_UNAVAILABLE: &str =
    "coverage experiments are not included in this application build";

/// Operator-authored proposal; no evidence or mutation timestamps come from clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCoverageExperimentRequest {
    #[serde(deserialize_with = "request_project")]
    pub project: PathBuf,
    #[serde(deserialize_with = "request_uuid")]
    pub target_id: Uuid,
    #[serde(deserialize_with = "request_uuid")]
    pub baseline_run_id: Uuid,
    pub kind: CoverageExperimentKind,
    #[serde(deserialize_with = "goal_text")]
    pub goal_function: String,
    #[serde(deserialize_with = "long_text")]
    pub hypothesis: String,
    #[serde(deserialize_with = "request_duration")]
    pub duration_secs: u64,
}
/// Explicit bounded history selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListCoverageExperimentsRequest {
    #[serde(deserialize_with = "request_project")]
    pub project: PathBuf,
    #[serde(deserialize_with = "optional_request_uuid")]
    pub target_id: Option<Uuid>,
    #[serde(deserialize_with = "request_limit")]
    pub limit: usize,
    #[serde(deserialize_with = "required_optional")]
    pub before: Option<CoverageExperimentCursor>,
}
/// Position in descending creation-time/UUID history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageExperimentCursor {
    #[serde(serialize_with = "serialize_time", deserialize_with = "request_time")]
    pub created_at: DateTime<Utc>,
    #[serde(deserialize_with = "request_experiment_id")]
    pub id: Uuid,
}
/// Selected owner; every ID operation verifies these values against storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageExperimentScope {
    #[serde(deserialize_with = "request_project")]
    pub project: PathBuf,
    #[serde(deserialize_with = "request_uuid")]
    pub target_id: Uuid,
}
/// Access-only owner projection, available even without experiment lifecycle support.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageExperimentOwner {
    pub project_root: PathBuf,
    pub target_id: Uuid,
}
/// Explicit attachment of an already retained campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteCoverageExperimentRequest {
    pub scope: CoverageExperimentScope,
    #[serde(deserialize_with = "request_uuid")]
    pub result_run_id: Uuid,
}
/// Cancellation changes only the experiment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelCoverageExperimentRequest {
    pub scope: CoverageExperimentScope,
    #[serde(deserialize_with = "long_text")]
    pub reason: String,
}

/// Stable service error codes; details never include retained environment values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageExperimentErrorCode {
    FeatureUnavailable,
    StorageUnavailable,
    StorageError,
    NotFound,
    InvalidRequest,
    InvalidProjectPath,
    ProjectNotAuthorized,
    InvalidBaseline,
    InvalidResult,
    MissingSetupEvidence,
    InvalidChronology,
    DifferentProject,
    DifferentTarget,
    DifferentEngine,
    DifferentSource,
    DifferentSandbox,
    DifferentRunSettings,
    DifferentBuildInputs,
    DifferentHarness,
    DifferentCorpus,
    UnexpectedBinaryChange,
    TerminalConflict,
    SourceEvidenceChanged,
    RunRetainedByExperiment,
}
impl CoverageExperimentErrorCode {
    /// Stable transport code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FeatureUnavailable => "feature_unavailable",
            Self::StorageUnavailable => "storage_unavailable",
            Self::StorageError => "storage_error",
            Self::NotFound => "not_found",
            Self::InvalidRequest => "invalid_request",
            Self::InvalidProjectPath => "invalid_project_path",
            Self::ProjectNotAuthorized => "project_not_authorized",
            Self::InvalidBaseline => "invalid_baseline",
            Self::InvalidResult => "invalid_result",
            Self::MissingSetupEvidence => "missing_setup_evidence",
            Self::InvalidChronology => "invalid_chronology",
            Self::DifferentProject => "different_project",
            Self::DifferentTarget => "different_target",
            Self::DifferentEngine => "different_engine",
            Self::DifferentSource => "different_source",
            Self::DifferentSandbox => "different_sandbox",
            Self::DifferentRunSettings => "different_run_settings",
            Self::DifferentBuildInputs => "different_build_inputs",
            Self::DifferentHarness => "different_harness",
            Self::DifferentCorpus => "different_corpus",
            Self::UnexpectedBinaryChange => "unexpected_binary_change",
            Self::TerminalConflict => "terminal_conflict",
            Self::SourceEvidenceChanged => "source_evidence_changed",
            Self::RunRetainedByExperiment => "run_retained_by_experiment",
        }
    }
}
/// Redacted typed refusal with optional identifiers and a bounded differing-field label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{code}: {error}")]
pub struct CoverageExperimentError {
    pub code: &'static str,
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experiment_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<CoverageExperimentRunRole>,
}
impl CoverageExperimentError {
    /// Construct a safe stable refusal without exposing raw storage errors.
    #[must_use]
    pub const fn new(code: CoverageExperimentErrorCode) -> Self {
        Self {
            code: code.as_str(),
            error: match code {
                CoverageExperimentErrorCode::FeatureUnavailable => COVERAGE_EXPERIMENT_UNAVAILABLE,
                _ => code.as_str(),
            },
            field: None,
            run_id: None,
            experiment_id: None,
            role: None,
        }
    }
    /// Stable code used by transports for status and localization.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }
    fn field(code: CoverageExperimentErrorCode, field: &'static str) -> Self {
        Self {
            field: Some(field),
            ..Self::new(code)
        }
    }
}
impl From<StorageError> for CoverageExperimentError {
    fn from(error: StorageError) -> Self {
        use CoverageExperimentErrorCode as C;
        match error {
            StorageError::CoverageExperimentConflict { id } => Self {
                experiment_id: Some(id),
                ..Self::new(C::TerminalConflict)
            },
            StorageError::CoverageExperimentSourceChanged { run_id } => Self {
                run_id: Some(run_id),
                ..Self::new(C::SourceEvidenceChanged)
            },
            StorageError::CoverageExperimentInvalidChronology => Self::new(C::InvalidChronology),
            StorageError::CoverageExperimentMissingSetup { field } => {
                Self::field(C::MissingSetupEvidence, field)
            }
            StorageError::RunRetainedByExperiment {
                run_id,
                experiment_id,
                role,
            } => Self {
                run_id: Some(run_id),
                experiment_id: Some(experiment_id),
                role: Some(role),
                ..Self::new(C::RunRetainedByExperiment)
            },
            StorageError::NotFound(_) => Self::new(C::NotFound),
            StorageError::Db(_) | StorageError::Migrate(_) => Self::new(C::StorageError),
            StorageError::InvalidData(_) | StorageError::Serde(_) | StorageError::Timestamp(_) => {
                Self::new(C::StorageError)
            }
        }
    }
}
impl ServiceContainer {
    fn experiment_store(&self) -> Result<&Store, CoverageExperimentError> {
        self.store()
            .map(std::convert::AsRef::as_ref)
            .ok_or_else(|| {
                CoverageExperimentError::new(CoverageExperimentErrorCode::StorageUnavailable)
            })
    }
    /// Read only persisted project and target identity, including in feature-off builds.
    #[tracing::instrument(skip_all)]
    pub async fn coverage_experiment_owner(
        &self,
        id: Uuid,
    ) -> Result<CoverageExperimentOwner, CoverageExperimentError> {
        let owner = self
            .experiment_store()?
            .coverage_experiment_owner(id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(CoverageExperimentErrorCode::NotFound))?;
        Ok(CoverageExperimentOwner {
            project_root: owner.project_root.into(),
            target_id: owner.target_id,
        })
    }
    /// Verify selected owner and optional result owner without reading experiment evidence.
    #[tracing::instrument(skip_all)]
    pub async fn validate_coverage_experiment_scope(
        &self,
        id: Uuid,
        scope: CoverageExperimentScope,
        result_run_id: Option<Uuid>,
    ) -> Result<(), CoverageExperimentError> {
        let owner = self.coverage_experiment_owner(id).await?;
        let project = validate_coverage_experiment_project(&scope.project)?;
        ensure_owner(&owner, &project, scope.target_id)?;
        if let Some(run_id) = result_run_id {
            let store = self.experiment_store()?;
            let run = store.get_run(run_id).await?.ok_or_else(|| {
                CoverageExperimentError::new(CoverageExperimentErrorCode::NotFound)
            })?;
            if std::path::Path::new(&run.project_root) != owner.project_root {
                return Err(CoverageExperimentError::new(
                    CoverageExperimentErrorCode::DifferentProject,
                ));
            }
            let target = self
                .run_target_id(store, &run)
                .await
                .map_err(|_| {
                    CoverageExperimentError::new(CoverageExperimentErrorCode::StorageError)
                })?
                .ok_or_else(|| {
                    CoverageExperimentError::field(
                        CoverageExperimentErrorCode::MissingSetupEvidence,
                        "config",
                    )
                })?;
            if target != owner.target_id {
                return Err(CoverageExperimentError::new(
                    CoverageExperimentErrorCode::DifferentTarget,
                ));
            }
            let target = store
                .list_all_targets()
                .await?
                .into_iter()
                .find(|item| item.id == target)
                .ok_or_else(|| {
                    CoverageExperimentError::field(
                        CoverageExperimentErrorCode::MissingSetupEvidence,
                        "target",
                    )
                })?;
            if target.project_root != owner.project_root {
                return Err(CoverageExperimentError::new(
                    CoverageExperimentErrorCode::DifferentProject,
                ));
            }
        }
        Ok(())
    }
}
/// Resolve selected project identity without storage, policy admission or lifecycle execution.
///
/// Canonicalization reads filesystem metadata; this helper does not mutate the project.
/// # Errors
/// Returns `invalid_project_path` when the directory cannot be resolved.
pub fn validate_coverage_experiment_project(
    project: &std::path::Path,
) -> Result<PathBuf, CoverageExperimentError> {
    let invalid = || CoverageExperimentError::new(CoverageExperimentErrorCode::InvalidProjectPath);
    if !project.to_str().is_some_and(valid_project_text) {
        return Err(invalid());
    }
    let canonical = crate::container::canonical_project_root(project).map_err(|_| invalid())?;
    if !canonical.to_str().is_some_and(valid_project_text) {
        return Err(invalid());
    }
    Ok(canonical)
}
fn valid_project_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control)
}
fn request_project<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PathBuf, D::Error> {
    let value = String::deserialize(d)?;
    if !valid_project_text(&value) {
        return Err(serde::de::Error::custom("invalid bounded project path"));
    }
    Ok(value.into())
}
fn ensure_owner(
    owner: &CoverageExperimentOwner,
    project: &std::path::Path,
    target_id: Uuid,
) -> Result<(), CoverageExperimentError> {
    if owner.project_root != project {
        return Err(CoverageExperimentError::new(
            CoverageExperimentErrorCode::DifferentProject,
        ));
    }
    if owner.target_id != target_id {
        return Err(CoverageExperimentError::new(
            CoverageExperimentErrorCode::DifferentTarget,
        ));
    }
    Ok(())
}
fn valid_text(value: &str, max: usize, multiline: bool) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value
            .chars()
            .any(|c| c.is_control() && !(multiline && matches!(c, '\n' | '\t')))
}
/// Parse an experiment ID at a foreign wire input before constructing a typed request.
///
/// REST paths and native raw request envelopes must use this parser.
/// # Errors
/// Returns `invalid_request` for noncanonical, nil, or non-v4 UUID text.
pub fn parse_coverage_experiment_id(text: &str) -> Result<Uuid, CoverageExperimentError> {
    let id = canonical_uuid(text).map_err(|_| {
        CoverageExperimentError::field(CoverageExperimentErrorCode::InvalidRequest, "id")
    })?;
    if id.get_version() != Some(uuid::Version::Random) || id.get_variant() != uuid::Variant::RFC4122
    {
        return Err(CoverageExperimentError::field(
            CoverageExperimentErrorCode::InvalidRequest,
            "id",
        ));
    }
    Ok(id)
}
fn canonical_uuid(text: &str) -> Result<Uuid, &'static str> {
    let id = Uuid::parse_str(text).map_err(|_| "expected canonical non-nil UUID")?;
    if id.is_nil() || id.to_string() != text {
        return Err("expected canonical non-nil UUID");
    }
    Ok(id)
}
fn request_experiment_id<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
    parse_coverage_experiment_id(&String::deserialize(d)?).map_err(serde::de::Error::custom)
}
fn request_uuid<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
    canonical_uuid(&String::deserialize(d)?).map_err(serde::de::Error::custom)
}
fn optional_request_uuid<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Uuid>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|text| canonical_uuid(&text).map_err(serde::de::Error::custom))
        .transpose()
}
fn required_optional<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
fn goal_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    read_text(d, 1024, false)
}
fn long_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    read_text(d, 4096, true)
}
fn read_text<'de, D: serde::Deserializer<'de>>(
    d: D,
    max: usize,
    multiline: bool,
) -> Result<String, D::Error> {
    let value = String::deserialize(d)?;
    if !valid_text(&value, max, multiline) {
        return Err(serde::de::Error::custom("invalid bounded text"));
    }
    Ok(value)
}
fn request_duration<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(d)?;
    if !(1..=604_800).contains(&value) {
        return Err(serde::de::Error::custom(
            "duration must be within 1..=604800",
        ));
    }
    Ok(value)
}
fn request_limit<'de, D: serde::Deserializer<'de>>(d: D) -> Result<usize, D::Error> {
    let value = usize::deserialize(d)?;
    if !(1..=100).contains(&value) {
        return Err(serde::de::Error::custom("limit must be within 1..=100"));
    }
    Ok(value)
}
fn serialize_time<S: serde::Serializer>(value: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
}
fn request_time<'de, D: serde::Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
    let text = String::deserialize(d)?;
    let value = text
        .parse::<DateTime<Utc>>()
        .map_err(serde::de::Error::custom)?;
    if text.len() != 30
        || value.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true) != text
        || chrono::Datelike::year(&value) == 0
    {
        return Err(serde::de::Error::custom("expected canonical UTC timestamp"));
    }
    Ok(value)
}
