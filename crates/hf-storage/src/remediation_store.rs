//! Durable Patch-to-Proof operation records and lifecycle transitions.

use std::path::{Component, Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{StorageError, Store};

/// Durable state of one remediation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationOperationStatus {
    Draft,
    Approved,
    Running,
    Verified,
    Rejected,
    Inconclusive,
}

impl RemediationOperationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Approved => "approved",
            Self::Running => "running",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
            Self::Inconclusive => "inconclusive",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "draft" => Ok(Self::Draft),
            "approved" => Ok(Self::Approved),
            "running" => Ok(Self::Running),
            "verified" => Ok(Self::Verified),
            "rejected" => Ok(Self::Rejected),
            "inconclusive" => Ok(Self::Inconclusive),
            _ => Err(StorageError::InvalidData(format!(
                "invalid remediation status '{value}'"
            ))),
        }
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Verified | Self::Rejected | Self::Inconclusive)
    }
}

/// Current service-owned stage of a running remediation attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationOperationStage {
    Review,
    OriginalReplay,
    PatchBuild,
    PatchedReplay,
    Regression,
    FollowUp,
    Complete,
}

impl RemediationOperationStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::OriginalReplay => "original_replay",
            Self::PatchBuild => "patch_build",
            Self::PatchedReplay => "patched_replay",
            Self::Regression => "regression",
            Self::FollowUp => "follow_up",
            Self::Complete => "complete",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "review" => Ok(Self::Review),
            "original_replay" => Ok(Self::OriginalReplay),
            "patch_build" => Ok(Self::PatchBuild),
            "patched_replay" => Ok(Self::PatchedReplay),
            "regression" => Ok(Self::Regression),
            "follow_up" => Ok(Self::FollowUp),
            "complete" => Ok(Self::Complete),
            _ => Err(StorageError::InvalidData(format!(
                "invalid remediation stage '{value}'"
            ))),
        }
    }
}

/// One persisted Patch-to-Proof attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationOperationRecord {
    pub id: Uuid,
    pub run_id: Uuid,
    pub finding_id: Uuid,
    pub project_root: String,
    pub target: String,
    pub status: RemediationOperationStatus,
    pub current_stage: RemediationOperationStage,
    pub binding_json: String,
    pub approval_json: Option<String>,
    pub verification_json: Option<String>,
    pub artifact_dir: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
}

/// Fields published atomically when a running remediation reaches a terminal
/// state.
pub struct RemediationOperationCompletion<'a> {
    pub status: RemediationOperationStatus,
    pub verification_json: Option<&'a str>,
    pub failure_code: Option<&'a str>,
    pub failure_message: Option<&'a str>,
    pub completed_at: DateTime<Utc>,
}

impl Store {
    /// Insert a new immutable remediation draft.
    ///
    /// # Errors
    /// Returns an error for invalid draft state, missing parent evidence, or a
    /// database failure.
    pub async fn insert_remediation_operation(
        &self,
        record: &RemediationOperationRecord,
    ) -> Result<(), StorageError> {
        validate_draft(record)?;
        let parent: Option<String> = sqlx::query_scalar(
            "SELECT r.project_root
             FROM crashes c JOIN runs r ON r.id = c.run_id
             WHERE c.id = ?1 AND c.run_id = ?2",
        )
        .bind(record.finding_id.to_string())
        .bind(record.run_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        if parent.as_deref() != Some(record.project_root.as_str()) {
            return Err(StorageError::InvalidData(
                "remediation finding, run, and project do not match".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO remediation_operations (
                id, run_id, finding_id, project_root, target, status, current_stage,
                binding_json, approval_json, verification_json, artifact_dir,
                created_at, updated_at, ended_at, failure_code, failure_message
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, ?9, ?10, ?11,
                NULL, NULL, NULL
             )",
        )
        .bind(record.id.to_string())
        .bind(record.run_id.to_string())
        .bind(record.finding_id.to_string())
        .bind(&record.project_root)
        .bind(&record.target)
        .bind(record.status.as_str())
        .bind(record.current_stage.as_str())
        .bind(&record.binding_json)
        .bind(&record.artifact_dir)
        .bind(record.created_at.to_rfc3339())
        .bind(record.updated_at.to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Load one remediation attempt by id.
    pub async fn remediation_operation(
        &self,
        id: Uuid,
    ) -> Result<Option<RemediationOperationRecord>, StorageError> {
        let row = sqlx::query(&format!("{REMEDIATION_COLUMNS} WHERE id = ?1"))
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?;
        row.map(|row| decode_record(&row)).transpose()
    }

    /// Load the newest attempt for one finding.
    pub async fn latest_remediation_for_finding(
        &self,
        finding_id: Uuid,
    ) -> Result<Option<RemediationOperationRecord>, StorageError> {
        let row = sqlx::query(&format!(
            "{REMEDIATION_COLUMNS} WHERE finding_id = ?1 ORDER BY created_at DESC, id DESC LIMIT 1"
        ))
        .bind(finding_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| decode_record(&row)).transpose()
    }

    /// Record immutable exact-scope human approval for a draft.
    pub async fn approve_remediation_operation(
        &self,
        id: Uuid,
        approval_json: &str,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        require_json("approval_json", approval_json, 16_384)?;
        compare_and_set(
            self,
            "UPDATE remediation_operations
             SET status = 'approved', approval_json = ?1, updated_at = ?2
             WHERE id = ?3 AND status = 'draft' AND current_stage = 'review'",
            approval_json,
            now,
            id,
            "draft remediation could not be approved",
        )
        .await
    }

    /// Atomically claim an approved attempt for execution.
    pub async fn claim_remediation_operation(
        &self,
        id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE remediation_operations
             SET status = 'running', current_stage = 'original_replay', updated_at = ?1
             WHERE id = ?2 AND status = 'approved' AND current_stage = 'review'",
        )
        .bind(now.to_rfc3339())
        .bind(id.to_string())
        .execute(self.pool())
        .await?;
        require_one(
            result.rows_affected(),
            "approved remediation could not be claimed",
        )
    }

    /// Advance one running attempt through the ordered verification stages.
    pub async fn advance_remediation_stage(
        &self,
        id: Uuid,
        expected: RemediationOperationStage,
        next: RemediationOperationStage,
        now: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if !valid_stage_transition(expected, next) {
            return Err(StorageError::InvalidData(
                "invalid remediation stage transition".to_owned(),
            ));
        }
        let result = sqlx::query(
            "UPDATE remediation_operations SET current_stage = ?1, updated_at = ?2
             WHERE id = ?3 AND status = 'running' AND current_stage = ?4",
        )
        .bind(next.as_str())
        .bind(now.to_rfc3339())
        .bind(id.to_string())
        .bind(expected.as_str())
        .execute(self.pool())
        .await?;
        require_one(
            result.rows_affected(),
            "remediation stage changed concurrently",
        )
    }

    /// Publish one terminal remediation result from a running attempt.
    pub async fn finish_remediation_operation(
        &self,
        id: Uuid,
        completion: &RemediationOperationCompletion<'_>,
    ) -> Result<(), StorageError> {
        if !completion.status.is_terminal() {
            return Err(StorageError::InvalidData(
                "remediation completion requires a terminal status".to_owned(),
            ));
        }
        if let Some(value) = completion.verification_json {
            require_json("verification_json", value, 1_048_576)?;
        }
        validate_failure(completion.failure_code, completion.failure_message)?;
        let result = sqlx::query(
            "UPDATE remediation_operations
             SET status = ?1, current_stage = 'complete', verification_json = ?2,
                 ended_at = ?3, updated_at = ?3, failure_code = ?4, failure_message = ?5
             WHERE id = ?6 AND status = 'running'",
        )
        .bind(completion.status.as_str())
        .bind(completion.verification_json)
        .bind(completion.completed_at.to_rfc3339())
        .bind(completion.failure_code)
        .bind(completion.failure_message)
        .bind(id.to_string())
        .execute(self.pool())
        .await?;
        require_one(
            result.rows_affected(),
            "running remediation could not be completed",
        )
    }

    /// Mark orphaned running attempts inconclusive during startup recovery.
    pub async fn recover_interrupted_remediations(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "UPDATE remediation_operations
             SET status = 'inconclusive', current_stage = 'complete', ended_at = ?1,
                 updated_at = ?1, failure_code = 'interrupted_after_restart',
                 failure_message = 'The application restarted before sandbox verification completed.'
             WHERE status = 'running'",
        )
        .bind(now.to_rfc3339())
        .execute(self.pool())
        .await?;
        Ok(result.rows_affected())
    }
}

const REMEDIATION_COLUMNS: &str = "SELECT id, run_id, finding_id, project_root, target,
    status, current_stage, binding_json, approval_json, verification_json, artifact_dir,
    created_at, updated_at, ended_at, failure_code, failure_message
    FROM remediation_operations";

fn decode_record(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<RemediationOperationRecord, StorageError> {
    Ok(RemediationOperationRecord {
        id: parse_uuid("id", &row.try_get::<String, _>("id")?)?,
        run_id: parse_uuid("run_id", &row.try_get::<String, _>("run_id")?)?,
        finding_id: parse_uuid("finding_id", &row.try_get::<String, _>("finding_id")?)?,
        project_root: row.try_get("project_root")?,
        target: row.try_get("target")?,
        status: RemediationOperationStatus::parse(row.try_get("status")?)?,
        current_stage: RemediationOperationStage::parse(row.try_get("current_stage")?)?,
        binding_json: row.try_get("binding_json")?,
        approval_json: row.try_get("approval_json")?,
        verification_json: row.try_get("verification_json")?,
        artifact_dir: row.try_get("artifact_dir")?,
        created_at: parse_timestamp("created_at", &row.try_get::<String, _>("created_at")?)?,
        updated_at: parse_timestamp("updated_at", &row.try_get::<String, _>("updated_at")?)?,
        ended_at: row
            .try_get::<Option<String>, _>("ended_at")?
            .map(|value| parse_timestamp("ended_at", &value))
            .transpose()?,
        failure_code: row.try_get("failure_code")?,
        failure_message: row.try_get("failure_message")?,
    })
}

fn validate_draft(record: &RemediationOperationRecord) -> Result<(), StorageError> {
    if record.project_root.trim().is_empty()
        || record.target.trim().is_empty()
        || record.status != RemediationOperationStatus::Draft
        || record.current_stage != RemediationOperationStage::Review
        || record.approval_json.is_some()
        || record.verification_json.is_some()
        || record.ended_at.is_some()
        || record.failure_code.is_some()
        || record.failure_message.is_some()
        || record.updated_at < record.created_at
    {
        return Err(StorageError::InvalidData(
            "invalid remediation draft state".to_owned(),
        ));
    }
    require_json("binding_json", &record.binding_json, 2_097_152)?;
    let artifact = Path::new(&record.artifact_dir);
    if artifact.is_absolute()
        || record.artifact_dir.is_empty()
        || artifact.components().any(|component| {
            matches!(
                component,
                Component::Prefix(_)
                    | Component::RootDir
                    | Component::CurDir
                    | Component::ParentDir
            )
        })
    {
        return Err(StorageError::InvalidData(
            "remediation artifact directory must be workspace-relative".to_owned(),
        ));
    }
    Ok(())
}

async fn compare_and_set(
    store: &Store,
    sql: &str,
    json: &str,
    now: DateTime<Utc>,
    id: Uuid,
    message: &str,
) -> Result<(), StorageError> {
    let result = sqlx::query(sql)
        .bind(json)
        .bind(now.to_rfc3339())
        .bind(id.to_string())
        .execute(store.pool())
        .await?;
    require_one(result.rows_affected(), message)
}

fn valid_stage_transition(
    expected: RemediationOperationStage,
    next: RemediationOperationStage,
) -> bool {
    matches!(
        (expected, next),
        (
            RemediationOperationStage::OriginalReplay,
            RemediationOperationStage::PatchBuild
        ) | (
            RemediationOperationStage::PatchBuild,
            RemediationOperationStage::PatchedReplay
        ) | (
            RemediationOperationStage::PatchedReplay,
            RemediationOperationStage::Regression
        ) | (
            RemediationOperationStage::Regression,
            RemediationOperationStage::FollowUp
        )
    )
}

fn require_one(rows: u64, message: &str) -> Result<(), StorageError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StorageError::InvalidData(message.to_owned()))
    }
}

fn require_json(field: &str, value: &str, max_bytes: usize) -> Result<(), StorageError> {
    if value.len() > max_bytes || serde_json::from_str::<serde_json::Value>(value).is_err() {
        return Err(StorageError::InvalidData(format!(
            "{field} must be bounded valid JSON"
        )));
    }
    Ok(())
}

fn validate_failure(code: Option<&str>, message: Option<&str>) -> Result<(), StorageError> {
    match (code, message) {
        (None, None) => Ok(()),
        (Some(code), Some(message))
            if !code.is_empty()
                && code.len() <= 128
                && !message.is_empty()
                && message.len() <= 4_096 =>
        {
            Ok(())
        }
        _ => Err(StorageError::InvalidData(
            "remediation failure code and message must be paired and bounded".to_owned(),
        )),
    }
}

fn parse_uuid(field: &str, value: &str) -> Result<Uuid, StorageError> {
    Uuid::parse_str(value)
        .map_err(|error| StorageError::InvalidData(format!("invalid {field}: {error}")))
}

fn parse_timestamp(field: &str, value: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| StorageError::Timestamp(format!("invalid {field}: {error}")))
}
