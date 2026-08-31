//! Durable Harness Work Order records.

use std::{fmt, str::FromStr};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

use crate::{StorageError, Store};

/// Maximum immutable submissions retained for one work order.
pub const MAX_WORK_ORDER_SUBMISSIONS: u32 = 20;
/// Maximum attempts that may be ranked in one request.
pub const MAX_WORK_ORDER_RANK_ATTEMPTS: usize = 5;

/// Typed policy outcomes from immutable submission insertion.
#[derive(Debug, Error)]
pub enum HarnessWorkOrderSubmissionInsertError {
    /// The declared work order does not exist.
    #[error("work order was not found")]
    MissingWorkOrder,
    /// The declared repair parent does not exist.
    #[error("submission parent was not found")]
    MissingParent,
    /// The declared repair parent belongs to another work order.
    #[error("submission parent belongs to a different work order")]
    ParentWorkOrderMismatch,
    /// The work order already has the maximum number of submissions.
    #[error("work order submission limit reached")]
    SubmissionLimitReached,
    /// A database, serialization, or other storage failure occurred.
    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl From<sqlx::Error> for HarnessWorkOrderSubmissionInsertError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(StorageError::Db(error))
    }
}

/// The service-owned qualification phase recorded for an attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkOrderAttemptStage {
    Compile,
    Review,
    Smoke,
    Complete,
}

impl HarnessWorkOrderAttemptStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Review => "review",
            Self::Smoke => "smoke",
            Self::Complete => "complete",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "compile" => Ok(Self::Compile),
            "review" => Ok(Self::Review),
            "smoke" => Ok(Self::Smoke),
            "complete" => Ok(Self::Complete),
            _ => Err(StorageError::InvalidData(format!(
                "invalid harness work order attempt stage '{value}'"
            ))),
        }
    }
}

impl fmt::Display for HarnessWorkOrderAttemptStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HarnessWorkOrderAttemptStage {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// The durable outcome recorded for a qualification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessWorkOrderAttemptStatus {
    Running,
    CompileFailed,
    ReviewFailed,
    SmokeFailed,
    SmokePassed,
    Interrupted,
}

impl HarnessWorkOrderAttemptStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::CompileFailed => "compile_failed",
            Self::ReviewFailed => "review_failed",
            Self::SmokeFailed => "smoke_failed",
            Self::SmokePassed => "smoke_passed",
            Self::Interrupted => "interrupted",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "running" => Ok(Self::Running),
            "compile_failed" => Ok(Self::CompileFailed),
            "review_failed" => Ok(Self::ReviewFailed),
            "smoke_failed" => Ok(Self::SmokeFailed),
            "smoke_passed" => Ok(Self::SmokePassed),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(StorageError::InvalidData(format!(
                "invalid harness work order attempt status '{value}'"
            ))),
        }
    }
}

impl fmt::Display for HarnessWorkOrderAttemptStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for HarnessWorkOrderAttemptStatus {
    type Err = StorageError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// One immutable, canonical work-order packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderRecord {
    pub id: String,
    pub target_id: Uuid,
    pub project_root: String,
    pub schema_version: u32,
    pub packet_json: String,
    pub created_at: DateTime<Utc>,
}

/// One immutable source submission for a work order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderSubmissionRecord {
    pub id: Uuid,
    pub work_order_id: String,
    pub source: String,
    pub source_sha256: String,
    pub origin_json: String,
    pub parent_submission_id: Option<Uuid>,
    pub lint_json: String,
    pub submitted_at: DateTime<Utc>,
}

/// One durable qualification attempt for an immutable submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderAttemptRecord {
    pub id: Uuid,
    pub submission_id: Uuid,
    pub status: HarnessWorkOrderAttemptStatus,
    pub current_stage: HarnessWorkOrderAttemptStage,
    pub harness_id: Option<Uuid>,
    pub smoke_run_id: Option<Uuid>,
    pub result_json: Option<String>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// Fields published atomically when a qualification attempt reaches a terminal outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderAttemptCompletion<'a> {
    pub expected_stage: HarnessWorkOrderAttemptStage,
    pub status: HarnessWorkOrderAttemptStatus,
    pub harness_id: Option<Uuid>,
    pub smoke_run_id: Option<Uuid>,
    pub result_json: Option<&'a str>,
    pub failure_code: Option<&'a str>,
    pub failure_message: Option<&'a str>,
    pub completed_at: DateTime<Utc>,
}

impl Store {
    /// Insert an immutable work-order packet or return an exact prior insert.
    ///
    /// # Errors
    /// Returns an error when an existing identifier has different immutable
    /// evidence or a database operation fails.
    pub async fn insert_harness_work_order(
        &self,
        record: &HarnessWorkOrderRecord,
    ) -> Result<HarnessWorkOrderRecord, StorageError> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query(
            "INSERT INTO harness_work_orders
                (id, target_id, project_root, schema_version, packet_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&record.id)
        .bind(record.target_id.to_string())
        .bind(&record.project_root)
        .bind(record.schema_version)
        .bind(&record.packet_json)
        .bind(utc_timestamp(record.created_at))
        .execute(&mut *transaction)
        .await?;
        let persisted = load_work_order(&mut *transaction, &record.id)
            .await?
            .ok_or_else(|| StorageError::InvalidData("work order insert returned no row".into()))?;
        let persisted = exact_or_conflict(persisted, record, "work order identifier conflicts")?;
        transaction.commit().await?;
        Ok(persisted)
    }

    /// Load one work-order packet by its content identifier.
    pub async fn harness_work_order(
        &self,
        id: &str,
    ) -> Result<Option<HarnessWorkOrderRecord>, StorageError> {
        load_work_order(self.pool(), id).await
    }

    /// List durable work orders newest first, optionally for one project.
    pub async fn list_harness_work_orders(
        &self,
        project_root: Option<&str>,
    ) -> Result<Vec<HarnessWorkOrderRecord>, StorageError> {
        let rows = match project_root {
            Some(project_root) => {
                sqlx::query(&format!(
                "{WORK_ORDER_COLUMNS} WHERE project_root = ?1 ORDER BY created_at DESC, id DESC"
            ))
                .bind(project_root)
                .fetch_all(self.pool())
                .await?
            }
            None => {
                sqlx::query(&format!(
                    "{WORK_ORDER_COLUMNS} ORDER BY created_at DESC, id DESC"
                ))
                .fetch_all(self.pool())
                .await?
            }
        };
        rows.iter().map(work_order_from_row).collect()
    }

    /// Insert an immutable submission or return an exact prior submission.
    ///
    /// The parent and submission cap checks execute in the same transaction as
    /// the insert, so an accepted submission always has durable ancestry.
    pub async fn insert_harness_work_order_submission(
        &self,
        record: &HarnessWorkOrderSubmissionRecord,
    ) -> Result<HarnessWorkOrderSubmissionRecord, HarnessWorkOrderSubmissionInsertError> {
        let mut transaction = self.pool().begin().await?;
        if let Some(existing) = load_submission(&mut *transaction, record.id).await? {
            transaction.commit().await?;
            return exact_or_conflict(existing, record, "submission identifier conflicts")
                .map_err(Into::into);
        }
        if let Some(existing) = load_submission_identity(&mut transaction, record).await? {
            transaction.commit().await?;
            return Ok(existing);
        }
        let work_order_exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM harness_work_orders WHERE id = ?1")
                .bind(&record.work_order_id)
                .fetch_optional(&mut *transaction)
                .await?;
        if work_order_exists.is_none() {
            return Err(HarnessWorkOrderSubmissionInsertError::MissingWorkOrder);
        }
        if let Some(parent_id) = record.parent_submission_id {
            let parent_work_order: Option<String> = sqlx::query_scalar(
                "SELECT work_order_id FROM harness_work_order_submissions WHERE id = ?1",
            )
            .bind(parent_id.to_string())
            .fetch_optional(&mut *transaction)
            .await?;
            match parent_work_order {
                Some(parent_work_order) if parent_work_order == record.work_order_id => {}
                Some(_) => {
                    return Err(HarnessWorkOrderSubmissionInsertError::ParentWorkOrderMismatch);
                }
                None => return Err(HarnessWorkOrderSubmissionInsertError::MissingParent),
            }
        }
        let submission_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM harness_work_order_submissions WHERE work_order_id = ?1",
        )
        .bind(&record.work_order_id)
        .fetch_one(&mut *transaction)
        .await?;
        if submission_count >= i64::from(MAX_WORK_ORDER_SUBMISSIONS) {
            return Err(HarnessWorkOrderSubmissionInsertError::SubmissionLimitReached);
        }
        sqlx::query(
            "INSERT INTO harness_work_order_submissions
                (id, work_order_id, source, source_sha256, origin_json, parent_submission_id,
                 lint_json, submitted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(record.id.to_string())
        .bind(&record.work_order_id)
        .bind(&record.source)
        .bind(&record.source_sha256)
        .bind(&record.origin_json)
        .bind(record.parent_submission_id.map(|id| id.to_string()))
        .bind(&record.lint_json)
        .bind(utc_timestamp(record.submitted_at))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(record.clone())
    }

    /// Load one immutable submission by identifier.
    pub async fn harness_work_order_submission(
        &self,
        id: Uuid,
    ) -> Result<Option<HarnessWorkOrderSubmissionRecord>, StorageError> {
        load_submission(self.pool(), id).await
    }

    /// List one work order's submissions newest first.
    pub async fn list_harness_work_order_submissions(
        &self,
        work_order_id: &str,
    ) -> Result<Vec<HarnessWorkOrderSubmissionRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            "{SUBMISSION_COLUMNS} WHERE work_order_id = ?1 ORDER BY submitted_at DESC, id DESC"
        ))
        .bind(work_order_id)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(submission_from_row).collect()
    }

    /// Insert a new running qualification attempt.
    pub async fn insert_harness_work_order_attempt(
        &self,
        record: &HarnessWorkOrderAttemptRecord,
    ) -> Result<HarnessWorkOrderAttemptRecord, StorageError> {
        validate_new_attempt(record)?;
        let mut transaction = self.pool().begin().await?;
        if let Some(existing) = load_attempt(&mut *transaction, record.id).await? {
            transaction.commit().await?;
            return exact_or_conflict(existing, record, "attempt identifier conflicts");
        }
        let submission_exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM harness_work_order_submissions WHERE id = ?1")
                .bind(record.submission_id.to_string())
                .fetch_optional(&mut *transaction)
                .await?;
        if submission_exists.is_none() {
            return Err(StorageError::NotFound(format!(
                "submission {}",
                record.submission_id
            )));
        }
        sqlx::query(
            "INSERT INTO harness_work_order_attempts
                (id, submission_id, status, current_stage, harness_id, smoke_run_id,
                 result_json, failure_code, failure_message, started_at, updated_at, ended_at)
             VALUES (?1, ?2, 'running', 'compile', NULL, NULL, NULL, NULL, NULL, ?3, ?4, NULL)",
        )
        .bind(record.id.to_string())
        .bind(record.submission_id.to_string())
        .bind(utc_timestamp(record.started_at))
        .bind(utc_timestamp(record.updated_at))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(record.clone())
    }

    /// Load one qualification attempt by identifier.
    pub async fn harness_work_order_attempt(
        &self,
        id: Uuid,
    ) -> Result<Option<HarnessWorkOrderAttemptRecord>, StorageError> {
        load_attempt(self.pool(), id).await
    }

    /// List one submission's qualification attempts newest first.
    pub async fn list_harness_work_order_attempts(
        &self,
        submission_id: Uuid,
    ) -> Result<Vec<HarnessWorkOrderAttemptRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            "{ATTEMPT_COLUMNS} WHERE submission_id = ?1 ORDER BY started_at DESC, id DESC"
        ))
        .bind(submission_id.to_string())
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(attempt_from_row).collect()
    }

    /// List every unfinished qualification attempt for owner-liveness recovery.
    pub async fn list_running_harness_work_order_attempts(
        &self,
    ) -> Result<Vec<HarnessWorkOrderAttemptRecord>, StorageError> {
        let rows = sqlx::query(&format!(
            "{ATTEMPT_COLUMNS} WHERE status = 'running' ORDER BY started_at, id"
        ))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(attempt_from_row).collect()
    }

    /// Advance a running attempt by one service-owned qualification stage.
    pub async fn transition_harness_work_order_attempt(
        &self,
        id: Uuid,
        expected_stage: HarnessWorkOrderAttemptStage,
        next_stage: HarnessWorkOrderAttemptStage,
        harness_id: Option<Uuid>,
        updated_at: DateTime<Utc>,
    ) -> Result<HarnessWorkOrderAttemptRecord, StorageError> {
        if !valid_stage_transition(expected_stage, next_stage) {
            return Err(StorageError::InvalidData(
                "invalid harness work order attempt stage transition".to_owned(),
            ));
        }
        let updated = sqlx::query(
            "UPDATE harness_work_order_attempts
             SET current_stage = ?1,
                 harness_id = COALESCE(harness_id, ?2),
                 updated_at = ?3
             WHERE id = ?4 AND status = 'running' AND current_stage = ?5",
        )
        .bind(next_stage.as_str())
        .bind(harness_id.map(|value| value.to_string()))
        .bind(utc_timestamp(updated_at))
        .bind(id.to_string())
        .bind(expected_stage.as_str())
        .execute(self.pool())
        .await?;
        require_one_attempt_row(
            updated.rows_affected(),
            "attempt stage changed concurrently",
        )?;
        self.harness_work_order_attempt(id).await?.ok_or_else(|| {
            StorageError::InvalidData("transitioned work order attempt is missing".to_owned())
        })
    }

    /// Publish a terminal qualification outcome from the expected running stage.
    pub async fn complete_harness_work_order_attempt(
        &self,
        id: Uuid,
        completion: HarnessWorkOrderAttemptCompletion<'_>,
    ) -> Result<HarnessWorkOrderAttemptRecord, StorageError> {
        if !valid_completion(&completion) {
            return Err(StorageError::InvalidData(
                "invalid harness work order attempt completion".to_owned(),
            ));
        }
        let updated = sqlx::query(
            "UPDATE harness_work_order_attempts
             SET status = ?1,
                 current_stage = 'complete',
                 harness_id = COALESCE(harness_id, ?2),
                 smoke_run_id = ?3,
                 result_json = ?4,
                 failure_code = ?5,
                 failure_message = ?6,
                 updated_at = ?7,
                 ended_at = ?7
             WHERE id = ?8 AND status = 'running' AND current_stage = ?9",
        )
        .bind(completion.status.as_str())
        .bind(completion.harness_id.map(|value| value.to_string()))
        .bind(completion.smoke_run_id.map(|value| value.to_string()))
        .bind(completion.result_json)
        .bind(completion.failure_code)
        .bind(completion.failure_message)
        .bind(utc_timestamp(completion.completed_at))
        .bind(id.to_string())
        .bind(completion.expected_stage.as_str())
        .execute(self.pool())
        .await?;
        require_one_attempt_row(
            updated.rows_affected(),
            "attempt completion changed concurrently",
        )?;
        self.harness_work_order_attempt(id).await?.ok_or_else(|| {
            StorageError::InvalidData("completed work order attempt is missing".to_owned())
        })
    }

    /// Mark one unfinished qualification attempt interrupted after its owner is gone.
    pub async fn recover_harness_work_order_attempt(
        &self,
        id: Uuid,
        recovered_at: DateTime<Utc>,
    ) -> Result<bool, StorageError> {
        let updated = sqlx::query(
            "UPDATE harness_work_order_attempts
             SET status = 'interrupted',
                 current_stage = 'complete',
                 failure_code = 'attempt_interrupted',
                 failure_message = 'The application restarted before harness qualification completed.',
                 updated_at = ?1,
                 ended_at = ?1
             WHERE id = ?2 AND status = 'running'",
        )
        .bind(utc_timestamp(recovered_at))
        .bind(id.to_string())
        .execute(self.pool())
        .await?;
        Ok(updated.rows_affected() == 1)
    }
}

const WORK_ORDER_COLUMNS: &str =
    "SELECT id, target_id, project_root, schema_version, packet_json, created_at
    FROM harness_work_orders";
const SUBMISSION_COLUMNS: &str = "SELECT id, work_order_id, source, source_sha256, origin_json,
    parent_submission_id, lint_json, submitted_at FROM harness_work_order_submissions";
const ATTEMPT_COLUMNS: &str = "SELECT id, submission_id, status, current_stage, harness_id,
    smoke_run_id, result_json, failure_code, failure_message, started_at, updated_at, ended_at
    FROM harness_work_order_attempts";

async fn load_work_order<'e, E>(
    executor: E,
    id: &str,
) -> Result<Option<HarnessWorkOrderRecord>, StorageError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query(&format!("{WORK_ORDER_COLUMNS} WHERE id = ?1"))
        .bind(id)
        .fetch_optional(executor)
        .await?;
    row.map(|row| work_order_from_row(&row)).transpose()
}

async fn load_submission<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<HarnessWorkOrderSubmissionRecord>, StorageError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query(&format!("{SUBMISSION_COLUMNS} WHERE id = ?1"))
        .bind(id.to_string())
        .fetch_optional(executor)
        .await?;
    row.map(|row| submission_from_row(&row)).transpose()
}

async fn load_submission_identity(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    record: &HarnessWorkOrderSubmissionRecord,
) -> Result<Option<HarnessWorkOrderSubmissionRecord>, StorageError> {
    let row = sqlx::query(&format!(
        "{SUBMISSION_COLUMNS}
         WHERE work_order_id = ?1 AND source_sha256 = ?2 AND origin_json = ?3
           AND COALESCE(parent_submission_id, '') = COALESCE(?4, '')"
    ))
    .bind(&record.work_order_id)
    .bind(&record.source_sha256)
    .bind(&record.origin_json)
    .bind(record.parent_submission_id.map(|value| value.to_string()))
    .fetch_optional(&mut **transaction)
    .await?;
    row.map(|row| submission_from_row(&row)).transpose()
}

async fn load_attempt<'e, E>(
    executor: E,
    id: Uuid,
) -> Result<Option<HarnessWorkOrderAttemptRecord>, StorageError>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query(&format!("{ATTEMPT_COLUMNS} WHERE id = ?1"))
        .bind(id.to_string())
        .fetch_optional(executor)
        .await?;
    row.map(|row| attempt_from_row(&row)).transpose()
}

fn work_order_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<HarnessWorkOrderRecord, StorageError> {
    Ok(HarnessWorkOrderRecord {
        id: row.try_get("id")?,
        target_id: parse_uuid("target_id", &row.try_get::<String, _>("target_id")?)?,
        project_root: row.try_get("project_root")?,
        schema_version: row.try_get("schema_version")?,
        packet_json: row.try_get("packet_json")?,
        created_at: parse_timestamp("created_at", &row.try_get::<String, _>("created_at")?)?,
    })
}

fn submission_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<HarnessWorkOrderSubmissionRecord, StorageError> {
    Ok(HarnessWorkOrderSubmissionRecord {
        id: parse_uuid("id", &row.try_get::<String, _>("id")?)?,
        work_order_id: row.try_get("work_order_id")?,
        source: row.try_get("source")?,
        source_sha256: row.try_get("source_sha256")?,
        origin_json: row.try_get("origin_json")?,
        parent_submission_id: row
            .try_get::<Option<String>, _>("parent_submission_id")?
            .map(|value| parse_uuid("parent_submission_id", &value))
            .transpose()?,
        lint_json: row.try_get("lint_json")?,
        submitted_at: parse_timestamp("submitted_at", &row.try_get::<String, _>("submitted_at")?)?,
    })
}

fn attempt_from_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<HarnessWorkOrderAttemptRecord, StorageError> {
    Ok(HarnessWorkOrderAttemptRecord {
        id: parse_uuid("id", &row.try_get::<String, _>("id")?)?,
        submission_id: parse_uuid("submission_id", &row.try_get::<String, _>("submission_id")?)?,
        status: HarnessWorkOrderAttemptStatus::parse(&row.try_get::<String, _>("status")?)?,
        current_stage: HarnessWorkOrderAttemptStage::parse(
            &row.try_get::<String, _>("current_stage")?,
        )?,
        harness_id: row
            .try_get::<Option<String>, _>("harness_id")?
            .map(|value| parse_uuid("harness_id", &value))
            .transpose()?,
        smoke_run_id: row
            .try_get::<Option<String>, _>("smoke_run_id")?
            .map(|value| parse_uuid("smoke_run_id", &value))
            .transpose()?,
        result_json: row.try_get("result_json")?,
        failure_code: row.try_get("failure_code")?,
        failure_message: row.try_get("failure_message")?,
        started_at: parse_timestamp("started_at", &row.try_get::<String, _>("started_at")?)?,
        updated_at: parse_timestamp("updated_at", &row.try_get::<String, _>("updated_at")?)?,
        ended_at: row
            .try_get::<Option<String>, _>("ended_at")?
            .map(|value| parse_timestamp("ended_at", &value))
            .transpose()?,
    })
}

fn validate_new_attempt(record: &HarnessWorkOrderAttemptRecord) -> Result<(), StorageError> {
    if record.status != HarnessWorkOrderAttemptStatus::Running
        || record.current_stage != HarnessWorkOrderAttemptStage::Compile
        || record.harness_id.is_some()
        || record.smoke_run_id.is_some()
        || record.result_json.is_some()
        || record.failure_code.is_some()
        || record.failure_message.is_some()
        || record.ended_at.is_some()
        || record.updated_at < record.started_at
    {
        return Err(StorageError::InvalidData(
            "invalid new harness work order attempt".to_owned(),
        ));
    }
    Ok(())
}

fn valid_stage_transition(
    expected: HarnessWorkOrderAttemptStage,
    next: HarnessWorkOrderAttemptStage,
) -> bool {
    matches!(
        (expected, next),
        (
            HarnessWorkOrderAttemptStage::Compile,
            HarnessWorkOrderAttemptStage::Review
        ) | (
            HarnessWorkOrderAttemptStage::Review,
            HarnessWorkOrderAttemptStage::Smoke
        )
    )
}

fn valid_completion(completion: &HarnessWorkOrderAttemptCompletion<'_>) -> bool {
    matches!(
        (completion.expected_stage, completion.status),
        (
            HarnessWorkOrderAttemptStage::Compile,
            HarnessWorkOrderAttemptStatus::CompileFailed
        ) | (
            HarnessWorkOrderAttemptStage::Review,
            HarnessWorkOrderAttemptStatus::ReviewFailed
        ) | (
            HarnessWorkOrderAttemptStage::Smoke,
            HarnessWorkOrderAttemptStatus::SmokeFailed | HarnessWorkOrderAttemptStatus::SmokePassed
        )
    )
}

fn require_one_attempt_row(rows: u64, message: &str) -> Result<(), StorageError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(StorageError::InvalidData(message.to_owned()))
    }
}

fn exact_or_conflict<T: PartialEq>(
    existing: T,
    incoming: &T,
    message: &str,
) -> Result<T, StorageError> {
    if existing == *incoming {
        Ok(existing)
    } else {
        Err(StorageError::InvalidData(message.to_owned()))
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

fn utc_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
