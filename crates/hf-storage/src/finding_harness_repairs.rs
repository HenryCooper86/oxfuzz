//! Finding-driven harness repair requests retained before dispatch, and their
//! outcomes (migration 0055).
use crate::{StorageError, Store};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

/// Bytes of a retained prompt or response, matching the table's `CHECK`s.
pub const MAX_FINDING_HARNESS_REPAIR_BYTES: usize = 64 * 1024;

/// Bytes of a retained outcome detail, matching the table's `CHECK`.
pub const MAX_FINDING_HARNESS_REPAIR_DETAIL_BYTES: usize = 4096;

/// How one finding-driven repair request finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingHarnessRepairOutcome {
    /// A changed source compiled as an unpromoted proposal revision.
    Proposed,
    /// The model returned the harness unchanged.
    Unchanged,
    /// The answer was refused before it was compiled.
    Rejected,
    /// The provider, the response, or the compile failed.
    Failed,
}

impl FindingHarnessRepairOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Unchanged => "unchanged",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }

    fn parse(text: &str) -> Result<Self, StorageError> {
        match text {
            "proposed" => Ok(Self::Proposed),
            "unchanged" => Ok(Self::Unchanged),
            "rejected" => Ok(Self::Rejected),
            "failed" => Ok(Self::Failed),
            _ => Err(invalid("unknown outcome")),
        }
    }
}

/// One repair request and, once finished, its response and outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingHarnessRepairRecord {
    /// Immutable repair ID.
    pub id: Uuid,
    /// The finding the repair responds to.
    pub crash_id: Uuid,
    /// The run that found the crash.
    pub run_id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// `hf_prompt::FINDING_REPAIR_PROMPT_VERSION` of the renderer.
    pub prompt_version: u32,
    /// SHA-256 of the harness source the repair started from.
    pub base_source_sha256: String,
    /// Exact prompt sent to the provider.
    pub prompt: String,
    /// The provider's response text, when one was received and fits.
    pub response: Option<String>,
    /// How the repair finished; `None` while pending.
    pub outcome: Option<FindingHarnessRepairOutcome>,
    /// Why it finished that way; `None` while pending.
    pub detail: Option<String>,
    /// The compiled proposal revision, for a `Proposed` outcome only.
    pub harness_id: Option<Uuid>,
    /// When the prompt was retained.
    pub created_at: DateTime<Utc>,
    /// When the outcome was recorded.
    pub completed_at: Option<DateTime<Utc>>,
}

/// The terminal values of one repair request.
#[derive(Debug, Clone, Copy)]
pub struct FindingHarnessRepairCompletion<'a> {
    /// The provider's response, when one was received and fits.
    pub response: Option<&'a str>,
    /// How the repair finished.
    pub outcome: FindingHarnessRepairOutcome,
    /// Why it finished that way.
    pub detail: &'a str,
    /// The compiled proposal revision, for a `Proposed` outcome only.
    pub harness_id: Option<Uuid>,
}

fn invalid(reason: &str) -> StorageError {
    StorageError::InvalidData(format!("finding harness repair: {reason}"))
}

fn encode_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn decode_time(text: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(text)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid("invalid timestamp"))
}

fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<FindingHarnessRepairRecord, StorageError> {
    let uuid = |column: &str| -> Result<Uuid, StorageError> {
        let text: String = row.try_get(column)?;
        Uuid::parse_str(&text).map_err(|_| invalid("invalid UUID"))
    };
    let version: i64 = row.try_get("prompt_version")?;
    let outcome: Option<String> = row.try_get("outcome")?;
    let harness_id: Option<String> = row.try_get("harness_id")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;
    Ok(FindingHarnessRepairRecord {
        id: uuid("id")?,
        crash_id: uuid("crash_id")?,
        run_id: uuid("run_id")?,
        project_root: row.try_get("project_root")?,
        prompt_version: u32::try_from(version).map_err(|_| invalid("invalid prompt version"))?,
        base_source_sha256: row.try_get("base_source_sha256")?,
        prompt: row.try_get("prompt")?,
        response: row.try_get("response")?,
        outcome: outcome
            .as_deref()
            .map(FindingHarnessRepairOutcome::parse)
            .transpose()?,
        detail: row.try_get("detail")?,
        harness_id: harness_id
            .as_deref()
            .map(|text| Uuid::parse_str(text).map_err(|_| invalid("invalid harness UUID")))
            .transpose()?,
        created_at: decode_time(&row.try_get::<String, _>("created_at")?)?,
        completed_at: completed_at.as_deref().map(decode_time).transpose()?,
    })
}

impl Store {
    /// Retain a repair request before it is dispatched.
    ///
    /// # Errors
    /// Rejects a record that is already finished, an empty or oversized prompt,
    /// an invalid source digest, an unknown crash, a duplicate ID, or a SQL
    /// failure.
    pub async fn begin_finding_harness_repair(
        &self,
        record: &FindingHarnessRepairRecord,
    ) -> Result<(), StorageError> {
        if record.response.is_some()
            || record.outcome.is_some()
            || record.detail.is_some()
            || record.harness_id.is_some()
            || record.completed_at.is_some()
        {
            return Err(invalid("a new repair carries no result"));
        }
        if record.prompt.is_empty() || record.prompt.len() > MAX_FINDING_HARNESS_REPAIR_BYTES {
            return Err(invalid("prompt is empty or too large"));
        }
        if record.project_root.is_empty()
            || record.prompt_version == 0
            || record.base_source_sha256.len() != 64
        {
            return Err(invalid(
                "project root, prompt version, and source digest are required",
            ));
        }
        sqlx::query(
            "INSERT INTO finding_harness_repairs
             (id, crash_id, run_id, project_root, prompt_version, base_source_sha256, prompt,
              created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )
        .bind(record.id.to_string())
        .bind(record.crash_id.to_string())
        .bind(record.run_id.to_string())
        .bind(&record.project_root)
        .bind(i64::from(record.prompt_version))
        .bind(&record.base_source_sha256)
        .bind(&record.prompt)
        .bind(encode_time(record.created_at))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Record how a pending repair finished, once.
    ///
    /// # Errors
    /// Rejects an oversized response or detail, a revision on an outcome other
    /// than `Proposed` or none on `Proposed`, an unknown or finished repair, or
    /// a SQL failure.
    pub async fn complete_finding_harness_repair(
        &self,
        id: Uuid,
        completion: &FindingHarnessRepairCompletion<'_>,
        completed_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if completion
            .response
            .is_some_and(|response| response.len() > MAX_FINDING_HARNESS_REPAIR_BYTES)
            || completion.detail.len() > MAX_FINDING_HARNESS_REPAIR_DETAIL_BYTES
        {
            return Err(invalid("response or detail is too large"));
        }
        if (completion.outcome == FindingHarnessRepairOutcome::Proposed)
            != completion.harness_id.is_some()
        {
            return Err(invalid("only a proposal names a revision"));
        }
        let updated = sqlx::query(
            "UPDATE finding_harness_repairs
             SET response = ?2, outcome = ?3, detail = ?4, harness_id = ?5, completed_at = ?6
             WHERE id = ?1 AND outcome IS NULL",
        )
        .bind(id.to_string())
        .bind(completion.response)
        .bind(completion.outcome.as_str())
        .bind(completion.detail)
        .bind(completion.harness_id.map(|harness| harness.to_string()))
        .bind(encode_time(completed_at))
        .execute(self.pool())
        .await?;
        if updated.rows_affected() != 1 {
            return Err(invalid("repair is unknown or already finished"));
        }
        Ok(())
    }

    /// A finding's repair requests, newest first.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn finding_harness_repairs_for_crash(
        &self,
        crash_id: Uuid,
    ) -> Result<Vec<FindingHarnessRepairRecord>, StorageError> {
        sqlx::query(
            "SELECT * FROM finding_harness_repairs WHERE crash_id = ?1
             ORDER BY created_at DESC, id DESC",
        )
        .bind(crash_id.to_string())
        .fetch_all(self.pool())
        .await?
        .iter()
        .map(from_row)
        .collect()
    }
}
