//! Bug-report drafting requests retained before dispatch, and their responses
//! (migration 0046).
use crate::{StorageError, Store};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row as _;
use uuid::Uuid;

/// Bytes of a retained prompt or response, matching the table's `CHECK`s.
pub const MAX_CRASH_REPORT_DRAFT_BYTES: usize = 64 * 1024;

/// One bug-report drafting request and, once answered, its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrashReportDraftRecord {
    /// Immutable draft ID.
    pub id: Uuid,
    /// The crash the report describes.
    pub crash_id: Uuid,
    /// The run that found the crash.
    pub run_id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// `hf_prompt::BUG_REPORT_PROMPT_VERSION` of the renderer.
    pub prompt_version: u32,
    /// Exact prompt sent to the provider.
    pub prompt: String,
    /// The provider's response text; `None` until it arrives.
    pub response: Option<String>,
    /// When the prompt was retained.
    pub created_at: DateTime<Utc>,
    /// When the response was recorded.
    pub completed_at: Option<DateTime<Utc>>,
}

fn invalid(reason: &str) -> StorageError {
    StorageError::InvalidData(format!("crash report draft: {reason}"))
}

fn encode_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn decode_time(text: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(text)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid("invalid timestamp"))
}

fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<CrashReportDraftRecord, StorageError> {
    let uuid = |column: &str| -> Result<Uuid, StorageError> {
        let text: String = row.try_get(column)?;
        Uuid::parse_str(&text).map_err(|_| invalid("invalid UUID"))
    };
    let version: i64 = row.try_get("prompt_version")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;
    Ok(CrashReportDraftRecord {
        id: uuid("id")?,
        crash_id: uuid("crash_id")?,
        run_id: uuid("run_id")?,
        project_root: row.try_get("project_root")?,
        prompt_version: u32::try_from(version).map_err(|_| invalid("invalid prompt version"))?,
        prompt: row.try_get("prompt")?,
        response: row.try_get("response")?,
        created_at: decode_time(&row.try_get::<String, _>("created_at")?)?,
        completed_at: completed_at.as_deref().map(decode_time).transpose()?,
    })
}

impl Store {
    /// Retain a drafting request before it is dispatched.
    ///
    /// # Errors
    /// Rejects a record that already carries a response, an empty or
    /// oversized prompt, an unknown crash, a duplicate ID, or a SQL failure.
    pub async fn begin_crash_report_draft(
        &self,
        record: &CrashReportDraftRecord,
    ) -> Result<(), StorageError> {
        if record.response.is_some() || record.completed_at.is_some() {
            return Err(invalid("a new draft carries no response"));
        }
        if record.prompt.is_empty() || record.prompt.len() > MAX_CRASH_REPORT_DRAFT_BYTES {
            return Err(invalid("prompt is empty or too large"));
        }
        if record.project_root.is_empty() || record.prompt_version == 0 {
            return Err(invalid("project root and prompt version are required"));
        }
        sqlx::query(
            "INSERT INTO crash_report_drafts
             (id, crash_id, run_id, project_root, prompt_version, prompt, response,
              created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, NULL)",
        )
        .bind(record.id.to_string())
        .bind(record.crash_id.to_string())
        .bind(record.run_id.to_string())
        .bind(&record.project_root)
        .bind(i64::from(record.prompt_version))
        .bind(&record.prompt)
        .bind(encode_time(record.created_at))
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Record the provider's response of a pending draft, once.
    ///
    /// # Errors
    /// Rejects an oversized response, an unknown or already answered draft,
    /// or a SQL failure.
    pub async fn complete_crash_report_draft(
        &self,
        id: Uuid,
        response: &str,
        completed_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if response.len() > MAX_CRASH_REPORT_DRAFT_BYTES {
            return Err(invalid("response is too large"));
        }
        let updated = sqlx::query(
            "UPDATE crash_report_drafts SET response = ?2, completed_at = ?3
             WHERE id = ?1 AND response IS NULL",
        )
        .bind(id.to_string())
        .bind(response)
        .bind(encode_time(completed_at))
        .execute(self.pool())
        .await?;
        if updated.rows_affected() != 1 {
            return Err(invalid("draft is unknown or already answered"));
        }
        Ok(())
    }

    /// A crash's drafts, newest first.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn crash_report_drafts_for_crash(
        &self,
        crash_id: Uuid,
    ) -> Result<Vec<CrashReportDraftRecord>, StorageError> {
        sqlx::query(
            "SELECT * FROM crash_report_drafts WHERE crash_id = ?1
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
