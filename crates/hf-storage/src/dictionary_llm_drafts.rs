//! Dictionary-augmentation requests retained before dispatch, and their
//! responses (migration 0047).
use crate::{StorageError, Store};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row as _;
use uuid::Uuid;

/// Bytes of a retained prompt or response, matching the table's `CHECK`s.
pub const MAX_DICTIONARY_LLM_DRAFT_BYTES: usize = 64 * 1024;

/// One dictionary-augmentation request and, once answered, its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DictionaryLlmDraftRecord {
    /// Immutable draft ID.
    pub id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// The target selector of the run being staged.
    pub target: String,
    /// Hex SHA-256 of the static dictionary text the prompt was built from.
    pub static_dict_sha256: String,
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
    StorageError::InvalidData(format!("dictionary draft: {reason}"))
}

fn encode_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn decode_time(text: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(text)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid("invalid timestamp"))
}

fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<DictionaryLlmDraftRecord, StorageError> {
    let id: String = row.try_get("id")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;
    Ok(DictionaryLlmDraftRecord {
        id: Uuid::parse_str(&id).map_err(|_| invalid("invalid UUID"))?,
        project_root: row.try_get("project_root")?,
        target: row.try_get("target")?,
        static_dict_sha256: row.try_get("static_dict_sha256")?,
        prompt: row.try_get("prompt")?,
        response: row.try_get("response")?,
        created_at: decode_time(&row.try_get::<String, _>("created_at")?)?,
        completed_at: completed_at.as_deref().map(decode_time).transpose()?,
    })
}

impl Store {
    /// Retain an augmentation request before it is dispatched.
    ///
    /// # Errors
    /// Rejects a record that already carries a response, an empty or
    /// oversized prompt, an empty project root or target, a malformed
    /// static-dictionary signature, a duplicate ID, or a SQL failure.
    pub async fn begin_dictionary_llm_draft(
        &self,
        record: &DictionaryLlmDraftRecord,
    ) -> Result<(), StorageError> {
        if record.response.is_some() || record.completed_at.is_some() {
            return Err(invalid("a new draft carries no response"));
        }
        if record.prompt.is_empty() || record.prompt.len() > MAX_DICTIONARY_LLM_DRAFT_BYTES {
            return Err(invalid("prompt is empty or too large"));
        }
        if record.project_root.is_empty() || record.target.is_empty() {
            return Err(invalid("project root and target are required"));
        }
        if record.static_dict_sha256.len() != 64
            || !record
                .static_dict_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid(
                "static dictionary signature must be 64 hex characters",
            ));
        }
        sqlx::query(
            "INSERT INTO dictionary_llm_drafts
             (id, project_root, target, static_dict_sha256, prompt, response,
              created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, NULL)",
        )
        .bind(record.id.to_string())
        .bind(&record.project_root)
        .bind(&record.target)
        .bind(&record.static_dict_sha256)
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
    pub async fn complete_dictionary_llm_draft(
        &self,
        id: Uuid,
        response: &str,
        completed_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if response.len() > MAX_DICTIONARY_LLM_DRAFT_BYTES {
            return Err(invalid("response is too large"));
        }
        let updated = sqlx::query(
            "UPDATE dictionary_llm_drafts SET response = ?2, completed_at = ?3
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

    /// The latest completed draft for a project, target, and static
    /// dictionary version, for reuse without a provider call.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn latest_completed_dictionary_llm_draft(
        &self,
        project_root: &str,
        target: &str,
        static_dict_sha256: &str,
    ) -> Result<Option<DictionaryLlmDraftRecord>, StorageError> {
        sqlx::query(
            "SELECT * FROM dictionary_llm_drafts
             WHERE project_root = ?1 AND target = ?2 AND static_dict_sha256 = ?3
               AND response IS NOT NULL
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(project_root)
        .bind(target)
        .bind(static_dict_sha256)
        .fetch_optional(self.pool())
        .await?
        .as_ref()
        .map(from_row)
        .transpose()
    }

    /// A project and target's drafts, newest first.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn dictionary_llm_drafts_for(
        &self,
        project_root: &str,
        target: &str,
    ) -> Result<Vec<DictionaryLlmDraftRecord>, StorageError> {
        sqlx::query(
            "SELECT * FROM dictionary_llm_drafts
             WHERE project_root = ?1 AND target = ?2
             ORDER BY created_at DESC, id DESC",
        )
        .bind(project_root)
        .bind(target)
        .fetch_all(self.pool())
        .await?
        .iter()
        .map(from_row)
        .collect()
    }
}
