//! Seed-drafting requests retained before dispatch, and their responses
//! (migration 0049).
use crate::{StorageError, Store};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row as _;
use uuid::Uuid;

/// Bytes of a retained prompt or response, matching the table's `CHECK`s.
pub const MAX_SEED_LLM_DRAFT_BYTES: usize = 64 * 1024;

/// The seed path a draft belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedDraftPurpose {
    /// First-time corpus seeding (`generate_seeds_llm`).
    Initial,
    /// Replacing seeds that died at the harness's entry validation
    /// (`regenerate_dead_seeds`).
    Regenerate,
}

impl SeedDraftPurpose {
    /// The stored name, matching the table's `CHECK` list.
    fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Regenerate => "regenerate",
        }
    }

    /// Decode a stored name, rejecting a value the `CHECK` admits no writer
    /// for.
    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "initial" => Ok(Self::Initial),
            "regenerate" => Ok(Self::Regenerate),
            _ => Err(invalid("unknown seed draft purpose")),
        }
    }
}

/// One seed-drafting request and, once answered, its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedLlmDraftRecord {
    /// Immutable draft ID.
    pub id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// The target selector being seeded.
    pub target: String,
    /// The seed path the prompt serves.
    pub purpose: SeedDraftPurpose,
    /// `hf_prompt::SEED_PROMPT_VERSION` of the renderer.
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
    StorageError::InvalidData(format!("seed draft: {reason}"))
}

fn encode_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn decode_time(text: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(text)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid("invalid timestamp"))
}

fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<SeedLlmDraftRecord, StorageError> {
    let id: String = row.try_get("id")?;
    let purpose: String = row.try_get("purpose")?;
    let version: i64 = row.try_get("prompt_version")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;
    Ok(SeedLlmDraftRecord {
        id: Uuid::parse_str(&id).map_err(|_| invalid("invalid UUID"))?,
        project_root: row.try_get("project_root")?,
        target: row.try_get("target")?,
        purpose: SeedDraftPurpose::parse(&purpose)?,
        prompt_version: u32::try_from(version).map_err(|_| invalid("invalid prompt version"))?,
        prompt: row.try_get("prompt")?,
        response: row.try_get("response")?,
        created_at: decode_time(&row.try_get::<String, _>("created_at")?)?,
        completed_at: completed_at.as_deref().map(decode_time).transpose()?,
    })
}

impl Store {
    /// Retain a seed-drafting request before it is dispatched.
    ///
    /// # Errors
    /// Rejects a record that already carries a response, an empty or
    /// oversized prompt, an empty project root or target, a zero prompt
    /// version, a duplicate ID, or a SQL failure.
    pub async fn begin_seed_llm_draft(
        &self,
        record: &SeedLlmDraftRecord,
    ) -> Result<(), StorageError> {
        if record.response.is_some() || record.completed_at.is_some() {
            return Err(invalid("a new draft carries no response"));
        }
        if record.prompt.is_empty() || record.prompt.len() > MAX_SEED_LLM_DRAFT_BYTES {
            return Err(invalid("prompt is empty or too large"));
        }
        if record.project_root.is_empty() || record.target.is_empty() {
            return Err(invalid("project root and target are required"));
        }
        if record.prompt_version == 0 {
            return Err(invalid("prompt version must be at least 1"));
        }
        sqlx::query(
            "INSERT INTO seed_llm_drafts
             (id, project_root, target, purpose, prompt_version, prompt, response,
              created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, NULL)",
        )
        .bind(record.id.to_string())
        .bind(&record.project_root)
        .bind(&record.target)
        .bind(record.purpose.as_str())
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
    pub async fn complete_seed_llm_draft(
        &self,
        id: Uuid,
        response: &str,
        completed_at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if response.len() > MAX_SEED_LLM_DRAFT_BYTES {
            return Err(invalid("response is too large"));
        }
        let updated = sqlx::query(
            "UPDATE seed_llm_drafts SET response = ?2, completed_at = ?3
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

    /// A project and target's seed drafts, newest first.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn seed_llm_drafts_for(
        &self,
        project_root: &str,
        target: &str,
    ) -> Result<Vec<SeedLlmDraftRecord>, StorageError> {
        sqlx::query(
            "SELECT * FROM seed_llm_drafts
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
