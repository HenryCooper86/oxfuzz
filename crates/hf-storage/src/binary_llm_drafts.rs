//! Binary-only-fuzzing model prompts retained before dispatch, and their
//! responses (migration 0056).
use crate::{StorageError, Store};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row as _;
use uuid::Uuid;

/// Bytes of a retained prompt or response, matching the table's `CHECK`s.
pub const MAX_BINARY_LLM_DRAFT_BYTES: usize = 64 * 1024;

/// The binary-only assist a draft belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryDraftPurpose {
    /// Seed drafting for a binary target.
    Seeds,
    /// Dictionary drafting for a binary target.
    Dictionary,
    /// Explanation of one finding of a session.
    Explain,
}

impl BinaryDraftPurpose {
    /// The stored name, matching the table's `CHECK` list.
    fn as_str(self) -> &'static str {
        match self {
            Self::Seeds => "seeds",
            Self::Dictionary => "dictionary",
            Self::Explain => "explain",
        }
    }

    /// Decode a stored name, rejecting a value the `CHECK` admits no writer
    /// for.
    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "seeds" => Ok(Self::Seeds),
            "dictionary" => Ok(Self::Dictionary),
            "explain" => Ok(Self::Explain),
            _ => Err(invalid("unknown binary draft purpose")),
        }
    }
}

/// One binary-only model request and, once answered, its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryLlmDraftRecord {
    /// Immutable draft ID.
    pub id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// Hex SHA-256 of the binary the prompt describes.
    pub binary_sha256: String,
    /// The assist the prompt serves.
    pub purpose: BinaryDraftPurpose,
    /// Fuzzing session of an explanation; `None` for the other purposes.
    pub session: Option<Uuid>,
    /// Hex SHA-256 of the explained finding; `None` for the other purposes.
    pub finding_sha256: Option<String>,
    /// Version of the prompt renderer.
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
    StorageError::InvalidData(format!("binary draft: {reason}"))
}

fn encode_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn decode_time(text: &str) -> Result<DateTime<Utc>, StorageError> {
    DateTime::parse_from_rfc3339(text)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| invalid("invalid timestamp"))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<BinaryLlmDraftRecord, StorageError> {
    let id: String = row.try_get("id")?;
    let purpose: String = row.try_get("purpose")?;
    let session: Option<String> = row.try_get("session")?;
    let version: i64 = row.try_get("prompt_version")?;
    let completed_at: Option<String> = row.try_get("completed_at")?;
    Ok(BinaryLlmDraftRecord {
        id: Uuid::parse_str(&id).map_err(|_| invalid("invalid UUID"))?,
        project_root: row.try_get("project_root")?,
        binary_sha256: row.try_get("binary_sha256")?,
        purpose: BinaryDraftPurpose::parse(&purpose)?,
        session: session
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| invalid("invalid session UUID"))?,
        finding_sha256: row.try_get("finding_sha256")?,
        prompt_version: u32::try_from(version).map_err(|_| invalid("invalid prompt version"))?,
        prompt: row.try_get("prompt")?,
        response: row.try_get("response")?,
        created_at: decode_time(&row.try_get::<String, _>("created_at")?)?,
        completed_at: completed_at.as_deref().map(decode_time).transpose()?,
    })
}

fn validate_new(record: &BinaryLlmDraftRecord) -> Result<(), StorageError> {
    if record.response.is_some() || record.completed_at.is_some() {
        return Err(invalid("a new draft carries no response"));
    }
    if record.prompt.is_empty() || record.prompt.len() > MAX_BINARY_LLM_DRAFT_BYTES {
        return Err(invalid("prompt is empty or too large"));
    }
    if record.project_root.is_empty() {
        return Err(invalid("project root is required"));
    }
    if record.prompt_version == 0 {
        return Err(invalid("prompt version must be at least 1"));
    }
    if !is_sha256_hex(&record.binary_sha256) {
        return Err(invalid("binary signature must be 64 hex characters"));
    }
    if record
        .finding_sha256
        .as_deref()
        .is_some_and(|sha| !is_sha256_hex(sha))
    {
        return Err(invalid("finding signature must be 64 hex characters"));
    }
    let keyed = record.session.is_some() && record.finding_sha256.is_some();
    let unkeyed = record.session.is_none() && record.finding_sha256.is_none();
    let explain = record.purpose == BinaryDraftPurpose::Explain;
    if (explain && !keyed) || (!explain && !unkeyed) {
        return Err(invalid(
            "only an explanation carries a session and a finding",
        ));
    }
    Ok(())
}

impl Store {
    /// Retain a binary-only model request before it is dispatched.
    ///
    /// # Errors
    /// Rejects a record that already carries a response, an empty or
    /// oversized prompt, an empty project root, a zero prompt version, a
    /// malformed signature, a purpose that disagrees with its session and
    /// finding, a duplicate ID, or a SQL failure.
    pub async fn begin_binary_llm_draft(
        &self,
        record: &BinaryLlmDraftRecord,
    ) -> Result<(), StorageError> {
        validate_new(record)?;
        sqlx::query(
            "INSERT INTO binary_llm_drafts
             (id, project_root, binary_sha256, purpose, session, finding_sha256,
              prompt_version, prompt, response, created_at, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, NULL)",
        )
        .bind(record.id.to_string())
        .bind(&record.project_root)
        .bind(&record.binary_sha256)
        .bind(record.purpose.as_str())
        .bind(record.session.map(|session| session.to_string()))
        .bind(&record.finding_sha256)
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
    pub async fn complete_binary_llm_draft(
        &self,
        id: Uuid,
        response: &str,
        at: DateTime<Utc>,
    ) -> Result<(), StorageError> {
        if response.len() > MAX_BINARY_LLM_DRAFT_BYTES {
            return Err(invalid("response is too large"));
        }
        let updated = sqlx::query(
            "UPDATE binary_llm_drafts SET response = ?2, completed_at = ?3
             WHERE id = ?1 AND response IS NULL",
        )
        .bind(id.to_string())
        .bind(response)
        .bind(encode_time(at))
        .execute(self.pool())
        .await?;
        if updated.rows_affected() != 1 {
            return Err(invalid("draft is unknown or already answered"));
        }
        Ok(())
    }

    /// The newest completed explanation of a finding in a session.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn latest_binary_explanation(
        &self,
        project_root: &str,
        session: Uuid,
        finding_sha256: &str,
    ) -> Result<Option<BinaryLlmDraftRecord>, StorageError> {
        sqlx::query(
            "SELECT * FROM binary_llm_drafts
             WHERE project_root = ?1 AND session = ?2 AND finding_sha256 = ?3
               AND purpose = 'explain' AND response IS NOT NULL
             ORDER BY created_at DESC, id DESC LIMIT 1",
        )
        .bind(project_root)
        .bind(session.to_string())
        .bind(finding_sha256)
        .fetch_optional(self.pool())
        .await?
        .as_ref()
        .map(from_row)
        .transpose()
    }
}
