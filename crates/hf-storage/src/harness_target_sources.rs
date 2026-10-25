//! Immutable target-definition sections retained before harness draft
//! dispatch (migration 0045).
use crate::{StorageError, Store};
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row as _;
use uuid::Uuid;

/// Bytes of one retained rendered section, matching the table's `CHECK`.
pub const MAX_TARGET_SOURCE_SECTION_BYTES: usize = 16 * 1024;

/// The exact target-definition section one harness draft sent to a provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessTargetSourceRecord {
    /// Immutable record ID.
    pub id: Uuid,
    /// Canonical project root the source was read from.
    pub project_root: String,
    /// Discovery target the section describes.
    pub target_id: Uuid,
    /// Source file, relative to the project root.
    pub source_file: String,
    /// SHA-256 of the complete source file the excerpt was cut from.
    pub source_sha256: String,
    /// Exact rendered prompt section.
    pub rendered: String,
    /// Capture time.
    pub created_at: DateTime<Utc>,
}

fn invalid(reason: &str) -> StorageError {
    StorageError::InvalidData(format!("harness target source: {reason}"))
}

fn validate(record: &HarnessTargetSourceRecord) -> Result<(), StorageError> {
    if record.project_root.is_empty() || record.source_file.is_empty() {
        return Err(invalid("project root and source file are required"));
    }
    if record.source_sha256.len() != 64
        || !record
            .source_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid source digest"));
    }
    if record.rendered.is_empty() || record.rendered.len() > MAX_TARGET_SOURCE_SECTION_BYTES {
        return Err(invalid("rendered section is empty or too large"));
    }
    Ok(())
}

fn encode_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Nanos, true)
}

fn from_row(row: &sqlx::sqlite::SqliteRow) -> Result<HarnessTargetSourceRecord, StorageError> {
    let uuid = |column: &str| -> Result<Uuid, StorageError> {
        let text: String = row.try_get(column)?;
        Uuid::parse_str(&text).map_err(|_| invalid("invalid UUID"))
    };
    let created_at: String = row.try_get("created_at")?;
    let record = HarnessTargetSourceRecord {
        id: uuid("id")?,
        project_root: row.try_get("project_root")?,
        target_id: uuid("target_id")?,
        source_file: row.try_get("source_file")?,
        source_sha256: row.try_get("source_sha256")?,
        rendered: row.try_get("rendered")?,
        created_at: DateTime::parse_from_rfc3339(&created_at)
            .map_err(|_| invalid("invalid timestamp"))?
            .with_timezone(&Utc),
    };
    validate(&record)?;
    Ok(record)
}

impl Store {
    /// Retain the exact section before provider dispatch, accepting only an
    /// identical retry of the same ID.
    ///
    /// # Errors
    /// Rejects a malformed record, a differing retry, or a SQL failure.
    pub async fn append_harness_target_source(
        &self,
        record: &HarnessTargetSourceRecord,
    ) -> Result<(), StorageError> {
        validate(record)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let saved = sqlx::query("SELECT * FROM harness_target_sources WHERE id = ?1")
            .bind(record.id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
        if let Some(saved) = saved {
            if from_row(&saved)? != *record {
                return Err(invalid("retained section is immutable"));
            }
        } else {
            sqlx::query(
                "INSERT INTO harness_target_sources
                 (id, project_root, target_id, source_file, source_sha256, rendered, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )
            .bind(record.id.to_string())
            .bind(&record.project_root)
            .bind(record.target_id.to_string())
            .bind(&record.source_file)
            .bind(&record.source_sha256)
            .bind(&record.rendered)
            .bind(encode_time(record.created_at))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read one retained section, strictly decoded.
    ///
    /// # Errors
    /// Rejects corrupted rows or a SQL failure.
    pub async fn harness_target_source(
        &self,
        id: Uuid,
    ) -> Result<Option<HarnessTargetSourceRecord>, StorageError> {
        sqlx::query("SELECT * FROM harness_target_sources WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?
            .as_ref()
            .map(from_row)
            .transpose()
    }

    /// Read a project's retained sections, newest first, at most `limit`
    /// (1..=100).
    ///
    /// # Errors
    /// Rejects an out-of-range limit, corrupted rows, or a SQL failure.
    pub async fn harness_target_sources_for_project(
        &self,
        project_root: &str,
        limit: usize,
    ) -> Result<Vec<HarnessTargetSourceRecord>, StorageError> {
        if !(1..=100).contains(&limit) {
            return Err(invalid("history limit must be in 1..=100"));
        }
        let limit = i64::try_from(limit).map_err(|_| invalid("history limit overflow"))?;
        sqlx::query(
            "SELECT * FROM harness_target_sources WHERE project_root = ?1
             ORDER BY created_at DESC, id DESC LIMIT ?2",
        )
        .bind(project_root)
        .bind(limit)
        .fetch_all(self.pool())
        .await?
        .iter()
        .map(from_row)
        .collect()
    }
}
