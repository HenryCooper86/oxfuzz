//! Immutable LLVM export evidence owned by one campaign executable and image.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{StorageError, Store};

/// Retained function counters and the artifacts used to interpret them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunFunctionCoverageRecord {
    pub run_id: Uuid,
    pub binary_sha256: String,
    pub sandbox_rev: String,
    pub profile_sha256: String,
    pub export_sha256: String,
    pub export_json: String,
    pub collected_at: DateTime<Utc>,
}

fn invalid(reason: &str) -> StorageError {
    StorageError::InvalidData(format!("run function coverage: {reason}"))
}

fn validate(record: &RunFunctionCoverageRecord) -> Result<(), StorageError> {
    for digest in [
        &record.binary_sha256,
        &record.profile_sha256,
        &record.export_sha256,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid("invalid artifact digest"));
        }
    }
    if record.export_json.len() > 8 * 1024 * 1024
        || format!("{:x}", Sha256::digest(record.export_json.as_bytes())) != record.export_sha256
    {
        return Err(invalid("invalid export size or digest"));
    }
    serde_json::from_str::<serde_json::Value>(&record.export_json)?;
    Ok(())
}

fn from_row(
    row: &sqlx::sqlite::SqliteRow,
    run_id: Uuid,
) -> Result<RunFunctionCoverageRecord, StorageError> {
    let record = RunFunctionCoverageRecord {
        run_id,
        binary_sha256: row.try_get("binary_sha256")?,
        sandbox_rev: row.try_get("sandbox_rev")?,
        profile_sha256: row.try_get("profile_sha256")?,
        export_sha256: row.try_get("export_sha256")?,
        export_json: row.try_get("export_json")?,
        collected_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("collected_at")?)
            .map_err(|error| StorageError::Timestamp(error.to_string()))?
            .with_timezone(&Utc),
    };
    validate(&record)?;
    Ok(record)
}

impl Store {
    /// Retain a verified export once; identical retries preserve the original evidence.
    ///
    /// # Errors
    /// Rejects a missing/different run executable or image, invalid JSON/digests, and replacement.
    pub async fn record_run_function_coverage(
        &self,
        record: &RunFunctionCoverageRecord,
    ) -> Result<(), StorageError> {
        validate(record)?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("INSERT INTO run_function_coverage (run_id, binary_sha256, sandbox_rev, profile_sha256, export_sha256, export_json, collected_at) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 FROM runs WHERE id = ?1 AND binary_rev = ?2 AND sandbox_rev = ?3 ON CONFLICT(run_id) DO NOTHING")
            .bind(record.run_id.to_string()).bind(&record.binary_sha256).bind(&record.sandbox_rev)
            .bind(&record.profile_sha256).bind(&record.export_sha256).bind(&record.export_json)
            .bind(record.collected_at.to_rfc3339()).execute(&mut *tx).await?;
        let row = sqlx::query("SELECT c.* FROM run_function_coverage c JOIN runs r ON r.id = c.run_id AND r.binary_rev = c.binary_sha256 AND r.sandbox_rev = c.sandbox_rev WHERE c.run_id = ?1")
            .bind(record.run_id.to_string()).fetch_optional(&mut *tx).await?
            .ok_or_else(|| invalid("run executable or image does not match"))?;
        if from_row(&row, record.run_id)? != *record {
            return Err(invalid("different evidence is already retained"));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read original function evidence, checking that its run still owns the artifacts.
    ///
    /// # Errors
    /// Returns storage failures or malformed/inconsistent retained evidence.
    pub async fn run_function_coverage(
        &self,
        run_id: Uuid,
    ) -> Result<Option<RunFunctionCoverageRecord>, StorageError> {
        let Some(row) = sqlx::query("SELECT * FROM run_function_coverage WHERE run_id = ?1")
            .bind(run_id.to_string())
            .fetch_optional(self.pool())
            .await?
        else {
            return Ok(None);
        };
        let record = from_row(&row, run_id)?;
        let run = self
            .get_run(run_id)
            .await?
            .ok_or_else(|| invalid("owning run is missing"))?;
        if run.binary_rev.as_ref() != Some(&record.binary_sha256)
            || run.sandbox_rev.as_ref() != Some(&record.sandbox_rev)
        {
            return Err(invalid("run executable or image changed"));
        }
        Ok(Some(record))
    }
}
