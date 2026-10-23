//! Immutable behavioral evidence for one reviewed smoke executable.
use crate::{StorageError, Store};
use sha2::{Digest, Sha256};
use sqlx::Row as _;
use uuid::Uuid;

/// Serialized service report bound to the smoke run's exact artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessBehaviorRecord {
    pub run_id: Uuid,
    pub source_sha256: String,
    pub binary_sha256: String,
    pub sandbox_rev: String,
    pub report_sha256: String,
    pub report_json: String,
}

fn invalid(reason: &str) -> StorageError {
    StorageError::InvalidData(format!("harness behavior: {reason}"))
}

fn validate(record: &HarnessBehaviorRecord) -> Result<(), StorageError> {
    for digest in [
        &record.source_sha256,
        &record.binary_sha256,
        &record.report_sha256,
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid("invalid digest"));
        }
    }
    if record.report_json.len() > 1024 * 1024
        || format!("{:x}", Sha256::digest(record.report_json.as_bytes())) != record.report_sha256
    {
        return Err(invalid("invalid report size or digest"));
    }
    serde_json::from_str::<serde_json::Value>(&record.report_json)?;
    Ok(())
}

fn from_row(
    row: &sqlx::sqlite::SqliteRow,
    run_id: Uuid,
) -> Result<HarnessBehaviorRecord, StorageError> {
    let record = HarnessBehaviorRecord {
        run_id,
        source_sha256: row.try_get("source_sha256")?,
        binary_sha256: row.try_get("binary_sha256")?,
        sandbox_rev: row.try_get("sandbox_rev")?,
        report_sha256: row.try_get("report_sha256")?,
        report_json: row.try_get("report_json")?,
    };
    validate(&record)?;
    Ok(record)
}

impl Store {
    /// Persist once, permitting only identical retries with matching run artifacts.
    ///
    /// # Errors
    /// Rejects mismatched source, executable, image, oversized JSON, or replacement.
    pub async fn record_harness_behavior(
        &self,
        record: &HarnessBehaviorRecord,
    ) -> Result<(), StorageError> {
        validate(record)?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("INSERT INTO harness_behavior (run_id, source_sha256, binary_sha256, sandbox_rev, report_sha256, report_json) SELECT ?1, ?2, ?3, ?4, ?5, ?6 FROM runs WHERE id = ?1 AND harness_rev = ?2 AND binary_rev = ?3 AND sandbox_rev = ?4 ON CONFLICT(run_id) DO NOTHING")
            .bind(record.run_id.to_string()).bind(&record.source_sha256).bind(&record.binary_sha256).bind(&record.sandbox_rev).bind(&record.report_sha256).bind(&record.report_json).execute(&mut *tx).await?;
        let row = sqlx::query("SELECT c.* FROM harness_behavior c JOIN runs r ON r.id = c.run_id AND r.harness_rev = c.source_sha256 AND r.binary_rev = c.binary_sha256 AND r.sandbox_rev = c.sandbox_rev WHERE c.run_id = ?1")
            .bind(record.run_id.to_string()).fetch_optional(&mut *tx).await?.ok_or_else(|| invalid("run artifacts do not match"))?;
        if from_row(&row, record.run_id)? != *record {
            return Err(invalid("different evidence is already retained"));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read evidence after checking its digest and current run ownership.
    ///
    /// # Errors
    /// Rejects corrupted evidence and changed run artifacts.
    pub async fn harness_behavior(
        &self,
        run_id: Uuid,
    ) -> Result<Option<HarnessBehaviorRecord>, StorageError> {
        let Some(row) = sqlx::query("SELECT * FROM harness_behavior WHERE run_id = ?1")
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
            .ok_or_else(|| invalid("owning run missing"))?;
        if run.harness_rev.as_ref() != Some(&record.source_sha256)
            || run.binary_rev.as_ref() != Some(&record.binary_sha256)
            || run.sandbox_rev.as_ref() != Some(&record.sandbox_rev)
        {
            return Err(invalid("run artifacts changed"));
        }
        Ok(Some(record))
    }
}
