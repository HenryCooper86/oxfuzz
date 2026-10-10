//! Immutable per-run covered edge sets (migration `0038_run_edge_sets.sql`).
//!
//! One row retains the union of AFL coverage-map offsets a run's retained
//! corpus exercises, replayed through `afl-showmap` against the run's exact
//! staged binary. The bitmap is fixed at
//! [`hf_core::coverage::EDGE_SET_BYTES`] bytes, and `edge_count` must equal
//! its popcount, so a row is bounded and self-checking on read. The insert
//! binds the owning run's retained executable and sandbox image digests;
//! identical retries are idempotent, and different evidence for the same run
//! is rejected rather than replaced.

use chrono::{DateTime, Utc};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{StorageError, Store};

/// The typed sandbox image identity prefix runs persist in `sandbox_rev`.
const SANDBOX_IMAGE_REV_PREFIX: &str = "docker-image-id-sha256:";

/// One run's retained covered edge set and the artifacts it was measured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEdgeSetRecord {
    pub run_id: Uuid,
    /// SHA-256 of the exact staged executable the map was measured with.
    pub binary_sha256: String,
    /// Typed sandbox image identity the measurement ran under.
    pub sandbox_rev: String,
    /// Corpus inputs replayed to build the set.
    pub inputs: u64,
    /// Covered offsets; equals the bitmap popcount.
    pub edge_count: u64,
    /// The bitmap, exactly [`hf_core::coverage::EDGE_SET_BYTES`] bytes.
    pub edge_map: Vec<u8>,
    pub collected_at: DateTime<Utc>,
}

fn invalid(reason: &str) -> StorageError {
    StorageError::InvalidData(format!("run edge set: {reason}"))
}

fn lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn popcount(map: &[u8]) -> u64 {
    map.iter().map(|byte| u64::from(byte.count_ones())).sum()
}

fn validate(record: &RunEdgeSetRecord) -> Result<(), StorageError> {
    if !lower_hex_digest(&record.binary_sha256) {
        return Err(invalid("invalid executable digest"));
    }
    let Some(image) = record.sandbox_rev.strip_prefix(SANDBOX_IMAGE_REV_PREFIX) else {
        return Err(invalid("invalid sandbox image identity"));
    };
    if !lower_hex_digest(image) {
        return Err(invalid("invalid sandbox image identity"));
    }
    if record.inputs == 0 {
        return Err(invalid("a measured edge set replays at least one input"));
    }
    if record.edge_map.len() != hf_core::coverage::EDGE_SET_BYTES {
        return Err(invalid("edge map length mismatch"));
    }
    if record.edge_count != popcount(&record.edge_map) {
        return Err(invalid("edge count does not match the edge map"));
    }
    Ok(())
}

fn from_row(row: &sqlx::sqlite::SqliteRow, run_id: Uuid) -> Result<RunEdgeSetRecord, StorageError> {
    let record = RunEdgeSetRecord {
        run_id,
        binary_sha256: row.try_get("binary_sha256")?,
        sandbox_rev: row.try_get("sandbox_rev")?,
        inputs: u64::try_from(row.try_get::<i64, _>("inputs")?)
            .map_err(|_| invalid("negative input count"))?,
        edge_count: u64::try_from(row.try_get::<i64, _>("edge_count")?)
            .map_err(|_| invalid("negative edge count"))?,
        edge_map: row.try_get("edge_map")?,
        collected_at: DateTime::parse_from_rfc3339(&row.try_get::<String, _>("collected_at")?)
            .map_err(|error| StorageError::Timestamp(error.to_string()))?
            .with_timezone(&Utc),
    };
    validate(&record)?;
    Ok(record)
}

impl Store {
    /// Retain a verified edge set once; identical retries preserve the
    /// original evidence.
    ///
    /// # Errors
    /// Rejects a missing/different run executable or image, malformed
    /// digests, an inconsistent bitmap, and replacement.
    pub async fn record_run_edge_set(&self, record: &RunEdgeSetRecord) -> Result<(), StorageError> {
        validate(record)?;
        let mut tx = self.pool().begin().await?;
        sqlx::query("INSERT INTO run_edge_sets (run_id, binary_sha256, sandbox_rev, inputs, edge_count, edge_map, collected_at) SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7 FROM runs WHERE id = ?1 AND binary_rev = ?2 AND sandbox_rev = ?3 ON CONFLICT(run_id) DO NOTHING")
            .bind(record.run_id.to_string()).bind(&record.binary_sha256).bind(&record.sandbox_rev)
            .bind(i64::try_from(record.inputs).map_err(|_| invalid("input count overflows i64"))?)
            .bind(i64::try_from(record.edge_count).map_err(|_| invalid("edge count overflows i64"))?)
            .bind(&record.edge_map)
            .bind(record.collected_at.to_rfc3339()).execute(&mut *tx).await?;
        let row = sqlx::query("SELECT s.* FROM run_edge_sets s JOIN runs r ON r.id = s.run_id AND r.binary_rev = s.binary_sha256 AND r.sandbox_rev = s.sandbox_rev WHERE s.run_id = ?1")
            .bind(record.run_id.to_string()).fetch_optional(&mut *tx).await?
            .ok_or_else(|| invalid("run executable or image does not match"))?;
        if from_row(&row, record.run_id)? != *record {
            return Err(invalid("different evidence is already retained"));
        }
        tx.commit().await?;
        Ok(())
    }

    /// Read one run's retained edge set, checking that the run still owns the
    /// measured artifacts.
    ///
    /// # Errors
    /// Returns storage failures or malformed/inconsistent retained evidence.
    pub async fn run_edge_set(
        &self,
        run_id: Uuid,
    ) -> Result<Option<RunEdgeSetRecord>, StorageError> {
        let Some(row) = sqlx::query("SELECT * FROM run_edge_sets WHERE run_id = ?1")
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
