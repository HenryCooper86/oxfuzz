//! Durable scan publication and model input for target recommendations.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use hf_core::target::TargetLanguage;
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use uuid::Uuid;

use crate::{StorageError, Store};

/// State of one ranked discovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiDiscoveryState {
    Scanning,
    Ranking,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

impl AiDiscoveryState {
    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "scanning" => Ok(Self::Scanning),
            "ranking" => Ok(Self::Ranking),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "interrupted" => Ok(Self::Interrupted),
            _ => Err(StorageError::InvalidData(format!(
                "invalid AI discovery state: {value}"
            ))),
        }
    }
}

/// Provenance of the published ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiRankingSource {
    Pending,
    Ai,
    Mixed,
    Heuristic,
}

impl AiRankingSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ai => "ai",
            Self::Mixed => "mixed",
            Self::Heuristic => "heuristic",
        }
    }

    fn parse(value: &str) -> Result<Self, StorageError> {
        match value {
            "pending" => Ok(Self::Pending),
            "ai" => Ok(Self::Ai),
            "mixed" => Ok(Self::Mixed),
            "heuristic" => Ok(Self::Heuristic),
            _ => Err(StorageError::InvalidData(format!(
                "invalid AI ranking source: {value}"
            ))),
        }
    }
}

/// Persisted operation snapshot.
#[derive(Debug, Clone)]
pub struct AiDiscoveryRecord {
    pub id: Uuid,
    pub project_root: PathBuf,
    pub language: TargetLanguage,
    pub state: AiDiscoveryState,
    pub revision: u8,
    pub scan_json: Option<String>,
    pub assessment_json: Option<String>,
    pub source: AiRankingSource,
    pub reason_code: Option<String>,
    pub total_count: u32,
    pub assessed_count: u32,
    pub started_at: DateTime<Utc>,
    pub scanned_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// Persisted exact model input and batch result.
#[derive(Debug, Clone)]
pub struct AiRankBatchRecord {
    pub operation_id: Uuid,
    pub batch_index: u32,
    pub prompt: String,
    pub provider_model: String,
    pub resolved_model: Option<String>,
    pub outcome: String,
    pub assessment_json: Option<String>,
}

impl Store {
    /// Reserve an operation before starting the scan.
    ///
    /// # Errors
    /// Returns a storage error if insertion fails.
    pub async fn create_ai_discovery(
        &self,
        id: Uuid,
        project: &Path,
        language: TargetLanguage,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO ai_discovery_operations (id, project_root, language, state, started_at) VALUES (?1, ?2, ?3, 'scanning', ?4)")
            .bind(id.to_string())
            .bind(project.to_string_lossy().as_ref())
            .bind(language.as_str())
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        Ok(())
    }

    /// Publish the scan once, before any model request.
    ///
    /// # Errors
    /// Returns a storage error if publication fails.
    pub async fn publish_ai_scan(
        &self,
        id: Uuid,
        scan_json: &str,
        total_count: u32,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("UPDATE ai_discovery_operations SET state = 'ranking', revision = 1, scan_json = ?2, total_count = ?3, scanned_at = ?4 WHERE id = ?1 AND state = 'scanning' AND revision = 0")
            .bind(id.to_string())
            .bind(scan_json)
            .bind(i64::from(total_count))
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Start a new assessment from a retained scan without changing its scan time.
    ///
    /// # Errors
    /// Returns a storage error if the source is missing or insertion fails.
    pub async fn copy_ai_scan(&self, source_id: Uuid, new_id: Uuid) -> Result<(), StorageError> {
        let result = sqlx::query("INSERT INTO ai_discovery_operations (id, project_root, language, state, revision, scan_json, source, total_count, started_at, scanned_at) SELECT ?2, project_root, language, 'ranking', 1, scan_json, 'pending', total_count, ?3, scanned_at FROM ai_discovery_operations WHERE id = ?1 AND revision >= 1 AND scan_json IS NOT NULL")
            .bind(source_id.to_string())
            .bind(new_id.to_string())
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        if result.rows_affected() != 1 {
            return Err(StorageError::NotFound(format!(
                "retained AI discovery scan {source_id}"
            )));
        }
        Ok(())
    }

    /// Save exact rendered input before provider dispatch.
    ///
    /// # Errors
    /// Returns a storage error if insertion fails.
    pub async fn save_ai_rank_prompt(
        &self,
        id: Uuid,
        batch_index: u32,
        prompt: &str,
        provider_model: &str,
    ) -> Result<bool, StorageError> {
        if prompt.len() > 32 * 1024 {
            return Err(StorageError::InvalidData(
                "AI rank prompt exceeds 32 KiB".to_owned(),
            ));
        }
        let result = sqlx::query("INSERT INTO ai_rank_batches (operation_id, batch_index, prompt, provider_model) SELECT id, ?2, ?3, ?4 FROM ai_discovery_operations WHERE id = ?1 AND state = 'ranking'")
            .bind(id.to_string())
            .bind(i64::from(batch_index))
            .bind(prompt)
            .bind(provider_model)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Record a batch result after validation.
    ///
    /// # Errors
    /// Returns a storage error if updating fails.
    pub async fn finish_ai_rank_batch(
        &self,
        id: Uuid,
        batch_index: u32,
        outcome: &str,
        assessment_json: Option<&str>,
        resolved_model: Option<&str>,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("UPDATE ai_rank_batches SET outcome = ?3, assessment_json = ?4, resolved_model = ?5 WHERE operation_id = ?1 AND batch_index = ?2 AND outcome = 'pending' AND EXISTS (SELECT 1 FROM ai_discovery_operations WHERE id = ?1 AND state = 'ranking')")
            .bind(id.to_string())
            .bind(i64::from(batch_index))
            .bind(outcome)
            .bind(assessment_json)
            .bind(resolved_model)
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Publish one terminal overlay only while ranking is still active.
    ///
    /// # Errors
    /// Returns a storage error if publication fails.
    pub async fn finish_ai_discovery(
        &self,
        id: Uuid,
        assessment_json: &str,
        source: AiRankingSource,
        reason_code: Option<&str>,
        assessed_count: u32,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query("UPDATE ai_discovery_operations SET state = 'completed', revision = 2, assessment_json = ?2, source = ?3, reason_code = ?4, assessed_count = ?5, ended_at = ?6 WHERE id = ?1 AND state = 'ranking' AND revision = 1")
            .bind(id.to_string())
            .bind(assessment_json)
            .bind(source.as_str())
            .bind(reason_code)
            .bind(i64::from(assessed_count))
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Mark a scan error without publishing a result.
    ///
    /// # Errors
    /// Returns a storage error if updating fails.
    pub async fn fail_ai_scan(&self, id: Uuid, reason_code: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("UPDATE ai_discovery_operations SET state = 'failed', reason_code = ?2, ended_at = ?3 WHERE id = ?1 AND state IN ('scanning', 'ranking')")
            .bind(id.to_string())
            .bind(reason_code)
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Cancel an active operation and prevent its late result from publishing.
    ///
    /// # Errors
    /// Returns a storage error if updating fails.
    pub async fn cancel_ai_discovery(&self, id: Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query("UPDATE ai_discovery_operations SET state = 'cancelled', ended_at = ?2 WHERE id = ?1 AND state IN ('scanning', 'ranking')")
            .bind(id.to_string())
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Preserve scans and mark unfinished operations interrupted after restart.
    ///
    /// # Errors
    /// Returns a storage error if updating fails.
    pub async fn interrupt_active_ai_discoveries(&self) -> Result<u64, StorageError> {
        let result = sqlx::query("UPDATE ai_discovery_operations SET state = 'interrupted', reason_code = 'process_restart', ended_at = ?1 WHERE state IN ('scanning', 'ranking')")
            .bind(Utc::now().to_rfc3339())
            .execute(self.pool())
            .await?;
        Ok(result.rows_affected())
    }

    /// Read an operation by ID.
    ///
    /// # Errors
    /// Returns a storage error for invalid retained data or a query failure.
    pub async fn get_ai_discovery(
        &self,
        id: Uuid,
    ) -> Result<Option<AiDiscoveryRecord>, StorageError> {
        let row = sqlx::query("SELECT id, project_root, language, state, revision, scan_json, assessment_json, source, reason_code, total_count, assessed_count, started_at, scanned_at, ended_at FROM ai_discovery_operations WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?;
        row.map(|row| decode_operation(&row)).transpose()
    }

    /// Read persisted batch inputs and outcomes in dispatch order.
    ///
    /// # Errors
    /// Returns a storage error for invalid retained data or a query failure.
    pub async fn list_ai_rank_batches(
        &self,
        id: Uuid,
    ) -> Result<Vec<AiRankBatchRecord>, StorageError> {
        let rows = sqlx::query("SELECT operation_id, batch_index, prompt, provider_model, resolved_model, outcome, assessment_json FROM ai_rank_batches WHERE operation_id = ?1 ORDER BY batch_index")
            .bind(id.to_string())
            .fetch_all(self.pool())
            .await?;
        rows.iter().map(decode_batch).collect()
    }
}

fn decode_operation(row: &sqlx::sqlite::SqliteRow) -> Result<AiDiscoveryRecord, StorageError> {
    let language: String = row.try_get("language")?;
    let parse_time = |name| -> Result<Option<DateTime<Utc>>, StorageError> {
        row.try_get::<Option<String>, _>(name)?
            .map(|value| {
                DateTime::parse_from_rfc3339(&value)
                    .map(|time| time.with_timezone(&Utc))
                    .map_err(|error| StorageError::Timestamp(error.to_string()))
            })
            .transpose()
    };
    let id: String = row.try_get("id")?;
    let revision: i64 = row.try_get("revision")?;
    let total_count: i64 = row.try_get("total_count")?;
    let assessed_count: i64 = row.try_get("assessed_count")?;
    Ok(AiDiscoveryRecord {
        id: id
            .parse()
            .map_err(|error: uuid::Error| StorageError::InvalidData(error.to_string()))?,
        project_root: PathBuf::from(row.try_get::<String, _>("project_root")?),
        language: language.parse().map_err(|error| {
            StorageError::InvalidData(format!("invalid language {language}: {error}"))
        })?,
        state: AiDiscoveryState::parse(&row.try_get::<String, _>("state")?)?,
        revision: u8::try_from(revision)
            .map_err(|error| StorageError::InvalidData(error.to_string()))?,
        scan_json: row.try_get("scan_json")?,
        assessment_json: row.try_get("assessment_json")?,
        source: AiRankingSource::parse(&row.try_get::<String, _>("source")?)?,
        reason_code: row.try_get("reason_code")?,
        total_count: u32::try_from(total_count)
            .map_err(|error| StorageError::InvalidData(error.to_string()))?,
        assessed_count: u32::try_from(assessed_count)
            .map_err(|error| StorageError::InvalidData(error.to_string()))?,
        started_at: parse_time("started_at")?
            .ok_or_else(|| StorageError::InvalidData("missing AI discovery start".to_owned()))?,
        scanned_at: parse_time("scanned_at")?,
        ended_at: parse_time("ended_at")?,
    })
}

fn decode_batch(row: &sqlx::sqlite::SqliteRow) -> Result<AiRankBatchRecord, StorageError> {
    let id: String = row.try_get("operation_id")?;
    let index: i64 = row.try_get("batch_index")?;
    Ok(AiRankBatchRecord {
        operation_id: id
            .parse()
            .map_err(|error: uuid::Error| StorageError::InvalidData(error.to_string()))?,
        batch_index: u32::try_from(index)
            .map_err(|error| StorageError::InvalidData(error.to_string()))?,
        prompt: row.try_get("prompt")?,
        provider_model: row.try_get("provider_model")?,
        resolved_model: row.try_get("resolved_model")?,
        outcome: row.try_get("outcome")?,
        assessment_json: row.try_get("assessment_json")?,
    })
}
