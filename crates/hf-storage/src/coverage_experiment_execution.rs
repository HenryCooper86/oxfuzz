//! Atomic campaign reservation for guided coverage experiments.
use crate::{CoverageExperimentStatus, RunKind, RunRecord, RunStatus, StorageError, Store};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

/// Immutable execution association, retained independently of record cancellation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageExperimentExecution {
    /// Service-allocated campaign identifier.
    pub run_id: Uuid,
    /// Exact review accepted by the launch operation.
    pub review_json: String,
}

impl Store {
    /// List a bounded page of unfinished guided runs for owner-aware recovery.
    pub async fn unfinished_guided_runs_after(
        &self,
        after: &str,
    ) -> Result<Vec<Uuid>, StorageError> {
        let ids: Vec<String> = sqlx::query_scalar("SELECT r.id FROM runs r JOIN coverage_experiment_executions e ON e.run_id = r.id WHERE r.status = 'running' AND r.ended_at IS NULL AND r.id > ? ORDER BY r.id LIMIT 128")
            .bind(after).fetch_all(self.pool()).await?;
        ids.iter()
            .map(|id| crate::coverage_experiment_store::parse_uuid(id))
            .collect()
    }

    /// Identify guided rows before applying journal recovery ownership checks.
    pub async fn is_guided_experiment_run(&self, id: Uuid) -> Result<bool, StorageError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM coverage_experiment_executions WHERE run_id = ?",
        )
        .bind(id.to_string())
        .fetch_one(self.pool())
        .await?
            != 0)
    }

    /// Preserve an abandoned guided attempt as failed; caller must own its OS lease.
    pub async fn recover_guided_experiment_run(&self, id: Uuid) -> Result<bool, StorageError> {
        Ok(sqlx::query("UPDATE runs SET status = 'failed', ended_at = ? WHERE id = ? AND status = 'running' AND ended_at IS NULL AND EXISTS (SELECT 1 FROM coverage_experiment_executions WHERE run_id = runs.id)")
            .bind(chrono::Utc::now().to_rfc3339()).bind(id.to_string()).execute(self.pool()).await?.rows_affected() == 1)
    }

    /// Allocate a campaign and its unique experiment association in one transaction.
    ///
    /// # Errors
    /// Rejects terminal/already launched proposals, different owners or settings, and SQL failures.
    pub async fn insert_coverage_experiment_run(
        &self,
        id: Uuid,
        run: &RunRecord,
        review_json: &str,
    ) -> Result<(), StorageError> {
        let review = validate_review(id, review_json)?;
        let proposal = self
            .coverage_experiment(id)
            .await?
            .ok_or_else(|| StorageError::CoverageExperimentConflict { id })?;
        let config = run.config.as_ref().ok_or_else(|| {
            StorageError::InvalidData("experiment run requires configuration".into())
        })?;
        let memory = config.max_mem_mb.to_string();
        if review["run_id"] != proposal.baseline_run_id.to_string()
            || review["project"] != proposal.project_root
            || review["engine"] != serde_json::to_value(config.engine)?
            || review["duration_secs"].as_u64() != Some(proposal.duration_secs)
            || review["max_mem_mb"].as_str() != Some(memory.as_str())
            || review["max_cpus"].as_u64() != Some(u64::from(config.max_cpus))
            || review["seed"].as_str() != config.seed.map(|seed| seed.to_string()).as_deref()
        {
            return Err(StorageError::InvalidData(
                "experiment review differs from run settings".into(),
            ));
        }
        if proposal.status != CoverageExperimentStatus::Prepared
            || run.project_root != proposal.project_root
            || run.kind != RunKind::Campaign
            || run.status != RunStatus::Running
            || run.started_at <= proposal.created_at
            || config.engine != proposal.baseline.engine
            || config.seed != proposal.baseline.seed
            || config.replay_of != Some(proposal.baseline_run_id)
            || config.duration != Some(std::time::Duration::from_secs(proposal.duration_secs))
        {
            return Err(StorageError::CoverageExperimentConflict { id });
        }
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let eligible: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM coverage_experiments e JOIN harnesses h ON h.id = ?2 AND h.target_id = e.target_id WHERE e.id = ?1 AND e.status = 'prepared' AND NOT EXISTS (SELECT 1 FROM coverage_experiment_executions WHERE experiment_id = e.id)")
            .bind(id.to_string()).bind(config.harness_id.to_string()).fetch_one(&mut *tx).await?;
        if eligible != 1 {
            return Err(StorageError::CoverageExperimentConflict { id });
        }
        Self::insert_run_on(&mut tx, run).await?;
        sqlx::query("INSERT INTO coverage_experiment_executions (experiment_id, run_id, review_json) VALUES (?1, ?2, ?3)")
            .bind(id.to_string()).bind(run.id.to_string()).bind(review_json).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Read the one associated execution, including cancelled investigations.
    ///
    /// # Errors
    /// Returns malformed data or SQL errors.
    pub async fn coverage_experiment_execution(
        &self,
        id: Uuid,
    ) -> Result<Option<CoverageExperimentExecution>, StorageError> {
        let row = sqlx::query("SELECT run_id, review_json FROM coverage_experiment_executions WHERE experiment_id = ?1")
            .bind(id.to_string()).fetch_optional(self.pool()).await?;
        row.map(|row| {
            let text: String = row.try_get("run_id")?;
            let run_id = crate::coverage_experiment_store::parse_uuid(&text)?;
            let review_json: String = row.try_get("review_json")?;
            validate_review(id, &review_json)?;
            Ok(CoverageExperimentExecution {
                run_id,
                review_json,
            })
        })
        .transpose()
    }
}

fn validate_review(id: Uuid, text: &str) -> Result<serde_json::Value, StorageError> {
    if text.len() > 16_384 {
        return Err(StorageError::InvalidData(
            "experiment review exceeds size limit".into(),
        ));
    }
    let review = crate::coverage_experiment_store::unique_json(text)?;
    let digest = review["current_input_sha256"].as_str();
    if review["experiment_id"] != id.to_string()
        || review["inputs"] != "current"
        || review.get("input_manifest_sha256") != Some(&serde_json::Value::Null)
        || !digest.is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(StorageError::InvalidData(
            "invalid guided experiment review".into(),
        ));
    }
    Ok(review)
}
