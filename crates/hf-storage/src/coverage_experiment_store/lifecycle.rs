use super::{
    source::load_source,
    validation::{
        enum_from, enum_text, invalid, json_text, parse_time, parse_uuid, project, record,
        strict_json, timestamp, uuid, valid_time,
    },
    CoverageExperimentCursor, CoverageExperimentOwnerRecord, CoverageExperimentPageRecord,
    CoverageExperimentRecord, CoverageExperimentResultEvidenceV1, CoverageExperimentRunEvidenceV1,
    CoverageExperimentRunReference, CoverageExperimentStatus, DateTime, Utc, Uuid,
};
use crate::{StorageError, Store};
use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};

impl Store {
    /// Insert an immutable prepared proposal; accept only an identical same-ID retry.
    ///
    /// # Errors
    /// Returns validation, source-change, conflict, or SQL errors.
    pub async fn insert_coverage_experiment(
        &self,
        proposal: &CoverageExperimentRecord,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        if let Some(existing) = load(&mut tx, proposal.id).await? {
            return if existing == *proposal && proposal.status == CoverageExperimentStatus::Prepared
            {
                Ok(())
            } else {
                Err(conflict(proposal.id))
            };
        }
        record(proposal)?;
        if proposal.status != CoverageExperimentStatus::Prepared {
            return Err(invalid("insert requires prepared status"));
        }
        verify_source(&mut tx, &proposal.baseline).await?;
        sqlx::query("INSERT INTO coverage_experiments (id, schema_version, project_root, target_id, target_symbol, baseline_run_id, kind, goal_function, hypothesis, duration_secs, baseline_evidence_json, status, result_run_id, result_evidence_json, cancellation_reason, created_at, updated_at, ended_at) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'prepared', NULL, NULL, NULL, ?11, ?11, NULL)")
            .bind(proposal.id.to_string()).bind(&proposal.project_root).bind(proposal.target_id.to_string()).bind(&proposal.target_symbol).bind(proposal.baseline_run_id.to_string())
            .bind(enum_text(&proposal.kind)?).bind(&proposal.goal_function).bind(&proposal.hypothesis).bind(i64::try_from(proposal.duration_secs).map_err(|_| invalid("duration"))?)
            .bind(json_text(&proposal.baseline)?).bind(timestamp(proposal.created_at)).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Load retained evidence without rereading mutable campaign source rows.
    ///
    /// # Errors
    /// Returns malformed-data or SQL errors; absence alone returns `None`.
    pub async fn coverage_experiment(
        &self,
        id: Uuid,
    ) -> Result<Option<CoverageExperimentRecord>, StorageError> {
        load(&mut *self.pool().acquire().await?, id).await
    }
    /// Read only canonical owner columns for access checks, including feature-off use.
    ///
    /// # Errors
    /// Returns malformed-owner or SQL errors.
    pub async fn coverage_experiment_owner(
        &self,
        id: Uuid,
    ) -> Result<Option<CoverageExperimentOwnerRecord>, StorageError> {
        let row =
            sqlx::query("SELECT project_root, target_id FROM coverage_experiments WHERE id = ?1")
                .bind(id.to_string())
                .fetch_optional(self.pool())
                .await?;
        row.map(|row| {
            let project_root: String = row.try_get("project_root")?;
            project(&project_root)?;
            Ok(CoverageExperimentOwnerRecord {
                project_root,
                target_id: parse_uuid(row.try_get("target_id")?)?,
            })
        })
        .transpose()
    }
    /// Read a bounded deterministic page; a cursor must belong to the selected scope.
    ///
    /// # Errors
    /// Returns invalid-limit/cursor, malformed-data, or SQL errors.
    pub async fn list_coverage_experiments(
        &self,
        project_root: &str,
        target_id: Option<Uuid>,
        limit: usize,
        before: Option<CoverageExperimentCursor>,
    ) -> Result<CoverageExperimentPageRecord, StorageError> {
        project(project_root)?;
        if !(1..=100).contains(&limit) {
            return Err(invalid("list limit"));
        }
        if let Some(id) = target_id {
            uuid(id)?;
        }
        let mut tx = self.pool().begin().await?;
        if let Some(cursor) = before {
            uuid(cursor.id)?;
            valid_time(cursor.created_at)?;
            let row = load(&mut tx, cursor.id)
                .await?
                .ok_or_else(|| invalid("cursor missing"))?;
            if row.project_root != project_root
                || target_id.is_some_and(|id| row.target_id != id)
                || row.created_at != cursor.created_at
            {
                return Err(invalid("cursor scope or timestamp"));
            }
        }
        let rows = sqlx::query("SELECT * FROM coverage_experiments WHERE project_root = ?1 AND (?2 IS NULL OR target_id = ?2) AND (?3 IS NULL OR created_at < ?3 OR (created_at = ?3 AND id < ?4)) ORDER BY created_at DESC, id DESC LIMIT ?5")
            .bind(project_root).bind(target_id.map(|id| id.to_string())).bind(before.map(|c| timestamp(c.created_at))).bind(before.map(|c| c.id.to_string())).bind(i64::try_from(limit + 1).map_err(|_| invalid("limit"))?).fetch_all(&mut *tx).await?;
        let mut items = rows.iter().map(from_row).collect::<Result<Vec<_>, _>>()?;
        let has_more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = if has_more {
            items.last().map(|r| CoverageExperimentCursor {
                created_at: r.created_at,
                id: r.id,
            })
        } else {
            None
        };
        tx.commit().await?;
        Ok(CoverageExperimentPageRecord { items, next_cursor })
    }
    /// Attach one later campaign with prepared-to-terminal compare-and-set semantics.
    /// Exact terminal retries retain the original evidence and timestamps.
    ///
    /// # Errors
    /// Returns not-found, conflict, source-change, validation, or SQL errors.
    pub async fn complete_coverage_experiment(
        &self,
        id: Uuid,
        result: &CoverageExperimentResultEvidenceV1,
        ended_at: DateTime<Utc>,
    ) -> Result<CoverageExperimentRecord, StorageError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let mut saved = required_record(&mut tx, id).await?;
        if saved.status != CoverageExperimentStatus::Prepared {
            return completion_retry(saved, result);
        }
        saved.status = CoverageExperimentStatus::Completed;
        saved.result = Some(result.clone());
        saved.ended_at = Some(ended_at);
        saved.updated_at = ended_at;
        record(&saved)?;
        verify_source(&mut tx, &result.run).await?;
        let rows = sqlx::query("UPDATE coverage_experiments SET status = 'completed', result_run_id = ?2, result_evidence_json = ?3, ended_at = ?4, updated_at = ?4 WHERE id = ?1 AND status = 'prepared'")
            .bind(id.to_string()).bind(result.run.run_id.to_string()).bind(json_text(result)?).bind(timestamp(ended_at)).execute(&mut *tx).await?.rows_affected();
        if rows != 1 {
            return completion_retry(required_record(&mut tx, id).await?, result);
        }
        tx.commit().await?;
        Ok(saved)
    }
    /// Cancel a prepared investigation without changing any campaign.
    /// Exact reason retries preserve the original terminal time.
    ///
    /// # Errors
    /// Returns not-found, conflict, validation, or SQL errors.
    pub async fn cancel_coverage_experiment(
        &self,
        id: Uuid,
        reason: &str,
        ended_at: DateTime<Utc>,
    ) -> Result<CoverageExperimentRecord, StorageError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let mut saved = required_record(&mut tx, id).await?;
        if saved.status != CoverageExperimentStatus::Prepared {
            return cancellation_retry(saved, reason);
        }
        saved.status = CoverageExperimentStatus::Cancelled;
        saved.cancellation_reason = Some(reason.into());
        saved.ended_at = Some(ended_at);
        saved.updated_at = ended_at;
        record(&saved)?;
        let rows = sqlx::query("UPDATE coverage_experiments SET status = 'cancelled', cancellation_reason = ?2, ended_at = ?3, updated_at = ?3 WHERE id = ?1 AND status = 'prepared'")
            .bind(id.to_string()).bind(reason).bind(timestamp(ended_at)).execute(&mut *tx).await?.rows_affected();
        if rows != 1 {
            return cancellation_retry(required_record(&mut tx, id).await?, reason);
        }
        tx.commit().await?;
        Ok(saved)
    }
    /// Return the lexically first `(experiment_id, role)` retaining this run.
    ///
    /// # Errors
    /// Returns malformed-reference or SQL errors.
    pub async fn coverage_experiment_run_reference(
        &self,
        run_id: Uuid,
    ) -> Result<Option<CoverageExperimentRunReference>, StorageError> {
        run_reference(&mut *self.pool().acquire().await?, &run_id.to_string()).await
    }
}
fn conflict(id: Uuid) -> StorageError {
    StorageError::CoverageExperimentConflict { id }
}
fn completion_retry(
    saved: CoverageExperimentRecord,
    result: &CoverageExperimentResultEvidenceV1,
) -> Result<CoverageExperimentRecord, StorageError> {
    if saved.status == CoverageExperimentStatus::Completed && saved.result.as_ref() == Some(result)
    {
        Ok(saved)
    } else {
        Err(conflict(saved.id))
    }
}
fn cancellation_retry(
    saved: CoverageExperimentRecord,
    reason: &str,
) -> Result<CoverageExperimentRecord, StorageError> {
    if saved.status == CoverageExperimentStatus::Cancelled
        && saved.cancellation_reason.as_deref() == Some(reason)
    {
        Ok(saved)
    } else {
        Err(conflict(saved.id))
    }
}
async fn verify_source(
    connection: &mut SqliteConnection,
    snapshot: &CoverageExperimentRunEvidenceV1,
) -> Result<(), StorageError> {
    if load_source(connection, snapshot.run_id).await? != *snapshot {
        return Err(StorageError::CoverageExperimentSourceChanged {
            run_id: snapshot.run_id,
        });
    }
    Ok(())
}
pub(crate) async fn run_reference(
    connection: &mut SqliteConnection,
    run_id: &str,
) -> Result<Option<CoverageExperimentRunReference>, StorageError> {
    let row = sqlx::query("SELECT id, 'baseline' AS role FROM coverage_experiments WHERE baseline_run_id = ?1 UNION ALL SELECT id, 'result' AS role FROM coverage_experiments WHERE result_run_id = ?1 ORDER BY id, role LIMIT 1")
        .bind(run_id).fetch_optional(connection).await?;
    row.map(|row| {
        Ok(CoverageExperimentRunReference {
            experiment_id: parse_uuid(row.try_get("id")?)?,
            role: enum_from(row.try_get("role")?)?,
        })
    })
    .transpose()
}
async fn required_record(
    connection: &mut SqliteConnection,
    id: Uuid,
) -> Result<CoverageExperimentRecord, StorageError> {
    load(connection, id)
        .await?
        .ok_or_else(|| StorageError::NotFound(format!("coverage experiment {id}")))
}
async fn load(
    connection: &mut SqliteConnection,
    id: Uuid,
) -> Result<Option<CoverageExperimentRecord>, StorageError> {
    let row = sqlx::query("SELECT * FROM coverage_experiments WHERE id = ?1")
        .bind(id.to_string())
        .fetch_optional(connection)
        .await?;
    row.as_ref().map(from_row).transpose()
}
fn from_row(row: &SqliteRow) -> Result<CoverageExperimentRecord, StorageError> {
    let result: Option<CoverageExperimentResultEvidenceV1> = row
        .try_get::<Option<&str>, _>("result_evidence_json")?
        .map(strict_json)
        .transpose()?;
    let result_id = row
        .try_get::<Option<&str>, _>("result_run_id")?
        .map(parse_uuid)
        .transpose()?;
    if result.as_ref().map(|r| r.run.run_id) != result_id {
        return Err(invalid("result relational ID"));
    }
    let record_value = CoverageExperimentRecord {
        id: parse_uuid(row.try_get("id")?)?,
        schema_version: u32::try_from(row.try_get::<i64, _>("schema_version")?)
            .map_err(|_| invalid("schema version"))?,
        project_root: row.try_get("project_root")?,
        target_id: parse_uuid(row.try_get("target_id")?)?,
        target_symbol: row.try_get("target_symbol")?,
        baseline_run_id: parse_uuid(row.try_get("baseline_run_id")?)?,
        kind: enum_from(row.try_get("kind")?)?,
        goal_function: row.try_get("goal_function")?,
        hypothesis: row.try_get("hypothesis")?,
        duration_secs: u64::try_from(row.try_get::<i64, _>("duration_secs")?)
            .map_err(|_| invalid("duration"))?,
        baseline: strict_json(row.try_get("baseline_evidence_json")?)?,
        status: enum_from(row.try_get("status")?)?,
        result,
        cancellation_reason: row.try_get("cancellation_reason")?,
        created_at: parse_time(row.try_get("created_at")?)?,
        updated_at: parse_time(row.try_get("updated_at")?)?,
        ended_at: row
            .try_get::<Option<&str>, _>("ended_at")?
            .map(parse_time)
            .transpose()?,
    };
    record(&record_value)?;
    Ok(record_value)
}
