//! Paged execution history and transactional deletion of authorized snapshots.

use sqlx::{QueryBuilder, Row, Sqlite};

use crate::{StorageError, Store};

pub(crate) const DELETE_CLEARABLE_EXECUTIONS: &str =
    "DELETE FROM schedule_executions WHERE id NOT IN (
        SELECT execution_id FROM schedule_occurrences WHERE state IN ('reserved', 'running')
    )";

/// Persisted execution data with its database ordering and deletion identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleExecutionRecord {
    /// Database primary key.
    pub id: String,
    /// Stored timestamp used with the primary key for stable pagination.
    pub triggered_at: String,
    /// Exact serialized execution inspected by the owning service.
    pub data_json: String,
}

impl Store {
    /// Read a bounded history page, newest first, strictly after the supplied record.
    ///
    /// # Errors
    /// Returns an error when SQL or stored column decoding fails.
    pub async fn schedule_execution_page(
        &self,
        limit: i64,
        after: Option<&ScheduleExecutionRecord>,
    ) -> Result<Vec<ScheduleExecutionRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, triggered_at, data_json FROM schedule_executions
             WHERE ?1 IS NULL OR triggered_at < ?1 OR (triggered_at = ?1 AND id < ?2)
             ORDER BY triggered_at DESC, id DESC LIMIT ?3",
        )
        .bind(after.map(|record| record.triggered_at.as_str()))
        .bind(after.map(|record| record.id.as_str()))
        .bind(limit)
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(ScheduleExecutionRecord {
                    id: row.try_get("id")?,
                    triggered_at: row.try_get("triggered_at")?,
                    data_json: row.try_get("data_json")?,
                })
            })
            .collect()
    }

    /// Delete inspected execution snapshots in one transaction.
    ///
    /// Nonterminal one-time receipts protect their executions. An absent or
    /// changed snapshot aborts the transaction, preserving every selected row.
    ///
    /// # Errors
    /// Returns an error for missing/changed records or a SQL failure.
    pub async fn clear_schedule_execution_records(
        &self,
        records: &[ScheduleExecutionRecord],
    ) -> Result<u64, StorageError> {
        let mut transaction = self.pool().begin().await?;
        let mut cleared = 0;
        for record in records {
            let current: Option<String> =
                sqlx::query_scalar("SELECT data_json FROM schedule_executions WHERE id = ?1")
                    .bind(&record.id)
                    .fetch_optional(&mut *transaction)
                    .await?;
            let current = current
                .ok_or_else(|| StorageError::NotFound("selected schedule execution".to_owned()))?;
            if current != record.data_json {
                return Err(StorageError::InvalidData(
                    "selected schedule execution changed; retry clearing history".to_owned(),
                ));
            }
            let mut query = QueryBuilder::<Sqlite>::new(DELETE_CLEARABLE_EXECUTIONS);
            query.push(" AND id = ").push_bind(&record.id);
            cleared += query
                .build()
                .execute(&mut *transaction)
                .await?
                .rows_affected();
        }
        transaction.commit().await?;
        Ok(cleared)
    }
}
