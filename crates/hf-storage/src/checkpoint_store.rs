//! SQLite-backed [`ChatCheckpointStore`] for turn-level chat rollback.
//!
//! Persists checkpoints in the `chat_checkpoints` table so the GUI's rollback
//! survives restarts (the in-memory store lost them on exit, silently turning
//! rollback into a no-op after a restart).

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use hf_core::session::{ChatCheckpoint, ChatCheckpointStore, SessionError};
use hf_core::types::SessionId;

/// SQLite-backed chat checkpoint store over the `chat_checkpoints` table.
#[derive(Debug, Clone)]
pub struct SqliteChatCheckpointStore {
    pool: SqlitePool,
}

impl SqliteChatCheckpointStore {
    /// Create a new checkpoint store backed by the given pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

/// Map a query result row into a [`ChatCheckpoint`], surfacing a malformed row
/// as an error rather than panicking.
fn row_to_checkpoint(row: &sqlx::sqlite::SqliteRow) -> Result<ChatCheckpoint, SessionError> {
    let turn_number: i64 = row.try_get("turn_number").map_err(|e| storage_err(&e))?;
    let message_count_before: i64 = row
        .try_get("message_count_before")
        .map_err(|e| storage_err(&e))?;
    let invalidated: i64 = row.try_get("invalidated").map_err(|e| storage_err(&e))?;
    let created_at: String = row.try_get("created_at").map_err(|e| storage_err(&e))?;
    Ok(ChatCheckpoint {
        checkpoint_id: row.try_get("checkpoint_id").map_err(|e| storage_err(&e))?,
        session_id: SessionId(row.try_get("session_id").map_err(|e| storage_err(&e))?),
        turn_number: u32::try_from(turn_number).unwrap_or(0),
        message_count_before: u32::try_from(message_count_before).unwrap_or(0),
        journal_scope_id: row
            .try_get("journal_scope_id")
            .map_err(|e| storage_err(&e))?,
        invalidated: invalidated != 0,
        created_at: created_at.parse().unwrap_or_else(|_| chrono::Utc::now()),
    })
}

fn storage_err(e: &sqlx::Error) -> SessionError {
    SessionError::StorageError {
        message: e.to_string(),
    }
}

#[async_trait]
impl ChatCheckpointStore for SqliteChatCheckpointStore {
    async fn save(&self, checkpoint: &ChatCheckpoint) -> Result<(), SessionError> {
        // Upsert on the primary key so re-saving a checkpoint (e.g. after
        // toggling `invalidated`) replaces it rather than erroring.
        sqlx::query(
            r"INSERT INTO chat_checkpoints
                (checkpoint_id, session_id, turn_number, message_count_before,
                 journal_scope_id, invalidated, created_at)
              VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
              ON CONFLICT(checkpoint_id) DO UPDATE SET
                session_id = excluded.session_id,
                turn_number = excluded.turn_number,
                message_count_before = excluded.message_count_before,
                journal_scope_id = excluded.journal_scope_id,
                invalidated = excluded.invalidated,
                created_at = excluded.created_at",
        )
        .bind(&checkpoint.checkpoint_id)
        .bind(checkpoint.session_id.as_str())
        .bind(i64::from(checkpoint.turn_number))
        .bind(i64::from(checkpoint.message_count_before))
        .bind(&checkpoint.journal_scope_id)
        .bind(i64::from(checkpoint.invalidated))
        .bind(
            checkpoint
                .created_at
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(&e))?;
        Ok(())
    }

    async fn load(&self, checkpoint_id: &str) -> Result<ChatCheckpoint, SessionError> {
        let row = sqlx::query("SELECT * FROM chat_checkpoints WHERE checkpoint_id = ?1")
            .bind(checkpoint_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| storage_err(&e))?
            .ok_or_else(|| SessionError::NotFound {
                id: checkpoint_id.to_owned(),
            })?;
        row_to_checkpoint(&row)
    }

    async fn list_by_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ChatCheckpoint>, SessionError> {
        let rows = sqlx::query(
            "SELECT * FROM chat_checkpoints WHERE session_id = ?1 ORDER BY turn_number DESC",
        )
        .bind(session_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| storage_err(&e))?;
        rows.iter().map(row_to_checkpoint).collect()
    }

    async fn latest(&self, session_id: &SessionId) -> Result<Option<ChatCheckpoint>, SessionError> {
        let row = sqlx::query(
            "SELECT * FROM chat_checkpoints
             WHERE session_id = ?1 AND invalidated = 0
             ORDER BY turn_number DESC LIMIT 1",
        )
        .bind(session_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| storage_err(&e))?;
        row.as_ref().map(row_to_checkpoint).transpose()
    }

    async fn invalidate_after(
        &self,
        session_id: &SessionId,
        turn_number: u32,
    ) -> Result<u32, SessionError> {
        let result = sqlx::query(
            "UPDATE chat_checkpoints SET invalidated = 1
             WHERE session_id = ?1 AND turn_number > ?2 AND invalidated = 0",
        )
        .bind(session_id.as_str())
        .bind(i64::from(turn_number))
        .execute(&self.pool)
        .await
        .map_err(|e| storage_err(&e))?;
        Ok(u32::try_from(result.rows_affected()).unwrap_or(u32::MAX))
    }
}
