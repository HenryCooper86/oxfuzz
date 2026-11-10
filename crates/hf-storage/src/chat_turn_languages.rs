//! Language instructions retained before a chat turn contacts its provider.

use crate::{StorageError, Store};
use hf_core::types::SessionId;
use uuid::Uuid;

impl Store {
    /// Retain the exact language instruction for one chat attempt. Failed and
    /// cancelled attempts keep this evidence; deleting a session removes it.
    ///
    /// # Errors
    /// Returns a storage error for a missing session, an empty or oversized
    /// instruction, or a database write failure.
    pub async fn record_chat_language(
        &self,
        turn_id: Uuid,
        session_id: Option<&SessionId>,
        instruction: &str,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO chat_turn_languages (id, turn_id, session_id, instruction) VALUES (?1, ?2, ?3, ?4)")
            .bind(Uuid::new_v4().to_string())
            .bind(turn_id.to_string())
            .bind(session_id.map(ToString::to_string))
            .bind(instruction)
            .execute(self.pool())
            .await?;
        Ok(())
    }
}
