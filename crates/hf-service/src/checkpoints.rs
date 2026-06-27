//! In-memory chat checkpoint store for turn-level rollback.
//!
//! The GUI chat uses one session per view mount with its message list held in
//! the frontend, so checkpoints only need to live for the app session (an undo
//! buffer), not survive restarts. This backs [`ChatCheckpointManager`] with a
//! simple `Mutex<Vec<..>>`.

use std::sync::Mutex;

use async_trait::async_trait;
use hf_core::session::{ChatCheckpoint, ChatCheckpointStore, SessionError};
use hf_core::types::SessionId;
use serde::Serialize;

/// A checkpoint surfaced to the GUI turn picker.
#[derive(Debug, Clone, Serialize)]
pub struct CheckpointView {
    pub checkpoint_id: String,
    /// 1-indexed turn this checkpoint precedes.
    pub turn_number: u32,
    /// Transcript length before this turn -- rolling back truncates to here.
    pub message_count_before: u32,
    /// Preview of the user message that started this turn.
    pub preview: String,
}

/// A non-persistent [`ChatCheckpointStore`].
#[derive(Default)]
pub struct InMemoryChatCheckpointStore {
    checkpoints: Mutex<Vec<ChatCheckpoint>>,
}

impl InMemoryChatCheckpointStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<ChatCheckpoint>> {
        self.checkpoints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[async_trait]
impl ChatCheckpointStore for InMemoryChatCheckpointStore {
    async fn save(&self, checkpoint: &ChatCheckpoint) -> Result<(), SessionError> {
        let mut list = self.lock();
        list.retain(|c| c.checkpoint_id != checkpoint.checkpoint_id);
        list.push(checkpoint.clone());
        Ok(())
    }

    async fn load(&self, checkpoint_id: &str) -> Result<ChatCheckpoint, SessionError> {
        self.lock()
            .iter()
            .find(|c| c.checkpoint_id == checkpoint_id)
            .cloned()
            .ok_or_else(|| SessionError::NotFound {
                id: checkpoint_id.to_owned(),
            })
    }

    async fn list_by_session(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ChatCheckpoint>, SessionError> {
        let mut found: Vec<ChatCheckpoint> = self
            .lock()
            .iter()
            .filter(|c| &c.session_id == session_id)
            .cloned()
            .collect();
        found.sort_by_key(|c| c.turn_number);
        Ok(found)
    }

    async fn latest(&self, session_id: &SessionId) -> Result<Option<ChatCheckpoint>, SessionError> {
        Ok(self
            .lock()
            .iter()
            .filter(|c| &c.session_id == session_id && !c.invalidated)
            .max_by_key(|c| c.turn_number)
            .cloned())
    }

    async fn invalidate_after(
        &self,
        session_id: &SessionId,
        turn_number: u32,
    ) -> Result<u32, SessionError> {
        let mut list = self.lock();
        let mut invalidated = 0;
        for cp in list.iter_mut().filter(|c| {
            &c.session_id == session_id && c.turn_number > turn_number && !c.invalidated
        }) {
            cp.invalidated = true;
            invalidated += 1;
        }
        Ok(invalidated)
    }
}
