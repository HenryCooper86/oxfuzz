//! Chat checkpoint manager — coordinates checkpoint creation and rollback.
//!
//! Links session transcripts to File Journal scopes so that a single "undo"
//! operation can revert both conversation history and filesystem changes.

use std::sync::Arc;

use tracing::{info, instrument};

use hf_core::session::{
    ChatCheckpoint, ChatCheckpointStore, DisplayTranscriptStore, SessionError, SessionStore,
    TranscriptStore,
};
use hf_core::types::SessionId;

/// Result of a rollback operation.
#[derive(Debug, Clone)]
pub struct RollbackResult {
    /// Number of messages removed from the transcript.
    pub messages_removed: usize,
    /// File Journal scopes that were rolled back.
    pub scopes_rolled_back: Vec<String>,
    /// Turn number rolled back to.
    pub rolled_back_to_turn: u32,
    /// Number of checkpoints invalidated.
    pub checkpoints_invalidated: u32,
}

/// Manages chat-level checkpoints for turn-level rollback.
///
/// Coordinates between `TranscriptStore` (conversation), `ChatCheckpointStore`
/// (checkpoint records), and File Journal scopes (filesystem rollback).
pub struct ChatCheckpointManager {
    transcript_store: Arc<dyn TranscriptStore>,
    display_transcript_store: Arc<dyn DisplayTranscriptStore>,
    checkpoint_store: Arc<dyn ChatCheckpointStore>,
    session_store: Arc<dyn SessionStore>,
}

struct RollbackSnapshot {
    context: Vec<hf_core::types::Message>,
    display: Vec<hf_core::types::Message>,
    token_count: u32,
    message_count: u32,
}

impl ChatCheckpointManager {
    /// Create a new checkpoint manager.
    pub fn new(
        transcript_store: Arc<dyn TranscriptStore>,
        display_transcript_store: Arc<dyn DisplayTranscriptStore>,
        checkpoint_store: Arc<dyn ChatCheckpointStore>,
        session_store: Arc<dyn SessionStore>,
    ) -> Self {
        Self {
            transcript_store,
            display_transcript_store,
            checkpoint_store,
            session_store,
        }
    }

    /// Create a checkpoint after a completed agent turn.
    ///
    /// - `session_id`: The session this turn belongs to.
    /// - `turn_number`: 1-indexed turn counter.
    /// - `message_count_before`: Number of messages in transcript before the turn started.
    /// - `journal_scope_id`: File Journal scope ID for this turn's file operations.
    #[instrument(skip(self), fields(
        session_id = %session_id,
        turn = turn_number,
        msg_before = message_count_before,
    ))]
    pub async fn create_checkpoint(
        &self,
        session_id: &SessionId,
        turn_number: u32,
        message_count_before: u32,
        journal_scope_id: String,
    ) -> Result<ChatCheckpoint, SessionError> {
        self.session_store.get(session_id).await?;
        let checkpoint = ChatCheckpoint {
            checkpoint_id: uuid::Uuid::new_v4().to_string(),
            session_id: session_id.clone(),
            turn_number,
            message_count_before,
            journal_scope_id,
            invalidated: false,
            created_at: chrono::Utc::now(),
        };

        self.checkpoint_store.save(&checkpoint).await?;

        info!(
            checkpoint_id = %checkpoint.checkpoint_id,
            "chat checkpoint created"
        );

        Ok(checkpoint)
    }

    /// Rollback to the latest non-invalidated checkpoint (undo last turn).
    ///
    /// Truncates the transcript and invalidates the checkpoint.
    /// File Journal rollback is delegated back to the caller via the
    /// `scopes_rolled_back` field in the result (since y-journal is a
    /// separate crate and we use trait boundaries).
    #[instrument(skip(self), fields(session_id = %session_id))]
    pub async fn rollback_last(
        &self,
        session_id: &SessionId,
    ) -> Result<RollbackResult, SessionError> {
        let checkpoint = self
            .checkpoint_store
            .latest(session_id)
            .await?
            .ok_or_else(|| SessionError::Other {
                message: "no checkpoints available for rollback".to_string(),
            })?;

        self.rollback_to(session_id, &checkpoint.checkpoint_id)
            .await
    }

    /// Rollback to a specific checkpoint.
    ///
    /// Truncates the transcript to `message_count_before`, invalidates
    /// all checkpoints from the target turn onward, and returns the
    /// scope IDs that need file-level rollback.
    #[instrument(skip(self), fields(session_id = %session_id, checkpoint_id = %checkpoint_id))]
    pub async fn rollback_to(
        &self,
        session_id: &SessionId,
        checkpoint_id: &str,
    ) -> Result<RollbackResult, SessionError> {
        // Load the target checkpoint.
        let target = self.checkpoint_store.load(checkpoint_id).await?;

        if target.session_id != *session_id {
            return Err(SessionError::Other {
                message: format!(
                    "checkpoint {} belongs to session {}, not {}",
                    target.checkpoint_id, target.session_id, session_id
                ),
            });
        }

        if target.invalidated {
            return Err(SessionError::Other {
                message: format!("checkpoint {} is already invalidated", target.checkpoint_id),
            });
        }

        // Collect all scopes from target turn onward for file rollback.
        let all_checkpoints = self.checkpoint_store.list_by_session(session_id).await?;
        let scopes_to_rollback: Vec<String> = all_checkpoints
            .iter()
            .filter(|cp| cp.turn_number >= target.turn_number && !cp.invalidated)
            .map(|cp| cp.journal_scope_id.clone())
            .collect();

        let snapshot = self.rollback_snapshot(session_id).await?;
        let keep_count = usize::try_from(target.message_count_before).unwrap_or(usize::MAX);
        if keep_count > snapshot.context.len() || keep_count > snapshot.display.len() {
            return Err(SessionError::Other {
                message: format!(
                    "checkpoint {} expects {} messages, but transcripts contain {} context and {} display messages",
                    target.checkpoint_id,
                    keep_count,
                    snapshot.context.len(),
                    snapshot.display.len()
                ),
            });
        }
        let mutation = async {
            self.display_transcript_store
                .truncate(session_id, keep_count)
                .await?;
            let messages_removed = self
                .transcript_store
                .truncate(session_id, keep_count)
                .await?;
            self.session_store
                .update_metadata(
                    session_id,
                    None,
                    snapshot.token_count,
                    target.message_count_before,
                )
                .await?;
            let invalidated = self
                .checkpoint_store
                .invalidate_after(session_id, target.turn_number.saturating_sub(1))
                .await?;
            Ok::<_, SessionError>((messages_removed, invalidated))
        }
        .await;
        let (messages_removed, invalidated) = match mutation {
            Ok(result) => result,
            Err(error) => {
                let compensation = self.restore_rollback_snapshot(session_id, &snapshot).await;
                return Err(compensated_session_error(
                    "rollback chat transcript",
                    &error,
                    compensation,
                ));
            }
        };

        info!(
            messages_removed,
            invalidated,
            scopes = scopes_to_rollback.len(),
            "chat rollback completed"
        );

        Ok(RollbackResult {
            messages_removed,
            scopes_rolled_back: scopes_to_rollback,
            rolled_back_to_turn: target.turn_number.saturating_sub(1),
            checkpoints_invalidated: invalidated,
        })
    }

    async fn rollback_snapshot(
        &self,
        session_id: &SessionId,
    ) -> Result<RollbackSnapshot, SessionError> {
        let session = self.session_store.get(session_id).await?;
        let context = self.transcript_store.read_all(session_id).await?;
        let display = self.display_transcript_store.read_all(session_id).await?;
        Ok(RollbackSnapshot {
            context,
            display,
            token_count: session.token_count,
            message_count: session.message_count,
        })
    }

    async fn restore_rollback_snapshot(
        &self,
        session_id: &SessionId,
        snapshot: &RollbackSnapshot,
    ) -> Result<(), SessionError> {
        let mut errors = Vec::new();
        match self.display_transcript_store.truncate(session_id, 0).await {
            Ok(_) => {
                for message in &snapshot.display {
                    if let Err(error) = self
                        .display_transcript_store
                        .append(session_id, message)
                        .await
                    {
                        errors.push(format!("restore display transcript: {error}"));
                        break;
                    }
                }
            }
            Err(error) => errors.push(format!("reset display transcript: {error}")),
        }
        match self.transcript_store.truncate(session_id, 0).await {
            Ok(_) => {
                for message in &snapshot.context {
                    if let Err(error) = self.transcript_store.append(session_id, message).await {
                        errors.push(format!("restore context transcript: {error}"));
                        break;
                    }
                }
            }
            Err(error) => errors.push(format!("reset context transcript: {error}")),
        }
        if let Err(error) = self
            .session_store
            .update_metadata(
                session_id,
                None,
                snapshot.token_count,
                snapshot.message_count,
            )
            .await
        {
            errors.push(format!("restore session metadata: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SessionError::Other {
                message: errors.join("; "),
            })
        }
    }

    /// Get a reference to the underlying checkpoint store.
    pub fn checkpoint_store(&self) -> &dyn ChatCheckpointStore {
        &*self.checkpoint_store
    }

    /// List available (non-invalidated) checkpoints for a session.
    pub async fn list_checkpoints(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<ChatCheckpoint>, SessionError> {
        let all = self.checkpoint_store.list_by_session(session_id).await?;
        Ok(all.into_iter().filter(|cp| !cp.invalidated).collect())
    }

    /// Get the highest turn number ever assigned for a session.
    ///
    /// Invalidated checkpoints remain in durable storage and participate in a
    /// unique `(session_id, turn_number)` constraint, so turn numbers are
    /// monotonic and never reused after rollback.
    pub async fn current_turn(&self, session_id: &SessionId) -> Result<u32, SessionError> {
        let checkpoints = self.checkpoint_store.list_by_session(session_id).await?;
        Ok(checkpoints
            .into_iter()
            .map(|checkpoint| checkpoint.turn_number)
            .max()
            .unwrap_or(0))
    }
}

fn compensated_session_error(
    operation: &str,
    original: &SessionError,
    compensation: Result<(), SessionError>,
) -> SessionError {
    let message = match compensation {
        Ok(()) => format!("{operation} failed and was rolled back: {original}"),
        Err(rollback) => {
            format!("{operation} failed: {original}; compensation also failed: {rollback}")
        }
    };
    SessionError::Other { message }
}

impl std::fmt::Debug for ChatCheckpointManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatCheckpointManager")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_test_utils::fixtures::{make_assistant_message, make_user_message};
    use hf_test_utils::mock_storage::{
        MockDisplayTranscriptStore, MockSessionStore, MockTranscriptStore,
    };

    /// In-memory `ChatCheckpointStore` for tests.
    #[derive(Debug, Default)]
    struct MockChatCheckpointStore {
        data: std::sync::RwLock<Vec<ChatCheckpoint>>,
        fail_invalidation: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl ChatCheckpointStore for MockChatCheckpointStore {
        async fn save(&self, checkpoint: &ChatCheckpoint) -> Result<(), SessionError> {
            let mut data = self.data.write().unwrap();
            // Upsert by checkpoint_id.
            data.retain(|cp| cp.checkpoint_id != checkpoint.checkpoint_id);
            data.push(checkpoint.clone());
            Ok(())
        }

        async fn load(&self, checkpoint_id: &str) -> Result<ChatCheckpoint, SessionError> {
            let data = self.data.read().unwrap();
            data.iter()
                .find(|cp| cp.checkpoint_id == checkpoint_id)
                .cloned()
                .ok_or(SessionError::NotFound {
                    id: checkpoint_id.to_string(),
                })
        }

        async fn list_by_session(
            &self,
            session_id: &SessionId,
        ) -> Result<Vec<ChatCheckpoint>, SessionError> {
            let data = self.data.read().unwrap();
            let mut result: Vec<_> = data
                .iter()
                .filter(|cp| cp.session_id.as_str() == session_id.as_str())
                .cloned()
                .collect();
            result.sort_by_key(|b| std::cmp::Reverse(b.turn_number));
            Ok(result)
        }

        async fn latest(
            &self,
            session_id: &SessionId,
        ) -> Result<Option<ChatCheckpoint>, SessionError> {
            let data = self.data.read().unwrap();
            let latest = data
                .iter()
                .filter(|cp| cp.session_id.as_str() == session_id.as_str() && !cp.invalidated)
                .max_by_key(|cp| cp.turn_number)
                .cloned();
            Ok(latest)
        }

        async fn invalidate_after(
            &self,
            session_id: &SessionId,
            turn_number: u32,
        ) -> Result<u32, SessionError> {
            if self
                .fail_invalidation
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(SessionError::StorageError {
                    message: "injected checkpoint invalidation failure".to_owned(),
                });
            }
            let mut data = self.data.write().unwrap();
            let mut count = 0;
            for cp in data.iter_mut() {
                if cp.session_id.as_str() == session_id.as_str()
                    && cp.turn_number > turn_number
                    && !cp.invalidated
                {
                    cp.invalidated = true;
                    count += 1;
                }
            }
            Ok(count)
        }
    }

    async fn setup() -> (
        ChatCheckpointManager,
        SessionId,
        Arc<MockChatCheckpointStore>,
    ) {
        let session_store = Arc::new(MockSessionStore::new());
        let transcript_store = Arc::new(MockTranscriptStore::new());
        let display_transcript_store = Arc::new(MockDisplayTranscriptStore::new());
        let checkpoint_store = Arc::new(MockChatCheckpointStore::default());

        // Create a session.
        let session = session_store
            .create(hf_core::session::CreateSessionOptions {
                parent_id: None,
                session_type: hf_core::session::SessionType::Main,
                agent_id: None,
                title: Some("test".into()),
            })
            .await
            .unwrap();

        let mgr = ChatCheckpointManager::new(
            transcript_store,
            display_transcript_store,
            checkpoint_store.clone(),
            session_store,
        );
        (mgr, session.id, checkpoint_store)
    }

    // T-CP-10: end_turn creates checkpoint with correct message_count_before.
    #[tokio::test]
    async fn test_create_checkpoint() {
        let (mgr, sid, _) = setup().await;

        let cp = mgr
            .create_checkpoint(&sid, 1, 0, "scope-turn-1".into())
            .await
            .unwrap();

        assert_eq!(cp.turn_number, 1);
        assert_eq!(cp.message_count_before, 0);
        assert_eq!(cp.journal_scope_id, "scope-turn-1");
        assert!(!cp.invalidated);
    }

    // T-CP-11: rollback_last truncates transcript.
    #[tokio::test]
    async fn test_rollback_last() {
        let (mgr, sid, _) = setup().await;

        // Simulate turn 1: user + assistant messages.
        for message in [make_user_message("hello"), make_assistant_message("hi")] {
            mgr.transcript_store.append(&sid, &message).await.unwrap();
            mgr.display_transcript_store
                .append(&sid, &message)
                .await
                .unwrap();
        }

        mgr.create_checkpoint(&sid, 1, 0, "scope-1".into())
            .await
            .unwrap();

        // Simulate turn 2: user + assistant messages.
        for message in [make_user_message("more"), make_assistant_message("sure")] {
            mgr.transcript_store.append(&sid, &message).await.unwrap();
            mgr.display_transcript_store
                .append(&sid, &message)
                .await
                .unwrap();
        }

        mgr.create_checkpoint(&sid, 2, 2, "scope-2".into())
            .await
            .unwrap();

        // Rollback last turn.
        let result = mgr.rollback_last(&sid).await.unwrap();

        assert_eq!(result.messages_removed, 2);
        assert_eq!(result.rolled_back_to_turn, 1);
        assert!(result.scopes_rolled_back.contains(&"scope-2".to_string()));

        // Transcript should have only turn 1 messages.
        let msgs = mgr.transcript_store.read_all(&sid).await.unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].content, "hello");
    }

    // T-CP-12: rollback to specific checkpoint with multi-turn gap.
    #[tokio::test]
    async fn test_rollback_multi_turn() {
        let (mgr, sid, _) = setup().await;

        // 3 turns, 2 messages each.
        for turn in 1..=3 {
            let before = ((turn - 1) * 2) as u32;
            for message in [
                make_user_message(&format!("user-{turn}")),
                make_assistant_message(&format!("asst-{turn}")),
            ] {
                mgr.transcript_store.append(&sid, &message).await.unwrap();
                mgr.display_transcript_store
                    .append(&sid, &message)
                    .await
                    .unwrap();
            }
            mgr.create_checkpoint(&sid, turn as u32, before, format!("scope-{turn}"))
                .await
                .unwrap();
        }

        // Rollback to turn 1 (undoing turns 2 and 3).
        let checkpoints = mgr.list_checkpoints(&sid).await.unwrap();
        let turn1_cp = checkpoints.iter().find(|cp| cp.turn_number == 1).unwrap();

        let result = mgr
            .rollback_to(&sid, &turn1_cp.checkpoint_id)
            .await
            .unwrap();

        // Rolling back to turn 1 truncates to message_count_before=0, removing all 6 messages.
        assert_eq!(result.messages_removed, 6);
        assert_eq!(result.rolled_back_to_turn, 0); // before turn 1
        assert_eq!(result.scopes_rolled_back.len(), 3); // scopes 1, 2, 3

        let msgs = mgr.transcript_store.read_all(&sid).await.unwrap();
        assert_eq!(msgs.len(), 0); // all removed since turn 1 starts at msg 0
    }

    // T-CP-13: Rollback with no checkpoints returns error.
    #[tokio::test]
    async fn test_rollback_no_checkpoints() {
        let (mgr, sid, _) = setup().await;
        let result = mgr.rollback_last(&sid).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_current_turn_does_not_reuse_invalidated_turn_number() {
        let (mgr, sid, checkpoints) = setup().await;
        mgr.create_checkpoint(&sid, 1, 0, "scope-1".into())
            .await
            .unwrap();
        checkpoints.invalidate_after(&sid, 0).await.unwrap();

        assert_eq!(mgr.current_turn(&sid).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_rollback_to_rejects_checkpoint_from_other_session() {
        let (mgr, sid, _) = setup().await;
        let other_session = mgr
            .session_store
            .create(hf_core::session::CreateSessionOptions {
                parent_id: None,
                session_type: hf_core::session::SessionType::Main,
                agent_id: None,
                title: Some("other".into()),
            })
            .await
            .unwrap();

        let checkpoint = mgr
            .create_checkpoint(&sid, 1, 0, "scope-1".into())
            .await
            .unwrap();

        let result = mgr
            .rollback_to(&other_session.id, &checkpoint.checkpoint_id)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rollback_rejects_checkpoint_beyond_transcript_length() {
        let (mgr, sid, _) = setup().await;
        let message = make_user_message("only message");
        mgr.transcript_store.append(&sid, &message).await.unwrap();
        mgr.display_transcript_store
            .append(&sid, &message)
            .await
            .unwrap();
        mgr.create_checkpoint(&sid, 1, 2, "scope-1".into())
            .await
            .unwrap();

        let result = mgr.rollback_last(&sid).await;

        assert!(result.is_err());
        assert_eq!(mgr.transcript_store.read_all(&sid).await.unwrap().len(), 1);
        assert_eq!(
            mgr.display_transcript_store
                .read_all(&sid)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_rollback_restores_transcripts_when_checkpoint_invalidation_fails() {
        let (mgr, sid, checkpoints) = setup().await;
        for message in [make_user_message("hello"), make_assistant_message("hi")] {
            mgr.transcript_store.append(&sid, &message).await.unwrap();
            mgr.display_transcript_store
                .append(&sid, &message)
                .await
                .unwrap();
        }
        mgr.session_store
            .update_metadata(&sid, None, 7, 2)
            .await
            .unwrap();
        mgr.create_checkpoint(&sid, 1, 0, "scope-1".into())
            .await
            .unwrap();
        checkpoints
            .fail_invalidation
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let result = mgr.rollback_last(&sid).await;

        assert!(result.is_err());
        assert_eq!(mgr.transcript_store.read_all(&sid).await.unwrap().len(), 2);
        assert_eq!(
            mgr.display_transcript_store
                .read_all(&sid)
                .await
                .unwrap()
                .len(),
            2
        );
        let session = mgr.session_store.get(&sid).await.unwrap();
        assert_eq!(session.message_count, 2);
        assert_eq!(session.token_count, 7);
    }
}
