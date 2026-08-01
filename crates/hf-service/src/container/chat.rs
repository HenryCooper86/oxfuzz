//! Chat sessions, transcripts, checkpoints, and branches.

use hf_core::error::ClassifiedError;
use hf_guardrails::Action;
use uuid::Uuid;

use super::{chat_storage_error, ServiceContainer};

impl ServiceContainer {
    async fn create_chat_checkpoint_unlocked(
        &self,
        session: &hf_core::types::SessionId,
        message_count_before: u32,
    ) -> Result<(), ClassifiedError> {
        let manager = self.chat_checkpoint_manager()?;
        let turn = manager
            .current_turn(session)
            .await
            .map_err(|error| chat_storage_error("read current chat turn", error))?
            .saturating_add(1);
        manager
            .create_checkpoint(
                session,
                turn,
                message_count_before,
                Uuid::new_v4().to_string(),
            )
            .await
            .map_err(|error| chat_storage_error("create chat checkpoint", error))?;
        Ok(())
    }

    /// Create a turn checkpoint recording the transcript length before this
    /// turn (so a later rollback restores the pre-turn state).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the session is unknown, persistence is not
    /// configured, or the checkpoint cannot be saved.
    pub async fn chat_create_checkpoint(
        &self,
        session: &hf_core::types::SessionId,
        message_count_before: u32,
    ) -> Result<(), ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.create_chat_checkpoint_unlocked(session, message_count_before)
            .await
    }

    /// Roll back the most recent chat turn, truncating the transcript.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when the session/checkpoint is unavailable or
    /// any transcript, metadata, or checkpoint mutation fails.
    pub async fn chat_rollback_last(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<usize, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.chat_checkpoint_manager()?
            .rollback_last(session)
            .await
            .map(|result| result.messages_removed)
            .map_err(|error| chat_storage_error("rollback last chat turn", error))
    }

    /// List the (still-valid) per-turn checkpoints for a session, each with a
    /// preview of the user message that started the turn.
    pub async fn chat_checkpoints(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<Vec<crate::checkpoints::CheckpointView>, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        let checkpoints = self.chat_checkpoint_manager()?;
        let sessions = self.chat_session_manager()?;
        let list = checkpoints
            .list_checkpoints(session)
            .await
            .map_err(|error| chat_storage_error("list chat checkpoints", error))?;
        let transcript = sessions
            .read_transcript(session)
            .await
            .map_err(|error| chat_storage_error("read chat checkpoint previews", error))?;
        let mut valid: Vec<_> = list.into_iter().filter(|c| !c.invalidated).collect();
        // Present turns oldest-first for the picker, regardless of the store's
        // list ordering (the trait returns them newest-first).
        valid.sort_by_key(|c| c.turn_number);
        Ok(valid
            .into_iter()
            .map(|c| {
                let preview = transcript
                    .get(usize::try_from(c.message_count_before).unwrap_or(usize::MAX))
                    .map(|m| m.content.chars().take(80).collect())
                    .unwrap_or_default();
                crate::checkpoints::CheckpointView {
                    checkpoint_id: c.checkpoint_id,
                    turn_number: c.turn_number,
                    message_count_before: c.message_count_before,
                    preview,
                }
            })
            .collect())
    }

    /// Roll back to a specific checkpoint (removing that turn and everything
    /// after). Returns the number of messages removed.
    pub async fn chat_rollback_to(
        &self,
        session: &hf_core::types::SessionId,
        checkpoint_id: &str,
    ) -> Result<usize, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.chat_checkpoint_manager()?
            .rollback_to(session, checkpoint_id)
            .await
            .map(|result| result.messages_removed)
            .map_err(|error| chat_storage_error("rollback chat to checkpoint", error))
    }

    /// Fork a conversation: create a branch session off `parent`, copying the
    /// parent's transcript up to `fork_message_count` so the branch can diverge
    /// independently. Returns the new session id.
    pub async fn chat_branch(
        &self,
        parent: &hf_core::types::SessionId,
        fork_message_count: u32,
        title: Option<String>,
    ) -> Result<String, ClassifiedError> {
        if fork_message_count == 0 {
            return Err(ClassifiedError::Validation(
                "cannot branch an empty conversation".to_owned(),
            ));
        }
        let _guard = self.chat_session_guard(parent).await?;
        let message_index =
            usize::try_from(fork_message_count.saturating_sub(1)).unwrap_or(usize::MAX);
        self.chat_session_manager()?
            .fork_session(parent, message_index, title)
            .await
            .map(|branch| branch.id.0)
            .map_err(|error| chat_storage_error("branch chat session", error))
    }

    /// The canonical display transcript of a session, for loading a branch into
    /// the chat view.
    pub async fn chat_history(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<Vec<hf_core::types::Message>, ClassifiedError> {
        let _guard = self.chat_session_guard(session).await?;
        self.chat_session_manager()?
            .read_display_transcript(session)
            .await
            .map_err(|error| chat_storage_error("read chat history", error))
    }

    /// Create a new top-level chat session, returning its id, or `None` when no
    /// database is configured. Shared by every presentation layer so session
    /// creation behaves identically (AGENTS.md 2.9).
    pub async fn create_chat_session(
        &self,
        title: Option<String>,
    ) -> Result<Option<String>, ClassifiedError> {
        let Some(manager) = self.session_manager.as_ref() else {
            return Ok(None);
        };
        let id = manager
            .create_session(hf_core::session::CreateSessionOptions {
                parent_id: None,
                session_type: hf_core::session::SessionType::Main,
                agent_id: None,
                title: title.or_else(|| Some("Chat".to_owned())),
            })
            .await
            .map(|node| node.id.0)
            .map_err(|error| chat_storage_error("create chat session", error))?;
        Ok(Some(id))
    }

    /// Delete a chat session and its transcript (used by the "clear history"
    /// action). No-op when no session store is configured. Returns whether a
    /// deletion was performed.
    pub async fn delete_chat_session(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<bool, ClassifiedError> {
        let Some(manager) = self.session_manager.as_ref() else {
            return Ok(false);
        };
        let _guard = self.chat_session_guard(session).await?;
        manager
            .delete_session(session)
            .await
            .map_err(|error| chat_storage_error("delete chat session", error))?;
        // Drop the per-session turn lock now that the session is gone, so a
        // long-lived server does not accumulate one dead mutex per deleted
        // session for its entire lifetime. `_guard` still holds a clone of the
        // Arc, so the mutex is released only when this call returns; a later
        // caller for a (recreated) id simply gets a fresh lock.
        {
            let mut locks = self
                .session_turn_locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            locks.remove(session);
        }
        Ok(true)
    }

    /// All sessions in the same conversation tree as `session` (the main session
    /// plus every branch), for the branch switcher.
    pub async fn chat_branches(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<Vec<crate::checkpoints::BranchView>, ClassifiedError> {
        use hf_core::session::{SessionFilter, SessionType};
        let _guard = self.chat_session_guard(session).await?;
        let sessions = self.chat_session_manager()?;
        let node = sessions
            .get_session(session)
            .await
            .map_err(|error| chat_storage_error("read chat session tree", error))?;
        let filter = SessionFilter {
            root_id: Some(node.root_id.clone()),
            ..SessionFilter::default()
        };
        let mut nodes = sessions
            .list_sessions(&filter)
            .await
            .map_err(|error| chat_storage_error("list chat session tree", error))?;
        nodes.sort_by_key(|n| (n.depth, n.created_at));
        Ok(nodes
            .into_iter()
            .map(|n| {
                let is_main = n.session_type == SessionType::Main;
                let active = n.id == *session;
                crate::checkpoints::BranchView {
                    title: n.title.unwrap_or_else(|| {
                        if is_main {
                            "Main".to_owned()
                        } else {
                            format!("Branch (depth {})", n.depth)
                        }
                    }),
                    id: n.id.0,
                    depth: n.depth,
                    is_main,
                    active,
                }
            })
            .collect())
    }

    /// Send a chat message to the LLM provider pool.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if no provider is configured or the LLM
    /// call fails.
    pub async fn chat_send(&self, message: &str) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;
        self.authorize_recorded(Action::Chat, "chat_send", None)
            .await?;
        let pool = self
            .provider_pool()
            .ok_or_else(|| ClassifiedError::Provider("no LLM provider configured".to_owned()))?;
        let messages = vec![
            Message::system(
                "You are oxfuzz, an AI fuzzing assistant. You help users discover \
                 fuzzing targets, generate harnesses, run fuzzing engines, triage crashes, \
                 and manage corpora. Be concise and actionable.",
            ),
            Message::user(message),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["general", "reasoning", "code"]),
            )
            .await?;
        self.diagnostics
            .record("chat", &resp.model, &resp.usage)
            .await;
        Ok(resp.text().to_owned())
    }
}
