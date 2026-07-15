//! `SessionManager` — high-level facade for session lifecycle management.

use std::sync::Arc;
use std::sync::RwLock;

use tracing::instrument;

use hf_core::agent::{AgentDelegator, ContextStrategyHint};
use hf_core::session::{
    CreateSessionOptions, DisplayTranscriptStore, SessionFilter, SessionNode, SessionState,
    SessionStore, TranscriptStore,
};
use hf_core::types::{Message, SessionId};

use crate::config::SessionConfig;
use crate::error::SessionManagerError;
use crate::state_machine::StateMachine;

/// High-level session management facade.
///
/// Combines state machine validation, session store, and transcript store
/// into a unified API. All state transitions go through the state machine
/// to ensure validity.
pub struct SessionManager {
    session_store: Arc<dyn SessionStore>,
    transcript_store: Arc<dyn TranscriptStore>,
    display_transcript_store: Arc<dyn DisplayTranscriptStore>,
    config: RwLock<SessionConfig>,
}

/// Pre-mutation transcript and metadata counts used to compensate a failed
/// multi-store append.
#[derive(Debug, Clone)]
pub struct TranscriptSnapshot {
    context_count: usize,
    display_count: usize,
    token_count: u32,
    message_count: u32,
}

impl TranscriptSnapshot {
    /// Number of context messages present when the snapshot was taken.
    #[must_use]
    pub fn context_count(&self) -> usize {
        self.context_count
    }
}

#[derive(Debug, Clone)]
struct FullTranscriptSnapshot {
    context: Vec<Message>,
    display: Vec<Message>,
    session: hf_core::session::SessionNode,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(
        session_store: Arc<dyn SessionStore>,
        transcript_store: Arc<dyn TranscriptStore>,
        display_transcript_store: Arc<dyn DisplayTranscriptStore>,
        config: SessionConfig,
    ) -> Self {
        Self {
            session_store,
            transcript_store,
            display_transcript_store,
            config: RwLock::new(config),
        }
    }

    /// Hot-reload the session configuration.
    pub fn reload_config(&self, new_config: SessionConfig) {
        let mut guard = self
            .config
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *guard = new_config;
        tracing::info!("Session config hot-reloaded");
    }

    /// Create a new root session.
    #[instrument(skip(self))]
    pub async fn create_session(
        &self,
        options: CreateSessionOptions,
    ) -> Result<SessionNode, SessionManagerError> {
        // Validate depth if creating a child.
        if let Some(ref parent_id) = options.parent_id {
            let parent = self.session_store.get(parent_id).await?;
            let max_depth = self
                .config
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .max_depth;
            if parent.depth >= max_depth {
                return Err(SessionManagerError::Config {
                    message: format!("maximum tree depth {max_depth} exceeded"),
                });
            }
        }

        let node = self.session_store.create(options).await?;
        Ok(node)
    }

    /// Get a session by ID.
    #[instrument(skip(self), fields(session_id = %id))]
    pub async fn get_session(&self, id: &SessionId) -> Result<SessionNode, SessionManagerError> {
        Ok(self.session_store.get(id).await?)
    }

    /// List sessions matching filters.
    pub async fn list_sessions(
        &self,
        filter: &SessionFilter,
    ) -> Result<Vec<SessionNode>, SessionManagerError> {
        Ok(self.session_store.list(filter).await?)
    }

    /// Transition a session's state, validating the transition.
    #[instrument(skip(self), fields(session_id = %id, new_state = ?new_state))]
    pub async fn transition_state(
        &self,
        id: &SessionId,
        new_state: SessionState,
    ) -> Result<(), SessionManagerError> {
        let current = self.session_store.get(id).await?;
        StateMachine::validate_transition(&current.state, &new_state)?;
        self.session_store.set_state(id, new_state).await?;
        Ok(())
    }

    /// Append a message to both transcript stores as one recoverable mutation.
    #[instrument(skip(self, message), fields(session_id = %session_id))]
    pub async fn append_message(
        &self,
        session_id: &SessionId,
        message: &Message,
    ) -> Result<(), SessionManagerError> {
        self.append_messages(session_id, std::slice::from_ref(message))
            .await
    }

    /// Append multiple messages to the display and context transcripts and
    /// commit their metadata count together.
    ///
    /// If either transcript or the metadata write fails, both transcripts are
    /// truncated back to their independent pre-mutation counts before the
    /// error is returned.
    #[instrument(skip(self, messages), fields(session_id = %session_id, count = messages.len()))]
    pub async fn append_messages(
        &self,
        session_id: &SessionId,
        messages: &[Message],
    ) -> Result<(), SessionManagerError> {
        // Verify session exists and is active.
        let session = self.session_store.get(session_id).await?;
        if session.state != SessionState::Active {
            return Err(SessionManagerError::InvalidTransition {
                from: format!("{:?}", session.state),
                to: "append message (requires Active)".into(),
            });
        }
        if messages.is_empty() {
            return Ok(());
        }

        let snapshot = self.transcript_snapshot(session_id, &session).await?;
        let mutation = async {
            for message in messages {
                self.display_transcript_store
                    .append(session_id, message)
                    .await
                    .map_err(|error| SessionManagerError::Transcript {
                        message: format!("display transcript: {error}"),
                    })?;
            }
            for message in messages {
                self.transcript_store
                    .append(session_id, message)
                    .await
                    .map_err(|error| SessionManagerError::Transcript {
                        message: format!("context transcript: {error}"),
                    })?;
            }

            let count = self
                .transcript_store
                .message_count(session_id)
                .await
                .map_err(|error| SessionManagerError::Transcript {
                    message: format!("count context transcript: {error}"),
                })?;
            self.session_store
                .update_metadata(
                    session_id,
                    None,
                    session.token_count,
                    u32::try_from(count).unwrap_or(u32::MAX),
                )
                .await?;
            Ok(())
        }
        .await;

        if let Err(error) = mutation {
            let compensation = self
                .restore_transcript_snapshot(session_id, &snapshot)
                .await;
            return Err(compensated_error("append messages", &error, compensation));
        }

        Ok(())
    }

    /// Capture transcript and metadata counts before a larger chat mutation.
    pub async fn snapshot_transcripts(
        &self,
        session_id: &SessionId,
    ) -> Result<TranscriptSnapshot, SessionManagerError> {
        let session = self.session_store.get(session_id).await?;
        self.transcript_snapshot(session_id, &session).await
    }

    /// Restore transcript and metadata counts captured by
    /// [`Self::snapshot_transcripts`].
    pub async fn restore_transcript_snapshot(
        &self,
        session_id: &SessionId,
        snapshot: &TranscriptSnapshot,
    ) -> Result<(), SessionManagerError> {
        self.display_transcript_store
            .truncate(session_id, snapshot.display_count)
            .await
            .map_err(|error| SessionManagerError::Transcript {
                message: format!("restore display transcript: {error}"),
            })?;
        self.transcript_store
            .truncate(session_id, snapshot.context_count)
            .await
            .map_err(|error| SessionManagerError::Transcript {
                message: format!("restore context transcript: {error}"),
            })?;
        self.session_store
            .update_metadata(
                session_id,
                None,
                snapshot.token_count,
                snapshot.message_count,
            )
            .await?;
        Ok(())
    }

    async fn transcript_snapshot(
        &self,
        session_id: &SessionId,
        session: &hf_core::session::SessionNode,
    ) -> Result<TranscriptSnapshot, SessionManagerError> {
        let display_count = self
            .display_transcript_store
            .message_count(session_id)
            .await
            .map_err(|error| SessionManagerError::Transcript {
                message: format!("count display transcript: {error}"),
            })?;
        let context_count = self
            .transcript_store
            .message_count(session_id)
            .await
            .map_err(|error| SessionManagerError::Transcript {
                message: format!("count context transcript: {error}"),
            })?;
        Ok(TranscriptSnapshot {
            context_count,
            display_count,
            token_count: session.token_count,
            message_count: session.message_count,
        })
    }

    /// Read all messages from the context transcript (for LLM context assembly).
    pub async fn read_transcript(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<Message>, SessionManagerError> {
        self.session_store.get(session_id).await?;
        self.transcript_store
            .read_all(session_id)
            .await
            .map_err(|e| SessionManagerError::Transcript {
                message: e.to_string(),
            })
    }

    /// Read all messages from the display transcript (for GUI display).
    ///
    /// The display transcript is never compacted, so this always returns
    /// the full conversation history as seen by the user.
    pub async fn read_display_transcript(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<Message>, SessionManagerError> {
        self.session_store.get(session_id).await?;
        self.display_transcript_store
            .read_all(session_id)
            .await
            .map_err(|e| SessionManagerError::Transcript {
                message: format!("display transcript: {e}"),
            })
    }

    /// Read the last N messages from a session's transcript.
    pub async fn read_last_messages(
        &self,
        session_id: &SessionId,
        count: usize,
    ) -> Result<Vec<Message>, SessionManagerError> {
        self.session_store.get(session_id).await?;
        self.transcript_store
            .read_last(session_id, count)
            .await
            .map_err(|e| SessionManagerError::Transcript {
                message: e.to_string(),
            })
    }

    /// Create a branch session from an existing one.
    ///
    /// The branch is a new child of the specified session with type Branch.
    #[instrument(skip(self), fields(parent_id = %parent_id))]
    pub async fn branch(
        &self,
        parent_id: &SessionId,
        title: Option<String>,
    ) -> Result<SessionNode, SessionManagerError> {
        let parent = self.session_store.get(parent_id).await?;
        let max_depth = self
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .max_depth;
        if parent.depth >= max_depth {
            return Err(SessionManagerError::Config {
                message: format!("maximum tree depth {max_depth} exceeded"),
            });
        }

        let branch = self
            .session_store
            .create(CreateSessionOptions {
                parent_id: Some(parent_id.clone()),
                session_type: hf_core::session::SessionType::Branch,
                agent_id: parent.agent_id.clone(),
                title,
            })
            .await?;

        Ok(branch)
    }

    /// Get children of a session.
    pub async fn children(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<SessionNode>, SessionManagerError> {
        Ok(self.session_store.children(session_id).await?)
    }

    /// Get ancestors of a session (path from root to parent).
    pub async fn ancestors(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<SessionNode>, SessionManagerError> {
        Ok(self.session_store.ancestors(session_id).await?)
    }

    /// Collect this session and all of its descendants within the same session tree.
    pub async fn descendants_including_self(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<SessionNode>, SessionManagerError> {
        let current = self.session_store.get(session_id).await?;
        let all_in_tree = self
            .session_store
            .list(&SessionFilter {
                root_id: Some(current.root_id.clone()),
                ..Default::default()
            })
            .await?;

        Ok(all_in_tree
            .into_iter()
            .filter(|node| node.id == current.id || node.path.contains(&current.id))
            .collect())
    }

    /// Update only the session title.
    #[instrument(skip(self), fields(session_id = %id))]
    pub async fn update_title(
        &self,
        id: &SessionId,
        title: String,
    ) -> Result<(), SessionManagerError> {
        self.session_store.set_title(id, title).await?;
        Ok(())
    }

    /// Set or clear the manual (user-edited) title for a session.
    ///
    /// When set, this overrides the auto-generated title for display and
    /// prevents future automatic title generation. Pass `None` to revert
    /// to the auto-generated title.
    #[instrument(skip(self), fields(session_id = %id))]
    pub async fn set_manual_title(
        &self,
        id: &SessionId,
        title: Option<String>,
    ) -> Result<(), SessionManagerError> {
        self.session_store.set_manual_title(id, title).await?;
        Ok(())
    }

    /// Delete a session and clear transcript content.
    ///
    /// Preferred path is hard-delete of metadata row.
    /// If hard-delete is blocked by foreign-key dependencies, fallback to
    /// soft-delete (mark session as tombstone) to preserve referential integrity.
    #[instrument(skip(self), fields(session_id = %id))]
    pub async fn delete_session(&self, id: &SessionId) -> Result<(), SessionManagerError> {
        let snapshot = self.full_transcript_snapshot(id).await?;

        if let Err(error) = self.display_transcript_store.truncate(id, 0).await {
            return Err(SessionManagerError::Transcript {
                message: format!("clear display transcript before delete: {error}"),
            });
        }
        if let Err(error) = self.transcript_store.truncate(id, 0).await {
            let compensation = self.restore_full_transcript(id, &snapshot).await;
            return Err(compensated_error(
                "clear context transcript before delete",
                &SessionManagerError::Transcript {
                    message: error.to_string(),
                },
                compensation,
            ));
        }

        match self.session_store.delete(id).await {
            Ok(()) => Ok(()),
            Err(error) if is_foreign_key_delete_error(&error) => {
                tracing::warn!(
                    session_id = %id,
                    error = %error,
                    "hard-delete blocked by foreign key, falling back to tombstone"
                );
                let tombstone = async {
                    if snapshot.session.state != SessionState::Tombstone {
                        StateMachine::validate_transition(
                            &snapshot.session.state,
                            &SessionState::Tombstone,
                        )?;
                    }
                    self.session_store.update_metadata(id, None, 0, 0).await?;
                    if snapshot.session.state != SessionState::Tombstone {
                        self.session_store
                            .set_state(id, SessionState::Tombstone)
                            .await?;
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = tombstone {
                    let compensation = self.restore_full_transcript(id, &snapshot).await;
                    return Err(compensated_error(
                        "tombstone session after delete conflict",
                        &error,
                        compensation,
                    ));
                }
                Ok(())
            }
            Err(error) => {
                let compensation = self.restore_full_transcript(id, &snapshot).await;
                let error = SessionManagerError::from(error);
                Err(compensated_error(
                    "delete session metadata",
                    &error,
                    compensation,
                ))
            }
        }
    }

    /// Get the persisted context reset index for a session.
    pub async fn get_context_reset_index(
        &self,
        id: &SessionId,
    ) -> Result<Option<u32>, SessionManagerError> {
        Ok(self.session_store.get_context_reset_index(id).await?)
    }

    /// Set or clear the context reset index for a session.
    pub async fn set_context_reset_index(
        &self,
        id: &SessionId,
        index: Option<u32>,
    ) -> Result<(), SessionManagerError> {
        self.session_store
            .set_context_reset_index(id, index)
            .await?;
        Ok(())
    }

    /// Get the custom system prompt for a session.
    pub async fn get_custom_system_prompt(
        &self,
        id: &SessionId,
    ) -> Result<Option<String>, SessionManagerError> {
        Ok(self.session_store.get_custom_system_prompt(id).await?)
    }

    /// Set or clear the custom system prompt for a session.
    pub async fn set_custom_system_prompt(
        &self,
        id: &SessionId,
        prompt: Option<String>,
    ) -> Result<(), SessionManagerError> {
        self.session_store
            .set_custom_system_prompt(id, prompt)
            .await?;
        Ok(())
    }

    /// Generate a session title by summarizing the conversation via agent delegation.
    ///
    /// Delegates to the `title-generator` built-in agent defined in
    /// `config/agents/title-generator.toml`. The agent's system prompt,
    /// model preferences, and temperature are managed externally.
    #[instrument(skip(self, delegator, messages), fields(session_id = %session_id))]
    pub async fn generate_title(
        &self,
        delegator: &dyn AgentDelegator,
        session_id: &SessionId,
        messages: &[Message],
    ) -> Result<String, SessionManagerError> {
        // Only consider text content sent by the user. Tool results
        // (`Role::Tool`) and assistant turns can dominate the payload with
        // tool-call JSON that biases the generated title, so they are
        // excluded. Take at most the last 6 user messages to keep the
        // input compact.
        let user_msgs: Vec<&Message> = messages
            .iter()
            .filter(|m| m.role == hf_core::types::Role::User)
            .collect();
        let context: Vec<_> = user_msgs
            .iter()
            .rev()
            .take(6)
            .rev()
            .map(|m| serde_json::json!({ "role": format!("{:?}", m.role), "content": m.content }))
            .collect();

        let input = serde_json::json!({ "messages": context });

        let session_uuid = uuid::Uuid::parse_str(&session_id.0).ok();

        let output = delegator
            .delegate(
                "title-generator",
                input,
                ContextStrategyHint::None,
                session_uuid,
            )
            .await
            .map_err(|e| SessionManagerError::Other {
                message: format!("title generation delegation failed: {e}"),
            })?;

        let title = output
            .text
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

        if title.is_empty() {
            return Err(SessionManagerError::Other {
                message: "title-generator agent returned empty title".into(),
            });
        }

        // Persist the generated title.
        self.update_title(session_id, title.clone()).await?;

        Ok(title)
    }

    /// Get a reference to the underlying context transcript store.
    pub fn transcript_store(&self) -> &dyn TranscriptStore {
        &*self.transcript_store
    }

    /// Get a reference to the underlying display transcript store.
    pub fn display_transcript_store(&self) -> &dyn DisplayTranscriptStore {
        &*self.display_transcript_store
    }

    /// Fork a session at a specific message index, creating a new Branch session.
    ///
    /// Copies messages `[0..=message_index]` from both the context and display
    /// transcripts of the source session into a new `Branch` session. The
    /// original session is never mutated.
    ///
    /// If `message_index` equals or exceeds the total message count, all
    /// messages are copied (full fork).
    #[instrument(skip(self), fields(source_id = %source_id, message_index = message_index))]
    pub async fn fork_session(
        &self,
        source_id: &SessionId,
        message_index: usize,
        title: Option<String>,
    ) -> Result<SessionNode, SessionManagerError> {
        // 1. Validate source session exists.
        let source = self.session_store.get(source_id).await?;

        // 2. Read display transcript from source.
        let display_messages = self
            .display_transcript_store
            .read_all(source_id)
            .await
            .map_err(|e| SessionManagerError::Transcript {
                message: format!("read display transcript: {e}"),
            })?;

        // 3. Read context transcript from source.
        let context_messages = self
            .transcript_store
            .read_all(source_id)
            .await
            .map_err(|e| SessionManagerError::Transcript {
                message: e.to_string(),
            })?;

        if display_messages.is_empty() && context_messages.is_empty() {
            return Err(SessionManagerError::Other {
                message: "source session has no messages to fork".into(),
            });
        }

        // 4. Determine fork title.
        let fork_title = title.or_else(|| source.title.as_ref().map(|t| format!("{t} (Branch)")));

        // 5. Create the new Branch session.
        let max_depth = self
            .config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .max_depth;
        if source.depth >= max_depth {
            return Err(SessionManagerError::Config {
                message: format!("maximum tree depth {max_depth} exceeded"),
            });
        }

        let fork_node = self
            .session_store
            .create(CreateSessionOptions {
                parent_id: Some(source_id.clone()),
                session_type: hf_core::session::SessionType::Branch,
                agent_id: source.agent_id.clone(),
                title: fork_title,
            })
            .await?;

        let display_end = message_index.saturating_add(1).min(display_messages.len());
        let context_end = message_index.saturating_add(1).min(context_messages.len());
        let copy_result = async {
            // 6. Copy display messages [0..=message_index].
            for msg in &display_messages[..display_end] {
                self.display_transcript_store
                    .append(&fork_node.id, msg)
                    .await
                    .map_err(|error| SessionManagerError::Transcript {
                        message: format!("write forked display transcript: {error}"),
                    })?;
            }

            // 7. Copy context messages [0..=message_index].
            for msg in &context_messages[..context_end] {
                self.transcript_store
                    .append(&fork_node.id, msg)
                    .await
                    .map_err(|error| SessionManagerError::Transcript {
                        message: format!("write forked context transcript: {error}"),
                    })?;
            }

            // 8. Carry over context_reset_index if it falls within forked range.
            if let Some(reset_idx) = self
                .session_store
                .get_context_reset_index(source_id)
                .await?
            {
                if (reset_idx as usize) < context_end {
                    self.session_store
                        .set_context_reset_index(&fork_node.id, Some(reset_idx))
                        .await?;
                }
            }

            // 9. Update metadata on the new session.
            let msg_count = u32::try_from(context_end).unwrap_or(u32::MAX);
            self.session_store
                .update_metadata(&fork_node.id, None, 0, msg_count)
                .await?;
            Ok(())
        }
        .await;

        if let Err(error) = copy_result {
            let compensation = self.cleanup_incomplete_session(&fork_node.id).await;
            return Err(compensated_error(
                "copy branch transcript",
                &error,
                compensation,
            ));
        }

        tracing::info!(
            fork_id = %fork_node.id,
            source_id = %source_id,
            messages_copied = context_end,
            "session forked successfully"
        );

        // Re-read the node to get updated metadata.
        let updated = self.session_store.get(&fork_node.id).await?;
        Ok(updated)
    }

    async fn full_transcript_snapshot(
        &self,
        session_id: &SessionId,
    ) -> Result<FullTranscriptSnapshot, SessionManagerError> {
        let session = self.session_store.get(session_id).await?;
        let display = self
            .display_transcript_store
            .read_all(session_id)
            .await
            .map_err(|error| SessionManagerError::Transcript {
                message: format!("read display transcript: {error}"),
            })?;
        let context = self
            .transcript_store
            .read_all(session_id)
            .await
            .map_err(|error| SessionManagerError::Transcript {
                message: format!("read context transcript: {error}"),
            })?;
        Ok(FullTranscriptSnapshot {
            context,
            display,
            session,
        })
    }

    async fn restore_full_transcript(
        &self,
        session_id: &SessionId,
        snapshot: &FullTranscriptSnapshot,
    ) -> Result<(), SessionManagerError> {
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
            Err(error) => errors.push(format!("reset display transcript for restore: {error}")),
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
            Err(error) => errors.push(format!("reset context transcript for restore: {error}")),
        }
        if let Err(error) = self
            .session_store
            .update_metadata(
                session_id,
                None,
                snapshot.session.token_count,
                snapshot.session.message_count,
            )
            .await
        {
            errors.push(format!("restore session metadata: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SessionManagerError::Other {
                message: errors.join("; "),
            })
        }
    }

    async fn cleanup_incomplete_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(), SessionManagerError> {
        let mut errors = Vec::new();
        if let Err(error) = self.display_transcript_store.truncate(session_id, 0).await {
            errors.push(format!("clear display transcript: {error}"));
        }
        if let Err(error) = self.transcript_store.truncate(session_id, 0).await {
            errors.push(format!("clear context transcript: {error}"));
        }
        if let Err(error) = self.session_store.delete(session_id).await {
            errors.push(format!("delete session metadata: {error}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SessionManagerError::Other {
                message: errors.join("; "),
            })
        }
    }

    /// Get a snapshot of the session configuration.
    pub fn config(&self) -> SessionConfig {
        self.config
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl std::fmt::Debug for SessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionManager")
            .field(
                "config",
                &*self
                    .config
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
            .finish_non_exhaustive()
    }
}

fn is_foreign_key_delete_error(error: &hf_core::session::SessionError) -> bool {
    matches!(
        error,
        hf_core::session::SessionError::StorageError { message }
            if message.contains("FOREIGN KEY constraint failed")
    )
}

fn compensated_error(
    operation: &str,
    original: &SessionManagerError,
    compensation: Result<(), SessionManagerError>,
) -> SessionManagerError {
    let message = match compensation {
        Ok(()) => format!("{operation} failed and was rolled back: {original}"),
        Err(rollback) => {
            format!("{operation} failed: {original}; compensation also failed: {rollback}")
        }
    };
    SessionManagerError::Other { message }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use hf_core::session::{SessionError, SessionType};
    use hf_core::types::Role;
    use hf_test_utils::mock_storage::{
        MockDisplayTranscriptStore, MockSessionStore, MockTranscriptStore,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Debug, Default)]
    struct ToggleTranscriptStore {
        inner: MockTranscriptStore,
        fail_append: AtomicBool,
        fail_truncate: AtomicBool,
    }

    #[async_trait]
    impl TranscriptStore for ToggleTranscriptStore {
        async fn append(
            &self,
            session_id: &SessionId,
            message: &Message,
        ) -> Result<(), SessionError> {
            if self.fail_append.load(Ordering::SeqCst) {
                return Err(SessionError::TranscriptError {
                    message: "injected append failure".to_owned(),
                });
            }
            self.inner.append(session_id, message).await
        }

        async fn read_all(&self, session_id: &SessionId) -> Result<Vec<Message>, SessionError> {
            self.inner.read_all(session_id).await
        }

        async fn read_last(
            &self,
            session_id: &SessionId,
            count: usize,
        ) -> Result<Vec<Message>, SessionError> {
            self.inner.read_last(session_id, count).await
        }

        async fn message_count(&self, session_id: &SessionId) -> Result<usize, SessionError> {
            self.inner.message_count(session_id).await
        }

        async fn truncate(
            &self,
            session_id: &SessionId,
            keep_count: usize,
        ) -> Result<usize, SessionError> {
            if self.fail_truncate.load(Ordering::SeqCst) {
                return Err(SessionError::TranscriptError {
                    message: "injected truncate failure".to_owned(),
                });
            }
            self.inner.truncate(session_id, keep_count).await
        }
    }

    struct TestManager {
        manager: SessionManager,
        _storage_dir: tempfile::TempDir,
    }

    impl std::ops::Deref for TestManager {
        type Target = SessionManager;

        fn deref(&self) -> &Self::Target {
            &self.manager
        }
    }

    async fn setup() -> TestManager {
        let storage_dir = tempfile::tempdir().unwrap();
        let store = hf_storage::Store::connect(storage_dir.path().join("sessions.db"))
            .await
            .unwrap();
        let session_store = Arc::new(hf_storage::SqliteSessionStore::new(store.pool().clone()));
        let transcript_path = storage_dir.path().join("transcripts");
        let transcript_store = Arc::new(hf_storage::JsonlTranscriptStore::new(&transcript_path));
        let display_transcript_store = Arc::new(hf_storage::JsonlDisplayTranscriptStore::new(
            &transcript_path,
        ));

        TestManager {
            manager: SessionManager::new(
                session_store,
                transcript_store,
                display_transcript_store,
                SessionConfig::default(),
            ),
            _storage_dir: storage_dir,
        }
    }

    fn test_msg(content: &str) -> Message {
        Message {
            message_id: hf_core::types::generate_message_id(),
            role: Role::User,
            content: content.into(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
            metadata: serde_json::Value::Null,
        }
    }

    #[tokio::test]
    async fn test_manager_create_session() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("Test".into()),
            })
            .await
            .unwrap();

        assert_eq!(session.session_type, SessionType::Main);
        assert_eq!(session.state, SessionState::Active);
    }

    #[tokio::test]
    async fn test_manager_transition_active_to_paused() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.transition_state(&session.id, SessionState::Paused)
            .await
            .unwrap();

        let updated = mgr.get_session(&session.id).await.unwrap();
        assert_eq!(updated.state, SessionState::Paused);
    }

    #[tokio::test]
    async fn test_manager_invalid_transition_archived_to_active() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.transition_state(&session.id, SessionState::Archived)
            .await
            .unwrap();

        let result = mgr
            .transition_state(&session.id, SessionState::Active)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_manager_append_and_read_messages() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.append_message(&session.id, &test_msg("hello"))
            .await
            .unwrap();
        mgr.append_message(&session.id, &test_msg("world"))
            .await
            .unwrap();

        let transcript = mgr.read_transcript(&session.id).await.unwrap();
        assert_eq!(transcript.len(), 2);
        assert_eq!(transcript[0].content, "hello");
        assert_eq!(transcript[1].content, "world");
    }

    #[tokio::test]
    async fn test_manager_append_messages_commits_one_metadata_update() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.append_messages(
            &session.id,
            &[test_msg("user"), Message::assistant("assistant")],
        )
        .await
        .unwrap();

        let updated = mgr.get_session(&session.id).await.unwrap();
        assert_eq!(updated.message_count, 2);
        assert_eq!(mgr.read_transcript(&session.id).await.unwrap().len(), 2);
        assert_eq!(
            mgr.read_display_transcript(&session.id)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn test_manager_append_compensates_display_when_context_write_fails() {
        let transcript_dir = tempfile::tempdir().unwrap();
        let store = hf_storage::Store::connect(transcript_dir.path().join("sessions.db"))
            .await
            .unwrap();
        let session_store = Arc::new(hf_storage::SqliteSessionStore::new(store.pool().clone()));
        let invalid_context_dir = transcript_dir.path().join("context-is-a-file");
        std::fs::write(&invalid_context_dir, b"not a directory").unwrap();
        let display = Arc::new(hf_storage::JsonlDisplayTranscriptStore::new(
            transcript_dir.path().join("display"),
        ));
        let mgr = SessionManager::new(
            session_store,
            Arc::new(hf_storage::JsonlTranscriptStore::new(invalid_context_dir)),
            display.clone(),
            SessionConfig::default(),
        );
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let result = mgr
            .append_message(&session.id, &test_msg("not committed"))
            .await;

        assert!(result.is_err());
        assert!(display.read_all(&session.id).await.unwrap().is_empty());
        assert_eq!(mgr.get_session(&session.id).await.unwrap().message_count, 0);
    }

    #[tokio::test]
    async fn test_manager_rejects_transcript_reads_for_unknown_sessions() {
        let mgr = setup().await;
        let unknown = SessionId::from_string("unknown-session");

        assert!(mgr.read_transcript(&unknown).await.is_err());
        assert!(mgr.read_display_transcript(&unknown).await.is_err());
        assert!(mgr.read_last_messages(&unknown, 10).await.is_err());
    }

    #[tokio::test]
    async fn test_manager_append_to_paused_session_fails() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.transition_state(&session.id, SessionState::Paused)
            .await
            .unwrap();

        let result = mgr.append_message(&session.id, &test_msg("fail")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_manager_branch() {
        let mgr = setup().await;
        let main = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let branch = mgr.branch(&main.id, Some("Branch 1".into())).await.unwrap();

        assert_eq!(branch.session_type, SessionType::Branch);
        assert_eq!(branch.parent_id, Some(main.id.clone()));
        assert_eq!(branch.depth, 1);
    }

    #[tokio::test]
    async fn test_manager_max_depth_enforced() {
        let td = tempfile::tempdir().unwrap();
        let tp = td.path().to_path_buf();
        let mgr = SessionManager::new(
            {
                let store = hf_storage::Store::connect(td.path().join("sessions.db"))
                    .await
                    .unwrap();
                Arc::new(hf_storage::SqliteSessionStore::new(store.pool().clone()))
            },
            Arc::new(hf_storage::JsonlTranscriptStore::new(&tp)),
            Arc::new(hf_storage::JsonlDisplayTranscriptStore::new(&tp)),
            SessionConfig {
                max_depth: 2,
                ..Default::default()
            },
        );

        let root = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let child = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(root.id.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let grandchild = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(child.id.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        // grandchild is at depth 2 (max_depth), so creating another child should fail.
        let result = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(grandchild.id.clone()),
                session_type: SessionType::Child,
                agent_id: None,
                title: None,
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fork_session_copies_messages() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("Original".into()),
            })
            .await
            .unwrap();

        // Append 5 messages.
        for i in 0..5 {
            mgr.append_message(&session.id, &test_msg(&format!("msg-{i}")))
                .await
                .unwrap();
        }

        // Fork at message index 2 (copy messages 0, 1, 2).
        let fork = mgr.fork_session(&session.id, 2, None).await.unwrap();

        assert_eq!(fork.session_type, SessionType::Branch);
        assert_eq!(fork.parent_id, Some(session.id.clone()));
        assert_eq!(fork.message_count, 3);
        assert_eq!(fork.title, Some("Original (Branch)".into()));

        // Verify forked context transcript.
        let fork_msgs = mgr.read_transcript(&fork.id).await.unwrap();
        assert_eq!(fork_msgs.len(), 3);
        assert_eq!(fork_msgs[0].content, "msg-0");
        assert_eq!(fork_msgs[1].content, "msg-1");
        assert_eq!(fork_msgs[2].content, "msg-2");

        // Verify forked display transcript.
        let fork_display = mgr.read_display_transcript(&fork.id).await.unwrap();
        assert_eq!(fork_display.len(), 3);

        // Verify original is untouched.
        let orig_msgs = mgr.read_transcript(&session.id).await.unwrap();
        assert_eq!(orig_msgs.len(), 5);
    }

    #[tokio::test]
    async fn test_fork_session_at_index_zero() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.append_message(&session.id, &test_msg("first"))
            .await
            .unwrap();
        mgr.append_message(&session.id, &test_msg("second"))
            .await
            .unwrap();

        // Fork at index 0: only the first message.
        let fork = mgr
            .fork_session(&session.id, 0, Some("Just first".into()))
            .await
            .unwrap();

        let fork_msgs = mgr.read_transcript(&fork.id).await.unwrap();
        assert_eq!(fork_msgs.len(), 1);
        assert_eq!(fork_msgs[0].content, "first");
        assert_eq!(fork.title, Some("Just first".into()));
    }

    #[tokio::test]
    async fn test_fork_session_full_copy() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        for i in 0..3 {
            mgr.append_message(&session.id, &test_msg(&format!("msg-{i}")))
                .await
                .unwrap();
        }

        // Fork at index >= total count: should copy all.
        let fork = mgr.fork_session(&session.id, 100, None).await.unwrap();

        let fork_msgs = mgr.read_transcript(&fork.id).await.unwrap();
        assert_eq!(fork_msgs.len(), 3);
    }

    #[tokio::test]
    async fn test_fork_session_max_index_copies_all_messages() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        for i in 0..2 {
            mgr.append_message(&session.id, &test_msg(&format!("msg-{i}")))
                .await
                .unwrap();
        }

        let fork = mgr
            .fork_session(&session.id, usize::MAX, None)
            .await
            .unwrap();

        let fork_msgs = mgr.read_transcript(&fork.id).await.unwrap();
        assert_eq!(fork_msgs.len(), 2);
    }

    #[tokio::test]
    async fn test_fork_session_independence() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        mgr.append_message(&session.id, &test_msg("shared"))
            .await
            .unwrap();

        let fork = mgr.fork_session(&session.id, 0, None).await.unwrap();

        // Append to original after fork.
        mgr.append_message(&session.id, &test_msg("original-only"))
            .await
            .unwrap();

        // Fork should still have only 1 message.
        let fork_msgs = mgr.read_transcript(&fork.id).await.unwrap();
        assert_eq!(fork_msgs.len(), 1);
        assert_eq!(fork_msgs[0].content, "shared");
    }

    #[tokio::test]
    async fn test_fork_empty_session_fails() {
        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let result = mgr.fork_session(&session.id, 0, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fork_failure_removes_incomplete_branch() {
        let session_store = Arc::new(MockSessionStore::new());
        let context = Arc::new(ToggleTranscriptStore::default());
        let display = Arc::new(MockDisplayTranscriptStore::new());
        let mgr = SessionManager::new(
            session_store.clone(),
            context.clone(),
            display,
            SessionConfig::default(),
        );
        let source = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();
        mgr.append_message(&source.id, &test_msg("source"))
            .await
            .unwrap();
        context.fail_append.store(true, Ordering::SeqCst);

        let result = mgr.fork_session(&source.id, 0, None).await;

        assert!(result.is_err());
        let sessions = session_store.list(&SessionFilter::default()).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, source.id);
    }

    #[tokio::test]
    async fn test_descendants_including_self_returns_only_subtree() {
        let mgr = setup().await;
        let root = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("root".into()),
            })
            .await
            .unwrap();

        let target = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(root.id.clone()),
                session_type: SessionType::SubAgent,
                agent_id: None,
                title: Some("target".into()),
            })
            .await
            .unwrap();

        let descendant = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(target.id.clone()),
                session_type: SessionType::SubAgent,
                agent_id: None,
                title: Some("descendant".into()),
            })
            .await
            .unwrap();

        let sibling = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(root.id.clone()),
                session_type: SessionType::SubAgent,
                agent_id: None,
                title: Some("sibling".into()),
            })
            .await
            .unwrap();

        let collected = mgr.descendants_including_self(&target.id).await.unwrap();
        let collected_ids: Vec<_> = collected.into_iter().map(|node| node.id).collect();

        assert_eq!(
            collected_ids,
            vec![target.id.clone(), descendant.id.clone()]
        );
        assert!(!collected_ids.contains(&root.id));
        assert!(!collected_ids.contains(&sibling.id));
    }

    #[tokio::test]
    async fn test_delete_session_tombstones_and_clears_transcripts() {
        let mgr = setup().await;
        let parent = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: Some("parent".into()),
            })
            .await
            .unwrap();

        let _child = mgr
            .create_session(CreateSessionOptions {
                parent_id: Some(parent.id.clone()),
                session_type: SessionType::SubAgent,
                agent_id: None,
                title: Some("child".into()),
            })
            .await
            .unwrap();

        mgr.append_message(&parent.id, &test_msg("to be deleted"))
            .await
            .unwrap();

        mgr.delete_session(&parent.id).await.unwrap();

        let parent_after = mgr.get_session(&parent.id).await.unwrap();
        assert_eq!(parent_after.state, SessionState::Tombstone);
        assert_eq!(parent_after.message_count, 0);
        assert_eq!(parent_after.token_count, 0);

        let context_msgs = mgr.read_transcript(&parent.id).await.unwrap();
        let display_msgs = mgr.read_display_transcript(&parent.id).await.unwrap();
        assert!(context_msgs.is_empty());
        assert!(display_msgs.is_empty());
    }

    #[tokio::test]
    async fn test_delete_failure_restores_transcripts_and_keeps_session_active() {
        let session_store = Arc::new(MockSessionStore::new());
        let context = Arc::new(ToggleTranscriptStore::default());
        let display = Arc::new(MockDisplayTranscriptStore::new());
        let mgr = SessionManager::new(
            session_store,
            context.clone(),
            display,
            SessionConfig::default(),
        );
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();
        mgr.append_message(&session.id, &test_msg("keep me"))
            .await
            .unwrap();
        context.fail_truncate.store(true, Ordering::SeqCst);

        let result = mgr.delete_session(&session.id).await;

        assert!(result.is_err());
        let node = mgr.get_session(&session.id).await.unwrap();
        assert_eq!(node.state, SessionState::Active);
        assert_eq!(node.message_count, 1);
        assert_eq!(mgr.read_transcript(&session.id).await.unwrap().len(), 1);
        assert_eq!(
            mgr.read_display_transcript(&session.id)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_generate_title_only_includes_user_text_messages() {
        use async_trait::async_trait;
        use hf_core::agent::{
            AgentDelegator, ContextStrategyHint, DelegationError, DelegationOutput,
        };
        use std::sync::{Arc, Mutex};

        #[derive(Debug, Default)]
        struct CapturingDelegator {
            captured_input: Arc<Mutex<Option<serde_json::Value>>>,
        }

        #[async_trait]
        impl AgentDelegator for CapturingDelegator {
            async fn delegate(
                &self,
                _agent_name: &str,
                input: serde_json::Value,
                _context_strategy: ContextStrategyHint,
                _session_id: Option<uuid::Uuid>,
            ) -> Result<DelegationOutput, DelegationError> {
                *self.captured_input.lock().unwrap() = Some(input);
                Ok(DelegationOutput {
                    text: "Generated Title".to_string(),
                    tokens_used: 10,
                    input_tokens: 6,
                    output_tokens: 4,
                    model_used: "test-model".to_string(),
                    duration_ms: 1,
                })
            }
        }

        let mgr = setup().await;
        let session = mgr
            .create_session(CreateSessionOptions {
                parent_id: None,
                session_type: SessionType::Main,
                agent_id: None,
                title: None,
            })
            .await
            .unwrap();

        let user_msg = Message {
            message_id: hf_core::types::generate_message_id(),
            role: Role::User,
            content: "draft a release plan".into(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
            metadata: serde_json::Value::Null,
        };
        let assistant_msg = Message {
            message_id: hf_core::types::generate_message_id(),
            role: Role::Assistant,
            content: "Sure, let me look at the tests first.".into(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
            metadata: serde_json::Value::Null,
        };
        let tool_msg = Message {
            message_id: hf_core::types::generate_message_id(),
            role: Role::Tool,
            content: r#"{"exit_code":0,"stdout":"...","stderr":""}"#.into(),
            tool_call_id: Some("call_29ddfe381fed43528e4b4cc8".into()),
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
            metadata: serde_json::Value::Null,
        };
        let second_user_msg = Message {
            message_id: hf_core::types::generate_message_id(),
            role: Role::User,
            content: "thanks, also add a smoke test".into(),
            tool_call_id: None,
            tool_calls: vec![],
            timestamp: chrono::Utc::now(),
            metadata: serde_json::Value::Null,
        };

        let messages = vec![user_msg, assistant_msg, tool_msg, second_user_msg];

        let captured = Arc::new(Mutex::new(None));
        let delegator = CapturingDelegator {
            captured_input: Arc::clone(&captured),
        };

        let title = mgr
            .generate_title(&delegator, &session.id, &messages)
            .await
            .unwrap();
        assert_eq!(title, "Generated Title");

        let input = captured.lock().unwrap().clone().expect("delegator called");
        let arr = input
            .get("messages")
            .and_then(|v| v.as_array())
            .expect("input.messages is an array");

        assert_eq!(
            arr.len(),
            2,
            "only user-role text messages should reach the title generator, got {arr:?}"
        );
        for entry in arr {
            let role = entry.get("role").and_then(|v| v.as_str()).unwrap();
            assert_eq!(
                role, "User",
                "unexpected role in title generator input: {role}"
            );
        }

        let contents: Vec<&str> = arr
            .iter()
            .filter_map(|e| e.get("content").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(
            contents,
            vec!["draft a release plan", "thanks, also add a smoke test"]
        );
    }
}
