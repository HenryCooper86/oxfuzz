//! Simple durable chat-session store for the GUI conversation flow.
//!
//! hobot's GUI chat needs lightweight create/append/history persistence over
//! [`hf_storage::Store`]. y-agent's richer session-tree model (the ported
//! `hf-session` crate: `SessionManager`, checkpoints, transcript stores) is
//! available for future agent work, but the GUI chat keeps this minimal store
//! so it is not coupled to the tree model.

use std::sync::Arc;

use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::types::{Id, Message, Role};
use hf_storage::Store;

/// A minimal chat-session store backed by the `SQLite` [`Store`].
#[derive(Clone)]
pub struct ChatSessionStore {
    store: Arc<Store>,
}

impl ChatSessionStore {
    /// Wrap a storage handle.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    /// Create a new session, optionally rooted at a parent.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the session cannot be persisted.
    pub async fn create(&self, parent: Option<Id>) -> Result<Id, ClassifiedError> {
        let id = self
            .store
            .create_session(parent.map(|i| i.0), Utc::now())
            .await?;
        Ok(Id(id))
    }

    /// Append a message to a session's transcript.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the message cannot be persisted.
    pub async fn append(&self, session: Id, msg: Message) -> Result<(), ClassifiedError> {
        self.store
            .append_message(session.0, role_str(msg.role), &msg.content, Utc::now())
            .await?;
        Ok(())
    }

    /// Load a session's full message history.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the history cannot be read.
    pub async fn history(&self, session: Id) -> Result<Vec<Message>, ClassifiedError> {
        let rows = self.store.session_history(session.0).await?;
        Ok(rows
            .into_iter()
            .map(|(role, content)| Message::new(role_from(&role), content))
            .collect())
    }
}

/// The wire string for a role (stable, lowercase).
fn role_str(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

/// Parse a stored role string, defaulting unknown values to `User`.
fn role_from(s: &str) -> Role {
    match s {
        "system" => Role::System,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        _ => Role::User,
    }
}
