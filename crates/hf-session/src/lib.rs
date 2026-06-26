//! hf-session: persistent conversation sessions.
//!
//! Implements the [`SessionStore`] trait from `hf-core` on top of `hf-storage`,
//! giving the agent durable multi-turn memory: sessions and their message
//! history survive restarts instead of living only in the frontend.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::session::SessionStore;
use hf_core::types::{Id, Message, Role};
use hf_storage::Store;

/// A [`SessionStore`] backed by the `SQLite` [`Store`].
#[derive(Clone)]
pub struct SqliteSessionStore {
    store: Arc<Store>,
}

impl SqliteSessionStore {
    /// Wrap a storage handle.
    #[must_use]
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl SessionStore for SqliteSessionStore {
    async fn create(&self, parent: Option<Id>) -> Result<Id, ClassifiedError> {
        let id = self
            .store
            .create_session(parent.map(|i| i.0), Utc::now())
            .await?;
        Ok(Id(id))
    }

    async fn append(&self, session: Id, msg: Message) -> Result<(), ClassifiedError> {
        self.store
            .append_message(session.0, role_str(msg.role), &msg.content, Utc::now())
            .await?;
        Ok(())
    }

    async fn history(&self, session: Id) -> Result<Vec<Message>, ClassifiedError> {
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
