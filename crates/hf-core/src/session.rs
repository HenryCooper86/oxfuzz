//! Session and transcript storage traits.

use async_trait::async_trait;
use std::path::PathBuf;

use crate::error::ClassifiedError;
use crate::types::{Id, Message};

/// Stores session metadata and message history.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(&self, parent: Option<Id>) -> Result<Id, ClassifiedError>;
    async fn append(&self, session: Id, msg: Message) -> Result<(), ClassifiedError>;
    async fn history(&self, session: Id) -> Result<Vec<Message>, ClassifiedError>;
}

/// Stores raw transcripts to disk.
#[async_trait]
pub trait TranscriptStore: Send + Sync {
    async fn write(&self, session: Id, transcript: &str) -> Result<PathBuf, ClassifiedError>;
}
