//! Memory and experience store traits.

use async_trait::async_trait;

use crate::error::ClassifiedError;
use crate::types::Id;

/// Short/long-term memory client.
#[async_trait]
pub trait MemoryClient: Send + Sync {
    async fn remember(&self, key: &str, value: &str) -> Result<(), ClassifiedError>;
    async fn recall(&self, key: &str) -> Result<Option<String>, ClassifiedError>;
}

/// Experience store for skill evolution.
#[async_trait]
pub trait ExperienceStore: Send + Sync {
    async fn record(&self, session: Id, outcome: &str) -> Result<(), ClassifiedError>;
}
