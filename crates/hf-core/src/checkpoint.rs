//! Checkpoint storage for recoverability.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ClassifiedError;
use crate::types::Id;

/// A checkpoint of agent state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub session: Id,
    pub step: u64,
    pub state_json: String,
}

#[async_trait]
pub trait CheckpointStorage: Send + Sync {
    async fn save(&self, checkpoint: Checkpoint) -> Result<(), ClassifiedError>;
    async fn load(&self, session: Id) -> Result<Option<Checkpoint>, ClassifiedError>;
}
