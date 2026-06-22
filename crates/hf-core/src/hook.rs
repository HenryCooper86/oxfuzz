//! Middleware hooks.

use async_trait::async_trait;

use crate::error::ClassifiedError;

/// Middleware in the agent loop.
#[async_trait]
pub trait Middleware: Send + Sync {
    async fn before(&self, input: &str) -> Result<String, ClassifiedError>;
    async fn after(&self, output: &str) -> Result<String, ClassifiedError>;
}

/// Event handler.
#[async_trait]
pub trait HookHandler: Send + Sync {
    async fn handle(&self, event: &str) -> Result<(), ClassifiedError>;
}

/// Event subscriber.
#[async_trait]
pub trait EventSubscriber: Send + Sync {
    async fn subscribe(&self, topic: &str) -> Result<(), ClassifiedError>;
}
