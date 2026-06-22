//! LLM provider traits.

use async_trait::async_trait;
use futures::Stream;

use crate::error::ClassifiedError;
use crate::types::{Message, TokenUsage};

/// A single LLM provider backend.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn id(&self) -> &str;
    async fn complete(&self, messages: Vec<Message>) -> Result<LlmResponse, ClassifiedError>;
    async fn stream(
        &self,
        messages: Vec<Message>,
    ) -> Result<
        Box<dyn Stream<Item = Result<String, ClassifiedError>> + Send + Unpin>,
        ClassifiedError,
    >;
}

/// A response from an LLM provider.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub content: String,
    pub usage: TokenUsage,
    pub model: String,
}

/// A pool of providers with tag-based routing and failover.
#[async_trait]
pub trait ProviderPool: Send + Sync {
    async fn complete(
        &self,
        tags: &[&str],
        messages: Vec<Message>,
    ) -> Result<LlmResponse, ClassifiedError>;
    async fn freeze(&self, provider_id: &str);
    async fn thaw(&self, provider_id: &str);
}
