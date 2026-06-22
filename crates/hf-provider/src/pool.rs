//! Default provider pool implementation (stub).

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmProvider, LlmResponse, ProviderPool};
use hf_core::types::Message;
use std::sync::Mutex;

/// A stub provider pool that holds boxed providers and routes by tag.
pub struct DefaultProviderPool {
    #[allow(dead_code)]
    providers: Mutex<Vec<Box<dyn LlmProvider>>>,
}

impl DefaultProviderPool {
    #[must_use]
    pub fn new(providers: Vec<Box<dyn LlmProvider>>) -> Self {
        Self {
            providers: Mutex::new(providers),
        }
    }
}

#[async_trait]
impl ProviderPool for DefaultProviderPool {
    async fn complete(
        &self,
        _tags: &[&str],
        _messages: Vec<Message>,
    ) -> Result<LlmResponse, ClassifiedError> {
        Err(ClassifiedError::Provider(
            "no provider configured".to_owned(),
        ))
    }
    async fn freeze(&self, _provider_id: &str) {}
    async fn thaw(&self, _provider_id: &str) {}
}
