//! Default provider pool with tag-based routing.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmProvider, LlmResponse, ProviderPool};
use hf_core::types::Message;
use std::sync::Arc;

use crate::openai_compat::ProviderConfig;

/// A provider pool that routes by tag and calls the first matching provider.
pub struct DefaultProviderPool {
    providers: Vec<Arc<dyn LlmProvider>>,
    tags: Vec<Vec<String>>,
    #[allow(dead_code)]
    configs: Vec<ProviderConfig>,
}

impl DefaultProviderPool {
    /// Create a pool from a list of providers. Tags are empty; routing
    /// falls back to the first provider when tags are not set.
    #[must_use]
    pub fn new(providers: Vec<Box<dyn LlmProvider>>) -> Self {
        Self::with_configs(providers, Vec::new())
    }

    /// Create a pool with provider configs (tags used for routing).
    #[must_use]
    pub fn with_configs(
        providers: Vec<Box<dyn LlmProvider>>,
        configs: Vec<ProviderConfig>,
    ) -> Self {
        let tags = if configs.is_empty() {
            vec![Vec::new(); providers.len()]
        } else {
            configs.iter().map(|c| c.tags.clone()).collect()
        };
        Self {
            providers: providers.into_iter().map(Arc::from).collect(),
            tags,
            configs,
        }
    }

    fn find_matching(&self, requested: &[&str]) -> Option<usize> {
        if requested.is_empty() {
            return None;
        }
        for (i, provider_tags) in self.tags.iter().enumerate() {
            if !provider_tags.is_empty()
                && requested
                    .iter()
                    .all(|req| provider_tags.iter().any(|t| t == req))
            {
                return Some(i);
            }
        }
        None
    }
}

#[async_trait]
impl ProviderPool for DefaultProviderPool {
    async fn complete(
        &self,
        tags: &[&str],
        messages: Vec<Message>,
    ) -> Result<LlmResponse, ClassifiedError> {
        let idx = if tags.is_empty() {
            // No tags requested: use first provider if any.
            if self.providers.is_empty() {
                None
            } else {
                Some(0)
            }
        } else {
            // Tags requested: require a match, no fallback.
            self.find_matching(tags)
        }
        .ok_or_else(|| ClassifiedError::Provider("no provider configured".to_owned()))?;
        let provider = self
            .providers
            .get(idx)
            .ok_or_else(|| ClassifiedError::Provider("no provider configured".to_owned()))?;
        provider.complete(messages).await
    }

    async fn freeze(&self, _provider_id: &str) {}
    async fn thaw(&self, _provider_id: &str) {}
}
