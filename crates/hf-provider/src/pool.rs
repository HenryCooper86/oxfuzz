//! Default provider pool with tag-based routing, freeze/failover resilience.
//!
//! `complete()` builds an ordered candidate list (honouring tag routing), skips
//! providers that are currently frozen, and tries each in turn. A failed call is
//! classified (see [`crate::error_classifier`]); the offending provider is
//! frozen (see [`crate::freeze`]) and the pool fails over to the next candidate.
//! Only when every candidate is exhausted does the last error propagate, so a
//! single rate-limit/auth blip no longer kills an in-flight campaign.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmProvider, LlmResponse, ProviderPool};
use hf_core::types::Message;
use std::sync::Arc;

use crate::error_classifier::{classify, FailureClass};
use crate::freeze::FreezeRegistry;
use crate::openai_compat::ProviderConfig;

/// A provider pool that routes by tag, with freeze-based failover.
pub struct DefaultProviderPool {
    providers: Vec<Arc<dyn LlmProvider>>,
    tags: Vec<Vec<String>>,
    #[allow(dead_code)]
    configs: Vec<ProviderConfig>,
    freezes: FreezeRegistry,
}

impl DefaultProviderPool {
    /// Create a pool from a list of providers. Tags are empty; routing
    /// falls back to the first available provider when tags are not set.
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
            freezes: FreezeRegistry::new(),
        }
    }

    /// Whether provider `idx` matches all requested tags.
    fn matches(&self, idx: usize, requested: &[&str]) -> bool {
        let provider_tags = &self.tags[idx];
        !provider_tags.is_empty()
            && requested
                .iter()
                .all(|req| provider_tags.iter().any(|t| t == req))
    }

    /// Ordered candidate provider indices for a routing request.
    ///
    /// Preserves the existing tag semantics: empty tags route to every provider
    /// in declaration order (first available wins); tagged requests route only
    /// to matching providers, in declaration order.
    fn candidates(&self, tags: &[&str]) -> Vec<usize> {
        if tags.is_empty() {
            (0..self.providers.len()).collect()
        } else {
            (0..self.providers.len())
                .filter(|&i| self.matches(i, tags))
                .collect()
        }
    }
}

#[async_trait]
impl ProviderPool for DefaultProviderPool {
    async fn complete(
        &self,
        tags: &[&str],
        messages: Vec<Message>,
    ) -> Result<LlmResponse, ClassifiedError> {
        let candidates = self.candidates(tags);
        if candidates.is_empty() {
            return Err(ClassifiedError::Provider(
                "no provider configured".to_owned(),
            ));
        }

        let mut last_error: Option<ClassifiedError> = None;

        for idx in candidates {
            let provider = &self.providers[idx];
            let id = provider.id();
            if self.freezes.is_frozen(id) {
                continue;
            }

            match provider.complete(messages.clone()).await {
                Ok(resp) => return Ok(resp),
                Err(err) => {
                    // Freeze the offending provider per its classification, then
                    // fail over to the next candidate.
                    let class = classify(&err);
                    let backoff = class.backoff();
                    self.freezes.freeze_for(id, backoff);
                    match class {
                        FailureClass::Retryable { .. } => {
                            tracing::warn!(provider = id, error = %err, "provider retryable failure; failing over");
                        }
                        FailureClass::Fatal { .. } => {
                            tracing::error!(provider = id, error = %err, "provider fatal failure; failing over");
                        }
                    }
                    last_error = Some(err);
                }
            }
        }

        // Exhausted every candidate. Surface the last real error if we tried a
        // provider; otherwise every candidate was already frozen.
        Err(last_error.unwrap_or_else(|| {
            ClassifiedError::Provider("all candidate providers are frozen".to_owned())
        }))
    }

    async fn freeze(&self, provider_id: &str) {
        self.freezes.freeze(provider_id);
    }

    async fn thaw(&self, provider_id: &str) {
        self.freezes.thaw(provider_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::Stream;
    use hf_core::provider::LlmResponse;
    use hf_core::types::TokenUsage;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A mock provider whose `complete` outcome is fixed at construction.
    struct MockProvider {
        id: String,
        /// `Ok` => succeed; `Err` => fail with this error each call.
        outcome: Result<(), ClassifiedError>,
        calls: AtomicUsize,
    }

    impl MockProvider {
        fn ok(id: &str) -> Self {
            Self {
                id: id.to_owned(),
                outcome: Ok(()),
                calls: AtomicUsize::new(0),
            }
        }

        fn failing(id: &str, err: ClassifiedError) -> Self {
            Self {
                id: id.to_owned(),
                outcome: Err(err),
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        fn id(&self) -> &str {
            &self.id
        }

        async fn complete(&self, _messages: Vec<Message>) -> Result<LlmResponse, ClassifiedError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match &self.outcome {
                Ok(()) => Ok(LlmResponse {
                    content: format!("ok from {}", self.id),
                    usage: TokenUsage::default(),
                    model: self.id.clone(),
                }),
                Err(e) => Err(e.clone()),
            }
        }

        async fn stream(
            &self,
            _messages: Vec<Message>,
        ) -> Result<
            Box<dyn Stream<Item = Result<String, ClassifiedError>> + Send + Unpin>,
            ClassifiedError,
        > {
            Err(ClassifiedError::Provider("no streaming".to_owned()))
        }
    }

    fn pool_of(providers: Vec<Box<dyn LlmProvider>>) -> DefaultProviderPool {
        DefaultProviderPool::new(providers)
    }

    #[tokio::test]
    async fn frozen_provider_is_skipped() {
        let pool = pool_of(vec![
            Box::new(MockProvider::ok("a")),
            Box::new(MockProvider::ok("b")),
        ]);
        // Freeze the first provider; routing must skip to "b".
        pool.freeze("a").await;
        let resp = pool.complete(&[], vec![]).await.unwrap();
        assert_eq!(resp.model, "b");
    }

    #[tokio::test]
    async fn retryable_failure_fails_over() {
        let rate_limited = ClassifiedError::Provider("http 429 Too Many Requests: {}".to_owned());
        let a = Arc::new(MockProvider::failing("a", rate_limited));
        let b = Arc::new(MockProvider::ok("b"));
        let pool = DefaultProviderPool::new(vec![
            Box::new(MockProviderHandle(Arc::clone(&a))),
            Box::new(MockProviderHandle(Arc::clone(&b))),
        ]);

        let resp = pool.complete(&[], vec![]).await.unwrap();
        assert_eq!(resp.model, "b");
        assert_eq!(a.call_count(), 1, "a should have been tried once");
        // "a" is now frozen, so a second call goes straight to "b".
        let resp2 = pool.complete(&[], vec![]).await.unwrap();
        assert_eq!(resp2.model, "b");
        assert_eq!(a.call_count(), 1, "a stays frozen and is not retried");
    }

    #[tokio::test]
    async fn exhausting_all_candidates_errors() {
        let err = ClassifiedError::Provider("http 503 Service Unavailable: {}".to_owned());
        let pool = pool_of(vec![
            Box::new(MockProvider::failing("a", err.clone())),
            Box::new(MockProvider::failing("b", err)),
        ]);
        let result = pool.complete(&[], vec![]).await;
        assert!(
            result.is_err(),
            "all providers failing must surface an error"
        );
    }

    #[tokio::test]
    async fn thaw_re_enables_provider() {
        let pool = pool_of(vec![Box::new(MockProvider::ok("a"))]);
        pool.freeze("a").await;
        // Only provider is frozen -> error.
        assert!(pool.complete(&[], vec![]).await.is_err());
        // Thaw and it works again.
        pool.thaw("a").await;
        let resp = pool.complete(&[], vec![]).await.unwrap();
        assert_eq!(resp.model, "a");
    }

    #[tokio::test]
    async fn tag_routing_selects_only_matching() {
        let cfgs = vec![cfg("a", &["code"]), cfg("b", &["reasoning"])];
        let pool = DefaultProviderPool::with_configs(
            vec![
                Box::new(MockProvider::ok("a")),
                Box::new(MockProvider::ok("b")),
            ],
            cfgs,
        );
        let resp = pool.complete(&["reasoning"], vec![]).await.unwrap();
        assert_eq!(resp.model, "b");
    }

    fn cfg(id: &str, tags: &[&str]) -> ProviderConfig {
        ProviderConfig {
            id: id.to_owned(),
            model: id.to_owned(),
            api_key: String::new(),
            base_url: String::new(),
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            max_concurrency: 1,
            context_window: 8192,
        }
    }

    /// Wrapper so a test can hold an `Arc` to inspect call counts while the pool
    /// owns the provider as a `Box<dyn LlmProvider>`.
    struct MockProviderHandle(Arc<MockProvider>);

    #[async_trait]
    impl LlmProvider for MockProviderHandle {
        fn id(&self) -> &str {
            self.0.id()
        }
        async fn complete(&self, messages: Vec<Message>) -> Result<LlmResponse, ClassifiedError> {
            self.0.complete(messages).await
        }
        async fn stream(
            &self,
            messages: Vec<Message>,
        ) -> Result<
            Box<dyn Stream<Item = Result<String, ClassifiedError>> + Send + Unpin>,
            ClassifiedError,
        > {
            self.0.stream(messages).await
        }
    }
}
