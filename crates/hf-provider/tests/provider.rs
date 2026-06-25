//! Unit tests for the OpenAI-compatible provider and pool routing.

use hf_core::provider::{LlmProvider, ProviderPool};
use hf_core::types::{Message, Role};
use hf_provider::{DefaultProviderPool, OpenAiCompatProvider, ProviderConfig};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn user_msg(s: &str) -> Message {
    Message {
        role: Role::User,
        content: s.to_owned(),
    }
}

/// A mock HTTP sender that returns a canned OpenAI-compatible response.
struct MockSender {
    calls: Arc<AtomicUsize>,
}

impl MockSender {
    fn new() -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                calls: calls.clone(),
            },
            calls,
        )
    }
}

#[async_trait::async_trait]
impl hf_provider::HttpSender for MockSender {
    async fn post_json(
        &self,
        _url: &str,
        _api_key: &str,
        _body: serde_json::Value,
    ) -> Result<serde_json::Value, hf_core::error::ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "hello from mock"
                    }
                }
            ],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            }
        }))
    }
}

#[tokio::test]
async fn openai_compat_provider_returns_content() {
    let (sender, calls) = MockSender::new();
    let cfg = ProviderConfig {
        id: "test".to_owned(),
        model: "test-model".to_owned(),
        api_key: "k".to_owned(),
        base_url: "https://example.com/v1".to_owned(),
        tags: vec!["general".to_owned()],
        max_concurrency: 1,
        context_window: 4096,
    };
    let provider = OpenAiCompatProvider::with_sender(cfg, Arc::new(sender));
    let resp = provider
        .complete(vec![user_msg("hi")])
        .await
        .expect("complete should succeed");
    assert_eq!(resp.content, "hello from mock");
    assert_eq!(resp.usage.total_tokens, 15);
    assert_eq!(resp.model, "test-model");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn pool_routes_to_matching_tag() {
    let (sender, _calls) = MockSender::new();
    let cfg = ProviderConfig {
        id: "p1".to_owned(),
        model: "m".to_owned(),
        api_key: "k".to_owned(),
        base_url: "https://example.com/v1".to_owned(),
        tags: vec!["reasoning".to_owned(), "code".to_owned()],
        max_concurrency: 1,
        context_window: 4096,
    };
    let provider: Box<dyn LlmProvider> = Box::new(OpenAiCompatProvider::with_sender(
        cfg.clone(),
        Arc::new(sender),
    ));
    let pool = DefaultProviderPool::with_configs(vec![provider], vec![cfg]);
    let resp = pool
        .complete(&["code"], vec![user_msg("hi")])
        .await
        .expect("pool should route");
    assert_eq!(resp.content, "hello from mock");
}

#[tokio::test]
async fn pool_returns_error_when_no_tag_match() {
    let (sender, _calls) = MockSender::new();
    let cfg = ProviderConfig {
        id: "p1".to_owned(),
        model: "m".to_owned(),
        api_key: "k".to_owned(),
        base_url: "https://example.com/v1".to_owned(),
        tags: vec!["reasoning".to_owned()],
        max_concurrency: 1,
        context_window: 4096,
    };
    let provider: Box<dyn LlmProvider> =
        Box::new(OpenAiCompatProvider::with_sender(cfg, Arc::new(sender)));
    let pool = DefaultProviderPool::new(vec![provider]);
    let err = pool
        .complete(&["nonexistent"], vec![user_msg("hi")])
        .await
        .expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("no provider"), "unexpected error: {msg}");
}
