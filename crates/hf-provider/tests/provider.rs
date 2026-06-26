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

/// A mock sender returning a caller-supplied JSON body, for exercising the
/// response parser's tolerance of real-world OpenAI-compatible variants.
struct CannedSender(serde_json::Value);

#[async_trait::async_trait]
impl hf_provider::HttpSender for CannedSender {
    async fn post_json(
        &self,
        _url: &str,
        _api_key: &str,
        _body: serde_json::Value,
    ) -> Result<serde_json::Value, hf_core::error::ClassifiedError> {
        Ok(self.0.clone())
    }
}

fn test_cfg() -> ProviderConfig {
    ProviderConfig {
        id: "t".to_owned(),
        model: "m".to_owned(),
        api_key: "k".to_owned(),
        base_url: "https://example.com/v1".to_owned(),
        tags: vec!["general".to_owned()],
        max_concurrency: 1,
        context_window: 4096,
    }
}

/// Reasoning models (GLM, DeepSeek-R1) may return null `content` with the text
/// in `reasoning_content`. We should surface that instead of erroring.
#[tokio::test]
async fn reasoning_content_is_used_when_content_is_null() {
    let body = serde_json::json!({
        "choices": [{ "message": {
            "role": "assistant",
            "content": null,
            "reasoning_content": "answer from reasoning"
        }}],
        "usage": { "prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3 }
    });
    let provider = OpenAiCompatProvider::with_sender(test_cfg(), Arc::new(CannedSender(body)));
    let resp = provider.complete(vec![user_msg("hi")]).await.unwrap();
    assert_eq!(resp.content, "answer from reasoning");
}

/// Some OpenAI-compatible endpoints omit the `usage` block entirely. That must
/// not fail the request; usage just defaults to zero.
#[tokio::test]
async fn missing_usage_block_defaults_to_zero() {
    let body = serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": "ok" } }]
    });
    let provider = OpenAiCompatProvider::with_sender(test_cfg(), Arc::new(CannedSender(body)));
    let resp = provider.complete(vec![user_msg("hi")]).await.unwrap();
    assert_eq!(resp.content, "ok");
    assert_eq!(resp.usage.total_tokens, 0);
}
