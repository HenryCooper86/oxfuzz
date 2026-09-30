use std::sync::atomic::Ordering;

use hf_core::embedding::EmbeddingProvider;
use hf_core::provider::{ChatRequest, ProviderPool, RouteRequest};
use hf_provider::{OpenAiEmbedding, ProviderPoolConfig, ProviderPoolImpl};
mod common;
use common::{server, server_with_type};

fn config(url: &str, backend: &str, success: usize, error: usize) -> ProviderPoolConfig {
    serde_json::from_value(serde_json::json!({
        "response_body_limits": {"success_bytes": success, "error_bytes": error},
        "providers": [{"id":"fixture", "provider_type":backend, "model":"fixture",
                       "api_key":"fixture", "base_url":url, "max_concurrency":1}]
    }))
    .unwrap()
}

fn request() -> ChatRequest {
    ChatRequest::from_messages(vec![hf_core::types::Message::user("hello")])
}

fn success_body(backend: &str) -> &'static str {
    match backend {
        "anthropic" => {
            r#"{"id":"r","model":"fixture","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}"#
        }
        "gemini" => {
            r#"{"candidates":[{"content":{"parts":[{"text":"hello"}],"role":"model"},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}}"#
        }
        "ollama" => {
            r#"{"model":"fixture","message":{"role":"assistant","content":"hello"},"done":true,"prompt_eval_count":1,"eval_count":1}"#
        }
        _ => {
            r#"{"id":"r","model":"fixture","choices":[{"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#
        }
    }
}

#[tokio::test]
async fn pool_adapters_accept_exact_body_budget_and_reject_one_extra_byte() {
    for backend in ["openai", "anthropic", "azure", "gemini", "ollama"] {
        let body = success_body(backend).as_bytes();
        let fixture = server(200, vec![body[..15].to_vec(), body[15..].to_vec()]).await;
        let pool =
            ProviderPoolImpl::from_config(&config(&fixture.url, backend, body.len(), 64)).unwrap();
        assert_eq!(
            pool.chat_completion(&request(), &RouteRequest::default())
                .await
                .unwrap()
                .text(),
            "hello",
            "{backend}"
        );
        let pool =
            ProviderPoolImpl::from_config(&config(&fixture.url, backend, body.len() - 1, 64))
                .unwrap();
        let error = pool
            .chat_completion(&request(), &RouteRequest::default())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("response body exceeds"),
            "{backend}: {error}"
        );
        assert_eq!(
            fixture.calls.load(Ordering::SeqCst),
            2,
            "limit failures must not retry"
        );
        assert_eq!(pool.provider_statuses().await[0].active_requests, 0);
        assert!(!pool.provider_statuses().await[0].is_frozen);
    }
}

#[tokio::test]
async fn every_backend_bounds_http_errors_and_stream_handshake_errors() {
    for backend in ["openai", "anthropic", "azure", "gemini", "ollama"] {
        for status in [401, 429, 500] {
            let fixture = server(status, vec![vec![b'x'; 33]]).await;
            let pool =
                ProviderPoolImpl::from_config(&config(&fixture.url, backend, 1024, 32)).unwrap();
            let result = pool
                .chat_completion_stream(&request(), &RouteRequest::default())
                .await;
            let error = result.err().expect("oversized handshake must fail");
            assert!(
                error.to_string().contains("response body exceeds"),
                "{backend}/{status}: {error}"
            );
            let error = pool
                .chat_completion(&request(), &RouteRequest::default())
                .await
                .unwrap_err();
            if status == 429 && backend != "ollama" {
                // These nonstream adapters discard rate-limit bodies without collecting them.
                assert!(matches!(
                    error,
                    hf_core::provider::ProviderError::RateLimited { .. }
                ));
            } else {
                assert!(
                    error.to_string().contains("response body exceeds"),
                    "{backend}/{status}: {error}"
                );
            }
            let calls = if status == 429 && backend != "ollama" {
                4
            } else {
                2
            };
            assert_eq!(fixture.calls.load(Ordering::SeqCst), calls);
            assert_eq!(pool.provider_statuses().await[0].active_requests, 0);
        }
    }
}

#[tokio::test]
async fn default_error_budget_rejects_oversized_chunked_body_without_retries() {
    let fixture = server(500, vec![vec![b'x'; 65537]]).await;
    let cfg: ProviderPoolConfig = serde_json::from_value(serde_json::json!({
        "providers": [{"id":"fixture", "provider_type":"openai", "model":"fixture",
                       "api_key":"fixture", "base_url":fixture.url}]
    }))
    .unwrap();
    let pool = ProviderPoolImpl::from_config(&cfg).unwrap();
    let error = pool
        .chat_completion(&request(), &RouteRequest::default())
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("response body exceeds"));
    assert!(error.to_string().len() < 100);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn embedding_rejects_oversized_default_error_body() {
    let fixture = server(500, vec![vec![b'x'; 65537]]).await;
    let embedding = OpenAiEmbedding::new(&fixture.url, "fixture", "fixture", 2);
    let error = embedding.embed("hello").await.unwrap_err();
    assert!(error.to_string().contains("response body exceeds"));
    assert!(error.to_string().len() < 100);
}

#[test]
fn body_budget_configuration_rejects_zero_excess_and_unknown_fields() {
    for limits in [
        serde_json::json!({"success_bytes":0}),
        serde_json::json!({"error_bytes":0}),
        serde_json::json!({"success_bytes":268_435_457}),
        serde_json::json!({"error_bytes":1_048_577}),
        serde_json::json!({"success_byte":32}),
    ] {
        assert!(serde_json::from_value::<ProviderPoolConfig>(
            serde_json::json!({"response_body_limits": limits})
        )
        .is_err());
    }
    let _: ProviderPoolConfig = serde_json::from_value(
        serde_json::json!({"response_body_limits":{"success_bytes":1,"error_bytes":1}}),
    )
    .unwrap();
}

#[tokio::test]
async fn body_decoding_preserves_split_utf8_bom_and_declared_charset() {
    for (chunks, content_type, expected) in [
        (
            vec![vec![0xef, 0xbb], vec![0xbf, 0xe4, 0xbd], vec![0xa0]],
            "text/plain",
            "你",
        ),
        (vec![vec![0xe9]], "text/plain; charset=windows-1252", "é"),
        (vec![vec![0xff]], "text/plain", "�"),
    ] {
        let size = chunks.iter().map(Vec::len).sum();
        let fixture = server_with_type(401, chunks, content_type).await;
        let pool =
            ProviderPoolImpl::from_config(&config(&fixture.url, "openai", 1024, size)).unwrap();
        let error = pool
            .chat_completion(&request(), &RouteRequest::default())
            .await
            .unwrap_err();
        assert!(error.to_string().ends_with(expected), "{error}");
    }
}

#[tokio::test]
async fn embedding_custom_budgets_bound_success_and_error_bodies() {
    let body = br#"{"data":[{"embedding":[0.1,0.2],"index":0}]}"#;
    let fixture = server(200, vec![body.to_vec()]).await;
    let limits = hf_core::provider::ResponseBodyLimitsConfig {
        success_bytes: body.len(),
        error_bytes: 8,
    }
    .resolve()
    .unwrap();
    let embedding = OpenAiEmbedding::new(&fixture.url, "fixture", "fixture", 2)
        .with_response_body_limits(limits);
    assert_eq!(
        embedding.embed("hello").await.unwrap().vector,
        vec![0.1, 0.2]
    );
    let limits = hf_core::provider::ResponseBodyLimitsConfig {
        success_bytes: body.len() - 1,
        error_bytes: 8,
    }
    .resolve()
    .unwrap();
    let embedding = OpenAiEmbedding::new(&fixture.url, "fixture", "fixture", 2)
        .with_response_body_limits(limits);
    assert!(matches!(
        embedding.embed("hello").await,
        Err(hf_core::embedding::EmbeddingError::ResponseBodyLimitExceeded { .. })
    ));
    let fixture = server(401, vec![vec![b'x'; 9]]).await;
    let embedding = OpenAiEmbedding::new(&fixture.url, "fixture", "fixture", 2)
        .with_response_body_limits(limits);
    assert!(matches!(
        embedding.embed("hello").await,
        Err(hf_core::embedding::EmbeddingError::ResponseBodyLimitExceeded { .. })
    ));
}

#[tokio::test]
async fn image_responses_use_body_budget_in_both_request_modes() {
    use futures::StreamExt;
    let body = br#"{"data":[{"b64_json":"aW1hZ2U="}]}"#;
    for backend in ["openai", "azure"] {
        let fixture = server(200, vec![body.to_vec()]).await;
        let pool =
            ProviderPoolImpl::from_config(&config(&fixture.url, backend, body.len(), 64)).unwrap();
        let mut req = request();
        req.request_mode = hf_core::provider::RequestMode::ImageGeneration;
        assert_eq!(
            pool.chat_completion(&req, &RouteRequest::default())
                .await
                .unwrap()
                .generated_images
                .len(),
            1
        );
        let mut stream = pool
            .chat_completion_stream(&req, &RouteRequest::default())
            .await
            .unwrap()
            .stream;
        while let Some(item) = stream.next().await {
            item.unwrap();
        }
        let pool =
            ProviderPoolImpl::from_config(&config(&fixture.url, backend, body.len() - 1, 64))
                .unwrap();
        assert!(matches!(
            pool.chat_completion(&req, &RouteRequest::default()).await,
            Err(hf_core::provider::ProviderError::ResponseBodyLimitExceeded { .. })
        ));
        assert!(matches!(
            pool.chat_completion_stream(&req, &RouteRequest::default())
                .await,
            Err(hf_core::provider::ProviderError::ResponseBodyLimitExceeded { .. })
        ));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 4);
    }
}

#[test]
fn programmatic_invalid_budgets_fail_at_adapter_construction() {
    let mut cfg = config("http://127.0.0.1:1", "openai", 10, 10);
    cfg.response_body_limits.success_bytes = 0;
    assert!(hf_provider::build_providers(&cfg).is_err());
}
