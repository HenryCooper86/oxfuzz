use std::sync::atomic::Ordering;

use futures::StreamExt;
use hf_core::provider::{ChatRequest, ProviderPool, RouteRequest};
use hf_provider::{ProviderPoolConfig, ProviderPoolImpl};

mod common;
use common::server;

fn config(
    url: &str,
    backend: &str,
    wire: usize,
    decoded: usize,
    frame: usize,
) -> ProviderPoolConfig {
    serde_json::from_value(serde_json::json!({
        "response_stream_limits": {"wire_bytes":wire, "decoded_bytes":decoded, "frame_bytes":frame},
        "max_global_concurrency": 1,
        "providers": [{"id":"fixture", "provider_type":backend, "model":"fixture",
                       "api_key":"fixture", "base_url":url, "max_concurrency":1}]
    }))
    .unwrap()
}

fn request() -> ChatRequest {
    ChatRequest::from_messages(vec![hf_core::types::Message::user("hello")])
}

fn text_frame(backend: &str) -> &'static str {
    match backend {
        "anthropic" => "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
        "gemini" => "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hello\"}],\"role\":\"model\"}}]}\n\n",
        "ollama" => "{\"message\":{\"role\":\"assistant\",\"content\":\"hello\"},\"done\":false}\n",
        _ => "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\n",
    }
}

#[test]
fn stream_config_accepts_finite_budgets_and_rejects_invalid_fields() {
    let _ = config("http://127.0.0.1:1", "openai", 1, 1, 1);
    for limits in [
        serde_json::json!({"wire_bytes":0}),
        serde_json::json!({"decoded_bytes":0}),
        serde_json::json!({"frame_bytes":0}),
        serde_json::json!({"wire_bytes":268_435_457}),
        serde_json::json!({"decoded_bytes":805_306_369}),
        serde_json::json!({"frame_bytes":268_435_457}),
        serde_json::json!({"frame_byte":32}),
    ] {
        assert!(serde_json::from_value::<ProviderPoolConfig>(
            serde_json::json!({"response_stream_limits":limits})
        )
        .is_err());
    }
}

#[tokio::test]
async fn every_pool_adapter_enforces_each_stream_budget_at_the_receiver() {
    for backend in ["openai", "anthropic", "azure", "gemini", "ollama"] {
        let body = text_frame(backend).as_bytes();
        let fixture = server(200, vec![body[..17].to_vec(), body[17..].to_vec()]).await;
        let pool = ProviderPoolImpl::from_config(&config(
            &fixture.url,
            backend,
            body.len(),
            body.len(),
            body.len(),
        ))
        .unwrap();
        let chunks: Vec<_> = pool
            .chat_completion_stream(&request(), &RouteRequest::default())
            .await
            .unwrap()
            .stream
            .collect()
            .await;
        assert_eq!(chunks.len(), 1, "{backend}");
        assert_eq!(
            chunks[0].as_ref().unwrap().delta_content.as_deref(),
            Some("hello")
        );
        for (wire, decoded, frame) in [
            (body.len() - 1, body.len(), body.len()),
            (body.len(), body.len() - 1, body.len()),
            (body.len(), body.len(), body.len() - 1),
        ] {
            let pool =
                ProviderPoolImpl::from_config(&config(&fixture.url, backend, wire, decoded, frame))
                    .unwrap();
            let mut stream = pool
                .chat_completion_stream(&request(), &RouteRequest::default())
                .await
                .unwrap()
                .stream;
            let error = stream.next().await.unwrap().expect_err("limit must fail");
            assert!(
                error.to_string().starts_with("response stream"),
                "{backend}: {error}"
            );
            assert!(error.to_string().len() < 100);
            assert!(stream.next().await.is_none(), "only one terminal error");
            let status = &pool.provider_statuses().await[0];
            assert_eq!(status.active_requests, 0);
            assert_eq!(status.total_requests, 1);
            assert_eq!(status.total_errors, 1);
            assert!(!status.is_frozen);
            let response = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                pool.chat_completion_stream(&request(), &RouteRequest::default()),
            )
            .await
            .unwrap()
            .unwrap();
            drop(response);
            assert_eq!(pool.provider_statuses().await[0].active_requests, 0);
        }
        assert_eq!(
            fixture.calls.load(Ordering::SeqCst),
            7,
            "stream failures do not retry"
        );
    }
}

#[tokio::test]
async fn coalesced_frames_have_independent_frame_limits_and_cumulative_stream_limits() {
    for backend in ["openai", "anthropic", "azure", "gemini", "ollama"] {
        let frame = text_frame(backend);
        let body = frame.repeat(10);
        let fixture = server(200, vec![body.as_bytes().to_vec()]).await;
        let pool = ProviderPoolImpl::from_config(&config(
            &fixture.url,
            backend,
            body.len(),
            body.len(),
            frame.len(),
        ))
        .unwrap();
        let chunks: Vec<_> = pool
            .chat_completion_stream(&request(), &RouteRequest::default())
            .await
            .unwrap()
            .stream
            .collect()
            .await;
        assert_eq!(chunks.len(), 10, "{backend}");
        assert!(chunks
            .into_iter()
            .all(|chunk| chunk.unwrap().delta_content.as_deref() == Some("hello")));
        let pool = ProviderPoolImpl::from_config(&config(
            &fixture.url,
            backend,
            body.len() - 1,
            body.len(),
            frame.len(),
        ))
        .unwrap();
        let chunks: Vec<_> = pool
            .chat_completion_stream(&request(), &RouteRequest::default())
            .await
            .unwrap()
            .stream
            .collect()
            .await;
        assert_eq!(chunks.iter().filter(|c| c.is_err()).count(), 1, "{backend}");
        assert_eq!(pool.provider_statuses().await[0].total_errors, 1);
    }
}

#[tokio::test]
async fn clean_eof_releases_pool_permits_even_when_stream_is_retained() {
    let fixture = server(200, vec![text_frame("openai").as_bytes().to_vec()]).await;
    let pool =
        ProviderPoolImpl::from_config(&config(&fixture.url, "openai", 1024, 1024, 1024)).unwrap();
    let mut stream = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream;
    assert!(stream.next().await.unwrap().is_ok());
    assert!(stream.next().await.is_none());
    let status = &pool.provider_statuses().await[0];
    assert_eq!(status.active_requests, 0);
    assert_eq!(status.total_requests, 1);
    assert_eq!(status.total_errors, 0);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        pool.chat_completion_stream(&request(), &RouteRequest::default()),
    )
    .await
    .unwrap()
    .unwrap();
    drop(response);
}

#[tokio::test]
async fn repeated_argument_deltas_fail_without_flushing_incomplete_tool_calls() {
    for backend in ["openai", "azure", "anthropic"] {
        let (start, delta, stop) = if backend == "anthropic" {
            ("event: content_block_start\ndata: {\"content_block\":{\"type\":\"tool_use\",\"id\":\"call\",\"name\":\"tool\",\"input\":{}}}\n\n",
             "event: content_block_delta\ndata: {\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"xxxxxxxxxx\"}}\n\n",
             "event: content_block_stop\ndata: {}\n\nevent: message_stop\ndata: {}\n\n")
        } else {
            ("data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call\",\"function\":{\"name\":\"tool\",\"arguments\":\"\"}}]}}]}\n\n",
             "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"xxxxxxxxxx\"}}]}}]}\n\n",
             "data: [DONE]\n\n")
        };
        let body = format!("{start}{}{stop}", delta.repeat(10));
        let fixture = server(200, vec![body.as_bytes().to_vec()]).await;
        let pool = ProviderPoolImpl::from_config(&config(
            &fixture.url,
            backend,
            body.len(),
            start.len() + delta.len() * 3,
            start.len().max(delta.len()),
        ))
        .unwrap();
        let items: Vec<_> = pool
            .chat_completion_stream(&request(), &RouteRequest::default())
            .await
            .unwrap()
            .stream
            .collect()
            .await;
        assert_eq!(
            items.len(),
            1,
            "{backend}: no incomplete tools after violation"
        );
        assert!(items[0]
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("decoded_bytes"));
        assert_eq!(pool.provider_statuses().await[0].total_errors, 1);
    }
}

#[tokio::test]
async fn repeated_thinking_deltas_are_provisional_until_stream_completes() {
    let delta = "event: content_block_delta\ndata: {\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"think\"}}\n\n";
    let body = delta.repeat(10);
    let fixture = server(200, vec![body.as_bytes().to_vec()]).await;
    let pool = ProviderPoolImpl::from_config(&config(
        &fixture.url,
        "anthropic",
        body.len(),
        delta.len() * 3,
        delta.len(),
    ))
    .unwrap();
    let items: Vec<_> = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream
        .collect()
        .await;
    assert_eq!(items.len(), 4);
    for item in &items[..3] {
        assert_eq!(
            item.as_ref().unwrap().delta_reasoning_content.as_deref(),
            Some("think")
        );
    }
    assert!(items[3].is_err());
    assert_eq!(pool.provider_statuses().await[0].total_errors, 1);
}

#[tokio::test]
async fn gemini_image_frames_use_the_configured_frame_allowance() {
    let body = b"data: {\"candidates\":[{\"content\":{\"parts\":[{\"inlineData\":{\"mimeType\":\"image/png\",\"data\":\"aW1hZ2U=\"}}],\"role\":\"model\"}}]}\n\n";
    let fixture = server(200, vec![body.to_vec()]).await;
    let pool = ProviderPoolImpl::from_config(&config(
        &fixture.url,
        "gemini",
        body.len(),
        body.len(),
        body.len(),
    ))
    .unwrap();
    let items: Vec<_> = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream
        .collect()
        .await;
    assert_eq!(items[0].as_ref().unwrap().delta_images.len(), 1);
    let pool = ProviderPoolImpl::from_config(&config(
        &fixture.url,
        "gemini",
        body.len(),
        body.len(),
        body.len() - 1,
    ))
    .unwrap();
    let items: Vec<_> = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream
        .collect()
        .await;
    assert_eq!(items.len(), 1);
    assert!(items[0]
        .as_ref()
        .unwrap_err()
        .to_string()
        .contains("frame_bytes"));
}

#[test]
fn typed_invalid_stream_budget_fails_before_provider_construction() {
    let mut cfg = config("http://127.0.0.1:1", "openai", 10, 10, 10);
    cfg.response_stream_limits.wire_bytes = 0;
    assert!(hf_provider::build_providers(&cfg).is_err());
}
