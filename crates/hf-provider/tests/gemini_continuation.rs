use futures::StreamExt as _;
use hf_core::provider::{ChatRequest, ProviderPool, RouteRequest};
use hf_core::types::Message;
use hf_provider::{ProviderPoolConfig, ProviderPoolImpl};
use serde_json::{json, Value};

mod common;
use common::server;

fn pool(url: &str) -> ProviderPoolImpl {
    let config: ProviderPoolConfig = serde_json::from_value(json!({
        "providers": [{"id":"fixture", "provider_type":"gemini", "model":"fixture",
                       "api_key":"fixture", "base_url":url, "max_concurrency":1}]
    }))
    .unwrap();
    ProviderPoolImpl::from_config(&config).unwrap()
}

fn original_parts() -> Vec<Value> {
    vec![
        json!({"text":"Considering files", "thought":true, "thoughtSignature":"signed-thought"}),
        json!({"text":"Reading both files"}),
        json!({"functionCall":{"id":"provider-a", "name":"read", "args":{"path":"a"}},
               "thoughtSignature":"signed-first-call"}),
        json!({"functionCall":{"id":"provider-b", "name":"read", "args":{"path":"b"}}}),
        json!({"text":"", "thoughtSignature":"signed-empty-tail"}),
    ]
}

fn response(parts: &[Value], finished: bool) -> Value {
    let mut body = json!({
        "candidates":[{"content":{"role":"model", "parts":parts}}],
        "usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1}
    });
    if finished {
        body["candidates"][0]["finishReason"] = json!("STOP");
    }
    body
}

fn request() -> ChatRequest {
    ChatRequest::from_messages(vec![Message::user("Read both files")])
}

fn persisted_followup(assistant: &Message) -> ChatRequest {
    let stored = serde_json::to_vec(assistant).unwrap();
    let assistant: Message = serde_json::from_slice(&stored).unwrap();
    let first = assistant.tool_calls[0].id.clone();
    let second = assistant.tool_calls[1].id.clone();
    ChatRequest::from_messages(vec![
        Message::user("Read both files"),
        assistant,
        Message::tool("file b", second),
        Message::tool("file a", first),
    ])
}

async fn assert_original_parts_replayed(assistant: &Message) {
    let fixture = server(
        200,
        vec![response(&[json!({"text":"done"})], true)
            .to_string()
            .into_bytes()],
    )
    .await;
    let result = pool(&fixture.url)
        .chat_completion(&persisted_followup(assistant), &RouteRequest::default())
        .await
        .unwrap();
    let sent = result.raw_request.unwrap();
    assert_eq!(sent["contents"][1]["parts"], json!(original_parts()));
    assert_eq!(
        sent["contents"][2]["parts"][0]["functionResponse"]["response"],
        json!({"result":"file a"})
    );
    assert_eq!(
        sent["contents"][2]["parts"][1]["functionResponse"]["response"],
        json!({"result":"file b"})
    );
    assert_eq!(
        sent["contents"][2]["parts"][0]["functionResponse"]["id"],
        "provider-a"
    );
    assert_eq!(
        sent["contents"][2]["parts"][1]["functionResponse"]["id"],
        "provider-b"
    );
}

#[tokio::test]
async fn gemini_native_continuation_survives_nonstream_message_persistence() {
    let fixture = server(
        200,
        vec![response(&original_parts(), true).to_string().into_bytes()],
    )
    .await;
    let result = pool(&fixture.url)
        .chat_completion(&request(), &RouteRequest::default())
        .await
        .unwrap();
    let mut assistant = Message::assistant(result.text());
    assistant.tool_calls = result.tool_calls;

    assert_original_parts_replayed(&assistant).await;
}

#[tokio::test]
async fn gemini_native_continuation_survives_split_stream_message_persistence() {
    let parts = original_parts();
    let frames = [
        format!("data: {}\n\n", response(&parts[..2], false)).into_bytes(),
        format!("data: {}\n\n", response(&parts[2..4], false)).into_bytes(),
        format!("data: {}\n\n", response(&parts[4..], true)).into_bytes(),
    ];
    let fixture = server(200, frames.to_vec()).await;
    let pool = pool(&fixture.url);
    let mut stream = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream;
    let mut assistant = Message::assistant("");
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        if let Some(text) = chunk.delta_content {
            assistant.content.push_str(&text);
        }
        assistant.tool_calls.extend(chunk.delta_tool_calls);
    }
    assert_eq!(assistant.tool_calls.len(), 2);

    assert_original_parts_replayed(&assistant).await;
}

#[tokio::test]
async fn gemini_native_continuation_rejects_changed_calls_before_transport() {
    use std::sync::atomic::Ordering;

    let fixture = server(
        200,
        vec![response(&original_parts(), true).to_string().into_bytes()],
    )
    .await;
    let pool = pool(&fixture.url);
    let result = pool
        .chat_completion(&request(), &RouteRequest::default())
        .await
        .unwrap();
    let mut assistant = Message::assistant(result.text());
    assistant.tool_calls = result.tool_calls;
    assistant.tool_calls[0].arguments = json!({"path":"changed"});

    let result = pool
        .chat_completion(&persisted_followup(&assistant), &RouteRequest::default())
        .await;

    assert!(
        result.is_err(),
        "changed calls cannot reuse original signatures"
    );
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gemini_native_continuation_does_not_publish_unfinished_stream_calls() {
    let body = format!("data: {}\n\n", response(&original_parts(), false));
    let fixture = server(200, vec![body.into_bytes()]).await;
    let pool = pool(&fixture.url);
    let chunks: Vec<_> = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream
        .collect()
        .await;

    assert!(
        chunks.iter().any(Result::is_err),
        "missing finish reason must fail"
    );
    assert!(chunks
        .into_iter()
        .filter_map(Result::ok)
        .all(|chunk| chunk.delta_tool_calls.is_empty()));
}

#[tokio::test]
async fn gemini_native_continuation_parse_error_is_terminal() {
    let frames = vec![
        format!("data: {}\n\n", response(&original_parts(), false)).into_bytes(),
        b"data: not-json\n\n".to_vec(),
        format!("data: {}\n\n", response(&[], true)).into_bytes(),
    ];
    let fixture = server(200, frames).await;
    let pool = pool(&fixture.url);
    let chunks: Vec<_> = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream
        .collect()
        .await;

    let error_index = chunks.iter().position(Result::is_err).unwrap();
    assert_eq!(
        error_index + 1,
        chunks.len(),
        "no events after a parse error"
    );
    assert!(chunks
        .into_iter()
        .filter_map(Result::ok)
        .all(|chunk| chunk.delta_tool_calls.is_empty()));
}

#[tokio::test]
async fn gemini_native_continuation_rejects_unsuccessful_finish_reasons() {
    for reason in ["MAX_TOKENS", "SAFETY", "MALFORMED_FUNCTION_CALL"] {
        let mut body = response(&original_parts(), true);
        body["candidates"][0]["finishReason"] = json!(reason);
        let fixture = server(200, vec![format!("data: {body}\n\n").into_bytes()]).await;
        let pool = pool(&fixture.url);
        let chunks: Vec<_> = pool
            .chat_completion_stream(&request(), &RouteRequest::default())
            .await
            .unwrap()
            .stream
            .collect()
            .await;

        assert!(chunks.iter().any(Result::is_err), "{reason}");
        assert!(
            chunks
                .into_iter()
                .filter_map(Result::ok)
                .all(|chunk| chunk.delta_tool_calls.is_empty()),
            "{reason}"
        );
    }
}

#[tokio::test]
async fn gemini_native_continuation_rejects_unsuccessful_nonstream_calls() {
    for reason in ["MAX_TOKENS", "SAFETY", "MALFORMED_FUNCTION_CALL"] {
        let mut body = response(&original_parts(), true);
        body["candidates"][0]["finishReason"] = json!(reason);
        let fixture = server(200, vec![body.to_string().into_bytes()]).await;
        let result = pool(&fixture.url)
            .chat_completion(&request(), &RouteRequest::default())
            .await;

        assert!(
            result.is_err(),
            "incomplete calls cannot be published: {reason}"
        );
    }
}

#[tokio::test]
async fn gemini_native_continuation_rejects_inconsistent_persisted_records() {
    use hf_core::provider::ProviderError;
    use std::sync::atomic::Ordering;

    let fixture = server(
        200,
        vec![response(&original_parts(), true).to_string().into_bytes()],
    )
    .await;
    let result = pool(&fixture.url)
        .chat_completion(&request(), &RouteRequest::default())
        .await
        .unwrap();
    let mut assistant = Message::assistant(result.text());
    assistant.tool_calls = result.tool_calls;
    assert!(assistant.tool_calls[1].provider_metadata.is_none());
    let original = serde_json::to_value(assistant).unwrap();
    let record = original["tool_calls"][0]["provider_metadata"].clone();
    let mut malformed = original.clone();
    malformed["tool_calls"][0]["provider_metadata"]["gemini"] = Value::Null;
    let mut duplicate = original.clone();
    duplicate["tool_calls"][1]["provider_metadata"] = record.clone();
    let mut misplaced = original.clone();
    misplaced["tool_calls"][0]["provider_metadata"] = Value::Null;
    misplaced["tool_calls"][1]["provider_metadata"] = record;
    let mut unknown_version = original.clone();
    unknown_version["tool_calls"][0]["provider_metadata"]["gemini"]["version"] = json!(2);
    let mut changed_id = original.clone();
    changed_id["tool_calls"][0]["id"] = json!("different-id");
    let mut changed_name = original.clone();
    changed_name["tool_calls"][0]["name"] = json!("other_function");
    let mut changed_text = original;
    changed_text["content"] = json!("changed text");

    for altered in [
        malformed,
        duplicate,
        misplaced,
        unknown_version,
        changed_id,
        changed_name,
        changed_text,
    ] {
        let assistant = serde_json::from_value(altered).unwrap();
        let result = pool(&fixture.url)
            .chat_completion(&persisted_followup(&assistant), &RouteRequest::default())
            .await;
        assert!(matches!(result, Err(ProviderError::ParseError { .. })));
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn gemini_native_continuation_preserves_each_sequential_turn() {
    let first_parts = original_parts();
    let first_fixture = server(
        200,
        vec![response(&first_parts, true).to_string().into_bytes()],
    )
    .await;
    let first = pool(&first_fixture.url)
        .chat_completion(&request(), &RouteRequest::default())
        .await
        .unwrap();
    let mut assistant = Message::assistant(first.text());
    assistant.tool_calls = first.tool_calls;
    let mut followup = persisted_followup(&assistant);
    let mut second_parts = original_parts();
    second_parts[2]["thoughtSignature"] = json!("signed-second-step");
    let second_fixture = server(
        200,
        vec![response(&second_parts, true).to_string().into_bytes()],
    )
    .await;
    let second = pool(&second_fixture.url)
        .chat_completion(&followup, &RouteRequest::default())
        .await
        .unwrap();
    let mut assistant = Message::assistant(second.text());
    assistant.tool_calls = second.tool_calls;
    let persisted = persisted_followup(&assistant);
    followup
        .messages
        .extend(persisted.messages.into_iter().skip(1));
    let final_fixture = server(
        200,
        vec![response(&[json!({"text":"done"})], true)
            .to_string()
            .into_bytes()],
    )
    .await;

    let result = pool(&final_fixture.url)
        .chat_completion(&followup, &RouteRequest::default())
        .await
        .unwrap();

    let sent = result.raw_request.unwrap();
    assert_eq!(sent["contents"][1]["parts"], json!(first_parts));
    assert_eq!(sent["contents"][3]["parts"], json!(second_parts));
}

#[tokio::test]
async fn gemini_native_continuation_resource_failure_discards_pending_calls() {
    use hf_core::provider::{ProviderError, ResponseStreamBudget};

    let first = format!("data: {}\n\n", response(&original_parts(), false)).into_bytes();
    let size = first.len();
    let fixture = server(200, vec![first, vec![b'x'; size + 1]]).await;
    let config: ProviderPoolConfig = serde_json::from_value(json!({
        "response_stream_limits":{"frame_bytes":size, "wire_bytes":size*3, "decoded_bytes":size*3},
        "providers":[{"id":"fixture", "provider_type":"gemini", "model":"fixture",
                      "api_key":"fixture", "base_url":fixture.url, "max_concurrency":1}]
    }))
    .unwrap();
    let pool = ProviderPoolImpl::from_config(&config).unwrap();
    let chunks: Vec<_> = pool
        .chat_completion_stream(&request(), &RouteRequest::default())
        .await
        .unwrap()
        .stream
        .collect()
        .await;

    assert!(chunks.iter().any(|chunk| matches!(
        chunk,
        Err(ProviderError::ResponseStreamLimitExceeded {
            budget: ResponseStreamBudget::Frame,
            ..
        })
    )));
    assert!(chunks
        .into_iter()
        .filter_map(Result::ok)
        .all(|chunk| chunk.delta_tool_calls.is_empty()));
}
