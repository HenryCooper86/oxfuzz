//! Ollama provider backend.
//!
//! Implements the Ollama REST API format with:
//! - `/api/chat` endpoint for chat completions
//! - Streaming JSON responses (one JSON object per line)
//! - No API key required (local provider)
//! - Tool calling support via Ollama's function calling

use async_trait::async_trait;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::instrument;

use std::collections::VecDeque;

use crate::config::HttpProtocol;
use crate::inter_stream::InterStreamEvent;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, LlmProvider, ProviderCapability,
    ProviderError, ProviderMetadata, ProviderType, RequestMode, ToolCallingMode,
};
use hf_core::types::ToolCallRequest;
use hf_core::types::{ProviderId, TokenUsage};

const OLLAMA_DEFAULT_URL: &str = "http://localhost:11434";

/// Normalize a configured Ollama base URL to the host root the native
/// `/api/*` endpoints hang off.
///
/// Ollama exposes its native API at `<host>/api/chat`, but its OpenAI-compatible
/// surface (and therefore most GUIs and copy-pasted docs) advertises `<host>/v1`.
/// Users routinely paste the `/v1` form into an Ollama provider entry, which would
/// otherwise resolve to the invalid `<host>/v1/api/chat`. Strip a trailing `/v1`
/// (and any trailing slash) so both forms land on the correct native endpoint.
fn normalize_base_url(base_url: Option<String>) -> String {
    let raw = base_url.unwrap_or_else(|| OLLAMA_DEFAULT_URL.to_string());
    let trimmed = raw.trim_end_matches('/');
    let normalized = trimmed.strip_suffix("/v1").unwrap_or(trimmed);
    if normalized.is_empty() {
        OLLAMA_DEFAULT_URL.to_string()
    } else {
        normalized.to_string()
    }
}

/// Ollama local LLM provider.
#[derive(Debug)]
pub struct OllamaProvider {
    client: Client,
    base_url: String,
    custom_headers: reqwest::header::HeaderMap,
    metadata: ProviderMetadata,
}

impl OllamaProvider {
    /// Create a new Ollama provider.
    ///
    /// Ollama runs locally so no API key is needed. The `api_key` argument
    /// is accepted for interface consistency but ignored.
    pub fn new(
        id: &str,
        model: &str,
        api_key: String,
        base_url: Option<String>,
        proxy_url: Option<String>,
        tags: Vec<String>,
        capabilities: Vec<ProviderCapability>,
        max_concurrency: usize,
        context_window: usize,
        tool_calling_mode: ToolCallingMode,
    ) -> Self {
        let headers = std::collections::HashMap::new();
        Self::with_headers(
            id,
            model,
            api_key,
            base_url,
            proxy_url,
            tags,
            capabilities,
            max_concurrency,
            context_window,
            tool_calling_mode,
            &headers,
            HttpProtocol::Http1,
        )
    }

    /// Create a new Ollama provider with additional HTTP headers.
    pub fn with_headers<S: std::hash::BuildHasher>(
        id: &str,
        model: &str,
        api_key: String,
        base_url: Option<String>,
        proxy_url: Option<String>,
        tags: Vec<String>,
        capabilities: Vec<ProviderCapability>,
        max_concurrency: usize,
        context_window: usize,
        tool_calling_mode: ToolCallingMode,
        headers: &std::collections::HashMap<String, String, S>,
        http_protocol: HttpProtocol,
    ) -> Self {
        let base_url = normalize_base_url(base_url);

        // Ollama Cloud (and any authenticated endpoint) uses a bearer token; the
        // local server needs none. Attach `Authorization: Bearer <key>` only when
        // a key is set, and never clobber an Authorization header the operator
        // supplied explicitly via custom headers.
        let mut effective_headers: std::collections::HashMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let has_auth = effective_headers
            .keys()
            .any(|k| k.eq_ignore_ascii_case("authorization"));
        // Turn the key into a bearer header value, consuming it; an empty key
        // (local Ollama) yields no header.
        let bearer = Some(api_key)
            .filter(|k| !k.trim().is_empty())
            .map(|k| format!("Bearer {}", k.trim()));
        if let (false, Some(value)) = (has_auth, bearer) {
            effective_headers.insert("Authorization".to_string(), value);
        }
        let custom_headers = crate::http_headers::custom_header_map(&effective_headers)
            .unwrap_or_else(|message| {
                tracing::warn!(provider_id = %id, error = %message, "Ignoring invalid provider custom headers");
                reqwest::header::HeaderMap::default()
            });

        // Ollama is typically local, but proxy is still applied if configured.
        // Operators should set `enabled = false` in proxy config to bypass.
        let client = crate::http_headers::provider_http_client(http_protocol, proxy_url)
            .unwrap_or_else(|_| Client::new());

        Self {
            client,
            base_url,
            custom_headers,
            metadata: ProviderMetadata {
                id: ProviderId::from_string(id),
                provider_type: ProviderType::Ollama,
                model: model.to_string(),
                tags,
                capabilities,
                max_concurrency,
                context_window,
                cost_per_1k_input: 0.0,
                cost_per_1k_output: 0.0,
                tool_calling_mode,
            },
        }
    }

    /// Build the full API URL for a given endpoint.
    fn api_url(&self, endpoint: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), endpoint)
    }

    /// Build Ollama messages from `ChatRequest`.
    fn build_messages(request: &ChatRequest) -> Vec<OllamaMessage> {
        request
            .messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    hf_core::types::Role::User => "user",
                    hf_core::types::Role::Assistant => "assistant",
                    hf_core::types::Role::System => "system",
                    hf_core::types::Role::Tool => "tool",
                };
                OllamaMessage {
                    role: role.to_string(),
                    content: m.content.clone(),
                    tool_calls: None,
                }
            })
            .collect()
    }

    /// Build Ollama tool definitions.
    fn build_tools(request: &ChatRequest) -> Option<Vec<OllamaTool>> {
        use hf_core::provider::ToolCallingMode;

        // PromptBased mode: never send tool definitions to the provider.
        if request.tool_calling_mode == ToolCallingMode::PromptBased {
            return None;
        }

        if request.tools.is_empty() {
            return None;
        }

        let tools: Vec<OllamaTool> = request
            .tools
            .iter()
            .filter_map(|t| {
                let func = t.get("function")?;
                Some(OllamaTool {
                    r#type: "function".into(),
                    function: OllamaFunction {
                        name: func.get("name")?.as_str()?.to_string(),
                        description: func
                            .get("description")
                            .and_then(|d| d.as_str())
                            .map(String::from)
                            .unwrap_or_default(),
                        parameters: func
                            .get("parameters")
                            .cloned()
                            .unwrap_or(serde_json::json!({"type": "object", "properties": {}})),
                    },
                })
            })
            .collect();

        if tools.is_empty() {
            None
        } else {
            Some(tools)
        }
    }

    /// Build the Ollama request body.
    fn build_request_body(&self, request: &ChatRequest, stream: bool) -> OllamaRequest {
        let model = request
            .model
            .as_deref()
            .unwrap_or(&self.metadata.model)
            .to_string();

        let options = OllamaOptions {
            temperature: request.temperature,
            top_p: request.top_p,
            num_predict: request.max_tokens.map(i64::from),
            stop: if request.stop.is_empty() {
                None
            } else {
                Some(request.stop.clone())
            },
        };

        OllamaRequest {
            model,
            messages: Self::build_messages(request),
            stream,
            tools: Self::build_tools(request),
            options: Some(options),
        }
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    #[instrument(skip(self, request), fields(model = %self.metadata.model, provider_id = %self.metadata.id))]
    async fn chat_completion(&self, request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        if request.request_mode == RequestMode::ImageGeneration {
            return Err(ProviderError::Other {
                message: "dedicated image generation is not implemented for ollama providers"
                    .into(),
            });
        }

        let body = self.build_request_body(request, false);
        let raw_request = serde_json::to_value(&body).ok();

        let request_builder = self.client.post(self.api_url("api/chat"));
        let response =
            crate::http_headers::apply_custom_headers(request_builder, &self.custom_headers)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| ProviderError::NetworkError {
                    message: format!("Ollama connection error (is Ollama running?): {e}"),
                })?;

        let status = response.status();

        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(crate::error_classifier::http_failure_to_provider_error(
                &self.metadata.id.to_string(),
                status.as_u16(),
                &error_body,
            ));
        }

        let response_text = response.text().await.map_err(|e| ProviderError::Other {
            message: format!("read response body: {e}"),
        })?;
        let raw_response: serde_json::Value =
            serde_json::from_str(&response_text).map_err(|e| ProviderError::Other {
                message: format!("parse response JSON: {e}"),
            })?;

        let ollama_response: OllamaResponse = serde_json::from_value(raw_response.clone())
            .map_err(|e| ProviderError::Other {
                message: format!("parse response: {e}"),
            })?;

        let content = if ollama_response.message.content.is_empty() {
            None
        } else {
            Some(ollama_response.message.content)
        };

        let tool_calls = ollama_response
            .message
            .tool_calls
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(i, tc)| ToolCallRequest {
                id: format!("call_{i}"),
                name: tc.function.name,
                arguments: tc.function.arguments,
            })
            .collect::<Vec<_>>();

        let finish_reason = if ollama_response.done {
            if tool_calls.is_empty() {
                match ollama_response.done_reason.as_deref() {
                    Some("length") => FinishReason::Length,
                    _ => FinishReason::Stop,
                }
            } else {
                FinishReason::ToolUse
            }
        } else {
            FinishReason::Unknown
        };

        // Ollama reports token counts.
        let usage = TokenUsage {
            input_tokens: ollama_response.prompt_eval_count.unwrap_or(0),
            output_tokens: ollama_response.eval_count.unwrap_or(0),
            cache_read_tokens: None,
            cache_write_tokens: None,
            ..Default::default()
        };

        Ok(ChatResponse {
            id: String::new(),
            model: ollama_response.model,
            content,
            reasoning_content: None,
            tool_calls,
            usage,
            finish_reason,
            raw_request,
            raw_response: Some(raw_response),
            provider_id: None,
            generated_images: vec![],
        })
    }

    #[instrument(skip(self, request), fields(model = %self.metadata.model, provider_id = %self.metadata.id))]
    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        if request.request_mode == RequestMode::ImageGeneration {
            return Err(ProviderError::Other {
                message: "dedicated image generation is not implemented for ollama providers"
                    .into(),
            });
        }

        let body = self.build_request_body(request, true);
        let raw_request = serde_json::to_value(&body).ok();

        let request_builder = self.client.post(self.api_url("api/chat"));
        let response =
            crate::http_headers::apply_custom_headers(request_builder, &self.custom_headers)
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| ProviderError::NetworkError {
                    message: format!("Ollama connection error (is Ollama running?): {e}"),
                })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(crate::error_classifier::http_failure_to_provider_error(
                &self.metadata.id.to_string(),
                status.as_u16(),
                &error_body,
            ));
        }

        let byte_stream = response.bytes_stream();
        let inter_stream = futures::stream::unfold(
            (
                crate::sse::SseStreamState::new(Box::pin(byte_stream)),
                VecDeque::<InterStreamEvent>::new(),
                0_usize, // monotonic tool-call index for stable ids across chunks
            ),
            move |mut composite| async move {
                let (ref mut state, ref mut pending, ref mut tool_index) = composite;

                if let Some(event) = pending.pop_front() {
                    return Some((Ok(event), composite));
                }

                if state.done {
                    return None;
                }

                loop {
                    if let Some(line) = crate::sse::extract_json_line(&mut state.buffer) {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        match serde_json::from_str::<OllamaStreamChunk>(trimmed) {
                            Ok(chunk) => {
                                // Emit any tool calls carried by this chunk. Ollama
                                // sends fully-formed tool calls (not deltas), often
                                // in the terminal `done: true` chunk, so this must
                                // run before the done/content handling below. Ids
                                // use a monotonic index so calls spanning chunks
                                // stay unique.
                                for tc in chunk.message.tool_calls.unwrap_or_default() {
                                    pending.push_back(InterStreamEvent::ToolCall(
                                        ToolCallRequest {
                                            id: format!("call_{tool_index}"),
                                            name: tc.function.name,
                                            arguments: tc.function.arguments,
                                        },
                                    ));
                                    *tool_index += 1;
                                }

                                if !chunk.message.content.is_empty() {
                                    pending.push_back(InterStreamEvent::TextDelta(
                                        chunk.message.content,
                                    ));
                                }

                                if chunk.done {
                                    state.done = true;
                                    let usage = TokenUsage {
                                        input_tokens: chunk.prompt_eval_count.unwrap_or(0),
                                        output_tokens: chunk.eval_count.unwrap_or(0),
                                        cache_read_tokens: None,
                                        cache_write_tokens: None,
                                        ..Default::default()
                                    };
                                    // If any tool call was emitted, report ToolUse
                                    // (mirrors the non-stream path); otherwise map
                                    // done_reason so a truncated ("length") reply is
                                    // distinguishable from a natural stop.
                                    let finish_reason = if *tool_index > 0 {
                                        FinishReason::ToolUse
                                    } else if chunk.done_reason.as_deref() == Some("length") {
                                        FinishReason::Length
                                    } else {
                                        FinishReason::Stop
                                    };
                                    pending.push_back(InterStreamEvent::Usage(usage));
                                    pending.push_back(InterStreamEvent::Finished(finish_reason));
                                }

                                if let Some(event) = pending.pop_front() {
                                    return Some((Ok(event), composite));
                                }
                                continue;
                            }
                            Err(e) => {
                                return Some((
                                    Err(ProviderError::ParseError {
                                        message: format!(
                                            "Ollama JSON parse error: {e}, line: {trimmed}"
                                        ),
                                    }),
                                    composite,
                                ));
                            }
                        }
                    }

                    match state.read_next().await {
                        Ok(true) => {}
                        Ok(false) => return None,
                        Err(e) => return Some((Err(e), composite)),
                    }
                }
            },
        );

        Ok(ChatStreamResponse {
            stream: crate::inter_stream_adapter::into_chat_stream(Box::pin(inter_stream)),
            raw_request,
            provider_id: None,
            model: String::new(),
            context_window: 0,
        })
    }

    fn metadata(&self) -> &ProviderMetadata {
        &self.metadata
    }
}

// (SSE state and extract_json_line are now in crate::sse)

// ---------------------------------------------------------------------------
// Ollama API types (internal)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct OllamaRequest {
    model: String,
    messages: Vec<OllamaMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<Vec<OllamaTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaMessage {
    role: String,
    content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaToolCall {
    function: OllamaToolCallFunction,
}

#[derive(Debug, Serialize, Deserialize)]
struct OllamaToolCallFunction {
    name: String,
    arguments: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OllamaTool {
    r#type: String,
    function: OllamaFunction,
}

#[derive(Debug, Serialize)]
struct OllamaFunction {
    name: String,
    description: String,
    parameters: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    top_p: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stop: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    model: String,
    message: OllamaMessage,
    done: bool,
    done_reason: Option<String>,
    prompt_eval_count: Option<u32>,
    eval_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OllamaStreamChunk {
    #[allow(dead_code)]
    model: Option<String>,
    message: OllamaStreamMessage,
    done: bool,
    /// Why generation stopped (`"length"` on a token/context cap). Mapped to
    /// `FinishReason::Length` like the non-streaming path so a caller can tell a
    /// truncated reply from a natural stop.
    #[serde(default)]
    done_reason: Option<String>,
    prompt_eval_count: Option<u32>,
    eval_count: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct OllamaStreamMessage {
    #[allow(dead_code)]
    role: Option<String>,
    #[serde(default)]
    content: String,
    /// Tool calls carried by a streamed chunk. Ollama sends fully-formed tool
    /// calls (not incremental deltas), matching the non-stream [`OllamaMessage`].
    #[serde(default)]
    tool_calls: Option<Vec<OllamaToolCall>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sse::extract_json_line;
    use hf_core::provider::ToolCallingMode;

    #[test]
    fn test_ollama_provider_metadata() {
        let provider = OllamaProvider::new(
            "ollama-local",
            "llama3.1:8b",
            String::new(), // No API key needed.
            None,
            None,
            vec!["local".into(), "fast".into(), "free".into()],
            vec![],
            3,
            32_768,
            ToolCallingMode::default(),
        );

        let meta = provider.metadata();
        assert_eq!(meta.id, ProviderId::from_string("ollama-local"));
        assert_eq!(meta.model, "llama3.1:8b");
        assert_eq!(meta.provider_type, ProviderType::Ollama);
        assert_eq!(meta.tags, vec!["local", "fast", "free"]);
        // Local provider has zero cost.
        assert!(meta.cost_per_1k_input.abs() < f64::EPSILON);
        assert!(meta.cost_per_1k_output.abs() < f64::EPSILON);
    }

    #[test]
    fn test_ollama_api_url() {
        let provider = OllamaProvider::new(
            "test",
            "llama3",
            String::new(),
            None,
            None,
            vec![],
            vec![],
            3,
            32_768,
            ToolCallingMode::default(),
        );
        assert_eq!(
            provider.api_url("api/chat"),
            "http://localhost:11434/api/chat"
        );
    }

    #[test]
    fn test_ollama_custom_base_url() {
        let provider = OllamaProvider::new(
            "test",
            "llama3",
            String::new(),
            Some("http://192.168.1.100:11434".into()),
            None,
            vec![],
            vec![],
            3,
            32_768,
            ToolCallingMode::default(),
        );
        assert_eq!(
            provider.api_url("api/chat"),
            "http://192.168.1.100:11434/api/chat"
        );
    }

    #[test]
    fn test_ollama_base_url_strips_v1_suffix() {
        // The GUI and Ollama's own docs surface the OpenAI-compatible base URL
        // (`.../v1`). The native provider appends `/api/chat`, so a `/v1` suffix
        // would yield the invalid `.../v1/api/chat`. Normalize it away so both
        // `http://localhost:11434` and `http://localhost:11434/v1` work.
        for base in [
            "http://localhost:11434/v1",
            "http://localhost:11434/v1/",
            "http://localhost:11434/",
        ] {
            let provider = OllamaProvider::new(
                "test",
                "llama3",
                String::new(),
                Some(base.into()),
                None,
                vec![],
                vec![],
                3,
                32_768,
                ToolCallingMode::default(),
            );
            assert_eq!(
                provider.api_url("api/chat"),
                "http://localhost:11434/api/chat",
                "base {base} should normalize to the native /api/chat endpoint",
            );
        }
    }

    #[test]
    fn test_ollama_cloud_sets_bearer_auth_header() {
        // Ollama Cloud (https://ollama.com) authenticates with a bearer token,
        // unlike the keyless local server. A configured API key must ride on the
        // Authorization header of every request.
        let provider = OllamaProvider::new(
            "ollama-cloud",
            "gpt-oss:120b",
            "sk-secret".to_string(),
            Some("https://ollama.com".into()),
            None,
            vec![],
            vec![],
            3,
            32_768,
            ToolCallingMode::default(),
        );
        let auth = provider
            .custom_headers
            .get(reqwest::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        assert_eq!(auth, Some("Bearer sk-secret"));
        assert_eq!(provider.api_url("api/chat"), "https://ollama.com/api/chat");
    }

    #[test]
    fn test_ollama_local_has_no_auth_header() {
        // Local Ollama needs no key; we must not fabricate an Authorization header.
        let provider = OllamaProvider::new(
            "ollama-local",
            "llama3",
            String::new(),
            None,
            None,
            vec![],
            vec![],
            3,
            32_768,
            ToolCallingMode::default(),
        );
        assert!(provider
            .custom_headers
            .get(reqwest::header::AUTHORIZATION)
            .is_none());
    }

    #[test]
    fn test_ollama_request_serialization() {
        let req = OllamaRequest {
            model: "llama3.1:8b".into(),
            messages: vec![OllamaMessage {
                role: "user".into(),
                content: "Hello".into(),
                tool_calls: None,
            }],
            stream: false,
            tools: None,
            options: Some(OllamaOptions {
                temperature: Some(0.7),
                top_p: None,
                num_predict: Some(100),
                stop: None,
            }),
        };

        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["model"], "llama3.1:8b");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"][0]["content"], "Hello");
        assert!(!json["stream"].as_bool().unwrap());
        let temp = json["options"]["temperature"].as_f64().unwrap();
        assert!(
            (temp - 0.7).abs() < 0.001,
            "temperature should be ~0.7, got {temp}"
        );
        assert_eq!(json["options"]["num_predict"], 100);
    }

    #[test]
    fn test_ollama_response_deserialization() {
        let json = serde_json::json!({
            "model": "llama3.1:8b",
            "message": {
                "role": "assistant",
                "content": "Hello!"
            },
            "done": true,
            "done_reason": "stop",
            "prompt_eval_count": 10,
            "eval_count": 5
        });

        let response: OllamaResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(response.model, "llama3.1:8b");
        assert_eq!(response.message.content, "Hello!");
        assert!(response.done);
        assert_eq!(response.prompt_eval_count, Some(10));
        assert_eq!(response.eval_count, Some(5));
    }

    #[test]
    fn test_ollama_stream_chunk_deserialization() {
        let json = serde_json::json!({
            "model": "llama3.1:8b",
            "message": {"role": "assistant", "content": "Hi"},
            "done": false
        });

        let chunk: OllamaStreamChunk = serde_json::from_value(json).expect("deserialize");
        assert_eq!(chunk.message.content, "Hi");
        assert!(!chunk.done);
    }

    #[test]
    fn test_ollama_extract_json_line() {
        let mut buffer = String::from("{\"done\": false, \"message\": {\"content\": \"hi\"}}\n");
        let line = extract_json_line(&mut buffer);
        assert!(line.is_some());
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_ollama_extract_json_line_incomplete() {
        let mut buffer = String::from("{\"done\": false, \"message\": {\"cont");
        let line = extract_json_line(&mut buffer);
        assert!(line.is_none());
        assert!(buffer.contains("cont"));
    }

    #[test]
    fn test_ollama_response_with_tool_calls() {
        let json = serde_json::json!({
            "model": "llama3.1:8b",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "get_weather",
                        "arguments": {"location": "Tokyo"}
                    }
                }]
            },
            "done": true,
            "done_reason": "stop",
            "prompt_eval_count": 20,
            "eval_count": 15
        });

        let response: OllamaResponse = serde_json::from_value(json).expect("deserialize");
        assert!(response.message.tool_calls.is_some());
        let tool_calls = response.message.tool_calls.unwrap();
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].function.name, "get_weather");
    }

    /// A streamed chunk carrying tool calls must deserialize into
    /// `OllamaStreamChunk`. Regression test for `OllamaStreamMessage` lacking a
    /// `tool_calls` field, which silently dropped streamed Ollama tool calls.
    #[test]
    fn test_ollama_stream_chunk_with_tool_calls() {
        // Ollama typically delivers tool calls in the terminal done=true chunk.
        let json = serde_json::json!({
            "model": "llama3.1:8b",
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "function": {
                        "name": "get_weather",
                        "arguments": {"location": "Tokyo"}
                    }
                }]
            },
            "done": true,
            "prompt_eval_count": 20,
            "eval_count": 15
        });

        let chunk: OllamaStreamChunk = serde_json::from_value(json).expect("deserialize");
        assert!(chunk.done);
        assert_eq!(chunk.message.content, "");
        let tool_calls = chunk.message.tool_calls.expect("tool_calls present");
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].function.name, "get_weather");
        assert_eq!(tool_calls[0].function.arguments["location"], "Tokyo");
    }

    #[test]
    fn test_ollama_build_messages() {
        use hf_core::types::{Message, Role};

        let request = ChatRequest {
            messages: vec![
                Message {
                    message_id: String::new(),
                    role: Role::System,
                    content: "Be helpful".into(),
                    tool_call_id: None,
                    tool_calls: vec![],
                    timestamp: hf_core::types::now(),
                    metadata: serde_json::Value::Null,
                },
                Message {
                    message_id: String::new(),
                    role: Role::User,
                    content: "Hello".into(),
                    tool_call_id: None,
                    tool_calls: vec![],
                    timestamp: hf_core::types::now(),
                    metadata: serde_json::Value::Null,
                },
            ],
            model: None,
            request_mode: RequestMode::TextChat,
            max_tokens: None,
            temperature: None,
            top_p: None,
            tools: vec![],
            tool_calling_mode: ToolCallingMode::default(),
            stop: vec![],
            extra: serde_json::Value::Null,
            thinking: None,
            response_format: None,
            image_generation_options: None,
        };

        let messages = OllamaProvider::build_messages(&request);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].role, "system");
        assert_eq!(messages[1].role, "user");
    }
}
