//! OpenAI-compatible chat completions provider.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::provider::{LlmProvider, LlmResponse};
use hf_core::types::{Message, Role, TokenUsage};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::http::HttpSender;

/// Configuration for one OpenAI-compatible provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub id: String,
    pub model: String,
    pub api_key: String,
    pub base_url: String,
    pub tags: Vec<String>,
    pub max_concurrency: u32,
    pub context_window: u64,
}

/// An OpenAI-compatible provider that calls `/chat/completions`.
pub struct OpenAiCompatProvider {
    cfg: ProviderConfig,
    sender: Arc<dyn HttpSender>,
}

impl OpenAiCompatProvider {
    #[must_use]
    pub fn new(cfg: ProviderConfig) -> Self {
        Self {
            cfg,
            sender: Arc::new(crate::http::ReqwestSender::new()),
        }
    }

    /// Construct with a custom HTTP sender (for testing).
    #[must_use]
    pub fn with_sender(cfg: ProviderConfig, sender: Arc<dyn HttpSender>) -> Self {
        Self { cfg, sender }
    }

    fn url(&self) -> String {
        format!(
            "{}/chat/completions",
            self.cfg.base_url.trim_end_matches('/')
        )
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    fn id(&self) -> &str {
        &self.cfg.id
    }

    async fn complete(&self, messages: Vec<Message>) -> Result<LlmResponse, ClassifiedError> {
        let body = serde_json::json!({
            "model": self.cfg.model,
            "messages": messages.iter().map(|m| {
                serde_json::json!({
                    "role": role_str(m.role),
                    "content": m.content,
                })
            }).collect::<Vec<_>>(),
        });
        let resp = self
            .sender
            .post_json(&self.url(), &self.cfg.api_key, body)
            .await?;
        let parsed: ChatResponse = serde_json::from_value(resp)
            .map_err(|e| ClassifiedError::Provider(format!("parse: {e}")))?;
        let choice = parsed
            .choices
            .first()
            .ok_or_else(|| ClassifiedError::Provider("no choices in response".to_owned()))?;
        Ok(LlmResponse {
            content: choice.message.content.clone(),
            usage: TokenUsage {
                prompt_tokens: parsed.usage.prompt_tokens,
                completion_tokens: parsed.usage.completion_tokens,
                total_tokens: parsed.usage.total_tokens,
            },
            model: self.cfg.model.clone(),
        })
    }

    async fn stream(
        &self,
        _messages: Vec<Message>,
    ) -> Result<
        Box<dyn futures::Stream<Item = Result<String, ClassifiedError>> + Send + Unpin>,
        ClassifiedError,
    > {
        Err(ClassifiedError::Provider(
            "streaming not implemented".to_owned(),
        ))
    }
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatResponse {
    choices: Vec<Choice>,
    usage: Usage,
}

#[derive(Debug, Deserialize, Serialize)]
struct Choice {
    message: ChatMessage,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChatMessage {
    content: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Usage {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
}
