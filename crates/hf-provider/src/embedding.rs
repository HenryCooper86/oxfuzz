//! `OpenAI`-compatible embedding provider.
//!
//! Implements [`hf_core::embedding::EmbeddingProvider`] against any endpoint
//! that speaks the `OpenAI` `POST /embeddings` shape. Because the base URL is
//! configurable, the same client covers `OpenAI`, Azure, LM Studio, and Ollama
//! (via its OpenAI-compatible `/v1` endpoint) with no extra dependencies. Chat
//! and embeddings are deliberately separate traits, so this does not touch the
//! `LlmProvider` pool.

use async_trait::async_trait;
use hf_core::embedding::{EmbeddingError, EmbeddingProvider, EmbeddingResult};
use serde::{Deserialize, Serialize};

/// An embedding provider that calls an `OpenAI`-compatible `/embeddings` API.
#[derive(Debug, Clone)]
pub struct OpenAiEmbedding {
    client: reqwest::Client,
    /// Base URL up to and including the API version (e.g.
    /// `https://api.openai.com/v1`), without a trailing `/embeddings`.
    base_url: String,
    api_key: String,
    model: String,
    dimensions: usize,
}

impl OpenAiEmbedding {
    /// Build a provider for `model` at `base_url` (its trailing slash is
    /// trimmed). `api_key` may be empty for a keyless local endpoint.
    #[must_use]
    pub fn new(base_url: &str, api_key: &str, model: &str, dimensions: usize) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_owned(),
            api_key: api_key.to_owned(),
            model: model.to_owned(),
            dimensions,
        }
    }

    fn endpoint(&self) -> String {
        format!("{}/embeddings", self.base_url)
    }
}

#[derive(Serialize)]
struct EmbeddingRequest<'a> {
    model: &'a str,
    input: &'a [String],
}

#[derive(Deserialize)]
struct EmbeddingResponse {
    #[serde(default)]
    data: Vec<EmbeddingData>,
    #[serde(default)]
    usage: Option<EmbeddingUsage>,
}

#[derive(Deserialize)]
struct EmbeddingData {
    #[serde(default)]
    embedding: Vec<f32>,
    #[serde(default)]
    index: usize,
}

#[derive(Deserialize)]
struct EmbeddingUsage {
    #[serde(default)]
    prompt_tokens: u32,
}

#[async_trait]
impl EmbeddingProvider for OpenAiEmbedding {
    async fn embed(&self, text: &str) -> Result<EmbeddingResult, EmbeddingError> {
        let batch = self
            .embed_batch(std::slice::from_ref(&text.to_owned()))
            .await?;
        batch
            .into_iter()
            .next()
            .ok_or_else(|| EmbeddingError::ProviderError {
                message: "embedding response was empty".to_owned(),
            })
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<EmbeddingResult>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let body = EmbeddingRequest {
            model: &self.model,
            input: texts,
        };
        let mut request = self.client.post(self.endpoint()).json(&body);
        if !self.api_key.is_empty() {
            request = request.bearer_auth(&self.api_key);
        }
        let response = request
            .send()
            .await
            .map_err(|e| EmbeddingError::ProviderError {
                message: format!("embedding request failed: {e}"),
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(EmbeddingError::ProviderError {
                message: format!("embedding API returned {status}: {}", body.trim()),
            });
        }
        let parsed: EmbeddingResponse =
            response
                .json()
                .await
                .map_err(|e| EmbeddingError::ProviderError {
                    message: format!("decode embedding response: {e}"),
                })?;
        // The API preserves input order via `index`; sort defensively so a
        // reordering proxy cannot misalign vectors with their source chunks.
        let mut data = parsed.data;
        data.sort_by_key(|d| d.index);
        if data.len() != texts.len() {
            return Err(EmbeddingError::ProviderError {
                message: format!(
                    "embedding count mismatch: requested {}, got {}",
                    texts.len(),
                    data.len()
                ),
            });
        }
        let token_count = parsed.usage.map_or(0, |u| u.prompt_tokens);
        Ok(data
            .into_iter()
            .map(|d| EmbeddingResult {
                dimensions: d.embedding.len(),
                vector: d.embedding,
                model: self.model.clone(),
                token_count,
            })
            .collect())
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_trims_trailing_slash() {
        let p = OpenAiEmbedding::new("https://api.openai.com/v1/", "k", "m", 1536);
        assert_eq!(p.endpoint(), "https://api.openai.com/v1/embeddings");
    }

    #[test]
    fn response_deserializes_and_sorts_by_index() {
        let json = r#"{
            "data": [
                {"embedding": [0.4, 0.5], "index": 1},
                {"embedding": [0.1, 0.2], "index": 0}
            ],
            "usage": {"prompt_tokens": 7}
        }"#;
        let parsed: EmbeddingResponse = serde_json::from_str(json).unwrap();
        let mut data = parsed.data;
        data.sort_by_key(|d| d.index);
        assert_eq!(data[0].embedding, vec![0.1, 0.2]);
        assert_eq!(data[1].embedding, vec![0.4, 0.5]);
        assert_eq!(parsed.usage.unwrap().prompt_tokens, 7);
    }

    #[test]
    fn metadata_accessors() {
        let p = OpenAiEmbedding::new("http://localhost:11434/v1", "", "nomic-embed-text", 768);
        assert_eq!(p.dimensions(), 768);
        assert_eq!(p.model_name(), "nomic-embed-text");
    }
}
