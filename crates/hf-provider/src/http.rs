//! HTTP sender abstraction for testability.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use serde_json::Value;

/// A trait for sending POST JSON requests, so the provider can be tested
/// without hitting the network.
#[async_trait]
pub trait HttpSender: Send + Sync {
    /// POST JSON to `url` and return the JSON response body.
    async fn post_json(&self, url: &str, body: Value) -> Result<Value, ClassifiedError>;
}

/// A `reqwest`-backed HTTP sender for production use.
pub struct ReqwestSender {
    client: reqwest::Client,
}

impl ReqwestSender {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for ReqwestSender {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpSender for ReqwestSender {
    async fn post_json(&self, url: &str, body: Value) -> Result<Value, ClassifiedError> {
        let resp = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("http: {e}")))?;
        let status = resp.status();
        let json: Value = resp
            .json()
            .await
            .map_err(|e| ClassifiedError::Provider(format!("decode: {e}")))?;
        if !status.is_success() {
            return Err(ClassifiedError::Provider(format!("http {status}: {json}")));
        }
        Ok(json)
    }
}
