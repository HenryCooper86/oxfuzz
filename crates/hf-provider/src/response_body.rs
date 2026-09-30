//! Bounded HTTP body collection shared by chat, image and embedding adapters.

use hf_core::provider::{ProviderError, ResponseBodyLimits};

pub(crate) async fn read_bytes(
    mut response: reqwest::Response,
    limits: ResponseBodyLimits,
) -> Result<Vec<u8>, ProviderError> {
    let limit_bytes = if response.status().is_success() {
        limits.success_bytes()
    } else {
        limits.error_bytes()
    };
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ProviderError::NetworkError {
            message: format!("read response body: {error}"),
        })?
    {
        if chunk.len() > limit_bytes - body.len() {
            return Err(ProviderError::ResponseBodyLimitExceeded { limit_bytes });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) async fn read_text(
    response: reqwest::Response,
    limits: ResponseBodyLimits,
) -> Result<String, ProviderError> {
    // Invalid Content-Type or unknown charset retains reqwest's UTF-8 fallback.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok());
    let label = content_type
        .as_ref()
        .and_then(|value| value.get_param("charset"))
        .map_or("utf-8", |value| value.as_str());
    let encoding = encoding_rs::Encoding::for_label(label.as_bytes()).unwrap_or(encoding_rs::UTF_8);
    let body = read_bytes(response, limits).await?;
    let (text, _, _) = encoding.decode(&body);
    Ok(text.into_owned())
}

pub(crate) fn resolve_default_limits() -> ResponseBodyLimits {
    hf_core::provider::ResponseBodyLimitsConfig::default()
        .resolve()
        .expect("default response body budgets are valid")
}
