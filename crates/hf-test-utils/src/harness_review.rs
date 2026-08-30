//! Provider-pool fixture for execution tests that need a positive independent
//! harness review without exercising an external model.

use std::sync::Arc;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, ProviderError, ProviderPool, ProviderStatus,
    RouteRequest,
};
use hf_core::types::ProviderId;

struct ApprovingHarnessReviewPool;

#[async_trait::async_trait]
impl ProviderPool for ApprovingHarnessReviewPool {
    async fn chat_completion(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        Ok(approving_harness_review_response())
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "streaming is not used by the harness review fixture".to_owned(),
        })
    }

    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// Return a provider pool that approves the strict pre-execution review JSON.
#[must_use]
pub fn approving_harness_review_pool() -> Arc<dyn ProviderPool> {
    Arc::new(ApprovingHarnessReviewPool)
}

/// Whether a model request is the strict pre-execution review rather than a
/// draft, repair, or seed-generation request.
#[must_use]
pub fn is_harness_review_request(request: &ChatRequest) -> bool {
    request
        .messages
        .last()
        .is_some_and(|message| message.content.contains("pre-execution harness reviewer"))
}

/// Return the canonical positive response for a test harness review.
#[must_use]
pub fn approving_harness_review_response() -> ChatResponse {
    crate::fixtures::make_chat_response(
        r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["test harness passes independent review"]}"#,
    )
}
