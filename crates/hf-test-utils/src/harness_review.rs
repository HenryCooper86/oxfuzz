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

/// Answers a non-review harness prompt: called with the zero-based index of
/// that prompt among all non-review prompts and its text.
pub type HarnessAnswer = dyn Fn(usize, &str) -> String + Send + Sync;

/// A provider pool for harness pipeline tests: approves every pre-execution
/// review, answers every other prompt (draft, repair, refine, seeds) through
/// a test-supplied function, and records the text of every prompt it served.
pub struct RecordingHarnessPool {
    prompts: std::sync::Mutex<Vec<String>>,
    answer: Box<HarnessAnswer>,
}

impl RecordingHarnessPool {
    /// A pool answering non-review prompts with `answer`.
    #[must_use]
    pub fn new(answer: impl Fn(usize, &str) -> String + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            prompts: std::sync::Mutex::new(Vec::new()),
            answer: Box::new(answer),
        })
    }

    /// Every prompt served so far, in order, including review prompts.
    ///
    /// # Panics
    /// Panics if a previous holder of the prompt lock panicked.
    #[must_use]
    pub fn prompts(&self) -> Vec<String> {
        self.prompts.lock().expect("prompt lock").clone()
    }

    /// The served prompts that contain `needle`.
    #[must_use]
    pub fn prompts_containing(&self, needle: &str) -> Vec<String> {
        self.prompts()
            .into_iter()
            .filter(|prompt| prompt.contains(needle))
            .collect()
    }
}

#[async_trait::async_trait]
impl ProviderPool for RecordingHarnessPool {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        let prompt = request
            .messages
            .last()
            .map(|message| message.content.clone())
            .unwrap_or_default();
        let review = is_harness_review_request(request);
        let mut prompts = self.prompts.lock().expect("prompt lock");
        let index = prompts
            .iter()
            .filter(|seen| !seen.contains("pre-execution harness reviewer"))
            .count();
        prompts.push(prompt.clone());
        drop(prompts);
        if review {
            return Ok(approving_harness_review_response());
        }
        Ok(crate::fixtures::make_chat_response(&(self.answer)(
            index, &prompt,
        )))
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "streaming is not used by the harness pipeline fixture".to_owned(),
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
