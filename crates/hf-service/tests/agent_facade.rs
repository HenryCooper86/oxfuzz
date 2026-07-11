//! The presentation-facing chat entry point is owned by `hf-service`.

use std::sync::Arc;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderPool,
    RouteRequest,
};
use hf_service::{AgentTurnRequest, CollectingSink, ServiceContainer};

struct AnswerPool;

#[async_trait::async_trait]
impl ProviderPool for AnswerPool {
    async fn chat_completion(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        Ok(ChatResponse {
            id: "service-agent".to_owned(),
            model: "scripted".to_owned(),
            content: Some(r#"{"final":"service facade works"}"#.to_owned()),
            reasoning_content: None,
            tool_calls: Vec::new(),
            usage: Default::default(),
            finish_reason: FinishReason::Stop,
            raw_request: None,
            raw_response: None,
            provider_id: None,
            generated_images: Vec::new(),
        })
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "unused".to_owned(),
        })
    }

    fn report_error(&self, _provider_id: &hf_core::types::ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &hf_core::types::ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[tokio::test]
async fn run_chat_turn_is_available_through_service() {
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(AnswerPool)),
    );
    let sink = CollectingSink::new();
    let answer = container
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: None,
                session: None,
                history_fallback: Vec::new(),
                message: "hello".to_owned(),
            },
            &sink,
        )
        .await
        .unwrap();

    assert_eq!(answer, "service facade works");
}
