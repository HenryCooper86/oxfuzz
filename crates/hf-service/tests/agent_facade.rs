//! The presentation-facing chat entry point is owned by `hf-service`.

use std::sync::Arc;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderPool,
    RouteRequest,
};
use hf_core::types::TokenUsage;
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
            usage: TokenUsage::default(),
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
                display_message: None,
            },
            &sink,
        )
        .await
        .unwrap();

    assert_eq!(answer, "service facade works");
}

#[tokio::test]
async fn run_chat_turn_rejects_an_unknown_persistent_session() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("chat.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(AnswerPool)),
    )
    .with_store(store);
    let sink = CollectingSink::new();

    let result = container
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: None,
                session: Some(hf_core::types::SessionId::from_string("../outside")),
                history_fallback: Vec::new(),
                message: "hello".to_owned(),
                display_message: None,
            },
            &sink,
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn run_chat_turn_persists_messages_and_checkpoint_before_success() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("durable-chat.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(AnswerPool)),
    )
    .with_store(store);
    let session_id = container
        .create_chat_session(Some("Durable".to_owned()))
        .await
        .unwrap()
        .unwrap();
    let session_id = hf_core::types::SessionId::from_string(session_id);
    let sink = CollectingSink::new();

    let answer = container
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: None,
                session: Some(session_id.clone()),
                history_fallback: Vec::new(),
                message: "[Plan mode] internal instruction\n\nhello".to_owned(),
                display_message: Some("hello".to_owned()),
            },
            &sink,
        )
        .await
        .unwrap();

    assert_eq!(answer, "service facade works");
    let history = container.chat_history(&session_id).await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].content, "hello");
    assert_eq!(history[1].content, "service facade works");
    assert_eq!(
        container.chat_checkpoints(&session_id).await.unwrap().len(),
        1
    );

    container.chat_rollback_last(&session_id).await.unwrap();
    container
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: None,
                session: Some(session_id.clone()),
                history_fallback: Vec::new(),
                message: "replacement".to_owned(),
                display_message: Some("replacement".to_owned()),
            },
            &CollectingSink::new(),
        )
        .await
        .unwrap();
    let checkpoints = container.chat_checkpoints(&session_id).await.unwrap();
    assert_eq!(checkpoints.len(), 1);
    assert_eq!(checkpoints[0].turn_number, 2);
}

#[tokio::test]
async fn run_chat_turn_rolls_back_transcripts_when_checkpoint_save_fails() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("failed-checkpoint.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(AnswerPool)),
    )
    .with_store(store.clone());
    let session_id = container
        .create_chat_session(Some("Checkpoint failure".to_owned()))
        .await
        .unwrap()
        .unwrap();
    let session_id = hf_core::types::SessionId::from_string(session_id);
    sqlx::query(
        "CREATE TRIGGER reject_chat_checkpoints BEFORE INSERT ON chat_checkpoints \
         BEGIN SELECT RAISE(FAIL, 'injected checkpoint failure'); END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let result = container
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: None,
                session: Some(session_id.clone()),
                history_fallback: Vec::new(),
                message: "do not retain this turn".to_owned(),
                display_message: Some("do not retain this turn".to_owned()),
            },
            &CollectingSink::new(),
        )
        .await;

    assert!(result.is_err());
    let manager = container.session_manager().unwrap();
    assert!(manager
        .read_transcript(&session_id)
        .await
        .unwrap()
        .is_empty());
    assert!(manager
        .read_display_transcript(&session_id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        manager
            .get_session(&session_id)
            .await
            .unwrap()
            .message_count,
        0
    );
}
