//! The presentation-facing chat entry point is owned by `hf-service`.

use std::sync::Arc;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderPool,
    RouteRequest,
};
use hf_core::types::TokenUsage;
use hf_service::{AgentTurnRequest, CollectingSink, ServiceContainer};

#[derive(Default)]
struct AnswerPool {
    requests: std::sync::Mutex<Vec<ChatRequest>>,
    store: Option<Arc<hf_storage::Store>>,
}

#[async_trait::async_trait]
impl ProviderPool for AnswerPool {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        if let Some(store) = &self.store {
            let instruction: String = sqlx::query_scalar(
                "SELECT instruction FROM chat_turn_languages ORDER BY rowid DESC LIMIT 1",
            )
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert!(request.messages[0].content.contains(&instruction));
        }
        self.requests.lock().unwrap().push(request.clone());
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
        Some(Arc::new(AnswerPool::default())),
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
                response_language: None,
                display_message: None,
                provider: None,
                turn_id: None,
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
        Some(Arc::new(AnswerPool::default())),
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
                response_language: None,
                display_message: None,
                provider: None,
                turn_id: None,
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
        Some(Arc::new(AnswerPool::default())),
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
                response_language: None,
                display_message: Some("hello".to_owned()),
                provider: None,
                turn_id: None,
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
                response_language: None,
                display_message: Some("replacement".to_owned()),
                provider: None,
                turn_id: None,
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
        Some(Arc::new(AnswerPool::default())),
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
                response_language: None,
                display_message: Some("do not retain this turn".to_owned()),
                provider: None,
                turn_id: None,
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

#[tokio::test]
async fn chat_language_is_in_the_system_message_and_persisted_turn() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("language.db"))
            .await
            .unwrap(),
    );
    let pool = Arc::new(AnswerPool {
        store: Some(store.clone()),
        ..AnswerPool::default()
    });
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), Some(pool.clone()))
        .with_store(store.clone());
    let session = hf_core::types::SessionId::from_string(
        container.create_chat_session(None).await.unwrap().unwrap(),
    );
    for (index, language, code, instruction, input) in [
        (0, None, "en", "Reply in English", "请解释模糊测试。"),
        (
            1,
            Some(hf_service::ChatResponseLanguage::Chinese),
            "zh",
            "Reply in Simplified Chinese",
            "Explain fuzzing.",
        ),
        (
            2,
            Some(hf_service::ChatResponseLanguage::English),
            "en",
            "Reply in English",
            "请继续。",
        ),
    ] {
        container
            .run_chat_turn(
                AgentTurnRequest {
                    project: None,
                    agent_id: None,
                    session: Some(session.clone()),
                    history_fallback: Vec::new(),
                    message: input.into(),
                    response_language: language,
                    display_message: None,
                    provider: None,
                    turn_id: None,
                },
                &CollectingSink::new(),
            )
            .await
            .unwrap();
        {
            let requests = pool.requests.lock().unwrap();
            assert!(requests[index].messages[0].content.contains(instruction));
            assert_eq!(requests[index].messages.last().unwrap().content, input);
        }
        let history = container.chat_history(&session).await.unwrap();
        assert_eq!(history[index * 2].metadata["response_language"], code);
        assert!(history[index * 2].metadata["response_language_instruction"]
            .as_str()
            .unwrap()
            .contains(instruction));
        assert_eq!(history[index * 2].content, input);
    }
    container.chat_rollback_last(&session).await.unwrap();
    let history = container.chat_history(&session).await.unwrap();
    assert_eq!(history.len(), 4);
    assert_eq!(history[2].metadata["response_language"], "zh");
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_turn_languages")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(retained, 3, "rollback retains attempted model inputs");
    container.delete_chat_session(&session).await.unwrap();
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat_turn_languages")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(retained, 0, "session deletion removes its language records");
}

#[tokio::test]
async fn chat_does_not_contact_a_provider_when_language_evidence_cannot_be_saved() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("failed-language.db"))
            .await
            .unwrap(),
    );
    let pool = Arc::new(AnswerPool::default());
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), Some(pool.clone()))
        .with_store(store.clone());
    sqlx::query("DROP TABLE chat_turn_languages")
        .execute(store.pool())
        .await
        .unwrap();
    let result = container
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: None,
                session: None,
                history_fallback: Vec::new(),
                message: "hello".into(),
                response_language: None,
                display_message: None,
                provider: None,
                turn_id: None,
            },
            &CollectingSink::new(),
        )
        .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("retain chat language"));
    assert!(pool.requests.lock().unwrap().is_empty());
}
