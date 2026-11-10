//! Operator control over one chat turn: the provider that answers it and
//! cancelling it while it runs.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, LlmProvider, ProviderCapability,
    ProviderError, ProviderMetadata, ProviderPool, ProviderType, RouteRequest, ToolCallingMode,
};
use hf_core::types::{ProviderId, SessionId, TokenUsage};
use hf_service::approval::{
    ApprovalNotifier, Delivery, InteractiveApprovalGate, PendingApprovals, PermissionClosed,
    PermissionRequest,
};
use hf_service::{
    AgentTurnRequest, ClassifiedError, CollectingSink, GuardrailPolicy, Guardrails, NullSink,
    OperationCancelOutcome, ServiceContainer,
};
use uuid::Uuid;

const WAIT: Duration = Duration::from_secs(10);

fn answer(content: &str, provider: Option<&str>) -> ChatResponse {
    ChatResponse {
        id: "scripted".to_owned(),
        model: "scripted-model".to_owned(),
        content: Some(content.to_owned()),
        reasoning_content: None,
        tool_calls: Vec::new(),
        usage: TokenUsage::default(),
        finish_reason: FinishReason::Stop,
        raw_request: None,
        raw_response: None,
        provider_id: provider.map(ProviderId::from_string),
        generated_images: Vec::new(),
    }
}

/// A pool that answers from a script, records every route, and never returns
/// from the call numbered `hang_at` (0-based).
struct ScriptedPool {
    replies: Mutex<VecDeque<String>>,
    routes: Mutex<Vec<RouteRequest>>,
    served_by: Option<&'static str>,
    hang_at: Option<usize>,
    calls: AtomicUsize,
    started: tokio::sync::Notify,
}

impl ScriptedPool {
    fn new(replies: &[&str]) -> Self {
        Self {
            replies: Mutex::new(replies.iter().map(|&reply| reply.to_owned()).collect()),
            routes: Mutex::new(Vec::new()),
            served_by: None,
            hang_at: None,
            calls: AtomicUsize::new(0),
            started: tokio::sync::Notify::new(),
        }
    }

    fn served_by(mut self, provider: &'static str) -> Self {
        self.served_by = Some(provider);
        self
    }

    fn hanging_at(mut self, call: usize) -> Self {
        self.hang_at = Some(call);
        self
    }

    fn routes(&self) -> Vec<RouteRequest> {
        self.routes.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl ProviderPool for ScriptedPool {
    async fn chat_completion(
        &self,
        _request: &ChatRequest,
        route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        self.routes.lock().unwrap().push(route.clone());
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.notify_one();
        if self.hang_at == Some(call) {
            std::future::pending::<()>().await;
        }
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| r#"{"final":"done"}"#.to_owned());
        Ok(answer(&reply, self.served_by))
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

    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// A concrete provider for the production pool that counts its calls.
struct CountingProvider {
    meta: ProviderMetadata,
    calls: Arc<AtomicUsize>,
}

impl CountingProvider {
    fn counted(id: &str) -> (Arc<dyn LlmProvider>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(Self {
            meta: ProviderMetadata {
                id: ProviderId::from_string(id),
                provider_type: ProviderType::OpenAi,
                model: format!("{id}-model"),
                tags: vec!["general".to_owned()],
                capabilities: vec![ProviderCapability::Text],
                max_concurrency: 4,
                context_window: 128_000,
                cost_per_1k_input: 0.0,
                cost_per_1k_output: 0.0,
                tool_calling_mode: ToolCallingMode::PromptBased,
            },
            calls: Arc::clone(&calls),
        });
        (provider, calls)
    }
}

#[async_trait::async_trait]
impl LlmProvider for CountingProvider {
    async fn chat_completion(&self, _request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(answer(r#"{"final":"answered"}"#, None))
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "unused".to_owned(),
        })
    }

    fn metadata(&self) -> &ProviderMetadata {
        &self.meta
    }
}

#[derive(Default)]
struct RecordingNotifier {
    requested: Mutex<Vec<PermissionRequest>>,
    closed: Mutex<Vec<PermissionClosed>>,
    notify: tokio::sync::Notify,
}

impl ApprovalNotifier for RecordingNotifier {
    fn requested(&self, request: &PermissionRequest) -> Delivery {
        self.requested.lock().unwrap().push(request.clone());
        self.notify.notify_one();
        Delivery::Delivered
    }

    fn closed(&self, closed: &PermissionClosed) {
        self.closed.lock().unwrap().push(closed.clone());
    }
}

fn request(message: &str) -> AgentTurnRequest {
    AgentTurnRequest {
        project: None,
        agent_id: None,
        session: None,
        history_fallback: Vec::new(),
        message: message.to_owned(),
        response_language: None,
        display_message: None,
        provider: None,
        turn_id: None,
    }
}

fn container(pool: Arc<dyn ProviderPool>) -> ServiceContainer {
    // Every turn resolves user agents from the config dir; pin it before any
    // turn runs so no test reads the environment while another sets it.
    private_config_dir();
    ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), Some(pool))
}

async fn persistent(
    pool: Arc<dyn ProviderPool>,
) -> (ServiceContainer, SessionId, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("chat.db"))
            .await
            .unwrap(),
    );
    let service = container(pool).with_store(store);
    let session = service
        .create_chat_session(Some("control".to_owned()))
        .await
        .unwrap()
        .unwrap();
    (service, SessionId::from_string(session), dir)
}

/// Point the user agent registry at a private directory once per test binary.
fn private_config_dir() -> &'static std::path::Path {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("HF_CONFIG_DIR", dir.path());
        dir
    })
    .path()
}

fn production_pool(ids: &[&str]) -> (Arc<hf_provider::ProviderPoolImpl>, Vec<Arc<AtomicUsize>>) {
    let mut providers = Vec::new();
    let mut counters = Vec::new();
    for id in ids {
        let (provider, calls) = CountingProvider::counted(id);
        providers.push(provider);
        counters.push(calls);
    }
    let pool = hf_provider::ProviderPoolImpl::from_providers(
        providers,
        &hf_provider::ProviderPoolConfig::default(),
    );
    (Arc::new(pool), counters)
}

// -- Provider selection ------------------------------------------------------

#[tokio::test]
async fn a_selected_provider_is_pinned_on_every_model_call_of_the_turn() {
    // The first step calls a tool (which fails: no project), so the turn makes
    // two model calls; both must carry the pin.
    let pool = Arc::new(ScriptedPool::new(&[
        r#"{"tool":"discover","args":{"lang":"c"}}"#,
        r#"{"final":"pinned"}"#,
    ]));
    let service = container(pool.clone());

    let answer = service
        .run_chat_turn(
            AgentTurnRequest {
                provider: Some(ProviderId::from_string("chosen")),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap();

    assert_eq!(answer, "pinned");
    let routes = pool.routes();
    assert_eq!(routes.len(), 2);
    for route in routes {
        assert_eq!(
            route.pinned_provider_id,
            Some(ProviderId::from_string("chosen"))
        );
    }
}

#[tokio::test]
async fn without_a_selection_the_turn_keeps_default_routing() {
    let pool = Arc::new(ScriptedPool::new(&[r#"{"final":"routed"}"#]));
    let service = container(pool.clone());

    service
        .run_chat_turn(request("hello"), &NullSink)
        .await
        .unwrap();

    assert!(pool
        .routes()
        .iter()
        .all(|route| route.pinned_provider_id.is_none()));
}

#[tokio::test]
async fn an_unregistered_selected_provider_fails_naming_it_and_nothing_else_answers() {
    let (pool, counters) = production_pool(&["other"]);
    let service = container(pool);

    let error = service
        .run_chat_turn(
            AgentTurnRequest {
                provider: Some(ProviderId::from_string("missing")),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, ClassifiedError::Provider(_)), "{error}");
    assert!(error.to_string().contains("'missing'"), "{error}");
    assert_eq!(counters[0].load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_frozen_selected_provider_fails_naming_it_and_is_not_substituted() {
    let (pool, counters) = production_pool(&["first", "second"]);
    pool.freeze(
        &ProviderId::from_string("first"),
        "operator freeze".to_owned(),
    )
    .await;
    let service = container(pool);

    let error = service
        .run_chat_turn(
            AgentTurnRequest {
                provider: Some(ProviderId::from_string("first")),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap_err();

    let message = error.to_string();
    assert!(message.contains("'first'"), "{message}");
    assert!(message.contains("frozen"), "{message}");
    assert_eq!(counters[0].load(Ordering::SeqCst), 0);
    assert_eq!(counters[1].load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_healthy_selected_provider_answers_instead_of_the_first_in_order() {
    let (pool, counters) = production_pool(&["first", "second"]);
    let service = container(pool);

    service
        .run_chat_turn(
            AgentTurnRequest {
                provider: Some(ProviderId::from_string("second")),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap();

    assert_eq!(counters[0].load(Ordering::SeqCst), 0);
    assert_eq!(counters[1].load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_selection_without_any_configured_provider_fails_naming_it() {
    private_config_dir();
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let error = service
        .run_chat_turn(
            AgentTurnRequest {
                provider: Some(ProviderId::from_string("chosen")),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap_err();

    assert!(error.to_string().contains("'chosen'"), "{error}");
}

#[tokio::test]
async fn the_provider_that_answered_is_recorded_on_the_persisted_answer() {
    let pool = Arc::new(ScriptedPool::new(&[r#"{"final":"recorded"}"#]).served_by("chosen"));
    let (service, session, _dir) = persistent(pool).await;

    service
        .run_chat_turn(
            AgentTurnRequest {
                session: Some(session.clone()),
                provider: Some(ProviderId::from_string("chosen")),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap();

    let history = service.chat_history(&session).await.unwrap();
    assert_eq!(history.len(), 2);
    let provider = &history[1].metadata["provider"];
    assert_eq!(provider["selected"], "chosen");
    assert_eq!(provider["served"], "chosen");
    assert_eq!(provider["model"], "scripted-model");
}

// -- Cancellation --------------------------------------------------------------

#[tokio::test]
async fn a_cancelled_turn_persists_nothing_and_the_next_turn_runs_normally() {
    let pool = Arc::new(ScriptedPool::new(&[r#"{"final":"second turn"}"#]).hanging_at(0));
    let (service, session, _dir) = persistent(pool.clone()).await;
    let turn_id = Uuid::new_v4();

    let running = {
        let service = service.clone();
        let session = session.clone();
        tokio::spawn(async move {
            service
                .run_chat_turn(
                    AgentTurnRequest {
                        session: Some(session),
                        turn_id: Some(turn_id),
                        ..request("first")
                    },
                    &CollectingSink::new(),
                )
                .await
        })
    };
    tokio::time::timeout(WAIT, pool.started.notified())
        .await
        .unwrap();

    assert_eq!(
        service.cancel_chat_turn(turn_id),
        OperationCancelOutcome::Accepted
    );
    assert_eq!(
        service.cancel_chat_turn(turn_id),
        OperationCancelOutcome::Accepted,
        "a repeated cancel of a turn still winding down is accepted, not an error"
    );
    let result = tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    assert!(
        matches!(result, Err(ClassifiedError::Cancelled)),
        "{result:?}"
    );
    assert_eq!(
        service.cancel_chat_turn(turn_id),
        OperationCancelOutcome::NotRunning
    );
    assert!(service.chat_history(&session).await.unwrap().is_empty());
    assert!(service.chat_checkpoints(&session).await.unwrap().is_empty());

    let answer = service
        .run_chat_turn(
            AgentTurnRequest {
                session: Some(session.clone()),
                turn_id: Some(Uuid::new_v4()),
                ..request("second")
            },
            &NullSink,
        )
        .await
        .unwrap();
    assert_eq!(answer, "second turn");
    assert_eq!(service.chat_history(&session).await.unwrap().len(), 2);
    assert_eq!(service.chat_checkpoints(&session).await.unwrap().len(), 1);
}

#[tokio::test]
async fn cancelling_a_finished_turn_changes_nothing() {
    let pool = Arc::new(ScriptedPool::new(&[r#"{"final":"kept"}"#]));
    let (service, session, _dir) = persistent(pool).await;
    let turn_id = Uuid::new_v4();

    service
        .run_chat_turn(
            AgentTurnRequest {
                session: Some(session.clone()),
                turn_id: Some(turn_id),
                ..request("hello")
            },
            &NullSink,
        )
        .await
        .unwrap();

    assert_eq!(
        service.cancel_chat_turn(turn_id),
        OperationCancelOutcome::NotRunning
    );
    assert_eq!(service.chat_history(&session).await.unwrap().len(), 2);
    assert_eq!(service.chat_checkpoints(&session).await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_turn_id_that_is_already_running_is_rejected() {
    let pool = Arc::new(ScriptedPool::new(&[]).hanging_at(0));
    let service = container(pool.clone());
    let turn_id = Uuid::new_v4();

    let running = {
        let service = service.clone();
        tokio::spawn(async move {
            service
                .run_chat_turn(
                    AgentTurnRequest {
                        turn_id: Some(turn_id),
                        ..request("first")
                    },
                    &NullSink,
                )
                .await
        })
    };
    tokio::time::timeout(WAIT, pool.started.notified())
        .await
        .unwrap();

    let duplicate = service
        .run_chat_turn(
            AgentTurnRequest {
                turn_id: Some(turn_id),
                ..request("second")
            },
            &NullSink,
        )
        .await;
    assert!(
        matches!(duplicate, Err(ClassifiedError::Validation(_))),
        "{duplicate:?}"
    );

    assert_eq!(
        service.cancel_chat_turn(turn_id),
        OperationCancelOutcome::Accepted
    );
    let result = tokio::time::timeout(WAIT, running).await.unwrap().unwrap();
    assert!(matches!(result, Err(ClassifiedError::Cancelled)));
}

#[tokio::test]
async fn a_turn_queued_behind_its_session_lock_can_be_cancelled() {
    let pool = Arc::new(ScriptedPool::new(&[]).hanging_at(0));
    let (service, session, _dir) = persistent(pool.clone()).await;
    let first = Uuid::new_v4();
    let queued = Uuid::new_v4();

    let spawn_turn = |turn_id: Uuid| {
        let service = service.clone();
        let session = session.clone();
        tokio::spawn(async move {
            service
                .run_chat_turn(
                    AgentTurnRequest {
                        session: Some(session),
                        turn_id: Some(turn_id),
                        ..request("hello")
                    },
                    &NullSink,
                )
                .await
        })
    };
    let first_turn = spawn_turn(first);
    tokio::time::timeout(WAIT, pool.started.notified())
        .await
        .unwrap();
    let queued_turn = spawn_turn(queued);
    // One cancel stops the queued turn whenever it lands: after the turn has
    // registered (it registers before waiting for the session lock) it is
    // accepted and wakes the waiting turn; before that, the cancel is
    // remembered and the turn is refused at registration. Retrying until
    // "accepted" would spin forever in the second case.
    let outcome = service.cancel_chat_turn(queued);
    assert!(
        matches!(
            outcome,
            OperationCancelOutcome::Accepted | OperationCancelOutcome::NotRunning
        ),
        "{outcome:?}"
    );
    let result = tokio::time::timeout(WAIT, queued_turn)
        .await
        .expect("a queued turn must not wait for the running one to finish")
        .unwrap();
    assert!(matches!(result, Err(ClassifiedError::Cancelled)));

    assert_eq!(
        service.cancel_chat_turn(first),
        OperationCancelOutcome::Accepted
    );
    let result = tokio::time::timeout(WAIT, first_turn)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ClassifiedError::Cancelled)));
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelling_during_an_approval_wait_denies_it_and_closes_the_prompt() {
    let pool = Arc::new(ScriptedPool::new(&[
        r#"{"tool":"discover","args":{"lang":"c"}}"#,
        r#"{"final":"must not run"}"#,
    ]));
    let pending = Arc::new(PendingApprovals::default());
    let notifier = Arc::new(RecordingNotifier::default());
    let gate = InteractiveApprovalGate::new(Arc::clone(&pending), notifier.clone());
    let service = container(pool.clone())
        .with_guardrails(Guardrails::new(GuardrailPolicy::default(), Arc::new(gate)));
    let mut manual = service
        .get_agent_definition("target-scout")
        .expect("built-in agent");
    "manual-scout".clone_into(&mut manual.id);
    manual.autonomy = hf_agent::Autonomy::Manual;
    service.save_agent_definition(manual).unwrap();
    let project = tempfile::tempdir().unwrap();
    let turn_id = Uuid::new_v4();

    let running = {
        let service = service.clone();
        let project = project.path().to_path_buf();
        tokio::spawn(async move {
            service
                .run_chat_turn(
                    AgentTurnRequest {
                        project: Some(project),
                        agent_id: Some("manual-scout".to_owned()),
                        turn_id: Some(turn_id),
                        ..request("discover")
                    },
                    &NullSink,
                )
                .await
        })
    };
    tokio::time::timeout(WAIT, notifier.notify.notified())
        .await
        .expect("the manual agent must ask for approval");
    let prompt = notifier.requested.lock().unwrap()[0].clone();
    assert_eq!(pending.pending_count(), 1);

    assert_eq!(
        service.cancel_chat_turn(turn_id),
        OperationCancelOutcome::Accepted
    );
    let result = tokio::time::timeout(WAIT, running)
        .await
        .expect("an approval wait must not hold a cancelled turn open")
        .unwrap();

    assert!(
        matches!(result, Err(ClassifiedError::Cancelled)),
        "{result:?}"
    );
    assert_eq!(pending.pending_count(), 0);
    assert!(notifier
        .closed
        .lock()
        .unwrap()
        .iter()
        .any(|closed| closed.id == prompt.id));
    let id = Uuid::parse_str(&prompt.id).unwrap();
    assert!(
        !pending.resolve(id, true),
        "a late approval of a cancelled prompt must not be accepted"
    );
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
    service.delete_agent_definition("manual-scout").unwrap();
}
