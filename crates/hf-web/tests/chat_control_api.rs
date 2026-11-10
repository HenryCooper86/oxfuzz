//! Web-mode chat control: answering approval prompts, stopping a turn, and
//! choosing the provider that answers it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use futures::StreamExt as _;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, ProviderError, ProviderPool,
    RouteRequest,
};
use hf_core::types::{ProviderId, TokenUsage};
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt as _;

const WAIT: Duration = Duration::from_secs(10);
const TOKEN: &str = "chat-control-test-token-0123456789";

struct ScriptedPool {
    replies: Mutex<VecDeque<String>>,
    routes: Mutex<Vec<RouteRequest>>,
    requests: Mutex<Vec<ChatRequest>>,
}

impl ScriptedPool {
    fn new(replies: &[&str]) -> Arc<Self> {
        Arc::new(Self {
            replies: Mutex::new(replies.iter().map(|&reply| reply.to_owned()).collect()),
            routes: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl ProviderPool for ScriptedPool {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        self.routes.lock().unwrap().push(route.clone());
        self.requests.lock().unwrap().push(request.clone());
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| r#"{"final":"done"}"#.to_owned());
        Ok(ChatResponse {
            id: "scripted".to_owned(),
            model: "scripted".to_owned(),
            content: Some(reply),
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

    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// One private config root per test binary, holding a manual-autonomy agent
/// that asks for approval before every tool.
fn manual_agent() -> &'static str {
    static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: this binary sets HF_CONFIG_DIR once, to this value only.
        unsafe {
            std::env::set_var("HF_CONFIG_DIR", dir.path());
        }
        let service = hf_service::ServiceContainer::stubbed();
        let mut agent = service
            .get_agent_definition("target-scout")
            .expect("built-in agent");
        "manual-scout".clone_into(&mut agent.id);
        agent.autonomy = hf_service::Autonomy::Manual;
        service.save_agent_definition(agent).unwrap();
        dir
    });
    "manual-scout"
}

fn app(pool: Arc<ScriptedPool>) -> axum::Router {
    app_with_security(
        pool,
        WebSecurityConfig::new(Some(TOKEN.to_owned()), false, Vec::new(), Vec::new()).unwrap(),
    )
}

/// A loopback development server with `HF_WEB_TOKEN_OPTIONAL` and no token.
fn open_access_app(pool: Arc<ScriptedPool>) -> axum::Router {
    app_with_security(
        pool,
        WebSecurityConfig::new(None, true, Vec::new(), Vec::new()).unwrap(),
    )
}

fn app_with_security(pool: Arc<ScriptedPool>, security: WebSecurityConfig) -> axum::Router {
    // Pin the config dir before any turn reads it.
    manual_agent();
    let container = hf_service::ServiceContainer::stubbed()
        .with_provider_pool(pool)
        .with_guardrails(hf_service::Guardrails::env_gated());
    build_with_state_and_security(AppState::new(container), security)
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<serde_json::Value>,
    authorized: bool,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if authorized {
        builder = builder.header("authorization", format!("Bearer {TOKEN}"));
    }
    let body = body.map_or_else(Body::empty, |value| {
        Body::from(serde_json::to_vec(&value).unwrap())
    });
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Read SSE frames until one named `event` arrives, returning its payload.
async fn next_event(
    stream: &mut (impl futures::Stream<Item = Result<axum::body::Bytes, axum::Error>> + Unpin),
    event: &str,
) -> serde_json::Value {
    let mut buffer = String::new();
    loop {
        let chunk = tokio::time::timeout(WAIT, stream.next())
            .await
            .unwrap_or_else(|_| panic!("no {event} event arrived"))
            .expect("open SSE stream")
            .expect("readable SSE chunk");
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(end) = buffer.find("\n\n") {
            let frame = buffer[..end].to_owned();
            buffer.drain(..end + 2);
            if frame.lines().any(|line| line == format!("event: {event}")) {
                let data = frame
                    .lines()
                    .find_map(|line| line.strip_prefix("data: "))
                    .expect("event data");
                let parsed: serde_json::Value = serde_json::from_str(data).unwrap();
                return parsed["data"].clone();
            }
        }
    }
}

fn spawn_turn(
    app: &axum::Router,
    body: serde_json::Value,
) -> tokio::task::JoinHandle<axum::response::Response> {
    let app = app.clone();
    tokio::spawn(async move { send(&app, Method::POST, "/chat/agent", Some(body), true).await })
}

#[tokio::test]
async fn a_web_client_answers_an_approval_prompt_delivered_over_sse() {
    let agent = manual_agent();
    let pool = ScriptedPool::new(&[
        r#"{"tool":"discover","args":{"lang":"c"}}"#,
        r#"{"final":"declined and reported"}"#,
    ]);
    let app = app(pool);
    let mut events = send(&app, Method::GET, "/events", None, true)
        .await
        .into_body()
        .into_data_stream();

    let turn = spawn_turn(
        &app,
        serde_json::json!({"message": "discover", "agent_id": agent}),
    );
    let prompt = next_event(&mut events, "chat:permission_request").await;
    assert_eq!(prompt["risk"], "medium");
    assert!(prompt["action"].as_str().unwrap().contains("discover"));
    let id = prompt["id"].as_str().unwrap().to_owned();

    let unauthorized = send(
        &app,
        Method::POST,
        "/chat/permission",
        Some(serde_json::json!({"id": id, "approved": true})),
        false,
    )
    .await;
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let answered = send(
        &app,
        Method::POST,
        "/chat/permission",
        Some(serde_json::json!({"id": id, "approved": false})),
        true,
    )
    .await;
    assert_eq!(answered.status(), StatusCode::OK);
    assert_eq!(json(answered).await, serde_json::json!(true));
    let closed = next_event(&mut events, "chat:permission_closed").await;
    assert_eq!(closed["id"], id.as_str());

    let response = tokio::time::timeout(WAIT, turn).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await, "declined and reported");

    let stale = send(
        &app,
        Method::POST,
        "/chat/permission",
        Some(serde_json::json!({"id": id, "approved": true})),
        true,
    )
    .await;
    assert_eq!(json(stale).await, serde_json::json!(false));
}

#[tokio::test]
async fn a_web_client_stops_a_turn_waiting_for_approval() {
    let agent = manual_agent();
    let pool = ScriptedPool::new(&[r#"{"tool":"discover","args":{"lang":"c"}}"#]);
    let app = app(pool);
    let mut events = send(&app, Method::GET, "/events", None, true)
        .await
        .into_body()
        .into_data_stream();
    let turn_id = uuid::Uuid::new_v4().to_string();

    let turn = spawn_turn(
        &app,
        serde_json::json!({"message": "discover", "agent_id": agent, "turn_id": turn_id}),
    );
    let prompt = next_event(&mut events, "chat:permission_request").await;

    let cancelled = send(
        &app,
        Method::POST,
        "/chat/cancel",
        Some(serde_json::json!({"turn_id": turn_id})),
        true,
    )
    .await;
    assert_eq!(cancelled.status(), StatusCode::OK);
    assert_eq!(json(cancelled).await, "accepted");
    let closed = next_event(&mut events, "chat:permission_closed").await;
    assert_eq!(closed["id"], prompt["id"]);

    let response = tokio::time::timeout(WAIT, turn).await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);

    let again = send(
        &app,
        Method::POST,
        "/chat/cancel",
        Some(serde_json::json!({"turn_id": turn_id})),
        true,
    )
    .await;
    assert_eq!(json(again).await, "not_running");
}

#[tokio::test]
async fn a_malformed_turn_id_is_rejected() {
    let app = app(ScriptedPool::new(&[]));

    for (uri, body) in [
        ("/chat/cancel", serde_json::json!({"turn_id": "not-a-uuid"})),
        (
            "/chat/agent",
            serde_json::json!({"message": "hi", "turn_id": "not-a-uuid"}),
        ),
    ] {
        let response = send(&app, Method::POST, uri, Some(body), true).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn the_selected_provider_reaches_the_route_of_a_web_turn() {
    let pool = ScriptedPool::new(&[r#"{"final":"pinned"}"#]);
    let app = app(Arc::clone(&pool));

    let response = send(
        &app,
        Method::POST,
        "/chat/agent",
        Some(serde_json::json!({"message": "hi", "provider": "chosen"})),
        true,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let routes = pool.routes.lock().unwrap().clone();
    assert_eq!(routes.len(), 1);
    assert_eq!(
        routes[0].pinned_provider_id,
        Some(ProviderId::from_string("chosen"))
    );
}

#[tokio::test]
async fn a_gated_web_turn_with_no_event_client_is_denied_without_waiting() {
    let agent = manual_agent();
    let pool = ScriptedPool::new(&[
        r#"{"tool":"discover","args":{"lang":"c"}}"#,
        r#"{"final":"declined and reported"}"#,
    ]);
    let app = app(pool);

    // No `/events` client: the prompt reaches nobody, so the gate denies at
    // once instead of holding the request for its five-minute deadline.
    let turn = spawn_turn(
        &app,
        serde_json::json!({"message": "discover", "agent_id": agent}),
    );
    let response = tokio::time::timeout(WAIT, turn)
        .await
        .expect("an undeliverable prompt must not wait for its deadline")
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await, "declined and reported");
}

#[tokio::test]
async fn an_open_access_server_keeps_the_environment_gate_and_refuses_answers() {
    let agent = manual_agent();
    let pool = ScriptedPool::new(&[
        r#"{"tool":"discover","args":{"lang":"c"}}"#,
        r#"{"final":"declined and reported"}"#,
    ]);
    let app = open_access_app(Arc::clone(&pool));
    // An unauthenticated event client is connected; with the interactive gate
    // it would receive the prompt and the turn would wait for an answer.
    let events = send(&app, Method::GET, "/events", None, false).await;
    assert_eq!(events.status(), StatusCode::OK);
    let _events = events.into_body().into_data_stream();

    let turn = spawn_turn(
        &app,
        serde_json::json!({"message": "discover", "agent_id": agent}),
    );
    let response = tokio::time::timeout(WAIT, turn)
        .await
        .expect("the environment gate denies without prompting")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await, "declined and reported");

    let answer = send(
        &app,
        Method::POST,
        "/chat/permission",
        Some(serde_json::json!({"id": uuid::Uuid::new_v4().to_string(), "approved": true})),
        false,
    )
    .await;
    assert_eq!(answer.status(), StatusCode::FORBIDDEN);
    let error = json(answer).await["error"].as_str().unwrap().to_owned();
    assert!(error.contains("HF_WEB_TOKEN"), "{error}");
    assert!(error.contains("HF_AUTO_APPROVE"), "{error}");
}

#[tokio::test]
async fn web_chat_applies_the_selected_language_and_rejects_unknown_locales() {
    let pool = ScriptedPool::new(&[]);
    let app = app(Arc::clone(&pool));
    for (language, status) in [
        ("zh", StatusCode::OK),
        ("unknown", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = send(
            &app,
            Method::POST,
            "/chat/agent",
            Some(serde_json::json!({
                "message": "Explain fuzzing.", "response_language": language,
            })),
            true,
        )
        .await;
        assert_eq!(response.status(), status);
    }
    let requests = pool.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].messages[0]
        .content
        .contains("Reply in Simplified Chinese"));
}
