//! Axum router with REST endpoints + SSE streaming.
//!
//! Mirrors the `y-web` pattern: routes are grouped, SSE events are broadcast
//! via a `tokio::sync::broadcast` channel, and the router matches the
//! `httpTransport.ts` `COMMAND_MAP` used by the web-mode frontend.

use axum::extract::{Json, Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::broadcast;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Shared application state injected into every handler via axum `State`.
#[derive(Clone)]
pub struct AppState {
    pub container: ServiceContainer,
    pub event_tx: broadcast::Sender<SseEvent>,
}

impl AppState {
    /// Create a new `AppState` with a service container.
    #[must_use]
    pub fn new(container: ServiceContainer) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            container,
            event_tx,
        }
    }
}

// ---------------------------------------------------------------------------
// SSE events
// ---------------------------------------------------------------------------

/// Unified SSE event enum broadcast to all connected clients.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum SseEvent {
    /// `run:progress` -- a fuzz run progress event.
    RunProgress {
        kind: String,
        data: serde_json::Value,
    },
    /// `docker:status` -- Docker daemon / sandbox image build progress.
    DockerStatus { message: String },
}

impl SseEvent {
    fn event_name(&self) -> &'static str {
        match self {
            SseEvent::RunProgress { .. } => "run:progress",
            SseEvent::DockerStatus { .. } => "docker:status",
        }
    }
}

// ---------------------------------------------------------------------------
// Error helper
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;

fn map_err<E: std::fmt::Display>(
    status: StatusCode,
) -> impl Fn(E) -> (StatusCode, Json<ErrorResponse>) {
    move |e| {
        (
            status,
            Json(ErrorResponse {
                error: e.to_string(),
            }),
        )
    }
}

// ---------------------------------------------------------------------------
// Build the router
// ---------------------------------------------------------------------------

/// Build the application router with a minimal stub container (no Docker, no
/// LLM, no persistence). Intended for tests and health checks.
pub fn build() -> Router {
    build_with_state(AppState::new(hf_service::ServiceContainer::new(
        std::sync::Arc::new(hf_runtime::StubRuntime),
        None,
    )))
}

/// Build the application router from the canonical
/// [`ServiceContainer::bootstrap`]: Docker runtime, env-configured LLM provider
/// pool, and `HF_DB_PATH` persistence -- the same container the CLI and GUI use.
pub async fn build_bootstrapped() -> Router {
    build_with_state(AppState::new(ServiceContainer::bootstrap().await))
}

/// Build the router with a given `AppState` (for testing or custom containers).
pub fn build_with_state(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/discover", post(discover))
        .route("/harness/draft", post(harness_draft))
        .route("/harness/compile", post(harness_compile))
        .route("/seeds/generate", post(generate_seeds))
        .route("/corpus/{op}", post(corpus))
        .route("/triage", post(triage))
        .route("/chat/send", post(chat_send))
        .route("/config/models", get(list_models))
        .route("/config/sections", get(list_configs))
        .route("/config/read", post(read_config))
        .route("/config/write", post(write_config))
        .route("/config/providers", get(get_providers).post(set_providers))
        .route("/system/paths", get(app_paths))
        .route("/system/arch", get(host_arch))
        .route("/events", get(event_stream))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
struct DiscoverRequest {
    project: PathBuf,
    lang: String,
}

async fn discover(
    State(state): State<AppState>,
    Json(req): Json<DiscoverRequest>,
) -> ApiResult<serde_json::Value> {
    let lang = parse_lang(&req.lang).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let inv = state
        .container
        .discover(&req.project, lang)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::to_value(&inv).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct HarnessDraftRequest {
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
}

async fn harness_draft(
    State(state): State<AppState>,
    Json(req): Json<HarnessDraftRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine);
    let lang = req.lang.as_deref().map_or(TargetLanguage::C, |l| {
        parse_lang(l).unwrap_or(TargetLanguage::C)
    });
    let draft = state
        .container
        .harness_draft(&req.project, &req.target, engine, lang)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    let build_cmd = hf_harness::build_command(engine, lang, &format!("fuzz_{}", req.target));
    Ok(Json(serde_json::json!({
        "source": draft.source,
        "target": req.target,
        "engine": req.engine,
        "build_cmd": {
            "compiler": build_cmd.compiler,
            "args": build_cmd.args,
        },
        "status": "Draft",
    })))
}

#[derive(Debug, Deserialize)]
struct HarnessCompileRequest {
    source: String,
    project: PathBuf,
    engine: String,
    target: String,
    lang: Option<String>,
}

async fn harness_compile(
    State(state): State<AppState>,
    Json(req): Json<HarnessCompileRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine);
    let lang = req.lang.as_deref().map_or(TargetLanguage::C, |l| {
        parse_lang(l).unwrap_or(TargetLanguage::C)
    });
    match state
        .container
        .harness_compile(req.source, &req.project, engine, &req.target, lang)
        .await
    {
        Ok(out) => Ok(Json(serde_json::json!({
            "status": format!("{:?}", out.status),
            "message": "Harness compiled successfully in sandbox.",
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "status": "Failed",
            "message": format!("Compile failed: {e}"),
        }))),
    }
}

#[derive(Debug, Deserialize)]
struct GenerateSeedsRequest {
    project: String,
    target: String,
}

async fn generate_seeds(
    State(state): State<AppState>,
    Json(req): Json<GenerateSeedsRequest>,
) -> ApiResult<serde_json::Value> {
    let entries = state
        .container
        .generate_seeds(std::path::Path::new(&req.project), &req.target)
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({"seeds": entries})))
}

#[derive(Debug, Deserialize)]
struct CorpusRequest {
    project: String,
    target: String,
}

async fn corpus(
    State(state): State<AppState>,
    Path(op): Path<String>,
    Json(req): Json<CorpusRequest>,
) -> ApiResult<serde_json::Value> {
    match op.as_str() {
        "list" => {
            let corpus = state
                .container
                .corpus_list(std::path::Path::new(&req.project), &req.target)
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(
                serde_json::to_value(&corpus.entries).unwrap_or_default(),
            ))
        }
        "seed" => {
            let n = state
                .container
                .corpus_seed(std::path::Path::new(&req.project), &req.target)
                .await
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(serde_json::json!({"seeded": n})))
        }
        "grow" => {
            let n = state
                .container
                .corpus_grow(std::path::Path::new(&req.project), &req.target)
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(serde_json::json!({"entries": n})))
        }
        "prune" => {
            let n = state
                .container
                .corpus_prune(std::path::Path::new(&req.project), &req.target)
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(serde_json::json!({"entries": n})))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("unknown op: {other}"),
            }),
        )),
    }
}

#[derive(Debug, Deserialize)]
struct TriageRequest {
    project: String,
    target: String,
}

async fn triage(
    State(state): State<AppState>,
    Json(req): Json<TriageRequest>,
) -> ApiResult<serde_json::Value> {
    let deduped = state
        .container
        .triage(std::path::Path::new(&req.project), &req.target)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::to_value(&deduped).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct ChatSendRequest {
    message: String,
}

async fn chat_send(
    State(state): State<AppState>,
    Json(req): Json<ChatSendRequest>,
) -> ApiResult<String> {
    let resp = state
        .container
        .chat_send(&req.message)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(resp))
}

// -- Config endpoints ------------------------------------------------------

async fn list_models(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

async fn list_configs(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

#[derive(Debug, Deserialize)]
struct ReadConfigRequest {
    _name: String,
}

async fn read_config(
    State(_): State<AppState>,
    Json(req): Json<ReadConfigRequest>,
) -> ApiResult<String> {
    let _ = req;
    Ok(Json(String::new()))
}

#[derive(Debug, Deserialize)]
struct WriteConfigRequest {
    _name: String,
    _content: String,
}

async fn write_config(
    State(_): State<AppState>,
    Json(req): Json<WriteConfigRequest>,
) -> ApiResult<()> {
    let _ = req;
    Ok(Json(()))
}

async fn get_providers(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!([]))
}

async fn set_providers(
    State(_): State<AppState>,
    Json(_req): Json<serde_json::Value>,
) -> ApiResult<()> {
    Ok(Json(()))
}

// -- System endpoints ------------------------------------------------------

async fn app_paths(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "config_dir": "config",
        "data_dir": "data",
    }))
}

async fn host_arch() -> Json<String> {
    Json(hf_runtime::host_platform())
}

// -- SSE -------------------------------------------------------------------

async fn event_stream(State(state): State<AppState>) -> Response {
    let mut rx = state.event_tx.subscribe();
    let stream = async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let name = event.event_name().to_string();
                    if let Ok(json) = serde_json::to_string(&event) {
                        yield Ok::<_, std::convert::Infallible>(
                            Event::default().event(name).data(json),
                        );
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(lagged = n, "SSE client fell behind, skipped events");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_lang(s: &str) -> Result<TargetLanguage, String> {
    match s.to_ascii_lowercase().as_str() {
        "c" => Ok(TargetLanguage::C),
        "cpp" | "c++" => Ok(TargetLanguage::Cpp),
        "rust" | "rs" => Ok(TargetLanguage::Rust),
        "go" => Ok(TargetLanguage::Go),
        "python" | "py" => Ok(TargetLanguage::Python),
        other => Err(format!("unsupported language: {other}")),
    }
}

fn parse_engine(s: &str) -> EngineKind {
    match s.to_ascii_lowercase().as_str() {
        "afl++" | "aflplusplus" => EngineKind::AflPlusPlus,
        "honggfuzz" | "hfuzz" => EngineKind::Honggfuzz,
        "clusterfuzzlite" | "cfl" => EngineKind::ClusterFuzzLite,
        "syzkaller" | "syz" => EngineKind::Syzkaller,
        _ => EngineKind::LibFuzzer,
    }
}
