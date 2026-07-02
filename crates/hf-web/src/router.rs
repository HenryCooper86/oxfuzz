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

use hf_service::{EngineKind, Message, Role, ServiceContainer, SessionId, TargetLanguage};

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Shared application state injected into every handler via axum `State`.
#[derive(Clone)]
pub struct AppState {
    pub container: ServiceContainer,
    pub event_tx: broadcast::Sender<SseEvent>,
    /// Campaign scheduler, when started (present in `build_bootstrapped`, absent
    /// in bare test states). Schedule endpoints degrade to empty results when
    /// `None`.
    pub scheduler: Option<std::sync::Arc<hf_service::scheduler::CampaignScheduler>>,
}

impl AppState {
    /// Create a new `AppState` with a service container (no scheduler).
    #[must_use]
    pub fn new(container: ServiceContainer) -> Self {
        let (event_tx, _) = broadcast::channel(256);
        Self {
            container,
            event_tx,
            scheduler: None,
        }
    }

    /// Attach a started campaign scheduler.
    #[must_use]
    pub fn with_scheduler(
        mut self,
        scheduler: std::sync::Arc<hf_service::scheduler::CampaignScheduler>,
    ) -> Self {
        self.scheduler = Some(scheduler);
        self
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
    build_with_state(AppState::new(ServiceContainer::stubbed()))
}

/// Build the application router from the canonical
/// [`ServiceContainer::bootstrap`]: Docker runtime, env-configured LLM provider
/// pool, and `HF_DB_PATH` persistence -- the same container the CLI and GUI use.
pub async fn build_bootstrapped() -> Router {
    let container = ServiceContainer::bootstrap().await;
    // Start the campaign scheduler so headless schedules fire and the schedule
    // endpoints are live (mirrors the desktop shell). Schedules persist under
    // the user data dir so they survive restarts.
    let store_path = hf_service::init::user_app_dir().join("schedules.json");
    let scheduler = std::sync::Arc::new(
        hf_service::scheduler::CampaignScheduler::start(container.clone(), store_path).await,
    );
    build_with_state(AppState::new(container).with_scheduler(scheduler))
}

/// Build the router with a given `AppState` (for testing or custom containers).
pub fn build_with_state(state: AppState) -> Router {
    let policy = AuthPolicy::from_env();
    match (&policy.token, policy.allow_open) {
        (Some(_), _) => tracing::info!("hf-web: bearer-token auth enabled"),
        (None, true) => tracing::warn!(
            "hf-web: HF_WEB_TOKEN is not set and HF_WEB_TOKEN_OPTIONAL=1 -- \
             the API is UNAUTHENTICATED (local-dev mode)."
        ),
        (None, false) => tracing::warn!(
            "hf-web: HF_WEB_TOKEN is not set -- the API is FAIL-CLOSED and will \
             reject every request except /health with 401. Set HF_WEB_TOKEN to \
             require an Authorization: Bearer <token> header, or set \
             HF_WEB_TOKEN_OPTIONAL=1 to allow unauthenticated local-dev access."
        ),
    }
    Router::new()
        .route("/health", get(health))
        .route("/discover", post(discover))
        .route("/harness/draft", post(harness_draft))
        .route("/harness/compile", post(harness_compile))
        .route("/seeds/generate", post(generate_seeds))
        .route("/corpus/{op}", post(corpus))
        .route("/triage", post(triage))
        .route("/report", post(report))
        .route("/sarif", post(sarif))
        .route("/knowledge/clear", post(clear_knowledge))
        .route("/providers/status", get(provider_statuses))
        .route("/system/snapshot", get(system_snapshot))
        .route("/workbench/dashboard", post(workbench_dashboard))
        .route("/workbench/harnesses", post(harness_review_queue))
        .route("/gitlab/issue", post(gitlab_issue_export))
        .route("/chat/send", post(chat_send))
        .route("/chat/agent", post(chat_agent))
        // Session management (parity with the desktop shell).
        .route("/chat/session", post(create_session))
        .route("/chat/history", post(chat_history))
        .route("/chat/rollback", post(chat_rollback))
        .route("/chat/rollback_to", post(chat_rollback_to))
        .route("/chat/checkpoints", post(chat_checkpoints))
        .route("/chat/branch", post(chat_branch))
        .route("/chat/branches", post(chat_branches))
        // Knowledge base.
        .route("/knowledge/index", post(knowledge_index))
        .route("/knowledge/ingest", post(knowledge_ingest))
        .route("/knowledge/search", post(knowledge_search))
        // Campaign scheduling.
        .route("/schedule", get(schedule_list).post(schedule_create))
        .route("/schedule/history", get(schedule_history))
        .route("/schedule/{id}", axum::routing::delete(schedule_delete))
        .route("/schedule/{id}/enabled", post(schedule_set_enabled))
        .route("/config/models", get(list_models))
        .route("/config/sections", get(list_configs))
        .route("/config/read", post(read_config))
        .route("/config/write", post(write_config))
        .route("/config/providers", get(get_providers).post(set_providers))
        .route("/system/paths", get(app_paths))
        .route("/system/arch", get(host_arch))
        .route("/events", get(event_stream))
        // Auth + audit wraps every route above (layers apply to routes added
        // before them). The policy is resolved once at build time and captured
        // by the middleware so per-request handling needs no env lookups.
        .layer(axum::middleware::from_fn(move |req, next| {
            let policy = policy.clone();
            async move { auth_audit(policy, req, next).await }
        }))
        .with_state(state)
}

/// Resolved authentication policy for the REST API, derived once at router
/// build time from the environment.
#[derive(Clone, Debug)]
struct AuthPolicy {
    /// The required bearer token, when configured (`HF_WEB_TOKEN`).
    token: Option<String>,
    /// When no token is configured, whether to allow unauthenticated access
    /// (`HF_WEB_TOKEN_OPTIONAL=1`). Defaults to `false` (fail-closed).
    allow_open: bool,
}

impl AuthPolicy {
    fn from_env() -> Self {
        let token = std::env::var("HF_WEB_TOKEN").ok().filter(|t| !t.is_empty());
        let allow_open = std::env::var("HF_WEB_TOKEN_OPTIONAL")
            .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        Self { token, allow_open }
    }

    /// Decide whether a request to `path` carrying `presented` (the value after
    /// `Bearer `) is allowed. `/health` is always open for liveness probes.
    fn authorize(&self, path: &str, presented: Option<&str>) -> bool {
        if path == "/health" {
            return true;
        }
        match &self.token {
            // A token is configured: require an exact bearer match.
            Some(expected) => presented == Some(expected.as_str()),
            // No token: open only when explicitly opted in; else fail-closed.
            None => self.allow_open,
        }
    }
}

/// Bearer-token auth + request audit middleware.
///
/// Enforces [`AuthPolicy`]: with a token configured, every request except
/// `/health` must carry a matching `Authorization: Bearer <token>` header.
/// With no token configured the API is fail-closed (rejects everything but
/// `/health`) unless `HF_WEB_TOKEN_OPTIONAL=1`. Every request is logged
/// (method + path) as a lightweight audit trail.
async fn auth_audit(
    policy: AuthPolicy,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();

    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if !policy.authorize(&path, presented) {
        tracing::warn!(%method, %path, "hf-web: rejected unauthorized request");
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }

    tracing::info!(%method, %path, "hf-web request");
    next.run(req).await
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
    let engine = parse_engine(&req.engine).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let lang = match req.lang.as_deref() {
        Some(l) => parse_lang(l).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    let draft = state
        .container
        .harness_draft(&req.project, &req.target, engine, lang)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({
        "source": draft.source,
        "target": req.target,
        "engine": req.engine,
        "build_cmd": {
            "compiler": draft.build_cmd.compiler,
            "args": draft.build_cmd.args,
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
    let engine = parse_engine(&req.engine).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let lang = match req.lang.as_deref() {
        Some(l) => parse_lang(l).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
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
                .await
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

async fn system_snapshot(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let snapshot = state.container.system_snapshot().await;
    Ok(Json(serde_json::to_value(&snapshot).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct WorkbenchRequest {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    target: Option<String>,
}

fn opt_project_path(project: Option<&String>) -> Option<&std::path::Path> {
    project.filter(|p| !p.is_empty()).map(std::path::Path::new)
}

fn opt_target(target: Option<&String>) -> Option<&str> {
    target.filter(|t| !t.is_empty()).map(String::as_str)
}

async fn workbench_dashboard(
    State(state): State<AppState>,
    Json(req): Json<WorkbenchRequest>,
) -> ApiResult<hf_service::WorkbenchDashboard> {
    Ok(Json(
        state
            .container
            .workbench_dashboard(
                opt_project_path(req.project.as_ref()),
                opt_target(req.target.as_ref()),
            )
            .await,
    ))
}

async fn harness_review_queue(
    State(state): State<AppState>,
    Json(req): Json<WorkbenchRequest>,
) -> ApiResult<Vec<hf_service::HarnessReviewItem>> {
    Ok(Json(
        state
            .container
            .harness_review_queue(
                opt_project_path(req.project.as_ref()),
                opt_target(req.target.as_ref()),
            )
            .await,
    ))
}

#[derive(Debug, Deserialize)]
struct GitLabIssueRequest {
    project: String,
    crash_id: String,
}

async fn gitlab_issue_export(
    State(state): State<AppState>,
    Json(req): Json<GitLabIssueRequest>,
) -> ApiResult<hf_service::GitLabIssueExport> {
    let export = state
        .container
        .gitlab_issue_export(std::path::Path::new(&req.project), &req.crash_id)
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(export))
}

async fn provider_statuses(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let statuses = state.container.provider_statuses().await;
    let arr: Vec<serde_json::Value> = statuses
        .into_iter()
        .map(|s| {
            serde_json::json!({
                "id": s.id.0,
                "frozen": s.is_frozen,
                "freeze_reason": s.freeze_reason,
                "active_requests": s.active_requests,
                "total_requests": s.total_requests,
                "total_errors": s.total_errors,
            })
        })
        .collect();
    Ok(Json(serde_json::Value::Array(arr)))
}

async fn clear_knowledge(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    state
        .container
        .clear_knowledge()
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({ "cleared": true })))
}

async fn sarif(State(state): State<AppState>, Json(req): Json<TriageRequest>) -> ApiResult<String> {
    let doc = state
        .container
        .export_sarif(std::path::Path::new(&req.project), &req.target)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(doc))
}

async fn report(
    State(state): State<AppState>,
    Json(req): Json<TriageRequest>,
) -> ApiResult<String> {
    let markdown = state
        .container
        .generate_report(std::path::Path::new(&req.project), &req.target)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(markdown))
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

#[derive(Debug, Deserialize)]
struct ChatAgentRequest {
    message: String,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    /// Prior conversation turns, used only when no persistent session applies.
    #[serde(default)]
    history: Vec<ChatHistoryTurn>,
}

#[derive(Debug, Deserialize)]
struct ChatHistoryTurn {
    role: String,
    content: String,
}

/// Drive one autonomous agent turn over the project, the same loop the GUI and
/// CLI use (via `hf_agent::run_chat_turn`). Returns the final assistant answer.
/// Tool-call progress is not streamed here; this is a request/response endpoint.
async fn chat_agent(
    State(state): State<AppState>,
    Json(req): Json<ChatAgentRequest>,
) -> ApiResult<String> {
    let project = req.project.filter(|p| !p.is_empty()).map(PathBuf::from);
    let session = req.session_id.filter(|s| !s.is_empty()).map(SessionId);
    let history_fallback: Vec<Message> = req
        .history
        .into_iter()
        .map(|t| Message::new(parse_role(&t.role), t.content))
        .collect();
    let answer = hf_agent::run_chat_turn(
        state.container.clone(),
        project,
        req.agent_id.as_deref(),
        agents_dir(),
        session,
        history_fallback,
        &req.message,
        &hf_agent::NullSink,
    )
    .await
    .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(answer))
}

/// Parse a transcript role string into a [`Role`],
/// defaulting unknown values to `User`.
fn parse_role(role: &str) -> Role {
    match role.to_ascii_lowercase().as_str() {
        "assistant" => Role::Assistant,
        "system" => Role::System,
        _ => Role::User,
    }
}

/// Resolve the user agent-definitions directory: `<repo>/agents`, else
/// `./agents` (mirrors how `hf-agent` resolves skills).
fn agents_dir() -> PathBuf {
    hf_service::repo_root().map_or_else(|| PathBuf::from("agents"), |r| r.join("agents"))
}

// -- Session management ----------------------------------------------------
//
// All delegate to `ServiceContainer` chat/session methods, the same ones the
// desktop shell uses, so sessions behave identically across GUI/web/CLI.

#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    #[serde(default)]
    title: Option<String>,
}

async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Json<Option<String>> {
    Json(state.container.create_chat_session(req.title).await)
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    session_id: String,
}

async fn chat_history(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> Json<Vec<Message>> {
    let id = SessionId(req.session_id);
    Json(state.container.chat_history(&id).await)
}

async fn chat_rollback(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> Json<usize> {
    let id = SessionId(req.session_id);
    Json(state.container.chat_rollback_last(&id).await)
}

#[derive(Debug, Deserialize)]
struct RollbackToRequest {
    session_id: String,
    checkpoint_id: String,
}

async fn chat_rollback_to(
    State(state): State<AppState>,
    Json(req): Json<RollbackToRequest>,
) -> Json<usize> {
    let id = SessionId(req.session_id);
    Json(
        state
            .container
            .chat_rollback_to(&id, &req.checkpoint_id)
            .await,
    )
}

async fn chat_checkpoints(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> Json<Vec<hf_service::checkpoints::CheckpointView>> {
    let id = SessionId(req.session_id);
    Json(state.container.chat_checkpoints(&id).await)
}

#[derive(Debug, Deserialize)]
struct BranchRequest {
    session_id: String,
    fork_message_count: u32,
    #[serde(default)]
    title: Option<String>,
}

async fn chat_branch(
    State(state): State<AppState>,
    Json(req): Json<BranchRequest>,
) -> Json<Option<String>> {
    let id = SessionId(req.session_id);
    Json(
        state
            .container
            .chat_branch(
                &id,
                req.fork_message_count,
                req.title.filter(|t| !t.is_empty()),
            )
            .await,
    )
}

async fn chat_branches(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> Json<Vec<hf_service::checkpoints::BranchView>> {
    let id = SessionId(req.session_id);
    Json(state.container.chat_branches(&id).await)
}

// -- Knowledge base --------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ProjectRequest {
    project: String,
}

async fn knowledge_index(
    State(_): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<hf_service::knowledge::KnowledgeStats> {
    let stats = hf_service::knowledge::index_project(std::path::Path::new(&req.project))
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(stats))
}

#[derive(Debug, Deserialize)]
struct IngestRequest {
    project: String,
    file: String,
}

async fn knowledge_ingest(
    State(state): State<AppState>,
    Json(req): Json<IngestRequest>,
) -> ApiResult<hf_service::knowledge::KnowledgeStats> {
    let ingested = state
        .container
        .ingest_document(
            std::path::Path::new(&req.project),
            std::path::Path::new(&req.file),
        )
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(ingested))
}

#[derive(Debug, Deserialize)]
struct KnowledgeSearchRequest {
    project: String,
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

async fn knowledge_search(
    State(_): State<AppState>,
    Json(req): Json<KnowledgeSearchRequest>,
) -> Json<Vec<hf_service::knowledge::KnowledgeHit>> {
    // Index-on-demand so a server restarted since the last `index` call does not
    // silently return nothing. The tree walk is blocking, so run it off the
    // async runtime.
    let hits = tokio::task::spawn_blocking(move || {
        hf_service::knowledge::search_project_ensured(
            std::path::Path::new(&req.project),
            &req.query,
            req.limit.unwrap_or(10),
        )
    })
    .await
    .unwrap_or_default();
    Json(hits)
}

// -- Campaign scheduling ---------------------------------------------------
//
// Endpoints degrade to empty results when no scheduler is attached (e.g. a
// bare test state).

async fn schedule_list(
    State(state): State<AppState>,
) -> Json<Vec<hf_service::scheduler::CampaignView>> {
    match &state.scheduler {
        Some(s) => Json(s.list_views().await),
        None => Json(Vec::new()),
    }
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn schedule_history(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<HistoryQuery>,
) -> Json<Vec<hf_service::scheduler::ExecutionView>> {
    match &state.scheduler {
        Some(s) => Json(s.recent_executions(q.limit.unwrap_or(20)).await),
        None => Json(Vec::new()),
    }
}

#[derive(Debug, Deserialize)]
struct ScheduleCreateRequest {
    name: String,
    trigger_kind: String,
    trigger_value: String,
    project: String,
    target: String,
    engine: String,
    duration_secs: u64,
}

async fn schedule_create(
    State(state): State<AppState>,
    Json(req): Json<ScheduleCreateRequest>,
) -> ApiResult<Vec<hf_service::scheduler::CampaignView>> {
    let Some(scheduler) = &state.scheduler else {
        return Ok(Json(Vec::new()));
    };
    let trigger = hf_service::scheduler::parse_trigger(&req.trigger_kind, &req.trigger_value)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    let params = hf_service::scheduler::CampaignParams {
        project: req.project,
        target: req.target,
        engine: req.engine,
        duration_secs: req.duration_secs,
    };
    scheduler.create(&req.name, &params, trigger).await;
    Ok(Json(scheduler.list_views().await))
}

async fn schedule_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Json<Vec<hf_service::scheduler::CampaignView>> {
    match &state.scheduler {
        Some(s) => {
            s.remove(&id).await;
            Json(s.list_views().await)
        }
        None => Json(Vec::new()),
    }
}

#[derive(Debug, Deserialize)]
struct SetEnabledRequest {
    enabled: bool,
}

async fn schedule_set_enabled(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> Json<Vec<hf_service::scheduler::CampaignView>> {
    match &state.scheduler {
        Some(s) => {
            s.set_enabled(&id, req.enabled).await;
            Json(s.list_views().await)
        }
        None => Json(Vec::new()),
    }
}

// -- Config endpoints ------------------------------------------------------
//
// These delegate to `hf_service::config`, the single source of truth shared
// with the CLI and GUI, so the HTTP API edits the same `config/*.toml` files.

async fn list_models(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(hf_service::config::list_models()))
}

async fn list_configs(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(hf_service::config::list_configs()))
}

#[derive(Debug, Deserialize)]
struct ReadConfigRequest {
    name: String,
}

async fn read_config(
    State(_): State<AppState>,
    Json(req): Json<ReadConfigRequest>,
) -> ApiResult<String> {
    let content =
        hf_service::config::read_config(&req.name).map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(content))
}

#[derive(Debug, Deserialize)]
struct WriteConfigRequest {
    name: String,
    content: String,
}

async fn write_config(
    State(_): State<AppState>,
    Json(req): Json<WriteConfigRequest>,
) -> ApiResult<()> {
    hf_service::config::write_config(&req.name, &req.content)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(()))
}

async fn get_providers(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(hf_service::config::get_providers()))
}

async fn set_providers(
    State(state): State<AppState>,
    Json(req): Json<Vec<hf_service::config::ProviderConfig>>,
) -> ApiResult<()> {
    hf_service::config::set_providers(&req).map_err(map_err(StatusCode::BAD_REQUEST))?;
    // Apply the new providers to the live pool so the change takes effect without
    // restarting the server.
    state.container.reload_providers();
    Ok(Json(()))
}

// -- System endpoints ------------------------------------------------------

async fn app_paths(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(hf_service::config::app_paths()))
}

async fn host_arch() -> Json<String> {
    Json(hf_service::host_platform())
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
    s.parse()
}

fn parse_engine(s: &str) -> Result<EngineKind, String> {
    s.parse()
}

#[cfg(test)]
mod auth_tests {
    use super::AuthPolicy;

    fn with_token(tok: &str) -> AuthPolicy {
        AuthPolicy {
            token: Some(tok.to_owned()),
            allow_open: false,
        }
    }

    #[test]
    fn health_is_always_open() {
        let fail_closed = AuthPolicy {
            token: None,
            allow_open: false,
        };
        assert!(fail_closed.authorize("/health", None));
        assert!(with_token("secret").authorize("/health", None));
    }

    #[test]
    fn no_token_is_fail_closed_by_default() {
        let policy = AuthPolicy {
            token: None,
            allow_open: false,
        };
        assert!(!policy.authorize("/discover", None));
        assert!(!policy.authorize("/harness/compile", Some("anything")));
    }

    #[test]
    fn no_token_with_opt_out_is_open() {
        let policy = AuthPolicy {
            token: None,
            allow_open: true,
        };
        assert!(policy.authorize("/discover", None));
        assert!(policy.authorize("/harness/compile", None));
    }

    #[test]
    fn configured_token_requires_exact_bearer_match() {
        let policy = with_token("secret");
        assert!(policy.authorize("/discover", Some("secret")));
        assert!(!policy.authorize("/discover", Some("wrong")));
        assert!(!policy.authorize("/discover", None));
    }
}
