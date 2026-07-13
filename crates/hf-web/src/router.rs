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
        hf_service::scheduler::CampaignScheduler::start(container.clone(), store_path, None).await,
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
        .route("/harness/smoke", post(harness_smoke))
        .route("/harness/promote", post(harness_promote))
        .route("/artifacts/summary", post(artifact_summary))
        .route("/seeds/generate", post(generate_seeds))
        .route("/seeds/generate-llm", post(generate_seeds_llm))
        .route("/corpus/{op}", post(corpus))
        .route("/triage", post(triage))
        .route("/report", post(report))
        .route("/reports", get(list_report_drafts))
        .route("/reports/save", post(save_report_draft))
        .route("/reports/delete", post(delete_report_draft))
        .route("/report/formats", get(report_formats))
        .route("/crashes/all", get(all_crashes))
        .route("/corpus/all", get(all_corpus))
        .route("/runs/history", post(run_history))
        .route("/runs/coverage", post(run_coverage_series))
        .route("/runs/harness-source", post(run_harness_source))
        .route("/runs/revert-harness", post(revert_harness_from_run))
        .route(
            "/projects/auto-revert",
            post(project_auto_revert_override),
        )
        .route(
            "/projects/auto-revert/all",
            get(project_auto_revert_overrides),
        )
        .route(
            "/projects/auto-revert/effective",
            post(effective_auto_revert_policy),
        )
        .route("/audit/auto-revert", post(auto_revert_events))
        .route(
            "/projects/auto-revert/set",
            post(set_project_auto_revert_override),
        )
        .route(
            "/projects/auto-revert/clear",
            post(clear_project_auto_revert_override),
        )
        .route("/sarif", post(sarif))
        .route("/knowledge/clear", post(clear_knowledge))
        .route("/projects/delete", post(delete_project))
        .route("/crashes/delete", post(delete_crash))
        .route("/corpus/delete-entry", post(delete_corpus_entry))
        .route("/artifacts/clear", post(clear_all_artifacts))
        .route("/runs/delete", post(delete_run))
        .route("/runs/clear", post(clear_all_runs))
        .route("/projects/export", post(export_project_data))
        .route("/providers/status", get(provider_statuses))
        .route("/system/snapshot", get(system_snapshot))
        .route("/system/status", get(system_status))
        .route("/workbench/dashboard", post(workbench_dashboard))
        .route("/workbench/harnesses", post(harness_review_queue))
        .route("/gitlab/issue", post(gitlab_issue_export))
        .route("/defectdojo/push", post(defectdojo_push))
        .route("/defectdojo/test", get(defectdojo_test))
        .route("/defectdojo/configured", get(defectdojo_configured))
        .route("/defectdojo/status", get(defectdojo_status))
        .route("/defectdojo/start", post(defectdojo_start))
        .route("/defectdojo/stop", post(defectdojo_stop))
        .route("/chat/send", post(chat_send))
        .route("/chat/agent", post(chat_agent))
        // Session management (parity with the desktop shell).
        .route("/chat/session", post(create_session))
        .route("/chat/history", post(chat_history))
        .route("/chat/delete", post(delete_session))
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
        .route("/schedule/history/clear", post(schedule_history_clear))
        .route("/schedule/targets", post(schedule_targets))
        .route(
            "/schedule/concurrency",
            get(schedule_concurrency_get).post(schedule_concurrency_set),
        )
        .route("/schedule/{id}", axum::routing::delete(schedule_delete))
        .route("/schedule/{id}/enabled", post(schedule_set_enabled))
        .route("/config/models", get(list_models))
        .route("/config/sections", get(list_configs))
        .route("/config/read", post(read_config))
        .route("/config/write", post(write_config))
        .route("/config/toml_to_value", post(config_toml_to_value))
        .route("/config/value_to_toml", post(config_value_to_toml))
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
struct HarnessQualificationRequest {
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
}

async fn harness_smoke(
    State(state): State<AppState>,
    Json(req): Json<HarnessQualificationRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let lang = match req.lang.as_deref() {
        Some(value) => parse_lang(value).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    let smoke = state
        .container
        .harness_smoke(&req.project, &req.target, engine, lang)
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(serde_json::json!({
        // Mirror the Tauri command: crashes during smoke mean it did not pass.
        "status": if smoke.passed { "SmokePassed" } else { "SmokeFailed" },
        "duration_secs": smoke.duration_secs,
        "execs_per_sec": smoke.execs_per_sec,
        "crashes": smoke.crashes,
        "passed": smoke.passed,
    })))
}

async fn harness_promote(
    State(state): State<AppState>,
    Json(req): Json<HarnessQualificationRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let harness = state
        .container
        .harness_promote(&req.project, &req.target, engine)
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(serde_json::json!({
        "status": format!("{:?}", harness.status),
        "harness_id": harness.id,
        "message": "Harness approved for full campaigns.",
    })))
}

#[derive(Debug, Deserialize)]
struct GenerateSeedsRequest {
    project: String,
    target: String,
}

async fn report_formats(State(state): State<AppState>) -> ApiResult<Vec<String>> {
    Ok(Json(state.container.report_formats()))
}

async fn run_history(
    State(state): State<AppState>,
    Json(req): Json<WorkbenchRequest>,
) -> ApiResult<serde_json::Value> {
    let path = opt_project_path(req.project.as_ref());
    Ok(Json(
        serde_json::to_value(state.container.run_history(path).await)
            .unwrap_or(serde_json::Value::Null),
    ))
}

#[derive(Debug, Deserialize)]
struct RunIdRequest {
    run_id: String,
}

async fn run_coverage_series(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(
        serde_json::to_value(state.container.run_coverage_series(&req.run_id).await)
            .unwrap_or(serde_json::Value::Null),
    ))
}

async fn run_harness_source(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<String> {
    Ok(Json(state.container.run_harness_source(&req.run_id).await))
}

async fn revert_harness_from_run(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<serde_json::Value> {
    let out = state
        .container
        .revert_harness_from_run(&req.run_id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({
        "status": format!("{:?}", out.status),
        "message": "Reverted and recompiled the harness in the sandbox.",
    })))
}

#[derive(Debug, Deserialize)]
struct SetProjectAutoRevertRequest {
    project: String,
    enabled: bool,
    threshold_pct: f64,
    notify_only: bool,
}

async fn project_auto_revert_override(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let over = state
        .container
        .project_auto_revert_override(std::path::Path::new(&req.project))
        .await;
    Ok(Json(
        serde_json::to_value(over).unwrap_or(serde_json::Value::Null),
    ))
}

#[derive(Debug, Deserialize)]
struct AuditRequest {
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn auto_revert_events(
    State(state): State<AppState>,
    Json(req): Json<AuditRequest>,
) -> ApiResult<serde_json::Value> {
    let project = req.project.filter(|p| !p.is_empty());
    let events = state
        .container
        .auto_revert_events(
            project.as_deref().map(std::path::Path::new),
            req.limit.unwrap_or(200),
        )
        .await;
    Ok(Json(
        serde_json::to_value(events).unwrap_or(serde_json::Value::Null),
    ))
}

async fn effective_auto_revert_policy(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let view = state
        .container
        .effective_auto_revert_view(std::path::Path::new(&req.project))
        .await;
    Ok(Json(
        serde_json::to_value(view).unwrap_or(serde_json::Value::Null),
    ))
}

async fn project_auto_revert_overrides(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(
        serde_json::to_value(state.container.project_auto_revert_overrides().await)
            .unwrap_or(serde_json::Value::Null),
    ))
}

async fn set_project_auto_revert_override(
    State(state): State<AppState>,
    Json(req): Json<SetProjectAutoRevertRequest>,
) -> ApiResult<serde_json::Value> {
    state
        .container
        .set_project_auto_revert_override(
            std::path::Path::new(&req.project),
            req.enabled,
            req.threshold_pct,
            req.notify_only,
        )
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn clear_project_auto_revert_override(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    state
        .container
        .clear_project_auto_revert_override(std::path::Path::new(&req.project))
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn all_crashes(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let crashes = state.container.all_crashes().await;
    Ok(Json(
        serde_json::to_value(&crashes).unwrap_or(serde_json::Value::Null),
    ))
}

async fn all_corpus(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let entries = state.container.all_corpus_entries().await;
    Ok(Json(
        serde_json::to_value(&entries).unwrap_or(serde_json::Value::Null),
    ))
}

async fn export_project_data(
    State(state): State<AppState>,
    Json(req): Json<ExportProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = req
        .project
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    Ok(Json(
        state
            .container
            .export_project_data(project.as_deref())
            .await,
    ))
}

#[derive(Debug, Deserialize)]
struct ExportProjectRequest {
    project: Option<String>,
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
struct GenerateSeedsLlmRequest {
    project: String,
    target: String,
    lang: Option<String>,
    count: Option<usize>,
}

async fn generate_seeds_llm(
    State(state): State<AppState>,
    Json(req): Json<GenerateSeedsLlmRequest>,
) -> ApiResult<serde_json::Value> {
    let lang = match req.lang.as_deref() {
        Some(l) => parse_lang(l).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    let count = req.count.unwrap_or(12).clamp(1, 64);
    let entries = state
        .container
        .generate_seeds_llm(std::path::Path::new(&req.project), &req.target, lang, count)
        .await
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

async fn system_status(State(_): State<AppState>) -> Json<hf_service::SystemStatus> {
    Json(hf_service::system_status().await)
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
struct ArtifactSummaryRequest {
    project: String,
    target: String,
}

async fn artifact_summary(
    State(state): State<AppState>,
    Json(req): Json<ArtifactSummaryRequest>,
) -> ApiResult<hf_service::ArtifactSummary> {
    Ok(Json(state.container.artifact_summary(
        std::path::Path::new(&req.project),
        &req.target,
    )))
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

#[derive(Debug, Deserialize)]
struct DefectDojoPushRequest {
    project: String,
    #[serde(default)]
    target: Option<String>,
}

async fn defectdojo_push(
    State(state): State<AppState>,
    Json(req): Json<DefectDojoPushRequest>,
) -> ApiResult<hf_service::PushOutcome> {
    let outcome = state
        .container
        .push_to_defectdojo(std::path::Path::new(&req.project), req.target.as_deref())
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(outcome))
}

async fn defectdojo_test(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .defectdojo_test_connection()
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(true))
}

async fn defectdojo_configured(State(state): State<AppState>) -> ApiResult<bool> {
    Ok(Json(state.container.defectdojo_configured()))
}

async fn defectdojo_status(State(_): State<AppState>) -> Json<hf_service::DefectDojoStatus> {
    Json(hf_service::defectdojo_lifecycle::status().await)
}

async fn defectdojo_start(State(_): State<AppState>) -> ApiResult<hf_service::DefectDojoStatus> {
    hf_service::defectdojo_lifecycle::start()
        .await
        .map(Json)
        .map_err(map_err(StatusCode::BAD_REQUEST))
}

async fn defectdojo_stop(State(_): State<AppState>) -> ApiResult<hf_service::DefectDojoStatus> {
    hf_service::defectdojo_lifecycle::stop()
        .await
        .map(Json)
        .map_err(map_err(StatusCode::BAD_REQUEST))
}

async fn list_report_drafts(
    State(state): State<AppState>,
) -> ApiResult<Vec<hf_service::ReportDraft>> {
    let reports = state
        .container
        .list_report_drafts()
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(reports))
}

#[derive(Debug, Deserialize)]
struct SaveReportDraftRequest {
    #[serde(default)]
    id: Option<String>,
    title: String,
    project: String,
    #[serde(default)]
    target: Option<String>,
    status: String,
    content: String,
}

async fn save_report_draft(
    State(state): State<AppState>,
    Json(req): Json<SaveReportDraftRequest>,
) -> ApiResult<hf_service::ReportDraft> {
    let report = state
        .container
        .save_report_draft(
            req.id,
            &req.title,
            &req.project,
            req.target.as_deref(),
            &req.status,
            &req.content,
        )
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(report))
}

#[derive(Debug, Deserialize)]
struct DeleteReportDraftRequest {
    id: String,
}

async fn delete_report_draft(
    State(state): State<AppState>,
    Json(req): Json<DeleteReportDraftRequest>,
) -> ApiResult<()> {
    state
        .container
        .delete_report_draft(&req.id)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(()))
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

async fn delete_project(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    state
        .container
        .delete_project(std::path::Path::new(&req.project))
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

#[derive(Debug, Deserialize)]
struct CrashIdRequest {
    crash_id: String,
}

async fn delete_crash(
    State(state): State<AppState>,
    Json(req): Json<CrashIdRequest>,
) -> ApiResult<bool> {
    state
        .container
        .delete_crash(&req.crash_id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(true))
}

#[derive(Debug, Deserialize)]
struct CorpusEntryRequest {
    sha256: String,
}

async fn delete_corpus_entry(
    State(state): State<AppState>,
    Json(req): Json<CorpusEntryRequest>,
) -> ApiResult<bool> {
    state
        .container
        .delete_corpus_entry(&req.sha256)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(true))
}

async fn clear_all_artifacts(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .clear_all_artifacts()
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(true))
}

async fn delete_run(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<bool> {
    state
        .container
        .delete_run(&req.run_id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(true))
}

async fn clear_all_runs(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .clear_all_runs()
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(true))
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

/// Drive one autonomous agent turn over the project through the service facade.
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
    let answer = state
        .container
        .run_chat_turn(
            hf_service::AgentTurnRequest {
                project,
                agent_id: req.agent_id,
                session,
                history_fallback,
                message: req.message,
            },
            &hf_service::NullSink,
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

async fn delete_session(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> Json<bool> {
    let id = SessionId(req.session_id);
    Json(state.container.delete_chat_session(&id).await)
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

async fn schedule_history_clear(State(state): State<AppState>) -> Json<u64> {
    match &state.scheduler {
        Some(s) => Json(s.clear_history().await),
        None => Json(0),
    }
}

#[derive(Debug, Deserialize)]
struct ScheduleTargetsRequest {
    project: String,
}

async fn schedule_targets(
    State(state): State<AppState>,
    Json(req): Json<ScheduleTargetsRequest>,
) -> ApiResult<Vec<hf_service::SchedulableTarget>> {
    state
        .container
        .schedulable_targets(std::path::Path::new(&req.project))
        .await
        .map(Json)
        .map_err(map_err(StatusCode::BAD_REQUEST))
}

#[derive(Debug, Deserialize)]
struct ScheduleCreateRequest {
    name: String,
    trigger_kind: String,
    trigger_value: String,
    project: String,
    /// Promoted target to fuzz; `None`/empty = portfolio over all promoted targets.
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    engine: String,
    /// Canonical language id of the promoted harness; defaults to C for clients
    /// written before scheduled campaigns could be anything else.
    #[serde(default = "default_campaign_lang")]
    lang: String,
    duration_secs: u64,
    /// Budget: stop after this many completed runs.
    #[serde(default)]
    max_runs: Option<u32>,
    /// Budget: stop after this much cumulative fuzz time (seconds).
    #[serde(default)]
    max_total_secs: Option<u64>,
}

fn default_campaign_lang() -> String {
    hf_service::TargetLanguage::C.as_str().to_owned()
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
        target: req.target.filter(|t| !t.is_empty()),
        engine: req.engine,
        lang: req.lang,
        duration_secs: req.duration_secs,
        max_runs: req.max_runs,
        max_total_secs: req.max_total_secs,
        schedule_id: String::new(),
    };
    scheduler.create(&req.name, &params, trigger).await;
    Ok(Json(scheduler.list_views().await))
}

async fn schedule_concurrency_get(State(state): State<AppState>) -> Json<usize> {
    Json(state.scheduler.as_ref().map_or(0, |s| s.max_concurrent()))
}

#[derive(Debug, Deserialize)]
struct ConcurrencyRequest {
    max_concurrent: usize,
}

async fn schedule_concurrency_set(
    State(state): State<AppState>,
    Json(req): Json<ConcurrencyRequest>,
) -> Json<usize> {
    match &state.scheduler {
        Some(s) => {
            s.set_max_concurrent(req.max_concurrent);
            Json(s.max_concurrent())
        }
        None => Json(0),
    }
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

#[derive(Debug, Deserialize)]
struct ConfigTomlToValueRequest {
    content: String,
}

async fn config_toml_to_value(
    State(_): State<AppState>,
    Json(req): Json<ConfigTomlToValueRequest>,
) -> ApiResult<serde_json::Value> {
    let value =
        hf_service::config::toml_to_json(&req.content).map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(value))
}

#[derive(Debug, Deserialize)]
struct ConfigValueToTomlRequest {
    value: serde_json::Value,
}

async fn config_value_to_toml(
    State(_): State<AppState>,
    Json(req): Json<ConfigValueToTomlRequest>,
) -> ApiResult<String> {
    let toml =
        hf_service::config::json_to_toml(&req.value).map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(toml))
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
