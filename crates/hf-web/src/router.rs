//! Axum router with REST endpoints + SSE streaming.
//!
//! Mirrors the `y-web` pattern: routes are grouped, SSE events are broadcast
//! via a `tokio::sync::broadcast` channel, and the router matches the
//! `httpTransport.ts` `COMMAND_MAP` used by the web-mode frontend.

use axum::extract::{Json, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::broadcast;

use hf_service::{EngineKind, Message, Role, ServiceContainer, SessionId, TargetLanguage};

use crate::security::{redact_config_text, redact_public_json};
use crate::WebSecurityConfig;

const SSE_CHANNEL_CAPACITY: usize = 256;
const MAX_SSE_EVENT_BYTES: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// AppState
// ---------------------------------------------------------------------------

/// Shared application state injected into every handler via axum `State`.
#[derive(Clone)]
pub struct AppState {
    pub container: ServiceContainer,
    event_tx: broadcast::Sender<SseEvent>,
    security: WebSecurityConfig,
    /// Campaign scheduler, when started (present in `build_bootstrapped`, absent
    /// in bare test states). Schedule endpoints degrade to empty results when
    /// `None`.
    pub scheduler: Option<std::sync::Arc<hf_service::scheduler::CampaignScheduler>>,
}

impl AppState {
    /// Create a new `AppState` with a service container (no scheduler).
    #[must_use]
    pub fn new(container: ServiceContainer) -> Self {
        let (event_tx, _) = broadcast::channel(SSE_CHANNEL_CAPACITY);
        Self {
            container,
            event_tx,
            security: WebSecurityConfig::deny_all(),
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

    /// Publish one bounded SSE event.
    ///
    /// The event is serialized before entering the broadcast channel so a
    /// single malformed log line cannot consume unbounded memory per receiver.
    /// A missing receiver is not an error: producers may emit before a browser
    /// subscribes.
    ///
    /// # Errors
    /// Returns [`PublishEventError`] when the serialized event exceeds the
    /// transport limit.
    pub fn publish_event(&self, event: SseEvent) -> Result<(), PublishEventError> {
        let mut size_writer = EventSizeWriter::new(MAX_SSE_EVENT_BYTES);
        if serde_json::to_writer(&mut size_writer, &event).is_err() {
            if size_writer.exceeded {
                return Err(PublishEventError::TooLarge {
                    size: size_writer.size,
                    limit: MAX_SSE_EVENT_BYTES,
                });
            }
            return Err(PublishEventError::Serialization);
        }
        let _ = self.event_tx.send(event);
        Ok(())
    }
}

struct EventSizeWriter {
    size: usize,
    limit: usize,
    exceeded: bool,
}

impl EventSizeWriter {
    fn new(limit: usize) -> Self {
        Self {
            size: 0,
            limit,
            exceeded: false,
        }
    }
}

impl std::io::Write for EventSizeWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.size = self.size.saturating_add(bytes.len());
        if self.size > self.limit {
            self.exceeded = true;
            return Err(std::io::Error::other("SSE event exceeds size limit"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Failure to enqueue a bounded SSE event.
#[derive(Debug, thiserror::Error)]
pub enum PublishEventError {
    /// The event could not be serialized.
    #[error("SSE event could not be serialized")]
    Serialization,
    /// The event exceeded the per-message transport limit.
    #[error("SSE event is {size} bytes; limit is {limit} bytes")]
    TooLarge { size: usize, limit: usize },
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
        /// Durable service-owned run id, when the producer has one.
        #[serde(skip_serializing_if = "Option::is_none")]
        run_id: Option<String>,
        kind: String,
        data: serde_json::Value,
    },
    /// `run:status` -- one run changed lifecycle state.
    RunStatus { run_id: String, status: String },
    /// `docker:status` -- Docker daemon / sandbox image build progress.
    DockerStatus { message: String },
    /// `stream:lagged` -- this subscriber fell behind the bounded channel.
    StreamLagged { dropped: u64 },
}

impl SseEvent {
    fn event_name(&self) -> &'static str {
        match self {
            SseEvent::RunProgress { .. } => "run:progress",
            SseEvent::RunStatus { .. } => "run:status",
            SseEvent::DockerStatus { .. } => "docker:status",
            SseEvent::StreamLagged { .. } => "stream:lagged",
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
type ApiError = (StatusCode, Json<ErrorResponse>);

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
    build_bootstrapped_with_security(WebSecurityConfig::from_env()).await
}

/// Build the production router with one already-resolved security policy.
///
/// The CLI uses this after validating its bind address, ensuring the socket
/// check and router authentication use the exact same immutable policy.
pub async fn build_bootstrapped_with_security(security: WebSecurityConfig) -> Router {
    let container = ServiceContainer::bootstrap().await;
    // Start the campaign scheduler so headless schedules fire and the schedule
    // endpoints are live (mirrors the desktop shell). Schedules persist under
    // the user data dir so they survive restarts.
    let store_path = hf_service::init::user_app_dir().join("schedules.json");
    let scheduler = std::sync::Arc::new(
        hf_service::scheduler::CampaignScheduler::start(container.clone(), store_path, None).await,
    );
    build_with_state_and_security(AppState::new(container).with_scheduler(scheduler), security)
}

/// Build the router with a given `AppState` (for testing or custom containers).
pub fn build_with_state(state: AppState) -> Router {
    let security = WebSecurityConfig::from_env();
    build_with_state_and_security(state, security)
}

/// Build the router with an explicit immutable security policy.
///
/// This is useful for an embedding server and keeps tests independent of
/// process-global environment mutation.
pub fn build_with_state_and_security(mut state: AppState, security: WebSecurityConfig) -> Router {
    state.security = security;
    match (
        state.security.token_configured(),
        state.security.allows_open_access(),
    ) {
        (true, _) => tracing::info!("hf-web: bearer-token auth enabled"),
        (false, true) => tracing::warn!(
            "hf-web: HF_WEB_TOKEN is not set and HF_WEB_TOKEN_OPTIONAL=1 -- \
             the API is UNAUTHENTICATED (local-dev mode)."
        ),
        (false, false) => tracing::warn!(
            "hf-web: HF_WEB_TOKEN is not set -- the API is FAIL-CLOSED and will \
             reject every request except /health with 401. Set HF_WEB_TOKEN to \
             require an Authorization: Bearer <token> header, or set \
             HF_WEB_TOKEN_OPTIONAL=1 to allow unauthenticated local-dev access."
        ),
    }
    tracing::info!(
        approved_project_roots = state.security.project_root_count(),
        "hf-web project path policy loaded"
    );
    let security = state.security.clone();
    let cors = state.security.cors_layer();
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
        .route("/runs/start", post(run_start_unavailable))
        .route("/runs/{id}/status", get(run_status))
        .route("/runs/{id}/cancel", post(cancel_run_by_id))
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
        .route("/diagnostics/cost", get(diagnostics_cost_summary))
        .route("/system/snapshot", get(system_snapshot))
        .route("/system/status", get(system_status))
        .route("/workbench/dashboard", post(workbench_dashboard))
        .route("/workbench/harnesses", post(harness_review_queue))
        .route("/gitlab/issue", post(issue_export))
        .route("/issues/export", post(issue_export))
        .route("/issues/file", post(file_issue))
        .route("/issues/configured", get(issue_tracker_configured))
        .route("/issues/test", get(issue_tracker_test))
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
            let security = security.clone();
            async move { auth_audit(security, req, next).await }
        }))
        .layer(cors)
        .with_state(state)
}

/// Bearer-token auth + request audit middleware.
///
/// Enforces [`AuthPolicy`]: with a token configured, every request except
/// `/health` must carry a matching `Authorization: Bearer <token>` header.
/// With no token configured the API is fail-closed (rejects everything but
/// `/health`) unless `HF_WEB_TOKEN_OPTIONAL=1`. Every request is logged
/// (method + path) as a lightweight audit trail.
async fn auth_audit(
    security: WebSecurityConfig,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();

    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            (scheme.eq_ignore_ascii_case("Bearer")
                && !token.is_empty()
                && !token.chars().any(char::is_whitespace))
            .then_some(token)
        });

    if !security.origin_allowed(
        req.headers().get(header::ORIGIN),
        req.headers().get(header::HOST),
    ) {
        tracing::warn!(%method, %path, "hf-web: rejected cross-origin request");
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "origin not allowed".to_owned(),
            }),
        )
            .into_response();
    }

    if !security.auth.authorize(&path, presented) {
        tracing::warn!(%method, %path, "hf-web: rejected unauthorized request");
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"))],
            Json(ErrorResponse {
                error: "unauthorized".to_owned(),
            }),
        )
            .into_response();
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

fn approved_project(state: &AppState, requested: &std::path::Path) -> Result<PathBuf, ApiError> {
    state
        .security
        .approve_project(requested)
        .map_err(map_err(StatusCode::FORBIDDEN))
}

fn approved_optional_project(
    state: &AppState,
    requested: Option<&String>,
) -> Result<Option<PathBuf>, ApiError> {
    requested
        .filter(|path| !path.is_empty())
        .map(|path| approved_project(state, std::path::Path::new(path)))
        .transpose()
}

fn public_value<T: Serialize>(value: T) -> serde_json::Value {
    redact_public_json(serde_json::to_value(value).unwrap_or(serde_json::Value::Null))
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
    let project = approved_project(&state, &req.project)?;
    let inv = state
        .container
        .discover(&project, lang)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(public_value(inv)))
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
    let project = approved_project(&state, &req.project)?;
    let lang = match req.lang.as_deref() {
        Some(l) => parse_lang(l).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    let draft = state
        .container
        .harness_draft(&project, &req.target, engine, lang)
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
    let project = approved_project(&state, &req.project)?;
    let lang = match req.lang.as_deref() {
        Some(l) => parse_lang(l).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    match state
        .container
        .harness_compile(req.source, &project, engine, &req.target, lang)
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
    let project = approved_project(&state, &req.project)?;
    let lang = match req.lang.as_deref() {
        Some(value) => parse_lang(value).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    let smoke = state
        .container
        .harness_smoke(&project, &req.target, engine, lang)
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
    let project = approved_project(&state, &req.project)?;
    let harness = state
        .container
        .harness_promote(&project, &req.target, engine)
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
    let project = approved_optional_project(&state, req.project.as_ref())?;
    Ok(Json(public_value(
        state.container.run_history(project.as_deref()).await,
    )))
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

async fn run_start_unavailable() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorResponse {
            error: "run start requires a service-owned durable run handle; use the CLI or desktop until that service contract is available".to_owned(),
        }),
    )
}

async fn run_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let run_id = uuid::Uuid::parse_str(&id).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let item = state
        .container
        .run_history(None)
        .await
        .into_iter()
        .find(|run| run.id == run_id.to_string())
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "run not found".to_owned(),
                }),
            )
        })?;
    let mut value = public_value(item);
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "active".to_owned(),
            serde_json::Value::Bool(state.container.active_run_ids().contains(&run_id)),
        );
    }
    Ok(Json(value))
}

async fn cancel_run_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let run_id = uuid::Uuid::parse_str(&id).map_err(map_err(StatusCode::BAD_REQUEST))?;
    if !state.container.cancel_run(run_id) {
        return Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "run is not active".to_owned(),
            }),
        ));
    }
    let _ = state.publish_event(SseEvent::RunStatus {
        run_id: run_id.to_string(),
        status: "cancellation_requested".to_owned(),
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "run_id": run_id,
            "accepted": true,
        })),
    ))
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let over = state.container.project_auto_revert_override(&project).await;
    Ok(Json(public_value(over)))
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
    let requested = req.project.filter(|path| !path.is_empty());
    let project = approved_optional_project(&state, requested.as_ref())?;
    let events = state
        .container
        .auto_revert_events(project.as_deref(), req.limit.unwrap_or(200))
        .await;
    Ok(Json(public_value(events)))
}

async fn effective_auto_revert_policy(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let view = state.container.effective_auto_revert_view(&project).await;
    Ok(Json(public_value(view)))
}

async fn project_auto_revert_overrides(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(public_value(
        state.container.project_auto_revert_overrides().await,
    )))
}

async fn set_project_auto_revert_override(
    State(state): State<AppState>,
    Json(req): Json<SetProjectAutoRevertRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    state
        .container
        .set_project_auto_revert_override(&project, req.enabled, req.threshold_pct, req.notify_only)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn clear_project_auto_revert_override(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    state
        .container
        .clear_project_auto_revert_override(&project)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn all_crashes(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let crashes = state.container.all_crashes().await;
    Ok(Json(public_value(crashes)))
}

async fn all_corpus(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let entries = state.container.all_corpus_entries().await;
    Ok(Json(public_value(entries)))
}

async fn export_project_data(
    State(state): State<AppState>,
    Json(req): Json<ExportProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_optional_project(&state, req.project.as_ref())?;
    Ok(Json(public_value(
        state
            .container
            .export_project_data(project.as_deref())
            .await,
    )))
}

#[derive(Debug, Deserialize)]
struct ExportProjectRequest {
    project: Option<String>,
}

async fn generate_seeds(
    State(state): State<AppState>,
    Json(req): Json<GenerateSeedsRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let entries = state
        .container
        .generate_seeds(&project, &req.target)
        .await
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let lang = match req.lang.as_deref() {
        Some(l) => parse_lang(l).map_err(map_err(StatusCode::BAD_REQUEST))?,
        None => TargetLanguage::C,
    };
    // The service clamps the count to a sane range; default when unspecified.
    let count = req.count.unwrap_or(12);
    let entries = state
        .container
        .generate_seeds_llm(&project, &req.target, lang, count)
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    match op.as_str() {
        "list" => {
            let corpus = state
                .container
                .corpus_list(&project, &req.target)
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(public_value(corpus.entries)))
        }
        "seed" => {
            let n = state
                .container
                .corpus_seed(&project, &req.target)
                .await
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(serde_json::json!({"seeded": n})))
        }
        "grow" => {
            let n = state
                .container
                .corpus_grow(&project, &req.target)
                .await
                .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
            Ok(Json(serde_json::json!({"entries": n})))
        }
        "prune" => {
            let n = state
                .container
                .corpus_prune(&project, &req.target)
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let deduped = state
        .container
        .triage(&project, &req.target)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(public_value(deduped)))
}

async fn system_snapshot(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let snapshot = state
        .container
        .system_snapshot()
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(public_value(snapshot)))
}

async fn diagnostics_cost_summary(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let summary = state
        .container
        .cost_summary()
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(public_value(summary)))
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

fn opt_target(target: Option<&String>) -> Option<&str> {
    target.filter(|t| !t.is_empty()).map(String::as_str)
}

async fn workbench_dashboard(
    State(state): State<AppState>,
    Json(req): Json<WorkbenchRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_optional_project(&state, req.project.as_ref())?;
    Ok(Json(public_value(
        state
            .container
            .workbench_dashboard(project.as_deref(), opt_target(req.target.as_ref()))
            .await,
    )))
}

async fn harness_review_queue(
    State(state): State<AppState>,
    Json(req): Json<WorkbenchRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_optional_project(&state, req.project.as_ref())?;
    Ok(Json(public_value(
        state
            .container
            .harness_review_queue(project.as_deref(), opt_target(req.target.as_ref()))
            .await,
    )))
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    Ok(Json(
        state.container.artifact_summary(&project, &req.target),
    ))
}

#[derive(Debug, Deserialize)]
struct IssueExportRequest {
    project: String,
    crash_id: String,
}

async fn issue_export(
    State(state): State<AppState>,
    Json(req): Json<IssueExportRequest>,
) -> ApiResult<hf_service::IssueExport> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let export = state
        .container
        .issue_export(&project, &req.crash_id)
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(export))
}

#[derive(Debug, Deserialize)]
struct FileIssueRequest {
    crash_id: String,
}

async fn file_issue(
    State(state): State<AppState>,
    Json(req): Json<FileIssueRequest>,
) -> ApiResult<hf_service::CreatedIssue> {
    let created = state
        .container
        .file_issue(&req.crash_id)
        .await
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(created))
}

async fn issue_tracker_configured(State(state): State<AppState>) -> Json<bool> {
    Json(state.container.issue_tracker_configured())
}

async fn issue_tracker_test(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .issue_tracker_test_connection()
        .await
        .map(|()| Json(true))
        .map_err(map_err(StatusCode::BAD_REQUEST))
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let outcome = state
        .container
        .push_to_defectdojo(&project, req.target.as_deref())
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

async fn list_report_drafts(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let reports = state
        .container
        .list_report_drafts()
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(public_value(reports)))
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
) -> ApiResult<serde_json::Value> {
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
    Ok(Json(public_value(report)))
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    state
        .container
        .delete_project(&project)
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let doc = state
        .container
        .export_sarif(&project, &req.target)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(doc))
}

async fn report(
    State(state): State<AppState>,
    Json(req): Json<TriageRequest>,
) -> ApiResult<String> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let markdown = state
        .container
        .generate_report(&project, &req.target)
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
    display_message: Option<String>,
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
    let requested = req.project.filter(|path| !path.is_empty());
    let project = approved_optional_project(&state, requested.as_ref())?;
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
                display_message: req.display_message,
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
) -> ApiResult<Option<String>> {
    let id = state
        .container
        .create_chat_session(req.title)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(id))
}

#[derive(Debug, Deserialize)]
struct SessionRequest {
    session_id: String,
}

async fn chat_history(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<Vec<Message>> {
    let id = SessionId(req.session_id);
    let history = state
        .container
        .chat_history(&id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(history))
}

async fn delete_session(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<bool> {
    let id = SessionId(req.session_id);
    let deleted = state
        .container
        .delete_chat_session(&id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(deleted))
}

async fn chat_rollback(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<usize> {
    let id = SessionId(req.session_id);
    let removed = state
        .container
        .chat_rollback_last(&id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(removed))
}

#[derive(Debug, Deserialize)]
struct RollbackToRequest {
    session_id: String,
    checkpoint_id: String,
}

async fn chat_rollback_to(
    State(state): State<AppState>,
    Json(req): Json<RollbackToRequest>,
) -> ApiResult<usize> {
    let id = SessionId(req.session_id);
    let removed = state
        .container
        .chat_rollback_to(&id, &req.checkpoint_id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(removed))
}

async fn chat_checkpoints(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<Vec<hf_service::checkpoints::CheckpointView>> {
    let id = SessionId(req.session_id);
    let checkpoints = state
        .container
        .chat_checkpoints(&id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(checkpoints))
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
) -> ApiResult<String> {
    let id = SessionId(req.session_id);
    let branch = state
        .container
        .chat_branch(
            &id,
            req.fork_message_count,
            req.title.filter(|t| !t.is_empty()),
        )
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(branch))
}

async fn chat_branches(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<Vec<hf_service::checkpoints::BranchView>> {
    let id = SessionId(req.session_id);
    let branches = state
        .container
        .chat_branches(&id)
        .await
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(branches))
}

// -- Knowledge base --------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ProjectRequest {
    project: String,
}

async fn knowledge_index(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<hf_service::knowledge::KnowledgeStats> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let knowledge_stats = hf_service::knowledge::index_project(&project)
        .map_err(map_err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(knowledge_stats))
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
    let (project, document) = state
        .security
        .approve_document(
            std::path::Path::new(&req.project),
            std::path::Path::new(&req.file),
        )
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    let ingested = state
        .container
        .ingest_document(&project, &document)
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
    State(state): State<AppState>,
    Json(req): Json<KnowledgeSearchRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    // Index-on-demand so a server restarted since the last `index` call does not
    // silently return nothing. The tree walk is blocking, so run it off the
    // async runtime.
    let hits = tokio::task::spawn_blocking(move || {
        hf_service::knowledge::search_project_ensured(&project, &req.query, req.limit.unwrap_or(10))
    })
    .await
    .unwrap_or_default();
    Ok(Json(public_value(hits)))
}

// -- Campaign scheduling ---------------------------------------------------
//
// Endpoints degrade to empty results when no scheduler is attached (e.g. a
// bare test state).

async fn schedule_list(State(state): State<AppState>) -> Json<serde_json::Value> {
    let views = match &state.scheduler {
        Some(scheduler) => scheduler.list_views().await,
        None => Vec::new(),
    };
    Json(public_value(views))
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn schedule_history(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<HistoryQuery>,
) -> Json<serde_json::Value> {
    let views = match &state.scheduler {
        Some(scheduler) => scheduler.recent_executions(q.limit.unwrap_or(20)).await,
        None => Vec::new(),
    };
    Json(public_value(views))
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
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    state
        .container
        .schedulable_targets(&project)
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
) -> ApiResult<serde_json::Value> {
    let Some(scheduler) = &state.scheduler else {
        return Ok(Json(serde_json::json!([])));
    };
    let trigger = hf_service::scheduler::parse_trigger(&req.trigger_kind, &req.trigger_value)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let params = hf_service::scheduler::CampaignParams {
        project: project.to_string_lossy().into_owned(),
        target: req.target.filter(|t| !t.is_empty()),
        engine: req.engine,
        lang: req.lang,
        duration_secs: req.duration_secs,
        max_runs: req.max_runs,
        max_total_secs: req.max_total_secs,
        schedule_id: String::new(),
    };
    scheduler.create(&req.name, &params, trigger).await;
    Ok(Json(public_value(scheduler.list_views().await)))
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
) -> Json<serde_json::Value> {
    match &state.scheduler {
        Some(s) => {
            s.remove(&id).await;
            Json(public_value(s.list_views().await))
        }
        None => Json(serde_json::json!([])),
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
) -> Json<serde_json::Value> {
    match &state.scheduler {
        Some(s) => {
            s.set_enabled(&id, req.enabled).await;
            Json(public_value(s.list_views().await))
        }
        None => Json(serde_json::json!([])),
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
    let redacted = redact_config_text(&content).map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(redacted))
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
    if req.content.contains("<redacted>") || req.content.contains("<redacted-path>") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "redaction markers cannot be written; supply a new value or edit through the trusted desktop settings".to_owned(),
            }),
        ));
    }
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
    let providers = hf_service::config::get_providers()
        .into_iter()
        .map(|provider| {
            let api_key_configured = provider
                .api_key
                .as_ref()
                .is_some_and(|value| !value.is_empty())
                || provider
                    .api_key_env
                    .as_ref()
                    .is_some_and(|value| !value.is_empty());
            let headers_configured = !provider.headers.is_empty();
            let mut value = public_value(provider);
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "api_key_configured".to_owned(),
                    serde_json::Value::Bool(api_key_configured),
                );
                object.insert(
                    "headers_configured".to_owned(),
                    serde_json::Value::Bool(headers_configured),
                );
            }
            value
        })
        .collect();
    Json(serde_json::Value::Array(providers))
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SetProvidersRequest {
    Wrapped {
        providers: Vec<hf_service::config::ProviderConfig>,
    },
    Bare(Vec<hf_service::config::ProviderConfig>),
}

impl SetProvidersRequest {
    fn into_providers(self) -> Vec<hf_service::config::ProviderConfig> {
        match self {
            Self::Wrapped { providers } | Self::Bare(providers) => providers,
        }
    }
}

async fn set_providers(
    State(state): State<AppState>,
    Json(req): Json<SetProvidersRequest>,
) -> ApiResult<()> {
    let providers = req.into_providers();
    hf_service::config::set_providers_preserving_secrets(&providers)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    // Apply the new providers to the live pool so the change takes effect without
    // restarting the server.
    state.container.reload_providers();
    Ok(Json(()))
}

// -- System endpoints ------------------------------------------------------

async fn app_paths(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(public_value(hf_service::config::app_paths()))
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
                    let event = SseEvent::StreamLagged { dropped: n };
                    if let Ok(json) = serde_json::to_string(&event) {
                        yield Ok::<_, std::convert::Infallible>(
                            Event::default().event(event.event_name()).data(json),
                        );
                    }
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
mod request_tests {
    use super::SetProvidersRequest;

    #[test]
    fn provider_write_accepts_the_browser_transport_wrapper() {
        let request: SetProvidersRequest =
            serde_json::from_str(r#"{"providers":[]}"#).expect("wrapped provider request");
        assert!(request.into_providers().is_empty());
    }
}
