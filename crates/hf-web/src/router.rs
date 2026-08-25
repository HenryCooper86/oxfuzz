//! Axum router with REST endpoints + SSE streaming.
//!
//! Mirrors the `y-web` pattern: routes are grouped, SSE events are broadcast
//! via a `tokio::sync::broadcast` channel, and the router matches the
//! `httpTransport.ts` `COMMAND_MAP` used by the web-mode frontend.

#[cfg(feature = "automotive-scapy")]
use axum::extract::Query;
use axum::extract::{Json, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::broadcast;

use hf_service::scheduler::{CampaignSchedulerError, RecoveryPublicError, RecoveryPublicErrorCode};
use hf_service::{
    ClassifiedError, EngineKind, FuzzProgress, Message, Role, RunCancelOutcome, RunLifecycleStatus,
    ServiceContainer, SessionId, TargetLanguage,
};

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
    integration_configs: hf_service::config::IntegrationConfigStore,
    #[cfg(feature = "automotive-scapy")]
    automotive_configs: hf_service::config::AutomotiveConfigStore,
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
            integration_configs: hf_service::config::IntegrationConfigStore::default(),
            #[cfg(feature = "automotive-scapy")]
            automotive_configs: hf_service::config::AutomotiveConfigStore::default(),
            scheduler: None,
        }
    }

    /// Use an isolated directory for typed integration configuration.
    ///
    /// Production uses the service-resolved config directory. Tests and
    /// embedders can override it without mutating process-global environment.
    #[must_use]
    pub fn with_integration_config_dir(mut self, directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        self.integration_configs =
            hf_service::config::IntegrationConfigStore::new(directory.clone());
        #[cfg(feature = "automotive-scapy")]
        {
            self.automotive_configs = hf_service::config::AutomotiveConfigStore::new(directory);
        }
        self
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
    /// `stream:lagged` -- this subscriber fell behind the bounded channel.
    StreamLagged { dropped: u64 },
}

impl SseEvent {
    fn event_name(&self) -> &'static str {
        match self {
            SseEvent::RunProgress { .. } => "run:progress",
            SseEvent::RunStatus { .. } => "run:status",
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

#[derive(Debug, Serialize)]
struct RecoveryErrorResponse {
    code: RecoveryPublicErrorCode,
    error: &'static str,
}

type ApiResult<T> = Result<Json<T>, (StatusCode, Json<ErrorResponse>)>;
type ApiError = (StatusCode, Json<ErrorResponse>);
type RecoveryApiResult<T> = Result<Json<T>, (StatusCode, Json<RecoveryErrorResponse>)>;
type RecoveryApiError = (StatusCode, Json<RecoveryErrorResponse>);

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

fn classified_api_error(error: impl Into<ClassifiedError>) -> ApiError {
    let error = error.into();
    let message = error.to_string();
    let status = match &error {
        ClassifiedError::Validation(_) => StatusCode::BAD_REQUEST,
        ClassifiedError::Harness(_) | ClassifiedError::Engine(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        ClassifiedError::Provider(_) => StatusCode::BAD_GATEWAY,
        ClassifiedError::Sandbox(_) => StatusCode::SERVICE_UNAVAILABLE,
        ClassifiedError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        ClassifiedError::Storage(_) | ClassifiedError::Internal(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    (status, Json(ErrorResponse { error: message }))
}

fn scheduler_api_error(error: CampaignSchedulerError) -> ApiError {
    match error {
        CampaignSchedulerError::OccurrenceNotFound(message) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse { error: message }),
        ),
        CampaignSchedulerError::OccurrenceConflict(message) => {
            (StatusCode::CONFLICT, Json(ErrorResponse { error: message }))
        }
        CampaignSchedulerError::DurabilityUnavailable(message) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse { error: message }),
        ),
        other => classified_api_error(other),
    }
}

fn recovery_api_error(public: RecoveryPublicError) -> RecoveryApiError {
    let status = match public.code {
        RecoveryPublicErrorCode::NotFound => StatusCode::NOT_FOUND,
        RecoveryPublicErrorCode::Conflict => StatusCode::CONFLICT,
        RecoveryPublicErrorCode::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        RecoveryPublicErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(RecoveryErrorResponse {
            code: public.code,
            error: public.message,
        }),
    )
}

fn scheduler_recovery_api_error(error: CampaignSchedulerError) -> RecoveryApiError {
    recovery_api_error(error.into_public_recovery_error())
}

fn missing_schedule_error(id: &str) -> ApiError {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: format!("no scheduled campaign with id '{id}'"),
        }),
    )
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
///
/// # Errors
/// Returns a scheduler-state error when persisted campaign definitions or
/// execution history cannot be loaded safely.
pub async fn build_bootstrapped() -> Result<Router, hf_service::scheduler::CampaignSchedulerError> {
    build_bootstrapped_with_security(WebSecurityConfig::from_env()).await
}

/// Build the production router with one already-resolved security policy.
///
/// The CLI uses this after validating its bind address, ensuring the socket
/// check and router authentication use the exact same immutable policy.
///
/// # Errors
/// Returns a scheduler-state error when persisted campaign definitions or
/// execution history cannot be loaded safely.
pub async fn build_bootstrapped_with_security(
    security: WebSecurityConfig,
) -> Result<Router, hf_service::scheduler::CampaignSchedulerError> {
    let container = ServiceContainer::bootstrap().await;
    // Start the campaign scheduler so headless schedules fire and the schedule
    // endpoints are live (mirrors the desktop shell). Schedules persist under
    // the user data dir so they survive restarts.
    let store_path = hf_service::init::user_app_dir().join("schedules.json");
    let scheduler = std::sync::Arc::new(
        hf_service::scheduler::CampaignScheduler::try_start(container.clone(), store_path, None)
            .await?,
    );
    Ok(build_with_state_and_security(
        AppState::new(container).with_scheduler(scheduler),
        security,
    ))
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
        .route("/semgrep/available", get(semgrep_available))
        .route("/harness/draft", post(harness_draft))
        .route("/harness/compile", post(harness_compile))
        .route("/harness/smoke", post(harness_smoke))
        .route("/harness/promote", post(harness_promote))
        .route("/artifacts/summary", post(artifact_summary))
        .route("/seeds/generate", post(generate_seeds))
        .route("/seeds/generate-llm", post(generate_seeds_llm))
        .route("/corpus/{op}", post(corpus))
        .route("/triage", post(triage))
        .route("/crash/verify", post(verify_crash))
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
        .route("/runs/start", post(run_start))
        .route("/runs/{id}/status", get(run_status))
        .route("/runs/{id}/cancel", post(cancel_run_by_id))
        .merge(proof_carrying_routes())
        .merge(patch_to_proof_routes())
        .merge(change_aware_routes())
        .merge(semgrep_routes())
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
        .route("/policy/decisions", get(policy_decisions))
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
        .route("/providers/{id}/thaw", post(provider_thaw))
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
        .route("/agents", get(list_agents))
        .route("/agents/info", get(agent_info))
        .route("/agents/tools", get(agent_tools))
        .route("/agents/read", post(get_agent))
        .route("/agents/save", post(save_agent))
        .route("/agents/delete", post(delete_agent))
        .route("/skills", get(list_skills))
        .route("/skills/read", post(read_skill))
        .route("/skills/save", post(save_skill))
        .route("/skills/delete", post(delete_skill))
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
        .route("/knowledge/stats", get(knowledge_stats))
        // Campaign scheduling.
        .route("/schedule", get(schedule_list).post(schedule_create))
        .route("/schedule/recovery", get(schedule_recovery_list))
        .route(
            "/schedule/arm",
            get(schedule_arm_get).post(schedule_arm).delete(schedule_disarm),
        )
        .route(
            "/schedule/recovery/{occurrence_id}/acknowledge",
            post(schedule_recovery_acknowledge),
        )
        .route("/schedule/history", get(schedule_history))
        .route("/schedule/history/clear", post(schedule_history_clear))
        .route("/schedule/targets", post(schedule_targets))
        .route(
            "/schedule/concurrency",
            get(schedule_concurrency_get).post(schedule_concurrency_set),
        )
        .route(
            "/schedule/concurrency/limits",
            get(schedule_concurrency_limits),
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
        .route("/config/fuzzing", get(get_fuzzing_settings))
        .route(
            "/config/defectdojo",
            get(get_defectdojo_config).patch(patch_defectdojo_config),
        )
        .route(
            "/config/issue-tracker",
            get(get_issue_tracker_config).patch(patch_issue_tracker_config),
        )
        .route("/system/paths", get(app_paths))
        .route("/system/arch", get(host_arch))
        .route("/events", get(event_stream))
        .merge(automotive_routes())
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

#[cfg(feature = "automotive-scapy")]
fn automotive_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/config/automotive",
            get(get_automotive_settings)
                .post(set_automotive_settings)
                .put(set_automotive_settings),
        )
        .route("/automotive/capabilities", post(automotive_capabilities))
        .route(
            "/automotive/analyze-capture",
            post(automotive_analyze_capture),
        )
        .route("/automotive/analyze", post(automotive_analyze_capture))
        .route(
            "/automotive/import-capture",
            post(automotive_import_capture),
        )
        .route("/automotive/diff-captures", post(automotive_diff_captures))
        .route("/automotive/mutations", post(automotive_generate_mutations))
        .route(
            "/automotive/replay-plan",
            post(automotive_build_replay_plan),
        )
        .route("/automotive/replay", post(automotive_execute_replay))
        .route("/automotive/report", post(generate_automotive_report))
        .route(
            "/automotive/operations",
            get(list_automotive_operations_query).post(list_automotive_operations),
        )
}

#[cfg(not(feature = "automotive-scapy"))]
fn automotive_routes() -> Router<AppState> {
    Router::new()
}

#[cfg(feature = "proof-carrying")]
fn proof_carrying_routes() -> Router<AppState> {
    Router::new()
        .route("/campaign/advice", post(campaign_advice))
        .route("/campaign/evidence", post(campaign_evidence))
        .route("/remediation/draft", post(remediation_draft))
}

#[cfg(not(feature = "proof-carrying"))]
fn proof_carrying_routes() -> Router<AppState> {
    Router::new()
}

#[cfg(feature = "patch-to-proof")]
fn patch_to_proof_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/remediation/operations",
            post(remediation_operation_create),
        )
        .route(
            "/remediation/operations/{id}/approve",
            post(remediation_operation_approve),
        )
        .route(
            "/remediation/operations/{id}/verify",
            post(remediation_operation_verify),
        )
        .route(
            "/remediation/operations/{id}",
            get(remediation_operation_get),
        )
        .route(
            "/findings/{id}/proof-card",
            get(finding_proof_card_for_crash),
        )
}

#[cfg(not(feature = "patch-to-proof"))]
fn patch_to_proof_routes() -> Router<AppState> {
    Router::new()
}

#[cfg(feature = "change-aware")]
fn change_aware_routes() -> Router<AppState> {
    Router::new()
        .route("/change/impact", post(change_impact))
        .route("/change/compare", post(change_compare))
        .route("/change/publish", post(change_publish))
}

#[cfg(not(feature = "change-aware"))]
fn change_aware_routes() -> Router<AppState> {
    Router::new()
}

#[cfg(feature = "semgrep-enrichment")]
fn semgrep_routes() -> Router<AppState> {
    Router::new()
        .route("/semgrep/enrich", post(semgrep_start))
        .route("/semgrep/enrich/{id}", get(semgrep_status))
        .route("/semgrep/enrich/{id}/cancel", post(semgrep_cancel))
}

#[cfg(not(feature = "semgrep-enrichment"))]
fn semgrep_routes() -> Router<AppState> {
    Router::new()
}

/// Bearer-token auth + request audit middleware.
///
/// Enforces [`crate::security::AuthPolicy`]: with a token configured, every request except
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

async fn semgrep_available() -> Json<bool> {
    // The Semgrep journal needs descriptor-relative advisory locks and fails
    // closed as Unsupported off unix, so the capability is only real where
    // both the feature and the platform support it. Reporting the feature flag
    // alone would advertise an operation Windows hosts can never complete.
    Json(cfg!(all(feature = "semgrep-enrichment", unix)))
}

#[cfg(feature = "semgrep-enrichment")]
#[derive(Debug, Deserialize)]
struct SemgrepStartRequest {
    project: PathBuf,
    #[serde(alias = "language")]
    lang: String,
}

#[cfg(feature = "semgrep-enrichment")]
#[derive(Debug, Serialize)]
struct SemgrepStartResponse {
    operation_id: uuid::Uuid,
    state: hf_service::SemgrepOperationState,
}

#[cfg(feature = "semgrep-enrichment")]
async fn semgrep_start(
    State(state): State<AppState>,
    Json(request): Json<SemgrepStartRequest>,
) -> Result<(StatusCode, Json<SemgrepStartResponse>), ApiError> {
    let language = request
        .lang
        .parse::<TargetLanguage>()
        .map_err(|error| classified_api_error(ClassifiedError::Validation(error)))?;
    let project = approved_project(&state, &request.project)?;
    let operation_id = state
        .container
        .start_semgrep_enrichment(project, language)
        .await
        .map_err(classified_api_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SemgrepStartResponse {
            operation_id,
            state: hf_service::SemgrepOperationState::Staging,
        }),
    ))
}

#[cfg(feature = "semgrep-enrichment")]
async fn semgrep_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<hf_service::SemgrepOperationView> {
    let operation_id = uuid::Uuid::parse_str(&id).map_err(|error| {
        classified_api_error(ClassifiedError::Validation(format!(
            "invalid Semgrep operation id: {error}"
        )))
    })?;
    let operation = state
        .container
        .semgrep_operation(operation_id)
        .await
        .map_err(classified_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "Semgrep operation not found".to_owned(),
                }),
            )
        })?;
    Ok(Json(operation))
}

#[cfg(feature = "semgrep-enrichment")]
async fn semgrep_cancel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<hf_service::SemgrepCancelOutcome>), ApiError> {
    let operation_id = uuid::Uuid::parse_str(&id).map_err(|error| {
        classified_api_error(ClassifiedError::Validation(format!(
            "invalid Semgrep operation id: {error}"
        )))
    })?;
    match state
        .container
        .request_semgrep_cancel(operation_id)
        .await
        .map_err(classified_api_error)?
    {
        hf_service::SemgrepCancelOutcome::Accepted => Ok((
            StatusCode::ACCEPTED,
            Json(hf_service::SemgrepCancelOutcome::Accepted),
        )),
        hf_service::SemgrepCancelOutcome::Inactive => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "Semgrep operation is not active".to_owned(),
            }),
        )),
        hf_service::SemgrepCancelOutcome::NotFound => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Semgrep operation not found".to_owned(),
            }),
        )),
    }
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

#[cfg(feature = "proof-carrying")]
async fn campaign_advice(
    State(state): State<AppState>,
    Json(request): Json<serde_json::Value>,
) -> ApiResult<serde_json::Value> {
    let request =
        serde_json::from_value(request).map_err(map_err(StatusCode::UNPROCESSABLE_ENTITY))?;
    let advice = state
        .container
        .campaign_advice(&request)
        .map_err(classified_api_error)?;
    Ok(Json(public_value(advice)))
}

#[cfg(feature = "proof-carrying")]
#[derive(Debug, Deserialize)]
struct CampaignEvidenceRequest {
    run_id: uuid::Uuid,
    compute_usd_per_hour: f64,
    model_cost_usd: f64,
}

#[cfg(feature = "proof-carrying")]
async fn campaign_evidence(
    State(state): State<AppState>,
    Json(request): Json<CampaignEvidenceRequest>,
) -> ApiResult<serde_json::Value> {
    let evidence = state
        .container
        .campaign_evidence_manifest(
            request.run_id,
            hf_service::evidence::CampaignEvidencePricing {
                compute_usd_per_hour: request.compute_usd_per_hour,
                model_cost_usd: request.model_cost_usd,
            },
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(evidence)))
}

#[cfg(feature = "proof-carrying")]
#[derive(Debug, Deserialize)]
struct RemediationDraftRequest {
    run_id: uuid::Uuid,
    finding_id: uuid::Uuid,
    patch: String,
    compute_usd_per_hour: f64,
    model_cost_usd: f64,
}

#[cfg(feature = "proof-carrying")]
async fn remediation_draft(
    State(state): State<AppState>,
    Json(request): Json<RemediationDraftRequest>,
) -> ApiResult<serde_json::Value> {
    let handoff = state
        .container
        .remediation_draft(
            request.run_id,
            request.finding_id,
            &request.patch,
            hf_service::evidence::CampaignEvidencePricing {
                compute_usd_per_hour: request.compute_usd_per_hour,
                model_cost_usd: request.model_cost_usd,
            },
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(handoff)))
}

#[cfg(feature = "change-aware")]
async fn change_impact(
    State(state): State<AppState>,
    Json(request): Json<hf_service::ChangeImpactRequest>,
) -> ApiResult<serde_json::Value> {
    let view = state
        .container
        .change_impact(request)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(view)))
}

#[cfg(feature = "change-aware")]
async fn change_compare(
    State(state): State<AppState>,
    Json(request): Json<hf_service::RevisionComparisonRequest>,
) -> ApiResult<serde_json::Value> {
    let view = state
        .container
        .compare_revisions(request)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(view)))
}

#[cfg(feature = "change-aware")]
async fn change_publish(
    State(state): State<AppState>,
    Json(request): Json<hf_service::PublishComparisonRequest>,
) -> ApiResult<serde_json::Value> {
    let published = state
        .container
        .publish_change_comparison(request)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(published)))
}

#[cfg(feature = "patch-to-proof")]
async fn remediation_operation_create(
    State(state): State<AppState>,
    Json(request): Json<hf_service::RemediationDraftRequest>,
) -> ApiResult<serde_json::Value> {
    let view = state
        .container
        .create_remediation_operation(request)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(view)))
}

#[cfg(feature = "patch-to-proof")]
#[derive(Debug, Deserialize)]
struct RemediationApproveRequest {
    operator: String,
}

#[cfg(feature = "patch-to-proof")]
async fn remediation_operation_approve(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    Json(request): Json<RemediationApproveRequest>,
) -> ApiResult<serde_json::Value> {
    let view = state
        .container
        .approve_remediation_operation(id, &request.operator)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(view)))
}

#[cfg(feature = "patch-to-proof")]
async fn remediation_operation_verify(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    state
        .container
        .start_remediation_verification(hf_service::RemediationStartRequest { operation_id: id })
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(
        serde_json::json!({ "operation_id": id, "accepted": true }),
    )))
}

#[cfg(feature = "patch-to-proof")]
async fn remediation_operation_get(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    let view = state
        .container
        .remediation_operation(id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(view)))
}

#[cfg(feature = "patch-to-proof")]
async fn finding_proof_card_for_crash(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    let card = state
        .container
        .finding_proof_card_for_crash(id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(card)))
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
    let out = state
        .container
        .harness_compile(req.source, &project, engine, &req.target, lang)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(serde_json::json!({
        "status": format!("{:?}", out.status),
        "message": "Harness compiled successfully in sandbox.",
    })))
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
        .map_err(classified_api_error)?;
    Ok(Json(serde_json::json!({
        // Mirror the Tauri command: crashes during smoke mean it did not pass.
        "status": if smoke.summary.passed { "SmokePassed" } else { "SmokeFailed" },
        "duration_secs": smoke.summary.duration_secs,
        "execs_per_sec": smoke.summary.execs_per_sec,
        "crashes": smoke.summary.crashes,
        "passed": smoke.summary.passed,
        // Deterministic self-verification verdict (grok-build L2): lets the UI
        // warn on a hollow pass instead of treating every "passed" as qualified.
        "verdict": smoke.verdict,
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
        .map_err(classified_api_error)?;
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
    let history = state
        .container
        .run_history(project.as_deref())
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(history)))
}

#[derive(Debug, Deserialize)]
struct RunIdRequest {
    run_id: String,
}

async fn run_coverage_series(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<serde_json::Value> {
    let series = state
        .container
        .run_coverage_series(&req.run_id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(
        serde_json::to_value(series).unwrap_or(serde_json::Value::Null),
    ))
}

async fn run_harness_source(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<String> {
    let source = state
        .container
        .run_harness_source(&req.run_id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(source))
}

async fn revert_harness_from_run(
    State(state): State<AppState>,
    Json(req): Json<RunIdRequest>,
) -> ApiResult<serde_json::Value> {
    let out = state
        .container
        .revert_harness_from_run(&req.run_id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(serde_json::json!({
        "status": format!("{:?}", out.status),
        "message": "Reverted and recompiled the harness in the sandbox.",
    })))
}

#[derive(Debug, Deserialize)]
struct RunStartRequest {
    project: PathBuf,
    target: String,
    engine: String,
    #[serde(alias = "duration")]
    duration_secs: u64,
}

async fn run_start(
    State(state): State<AppState>,
    Json(req): Json<RunStartRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let project = approved_project(&state, &req.project)?;
    let engine = parse_engine(&req.engine).map_err(map_err(StatusCode::BAD_REQUEST))?;
    if engine == EngineKind::Syzkaller {
        return Err(classified_api_error(ClassifiedError::Validation(
            "Syzkaller requires the trusted local desktop workflow for kernel and VM artifacts"
                .to_owned(),
        )));
    }
    let progress_state = state.clone();
    let on_progress = std::sync::Arc::new(move |run_id: uuid::Uuid, progress: FuzzProgress| {
        let (kind, data) = match progress {
            FuzzProgress::EdgesCovered(value) => ("EdgesCovered", serde_json::json!(value)),
            FuzzProgress::ExecsPerSec(value) => ("ExecsPerSec", serde_json::json!(value)),
            FuzzProgress::CrashesFound(value) => ("CrashesFound", serde_json::json!(value)),
            FuzzProgress::LogLine(value) => ("LogLine", serde_json::json!(value)),
            FuzzProgress::Done => ("Done", serde_json::Value::Null),
        };
        if let Err(error) = progress_state.publish_event(SseEvent::RunProgress {
            run_id: Some(run_id.to_string()),
            kind: kind.to_owned(),
            data,
        }) {
            tracing::warn!(%run_id, %error, "dropping invalid run progress event");
        }
    });
    let status_state = state.clone();
    let on_status = std::sync::Arc::new(move |run_id: uuid::Uuid, status: RunLifecycleStatus| {
        if let Err(error) = status_state.publish_event(SseEvent::RunStatus {
            run_id: run_id.to_string(),
            status: status.as_str().to_owned(),
        }) {
            tracing::warn!(%run_id, %error, "dropping invalid run status event");
        }
    });
    let run_id = state
        .container
        .start_fuzzer(
            project,
            req.target,
            engine,
            req.duration_secs,
            on_progress,
            on_status,
        )
        .await
        .map_err(classified_api_error)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "run_id": run_id,
            "status": RunLifecycleStatus::Running.as_str(),
        })),
    ))
}

async fn run_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let run_id = uuid::Uuid::parse_str(&id).map_err(map_err(StatusCode::BAD_REQUEST))?;
    let status = state
        .container
        .run_control_status(run_id)
        .await
        .map_err(classified_api_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "run not found".to_owned(),
                }),
            )
        })?;
    Ok(Json(public_value(status)))
}

async fn cancel_run_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let run_id = uuid::Uuid::parse_str(&id).map_err(map_err(StatusCode::BAD_REQUEST))?;
    match state
        .container
        .request_run_cancel(run_id)
        .await
        .map_err(classified_api_error)?
    {
        RunCancelOutcome::Accepted => {}
        RunCancelOutcome::NotFound => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(ErrorResponse {
                    error: "run not found".to_owned(),
                }),
            ));
        }
        RunCancelOutcome::Inactive => {
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "run is not active".to_owned(),
                }),
            ));
        }
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
    let over = state
        .container
        .project_auto_revert_override(&project)
        .await
        .map_err(classified_api_error)?;
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
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(events)))
}

#[derive(Debug, Deserialize)]
struct PolicyDecisionsQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn policy_decisions(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<PolicyDecisionsQuery>,
) -> ApiResult<serde_json::Value> {
    let decisions = state
        .container
        .policy_decisions(q.limit.unwrap_or(200))
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(decisions)))
}

async fn effective_auto_revert_policy(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let view = state
        .container
        .effective_auto_revert_view(&project)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(view)))
}

async fn project_auto_revert_overrides(
    State(state): State<AppState>,
) -> ApiResult<serde_json::Value> {
    let overrides = state
        .container
        .project_auto_revert_overrides()
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(overrides)))
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn all_crashes(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let crashes = state
        .container
        .all_crashes()
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(crashes)))
}

async fn all_corpus(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let entries = state
        .container
        .all_corpus_entries()
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(entries)))
}

async fn export_project_data(
    State(state): State<AppState>,
    Json(req): Json<ExportProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_optional_project(&state, req.project.as_ref())?;
    let export = state
        .container
        .export_project_data(project.as_deref())
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(export)))
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
                .map_err(classified_api_error)?;
            Ok(Json(public_value(corpus.entries)))
        }
        "seed" => {
            let n = state
                .container
                .corpus_seed(&project, &req.target)
                .await
                .map_err(classified_api_error)?;
            Ok(Json(serde_json::json!({"seeded": n})))
        }
        "grow" => {
            let n = state
                .container
                .corpus_grow(&project, &req.target)
                .await
                .map_err(classified_api_error)?;
            Ok(Json(serde_json::json!({"entries": n})))
        }
        "prune" => {
            let n = state
                .container
                .corpus_prune(&project, &req.target)
                .await
                .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
    Ok(Json(public_value(deduped)))
}

#[derive(serde::Deserialize)]
struct VerifyCrashRequest {
    project: String,
    target: String,
    crash: hf_service::Crash,
}

/// On-demand LLM verdict for one crash (L2 4c): the caller passes a crash it
/// already holds from a triage scan, so verifying is opt-in per crash rather than
/// blocking the whole scan on a model call.
async fn verify_crash(
    State(state): State<AppState>,
    Json(req): Json<VerifyCrashRequest>,
) -> ApiResult<serde_json::Value> {
    // Require an approved project for auth parity with triage, even though the
    // verdict is computed from the passed crash and the provider pool.
    let _project = approved_project(&state, std::path::Path::new(&req.project))?;
    let verdict = state.container.verify_crash(&req.target, &req.crash).await;
    Ok(Json(public_value(verdict)))
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
    let dashboard = state
        .container
        .workbench_dashboard(project.as_deref(), opt_target(req.target.as_ref()))
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(dashboard)))
}

async fn harness_review_queue(
    State(state): State<AppState>,
    Json(req): Json<WorkbenchRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_optional_project(&state, req.project.as_ref())?;
    let queue = state
        .container
        .harness_review_queue(project.as_deref(), opt_target(req.target.as_ref()))
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(queue)))
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)
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
        .map_err(classified_api_error)?;
    Ok(Json(outcome))
}

async fn defectdojo_test(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .defectdojo_test_connection()
        .await
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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

async fn provider_thaw(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    state
        .container
        .thaw_provider(&id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(serde_json::json!({ "id": id, "thawed": true })))
}

async fn clear_knowledge(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    state
        .container
        .clear_knowledge()
        .await
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
    Ok(Json(true))
}

#[derive(Debug, Deserialize)]
struct CorpusEntryRequest {
    sha256: String,
    path: String,
}

async fn delete_corpus_entry(
    State(state): State<AppState>,
    Json(req): Json<CorpusEntryRequest>,
) -> ApiResult<bool> {
    state
        .container
        .delete_corpus_entry(&req.sha256, std::path::Path::new(&req.path))
        .await
        .map_err(classified_api_error)?;
    Ok(Json(true))
}

async fn clear_all_artifacts(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .clear_all_artifacts()
        .await
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
    Ok(Json(true))
}

async fn clear_all_runs(State(state): State<AppState>) -> ApiResult<bool> {
    state
        .container
        .clear_all_runs()
        .await
        .map_err(classified_api_error)?;
    Ok(Json(true))
}

async fn sarif(State(state): State<AppState>, Json(req): Json<TriageRequest>) -> ApiResult<String> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let doc = state
        .container
        .export_sarif(&project, &req.target)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(doc))
}

/// The report request body: a triage request plus an optional language. Omitting
/// the field yields English, so existing clients are unaffected.
#[derive(Debug, Deserialize)]
struct ReportRequest {
    project: String,
    target: String,
    #[serde(default)]
    language: hf_service::ReportLanguage,
}

async fn report(
    State(state): State<AppState>,
    Json(req): Json<ReportRequest>,
) -> ApiResult<String> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    let markdown = state
        .container
        .generate_report(&project, &req.target, req.language)
        .await
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
    Ok(Json(answer))
}

/// Parse a transcript role string into a [`Role`],
/// defaulting unknown values to `User`.
fn parse_role(role: &str) -> Role {
    match role.to_ascii_lowercase().as_str() {
        "assistant" => Role::Assistant,
        "system" => Role::System,
        "tool" => Role::Tool,
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
    Ok(Json(branches))
}

// -- Knowledge base --------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ProjectRequest {
    project: String,
}

/// Read-only index status (no reindex): size, build time, ingested-document
/// count, and the active retrieval config. A GET, unlike the other knowledge
/// endpoints, because it has no side effects.
async fn knowledge_stats(
    State(state): State<AppState>,
    axum::extract::Query(req): axum::extract::Query<ProjectRequest>,
) -> ApiResult<hf_service::knowledge::KnowledgeIndexStatus> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    Ok(Json(hf_service::knowledge::stats_project(&project)))
}

async fn knowledge_index(
    State(state): State<AppState>,
    Json(req): Json<ProjectRequest>,
) -> ApiResult<hf_service::knowledge::KnowledgeStats> {
    let project = approved_project(&state, std::path::Path::new(&req.project))?;
    // The tree walk and chunking are blocking, so run them off the async
    // runtime (same pattern as `knowledge_search`).
    let knowledge_stats = tokio::task::spawn_blocking(move || {
        hf_service::knowledge::index_project(&project)
    })
    .await
    // A panic in the blocking index (JoinError) must surface as a 500, not a
    // silent empty 200 that a client cannot distinguish from "no documents".
    .map_err(|error| {
        classified_api_error(ClassifiedError::Internal(format!(
            "knowledge index task failed: {error}"
        )))
    })?
    .map_err(classified_api_error)?;
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
        .map_err(classified_api_error)?;
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
    // A panic in the blocking search (JoinError) must surface as a 500, not a
    // silent empty 200 that a client cannot distinguish from "no matches".
    .map_err(|error| {
        classified_api_error(ClassifiedError::Internal(format!(
            "knowledge search task failed: {error}"
        )))
    })?;
    Ok(Json(public_value(hits)))
}

// -- Campaign scheduling ---------------------------------------------------
//
// Endpoints degrade to empty results when no scheduler is attached (e.g. a
// bare test state).

async fn schedule_list(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let views = match &state.scheduler {
        Some(scheduler) => scheduler.list_views().await.map_err(scheduler_api_error)?,
        None => Vec::new(),
    };
    Ok(Json(public_value(views)))
}

async fn schedule_recovery_list(
    State(state): State<AppState>,
) -> RecoveryApiResult<serde_json::Value> {
    let recoveries = match &state.scheduler {
        Some(scheduler) => scheduler
            .list_one_time_recoveries()
            .await
            .map_err(scheduler_recovery_api_error)?,
        None => Vec::new(),
    };
    Ok(Json(public_value(recoveries)))
}

async fn schedule_recovery_acknowledge(
    State(state): State<AppState>,
    Path(occurrence_id): Path<String>,
) -> RecoveryApiResult<serde_json::Value> {
    let scheduler = state
        .scheduler
        .as_ref()
        .ok_or_else(|| recovery_api_error(RecoveryPublicError::unavailable()))?;
    let recovery = scheduler
        .acknowledge_one_time_recovery(&occurrence_id)
        .await
        .map_err(scheduler_recovery_api_error)?;
    Ok(Json(public_value(recovery)))
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    #[serde(default)]
    limit: Option<usize>,
}

async fn schedule_history(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<HistoryQuery>,
) -> ApiResult<serde_json::Value> {
    let views = match &state.scheduler {
        Some(scheduler) => scheduler
            .recent_executions(q.limit.unwrap_or(20))
            .await
            .map_err(scheduler_api_error)?,
        None => Vec::new(),
    };
    Ok(Json(public_value(views)))
}

async fn schedule_history_clear(State(state): State<AppState>) -> ApiResult<u64> {
    let cleared = match &state.scheduler {
        Some(s) => s.clear_history().await.map_err(scheduler_api_error)?,
        None => 0,
    };
    Ok(Json(cleared))
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
        .map_err(classified_api_error)
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
    scheduler
        .try_create(&req.name, &params, trigger)
        .await
        .map_err(scheduler_api_error)?;
    let views = scheduler.list_views().await.map_err(scheduler_api_error)?;
    Ok(Json(public_value(views)))
}

/// Whether restored work is authorized to run in this process.
async fn schedule_arm_get(State(state): State<AppState>) -> Json<serde_json::Value> {
    let armed = state.scheduler.as_ref().is_some_and(|s| s.is_armed());
    Json(serde_json::json!({ "armed": armed }))
}

/// Release recovery held since start.
///
/// A scheduler comes up disarmed on every process start: a restart restores
/// what it was doing without deciding to carry on. This is that decision.
async fn schedule_arm(State(state): State<AppState>) -> Json<serde_json::Value> {
    if let Some(scheduler) = &state.scheduler {
        scheduler.arm();
    }
    let armed = state.scheduler.as_ref().is_some_and(|s| s.is_armed());
    Json(serde_json::json!({ "armed": armed }))
}

/// Withdraw authorization; recovery not yet released stays held.
async fn schedule_disarm(State(state): State<AppState>) -> Json<serde_json::Value> {
    if let Some(scheduler) = &state.scheduler {
        scheduler.disarm();
    }
    let armed = state.scheduler.as_ref().is_some_and(|s| s.is_armed());
    Json(serde_json::json!({ "armed": armed }))
}

async fn schedule_concurrency_get(State(state): State<AppState>) -> Json<usize> {
    Json(state.scheduler.as_ref().map_or(0, |s| s.max_concurrent()))
}

async fn schedule_concurrency_limits(
    State(state): State<AppState>,
) -> Json<hf_service::scheduler::CampaignConcurrencyLimits> {
    Json(state.scheduler.as_ref().map_or(
        hf_service::scheduler::CampaignConcurrencyLimits {
            active_fuzz_campaign_limit: 0,
            scheduler_workflow_dispatch_limit: 0,
            effective_max_concurrent_fuzz_runs: 0,
        },
        |scheduler| scheduler.concurrency_limits(),
    ))
}

#[derive(Debug, Deserialize)]
struct ConcurrencyRequest {
    max_concurrent: usize,
}

async fn schedule_concurrency_set(
    State(state): State<AppState>,
    Json(req): Json<ConcurrencyRequest>,
) -> ApiResult<usize> {
    let max_concurrent = match &state.scheduler {
        Some(s) => {
            s.try_set_max_concurrent(req.max_concurrent)
                .map_err(scheduler_api_error)?;
            s.max_concurrent()
        }
        None => 0,
    };
    Ok(Json(max_concurrent))
}

async fn schedule_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let views = match &state.scheduler {
        Some(s) => {
            if !s.try_remove(&id).await.map_err(scheduler_api_error)? {
                return Err(missing_schedule_error(&id));
            }
            s.list_views().await.map_err(scheduler_api_error)?
        }
        None => Vec::new(),
    };
    Ok(Json(public_value(views)))
}

#[derive(Debug, Deserialize)]
struct SetEnabledRequest {
    enabled: bool,
}

async fn schedule_set_enabled(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SetEnabledRequest>,
) -> ApiResult<serde_json::Value> {
    let views = match &state.scheduler {
        Some(s) => {
            if !s
                .try_set_enabled(&id, req.enabled)
                .await
                .map_err(scheduler_api_error)?
            {
                return Err(missing_schedule_error(&id));
            }
            s.list_views().await.map_err(scheduler_api_error)?
        }
        None => Vec::new(),
    };
    Ok(Json(public_value(views)))
}

// -- Config endpoints ------------------------------------------------------
//
// These delegate to `hf_service::config`, the single source of truth shared
// with the CLI and GUI, so the HTTP API edits the same `config/*.toml` files.

async fn list_models(State(_): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!(hf_service::config::list_models()))
}

// -- Agent and skill registries -------------------------------------------
//
// All registry resolution, validation, and persistence is service-owned. The
// REST layer only maps typed request bodies to the same methods used by Tauri.

async fn agent_info(State(state): State<AppState>) -> Json<hf_service::AgentRegistryInfo> {
    Json(state.container.agent_registry_info())
}

async fn agent_tools(State(state): State<AppState>) -> Json<Vec<hf_service::AgentToolDefinition>> {
    Json(state.container.agent_tool_definitions())
}

async fn list_agents(State(state): State<AppState>) -> Json<Vec<hf_service::AgentDefinition>> {
    Json(state.container.list_agent_definitions())
}

#[derive(Debug, Deserialize)]
struct AgentIdRequest {
    id: String,
}

async fn get_agent(
    State(state): State<AppState>,
    Json(request): Json<AgentIdRequest>,
) -> Json<Option<hf_service::AgentDefinition>> {
    Json(state.container.get_agent_definition(&request.id))
}

#[derive(Debug, Deserialize)]
struct SaveAgentRequest {
    definition: hf_service::AgentDefinition,
}

async fn save_agent(
    State(state): State<AppState>,
    Json(request): Json<SaveAgentRequest>,
) -> ApiResult<()> {
    state
        .container
        .save_agent_definition(request.definition)
        .map_err(classified_api_error)?;
    Ok(Json(()))
}

async fn delete_agent(
    State(state): State<AppState>,
    Json(request): Json<AgentIdRequest>,
) -> ApiResult<()> {
    state
        .container
        .delete_agent_definition(&request.id)
        .map_err(classified_api_error)?;
    Ok(Json(()))
}

async fn list_skills(State(state): State<AppState>) -> Json<Vec<hf_service::SkillDefinition>> {
    Json(state.container.list_skill_definitions())
}

#[derive(Debug, Deserialize)]
struct SkillNameRequest {
    name: String,
}

async fn read_skill(
    State(state): State<AppState>,
    Json(request): Json<SkillNameRequest>,
) -> Json<Option<hf_service::SkillDefinition>> {
    Json(state.container.get_skill_definition(&request.name))
}

#[derive(Debug, Deserialize)]
struct SaveSkillRequest {
    definition: hf_service::SkillDefinition,
}

async fn save_skill(
    State(state): State<AppState>,
    Json(request): Json<SaveSkillRequest>,
) -> ApiResult<()> {
    state
        .container
        .save_skill_definition(request.definition)
        .map_err(classified_api_error)?;
    Ok(Json(()))
}

async fn delete_skill(
    State(state): State<AppState>,
    Json(request): Json<SkillNameRequest>,
) -> ApiResult<()> {
    state
        .container
        .delete_skill_definition(&request.name)
        .map_err(classified_api_error)?;
    Ok(Json(()))
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
    // Sections with a typed endpoint must go through it: the typed route also
    // refreshes live state (e.g. `reload_providers`), which a raw write would
    // silently skip, diverging the file from the running process.
    let typed_endpoint_message = match req.name.as_str() {
        "defectdojo" | "issue_tracker" => {
            Some("integration settings require the typed config endpoint")
        }
        "providers" => Some("provider settings require the typed config endpoint"),
        _ => None,
    };
    if let Some(message) = typed_endpoint_message {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: message.to_owned(),
            }),
        ));
    }
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
        .map(public_provider_value)
        .collect();
    Json(serde_json::Value::Array(providers))
}

fn public_provider_value(provider: hf_service::config::ProviderConfig) -> serde_json::Value {
    let api_key_configured = provider
        .api_key
        .as_ref()
        .is_some_and(|value| !value.is_empty());
    let api_key_env_configured = provider
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
            "api_key_env_configured".to_owned(),
            serde_json::Value::Bool(api_key_env_configured),
        );
        object.insert(
            "headers_configured".to_owned(),
            serde_json::Value::Bool(headers_configured),
        );
    }
    value
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

async fn get_fuzzing_settings(
    State(_): State<AppState>,
) -> ApiResult<hf_service::config::FuzzingSettings> {
    let settings = hf_service::config::effective_fuzzing_settings()
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(settings))
}

#[cfg(feature = "automotive-scapy")]
async fn get_automotive_settings(
    State(state): State<AppState>,
) -> ApiResult<hf_service::config::AutomotiveSettings> {
    state
        .automotive_configs
        .get()
        .map(Json)
        .map_err(map_err(StatusCode::BAD_REQUEST))
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct SetAutomotiveSettingsRequest {
    settings: hf_service::config::AutomotiveSettings,
}

#[cfg(feature = "automotive-scapy")]
async fn set_automotive_settings(
    State(state): State<AppState>,
    Json(request): Json<SetAutomotiveSettingsRequest>,
) -> ApiResult<hf_service::config::AutomotiveSettings> {
    state
        .automotive_configs
        .set(request.settings)
        .map(Json)
        .map_err(map_err(StatusCode::BAD_REQUEST))
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveProjectRequest {
    project_root: PathBuf,
}

#[cfg(feature = "automotive-scapy")]
async fn automotive_capabilities(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveProjectRequest>,
) -> ApiResult<hf_service::automotive::AutomotiveOperationOutcome> {
    let project_root = approved_project(&state, &request.project_root)?;
    state
        .container
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::Capabilities,
            approval: None,
        })
        .await
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveAnalyzeCaptureRequest {
    project_root: PathBuf,
    protocol: hf_service::automotive::AutomotiveProtocol,
    capture_path: PathBuf,
}

#[cfg(feature = "automotive-scapy")]
async fn automotive_analyze_capture(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveAnalyzeCaptureRequest>,
) -> ApiResult<hf_service::automotive::AutomotiveOperationOutcome> {
    let (project_root, capture_path) = state
        .security
        .approve_document(&request.project_root, &request.capture_path)
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    state
        .container
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::AnalyzeCapture {
                protocol: request.protocol,
                capture_path,
            },
            approval: None,
        })
        .await
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveImportRequest {
    project_root: PathBuf,
    format: String,
    capture_path: PathBuf,
    dbc_path: Option<PathBuf>,
}

/// Import and analyze a capture offline. Both the capture and the optional DBC
/// must resolve inside the approved project, as with other document routes.
#[cfg(feature = "automotive-scapy")]
async fn automotive_import_capture(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveImportRequest>,
) -> ApiResult<hf_service::automotive_offline::CaptureImport> {
    let (_, capture_path) = state
        .security
        .approve_document(&request.project_root, &request.capture_path)
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    let dbc_path = match &request.dbc_path {
        Some(path) => Some(
            state
                .security
                .approve_document(&request.project_root, path)
                .map_err(map_err(StatusCode::FORBIDDEN))?
                .1,
        ),
        None => None,
    };
    state
        .container
        .automotive_import_capture(&capture_path, &request.format, dbc_path.as_deref())
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveDiffRequest {
    project_root: PathBuf,
    format: String,
    first_path: PathBuf,
    second_path: PathBuf,
}

/// Compare two captures offline; both must resolve inside the approved project.
#[cfg(feature = "automotive-scapy")]
async fn automotive_diff_captures(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveDiffRequest>,
) -> ApiResult<hf_service::automotive_offline::CaptureDiffView> {
    let (_, first_path) = state
        .security
        .approve_document(&request.project_root, &request.first_path)
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    let (_, second_path) = state
        .security
        .approve_document(&request.project_root, &request.second_path)
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    state
        .container
        .automotive_diff_captures(&first_path, &second_path, &request.format)
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveMutationRequest {
    project_root: PathBuf,
    protocol: hf_service::automotive::AutomotiveProtocol,
    source_path: PathBuf,
    deterministic_seed: u64,
    mutation_count: u32,
    media_type: String,
}

#[cfg(feature = "automotive-scapy")]
async fn automotive_generate_mutations(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveMutationRequest>,
) -> ApiResult<hf_service::automotive::AutomotiveOperationOutcome> {
    let (project_root, source_path) = state
        .security
        .approve_document(&request.project_root, &request.source_path)
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    state
        .container
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::GenerateMutations {
                protocol: request.protocol,
                source_path,
                deterministic_seed: request.deterministic_seed,
                mutation_count: request.mutation_count,
                media_type: request.media_type,
            },
            approval: None,
        })
        .await
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveReplayPlanRequest {
    project_root: PathBuf,
    protocol: hf_service::automotive::AutomotiveProtocol,
    source_path: PathBuf,
    target_mode: hf_service::automotive::AutomotiveMode,
    deterministic_seed: u64,
}

#[cfg(feature = "automotive-scapy")]
async fn automotive_build_replay_plan(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveReplayPlanRequest>,
) -> ApiResult<hf_service::automotive::AutomotiveOperationOutcome> {
    let (project_root, source_path) = state
        .security
        .approve_document(&request.project_root, &request.source_path)
        .map_err(map_err(StatusCode::FORBIDDEN))?;
    state
        .container
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::BuildReplayPlan {
                protocol: request.protocol,
                source_path,
                target_mode: request.target_mode,
                deterministic_seed: request.deterministic_seed,
            },
            approval: None,
        })
        .await
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveExecuteReplayRequest {
    project_root: PathBuf,
    mode: hf_service::automotive::ModeConfig,
    plan: hf_service::automotive::ReplayPlan,
    approval: Option<hf_service::automotive::AutomotiveApprovalEvidence>,
}

#[cfg(feature = "automotive-scapy")]
async fn automotive_execute_replay(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveExecuteReplayRequest>,
) -> ApiResult<hf_service::automotive::AutomotiveOperationOutcome> {
    let project_root = approved_project(&state, &request.project_root)?;
    state
        .container
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::ExecuteReplay {
                mode: request.mode,
                plan: request.plan,
            },
            approval: request.approval,
        })
        .await
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveOperationListRequest {
    project_root: PathBuf,
    limit: Option<u32>,
}

/// The automotive report request body. It has its own struct rather than
/// sharing [`AutomotiveOperationListRequest`]: that route returns evidence rows
/// and no prose, so advertising a language on it would promise something it
/// cannot deliver. Omitting the field yields English, so existing clients are
/// unaffected.
#[cfg(feature = "automotive-scapy")]
#[derive(Debug, Deserialize)]
struct AutomotiveReportRequest {
    project_root: PathBuf,
    #[serde(default)]
    include_ai: bool,
    #[serde(default)]
    language: hf_service::ReportLanguage,
}

#[cfg(feature = "automotive-scapy")]
async fn generate_automotive_report(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveReportRequest>,
) -> ApiResult<hf_service::automotive_report::AutomotiveCampaignReport> {
    let project_root = approved_project(&state, &request.project_root)?;
    state
        .container
        .generate_automotive_report(&project_root, request.include_ai, request.language)
        .await
        .map(Json)
        .map_err(classified_api_error)
}

#[cfg(feature = "automotive-scapy")]
async fn list_automotive_operations(
    State(state): State<AppState>,
    Json(request): Json<AutomotiveOperationListRequest>,
) -> ApiResult<Vec<hf_service::automotive::AutomotiveOperationSummary>> {
    automotive_operation_list(&state, request).await
}

#[cfg(feature = "automotive-scapy")]
async fn list_automotive_operations_query(
    State(state): State<AppState>,
    Query(request): Query<AutomotiveOperationListRequest>,
) -> ApiResult<Vec<hf_service::automotive::AutomotiveOperationSummary>> {
    automotive_operation_list(&state, request).await
}

#[cfg(feature = "automotive-scapy")]
async fn automotive_operation_list(
    state: &AppState,
    request: AutomotiveOperationListRequest,
) -> ApiResult<Vec<hf_service::automotive::AutomotiveOperationSummary>> {
    let project_root = approved_project(state, &request.project_root)?;
    state
        .container
        .list_automotive_operations(&project_root, request.limit.unwrap_or(50))
        .await
        .map(Json)
        .map_err(classified_api_error)
}

async fn get_defectdojo_config(
    State(state): State<AppState>,
) -> ApiResult<hf_service::config::DefectDojoPublicConfig> {
    let config = state
        .integration_configs
        .defectdojo()
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(config))
}

async fn patch_defectdojo_config(
    State(state): State<AppState>,
    Json(patch): Json<hf_service::config::DefectDojoConfigPatch>,
) -> ApiResult<hf_service::config::DefectDojoPublicConfig> {
    let config = state
        .integration_configs
        .patch_defectdojo(patch)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(config))
}

async fn get_issue_tracker_config(
    State(state): State<AppState>,
) -> ApiResult<hf_service::config::IssueTrackerPublicConfig> {
    let config = state
        .integration_configs
        .issue_tracker()
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(config))
}

async fn patch_issue_tracker_config(
    State(state): State<AppState>,
    Json(patch): Json<hf_service::config::IssueTrackerConfigPatch>,
) -> ApiResult<hf_service::config::IssueTrackerPublicConfig> {
    let config = state
        .integration_configs
        .patch_issue_tracker(patch)
        .map_err(map_err(StatusCode::BAD_REQUEST))?;
    Ok(Json(config))
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
    use axum::http::StatusCode;

    use super::{
        classified_api_error, parse_role, public_provider_value, ReportRequest, SetProvidersRequest,
    };

    #[test]
    fn report_request_language_is_optional_and_defaults_to_english() {
        let omitted: ReportRequest = serde_json::from_str(r#"{"project":"/p","target":"t"}"#)
            .expect("language must stay optional for existing clients");
        assert_eq!(omitted.language, hf_service::ReportLanguage::En);

        let chinese: ReportRequest =
            serde_json::from_str(r#"{"project":"/p","target":"t","language":"zh"}"#)
                .expect("the wire value the desktop locale already uses");
        assert_eq!(chinese.language, hf_service::ReportLanguage::Zh);

        assert!(
            serde_json::from_str::<ReportRequest>(
                r#"{"project":"/p","target":"t","language":"fr"}"#
            )
            .is_err(),
            "an unsupported language is rejected, not silently rendered as English"
        );
    }

    #[test]
    fn transcript_roles_keep_tool_turns_instead_of_downgrading_to_user() {
        assert_eq!(parse_role("tool"), hf_service::Role::Tool);
        assert_eq!(parse_role("Tool"), hf_service::Role::Tool);
        assert_eq!(parse_role("assistant"), hf_service::Role::Assistant);
        assert_eq!(parse_role("system"), hf_service::Role::System);
        assert_eq!(parse_role("user"), hf_service::Role::User);
        assert_eq!(parse_role("anything-else"), hf_service::Role::User);
    }

    #[test]
    fn provider_write_accepts_the_browser_transport_wrapper() {
        let request: SetProvidersRequest =
            serde_json::from_str(r#"{"providers":[]}"#).expect("wrapped provider request");
        assert!(request.into_providers().is_empty());
    }

    #[test]
    fn public_provider_state_distinguishes_direct_key_env_name_and_headers() {
        let provider: hf_service::config::ProviderConfig = toml::from_str(
            r#"
id = "primary"
provider_type = "openai"
model = "gpt-test"
api_key = "synthetic-direct-key"
api_key_env = "SYNTHETIC_PROVIDER_KEY_ENV"

[headers]
Authorization = "Bearer synthetic-header"
"#,
        )
        .expect("synthetic provider config");

        let public = public_provider_value(provider);

        assert_eq!(public["api_key_configured"], true);
        assert_eq!(public["api_key_env_configured"], true);
        assert_eq!(public["headers_configured"], true);
        assert!(public["api_key"].is_null());
        assert!(public["api_key_env"].is_null());
        assert_eq!(public["headers"], serde_json::json!({}));
        let serialized = public.to_string();
        assert!(!serialized.contains("synthetic-direct-key"));
        assert!(!serialized.contains("SYNTHETIC_PROVIDER_KEY_ENV"));
        assert!(!serialized.contains("synthetic-header"));
    }

    #[test]
    fn classified_errors_have_one_stable_http_mapping() {
        use hf_service::ClassifiedError;

        let cases = [
            (
                ClassifiedError::Validation("bad input".into()),
                StatusCode::BAD_REQUEST,
            ),
            (
                ClassifiedError::Harness("not qualified".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                ClassifiedError::Engine("launch rejected".into()),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                ClassifiedError::Provider("offline".into()),
                StatusCode::BAD_GATEWAY,
            ),
            (
                ClassifiedError::Sandbox("docker offline".into()),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (ClassifiedError::Timeout, StatusCode::GATEWAY_TIMEOUT),
            (
                ClassifiedError::Storage("database".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                ClassifiedError::Internal("bug".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classified_api_error(error).0, expected);
        }
    }
}
