//! Thin HTTP transport for the desktop commands the browser GUI calls that had
//! no route: harness refinement and options, grammar mutators, bisection,
//! regression replay, campaigns and the CI gate, run detail and edge diffs,
//! Clang analysis, dictionaries, line-coverage reports, notifications, the
//! fuzzing preflight, and the read-only UDS scan.
//!
//! Each handler mirrors its Tauri command in `hf-gui/src-tauri`: the same
//! service call, the same approval action, the same response shape. Project
//! paths are confined to the approved roots; run- and operation-scoped routes
//! resolve the owning project first and refuse one outside them.
use std::path::PathBuf;

use axum::extract::Path;
use axum::routing::get;

use super::{
    approved_project, classified_api_error, map_err, parse_engine, parse_lang, post, public_value,
    workflow_container, ApiError, ApiResult, AppState, Deserialize, Json, Router, SseEvent, State,
    StatusCode,
};
use hf_service::workflow_approval::ExplicitAction;
use hf_service::{AiPolicy, FuzzProgress, TargetLanguage};

pub(super) fn routes() -> Router<AppState> {
    let router = Router::new()
        .route("/harness/refine", post(harness_refine))
        .route("/harness/adopt-revision", post(harness_adopt_revision))
        .route(
            "/harness/smoke-with-options",
            post(harness_smoke_with_options),
        )
        .route("/crashes/verify-regressions", post(verify_regressions))
        .route("/campaign/run", post(run_campaign))
        .route("/ci-gate", post(run_ci_gate))
        .route("/runs/detail/{run_id}", get(run_detail))
        .route("/dictionary", post(user_dictionary))
        .route("/dictionary/set", post(set_user_dictionary))
        .route("/dictionary/clear", post(clear_user_dictionary))
        .route("/coverage/line-report", post(coverage_line_report))
        .route("/fuzzing/preflight", post(fuzzing_preflight))
        .route("/clang/available", get(clang_available));
    let router = mutator_routes(router);
    let router = bisection_routes(router);
    let router = closeout_routes(router);
    let router = alert_routes(router);
    let router = clang_routes(router);
    automotive_routes(router)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn bad_request(error: impl std::fmt::Display) -> ApiError {
    map_err(StatusCode::BAD_REQUEST)(error)
}

fn language(lang: Option<&str>) -> Result<TargetLanguage, ApiError> {
    lang.map_or(Ok(TargetLanguage::C), |value| {
        parse_lang(value).map_err(bad_request)
    })
}

/// Refuse a run whose project is outside the approved roots.
#[cfg(feature = "run-closeout")]
async fn approve_run(state: &AppState, run_id: uuid::Uuid) -> Result<(), ApiError> {
    let project = state
        .container
        .run_project(run_id)
        .await
        .map_err(classified_api_error)?;
    approved_project(state, &project).map(drop)
}

/// The `{type, data}` payload the desktop shell emits as `campaign:progress`.
fn progress_payload(progress: FuzzProgress) -> serde_json::Value {
    let (kind, data) = match progress {
        FuzzProgress::EdgesCovered(value) => ("EdgesCovered", serde_json::json!(value)),
        FuzzProgress::ExecsPerSec(value) => ("ExecsPerSec", serde_json::json!(value)),
        FuzzProgress::CrashesFound(value) => ("CrashesFound", serde_json::json!(value)),
        FuzzProgress::LogLine(value) => ("LogLine", serde_json::json!(value)),
        FuzzProgress::Stats(value) => ("Stats", serde_json::json!(value)),
        FuzzProgress::Done => ("Done", serde_json::Value::Null),
    };
    serde_json::json!({ "type": kind, "data": data })
}

fn campaign_progress_sink(state: &AppState) -> impl Fn(FuzzProgress) + Send + Sync + 'static {
    let state = state.clone();
    move |progress: FuzzProgress| {
        // Progress display is advisory; the response is authoritative.
        if let Err(error) =
            state.publish_event(SseEvent::CampaignProgress(progress_payload(progress)))
        {
            tracing::warn!(%error, "dropping campaign progress event");
        }
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct HarnessRefineRequest {
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
    repairs: Option<usize>,
    ai: Option<AiPolicy>,
}

async fn harness_refine(
    State(state): State<AppState>,
    Json(req): Json<HarnessRefineRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    let lang = language(req.lang.as_deref())?;
    let project = approved_project(&state, &req.project)?;
    let outcome = state
        .container
        .harness_refine(
            &project,
            &req.target,
            engine,
            lang,
            // Refinement recompiles what the model wrote, so it always keeps
            // at least one repair attempt, as `oxfuzz harness --refine` does.
            req.repairs.unwrap_or(1).max(1),
            req.ai.unwrap_or_default(),
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(serde_json::json!({
        "status": format!("{:?}", outcome.status),
        "harness_id": outcome.harness_id,
        "repairs_used": outcome.repairs_used,
        "lint": outcome.lint,
    }))?))
}

#[derive(Deserialize)]
struct HarnessAdoptRequest {
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
    harness_id: uuid::Uuid,
}

async fn harness_adopt_revision(
    State(state): State<AppState>,
    Json(req): Json<HarnessAdoptRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    let lang = language(req.lang.as_deref())?;
    let project = approved_project(&state, &req.project)?;
    let outcome = state
        .container
        .harness_adopt_revision(&project, &req.target, engine, lang, req.harness_id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(
        serde_json::json!({ "status": format!("{:?}", outcome.status) }),
    ))
}

#[derive(Deserialize)]
struct HarnessSmokeOptionsRequest {
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
    repairs: Option<usize>,
    skip_model_review: Option<bool>,
    ai: Option<AiPolicy>,
}

async fn harness_smoke_with_options(
    State(state): State<AppState>,
    Json(req): Json<HarnessSmokeOptionsRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    let lang = language(req.lang.as_deref())?;
    let project = approved_project(&state, &req.project)?;
    let bypass = if req.skip_model_review.unwrap_or(false) {
        hf_service::HarnessReviewBypass::Requested
    } else {
        hf_service::HarnessReviewBypass::NotRequested
    };
    let qualified = workflow_container(&state, ExplicitAction::RunHarness)
        .harness_smoke_with_repair(
            &project,
            &req.target,
            engine,
            lang,
            bypass,
            req.repairs.unwrap_or(0),
            // The repair count is in the result; the attempts are not streamed.
            &|_, _| {},
            req.ai.unwrap_or_default(),
        )
        .await
        .map_err(classified_api_error)?;
    let smoke = qualified.smoke;
    Ok(Json(public_value(serde_json::json!({
        "status": if smoke.summary.passed { "SmokePassed" } else { "SmokeFailed" },
        "duration_secs": smoke.summary.duration_secs,
        "execs_per_sec": smoke.summary.execs_per_sec,
        "crashes": smoke.summary.crashes,
        "passed": smoke.summary.passed,
        "verdict": smoke.verdict,
        "behavior": smoke.behavior,
        "smoke_repairs": qualified.smoke_repairs,
    }))?))
}

#[cfg(feature = "managed-mutators")]
fn mutator_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/harness/mutator/grammar", post(attach_grammar_mutator))
        .route(
            "/harness/mutator/grammar-source",
            post(grammar_mutator_source),
        )
}

#[cfg(not(feature = "managed-mutators"))]
fn mutator_routes(router: Router<AppState>) -> Router<AppState> {
    router
}

#[cfg(feature = "managed-mutators")]
#[derive(Deserialize)]
struct GrammarMutatorRequest {
    project: PathBuf,
    target: String,
    engine: String,
    expected_harness_id: uuid::Uuid,
    grammar: String,
}

#[cfg(feature = "managed-mutators")]
async fn attach_grammar_mutator(
    State(state): State<AppState>,
    Json(req): Json<GrammarMutatorRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    let project = approved_project(&state, &req.project)?;
    let status = state
        .container
        .attach_grammar_mutator(
            &project,
            &req.target,
            engine,
            req.expected_harness_id,
            &req.grammar,
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(status)?))
}

#[cfg(feature = "managed-mutators")]
#[derive(Deserialize)]
struct GrammarSourceRequest {
    grammar: String,
    engine: String,
}

#[cfg(feature = "managed-mutators")]
async fn grammar_mutator_source(Json(req): Json<GrammarSourceRequest>) -> ApiResult<String> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    hf_service::ServiceContainer::grammar_mutator_source(&req.grammar, engine)
        .map(Json)
        .map_err(classified_api_error)
}

// ---------------------------------------------------------------------------
// Crashes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ProjectTargetRequest {
    project: PathBuf,
    target: String,
}

async fn verify_regressions(
    State(state): State<AppState>,
    Json(req): Json<ProjectTargetRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &req.project)?;
    let results = workflow_container(&state, ExplicitAction::Triage)
        .verify_regressions(&project, &req.target)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(results)?))
}

#[cfg(feature = "crash-bisection")]
fn bisection_routes(router: Router<AppState>) -> Router<AppState> {
    router.route("/crashes/bisect", post(bisect_crash))
}

#[cfg(not(feature = "crash-bisection"))]
fn bisection_routes(router: Router<AppState>) -> Router<AppState> {
    router
}

#[cfg(feature = "crash-bisection")]
#[derive(Deserialize)]
struct BisectRequest {
    project: PathBuf,
    target: String,
    crash_id: String,
    good: String,
    bad: Option<String>,
}

#[cfg(feature = "crash-bisection")]
async fn bisect_crash(
    State(state): State<AppState>,
    Json(req): Json<BisectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &req.project)?;
    let outcome = workflow_container(&state, ExplicitAction::RunHarness)
        .bisect_crash(
            &project,
            &req.target,
            &req.crash_id,
            &req.good,
            req.bad.as_deref().filter(|revision| !revision.is_empty()),
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(outcome)?))
}

// ---------------------------------------------------------------------------
// Campaigns, the CI gate, and runs
// ---------------------------------------------------------------------------

/// Options of `oxfuzz campaign`, under the desktop form's camelCase names.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CampaignOptions {
    project: PathBuf,
    /// Absent: the service picks the top-ranked target.
    target: Option<String>,
    engine: String,
    lang: Option<String>,
    duration_secs: u64,
    iterations: usize,
    timeout_ms: Option<u64>,
    resume: Option<bool>,
    sanitizer: Option<String>,
    cmplog: Option<bool>,
    /// Decimal text, so the browser keeps every bit above 2^53.
    seed: Option<String>,
    ai: Option<AiPolicy>,
}

#[derive(Deserialize)]
struct CampaignRequest {
    options: CampaignOptions,
}

async fn run_campaign(
    State(state): State<AppState>,
    Json(CampaignRequest { options }): Json<CampaignRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&options.engine).map_err(bad_request)?;
    let lang = language(options.lang.as_deref())?;
    let sanitizer = options
        .sanitizer
        .as_deref()
        .map(str::parse::<hf_service::Sanitizer>)
        .transpose()
        .map_err(bad_request)?;
    let seed = options
        .seed
        .as_deref()
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|error| bad_request(format!("invalid seed: {error}")))?;
    let project = approved_project(&state, &options.project)?;
    let container = workflow_container(&state, ExplicitAction::RunFuzzer)
        .scoped_to_ai_policy(options.ai.unwrap_or_default(), "this campaign")
        .await
        .map_err(classified_api_error)?;
    let on_progress = campaign_progress_sink(&state);
    let outcome = container
        .run_campaign_observed(
            &project,
            options
                .target
                .as_deref()
                .filter(|target| !target.is_empty()),
            engine,
            lang,
            options.duration_secs,
            options.timeout_ms,
            options.resume,
            sanitizer,
            options.cmplog,
            seed,
            options.iterations,
            &on_progress,
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(outcome)?))
}

#[derive(Deserialize)]
struct CiGateRequest {
    project: PathBuf,
    target: String,
    engine: String,
    duration_secs: u64,
    ai: Option<AiPolicy>,
}

async fn run_ci_gate(
    State(state): State<AppState>,
    Json(req): Json<CiGateRequest>,
) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    let project = approved_project(&state, &req.project)?;
    let container = workflow_container(&state, ExplicitAction::RunFuzzer)
        .scoped_to_ai_policy(req.ai.unwrap_or_default(), "this CI gate")
        .await
        .map_err(classified_api_error)?;
    let on_progress = campaign_progress_sink(&state);
    let outcome = container
        .run_ci_gate(
            hf_service::sarif::CiGateRequest {
                project: &project,
                target: &req.target,
                engine,
                duration_secs: req.duration_secs,
            },
            &on_progress,
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(serde_json::json!({
        "passed": outcome.passed(),
        "findings": outcome.findings,
        "seed_warning": outcome.seed_warning,
        "sarif": outcome.sarif,
    }))?))
}

/// One run's full record, by full or short id.
async fn run_detail(
    State(state): State<AppState>,
    Path(run_id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let detail = state
        .container
        .run_detail(&run_id)
        .await
        .map_err(classified_api_error)?;
    approved_project(&state, std::path::Path::new(&detail.run.project_root))?;
    Ok(Json(public_value(detail)?))
}

#[cfg(feature = "run-closeout")]
fn closeout_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/runs/{id}/edges", post(capture_run_edges))
        .route("/runs/edge-diff", post(run_edge_diff))
}

#[cfg(not(feature = "run-closeout"))]
fn closeout_routes(router: Router<AppState>) -> Router<AppState> {
    router
}

/// Capture a finished AFL++ run's covered edge set by replaying its corpus.
#[cfg(feature = "run-closeout")]
async fn capture_run_edges(
    State(state): State<AppState>,
    Path(run_id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    approve_run(&state, run_id).await?;
    let capture = workflow_container(&state, ExplicitAction::RunFuzzer)
        .capture_run_edge_set(run_id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(capture)?))
}

#[cfg(feature = "run-closeout")]
#[derive(Deserialize)]
struct EdgeDiffRequest {
    baseline_id: uuid::Uuid,
    result_id: uuid::Uuid,
}

/// Compare the retained covered edge sets of two runs.
#[cfg(feature = "run-closeout")]
async fn run_edge_diff(
    State(state): State<AppState>,
    Json(req): Json<EdgeDiffRequest>,
) -> ApiResult<serde_json::Value> {
    approve_run(&state, req.baseline_id).await?;
    approve_run(&state, req.result_id).await?;
    let report = state
        .container
        .coverage_diff(req.baseline_id, req.result_id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(report)?))
}

// ---------------------------------------------------------------------------
// Dictionaries, coverage reports, preflight
// ---------------------------------------------------------------------------

async fn user_dictionary(
    State(state): State<AppState>,
    Json(req): Json<ProjectTargetRequest>,
) -> ApiResult<Option<String>> {
    let project = approved_project(&state, &req.project)?;
    Ok(Json(state.container.user_dictionary(&project, &req.target)))
}

#[derive(Deserialize)]
struct SetDictionaryRequest {
    project: PathBuf,
    target: String,
    text: String,
}

/// Validate and store a target's dictionary; returns the token count.
async fn set_user_dictionary(
    State(state): State<AppState>,
    Json(req): Json<SetDictionaryRequest>,
) -> ApiResult<usize> {
    let project = approved_project(&state, &req.project)?;
    state
        .container
        .set_user_dictionary(&project, &req.target, &req.text)
        .await
        .map(Json)
        .map_err(classified_api_error)
}

async fn clear_user_dictionary(
    State(state): State<AppState>,
    Json(req): Json<ProjectTargetRequest>,
) -> ApiResult<()> {
    let project = approved_project(&state, &req.project)?;
    state
        .container
        .clear_user_dictionary(&project, &req.target)
        .await
        .map(Json)
        .map_err(classified_api_error)
}

/// Line coverage as both documents; the browser saves the one it asked for.
async fn coverage_line_report(
    State(state): State<AppState>,
    Json(req): Json<ProjectTargetRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &req.project)?;
    let report = state
        .container
        .coverage_line_report(&project, &req.target)
        .await
        .map_err(classified_api_error)?;
    // The documents name files relative to the project (`SF:` paths and the
    // HTML headings), so they pass through unredacted, like file contents.
    Ok(Json(serde_json::json!({
        "lcov": report.lcov,
        "html": report.html,
        "lines_hit": report.lines_hit,
        "lines_total": report.lines_total,
        "files": report.files,
        "skipped_files": report.skipped_files,
    })))
}

#[derive(Deserialize)]
struct PreflightRequest {
    engine: String,
    duration_secs: Option<u64>,
    require_provider: Option<bool>,
}

/// Check one engine and an intended duration against the campaign policy,
/// as `oxfuzz doctor --engine --duration --require-provider` does.
async fn fuzzing_preflight(Json(req): Json<PreflightRequest>) -> ApiResult<serde_json::Value> {
    let engine = parse_engine(&req.engine).map_err(bad_request)?;
    let preflight = hf_service::fuzzing_preflight(
        engine,
        req.duration_secs,
        req.require_provider.unwrap_or(false),
    )
    .await;
    Ok(Json(public_value(preflight)?))
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

#[cfg(feature = "crash-alerts")]
fn alert_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/notifications/test", post(notifications_test))
        .route("/notifications/latest-run", post(notify_latest_run))
}

#[cfg(not(feature = "crash-alerts"))]
fn alert_routes(router: Router<AppState>) -> Router<AppState> {
    router
}

/// Send a test message to the configured notification webhook.
#[cfg(feature = "crash-alerts")]
async fn notifications_test(State(state): State<AppState>) -> ApiResult<()> {
    workflow_container(&state, ExplicitAction::PublishFindings)
        .notifications_test()
        .await
        .map(Json)
        .map_err(classified_api_error)
}

/// Alert the webhook about the crashes of a target's latest run; returns the
/// number reported, zero meaning nothing was sent.
#[cfg(feature = "crash-alerts")]
async fn notify_latest_run(
    State(state): State<AppState>,
    Json(req): Json<ProjectTargetRequest>,
) -> ApiResult<usize> {
    let project = approved_project(&state, &req.project)?;
    workflow_container(&state, ExplicitAction::PublishFindings)
        .notify_latest_run(&project, &req.target)
        .await
        .map(Json)
        .map_err(classified_api_error)
}

// ---------------------------------------------------------------------------
// Clang analysis
// ---------------------------------------------------------------------------

/// Whether this server was built with Clang semantic analysis.
async fn clang_available() -> Json<bool> {
    Json(cfg!(feature = "clang-analysis"))
}

#[cfg(feature = "clang-analysis")]
fn clang_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/clang/analysis", post(clang_analysis_start))
        .route("/clang/analysis/{id}", get(clang_analysis_status))
        .route("/clang/analysis/{id}/result", get(clang_analysis_result))
        .route("/clang/analysis/{id}/cancel", post(clang_analysis_cancel))
}

#[cfg(not(feature = "clang-analysis"))]
fn clang_routes(router: Router<AppState>) -> Router<AppState> {
    router
}

#[cfg(feature = "clang-analysis")]
#[derive(Deserialize)]
struct ClangStartRequest {
    project: PathBuf,
    lang: String,
}

#[cfg(feature = "clang-analysis")]
async fn clang_analysis_start(
    State(state): State<AppState>,
    Json(req): Json<ClangStartRequest>,
) -> ApiResult<serde_json::Value> {
    let language = parse_lang(&req.lang).map_err(bad_request)?;
    let project = approved_project(&state, &req.project)?;
    let operation = state
        .container
        .start_clang_analysis(hf_service::clang_analysis::StartClangAnalysisRequest {
            project,
            language,
            target_ids: vec![],
        })
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(operation)?))
}

/// The operation, after refusing one whose project is outside the roots.
#[cfg(feature = "clang-analysis")]
async fn approved_clang_operation(
    state: &AppState,
    id: uuid::Uuid,
) -> Result<hf_service::clang_analysis::ClangOperationRecord, ApiError> {
    let operation = state
        .container
        .clang_analysis_operation(id)
        .await
        .map_err(classified_api_error)?
        .ok_or_else(|| map_err(StatusCode::NOT_FOUND)("Clang analysis operation not found"))?;
    approved_project(state, std::path::Path::new(&operation.project_root))?;
    Ok(operation)
}

#[cfg(feature = "clang-analysis")]
async fn clang_analysis_status(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    let operation = approved_clang_operation(&state, id).await?;
    Ok(Json(public_value(operation)?))
}

#[cfg(feature = "clang-analysis")]
async fn clang_analysis_result(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    approved_clang_operation(&state, id).await?;
    let result = state
        .container
        .clang_analysis_result(id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(result)?))
}

#[cfg(feature = "clang-analysis")]
async fn clang_analysis_cancel(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> ApiResult<serde_json::Value> {
    approved_clang_operation(&state, id).await?;
    let operation = state
        .container
        .cancel_clang_analysis(id)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(operation)?))
}

// ---------------------------------------------------------------------------
// Automotive
// ---------------------------------------------------------------------------

#[cfg(feature = "automotive-scapy")]
fn automotive_routes(router: Router<AppState>) -> Router<AppState> {
    router
        .route("/automotive/scan-uds", post(automotive_scan_uds))
        .route("/automotive/live-monitor", post(automotive_live_monitor))
}

#[cfg(not(feature = "automotive-scapy"))]
fn automotive_routes(router: Router<AppState>) -> Router<AppState> {
    router
}

#[cfg(feature = "automotive-scapy")]
#[derive(Deserialize)]
struct UdsScanRequest {
    project_root: PathBuf,
    interface: String,
    request_ids: Vec<u32>,
    services: Vec<u8>,
}

/// A read-only UDS discovery scan on an allowlisted virtual CAN interface;
/// the service denies any non-read-only service before dispatch.
#[cfg(feature = "automotive-scapy")]
async fn automotive_scan_uds(
    State(state): State<AppState>,
    Json(req): Json<UdsScanRequest>,
) -> ApiResult<serde_json::Value> {
    let project_root = approved_project(&state, &req.project_root)?;
    let outcome = workflow_container(&state, ExplicitAction::AutomotiveVirtualCan)
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::ScanUds {
                mode: hf_service::automotive::ModeConfig::VirtualCan {
                    interface: req.interface,
                },
                protocol: hf_service::automotive::AutomotiveProtocol::Uds,
                request_ids: req.request_ids,
                services: req.services,
            },
            approval: None,
        })
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(outcome)?))
}

#[cfg(feature = "automotive-scapy")]
#[derive(Deserialize)]
struct LiveMonitorRequest {
    project_root: PathBuf,
    interface: String,
    protocol: String,
}

/// Observe traffic on an allowlisted virtual CAN interface.
#[cfg(feature = "automotive-scapy")]
async fn automotive_live_monitor(
    State(state): State<AppState>,
    Json(req): Json<LiveMonitorRequest>,
) -> ApiResult<serde_json::Value> {
    let protocol =
        serde_json::from_value(serde_json::Value::String(req.protocol)).map_err(bad_request)?;
    let project_root = approved_project(&state, &req.project_root)?;
    let outcome = workflow_container(&state, ExplicitAction::AutomotiveVirtualCan)
        .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
            project_root,
            command: hf_service::automotive::AutomotiveCommand::LiveMonitor {
                mode: hf_service::automotive::ModeConfig::VirtualCan {
                    interface: req.interface,
                },
                protocol,
            },
            approval: None,
        })
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(outcome)?))
}
