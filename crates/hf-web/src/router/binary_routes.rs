//! Thin HTTP transport for binary-only fuzzing, the routes the desktop
//! app's Binary view calls. Every project, binary, seed, and library path is
//! confined to the approved project roots; the service authorizes the run
//! and the issue filing under the server's environment policy, and confines
//! session report paths to the project's own sessions.
use std::path::{Path, PathBuf};

use super::{
    approved_project, classified_api_error, map_err, post, public_value, ApiError, ApiResult,
    AppState, Deserialize, Json, Router, State, StatusCode,
};
use hf_service::{BinaryFuzzRequest, BinaryInput, BinaryPersistent};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/binary/fuzz", post(fuzz))
        .route("/binary/inspect", post(inspect))
        .route("/binary/seed-drafts", post(seed_drafts))
        .route("/binary/dictionary-refine", post(dictionary_refine))
        .route("/binary/progress", post(progress))
        .route("/binary/stop", post(stop))
        .route("/binary/sessions", post(sessions))
        .route("/binary/session", post(session))
        .route("/binary/finding-explanation", post(finding_explanation))
        .route("/binary/finding-explain", post(finding_explain))
        .route("/binary/issue-export", post(issue_export))
        .route("/binary/file-issue", post(file_issue))
}

fn approved_path(state: &AppState, requested: &Path) -> Result<PathBuf, ApiError> {
    state
        .security
        .approve_path(requested)
        .map_err(map_err(StatusCode::FORBIDDEN))
}

/// A seeds directory: below an approved root, or one the server itself
/// wrote under its workspace root (model-drafted seeds land there, and the
/// Binary view offers them as the next session's seeds).
fn approved_seeds(state: &AppState, requested: &Path) -> Result<PathBuf, ApiError> {
    approved_project(state, requested).or_else(|refusal| {
        let workspace = hf_service::workspace_root().canonicalize().ok();
        requested
            .canonicalize()
            .ok()
            .filter(|path| path.is_dir())
            .filter(|path| {
                workspace
                    .as_ref()
                    .is_some_and(|root| path.starts_with(root))
            })
            .ok_or(refusal)
    })
}

/// The desktop form's options, under the same camelCase names.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FuzzOptions {
    project: PathBuf,
    binary: PathBuf,
    input: BinaryInput,
    seeds: Option<PathBuf>,
    libraries: Option<PathBuf>,
    duration_secs: u64,
    timeout_ms: u64,
    #[serde(default)]
    dictionary: Vec<String>,
    #[serde(default)]
    continue_from: Option<uuid::Uuid>,
    #[serde(default)]
    compcov: bool,
    #[serde(default)]
    persistent: Option<BinaryPersistent>,
    #[serde(default)]
    target_args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FuzzRequest {
    options: FuzzOptions,
}

async fn fuzz(
    State(state): State<AppState>,
    Json(FuzzRequest { options }): Json<FuzzRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &options.project)?;
    let binary = approved_path(&state, &options.binary)?;
    let seeds = options
        .seeds
        .as_deref()
        .map(|path| approved_seeds(&state, path))
        .transpose()?;
    let libraries = options
        .libraries
        .as_deref()
        .map(|path| approved_project(&state, path))
        .transpose()?;
    let outcome = state
        .container
        .binary_fuzz(&BinaryFuzzRequest {
            project,
            binary,
            input: options.input,
            seeds,
            libraries,
            duration_secs: options.duration_secs,
            timeout_ms: options.timeout_ms,
            dictionary: options.dictionary,
            continue_from: options.continue_from,
            compcov: options.compcov,
            persistent: options.persistent,
            target_args: options.target_args,
        })
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(outcome)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryOnly {
    binary: PathBuf,
}

async fn inspect(
    State(state): State<AppState>,
    Json(request): Json<BinaryOnly>,
) -> ApiResult<serde_json::Value> {
    let binary = approved_path(&state, &request.binary)?;
    let profile = state
        .container
        .binary_inspect(&binary)
        .map_err(classified_api_error)?;
    Ok(Json(public_value(profile)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedDraftRequest {
    project: PathBuf,
    binary: PathBuf,
    input: BinaryInput,
    #[serde(default)]
    description: Option<String>,
    count: usize,
}

async fn seed_drafts(
    State(state): State<AppState>,
    Json(request): Json<SeedDraftRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let binary = approved_path(&state, &request.binary)?;
    let draft = state
        .container
        .binary_seed_drafts(
            &project,
            &binary,
            request.input,
            request.description.as_deref(),
            request.count,
        )
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(draft)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DictionaryRequest {
    project: PathBuf,
    binary: PathBuf,
    input: BinaryInput,
    tokens: Vec<String>,
}

async fn dictionary_refine(
    State(state): State<AppState>,
    Json(request): Json<DictionaryRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let binary = approved_path(&state, &request.binary)?;
    let tokens = state
        .container
        .binary_dictionary_refine(&project, &binary, request.input, &request.tokens)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(tokens)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRequest {
    project: PathBuf,
}

async fn progress(
    State(state): State<AppState>,
    Json(request): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    Ok(Json(public_value(
        state.container.binary_progress(&project),
    )?))
}

async fn sessions(
    State(state): State<AppState>,
    Json(request): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let sessions = state
        .container
        .binary_sessions(&project)
        .map_err(classified_api_error)?;
    Ok(Json(public_value(sessions)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionRequest {
    project: PathBuf,
    session: uuid::Uuid,
}

async fn stop(
    State(state): State<AppState>,
    Json(request): Json<SessionRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    Ok(Json(serde_json::Value::Bool(
        state.container.binary_stop(&project, request.session),
    )))
}

async fn session(
    State(state): State<AppState>,
    Json(request): Json<SessionRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let outcome = state
        .container
        .binary_session(&project, request.session)
        .map_err(classified_api_error)?;
    Ok(Json(public_value(outcome)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindingRequest {
    project: PathBuf,
    session: uuid::Uuid,
    finding: String,
}

async fn finding_explanation(
    State(state): State<AppState>,
    Json(request): Json<FindingRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let explanation = state
        .container
        .binary_finding_explanation(&project, request.session, &request.finding)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(explanation)?))
}

async fn finding_explain(
    State(state): State<AppState>,
    Json(request): Json<FindingRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let explanation = state
        .container
        .binary_finding_explain(&project, request.session, &request.finding)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(explanation)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportFindingRequest {
    project: PathBuf,
    report: PathBuf,
    finding: String,
}

async fn issue_export(
    State(state): State<AppState>,
    Json(request): Json<ReportFindingRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let export = state
        .container
        .binary_issue_export(&project, &request.report, &request.finding)
        .map_err(classified_api_error)?;
    Ok(Json(public_value(export)?))
}

async fn file_issue(
    State(state): State<AppState>,
    Json(request): Json<ReportFindingRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, &request.project)?;
    let created = state
        .container
        .binary_file_issue(&project, &request.report, &request.finding)
        .await
        .map_err(classified_api_error)?;
    Ok(Json(public_value(created)?))
}
