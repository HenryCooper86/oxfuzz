//! Bounded REST adapters for retained coverage investigations.
use crate::router::AppState;
use axum::{
    extract::{Path, Query, Request, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use hf_service::coverage_experiments::{
    parse_coverage_experiment_id, CancelCoverageExperimentRequest,
    CompleteCoverageExperimentRequest, CoverageExperimentError,
    CoverageExperimentErrorCode as Code, CoverageExperimentScope, CreateCoverageExperimentRequest,
    ListCoverageExperimentsRequest, MAX_COVERAGE_EXPERIMENT_REQUEST_BYTES,
};
use serde::{de::DeserializeOwned, Deserialize};

type ApiError = (StatusCode, Json<CoverageExperimentError>);
fn error(code: Code) -> ApiError {
    map_error(CoverageExperimentError::new(code))
}
fn map_error(value: CoverageExperimentError) -> ApiError {
    let status = match value.code() {
        "feature_unavailable" => StatusCode::NOT_IMPLEMENTED,
        "storage_unavailable" | "storage_error" => StatusCode::INTERNAL_SERVER_ERROR,
        "not_found" => StatusCode::NOT_FOUND,
        "project_not_authorized" => StatusCode::FORBIDDEN,
        "invalid_request" | "invalid_project_path" => StatusCode::BAD_REQUEST,
        "terminal_conflict" | "source_evidence_changed" | "run_retained_by_experiment" => {
            StatusCode::CONFLICT
        }
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (status, Json(value))
}
fn oversized() -> ApiError {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(CoverageExperimentError::new(Code::InvalidRequest)),
    )
}
fn approve(state: &AppState, project: &std::path::Path) -> Result<(), ApiError> {
    state
        .approve_project(project)
        .map(|_| ())
        .map_err(|_| error(Code::ProjectNotAuthorized))
}
async fn body<T: DeserializeOwned>(request: Request) -> Result<T, ApiError> {
    let bytes = axum::body::to_bytes(request.into_body(), MAX_COVERAGE_EXPERIMENT_REQUEST_BYTES)
        .await
        .map_err(|_| oversized())?;
    serde_json::from_slice(&bytes).map_err(|_| error(Code::InvalidRequest))
}
fn query<T: DeserializeOwned>(request: &Request) -> Result<T, ApiError> {
    if request
        .uri()
        .query()
        .is_some_and(|raw| raw.len() > MAX_COVERAGE_EXPERIMENT_REQUEST_BYTES)
    {
        return Err(oversized());
    }
    Query::try_from_uri(request.uri())
        .map(|Query(value)| value)
        .map_err(|_| error(Code::InvalidRequest))
}
fn decode<T: DeserializeOwned>(value: serde_json::Value) -> Result<T, ApiError> {
    serde_json::from_value(value).map_err(|_| error(Code::InvalidRequest))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeQuery {
    project: String,
    target_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    project: String,
    target_id: Option<String>,
    limit: usize,
    before_created_at: Option<String>,
    before_id: Option<String>,
}
async fn access(
    state: &AppState,
    id: uuid::Uuid,
    scope: CoverageExperimentScope,
    result: Option<uuid::Uuid>,
) -> Result<(), ApiError> {
    let owner = state
        .container
        .coverage_experiment_owner(id)
        .await
        .map_err(map_error)?;
    approve(state, &owner.project_root)?;
    if let Some(result) = result {
        if state.container.store().is_none() {
            return Err(error(Code::StorageUnavailable));
        }
        let project = state
            .container
            .run_project(result)
            .await
            .map_err(|value| match value {
                hf_service::ClassifiedError::Validation(_) => error(Code::NotFound),
                _ => error(Code::StorageError),
            })?;
        approve(state, &project)?;
    }
    state
        .container
        .validate_coverage_experiment_scope(id, scope, result)
        .await
        .map_err(map_error)
}
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/coverage/experiments", post(create).get(list))
        .route("/coverage/experiments/{id}", get(get_one))
        .route("/coverage/experiments/{id}/complete", post(complete))
        .route("/coverage/experiments/{id}/cancel", post(cancel))
}
async fn create(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request: CreateCoverageExperimentRequest = body(request).await?;
    approve(&state, &request.project)?;
    #[cfg(feature = "coverage-experiments")]
    {
        public(
            state
                .container
                .create_coverage_experiment(request)
                .await
                .map_err(map_error)?,
        )
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(error(Code::FeatureUnavailable))
    }
}
async fn list(
    State(state): State<AppState>,
    request: Request,
) -> Result<Json<serde_json::Value>, ApiError> {
    let raw: ListQuery = query(&request)?;
    let before = match (raw.before_created_at, raw.before_id) {
        (None, None) => serde_json::Value::Null,
        (Some(created_at), Some(id)) => serde_json::json!({"created_at":created_at,"id":id}),
        _ => return Err(error(Code::InvalidRequest)),
    };
    let request: ListCoverageExperimentsRequest = decode(
        serde_json::json!({"project":raw.project,"target_id":raw.target_id,"limit":raw.limit,"before":before}),
    )?;
    approve(&state, &request.project)?;
    #[cfg(feature = "coverage-experiments")]
    {
        public(
            state
                .container
                .list_coverage_experiments(request)
                .await
                .map_err(map_error)?,
        )
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(error(Code::FeatureUnavailable))
    }
}
async fn get_one(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Json<serde_json::Value>, ApiError> {
    let raw: ScopeQuery = query(&request)?;
    let scope: CoverageExperimentScope =
        decode(serde_json::json!({"project":raw.project,"target_id":raw.target_id}))?;
    let id = parse_coverage_experiment_id(&id).map_err(map_error)?;
    access(&state, id, scope.clone(), None).await?;
    #[cfg(feature = "coverage-experiments")]
    {
        public(
            state
                .container
                .coverage_experiment(id, scope)
                .await
                .map_err(map_error)?,
        )
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(error(Code::FeatureUnavailable))
    }
}
async fn complete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request: CompleteCoverageExperimentRequest = body(request).await?;
    let id = parse_coverage_experiment_id(&id).map_err(map_error)?;
    access(
        &state,
        id,
        request.scope.clone(),
        Some(request.result_run_id),
    )
    .await?;
    #[cfg(feature = "coverage-experiments")]
    {
        public(
            state
                .container
                .complete_coverage_experiment(id, request)
                .await
                .map_err(map_error)?,
        )
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(error(Code::FeatureUnavailable))
    }
}
async fn cancel(
    State(state): State<AppState>,
    Path(id): Path<String>,
    request: Request,
) -> Result<Json<serde_json::Value>, ApiError> {
    let request: CancelCoverageExperimentRequest = body(request).await?;
    let id = parse_coverage_experiment_id(&id).map_err(map_error)?;
    access(&state, id, request.scope.clone(), None).await?;
    #[cfg(feature = "coverage-experiments")]
    {
        public(
            state
                .container
                .cancel_coverage_experiment(id, request)
                .await
                .map_err(map_error)?,
        )
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(error(Code::FeatureUnavailable))
    }
}
#[cfg(feature = "coverage-experiments")]
fn public(value: impl serde::Serialize) -> Result<Json<serde_json::Value>, ApiError> {
    serde_json::to_value(value)
        .map(Json)
        .map_err(|_| error(Code::StorageError))
}
