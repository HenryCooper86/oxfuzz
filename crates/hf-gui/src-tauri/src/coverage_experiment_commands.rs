//! Trusted-local experiment IPC with bounded raw JSON requests.
use crate::state::AppState;
use hf_service::coverage_experiments::{
    parse_coverage_experiment_id, CancelCoverageExperimentRequest,
    CompleteCoverageExperimentRequest, CoverageExperimentError,
    CoverageExperimentErrorCode as Code, CoverageExperimentPage, CoverageExperimentScope,
    CoverageExperimentView, CreateCoverageExperimentRequest, ListCoverageExperimentsRequest,
    MAX_COVERAGE_EXPERIMENT_REQUEST_BYTES,
};
use serde::{de::DeserializeOwned, Deserialize};
use tauri::ipc::{InvokeBody, Request};

fn decode<T: DeserializeOwned>(request: &Request<'_>) -> Result<T, CoverageExperimentError> {
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err(CoverageExperimentError::new(Code::InvalidRequest));
    };
    if bytes.len() > MAX_COVERAGE_EXPERIMENT_REQUEST_BYTES {
        return Err(CoverageExperimentError::new(Code::InvalidRequest));
    }
    serde_json::from_slice(bytes).map_err(|_| CoverageExperimentError::new(Code::InvalidRequest))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GetRequest {
    id: String,
    scope: CoverageExperimentScope,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdRequest<T> {
    id: String,
    request: T,
}

/// Prepare a retained investigation from a bounded desktop request.
#[tauri::command]
pub async fn coverage_experiment_create(
    state: tauri::State<'_, AppState>,
    request: Request<'_>,
) -> Result<CoverageExperimentView, CoverageExperimentError> {
    let request: CreateCoverageExperimentRequest = decode(&request)?;
    #[cfg(feature = "coverage-experiments")]
    {
        state.container.create_coverage_experiment(request).await
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        let _ = state;
        hf_service::coverage_experiments::validate_coverage_experiment_project(&request.project)?;
        Err(CoverageExperimentError::new(Code::FeatureUnavailable))
    }
}
/// Read scoped retained investigation history from a bounded desktop request.
#[tauri::command]
pub async fn coverage_experiment_list(
    state: tauri::State<'_, AppState>,
    request: Request<'_>,
) -> Result<CoverageExperimentPage, CoverageExperimentError> {
    let request: ListCoverageExperimentsRequest = decode(&request)?;
    #[cfg(feature = "coverage-experiments")]
    {
        state.container.list_coverage_experiments(request).await
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        let _ = state;
        hf_service::coverage_experiments::validate_coverage_experiment_project(&request.project)?;
        Err(CoverageExperimentError::new(Code::FeatureUnavailable))
    }
}
/// Read one investigation after validating its selected project and target.
#[tauri::command]
pub async fn coverage_experiment_get(
    state: tauri::State<'_, AppState>,
    request: Request<'_>,
) -> Result<CoverageExperimentView, CoverageExperimentError> {
    let request: GetRequest = decode(&request)?;
    let id = parse_coverage_experiment_id(&request.id)?;
    state
        .container
        .validate_coverage_experiment_scope(id, request.scope.clone(), None)
        .await?;
    #[cfg(feature = "coverage-experiments")]
    {
        state.container.coverage_experiment(id, request.scope).await
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(CoverageExperimentError::new(Code::FeatureUnavailable))
    }
}
/// Attach one retained campaign after validating selected owners and scope.
#[tauri::command]
pub async fn coverage_experiment_complete(
    state: tauri::State<'_, AppState>,
    request: Request<'_>,
) -> Result<CoverageExperimentView, CoverageExperimentError> {
    let envelope: IdRequest<CompleteCoverageExperimentRequest> = decode(&request)?;
    let id = parse_coverage_experiment_id(&envelope.id)?;
    let request = envelope.request;
    state
        .container
        .validate_coverage_experiment_scope(id, request.scope.clone(), Some(request.result_run_id))
        .await?;
    #[cfg(feature = "coverage-experiments")]
    {
        state
            .container
            .complete_coverage_experiment(id, request)
            .await
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(CoverageExperimentError::new(Code::FeatureUnavailable))
    }
}
/// Cancel only the retained investigation after validating selected scope.
#[tauri::command]
pub async fn coverage_experiment_cancel(
    state: tauri::State<'_, AppState>,
    request: Request<'_>,
) -> Result<CoverageExperimentView, CoverageExperimentError> {
    let envelope: IdRequest<CancelCoverageExperimentRequest> = decode(&request)?;
    let id = parse_coverage_experiment_id(&envelope.id)?;
    let request = envelope.request;
    state
        .container
        .validate_coverage_experiment_scope(id, request.scope.clone(), None)
        .await?;
    #[cfg(feature = "coverage-experiments")]
    {
        state
            .container
            .cancel_coverage_experiment(id, request)
            .await
    }
    #[cfg(not(feature = "coverage-experiments"))]
    {
        Err(CoverageExperimentError::new(Code::FeatureUnavailable))
    }
}
