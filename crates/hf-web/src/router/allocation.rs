//! Thin HTTP transport for service-owned project allocations.
use super::{
    approved_project, classified_api_error, post, public_value, ApiResult, AppState, Deserialize,
    Json, Router, State,
};

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/campaign/allocation/candidates", post(candidates))
        .route("/campaign/allocation/status", post(status))
        .route("/campaign/allocation/propose", post(propose))
        .route("/campaign/allocation/review", post(review))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRequest {
    project: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewRequest {
    project: String,
    id: uuid::Uuid,
    digest: String,
    approve: bool,
}
async fn candidates(
    State(state): State<AppState>,
    Json(request): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&request.project))?;
    Ok(Json(public_value(
        state
            .container
            .allocation_candidates(&project)
            .await
            .map_err(classified_api_error)?,
    )))
}
async fn status(
    State(state): State<AppState>,
    Json(request): Json<ProjectRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&request.project))?;
    Ok(Json(public_value(
        state
            .container
            .allocation_status(&project)
            .await
            .map_err(classified_api_error)?,
    )))
}
async fn propose(
    State(state): State<AppState>,
    Json(mut request): Json<hf_service::campaign_allocation::AllocationRequest>,
) -> ApiResult<serde_json::Value> {
    request.project = approved_project(&state, std::path::Path::new(&request.project))?
        .to_string_lossy()
        .into_owned();
    Ok(Json(public_value(
        state
            .container
            .propose_allocation(request)
            .await
            .map_err(classified_api_error)?,
    )))
}
async fn review(
    State(state): State<AppState>,
    Json(request): Json<ReviewRequest>,
) -> ApiResult<serde_json::Value> {
    let project = approved_project(&state, std::path::Path::new(&request.project))?;
    Ok(Json(public_value(
        state
            .container
            .review_allocation(&project, request.id, &request.digest, request.approve)
            .await
            .map_err(classified_api_error)?,
    )))
}
