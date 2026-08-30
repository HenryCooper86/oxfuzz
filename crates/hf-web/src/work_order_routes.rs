//! Harness Work Order v2 REST resources.

use std::path::PathBuf;

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Json, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use hf_service::{
    sanitize_work_order_diagnostic, EngineKind, HarnessStatus, HarnessWorkOrder,
    HarnessWorkOrderError, HarnessWorkOrderErrorCode, HarnessWorkOrderErrorKind,
    HarnessWorkOrderExportRequest, HarnessWorkOrderPayload,
    ImportHarnessWorkOrderSubmissionRequest, TargetLanguage, WorkOrderCommand,
    WorkOrderSubmissionOrigin,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::router::AppState;

const IMPORT_BODY_LIMIT_BYTES: usize = 131_072;
const MAX_PUBLIC_ERROR_MESSAGE_BYTES: usize = 512;

/// Register the complete Harness Work Order v2 REST surface.
pub(crate) fn routes() -> Router<AppState> {
    Router::new()
        .route("/harness/work-orders", post(export).get(list))
        .route("/harness/work-orders/{work_order_id}", get(get_by_id))
        .route(
            "/harness/work-orders/{work_order_id}/submissions",
            post(import_submission)
                .layer(DefaultBodyLimit::max(IMPORT_BODY_LIMIT_BYTES))
                .get(list_submissions),
        )
        .route(
            "/harness/work-order-submissions/{submission_id}/qualifications",
            post(qualify_submission).get(list_attempts),
        )
        .route(
            "/harness/work-order-attempts/{attempt_id}",
            get(get_attempt),
        )
        .route("/harness/work-order-attempts/rank", post(rank_attempts))
        .route(
            "/harness/work-order-attempts/{attempt_id}/promotion",
            post(promote_attempt),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportRequest {
    project: PathBuf,
    target: String,
    lang: String,
    engine: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    project: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportSubmissionRequest {
    source: String,
    origin: SubmissionOriginRequest,
    parent_submission_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SubmissionOriginRequest {
    Human,
    ExternalTool(ExternalToolOriginRequest),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalToolOriginRequest {
    tool: String,
    model: Option<String>,
    response_id: Option<String>,
}

impl From<SubmissionOriginRequest> for WorkOrderSubmissionOrigin {
    fn from(origin: SubmissionOriginRequest) -> Self {
        match origin {
            SubmissionOriginRequest::Human => Self::Human,
            SubmissionOriginRequest::ExternalTool(origin) => Self::ExternalTool {
                tool: origin.tool,
                model: origin.model,
                response_id: origin.response_id,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RankAttemptsRequest {
    attempt_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct WorkOrderResponse {
    schema_version: u32,
    id: String,
    payload: HarnessWorkOrderPayload,
    validation_commands: Vec<WorkOrderCommand>,
}

impl From<HarnessWorkOrder> for WorkOrderResponse {
    fn from(work_order: HarnessWorkOrder) -> Self {
        let validation_commands = hf_service::work_order_commands(&work_order);
        Self {
            schema_version: work_order.schema_version,
            id: work_order.id,
            payload: work_order.payload,
            validation_commands,
        }
    }
}

#[derive(Debug, Serialize)]
struct PromotedHarnessResponse {
    id: Uuid,
    target_id: Uuid,
    engine: EngineKind,
    source: String,
    language: TargetLanguage,
    status: HarnessStatus,
}

#[derive(Debug, Serialize)]
struct WorkOrderErrorResponse {
    code: HarnessWorkOrderErrorCode,
    error: String,
}

type WorkOrderApiError = (StatusCode, Json<WorkOrderErrorResponse>);
type WorkOrderApiResult<T> = Result<Json<T>, WorkOrderApiError>;

async fn export(
    State(state): State<AppState>,
    request: Result<Json<ExportRequest>, JsonRejection>,
) -> WorkOrderApiResult<WorkOrderResponse> {
    let request = extract_json(request)?;
    let project = state.approve_project(&request.project).map_err(|error| {
        transport_error(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            error.to_string(),
        )
    })?;
    let language = request
        .lang
        .parse::<TargetLanguage>()
        .map_err(invalid_request)?;
    let engine = request
        .engine
        .parse::<EngineKind>()
        .map_err(invalid_request)?;
    let work_order = state
        .container
        .export_harness_work_order(HarnessWorkOrderExportRequest {
            project,
            target: request.target,
            language,
            engine,
        })
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(work_order.into()))
}

async fn list(
    State(state): State<AppState>,
    query: Result<Query<ListQuery>, QueryRejection>,
) -> WorkOrderApiResult<Vec<WorkOrderResponse>> {
    let Query(query) = query.map_err(|error| invalid_request(error.body_text()))?;
    let project = query
        .project
        .as_deref()
        .map(|project| {
            state.approve_project(project).map_err(|error| {
                transport_error(
                    HarnessWorkOrderErrorCode::InvalidProjectPath,
                    error.to_string(),
                )
            })
        })
        .transpose()?;
    let work_orders = state
        .container
        .list_harness_work_orders(project.as_deref())
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(
        work_orders
            .into_iter()
            .map(WorkOrderResponse::from)
            .collect(),
    ))
}

async fn get_by_id(
    State(state): State<AppState>,
    Path(work_order_id): Path<String>,
) -> WorkOrderApiResult<WorkOrderResponse> {
    let work_order_id = parse_work_order_id(work_order_id)?;
    let work_order = state
        .container
        .harness_work_order_by_id(&work_order_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(work_order.into()))
}

async fn import_submission(
    State(state): State<AppState>,
    Path(work_order_id): Path<String>,
    request: Result<Json<ImportSubmissionRequest>, JsonRejection>,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderSubmission> {
    let work_order_id = parse_work_order_id(work_order_id)?;
    let request = extract_json(request)?;
    let parent_submission_id = request
        .parent_submission_id
        .as_deref()
        .map(parse_identifier)
        .transpose()?;
    let submission = state
        .container
        .import_harness_work_order_submission(ImportHarnessWorkOrderSubmissionRequest {
            work_order_id,
            source: request.source,
            origin: request.origin.into(),
            parent_submission_id,
        })
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(submission))
}

async fn list_submissions(
    State(state): State<AppState>,
    Path(work_order_id): Path<String>,
) -> WorkOrderApiResult<Vec<hf_service::HarnessWorkOrderSubmission>> {
    let work_order_id = parse_work_order_id(work_order_id)?;
    let submissions = state
        .container
        .list_harness_work_order_submissions(&work_order_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(submissions))
}

async fn qualify_submission(
    State(state): State<AppState>,
    Path(submission_id): Path<String>,
    request: Request,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderAttempt> {
    let submission_id = parse_identifier(&submission_id)?;
    require_empty_body(request).await?;
    let attempt = state
        .container
        .qualify_harness_work_order_submission(submission_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(attempt))
}

async fn list_attempts(
    State(state): State<AppState>,
    Path(submission_id): Path<String>,
) -> WorkOrderApiResult<Vec<hf_service::HarnessWorkOrderAttempt>> {
    let submission_id = parse_identifier(&submission_id)?;
    let attempts = state
        .container
        .list_harness_work_order_attempts(submission_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(attempts))
}

async fn get_attempt(
    State(state): State<AppState>,
    Path(attempt_id): Path<String>,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderAttempt> {
    let attempt_id = parse_identifier(&attempt_id)?;
    let attempt = state
        .container
        .harness_work_order_attempt(attempt_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(attempt))
}

async fn rank_attempts(
    State(state): State<AppState>,
    request: Result<Json<RankAttemptsRequest>, JsonRejection>,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderRanking> {
    let request = extract_json(request)?;
    let attempt_ids = request
        .attempt_ids
        .into_iter()
        .map(|attempt_id| parse_identifier(&attempt_id))
        .collect::<Result<Vec<_>, _>>()?;
    let ranking = state
        .container
        .rank_harness_work_order_attempts(&attempt_ids)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(ranking))
}

async fn promote_attempt(
    State(state): State<AppState>,
    Path(attempt_id): Path<String>,
    request: Request,
) -> WorkOrderApiResult<PromotedHarnessResponse> {
    let attempt_id = parse_identifier(&attempt_id)?;
    require_empty_body(request).await?;
    let harness = state
        .container
        .promote_harness_work_order_attempt(attempt_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(PromotedHarnessResponse {
        id: harness.id,
        target_id: harness.target_id,
        engine: harness.engine,
        source: harness.source,
        language: harness.language,
        status: harness.status,
    }))
}

fn extract_json<T>(request: Result<Json<T>, JsonRejection>) -> Result<T, WorkOrderApiError> {
    match request {
        Ok(Json(request)) => Ok(request),
        Err(error) if error.status() == StatusCode::PAYLOAD_TOO_LARGE => Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            HarnessWorkOrderErrorCode::InvalidRequest,
            &error.body_text(),
        )),
        Err(error) => Err(invalid_request(error.body_text())),
    }
}

fn parse_work_order_id(value: String) -> Result<String, WorkOrderApiError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(value)
    } else {
        Err(transport_error(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "work-order identifier must be a lowercase 64-character SHA-256".to_owned(),
        ))
    }
}

fn parse_identifier(value: &str) -> Result<Uuid, WorkOrderApiError> {
    value.parse::<Uuid>().map_err(|_| {
        transport_error(
            HarnessWorkOrderErrorCode::InvalidIdentifier,
            "identifier must be a UUID".to_owned(),
        )
    })
}

async fn require_empty_body(request: Request) -> Result<(), WorkOrderApiError> {
    let bytes = axum::body::to_bytes(request.into_body(), 1)
        .await
        .map_err(|_| invalid_request("request body must be empty".to_owned()))?;
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(invalid_request("request body must be empty".to_owned()))
    }
}

fn invalid_request(message: String) -> WorkOrderApiError {
    transport_error(HarnessWorkOrderErrorCode::InvalidRequest, message)
}

fn transport_error(code: HarnessWorkOrderErrorCode, message: String) -> WorkOrderApiError {
    work_order_api_error(HarnessWorkOrderError {
        code,
        kind: HarnessWorkOrderErrorKind::Validation,
        message,
    })
}

fn work_order_api_error(error: HarnessWorkOrderError) -> WorkOrderApiError {
    let HarnessWorkOrderError {
        code,
        kind,
        message,
    } = error;
    let status = match kind {
        HarnessWorkOrderErrorKind::Validation => StatusCode::BAD_REQUEST,
        HarnessWorkOrderErrorKind::NotFound => StatusCode::NOT_FOUND,
        HarnessWorkOrderErrorKind::Conflict => StatusCode::CONFLICT,
        HarnessWorkOrderErrorKind::Unavailable | HarnessWorkOrderErrorKind::Sandbox => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        HarnessWorkOrderErrorKind::Provider => StatusCode::BAD_GATEWAY,
        HarnessWorkOrderErrorKind::Storage | HarnessWorkOrderErrorKind::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    api_error(status, code, &message)
}

fn api_error(
    status: StatusCode,
    code: HarnessWorkOrderErrorCode,
    message: &str,
) -> WorkOrderApiError {
    let message = sanitize_work_order_diagnostic(message, MAX_PUBLIC_ERROR_MESSAGE_BYTES);
    let message = if message.is_empty() {
        "harness work order request failed".to_owned()
    } else {
        message
    };
    (
        status,
        Json(WorkOrderErrorResponse {
            code,
            error: message,
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_error_kind_has_one_status_mapping() {
        let cases = [
            (
                HarnessWorkOrderErrorKind::Validation,
                StatusCode::BAD_REQUEST,
            ),
            (HarnessWorkOrderErrorKind::NotFound, StatusCode::NOT_FOUND),
            (HarnessWorkOrderErrorKind::Conflict, StatusCode::CONFLICT),
            (
                HarnessWorkOrderErrorKind::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (HarnessWorkOrderErrorKind::Provider, StatusCode::BAD_GATEWAY),
            (
                HarnessWorkOrderErrorKind::Sandbox,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                HarnessWorkOrderErrorKind::Storage,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (
                HarnessWorkOrderErrorKind::Internal,
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (kind, expected) in cases {
            let (status, Json(body)) = work_order_api_error(HarnessWorkOrderError {
                code: HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                kind,
                message: "bounded message".to_owned(),
            });
            assert_eq!(status, expected, "kind: {kind:?}");
            assert_eq!(body.code, HarnessWorkOrderErrorCode::InvalidWorkOrderDigest);
            assert_eq!(body.error, "bounded message");
        }
    }

    #[test]
    fn public_error_messages_are_bounded_and_sanitized() {
        let private_root = "/Users/operator/private-project";
        let message = format!(
            "storage at {private_root}/work-orders.db failed !sk-punctuated-secret! \
             !token=secret-value !Bearer opaque-credential {}",
            "x".repeat(MAX_PUBLIC_ERROR_MESSAGE_BYTES * 2)
        );
        let (_, Json(body)) = work_order_api_error(HarnessWorkOrderError {
            code: HarnessWorkOrderErrorCode::StorageRequired,
            kind: HarnessWorkOrderErrorKind::Storage,
            message,
        });

        assert!(body.error.len() <= MAX_PUBLIC_ERROR_MESSAGE_BYTES);
        assert!(!body.error.contains(private_root));
        assert!(!body.error.contains("punctuated-secret"));
        assert!(!body.error.contains("secret-value"));
        assert!(!body.error.contains("opaque-credential"));
        assert!(!body.error.chars().any(char::is_control));
    }
}
