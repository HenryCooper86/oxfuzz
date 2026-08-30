//! Harness Work Order v2 REST resources.

use std::path::PathBuf;

use axum::extract::{DefaultBodyLimit, Json, Path, Request, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use hf_service::{
    EngineKind, HarnessWorkOrder, HarnessWorkOrderError, HarnessWorkOrderErrorCode,
    HarnessWorkOrderErrorKind, HarnessWorkOrderExportRequest, HarnessWorkOrderPayload,
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
struct ImportSubmissionRequest {
    source: String,
    origin: SubmissionOriginRequest,
    parent_submission_id: Option<Uuid>,
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
    attempt_ids: Vec<Uuid>,
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
    Json(request): Json<ExportRequest>,
) -> WorkOrderApiResult<WorkOrderResponse> {
    let project = state.approve_project(&request.project).map_err(|error| {
        transport_error(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            error.to_string(),
        )
    })?;
    let language = request
        .lang
        .parse::<TargetLanguage>()
        .map_err(transport_validation_error)?;
    let engine = request
        .engine
        .parse::<EngineKind>()
        .map_err(transport_validation_error)?;
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

async fn list(State(state): State<AppState>) -> WorkOrderApiResult<Vec<WorkOrderResponse>> {
    let work_orders = state
        .container
        .list_harness_work_orders(None)
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
    Json(request): Json<ImportSubmissionRequest>,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderSubmission> {
    let submission = state
        .container
        .import_harness_work_order_submission(ImportHarnessWorkOrderSubmissionRequest {
            work_order_id,
            source: request.source,
            origin: request.origin.into(),
            parent_submission_id: request.parent_submission_id,
        })
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(submission))
}

async fn list_submissions(
    State(state): State<AppState>,
    Path(work_order_id): Path<String>,
) -> WorkOrderApiResult<Vec<hf_service::HarnessWorkOrderSubmission>> {
    let submissions = state
        .container
        .list_harness_work_order_submissions(&work_order_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(submissions))
}

async fn qualify_submission(
    State(state): State<AppState>,
    Path(submission_id): Path<Uuid>,
    request: Request,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderAttempt> {
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
    Path(submission_id): Path<Uuid>,
) -> WorkOrderApiResult<Vec<hf_service::HarnessWorkOrderAttempt>> {
    let attempts = state
        .container
        .list_harness_work_order_attempts(submission_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(attempts))
}

async fn get_attempt(
    State(state): State<AppState>,
    Path(attempt_id): Path<Uuid>,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderAttempt> {
    let attempt = state
        .container
        .harness_work_order_attempt(attempt_id)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(attempt))
}

async fn rank_attempts(
    State(state): State<AppState>,
    Json(request): Json<RankAttemptsRequest>,
) -> WorkOrderApiResult<hf_service::HarnessWorkOrderRanking> {
    let ranking = state
        .container
        .rank_harness_work_order_attempts(&request.attempt_ids)
        .await
        .map_err(work_order_api_error)?;
    Ok(Json(ranking))
}

async fn promote_attempt(
    State(state): State<AppState>,
    Path(attempt_id): Path<Uuid>,
    request: Request,
) -> WorkOrderApiResult<PromotedHarnessResponse> {
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
    }))
}

async fn require_empty_body(request: Request) -> Result<(), WorkOrderApiError> {
    let bytes = axum::body::to_bytes(request.into_body(), 1)
        .await
        .map_err(|_| transport_validation_error("request body must be empty".to_owned()))?;
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(transport_validation_error(
            "request body must be empty".to_owned(),
        ))
    }
}

fn transport_validation_error(message: String) -> WorkOrderApiError {
    transport_error(HarnessWorkOrderErrorCode::InvalidWorkOrderDigest, message)
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
    let message = sanitize_error_message(&message);
    let message = bounded_utf8(&message, MAX_PUBLIC_ERROR_MESSAGE_BYTES)
        .trim_end()
        .to_owned();
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

fn sanitize_error_message(message: &str) -> String {
    let mut redact_next = false;
    message
        .split_whitespace()
        .map(|token| {
            if redact_next {
                redact_next = false;
                return "<redacted>".to_owned();
            }
            let normalized = normalized_error_token(token);
            if normalized.eq_ignore_ascii_case("bearer") {
                redact_next = true;
                return "Bearer".to_owned();
            }
            if secret_key(normalized) {
                redact_next = true;
                return token.to_owned();
            }
            if let Some(redacted) = redact_secret_assignment(token, &mut redact_next) {
                return redacted;
            }
            if secret_value(normalized) {
                return "<redacted>".to_owned();
            }
            redact_absolute_path(token).unwrap_or_else(|| token.to_owned())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalized_error_token(token: &str) -> &str {
    token.trim_matches(|character: char| {
        matches!(
            character,
            '(' | ')' | '[' | ']' | '{' | '}' | '\'' | '"' | ',' | ';' | ':'
        )
    })
}

fn secret_key(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "password" | "secret" | "token" | "api_key" | "api-key" | "apikey"
    )
}

fn secret_value(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.starts_with("sk-")
        || lowercase.starts_with("ghp_")
        || lowercase.starts_with("github_pat_")
        || lowercase.starts_with("xoxb-")
        || lowercase.starts_with("xoxp-")
        || lowercase.starts_with("xoxa-")
        || lowercase.starts_with("hf_")
        || (lowercase.starts_with("akia") && lowercase.len() > 8)
}

fn redact_secret_assignment(token: &str, redact_next: &mut bool) -> Option<String> {
    for (index, character) in token.char_indices() {
        if !matches!(character, '=' | ':') {
            continue;
        }
        let key = normalized_error_token(&token[..index]);
        if !secret_key(key) && !key.eq_ignore_ascii_case("authorization") {
            continue;
        }
        let value = &token[index + character.len_utf8()..];
        if value.eq_ignore_ascii_case("bearer") || (value.is_empty() && secret_key(key)) {
            *redact_next = true;
        }
        return Some(format!("{}<redacted>", &token[..=index]));
    }
    None
}

fn redact_absolute_path(token: &str) -> Option<String> {
    let bytes = token.as_bytes();
    for index in 0..bytes.len() {
        let starts_after_non_word =
            index == 0 || (!bytes[index - 1].is_ascii_alphanumeric() && bytes[index - 1] != b'_');
        let unix = bytes[index] == b'/';
        let windows = bytes.get(index..index + 3).is_some_and(|part| {
            part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
        });
        if starts_after_non_word && (unix || windows) {
            return Some(format!("{}<redacted-path>", &token[..index]));
        }
    }
    None
}

fn bounded_utf8(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
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
            "storage at {private_root}/work-orders.db failed token=secret-value {}",
            "x".repeat(MAX_PUBLIC_ERROR_MESSAGE_BYTES * 2)
        );
        let (_, Json(body)) = work_order_api_error(HarnessWorkOrderError {
            code: HarnessWorkOrderErrorCode::StorageRequired,
            kind: HarnessWorkOrderErrorKind::Storage,
            message,
        });

        assert!(body.error.len() <= MAX_PUBLIC_ERROR_MESSAGE_BYTES);
        assert!(!body.error.contains(private_root));
        assert!(!body.error.contains("secret-value"));
        assert!(!body.error.chars().any(char::is_control));
    }
}
