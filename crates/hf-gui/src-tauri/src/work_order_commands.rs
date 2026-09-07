//! Thin desktop adapters for Harness Work Order v2.

use std::path::PathBuf;

#[cfg(feature = "harness-work-order")]
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

#[cfg(not(feature = "harness-work-order"))]
const UNAVAILABLE: &str = "Harness Work Order is not included in this application build";

#[cfg(feature = "harness-work-order")]
fn response<T: Serialize>(
    result: Result<T, hf_service::HarnessWorkOrderError>,
) -> Result<Value, Value> {
    match result {
        Ok(value) => serde_json::to_value(value).map_err(|error| {
            serde_json::json!({
                "code": "response_serialization_failed",
                "kind": "internal",
                "message": format!("serialize work order response: {error}")
            })
        }),
        Err(error) => serde_json::to_value(error).map_or_else(
            |_| {
                Err(serde_json::json!({
                    "code": "error_serialization_failed",
                    "kind": "internal",
                    "message": "serialize work order error"
                }))
            },
            Err,
        ),
    }
}

#[cfg(not(feature = "harness-work-order"))]
fn unavailable() -> Result<Value, Value> {
    Err(serde_json::json!({
        "code": "unavailable",
        "kind": "unavailable",
        "message": UNAVAILABLE
    }))
}

#[tauri::command]
pub async fn work_order_export(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    target: String,
    lang: String,
    engine: String,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    {
        let language = lang.parse().map_err(|message: String| {
            serde_json::json!({
                "code": "invalid_request", "kind": "validation", "message": message
            })
        })?;
        let engine = engine.parse().map_err(|message: String| {
            serde_json::json!({
                "code": "invalid_request", "kind": "validation", "message": message
            })
        })?;
        return response(
            state
                .container
                .export_harness_work_order(hf_service::HarnessWorkOrderExportRequest {
                    project,
                    target,
                    language,
                    engine,
                })
                .await,
        );
    }
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, project, target, lang, engine);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_list(
    state: tauri::State<'_, crate::state::AppState>,
    project: Option<PathBuf>,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .list_harness_work_orders(project.as_deref())
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, project);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_get(
    state: tauri::State<'_, crate::state::AppState>,
    work_order_id: String,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .harness_work_order_by_id(&work_order_id)
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, work_order_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_import(
    state: tauri::State<'_, crate::state::AppState>,
    work_order_id: String,
    source: String,
    origin: Value,
    parent_submission_id: Option<Uuid>,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    {
        let origin = serde_json::from_value(origin).map_err(|error| {
            serde_json::json!({
                "code": "invalid_provenance", "kind": "validation", "message": error.to_string()
            })
        })?;
        return response(
            state
                .container
                .import_harness_work_order_submission(
                    hf_service::ImportHarnessWorkOrderSubmissionRequest {
                        work_order_id,
                        source,
                        origin,
                        parent_submission_id,
                    },
                )
                .await,
        );
    }
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, work_order_id, source, origin, parent_submission_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_submissions(
    state: tauri::State<'_, crate::state::AppState>,
    work_order_id: String,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .list_harness_work_order_submissions(&work_order_id)
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, work_order_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_qualify(
    state: tauri::State<'_, crate::state::AppState>,
    submission_id: Uuid,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .qualify_harness_work_order_submission(submission_id)
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, submission_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_attempts(
    state: tauri::State<'_, crate::state::AppState>,
    submission_id: Uuid,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .list_harness_work_order_attempts(submission_id)
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, submission_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_attempt(
    state: tauri::State<'_, crate::state::AppState>,
    attempt_id: Uuid,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(state.container.harness_work_order_attempt(attempt_id).await);
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, attempt_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_rank(
    state: tauri::State<'_, crate::state::AppState>,
    attempt_ids: Vec<Uuid>,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .rank_harness_work_order_attempts(&attempt_ids)
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, attempt_ids);
        unavailable()
    }
}

#[tauri::command]
pub async fn work_order_promote(
    state: tauri::State<'_, crate::state::AppState>,
    attempt_id: Uuid,
) -> Result<Value, Value> {
    #[cfg(feature = "harness-work-order")]
    return response(
        state
            .container
            .promote_harness_work_order_attempt(attempt_id)
            .await,
    );
    #[cfg(not(feature = "harness-work-order"))]
    {
        let _ = (state, attempt_id);
        unavailable()
    }
}
