//! Thin desktop adapters for retained Run Closeout state.

use serde_json::Value;
use uuid::Uuid;

#[cfg(not(feature = "run-closeout"))]
const UNAVAILABLE: &str = "Run Closeout is not included in this application build";

#[cfg(not(feature = "run-closeout"))]
fn unavailable() -> Result<Value, Value> {
    Err(serde_json::json!({
        "code": "unavailable",
        "message": UNAVAILABLE
    }))
}

#[tauri::command]
pub async fn run_closeout_report(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: Uuid,
) -> Result<Value, Value> {
    #[cfg(feature = "run-closeout")]
    return state
        .container
        .retained_run_closeout(run_id)
        .await
        .map_err(|error| serde_json::json!({ "code": "closeout_read_failed", "message": error.to_string() }))
        .and_then(|report| serde_json::to_value(report).map_err(|error| serde_json::json!({
            "code": "closeout_response_failed", "message": error.to_string()
        })));
    #[cfg(not(feature = "run-closeout"))]
    {
        let _ = (state, run_id);
        unavailable()
    }
}

#[tauri::command]
pub async fn run_closeout(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: Uuid,
) -> Result<Value, Value> {
    #[cfg(feature = "run-closeout")]
    return state
        .container
        .close_out_run(run_id)
        .await
        .map_err(
            |error| serde_json::json!({ "code": "closeout_failed", "message": error.to_string() }),
        )
        .and_then(|report| {
            serde_json::to_value(report).map_err(|error| {
                serde_json::json!({
                    "code": "closeout_response_failed", "message": error.to_string()
                })
            })
        });
    #[cfg(not(feature = "run-closeout"))]
    {
        let _ = (state, run_id);
        unavailable()
    }
}
