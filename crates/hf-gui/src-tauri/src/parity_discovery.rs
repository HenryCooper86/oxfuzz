//! Desktop wrappers for discovery-side and scheduler operations the command
//! line already offers: Clang semantic analysis, a run's full record, and
//! arming another server. Thin adapters over `hf-service`.

use hf_service::remote_arm::RemoteArmAction;

use crate::state::AppState;

/// Whether this build includes Clang semantic analysis.
#[tauri::command]
#[must_use]
pub const fn clang_available() -> bool {
    cfg!(feature = "clang-analysis")
}

/// Start Clang call and type analysis of a C or C++ project in the sandbox.
#[cfg(feature = "clang-analysis")]
#[tauri::command]
pub async fn clang_analysis_start(
    state: tauri::State<'_, AppState>,
    project: std::path::PathBuf,
    lang: String,
) -> Result<serde_json::Value, String> {
    let language = lang.parse()?;
    let operation = state
        .container
        .start_clang_analysis(hf_service::clang_analysis::StartClangAnalysisRequest {
            project,
            language,
            target_ids: vec![],
        })
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(operation).map_err(|error| error.to_string())
}

/// The retained state of one Clang analysis operation.
#[cfg(feature = "clang-analysis")]
#[tauri::command]
pub async fn clang_analysis_status(
    state: tauri::State<'_, AppState>,
    operation_id: uuid::Uuid,
) -> Result<serde_json::Value, String> {
    let operation = state
        .container
        .clang_analysis_operation(operation_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Clang analysis operation not found".to_owned())?;
    serde_json::to_value(operation).map_err(|error| error.to_string())
}

/// The retained result of a finished Clang analysis, or `null`.
#[cfg(feature = "clang-analysis")]
#[tauri::command]
pub async fn clang_analysis_result(
    state: tauri::State<'_, AppState>,
    operation_id: uuid::Uuid,
) -> Result<serde_json::Value, String> {
    let result = state
        .container
        .clang_analysis_result(operation_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

/// Cancel a Clang analysis and return its terminal state.
#[cfg(feature = "clang-analysis")]
#[tauri::command]
pub async fn clang_analysis_cancel(
    state: tauri::State<'_, AppState>,
    operation_id: uuid::Uuid,
) -> Result<serde_json::Value, String> {
    let operation = state
        .container
        .cancel_clang_analysis(operation_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(operation).map_err(|error| error.to_string())
}

/// One run's full record and latest persisted metrics, by full or short id.
#[tauri::command]
pub async fn run_detail(
    state: tauri::State<'_, AppState>,
    run_id: String,
) -> Result<serde_json::Value, String> {
    let detail = state
        .container
        .run_detail(&run_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(detail).map_err(|error| error.to_string())
}

/// Arm, disarm, or read the arming state of another running server.
/// Returns the reported state, or `null` when the reply carries none.
#[tauri::command]
pub async fn remote_schedule_arm(
    url: String,
    action: RemoteArmAction,
    token: Option<String>,
) -> Result<Option<bool>, String> {
    hf_service::remote_arm::remote_schedule_arm(&url, action, token.as_deref())
        .await
        .map_err(|error| error.to_string())
}
