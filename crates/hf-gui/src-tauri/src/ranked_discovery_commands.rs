//! Desktop wrappers for service-owned ranked discovery.

use std::path::PathBuf;

use tauri::State;
use uuid::Uuid;

use crate::state::AppState;

#[tauri::command]
pub async fn ranked_discovery_start(
    state: State<'_, AppState>,
    project: PathBuf,
    lang: String,
    ai: Option<hf_service::AiPolicy>,
) -> Result<Uuid, String> {
    let language = lang.parse().map_err(|error: String| error)?;
    // `require` refuses to start a ranking no model can answer; `off` is the
    // plain `discover` command, which calls no model.
    state
        .container
        .scoped_to_ai_policy(ai.unwrap_or_default(), "target ranking")
        .await
        .map_err(|error| error.to_string())?
        .start_ranked_discovery(&project, language)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn ranked_discovery_status(
    state: State<'_, AppState>,
    operation_id: Uuid,
) -> Result<Option<hf_service::RankedDiscoveryStatus>, String> {
    state
        .container
        .ranked_discovery_status(operation_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn ranked_discovery_result(
    state: State<'_, AppState>,
    operation_id: Uuid,
) -> Result<Option<hf_service::RankedDiscoveryResult>, String> {
    state
        .container
        .ranked_discovery_result(operation_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn ranked_discovery_cancel(
    state: State<'_, AppState>,
    operation_id: Uuid,
) -> Result<bool, String> {
    state
        .container
        .cancel_ranked_discovery(operation_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn ranked_discovery_retry(
    state: State<'_, AppState>,
    operation_id: Uuid,
) -> Result<Uuid, String> {
    state
        .container
        .retry_ranked_discovery(operation_id)
        .await
        .map_err(|error| error.to_string())
}
