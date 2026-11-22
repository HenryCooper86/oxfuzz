//! Desktop wrappers for webhook alerts and provider recovery. Thin adapters
//! over `hf-service`.

use crate::state::AppState;

/// Send a test message to the configured notification webhook.
#[cfg(feature = "crash-alerts")]
#[tauri::command]
pub async fn notifications_test(state: tauri::State<'_, AppState>) -> Result<(), String> {
    crate::workflow_approval::with_user_approval(
        &state.container,
        crate::workflow_approval::ExplicitAction::PublishFindings,
    )
    .notifications_test()
    .await
    .map_err(|error| error.to_string())
}

/// Alert the webhook about the crashes of a target's latest run. Returns the
/// number of crashes reported; zero means nothing was sent.
#[cfg(feature = "crash-alerts")]
#[tauri::command]
pub async fn notify_latest_run(
    state: tauri::State<'_, AppState>,
    project: std::path::PathBuf,
    target: String,
) -> Result<usize, String> {
    crate::workflow_approval::with_user_approval(
        &state.container,
        crate::workflow_approval::ExplicitAction::PublishFindings,
    )
    .notify_latest_run(&project, &target)
    .await
    .map_err(|error| error.to_string())
}

/// Thaw a frozen provider after a verifying health check.
#[tauri::command]
pub async fn thaw_provider(
    state: tauri::State<'_, AppState>,
    provider_id: String,
) -> Result<(), String> {
    state
        .container
        .thaw_provider(&provider_id)
        .await
        .map_err(|error| error.to_string())
}
