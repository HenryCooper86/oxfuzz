//! Desktop wrappers for binary-only fuzzing (AFL++ QEMU mode) and for
//! drafting or filing one of its findings. Thin adapters over `hf-service`.

use std::path::PathBuf;

use hf_service::{BinaryFuzzRequest, BinaryInput};
use serde::Deserialize;

use crate::state::AppState;
use crate::workflow_approval::{with_user_approval, ExplicitAction};

/// Options of `oxfuzz binary`, as the desktop form sends them.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryFuzzOptions {
    project: PathBuf,
    binary: PathBuf,
    input: BinaryInput,
    seeds: Option<PathBuf>,
    libraries: Option<PathBuf>,
    duration_secs: u64,
    timeout_ms: u64,
    /// Dictionary tokens in AFL escaped form; absent from older forms.
    #[serde(default)]
    dictionary: Vec<String>,
    /// An earlier session of the same binary to continue from.
    #[serde(default)]
    continue_from: Option<uuid::Uuid>,
    /// Split multi-byte comparisons in the emulator; absent from older forms.
    #[serde(default)]
    compcov: bool,
}

/// Fuzz an uninstrumented Linux binary in the sandbox and return the
/// session's report.
#[tauri::command]
pub async fn binary_fuzz(
    state: tauri::State<'_, AppState>,
    options: BinaryFuzzOptions,
) -> Result<hf_service::BinaryFuzzOutcome, String> {
    with_user_approval(&state.container, ExplicitAction::RunHarness)
        .binary_fuzz(&BinaryFuzzRequest {
            project: options.project,
            binary: options.binary,
            input: options.input,
            seeds: options.seeds,
            libraries: options.libraries,
            duration_secs: options.duration_secs,
            timeout_ms: options.timeout_ms,
            dictionary: options.dictionary,
            continue_from: options.continue_from,
            compcov: options.compcov,
        })
        .await
        .map_err(|error| error.to_string())
}

/// Draft an issue for one finding of a session report. Publishes nothing.
#[tauri::command]
pub fn binary_issue_export(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    report: PathBuf,
    finding: String,
) -> Result<hf_service::IssueExport, String> {
    state
        .container
        .binary_issue_export(&project, &report, &finding)
        .map_err(|error| error.to_string())
}

/// File one finding of a session report in the configured issue tracker.
#[tauri::command]
pub async fn binary_file_issue(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    report: PathBuf,
    finding: String,
) -> Result<hf_service::CreatedIssue, String> {
    with_user_approval(&state.container, ExplicitAction::PublishFindings)
        .binary_file_issue(&project, &report, &finding)
        .await
        .map_err(|error| error.to_string())
}

/// Read a binary without running it: architecture, linking, imports, a
/// suggested input mode, strings and dictionary tokens.
#[tauri::command]
pub fn binary_inspect(
    state: tauri::State<'_, AppState>,
    binary: PathBuf,
) -> Result<hf_service::BinaryProfile, String> {
    state
        .container
        .binary_inspect(&binary)
        .map_err(|error| error.to_string())
}

/// Ask the model for seed inputs; they are written to a draft directory the
/// operator may then use as the session's seeds.
#[tauri::command]
pub async fn binary_seed_drafts(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    binary: PathBuf,
    input: BinaryInput,
    description: Option<String>,
    count: usize,
) -> Result<hf_service::BinarySeedDraft, String> {
    state
        .container
        .binary_seed_drafts(&project, &binary, input, description.as_deref(), count)
        .await
        .map_err(|error| error.to_string())
}

/// Ask the model to prune and extend dictionary tokens; returns them for
/// review.
#[tauri::command]
pub async fn binary_dictionary_refine(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    binary: PathBuf,
    input: BinaryInput,
    tokens: Vec<String>,
) -> Result<Vec<String>, String> {
    state
        .container
        .binary_dictionary_refine(&project, &binary, input, &tokens)
        .await
        .map_err(|error| error.to_string())
}

/// The progress of the session running for `project`, if any.
#[tauri::command]
pub fn binary_progress(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
) -> Option<hf_service::BinaryProgress> {
    state.container.binary_progress(&project)
}

/// Stop the running session `session` of `project`; it still reports what
/// it found. Returns whether such a session was running.
#[tauri::command]
pub fn binary_stop(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    session: uuid::Uuid,
) -> bool {
    state.container.binary_stop(&project, session)
}

/// The project's earlier sessions, newest first.
#[tauri::command]
pub fn binary_sessions(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
) -> Result<Vec<hf_service::BinarySessionSummary>, String> {
    state
        .container
        .binary_sessions(&project)
        .map_err(|error| error.to_string())
}

/// One earlier session's report.
#[tauri::command]
pub fn binary_session(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    session: uuid::Uuid,
) -> Result<hf_service::BinaryFuzzOutcome, String> {
    state
        .container
        .binary_session(&project, session)
        .map_err(|error| error.to_string())
}

/// The stored model explanation of one finding, when there is one.
#[tauri::command]
pub async fn binary_finding_explanation(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    session: uuid::Uuid,
    finding: String,
) -> Result<Option<hf_service::BinaryExplanation>, String> {
    state
        .container
        .binary_finding_explanation(&project, session, &finding)
        .await
        .map_err(|error| error.to_string())
}

/// Ask the model to explain one finding. The finding is not changed.
#[tauri::command]
pub async fn binary_finding_explain(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    session: uuid::Uuid,
    finding: String,
) -> Result<hf_service::BinaryExplanation, String> {
    state
        .container
        .binary_finding_explain(&project, session, &finding)
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::BinaryFuzzOptions;
    use hf_service::BinaryInput;

    #[test]
    fn every_input_mode_of_the_command_line_parses_from_the_form() {
        for (name, expected) in [
            ("file", BinaryInput::File),
            ("stdin", BinaryInput::Stdin),
            ("socket", BinaryInput::Socket),
            ("socket_messages", BinaryInput::SocketMessages),
        ] {
            let options: BinaryFuzzOptions = serde_json::from_value(serde_json::json!({
                "project": "/work/demo",
                "binary": "/work/demo/server",
                "input": name,
                "durationSecs": 60,
                "timeoutMs": 1000,
            }))
            .unwrap();
            assert_eq!(options.input, expected);
            assert!(options.seeds.is_none() && options.libraries.is_none());
        }
    }
}
