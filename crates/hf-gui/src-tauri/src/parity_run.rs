//! Desktop wrappers for run-side operations the command line already offers:
//! multi-iteration campaigns, the CI gate, per-target dictionaries, and the
//! engine preflight. Thin adapters over `hf-service`.

use std::path::PathBuf;

use hf_service::{AiPolicy, EngineKind, FuzzProgress, Sanitizer, TargetLanguage};
use serde::Deserialize;
use tauri::Emitter;

use crate::state::AppState;
use crate::workflow_approval::{with_user_approval, ExplicitAction};

fn progress_payload(progress: FuzzProgress) -> serde_json::Value {
    let (kind, data) = match progress {
        FuzzProgress::EdgesCovered(value) => ("EdgesCovered", serde_json::json!(value)),
        FuzzProgress::ExecsPerSec(value) => ("ExecsPerSec", serde_json::json!(value)),
        FuzzProgress::CrashesFound(value) => ("CrashesFound", serde_json::json!(value)),
        FuzzProgress::LogLine(value) => ("LogLine", serde_json::json!(value)),
        FuzzProgress::Stats(value) => ("Stats", serde_json::json!(value)),
        FuzzProgress::Done => ("Done", serde_json::Value::Null),
    };
    serde_json::json!({ "type": kind, "data": data })
}

fn parse_seed(seed: Option<&str>) -> Result<Option<u64>, String> {
    seed.map(str::parse)
        .transpose()
        .map_err(|error| format!("invalid seed: {error}"))
}

fn parse_sanitizer(sanitizer: Option<&str>) -> Result<Option<Sanitizer>, String> {
    sanitizer.map(str::parse).transpose()
}

/// Options of `oxfuzz campaign`, as the desktop form sends them.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CampaignOptions {
    project: PathBuf,
    /// Absent: the service picks the top-ranked target.
    target: Option<String>,
    engine: String,
    lang: Option<String>,
    duration_secs: u64,
    iterations: usize,
    timeout_ms: Option<u64>,
    resume: Option<bool>,
    sanitizer: Option<String>,
    cmplog: Option<bool>,
    /// Decimal text, so the webview keeps every bit above 2^53.
    seed: Option<String>,
    ai: Option<AiPolicy>,
}

/// Run an approved campaign: seed, run, triage, for up to `iterations`
/// rounds. Progress is emitted as `campaign:progress` events.
#[tauri::command]
pub async fn run_campaign<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: tauri::State<'_, AppState>,
    options: CampaignOptions,
) -> Result<serde_json::Value, String> {
    let engine: EngineKind = options.engine.parse()?;
    let lang: TargetLanguage = options
        .lang
        .as_deref()
        .map_or(Ok(TargetLanguage::C), str::parse)?;
    let sanitizer = parse_sanitizer(options.sanitizer.as_deref())?;
    let seed = parse_seed(options.seed.as_deref())?;
    let container = with_user_approval(&state.container, ExplicitAction::RunFuzzer)
        .scoped_to_ai_policy(options.ai.unwrap_or_default(), "this campaign")
        .await
        .map_err(|error| error.to_string())?;
    let on_progress = move |progress: FuzzProgress| {
        // Swallowed: progress display is advisory; the result is authoritative.
        let _ = app.emit("campaign:progress", progress_payload(progress));
    };
    let outcome = container
        .run_campaign_observed(
            &options.project,
            options
                .target
                .as_deref()
                .filter(|target| !target.is_empty()),
            engine,
            lang,
            options.duration_secs,
            options.timeout_ms,
            options.resume,
            sanitizer,
            options.cmplog,
            seed,
            options.iterations,
            &on_progress,
        )
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(outcome).map_err(|error| error.to_string())
}

/// The CI gate: a short run of a promoted harness plus triage. Returns the
/// findings and the SARIF document; `passed` is false when any input crashed.
#[tauri::command]
pub async fn run_ci_gate<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    duration_secs: u64,
    ai: Option<AiPolicy>,
) -> Result<serde_json::Value, String> {
    let engine: EngineKind = engine.parse()?;
    let container = with_user_approval(&state.container, ExplicitAction::RunFuzzer)
        .scoped_to_ai_policy(ai.unwrap_or_default(), "this CI gate")
        .await
        .map_err(|error| error.to_string())?;
    let on_progress = move |progress: FuzzProgress| {
        // Swallowed: progress display is advisory; the result is authoritative.
        let _ = app.emit("campaign:progress", progress_payload(progress));
    };
    let outcome = container
        .run_ci_gate(
            hf_service::sarif::CiGateRequest {
                project: &project,
                target: &target,
                engine,
                duration_secs,
            },
            &on_progress,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "passed": outcome.passed(),
        "findings": outcome.findings,
        "seed_warning": outcome.seed_warning,
        "sarif": outcome.sarif,
    }))
}

/// Save a document the frontend already holds (a CI gate's SARIF, a coverage
/// report) through a native save dialog. Returns the path, or `None` when
/// the dialog was cancelled.
#[tauri::command]
pub async fn save_text_file<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    file_name: String,
    extensions: Vec<String>,
    contents: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let extensions: Vec<&str> = extensions.iter().map(String::as_str).collect();
    let Some(path) = app
        .dialog()
        .file()
        .set_file_name(file_name)
        .add_filter("Document", &extensions)
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|error| format!("invalid save path: {error}"))?;
    std::fs::write(&path, contents)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(Some(path.display().to_string()))
}

/// The dictionary stored for a target, or `None` when there is none.
#[tauri::command]
pub fn user_dictionary(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Option<String> {
    state.container.user_dictionary(&project, &target)
}

/// Validate and store a dictionary for a target. Returns the token count.
#[tauri::command]
pub async fn set_user_dictionary(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    text: String,
) -> Result<usize, String> {
    state
        .container
        .set_user_dictionary(&project, &target, &text)
        .await
        .map_err(|error| error.to_string())
}

/// Remove the dictionary stored for a target.
#[tauri::command]
pub async fn clear_user_dictionary(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Result<(), String> {
    state
        .container
        .clear_user_dictionary(&project, &target)
        .await
        .map_err(|error| error.to_string())
}

/// Check one engine and an intended duration against the campaign policy,
/// as `oxfuzz doctor --engine --duration --require-provider` does.
#[tauri::command]
pub async fn fuzzing_preflight(
    engine: String,
    duration_secs: Option<u64>,
    require_provider: Option<bool>,
) -> Result<hf_service::FuzzingPreflight, String> {
    let engine: EngineKind = engine.parse()?;
    Ok(
        hf_service::fuzzing_preflight(engine, duration_secs, require_provider.unwrap_or(false))
            .await,
    )
}

#[cfg(test)]
mod tests {
    use super::{parse_sanitizer, parse_seed, CampaignOptions};

    #[test]
    fn campaign_options_use_the_frontend_field_names() {
        let options: CampaignOptions = serde_json::from_value(serde_json::json!({
            "project": "/work/demo",
            "engine": "afl++",
            "durationSecs": 60,
            "iterations": 3,
            "timeoutMs": 500,
            "seed": "18446744073709551615",
        }))
        .unwrap();
        assert_eq!(options.duration_secs, 60);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.timeout_ms, Some(500));
        assert_eq!(parse_seed(options.seed.as_deref()), Ok(Some(u64::MAX)));
        assert!(options.target.is_none());
    }

    #[test]
    fn a_seed_or_sanitizer_that_does_not_parse_is_refused() {
        assert!(parse_seed(Some("1.5"))
            .unwrap_err()
            .contains("invalid seed"));
        assert!(parse_sanitizer(Some("nonsense")).is_err());
        assert_eq!(parse_sanitizer(None), Ok(None));
    }
}
