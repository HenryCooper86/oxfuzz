//! Desktop wrappers for analysis operations the command line already offers:
//! bisection, regression replay, corpus maintenance, coverage reports, the
//! trust audit, and edge-set comparison. Thin adapters over `hf-service`.

use std::path::PathBuf;

use hf_service::TargetLanguage;

use crate::state::AppState;
use crate::workflow_approval::{with_user_approval, ExplicitAction};

fn json<T: serde::Serialize>(value: T) -> Result<serde_json::Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

/// Find the first commit at which a triaged crash input crashes.
#[cfg(feature = "crash-bisection")]
#[tauri::command]
pub async fn bisect_crash(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    crash_id: String,
    good: String,
    bad: Option<String>,
) -> Result<serde_json::Value, String> {
    let outcome = with_user_approval(&state.container, ExplicitAction::RunHarness)
        .bisect_crash(
            &project,
            &target,
            &crash_id,
            &good,
            bad.as_deref().filter(|revision| !revision.is_empty()),
        )
        .await
        .map_err(|error| error.to_string())?;
    json(outcome)
}

/// Replay the stored crashes of a target against its current harness.
#[tauri::command]
pub async fn verify_regressions(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Result<serde_json::Value, String> {
    let results = with_user_approval(&state.container, ExplicitAction::Triage)
        .verify_regressions(&project, &target)
        .await
        .map_err(|error| error.to_string())?;
    json(results)
}

/// Minimize the corpus with `afl-cmin` in the sandbox.
#[tauri::command]
pub async fn corpus_afl_cmin(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Result<serde_json::Value, String> {
    let outcome = with_user_approval(&state.container, ExplicitAction::RunFuzzer)
        .corpus_afl_cmin(&project, &target)
        .await
        .map_err(|error| error.to_string())?;
    json(outcome)
}

/// Replace seeds that never survived into the fuzzer's queue.
#[tauri::command]
pub async fn corpus_regenerate_dead_seeds(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    lang: Option<String>,
) -> Result<serde_json::Value, String> {
    let lang: TargetLanguage = lang.as_deref().map_or(Ok(TargetLanguage::C), str::parse)?;
    let outcome = with_user_approval(&state.container, ExplicitAction::RunFuzzer)
        .regenerate_dead_seeds(&project, &target, lang)
        .await
        .map_err(|error| error.to_string())?;
    json(outcome)
}

/// Add the minimized crash inputs of a target to its corpus. Returns the
/// number of inputs absorbed.
#[tauri::command]
pub async fn corpus_absorb_crashes(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Result<usize, String> {
    with_user_approval(&state.container, ExplicitAction::RunFuzzer)
        .corpus_absorb_crashes(&project, &target)
        .await
        .map_err(|error| error.to_string())
}

/// Whether concolic enrichment can run in this sandbox image.
#[cfg(feature = "concolic-enrichment")]
#[tauri::command]
pub async fn concolic_availability(
    state: tauri::State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    json(state.container.concolic_availability().await)
}

/// Grow the corpus with inputs a concolic executor derives.
#[cfg(feature = "concolic-enrichment")]
#[tauri::command]
pub async fn corpus_concolic(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Result<serde_json::Value, String> {
    let outcome = with_user_approval(&state.container, ExplicitAction::RunConcolic)
        .corpus_concolic(&project, &target)
        .await
        .map_err(|error| error.to_string())?;
    json(outcome)
}

/// Line, function and region coverage of a target's corpus, or `None` when
/// no coverage can be measured yet.
#[tauri::command]
pub async fn coverage_summary(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
) -> Result<Option<serde_json::Value>, String> {
    let Some(summary) = state.container.coverage_summary(&project, &target).await else {
        return Ok(None);
    };
    Ok(Some(serde_json::json!({
        "lines_covered": summary.lines_covered,
        "lines_total": summary.lines_total,
        "line_percent": summary.line_percent(),
        "functions_covered": summary.functions_covered,
        "functions_total": summary.functions_total,
        "function_percent": summary.function_percent(),
        "regions_covered": summary.regions_covered,
        "regions_total": summary.regions_total,
        "region_percent": summary.region_percent(),
    })))
}

fn line_report_file(target: &str, format: &str) -> Result<(String, &'static str), String> {
    let stem: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    match format {
        "lcov" => Ok((format!("oxfuzz_{stem}.lcov.info"), "info")),
        "html" => Ok((format!("oxfuzz_{stem}_coverage.html"), "html")),
        other => Err(format!(
            "unknown coverage report format '{other}'; expected lcov or html"
        )),
    }
}

/// Measure line coverage and save it as an lcov tracefile or an HTML report
/// through a native save dialog. Returns the counts and the saved path
/// (`null` when the dialog was cancelled).
#[tauri::command]
pub async fn export_coverage_line_report<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    format: String,
) -> Result<serde_json::Value, String> {
    use tauri_plugin_dialog::DialogExt;

    let (file_name, extension) = line_report_file(&target, &format)?;
    let report = state
        .container
        .coverage_line_report(&project, &target)
        .await
        .map_err(|error| error.to_string())?;
    let saved = match app
        .dialog()
        .file()
        .set_file_name(file_name)
        .add_filter("Coverage report", &[extension])
        .blocking_save_file()
    {
        Some(path) => {
            let path = path
                .into_path()
                .map_err(|error| format!("invalid save path: {error}"))?;
            let document = if format == "lcov" {
                &report.lcov
            } else {
                &report.html
            };
            std::fs::write(&path, document)
                .map_err(|error| format!("write {}: {error}", path.display()))?;
            Some(path.display().to_string())
        }
        None => None,
    };
    Ok(serde_json::json!({
        "path": saved,
        "lines_hit": report.lines_hit,
        "lines_total": report.lines_total,
        "files": report.files,
        "skipped_files": report.skipped_files,
    }))
}

/// Entry points no retained coverage measurement has covered, ranked.
#[cfg(feature = "unreached-surface")]
#[tauri::command]
pub async fn unreached_surface(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    lang: String,
) -> Result<serde_json::Value, String> {
    let lang: TargetLanguage = lang.parse()?;
    let view = state
        .container
        .unreached_surface(&project, lang)
        .await
        .map_err(|error| error.to_string())?;
    json(view)
}

/// Every discovered target attributed against retained coverage, ordered
/// for the next harness.
#[cfg(feature = "unreached-surface")]
#[tauri::command]
pub async fn coverage_attribution(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    lang: String,
) -> Result<serde_json::Value, String> {
    let lang: TargetLanguage = lang.parse()?;
    let view = state
        .container
        .coverage_attribution(&project, lang)
        .await
        .map_err(|error| error.to_string())?;
    json(view)
}

/// Which claims about a finished run its retained evidence supports.
#[cfg(feature = "campaign-trust")]
#[tauri::command]
pub async fn campaign_trust_report(
    state: tauri::State<'_, AppState>,
    run_id: uuid::Uuid,
) -> Result<serde_json::Value, String> {
    let report = state
        .container
        .campaign_trust_report(run_id)
        .await
        .map_err(|error| error.to_string())?;
    json(report)
}

/// Compare the retained covered edge sets of two runs.
#[cfg(feature = "run-closeout")]
#[tauri::command]
pub async fn run_edge_diff(
    state: tauri::State<'_, AppState>,
    baseline_id: uuid::Uuid,
    result_id: uuid::Uuid,
) -> Result<serde_json::Value, String> {
    let report = state
        .container
        .coverage_diff(baseline_id, result_id)
        .await
        .map_err(|error| error.to_string())?;
    json(report)
}

/// Capture a finished AFL++ run's covered edge set by replaying its corpus.
#[cfg(feature = "run-closeout")]
#[tauri::command]
pub async fn capture_run_edges(
    state: tauri::State<'_, AppState>,
    run_id: uuid::Uuid,
) -> Result<serde_json::Value, String> {
    let capture = with_user_approval(&state.container, ExplicitAction::RunFuzzer)
        .capture_run_edge_set(run_id)
        .await
        .map_err(|error| error.to_string())?;
    json(capture)
}

#[cfg(test)]
mod tests {
    use super::line_report_file;

    #[test]
    fn a_line_report_is_named_after_the_target_and_only_known_formats_are_accepted() {
        assert_eq!(
            line_report_file("ns::parse/1", "lcov").unwrap(),
            ("oxfuzz_ns__parse_1.lcov.info".to_owned(), "info")
        );
        assert_eq!(line_report_file("p", "html").unwrap().1, "html");
        assert!(line_report_file("p", "pdf")
            .unwrap_err()
            .contains("expected lcov or html"));
    }
}
