//! Desktop wrappers for harness operations the command line already offers:
//! coverage-guided refinement, adopting a stored revision, and grammar
//! mutators. Thin adapters over `hf-service` (Engineering Protocol 2.9).

use std::path::PathBuf;

use hf_service::{AiPolicy, EngineKind, TargetLanguage};

use crate::workflow_approval::{with_user_approval, ExplicitAction};
use uuid::Uuid;

use crate::state::AppState;

fn language(lang: Option<&str>) -> Result<TargetLanguage, String> {
    lang.map_or(Ok(TargetLanguage::C), str::parse)
}

/// Reshape the existing harness toward still-uncovered reachable functions,
/// then recompile it. The result is a new draft revision that still needs a
/// smoke run and explicit approval.
#[tauri::command]
pub async fn harness_refine(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
    repairs: Option<usize>,
    ai: Option<AiPolicy>,
) -> Result<serde_json::Value, String> {
    let engine: EngineKind = engine.parse()?;
    let outcome = state
        .container
        .harness_refine(
            &project,
            &target,
            engine,
            language(lang.as_deref())?,
            // Refinement recompiles what the model wrote, so it always keeps
            // at least one repair attempt, as `oxfuzz harness --refine` does.
            repairs.unwrap_or(1).max(1),
            ai.unwrap_or_default(),
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "status": format!("{:?}", outcome.status),
        "harness_id": outcome.harness_id,
        "repairs_used": outcome.repairs_used,
        "lint": outcome.lint,
    }))
}

/// Recompile a stored harness revision as the new active revision, such as
/// the refine proposal a campaign records after a coverage plateau.
#[tauri::command]
pub async fn harness_adopt_revision(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
    harness_id: Uuid,
) -> Result<serde_json::Value, String> {
    let engine: EngineKind = engine.parse()?;
    let outcome = state
        .container
        .harness_adopt_revision(
            &project,
            &target,
            engine,
            language(lang.as_deref())?,
            harness_id,
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({ "status": format!("{:?}", outcome.status) }))
}

/// The managed-mutator source a grammar generates, without attaching it.
#[cfg(feature = "managed-mutators")]
#[tauri::command]
pub fn grammar_mutator_source(grammar: String, engine: String) -> Result<String, String> {
    let engine: EngineKind = engine.parse()?;
    hf_service::ServiceContainer::grammar_mutator_source(&grammar, engine)
        .map_err(|error| error.to_string())
}

/// Generate a mutator from a grammar and attach it to the active harness.
#[cfg(feature = "managed-mutators")]
#[tauri::command]
pub async fn attach_grammar_mutator(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    expected_harness_id: Uuid,
    grammar: String,
) -> Result<serde_json::Value, String> {
    let engine: EngineKind = engine.parse()?;
    let status = state
        .container
        .attach_grammar_mutator(&project, &target, engine, expected_harness_id, &grammar)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(status).map_err(|error| error.to_string())
}

/// Smoke-qualify the active revision with the command line's options: repair
/// attempts, the model policy, and the audited opt-out of the model review.
#[tauri::command]
pub async fn harness_smoke_with_options(
    state: tauri::State<'_, AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
    repairs: Option<usize>,
    skip_model_review: Option<bool>,
    ai: Option<AiPolicy>,
) -> Result<serde_json::Value, String> {
    let engine: EngineKind = engine.parse()?;
    let bypass = if skip_model_review.unwrap_or(false) {
        hf_service::HarnessReviewBypass::Requested
    } else {
        hf_service::HarnessReviewBypass::NotRequested
    };
    let qualified = with_user_approval(&state.container, ExplicitAction::RunHarness)
        .harness_smoke_with_repair(
            &project,
            &target,
            engine,
            language(lang.as_deref())?,
            bypass,
            repairs.unwrap_or(0),
            // The repair count is in the result; the attempts are not streamed.
            &|_, _| {},
            ai.unwrap_or_default(),
        )
        .await
        .map_err(|error| error.to_string())?;
    let smoke = qualified.smoke;
    Ok(serde_json::json!({
        "status": if smoke.summary.passed { "SmokePassed" } else { "SmokeFailed" },
        "duration_secs": smoke.summary.duration_secs,
        "execs_per_sec": smoke.summary.execs_per_sec,
        "crashes": smoke.summary.crashes,
        "passed": smoke.summary.passed,
        "verdict": smoke.verdict,
        "behavior": smoke.behavior,
        "smoke_repairs": qualified.smoke_repairs,
    }))
}
