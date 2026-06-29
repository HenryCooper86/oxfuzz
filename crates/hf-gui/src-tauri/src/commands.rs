//! Tauri commands -- thin wrappers around `hf-service::ServiceContainer`.
//!
//! Per AGENTS.md 2.9: no domain logic here. All business logic lives in
//! `hf-service`; these commands handle I/O, Tauri event emission, and
//! argument marshalling only.

use std::path::PathBuf;

use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::target::TargetLanguage;
use serde::{Deserialize, Serialize};
use tauri::Manager;

// ---------------------------------------------------------------------------
// Docker daemon management (GUI-specific I/O -- not domain logic)
// ---------------------------------------------------------------------------

/// Best-effort start of the local Docker daemon on macOS. Prefers `OrbStack`,
/// falls back to Docker Desktop. Returns immediately; the caller polls
/// `docker_daemon_ready` for completion.
fn start_docker_daemon() {
    for app_name in ["OrbStack", "Docker"] {
        let started = std::process::Command::new("open")
            .args(["-ga", app_name])
            .status()
            .is_ok_and(|s| s.success());
        if started {
            return;
        }
    }
}

/// On launch, make sure Docker is usable: start the daemon if it is asleep,
/// wait for it, then ensure the sandbox image is loaded (building it if not).
/// Emits `docker:status` events so the UI can surface progress.
pub(crate) async fn ensure_docker_ready(
    app: &tauri::AppHandle,
    arch: Option<String>,
) -> SystemStatus {
    use tauri::Emitter;
    let emit = |message: &str| {
        let _ = app.emit("docker:status", serde_json::json!({ "message": message }));
    };

    let platform = arch
        .as_deref()
        .map_or_else(hf_runtime::host_platform, hf_runtime::norm_platform);
    let want_short = hf_runtime::platform_short(&platform).to_string();

    if !hf_runtime::docker_cli_present() {
        emit("Docker CLI not found -- install OrbStack or Docker Desktop.");
        return system_status();
    }

    if !hf_runtime::docker_daemon_ready() {
        emit("Starting Docker daemon...");
        start_docker_daemon();
        // Poll up to ~90s for the daemon to come up.
        for _ in 0..45 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if hf_runtime::docker_daemon_ready() {
                break;
            }
        }
    }

    if !hf_runtime::docker_daemon_ready() {
        emit("Docker daemon did not start -- start OrbStack/Docker manually.");
        return system_status();
    }
    emit("Docker daemon ready.");

    let arch_ok = hf_runtime::sandbox_image_arch().is_some_and(|a| a == want_short);
    if hf_runtime::sandbox_image_present() && arch_ok {
        emit(&format!("Sandbox image ready ({platform})."));
    } else if let Some(root) = hf_service::repo_root() {
        if hf_runtime::sandbox_image_present() {
            emit(&format!("Rebuilding sandbox image for {platform}..."));
        } else {
            emit(&format!(
                "Building sandbox image for {platform} (first run, may take several minutes)..."
            ));
        }
        let plat = platform.clone();
        let built =
            tokio::task::spawn_blocking(move || hf_service::build_sandbox_image(&root, &plat))
                .await;
        match built {
            Ok(Ok(())) => emit(&format!("Sandbox image built and ready ({platform}).")),
            _ => emit("Failed to build sandbox image -- run scripts/build-sandbox.sh."),
        }
    } else {
        emit("Sandbox image missing -- run scripts/build-sandbox.sh.");
    }

    system_status()
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// System status surfaced to the frontend.
#[derive(Debug, Clone, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SystemStatus {
    /// Docker daemon is reachable (not merely the CLI installed).
    pub docker: bool,
    /// The sandbox image is loaded locally.
    pub sandbox_image: bool,
    // Fuzzing engines run inside the sandbox image, so their availability tracks
    // whether that image is loaded (the Dockerfile bundles all of them).
    pub libfuzzer: bool,
    pub aflplusplus: bool,
    pub honggfuzz: bool,
    pub clusterfuzzlite: bool,
    pub syzkaller: bool,
}

/// Compute the current system status by probing Docker + the sandbox image.
#[must_use]
pub fn system_status() -> SystemStatus {
    let docker = hf_runtime::docker_daemon_ready();
    let img = docker && hf_runtime::sandbox_image_present();
    SystemStatus {
        docker,
        sandbox_image: img,
        libfuzzer: img,
        aflplusplus: img,
        honggfuzz: img,
        clusterfuzzlite: img,
        syzkaller: img,
    }
}

// ---------------------------------------------------------------------------
// Language + engine parsing helpers
// ---------------------------------------------------------------------------

fn parse_lang(s: &str) -> Result<TargetLanguage, String> {
    s.parse()
}

fn parse_engine(s: &str) -> Result<EngineKind, String> {
    s.parse()
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Discover fuzzing targets in a project.
#[tauri::command]
pub async fn discover(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    lang: String,
) -> Result<serde_json::Value, String> {
    let lang = parse_lang(&lang)?;
    let inv = state
        .container
        .discover(&project, lang)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(&inv).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_folder_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let result = app
        .dialog()
        .file()
        .set_title("Select a project folder")
        .blocking_pick_folder();
    Ok(result.map(|f| f.to_string()))
}

/// Open a native file picker and return the selected file path.
#[tauri::command]
pub async fn open_file_dialog(
    app: tauri::AppHandle,
    title: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let result = app
        .dialog()
        .file()
        .set_title(title.as_deref().unwrap_or("Select a file"))
        .blocking_pick_file();
    Ok(result.map(|f| f.to_string()))
}

/// Draft a harness for a target using the LLM (or heuristic fallback).
#[tauri::command]
pub async fn harness_draft(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
) -> Result<serde_json::Value, String> {
    let engine_kind = parse_engine(&engine)?;
    let lang = match lang.as_deref() {
        Some(l) => parse_lang(l)?,
        None => TargetLanguage::C,
    };
    let draft = state
        .container
        .harness_draft(&project, &target, engine_kind, lang)
        .await
        .map_err(|e| e.to_string())?;
    let build_cmd = hf_harness::build_command(engine_kind, lang, &format!("fuzz_{target}"));
    Ok(serde_json::json!({
        "source": draft.source,
        "target": target,
        "engine": engine,
        "build_cmd": {
            "compiler": build_cmd.compiler,
            "args": build_cmd.args,
        },
        "status": "Draft",
    }))
}

/// Compile a harness in the sandbox via `hf-runtime`.
#[tauri::command]
pub async fn harness_compile(
    state: tauri::State<'_, crate::state::AppState>,
    source: String,
    project: PathBuf,
    engine: String,
    target: String,
    lang: Option<String>,
) -> Result<serde_json::Value, String> {
    let engine_kind = parse_engine(&engine)?;
    let lang = match lang.as_deref() {
        Some(l) => parse_lang(l)?,
        None => TargetLanguage::C,
    };
    if !hf_runtime::docker_daemon_ready() {
        return Ok(serde_json::json!({
            "status": "Draft",
            "message": "Docker daemon not running -- harness source ready but not compiled.",
        }));
    }
    match state
        .container
        .harness_compile(source, &project, engine_kind, &target, lang)
        .await
    {
        Ok(out) => Ok(serde_json::json!({
            "status": format!("{:?}", out.status),
            "message": "Harness compiled successfully in sandbox.",
        })),
        Err(e) => Ok(serde_json::json!({
            "status": "Failed",
            "message": format!("Compile failed: {}", e),
        })),
    }
}

/// Generate seed corpus inputs for a target.
#[tauri::command]
pub async fn generate_seeds(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<serde_json::Value, String> {
    let entries = state
        .container
        .generate_seeds(std::path::Path::new(&project), &target)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"seeds": entries}))
}

#[tauri::command]
pub async fn corpus_list(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<serde_json::Value, String> {
    let corpus = state
        .container
        .corpus_list(std::path::Path::new(&project), &target)
        .map_err(|e| e.to_string())?;
    serde_json::to_value(&corpus.entries).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn corpus_seed(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<serde_json::Value, String> {
    let n = state
        .container
        .corpus_seed(std::path::Path::new(&project), &target)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"seeded": n}))
}

#[tauri::command]
pub async fn corpus_grow(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<serde_json::Value, String> {
    let n = state
        .container
        .corpus_grow(std::path::Path::new(&project), &target)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"entries": n}))
}

#[tauri::command]
pub async fn corpus_prune(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<serde_json::Value, String> {
    let n = state
        .container
        .corpus_prune(std::path::Path::new(&project), &target)
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"entries": n}))
}

/// Ingest and deduplicate crash artifacts.
#[tauri::command]
pub async fn triage(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<serde_json::Value, String> {
    let deduped = state
        .container
        .triage(std::path::Path::new(&project), &target)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::to_value(&deduped).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn system_status_cmd() -> SystemStatus {
    system_status()
}

/// Ensure Docker is ready (daemon running + sandbox image loaded), starting
/// and building as needed. Invoked by the frontend on launch.
#[tauri::command]
pub async fn ensure_docker(
    app: tauri::AppHandle,
    arch: Option<String>,
) -> Result<SystemStatus, String> {
    Ok(ensure_docker_ready(&app, arch).await)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn show_window(app: tauri::AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        win.show().ok();
    }
}

/// The host's native sandbox platform, e.g. "linux/arm64".
#[tauri::command]
#[must_use]
pub fn host_arch() -> String {
    hf_runtime::host_platform()
}

// ---------------------------------------------------------------------------
// Chat (LLM-backed)
// ---------------------------------------------------------------------------

/// Send a single-turn chat message to the LLM provider pool (no tools).
///
/// Uses the shared container's live provider pool, which `set_providers` swaps
/// in whenever Settings are saved -- so provider edits apply without a restart.
#[tauri::command]
pub async fn chat_send(
    state: tauri::State<'_, crate::state::AppState>,
    message: String,
) -> Result<String, String> {
    state
        .container
        .chat_send(&message)
        .await
        .map_err(|e| e.to_string())
}

/// A prior chat message passed from the frontend as agent history.
#[derive(Debug, Deserialize, Serialize)]
pub struct ChatTurn {
    pub role: String,
    pub content: String,
}

fn parse_role(role: &str) -> hf_core::types::Role {
    match role.to_ascii_lowercase().as_str() {
        "system" => hf_core::types::Role::System,
        "assistant" => hf_core::types::Role::Assistant,
        "tool" => hf_core::types::Role::Tool,
        _ => hf_core::types::Role::User,
    }
}

/// An [`EventSink`](hf_agent::EventSink) that forwards agent events to the
/// frontend as `chat:event` Tauri events for live rendering.
struct TauriEventSink {
    app: tauri::AppHandle,
}

#[async_trait::async_trait]
impl hf_agent::EventSink for TauriEventSink {
    async fn emit(&self, event: hf_agent::AgentEvent) {
        use tauri::Emitter;
        let _ = self.app.emit("chat:event", &event);
    }
}

/// A guardrail [`ApprovalGate`](hf_guardrails::ApprovalGate) that asks the user
/// via the GUI: it emits `chat:permission_request` and blocks until the
/// frontend answers through `chat_answer_permission`. A dropped channel (e.g.
/// the window closing) denies by default.
struct GuiApprovalGate {
    app: tauri::AppHandle,
    pending: std::sync::Arc<crate::state::PendingApprovals>,
}

#[async_trait::async_trait]
impl hf_guardrails::ApprovalGate for GuiApprovalGate {
    async fn request_approval(&self, action: &hf_guardrails::Action, reason: &str) -> bool {
        use tauri::Emitter;
        let id = uuid::Uuid::new_v4();
        let rx = self.pending.register(id).await;
        let _ = self.app.emit(
            "chat:permission_request",
            serde_json::json!({
                "id": id.to_string(),
                "action": action.label(),
                "reason": reason,
            }),
        );
        rx.await.unwrap_or(false)
    }
}

/// An approval gate that auto-approves. Used for high-risk actions the user has
/// already explicitly initiated via the workflow UI (e.g. clicking "Run Fuzzer"):
/// the click itself is the human approval, and execution still goes through the
/// hf-runtime sandbox. The agent/chat path uses the interactive `GuiApprovalGate`.
struct AutoApproveGate;

#[async_trait::async_trait]
impl hf_guardrails::ApprovalGate for AutoApproveGate {
    async fn request_approval(&self, _action: &hf_guardrails::Action, _reason: &str) -> bool {
        true
    }
}

/// Resolve a pending HITL approval request with the user's decision.
#[tauri::command]
pub async fn chat_answer_permission(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
    approved: bool,
) -> Result<bool, String> {
    let uid = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
    Ok(state.pending_approvals.resolve(uid, approved).await)
}

/// Everything `hobot_fuzz` has learned about your projects, read from the
/// `SQLite` store: discovered targets, fuzz runs, and crashes found. Powers the
/// Knowledge view. Returns empty lists when no database is configured.
#[derive(Debug, Default, Serialize)]
pub struct KnowledgeSummary {
    pub db_configured: bool,
    pub targets: Vec<serde_json::Value>,
    pub runs: Vec<serde_json::Value>,
    pub crashes: Vec<serde_json::Value>,
}

#[tauri::command]
pub async fn knowledge_summary(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<KnowledgeSummary, String> {
    let Some(store) = state.container.store() else {
        return Ok(KnowledgeSummary::default());
    };
    let targets = store.list_all_targets().await.map_err(|e| e.to_string())?;
    let runs = store.list_runs(None).await.map_err(|e| e.to_string())?;
    let crashes = store.list_all_crashes().await.map_err(|e| e.to_string())?;
    Ok(KnowledgeSummary {
        db_configured: true,
        targets: targets
            .iter()
            .map(|t| {
                serde_json::json!({
                    "symbol": t.symbol,
                    "kind": format!("{:?}", t.kind),
                    "fit_score": t.fit_score,
                    "project": t.project_root.to_string_lossy(),
                    "location": format!("{}:{}", t.location.file.display(), t.location.line),
                })
            })
            .collect(),
        runs: runs
            .iter()
            .map(|r| {
                serde_json::json!({
                    "id": r.id.to_string(),
                    "project": r.project_root,
                    "engine": format!("{:?}", r.engine),
                    "status": format!("{:?}", r.status),
                    "started_at": r.started_at.to_rfc3339(),
                })
            })
            .collect(),
        crashes: crashes
            .iter()
            .map(|c| {
                serde_json::json!({
                    "kind": format!("{:?}", c.kind),
                    "summary": c.summary,
                    "signature": c.stack_signature,
                    "severity": c.casr.as_ref().map(|r| format!("{:?}", r.severity)),
                })
            })
            .collect(),
    })
}

/// Per-provider health for the Observability panel.
#[derive(Debug, Serialize)]
pub struct ProviderStatusDto {
    id: String,
    frozen: bool,
    freeze_reason: Option<String>,
    active_requests: usize,
    total_requests: u64,
    total_errors: u64,
}

/// Live provider health/usage (freeze state, in-flight + total requests,
/// errors). Empty when no provider pool is configured.
#[tauri::command]
pub async fn provider_statuses(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Vec<ProviderStatusDto>, String> {
    let statuses = state.container.provider_statuses().await;
    Ok(statuses
        .into_iter()
        .map(|s| ProviderStatusDto {
            id: s.id.0,
            frozen: s.is_frozen,
            freeze_reason: s.freeze_reason,
            active_requests: s.active_requests,
            total_requests: s.total_requests,
            total_errors: s.total_errors,
        })
        .collect())
}

/// Live system snapshot for the Observability panel: providers, agent pool, and
/// memory. Fills the agent pool's available slots from the agent registry (the
/// service layer does not load it).
#[tauri::command]
pub async fn system_snapshot(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<hf_service::SystemSnapshot, String> {
    let mut snapshot = state.container.system_snapshot().await;
    let agent_count = hf_agent::AgentRegistry::with_user_dir(agents_dir())
        .list()
        .len();
    snapshot.agents.available_slots = agent_count;
    snapshot.agents.total_instances = snapshot.agents.instances.len();
    Ok(snapshot)
}

/// Cheap on-disk artifact snapshot (harness built?, corpus size, crash inputs)
/// for the Info panel.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn artifact_summary(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> hf_service::ArtifactSummary {
    state
        .container
        .artifact_summary(std::path::Path::new(&project), &target)
}

/// Clear learned knowledge (discovered targets, runs, crashes). Corpus inputs
/// and configuration are untouched.
#[tauri::command]
pub async fn clear_knowledge(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<(), String> {
    state
        .container
        .clear_knowledge()
        .await
        .map_err(|e| e.to_string())
}

/// Aggregated LLM cost/usage recorded this session (diagnostics).
#[tauri::command]
pub async fn diagnostics_cost_summary(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<hf_service::diagnostics::CostSummary, String> {
    Ok(state.container.cost_summary().await)
}

/// Runs interrupted by a prior crash/quit, awaiting recovery.
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn interrupted_runs(
    state: tauri::State<'_, crate::state::AppState>,
) -> Vec<hf_service::recovery::InterruptedRun> {
    state.container.interrupted_runs()
}

/// Dismiss an interrupted run; returns the updated list.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn dismiss_interrupted_run(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Vec<hf_service::recovery::InterruptedRun> {
    state.container.dismiss_interrupted_run(&run_id);
    state.container.interrupted_runs()
}

/// List all scheduled fuzz campaigns.
#[tauri::command]
pub async fn schedule_list(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    Ok(state.scheduler.list_views().await)
}

/// Recent scheduled-campaign executions (newest first).
#[tauri::command]
pub async fn schedule_history(
    state: tauri::State<'_, crate::state::AppState>,
    limit: Option<usize>,
) -> Result<Vec<hf_service::scheduler::ExecutionView>, String> {
    Ok(state.scheduler.recent_executions(limit.unwrap_or(20)).await)
}

/// Create a scheduled fuzz campaign; returns the updated list.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn schedule_create(
    state: tauri::State<'_, crate::state::AppState>,
    name: String,
    project: String,
    target: String,
    engine: String,
    duration_secs: u64,
    trigger_kind: String,
    trigger_value: String,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    let trigger = hf_service::scheduler::parse_trigger(&trigger_kind, &trigger_value)?;
    let params = hf_service::scheduler::CampaignParams {
        project,
        target,
        engine,
        duration_secs,
    };
    state.scheduler.create(&name, &params, trigger).await;
    Ok(state.scheduler.list_views().await)
}

/// Delete a scheduled campaign; returns the updated list.
#[tauri::command]
pub async fn schedule_delete(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    state.scheduler.remove(&id).await;
    Ok(state.scheduler.list_views().await)
}

/// Enable or disable a scheduled campaign; returns the updated list.
#[tauri::command]
pub async fn schedule_set_enabled(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
    enabled: bool,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    state.scheduler.set_enabled(&id, enabled).await;
    Ok(state.scheduler.list_views().await)
}

/// Index a project's source files into its BM25 knowledge base.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn knowledge_index(project: String) -> Result<hf_service::knowledge::KnowledgeStats, String> {
    hf_service::knowledge::index_project(std::path::Path::new(&project)).map_err(|e| e.to_string())
}

/// Convert a document (PDF/Office/HTML/...) to Markdown via markitdown in the
/// sandbox and index it into the project knowledge base.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn knowledge_ingest(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    file: String,
) -> Result<hf_service::knowledge::KnowledgeStats, String> {
    state
        .container
        .ingest_document(std::path::Path::new(&project), std::path::Path::new(&file))
        .await
        .map_err(|e| e.to_string())
}

/// Search a project's knowledge base (returns empty until indexed).
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn knowledge_search(
    project: String,
    query: String,
    limit: Option<usize>,
) -> Vec<hf_service::knowledge::KnowledgeHit> {
    hf_service::knowledge::search_project(
        std::path::Path::new(&project),
        &query,
        limit.unwrap_or(10),
    )
}

/// The AI agent's identity: configured model, guardrail mode, and the tools it
/// can call. Powers the Agents view.
#[derive(Debug, Serialize)]
pub struct AgentInfo {
    pub model: String,
    pub provider_type: String,
    pub guardrails: String,
    pub tools: Vec<serde_json::Value>,
}

#[tauri::command]
pub fn agent_info() -> AgentInfo {
    let models = list_models();
    let first = models.first();
    let model = first.map_or_else(|| "(none configured)".to_owned(), |m| m.model.clone());
    let provider_type = first.map(|m| m.provider_type.clone()).unwrap_or_default();
    // Default is env-gated (high-risk actions need approval/HF_AUTO_APPROVE);
    // HF_GUARDRAILS=permissive opts into auto-approve-with-audit.
    let guardrails = match std::env::var("HF_GUARDRAILS").as_deref() {
        Ok("permissive") => "permissive (audited)".to_owned(),
        _ => "approval required".to_owned(),
    };
    let tools = hf_agent::TOOL_SPECS
        .iter()
        .map(|(name, desc)| serde_json::json!({ "name": name, "description": desc }))
        .collect();
    AgentInfo {
        model,
        provider_type,
        guardrails,
        tools,
    }
}

/// List all skills -- built-in fuzzing skills plus any user-authored ones.
#[tauri::command]
#[must_use]
pub fn list_skills() -> Vec<hf_skills::SkillDefinition> {
    hf_skills::SkillRegistry::with_user_dir(skills_dir()).list()
}

/// Validate a file-backed entity name: alphanumeric, dash, underscore only
/// (no path traversal). Returns the trimmed name.
fn safe_name(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty()
        || !n
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err("name must be non-empty and only letters, digits, '-' or '_'".to_owned());
    }
    Ok(n.to_owned())
}

fn skills_dir() -> std::path::PathBuf {
    hf_service::repo_root().map_or_else(|| std::path::PathBuf::from("skills"), |r| r.join("skills"))
}

fn agents_dir() -> std::path::PathBuf {
    hf_service::repo_root().map_or_else(
        || std::path::PathBuf::from("config/agents"),
        |r| r.join("config").join("agents"),
    )
}

// -- Skills (registry-backed) -----------------------------------------------
//
// A skill is an `hf_skills::SkillDefinition`: a versioned instruction playbook
// (`root.md` body) plus metadata. Built-in fuzzing skills are embedded in the
// binary; user skills (and overrides) live under `skills/<name>/`. Agents
// reference skills by name and the runtime injects their bodies into context.

/// Read a single skill (built-in or user) for editing.
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn read_skill(name: String) -> Option<hf_skills::SkillDefinition> {
    hf_skills::SkillRegistry::with_user_dir(skills_dir())
        .get(&name)
        .cloned()
}

/// Create or update a user skill (writes `skills/<name>/{skill.toml,root.md}`).
/// Overriding a built-in name shadows it until reset via `delete_skill`.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn save_skill(
    name: String,
    description: String,
    version: String,
    domain: Vec<String>,
    content: String,
) -> Result<(), String> {
    let name = safe_name(&name)?;
    let version = if version.trim().is_empty() {
        "0.1.0".to_owned()
    } else {
        version
    };
    let def = hf_skills::SkillDefinition {
        name,
        version,
        description,
        domain,
        body: content,
        max_input_tokens: 0,
        trust_tier: hf_skills::TrustTier::UserDefined,
    };
    let mut reg = hf_skills::SkillRegistry::with_user_dir(skills_dir());
    reg.save(def).map_err(|e| e.to_string())
}

/// Delete a user skill, or reset a built-in override to its shipped version.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn delete_skill(name: String) -> Result<(), String> {
    let mut reg = hf_skills::SkillRegistry::with_user_dir(skills_dir());
    reg.delete(&name).map_err(|e| e.to_string())
}

// -- Agents (registry-backed) -----------------------------------------------
//
// An "agent" is an `hf_agent::AgentDefinition`: a flat-TOML profile that fully
// determines the runtime agent's system prompt, callable tools, model routing,
// and iteration budget. Built-in fuzzing agents are embedded in the binary;
// user agents (and overrides) live in `config/agents/*.toml`.

/// List all agents -- built-in fuzzing agents plus any user-authored ones.
#[tauri::command]
#[must_use]
pub fn list_agents() -> Vec<hf_agent::AgentDefinition> {
    hf_agent::AgentRegistry::with_user_dir(agents_dir()).list()
}

/// Fetch a single agent definition by id.
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn get_agent(id: String) -> Option<hf_agent::AgentDefinition> {
    hf_agent::AgentRegistry::with_user_dir(agents_dir())
        .get(&id)
        .cloned()
}

/// The runtime tool roster an agent may be granted, for the editor checklist.
#[tauri::command]
#[must_use]
pub fn agent_tools() -> Vec<serde_json::Value> {
    hf_agent::TOOL_SPECS
        .iter()
        .map(|(name, desc)| serde_json::json!({ "name": name, "description": desc }))
        .collect()
}

/// Create or update a user agent (writes `config/agents/<id>.toml`). Overriding
/// a built-in id shadows it until deleted.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn save_agent(def: hf_agent::AgentDefinition) -> Result<(), String> {
    let mut reg = hf_agent::AgentRegistry::with_user_dir(agents_dir());
    reg.save(def).map_err(|e| e.to_string())
}

/// Delete a user agent, or reset a built-in override to its shipped version.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn delete_agent(id: String) -> Result<(), String> {
    let mut reg = hf_agent::AgentRegistry::with_user_dir(agents_dir());
    reg.delete(&id).map_err(|e| e.to_string())
}

/// Create a new persistent conversation session and return its id.
///
/// Returns `None` when no database is configured (chat still works, but turns
/// are not persisted server-side).
#[tauri::command]
pub async fn create_session(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Option<String>, String> {
    Ok(state.container.create_chat_session(None).await)
}

/// Roll back the most recent chat turn for a session, truncating the persisted
/// transcript. Returns the number of messages removed.
#[tauri::command]
pub async fn chat_rollback(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<usize, String> {
    let id = hf_core::types::SessionId(session_id);
    Ok(state.container.chat_rollback_last(&id).await)
}

/// List the per-turn checkpoints for a chat session (the rollback picker).
#[tauri::command]
pub async fn chat_checkpoints(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<hf_service::checkpoints::CheckpointView>, String> {
    let id = hf_core::types::SessionId(session_id);
    Ok(state.container.chat_checkpoints(&id).await)
}

/// Roll back a chat session to a specific checkpoint. Returns messages removed.
#[tauri::command]
pub async fn chat_rollback_to(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
    checkpoint_id: String,
) -> Result<usize, String> {
    let id = hf_core::types::SessionId(session_id);
    Ok(state.container.chat_rollback_to(&id, &checkpoint_id).await)
}

/// Wire string for a message role.
fn role_to_str(role: hf_core::types::Role) -> &'static str {
    match role {
        hf_core::types::Role::System => "system",
        hf_core::types::Role::Assistant => "assistant",
        hf_core::types::Role::Tool => "tool",
        hf_core::types::Role::User => "user",
    }
}

/// Fork the conversation into a new branch, copying `fork_count` messages from
/// the current session. Returns the new branch session id.
#[tauri::command]
pub async fn chat_branch(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
    fork_count: u32,
    title: Option<String>,
) -> Result<Option<String>, String> {
    let id = hf_core::types::SessionId(session_id);
    Ok(state
        .container
        .chat_branch(&id, fork_count, title.filter(|t| !t.is_empty()))
        .await)
}

/// Load a session's transcript as chat turns (for switching branches).
#[tauri::command]
pub async fn chat_history(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<ChatTurn>, String> {
    let id = hf_core::types::SessionId(session_id);
    Ok(state
        .container
        .chat_history(&id)
        .await
        .into_iter()
        .map(|m| ChatTurn {
            role: role_to_str(m.role).to_owned(),
            content: m.content,
        })
        .collect())
}

/// Functions covered by a fuzz run of `target`, for the call-tree overlay.
#[tauri::command]
pub async fn coverage_functions(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<Vec<String>, String> {
    Ok(state
        .container
        .coverage_functions(std::path::Path::new(&project), &target)
        .await)
}

/// List the sessions in a conversation tree (the branch switcher).
#[tauri::command]
pub async fn chat_branches(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<hf_service::checkpoints::BranchView>, String> {
    let id = hf_core::types::SessionId(session_id);
    Ok(state.container.chat_branches(&id).await)
}

/// Run an autonomous agent turn over the active project.
///
/// The agent reasons and calls fuzzing tools (discover/harness/run/triage/
/// corpus) via the guardrail-gated service container, streaming progress to the
/// frontend via `chat:event`. Returns the final assistant answer.
///
/// When `session_id` is supplied and a database is configured, history is
/// loaded from and the turn is persisted to that session (server-side memory);
/// otherwise the frontend-supplied `history` is used and nothing is persisted.
#[tauri::command]
pub async fn chat_agent(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    message: String,
    project: Option<String>,
    history: Option<Vec<ChatTurn>>,
    session_id: Option<String>,
    agent_id: Option<String>,
) -> Result<String, String> {
    let project = project.filter(|p| !p.is_empty()).map(PathBuf::from);
    let session = session_id
        .filter(|s| !s.is_empty())
        .map(hf_core::types::SessionId);
    // Frontend-supplied history, used only when no persistent session applies.
    let history_fallback: Vec<hf_core::types::Message> = history
        .unwrap_or_default()
        .into_iter()
        .map(|t| hf_core::types::Message::new(parse_role(&t.role), t.content))
        .collect();

    // Run with an interactive guardrail gate: high-risk tool calls (e.g. run a
    // fuzzer) prompt the user via `chat:permission_request` before executing.
    let gate = std::sync::Arc::new(GuiApprovalGate {
        app: app.clone(),
        pending: state.pending_approvals.clone(),
    });
    let guardrails =
        hf_guardrails::Guardrails::new(hf_guardrails::GuardrailPolicy::default(), gate);
    let container = state.container.clone().with_guardrails(guardrails);
    let sink = TauriEventSink { app };

    // Drive the turn through the shared service-layer orchestration so the GUI,
    // web, and CLI all run the agent identically (AGENTS.md 2.9).
    hf_agent::run_chat_turn(
        container,
        project,
        agent_id.as_deref(),
        agents_dir(),
        session,
        history_fallback,
        &message,
        &sink,
    )
    .await
    .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Streaming fuzz run
// ---------------------------------------------------------------------------

/// Drive a compiled harness against its target inside the sandbox, streaming
/// progress to the GUI as `run:progress` events (`{ type, data }`).
///
/// Uses `hf-service::ServiceContainer::run_fuzzer` which routes through
/// `hf-engine::runner::EngineRunner` and `hf-runtime::DockerRuntime` (with
/// `--network=none` isolation).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn run_fuzzer(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    project: String,
    target: String,
    engine: String,
    duration: u64,
) -> Result<serde_json::Value, String> {
    use tauri::Emitter;

    let engine_kind = parse_engine(&engine)?;
    let emit = |ty: &str, data: serde_json::Value| {
        let _ = app.emit(
            "run:progress",
            serde_json::json!({ "type": ty, "data": data }),
        );
    };

    // syzkaller is a kernel fuzzer: it drives a VM against a coverage-enabled
    // kernel via `syz-manager`, not a per-target harness binary. Surface what
    // a campaign needs instead of trying to run a harness.
    if engine_kind == EngineKind::Syzkaller {
        for line in [
            format!("Starting syzkaller (kernel fuzzing) on project: {project}"),
            "syzkaller fuzzes an OS kernel by mutating sequences of system calls.".to_string(),
            "It does NOT use a per-function harness binary like libFuzzer/AFL++/honggfuzz."
                .to_string(),
            "Requirements:".to_string(),
            "  - a kernel built with CONFIG_KCOV=y and CONFIG_DEBUG_INFO=y".to_string(),
            "  - a VM image (qemu or GCE) with the kernel installed".to_string(),
            "  - a syz-manager config (manager.cfg) pointing at the kernel + image".to_string(),
            "Launch a campaign with:  syz-manager -config=manager.cfg".to_string(),
            "Setup guide: https://github.com/google/syzkaller/blob/master/docs/linux/setup.md"
                .to_string(),
        ] {
            emit("LogLine", serde_json::json!(line));
        }
        let workspace = hf_service::workspace_dir(std::path::Path::new(&project), &target);
        let manager = workspace.join("manager.cfg");
        if manager.exists() {
            emit(
                "LogLine",
                serde_json::json!(format!(
                    "Found {} -- run syz-manager against it to begin.",
                    manager.display()
                )),
            );
        } else {
            emit(
                "LogLine",
                serde_json::json!("No manager.cfg in the workspace yet -- create one to start."),
            );
        }
        emit(
            "LogLine",
            serde_json::json!("[syzkaller] guidance complete (exit 0)"),
        );
        return Ok(serde_json::json!({ "edges": 0, "crashes": 0, "execs": 0.0, "exit_code": 0 }));
    }

    if !hf_runtime::docker_daemon_ready() {
        emit(
            "LogLine",
            serde_json::json!("Docker daemon not running -- cannot run fuzzer."),
        );
        return Err("Docker daemon not running -- cannot run fuzzer.".to_string());
    }

    emit(
        "LogLine",
        serde_json::json!(format!(
            "Starting {engine} on {target} for {duration}s (project: {project})"
        )),
    );

    let app_handle = app.clone();
    let on_progress = move |p: FuzzProgress| match p {
        FuzzProgress::EdgesCovered(v) => {
            let _ = app_handle.emit(
                "run:progress",
                serde_json::json!({"type": "EdgesCovered", "data": v}),
            );
        }
        FuzzProgress::ExecsPerSec(v) => {
            let _ = app_handle.emit(
                "run:progress",
                serde_json::json!({"type": "ExecsPerSec", "data": v}),
            );
        }
        FuzzProgress::CrashesFound(n) => {
            let _ = app_handle.emit(
                "run:progress",
                serde_json::json!({"type": "CrashesFound", "data": n}),
            );
        }
        FuzzProgress::LogLine(s) => {
            let _ = app_handle.emit(
                "run:progress",
                serde_json::json!({"type": "LogLine", "data": s}),
            );
        }
        FuzzProgress::Done => {
            let _ = app_handle.emit(
                "run:progress",
                serde_json::json!({"type": "Done", "data": serde_json::Value::Null}),
            );
        }
    };

    // The explicit "Run Fuzzer" click is the human approval for this high-risk
    // action (sandboxed via hf-runtime); auto-approve so the workflow run is not
    // blocked by the agent-oriented HITL gate.
    let container = state
        .container
        .clone()
        .with_guardrails(hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy::default(),
            std::sync::Arc::new(AutoApproveGate),
        ));
    let result = container
        .run_fuzzer(
            std::path::Path::new(&project),
            &target,
            engine_kind,
            duration,
            &(on_progress),
        )
        .await;

    emit("Done", serde_json::Value::Null);

    match result {
        Ok(summary) => Ok(serde_json::json!({
            "edges": summary.edges,
            "crashes": summary.crashes,
            "execs": summary.execs,
            "exit_code": 0,
        })),
        Err(e) => Err(e.to_string()),
    }
}

/// Cancel any in-flight fuzz run, stopping the sandboxed fuzzer cooperatively.
///
/// The GUI runs one campaign at a time, so this cancels every active run rather
/// than tracking individual run ids. The interrupted `run_fuzzer` returns with
/// its partial results and the run is recorded as cancelled. Returns the number
/// of runs that were signalled.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn cancel_run(state: tauri::State<'_, crate::state::AppState>) -> usize {
    // The active-run registry is shared (Arc) across container clones, so the
    // base container sees runs started by the guardrail-adjusted clone in
    // `run_fuzzer`.
    state.container.cancel_all_runs()
}

/// Compose the Markdown campaign report for a target and return it as a string,
/// so the GUI can preview or download it.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn generate_report(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<String, String> {
    state
        .container
        .generate_report(std::path::Path::new(&project), &target)
        .await
        .map_err(|e| e.to_string())
}

/// Generate the campaign report and save it to a user-chosen `.md` file via a
/// native save dialog. Returns the saved path, or `None` if the user cancelled.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn save_report(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let markdown = state
        .container
        .generate_report(std::path::Path::new(&project), &target)
        .await
        .map_err(|e| e.to_string())?;

    let default_name = format!("hobot_fuzz_report_{}.md", sanitize_filename(&target));
    let Some(path) = app
        .dialog()
        .file()
        .set_title("Save fuzzing report")
        .set_file_name(&default_name)
        .add_filter("Markdown", &["md"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|e| format!("invalid save path: {e}"))?;
    std::fs::write(&path, markdown).map_err(|e| format!("write report: {e}"))?;
    Ok(Some(path.to_string_lossy().to_string()))
}

/// Reduce a target symbol to a filesystem-safe filename fragment.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Artifacts for a real syzkaller kernel-fuzzing campaign.
#[derive(Debug, Deserialize)]
pub struct SyzkallerOpts {
    project: String,
    arch: Option<String>,
    duration: u64,
    kernel_image: Option<String>,
    disk_image: Option<String>,
    ssh_key: Option<String>,
    manager_cfg: Option<String>,
    vm_count: Option<u32>,
}

/// Run a real syzkaller campaign by invoking `syz-manager` inside the sandbox.
///
/// syzkaller fuzzes an OS kernel by mutating syscall sequences inside a managed
/// VM whose kernel is built with KCOV coverage. This command mounts the
/// user-supplied kernel image + rootfs (or an existing `manager.cfg`) into the
/// sandbox, synthesizes a qemu `manager.cfg` when needed, and streams
/// `syz-manager` output back to the GUI as `run:progress` events.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn run_syzkaller(
    app: tauri::AppHandle,
    opts: SyzkallerOpts,
) -> Result<serde_json::Value, String> {
    use tauri::Emitter;
    use tokio::io::AsyncBufReadExt;

    let SyzkallerOpts {
        project,
        arch,
        duration,
        kernel_image,
        disk_image,
        ssh_key,
        manager_cfg,
        vm_count,
    } = opts;

    let platform = arch
        .as_deref()
        .map_or_else(hf_runtime::host_platform, hf_runtime::norm_platform);
    let target_triple = format!("linux/{}", hf_runtime::platform_short(&platform));

    let emit = |ty: &str, data: serde_json::Value| {
        let _ = app.emit(
            "run:progress",
            serde_json::json!({ "type": ty, "data": data }),
        );
    };
    let logln = |s: &str| emit("LogLine", serde_json::json!(s));

    let nonempty = |o: &Option<String>| {
        o.as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let manager_cfg = nonempty(&manager_cfg);
    let kernel_image = nonempty(&kernel_image);
    let disk_image = nonempty(&disk_image);
    let ssh_key = nonempty(&ssh_key);

    let have_artifacts = kernel_image.is_some() && disk_image.is_some();

    // No artifacts at all: surface what a campaign needs and stop (no error).
    if manager_cfg.is_none() && !have_artifacts {
        for line in [
            format!("syzkaller (kernel fuzzing) -- project: {project}"),
            "No campaign artifacts provided. syzkaller drives a VM against a".to_string(),
            "KCOV-instrumented kernel; it needs one of:".to_string(),
            "  (a) a kernel image (bzImage) + a rootfs disk image, or".to_string(),
            "  (b) an existing syz-manager config (manager.cfg).".to_string(),
            "Build a KCOV kernel + rootfs per the setup guide, then select them above:".to_string(),
            "https://github.com/google/syzkaller/blob/master/docs/linux/setup.md".to_string(),
        ] {
            logln(&line);
        }
        emit("Done", serde_json::Value::Null);
        return Ok(serde_json::json!({ "edges": 0, "crashes": 0, "execs": 0.0, "exit_code": 0 }));
    }

    if !hf_runtime::docker_daemon_ready() {
        logln("Docker daemon not running -- cannot launch syz-manager.");
        return Err("Docker daemon not running -- cannot launch syz-manager.".to_string());
    }

    let file_ok = |p: &str| std::path::Path::new(p).is_file();

    // Assemble bind mounts and resolve the in-container config path.
    let mut mounts: Vec<String> = Vec::new();
    let workspace = std::env::temp_dir().join("hobot_fuzz_syzkaller");
    std::fs::create_dir_all(&workspace).map_err(|e| e.to_string())?;
    let workdir = "/syzbench";
    let cfg_in_container: String;

    if let Some(cfg) = manager_cfg.as_deref() {
        if !file_ok(cfg) {
            return Err(format!("manager.cfg not found: {cfg}"));
        }
        let cfg_path = std::path::Path::new(cfg);
        let dir = cfg_path
            .parent()
            .ok_or_else(|| "manager.cfg has no parent directory".to_string())?;
        mounts.push(format!("{0}:{0}", dir.display()));
        cfg_in_container = cfg.to_string();
        logln(&format!("Using provided manager.cfg: {cfg}"));
    } else {
        let kernel = kernel_image.ok_or_else(|| {
            "kernel_image is required when no manager.cfg is provided".to_string()
        })?;
        let disk = disk_image
            .ok_or_else(|| "disk_image is required when no manager.cfg is provided".to_string())?;
        if !file_ok(&kernel) {
            return Err(format!("kernel image not found: {kernel}"));
        }
        if !file_ok(&disk) {
            return Err(format!("disk image not found: {disk}"));
        }
        mounts.push(format!("{kernel}:/syzbench/kernel:ro"));
        mounts.push(format!("{disk}:/syzbench/rootfs.img"));

        let sshkey_field = if let Some(key) = ssh_key.as_deref() {
            if !file_ok(key) {
                return Err(format!("ssh key not found: {key}"));
            }
            mounts.push(format!("{key}:/syzbench/id_rsa:ro"));
            "\n  \"sshkey\": \"/syzbench/id_rsa\",".to_string()
        } else {
            String::new()
        };

        let count = vm_count.unwrap_or(2).max(1);
        let procs = count.min(4);
        let qemu_args = if hf_runtime::platform_short(&platform) == "arm64" {
            "-machine virt,accel=tcg -cpu max"
        } else {
            "-machine pc,accel=tcg -cpu max"
        };
        let cfg_json = format!(
            "{{\n  \"target\": \"{target_triple}\",\n  \"http\": \"0.0.0.0:56741\",\n  \"workdir\": \"/syzbench/workdir\",\n  \"image\": \"/syzbench/rootfs.img\",{sshkey_field}\n  \"syzkaller\": \"/opt/syzkaller\",\n  \"procs\": {procs},\n  \"type\": \"qemu\",\n  \"vm\": {{\n    \"count\": {count},\n    \"kernel\": \"/syzbench/kernel\",\n    \"cpu\": 2,\n    \"mem\": 2048,\n    \"qemu_args\": \"{qemu_args}\"\n  }}\n}}\n"
        );
        let cfg_host = workspace.join("manager.cfg");
        std::fs::write(&cfg_host, &cfg_json).map_err(|e| e.to_string())?;
        let workdir_host = workspace.join("workdir");
        std::fs::create_dir_all(&workdir_host).map_err(|e| e.to_string())?;
        mounts.push(format!("{}:/syzbench/manager.cfg:ro", cfg_host.display()));
        mounts.push(format!("{}:/syzbench/workdir", workdir_host.display()));
        cfg_in_container = "/syzbench/manager.cfg".to_string();
        logln(&format!(
            "Synthesized qemu manager.cfg ({target_triple}, {count} VM(s))."
        ));
    }

    logln(&format!(
        "Launching syz-manager in the sandbox for {duration}s..."
    ));
    logln("Note: qemu runs under TCG emulation inside Docker (no /dev/kvm on macOS) -- expect low exec rates.");

    let inner = format!(
        "command -v syz-manager >/dev/null 2>&1 || {{ echo 'ERROR: syz-manager not found in the sandbox image. Rebuild the image with the syzkaller toolchain: open Settings > General and switch the sandbox Architecture (forces a rebuild), or remove the image with: docker image rm {sandbox_img}'; exit 3; }}; timeout {duration} syz-manager -config={cfg_in_container} 2>&1 || true",
        sandbox_img = hf_runtime::SANDBOX_IMAGE,
    );

    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "--platform".into(),
        platform.clone(),
        "--memory=4096m".into(),
        "--cpus=4".into(),
    ];
    for m in &mounts {
        args.push("-v".into());
        args.push(m.clone());
    }
    args.push("-w".into());
    args.push(workdir.into());
    args.push(hf_runtime::SANDBOX_IMAGE.into());
    args.push("bash".into());
    args.push("-c".into());
    args.push(inner);

    let mut child = tokio::process::Command::new(hf_runtime::docker_bin())
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("docker run (syz-manager): {e}"))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture stdout".to_string())?;
    let mut lines = tokio::io::BufReader::new(stdout).lines();

    let mut edges: u64 = 0;
    let mut execs: f64 = 0.0;
    let mut crashes: u64 = 0;

    while let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? {
        if let Some((cover, executed, crash_ct)) =
            hf_engine::progress::parse_syzkaller_status(&line)
        {
            edges = edges.max(cover);
            execs = executed as f64;
            if crash_ct > crashes {
                emit("CrashesFound", serde_json::json!(crash_ct - crashes));
                crashes = crash_ct;
            }
            emit("EdgesCovered", serde_json::json!(cover));
            emit("ExecsPerSec", serde_json::json!(executed));
            logln(&line);
        } else if !line.trim().is_empty() {
            logln(&line);
        }
    }

    let status = child.wait().await.map_err(|e| e.to_string())?;
    emit("Done", serde_json::Value::Null);

    Ok(serde_json::json!({
        "edges": edges,
        "crashes": crashes,
        "execs": execs,
        "exit_code": status.code(),
    }))
}

// ---------------------------------------------------------------------------
// Raw config file editing (FORM/RAW settings editor)
// ---------------------------------------------------------------------------

// These commands are thin presentation wrappers over `hf_service::config`,
// the single source of truth shared with the CLI and web API (AGENTS.md 2.9).
// The serde shapes are re-exported unchanged so the frontend JSON is identical.

pub use hf_service::config::{AppPaths, ConfigSection, ModelInfo, ProviderConfig};

#[tauri::command]
#[must_use]
pub fn app_paths() -> AppPaths {
    hf_service::config::app_paths()
}

/// List the models from the configured provider pool. Drives the chat model
/// selector.
#[tauri::command]
#[must_use]
pub fn list_models() -> Vec<ModelInfo> {
    hf_service::config::list_models()
}

/// Load the provider pool as structured data for the settings form.
#[tauri::command]
#[must_use]
pub fn get_providers() -> Vec<ProviderConfig> {
    hf_service::config::get_providers()
}

/// Persist the provider pool from the settings form back to `providers.toml`,
/// then reload it into the live container so the change applies immediately --
/// no app restart needed.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_providers(
    state: tauri::State<'_, crate::state::AppState>,
    providers: Vec<ProviderConfig>,
) -> Result<(), String> {
    hf_service::config::set_providers(&providers)?;
    state.container.reload_providers();
    Ok(())
}

/// Test a provider configuration with a live probe request.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn provider_test(provider: ProviderConfig) -> Result<String, String> {
    hf_service::config::test_provider(provider).await
}

/// List the editable config sections and whether each has a live file.
#[tauri::command]
#[must_use]
pub fn list_configs() -> Vec<ConfigSection> {
    hf_service::config::list_configs()
}

/// Read a config section's raw TOML.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn read_config(name: String) -> Result<String, String> {
    hf_service::config::read_config(&name)
}

/// Write a config section's raw TOML to its live file.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn write_config(name: String, content: String) -> Result<(), String> {
    hf_service::config::write_config(&name, &content)
}

/// Parse raw TOML into a JSON value, for driving a structured settings form.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn config_toml_to_value(content: String) -> Result<serde_json::Value, String> {
    hf_service::config::toml_to_json(&content)
}

/// Serialize a settings form's JSON value back into TOML text.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn config_value_to_toml(value: serde_json::Value) -> Result<String, String> {
    hf_service::config::json_to_toml(&value)
}
