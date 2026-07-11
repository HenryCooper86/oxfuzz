//! Tauri commands -- thin wrappers around `hf-service::ServiceContainer`.
//!
//! Per AGENTS.md 2.9: no domain logic here. All business logic lives in
//! `hf-service`; these commands handle I/O, Tauri event emission, and
//! argument marshalling only.

use std::path::PathBuf;

use hf_service::{
    Action, ApprovalGate, EngineKind, FuzzProgress, GuardrailPolicy, Guardrails, Message, Role,
    SessionId, SkillDefinition, SkillRegistry, TargetLanguage, TrustTier,
};
use serde::{Deserialize, Serialize};
use tauri::Manager;

pub use hf_service::SystemStatus;

// ---------------------------------------------------------------------------
// Docker daemon management (GUI-specific I/O -- not domain logic)
// ---------------------------------------------------------------------------

/// Best-effort start of the local Docker daemon. Returns immediately; the
/// caller polls `docker_daemon_ready` for completion.
///
/// - macOS: launches `OrbStack`, falling back to Docker Desktop, via `open`.
/// - Linux: the daemon is a system/user service, so try `systemctl start
///   docker`; if the user lacks privileges this no-ops and the caller surfaces
///   guidance to start it manually.
fn start_docker_daemon() {
    #[cfg(target_os = "macos")]
    {
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
    #[cfg(target_os = "linux")]
    {
        for args in [
            ["--user", "start", "docker"].as_slice(),
            ["start", "docker"].as_slice(),
        ] {
            let started = std::process::Command::new("systemctl")
                .args(args)
                .status()
                .is_ok_and(|s| s.success());
            if started {
                return;
            }
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
        .map_or_else(hf_service::host_platform, hf_service::norm_platform);
    let want_short = hf_service::platform_short(&platform).to_string();

    if !hf_service::docker_cli_present() {
        #[cfg(target_os = "linux")]
        emit("Docker CLI not found -- install Docker (e.g. your distro's docker.io / docker-ce).");
        #[cfg(not(target_os = "linux"))]
        emit("Docker CLI not found -- install OrbStack or Docker Desktop.");
        return system_status();
    }

    if !hf_service::docker_daemon_ready() {
        emit("Starting Docker daemon...");
        start_docker_daemon();
        // Poll up to ~90s for the daemon to come up.
        for _ in 0..45 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if hf_service::docker_daemon_ready() {
                break;
            }
        }
    }

    if !hf_service::docker_daemon_ready() {
        #[cfg(target_os = "linux")]
        emit(
            "Docker daemon did not start -- start it manually (e.g. sudo systemctl start docker).",
        );
        #[cfg(not(target_os = "linux"))]
        emit("Docker daemon did not start -- start OrbStack/Docker manually.");
        return system_status();
    }
    emit("Docker daemon ready.");

    let arch_ok = hf_service::sandbox_image_arch().is_some_and(|a| a == want_short);
    if hf_service::sandbox_image_present() && arch_ok {
        emit(&format!("Sandbox image ready ({platform})."));
    } else if !hf_service::can_run_platform(&platform) {
        // A non-native sandbox arch on a host without qemu-user/binfmt would
        // fail the build with an opaque "exec format error" -- say so plainly.
        emit(&format!(
            "Cannot build the {platform} sandbox: this host cannot run that architecture. \
             Register emulation with `docker run --privileged --rm tonistiigi/binfmt --install all` \
             (or install qemu-user-static), or pick the native arch in Settings."
        ));
    } else if let Some(root) = hf_service::repo_root() {
        if hf_service::sandbox_image_present() {
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

/// Compute the current system status by probing Docker + the sandbox image.
#[must_use]
pub fn system_status() -> SystemStatus {
    hf_service::system_status()
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
    Ok(serde_json::json!({
        "source": draft.source,
        "target": target,
        "engine": engine,
        "build_cmd": {
            "compiler": draft.build_cmd.compiler,
            "args": draft.build_cmd.args,
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
    if !hf_service::docker_daemon_ready() {
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

/// Smoke-qualify the exact active harness revision and persist the evidence.
#[tauri::command]
pub async fn harness_smoke(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    target: String,
    engine: String,
    lang: Option<String>,
) -> Result<serde_json::Value, String> {
    let engine_kind = parse_engine(&engine)?;
    let language = match lang.as_deref() {
        Some(value) => parse_lang(value)?,
        None => TargetLanguage::C,
    };
    // The explicit Smoke Test click is the human approval for this bounded,
    // sandboxed harness execution. Do not route workflow actions through the
    // chat-only approval listener: that would deny them when ChatView is not
    // mounted, even though the operator just clicked the action button.
    let container = state.container.clone().with_guardrails(Guardrails::new(
        GuardrailPolicy::default(),
        std::sync::Arc::new(AutoApproveGate),
    ));
    let smoke = container
        .harness_smoke(&project, &target, engine_kind, language)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        // A smoke run that surfaced crashes is a failure, not a pass: report it
        // as such so the UI (which keys its done/error state on this string)
        // does not render a crashing harness as qualified.
        "status": if smoke.passed { "SmokePassed" } else { "SmokeFailed" },
        "duration_secs": smoke.duration_secs,
        "execs_per_sec": smoke.execs_per_sec,
        "crashes": smoke.crashes,
        "passed": smoke.passed,
    }))
}

/// Explicitly approve a clean smoke-qualified harness for full campaigns.
#[tauri::command]
pub async fn harness_promote(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    target: String,
    engine: String,
) -> Result<serde_json::Value, String> {
    let engine_kind = parse_engine(&engine)?;
    let harness = state
        .container
        .harness_promote(&project, &target, engine_kind)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "status": format!("{:?}", harness.status),
        "harness_id": harness.id,
        "message": "Harness approved for full campaigns.",
    }))
}

/// Explicitly approve a harness while retaining known smoke findings.
#[tauri::command]
pub async fn harness_promote_with_findings(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    target: String,
    engine: String,
) -> Result<serde_json::Value, String> {
    let engine_kind = parse_engine(&engine)?;
    let promoted = state
        .container
        .harness_promote_with_findings(&project, &target, engine_kind)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"status": format!("{:?}", promoted.status), "known_findings": true}))
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

/// AI-generated corpus seeds for a target via the configured LLM provider,
/// persisted as tracked corpus entries. Falls back to heuristic seeds when no
/// provider is configured, so it always produces a corpus.
#[tauri::command]
pub async fn generate_seeds_llm(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
    lang: String,
    count: usize,
) -> Result<serde_json::Value, String> {
    let lang = parse_lang(&lang)?;
    let entries = state
        .container
        .generate_seeds_llm(std::path::Path::new(&project), &target, lang, count)
        .await
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

/// Every crash persisted to the store, across all targets and runs.
///
/// The browse-all Artifacts view uses this instead of `triage` with an empty
/// target (which would scan the wrong per-target workspace and find nothing).
#[tauri::command]
pub async fn all_crashes(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<serde_json::Value, String> {
    let crashes = state.container.all_crashes().await;
    serde_json::to_value(&crashes).map_err(|e| e.to_string())
}

/// Every corpus entry persisted to the store, across all targets.
#[tauri::command]
pub async fn all_corpus(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<serde_json::Value, String> {
    let entries = state.container.all_corpus_entries().await;
    serde_json::to_value(&entries).map_err(|e| e.to_string())
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
    // Clicking Scan for Crashes is the operator's approval for this bounded
    // sandboxed triage action; use the workflow gate rather than the Chat-only
    // interactive approval listener.
    let container = state.container.clone().with_guardrails(Guardrails::new(
        GuardrailPolicy::default(),
        std::sync::Arc::new(AutoApproveGate),
    ));
    let deduped = container
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
    hf_service::host_platform()
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

fn parse_role(role: &str) -> Role {
    match role.to_ascii_lowercase().as_str() {
        "system" => Role::System,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        _ => Role::User,
    }
}

/// An [`EventSink`](hf_service::EventSink) that forwards agent events to the
/// frontend as `chat:event` Tauri events for live rendering.
struct TauriEventSink {
    app: tauri::AppHandle,
}

#[async_trait::async_trait]
impl hf_service::EventSink for TauriEventSink {
    async fn emit(&self, event: hf_service::AgentEvent) {
        use tauri::Emitter;
        let _ = self.app.emit("chat:event", &event);
    }
}

/// A guardrail [`ApprovalGate`] that asks the user
/// via the GUI: it emits `chat:permission_request` and blocks until the
/// frontend answers through `chat_answer_permission`. A dropped channel (e.g.
/// the window closing) denies by default.
struct GuiApprovalGate {
    app: tauri::AppHandle,
    pending: std::sync::Arc<crate::state::PendingApprovals>,
}

#[async_trait::async_trait]
impl ApprovalGate for GuiApprovalGate {
    async fn request_approval(&self, action: &Action, reason: &str) -> bool {
        use tauri::Emitter;
        /// Deny an approval the user never answers so the agent turn cannot hang
        /// indefinitely (the only prompt listener lives in the Chat view).
        const APPROVAL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);
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
        self.pending.await_decision(id, rx, APPROVAL_TIMEOUT).await
    }
}

/// An approval gate that auto-approves. Used for high-risk actions the user has
/// already explicitly initiated via the workflow UI (e.g. clicking "Run Fuzzer"):
/// the click itself is the human approval, and execution still goes through the
/// hf-runtime sandbox. The agent/chat path uses the interactive `GuiApprovalGate`.
struct AutoApproveGate;

#[async_trait::async_trait]
impl ApprovalGate for AutoApproveGate {
    async fn request_approval(&self, _action: &Action, _reason: &str) -> bool {
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
    let agent_count = hf_service::AgentRegistry::with_user_dir(agents_dir())
        .list()
        .len();
    snapshot.agents.available_slots = agent_count;
    snapshot.agents.total_instances = snapshot.agents.instances.len();
    Ok(snapshot)
}

/// Internal-team dashboard summary for the active project/target.
#[tauri::command]
pub async fn workbench_dashboard(
    state: tauri::State<'_, crate::state::AppState>,
    project: Option<String>,
    target: Option<String>,
) -> Result<hf_service::WorkbenchDashboard, String> {
    let project_path = project
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(std::path::Path::new);
    let target = target.as_deref().filter(|t| !t.is_empty());
    Ok(state
        .container
        .workbench_dashboard(project_path, target)
        .await)
}

/// Generated harnesses that need human review or promotion.
#[tauri::command]
pub async fn harness_review_queue(
    state: tauri::State<'_, crate::state::AppState>,
    project: Option<String>,
    target: Option<String>,
) -> Result<Vec<hf_service::HarnessReviewItem>, String> {
    let project_path = project
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(std::path::Path::new);
    let target = target.as_deref().filter(|t| !t.is_empty());
    Ok(state
        .container
        .harness_review_queue(project_path, target)
        .await)
}

/// Build a GitLab issue draft/prefilled URL for a triaged crash.
#[tauri::command]
pub async fn gitlab_issue_export(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    crash_id: String,
) -> Result<hf_service::GitLabIssueExport, String> {
    state
        .container
        .gitlab_issue_export(std::path::Path::new(&project), &crash_id)
        .await
        .map_err(|e| e.to_string())
}

/// Whether a usable `DefectDojo` config is present (drives the settings UI state).
#[tauri::command]
pub async fn defectdojo_configured(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<bool, String> {
    Ok(state.container.defectdojo_configured())
}

/// Verify the configured `DefectDojo` URL + token without pushing.
#[tauri::command]
pub async fn defectdojo_test_connection(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<bool, String> {
    state
        .container
        .defectdojo_test_connection()
        .await
        .map(|()| true)
        .map_err(|e| e.to_string())
}

/// Push the latest run's triaged crashes to `DefectDojo` as findings.
#[tauri::command]
pub async fn push_to_defectdojo(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: Option<String>,
) -> Result<hf_service::PushOutcome, String> {
    state
        .container
        .push_to_defectdojo(std::path::Path::new(&project), target.as_deref())
        .await
        .map_err(|e| e.to_string())
}

/// Saved editable report drafts.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn list_report_drafts(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Vec<hf_service::ReportDraft>, String> {
    state
        .container
        .list_report_drafts()
        .map_err(|e| e.to_string())
}

/// Save or update one editable report draft.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn save_report_draft(
    state: tauri::State<'_, crate::state::AppState>,
    id: Option<String>,
    title: String,
    project: String,
    target: Option<String>,
    status: String,
    content: String,
) -> Result<hf_service::ReportDraft, String> {
    state
        .container
        .save_report_draft(id, &title, &project, target.as_deref(), &status, &content)
        .map_err(|e| e.to_string())
}

/// Delete one editable report draft.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn delete_report_draft(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
) -> Result<(), String> {
    state
        .container
        .delete_report_draft(&id)
        .map_err(|e| e.to_string())
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

/// Clear all learned knowledge across every project: discovered targets and
/// their harnesses, corpus entries, and crashes, plus all runs. Configuration
/// and on-disk workspaces are untouched.
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

/// Delete every trace of a single project: its persisted records (targets,
/// runs, harnesses, corpus entries, crashes) and its on-disk workspace. Other
/// projects are untouched.
#[tauri::command]
pub async fn delete_project(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
) -> Result<(), String> {
    state
        .container
        .delete_project(std::path::Path::new(&project))
        .await
        .map_err(|e| e.to_string())
}

/// Delete a single crash reproducer by id.
#[tauri::command]
pub async fn delete_crash(
    state: tauri::State<'_, crate::state::AppState>,
    crash_id: String,
) -> Result<(), String> {
    state
        .container
        .delete_crash(&crash_id)
        .await
        .map_err(|e| e.to_string())
}

/// Delete a single corpus entry by its content hash.
#[tauri::command]
pub async fn delete_corpus_entry(
    state: tauri::State<'_, crate::state::AppState>,
    sha256: String,
) -> Result<(), String> {
    state
        .container
        .delete_corpus_entry(&sha256)
        .await
        .map_err(|e| e.to_string())
}

/// Clear every persisted crash and corpus entry.
#[tauri::command]
pub async fn clear_all_artifacts(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<(), String> {
    state
        .container
        .clear_all_artifacts()
        .await
        .map_err(|e| e.to_string())
}

/// Delete a single run and the crashes it produced.
#[tauri::command]
pub async fn delete_run(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<(), String> {
    state
        .container
        .delete_run(&run_id)
        .await
        .map_err(|e| e.to_string())
}

/// Clear every persisted run and the crashes it produced.
#[tauri::command]
pub async fn clear_all_runs(state: tauri::State<'_, crate::state::AppState>) -> Result<(), String> {
    state
        .container
        .clear_all_runs()
        .await
        .map_err(|e| e.to_string())
}

/// Delete every on-disk fuzz workspace (compiled harnesses, corpora, crash
/// reproducers), reclaiming disk space. Persistent DB records are untouched.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn clear_workspace(state: tauri::State<'_, crate::state::AppState>) -> Result<(), String> {
    state.container.clear_workspace().map_err(|e| e.to_string())
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

/// Search a project's knowledge base, indexing it on demand if this process has
/// not yet (the index is an in-memory cache, so a restart would otherwise return
/// nothing). Runs on Tauri's blocking command pool, so the tree walk is fine.
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn knowledge_search(
    project: String,
    query: String,
    limit: Option<usize>,
) -> Vec<hf_service::knowledge::KnowledgeHit> {
    hf_service::knowledge::search_project_ensured(
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
    let tools = hf_service::TOOL_SPECS
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
pub fn list_skills() -> Vec<SkillDefinition> {
    SkillRegistry::with_user_dir(skills_dir()).list()
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
// A skill is an `hf_service::SkillDefinition`: a versioned instruction playbook
// (`root.md` body) plus metadata. Built-in fuzzing skills are embedded in the
// binary; user skills (and overrides) live under `skills/<name>/`. Agents
// reference skills by name and the runtime injects their bodies into context.

/// Read a single skill (built-in or user) for editing.
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn read_skill(name: String) -> Option<SkillDefinition> {
    SkillRegistry::with_user_dir(skills_dir())
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
    let def = SkillDefinition {
        name,
        version,
        description,
        domain,
        body: content,
        max_input_tokens: 0,
        trust_tier: TrustTier::UserDefined,
    };
    let mut reg = SkillRegistry::with_user_dir(skills_dir());
    reg.save(def).map_err(|e| e.to_string())
}

/// Delete a user skill, or reset a built-in override to its shipped version.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn delete_skill(name: String) -> Result<(), String> {
    let mut reg = SkillRegistry::with_user_dir(skills_dir());
    reg.delete(&name).map_err(|e| e.to_string())
}

// -- Agents (registry-backed) -----------------------------------------------
//
// An "agent" is an `hf_service::AgentDefinition`: a flat-TOML profile that fully
// determines the runtime agent's system prompt, callable tools, model routing,
// and iteration budget. Built-in fuzzing agents are embedded in the binary;
// user agents (and overrides) live in `config/agents/*.toml`.

/// List all agents -- built-in fuzzing agents plus any user-authored ones.
#[tauri::command]
#[must_use]
pub fn list_agents() -> Vec<hf_service::AgentDefinition> {
    hf_service::AgentRegistry::with_user_dir(agents_dir()).list()
}

/// Fetch a single agent definition by id.
#[tauri::command]
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn get_agent(id: String) -> Option<hf_service::AgentDefinition> {
    hf_service::AgentRegistry::with_user_dir(agents_dir())
        .get(&id)
        .cloned()
}

/// The runtime tool roster an agent may be granted, for the editor checklist.
#[tauri::command]
#[must_use]
pub fn agent_tools() -> Vec<serde_json::Value> {
    hf_service::TOOL_SPECS
        .iter()
        .map(|(name, desc)| serde_json::json!({ "name": name, "description": desc }))
        .collect()
}

/// Create or update a user agent (writes `config/agents/<id>.toml`). Overriding
/// a built-in id shadows it until deleted.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn save_agent(def: hf_service::AgentDefinition) -> Result<(), String> {
    let mut reg = hf_service::AgentRegistry::with_user_dir(agents_dir());
    reg.save(def).map_err(|e| e.to_string())
}

/// Delete a user agent, or reset a built-in override to its shipped version.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn delete_agent(id: String) -> Result<(), String> {
    let mut reg = hf_service::AgentRegistry::with_user_dir(agents_dir());
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
    let id = SessionId(session_id);
    Ok(state.container.chat_rollback_last(&id).await)
}

/// List the per-turn checkpoints for a chat session (the rollback picker).
#[tauri::command]
pub async fn chat_checkpoints(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<hf_service::checkpoints::CheckpointView>, String> {
    let id = SessionId(session_id);
    Ok(state.container.chat_checkpoints(&id).await)
}

/// Roll back a chat session to a specific checkpoint. Returns messages removed.
#[tauri::command]
pub async fn chat_rollback_to(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
    checkpoint_id: String,
) -> Result<usize, String> {
    let id = SessionId(session_id);
    Ok(state.container.chat_rollback_to(&id, &checkpoint_id).await)
}

/// Wire string for a message role.
fn role_to_str(role: Role) -> &'static str {
    match role {
        Role::System => "system",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
        Role::User => "user",
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
    let id = SessionId(session_id);
    Ok(state
        .container
        .chat_branch(&id, fork_count, title.filter(|t| !t.is_empty()))
        .await)
}

/// Delete a chat session and its transcript (the "clear history" action).
/// Returns whether a session was deleted.
#[tauri::command]
pub async fn delete_session(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<bool, String> {
    let id = SessionId(session_id);
    Ok(state.container.delete_chat_session(&id).await)
}

/// Load a session's transcript as chat turns (for switching branches).
#[tauri::command]
pub async fn chat_history(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<ChatTurn>, String> {
    let id = SessionId(session_id);
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
    let id = SessionId(session_id);
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
    let session = session_id.filter(|s| !s.is_empty()).map(SessionId);
    // Frontend-supplied history, used only when no persistent session applies.
    let history_fallback: Vec<Message> = history
        .unwrap_or_default()
        .into_iter()
        .map(|t| Message::new(parse_role(&t.role), t.content))
        .collect();

    // Run with an interactive guardrail gate: high-risk tool calls (e.g. run a
    // fuzzer) prompt the user via `chat:permission_request` before executing.
    let gate = std::sync::Arc::new(GuiApprovalGate {
        app: app.clone(),
        pending: state.pending_approvals.clone(),
    });
    let guardrails = Guardrails::new(GuardrailPolicy::default(), gate);
    let container = state.container.clone().with_guardrails(guardrails);
    let sink = TauriEventSink { app };

    // Register the turn so the Observability panel shows live agent activity;
    // the guard removes it when the turn returns (or errors). The shared
    // `active_agents` list is behind an Arc, so tracking via `state.container`
    // is visible to `system_snapshot`.
    let _agent_guard = state
        .container
        .track_agent(agent_id.as_deref().unwrap_or("agent"));

    // Drive the turn through the shared service-layer orchestration so the GUI,
    // web, and CLI all run the agent identically (AGENTS.md 2.9).
    container
        .run_chat_turn(
            hf_service::AgentTurnRequest {
                project,
                agent_id,
                session,
                history_fallback,
                message,
            },
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

    if !hf_service::docker_daemon_ready() {
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
    let container = state.container.clone().with_guardrails(Guardrails::new(
        GuardrailPolicy::default(),
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
            // A coverage-stagnation proposal (e.g. "new_harness") when the run
            // plateaued, so the UI can offer an iterate-next affordance; null
            // when coverage kept progressing.
            "stagnation": summary.stagnation,
            // Set when the auto-revert policy restored an earlier harness because
            // this run's revision regressed coverage past the threshold; null
            // otherwise. Lets the UI surface the automatic action.
            "auto_revert": summary.auto_revert,
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

/// Reveal a file or directory in the OS file manager (Finder / Explorer).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn reveal_path(app: tauri::AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|e| e.to_string())
}

/// Open a file or directory with the OS default handler (e.g. `$EDITOR`).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn open_path(app: tauri::AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(path, None::<&str>)
        .map_err(|e| e.to_string())
}

/// Open the `DefectDojo` web UI at the configured URL. With `in_browser`, hands it
/// to the OS default browser (a full, separate browser session). Otherwise opens
/// it in a dedicated, natively-decorated in-app window (title bar + close button;
/// reused/focused if already open), so the user can log in and browse findings
/// without leaving `hobot_fuzz`. The URL comes from the saved config, so callers
/// (sidebar, dashboard, settings) never pass it.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn open_defectdojo(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    in_browser: bool,
) -> Result<(), String> {
    let url = state.container.defectdojo_url().ok_or_else(|| {
        "DefectDojo is not configured -- set the URL in Settings first".to_owned()
    })?;
    if in_browser {
        use tauri_plugin_opener::OpenerExt;
        return app
            .opener()
            .open_url(url, None::<&str>)
            .map_err(|e| e.to_string());
    }
    // In-app window: focus an existing one rather than spawning duplicates.
    if let Some(win) = app.get_webview_window("defectdojo") {
        let _ = win.unminimize();
        return win.set_focus().map_err(|e| e.to_string());
    }
    let parsed = tauri::Url::parse(&url).map_err(|e| format!("invalid DefectDojo URL: {e}"))?;
    tauri::WebviewWindowBuilder::new(&app, "defectdojo", tauri::WebviewUrl::External(parsed))
        .title("DefectDojo")
        .inner_size(1280.0, 840.0)
        .min_inner_size(720.0, 500.0)
        .decorations(true)
        .center()
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Persisted run history for a project (crash counts + durations), newest first.
#[tauri::command]
pub async fn run_history(
    state: tauri::State<'_, crate::state::AppState>,
    project: Option<String>,
) -> Result<Vec<hf_service::RunHistoryItem>, String> {
    let path = project
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(std::path::Path::new);
    Ok(state.container.run_history(path).await)
}

/// The intra-run coverage/throughput curve for a single run (empty if none was
/// recorded).
#[tauri::command]
pub async fn run_coverage_series(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<Vec<hf_service::CoverageSample>, String> {
    Ok(state.container.run_coverage_series(&run_id).await)
}

/// The harness source a run used, for diffing between harness revisions.
#[tauri::command]
pub async fn run_harness_source(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<String, String> {
    Ok(state.container.run_harness_source(&run_id).await)
}

/// Restore the harness a run used (recompiling it), reverting the target to that
/// revision.
#[tauri::command]
pub async fn revert_harness_from_run(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<serde_json::Value, String> {
    let out = state
        .container
        .revert_harness_from_run(&run_id)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "status": format!("{:?}", out.status),
        "message": "Reverted and recompiled the harness in the sandbox.",
    }))
}

/// A project's auto-revert override, or `null` when it inherits the global
/// policy. Drives the per-project toggle in the Run History policy card.
#[tauri::command]
pub async fn project_auto_revert_override(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
) -> Result<Option<hf_service::ProjectAutoRevert>, String> {
    Ok(state
        .container
        .project_auto_revert_override(std::path::Path::new(&project))
        .await)
}

/// The auto-revert audit trail (newest first). `project` scopes to one project;
/// omit it for every project. `limit` caps the rows.
#[tauri::command]
pub async fn auto_revert_events(
    state: tauri::State<'_, crate::state::AppState>,
    project: Option<String>,
    limit: Option<usize>,
) -> Result<Vec<hf_service::AutoRevertEvent>, String> {
    let path = project.filter(|p| !p.is_empty());
    Ok(state
        .container
        .auto_revert_events(
            path.as_deref().map(std::path::Path::new),
            limit.unwrap_or(200),
        )
        .await)
}

/// The active project's effective auto-revert policy (override merged over the
/// global default) plus whether an override applies, for the Workbench badge.
#[tauri::command]
pub async fn effective_auto_revert_policy(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
) -> Result<hf_service::EffectiveAutoRevert, String> {
    Ok(state
        .container
        .effective_auto_revert_view(std::path::Path::new(&project))
        .await)
}

/// Every project's auto-revert override, keyed by project root, for badging the
/// projects overview.
#[tauri::command]
pub async fn project_auto_revert_overrides(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<std::collections::HashMap<String, hf_service::ProjectAutoRevert>, String> {
    Ok(state.container.project_auto_revert_overrides().await)
}

/// Set (or replace) a project's auto-revert override.
#[tauri::command]
pub async fn set_project_auto_revert_override(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    enabled: bool,
    threshold_pct: f64,
    notify_only: bool,
) -> Result<(), String> {
    state
        .container
        .set_project_auto_revert_override(
            std::path::Path::new(&project),
            enabled,
            threshold_pct,
            notify_only,
        )
        .await
        .map_err(|e| e.to_string())
}

/// Clear a project's auto-revert override, so it inherits the global policy.
#[tauri::command]
pub async fn clear_project_auto_revert_override(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
) -> Result<(), String> {
    state
        .container
        .clear_project_auto_revert_override(std::path::Path::new(&project))
        .await
        .map_err(|e| e.to_string())
}

/// Export a project's fuzzing data (targets, runs, harnesses, crashes, corpus)
/// as a JSON bundle via a native save dialog. Returns the saved path or `None`.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn export_project_data(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    project: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let path = project
        .as_deref()
        .filter(|p| !p.is_empty())
        .map(std::path::Path::new);
    let bundle = state.container.export_project_data(path).await;
    let json = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    let name = path
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("all");
    let default_name = format!("hobot_fuzz_export_{}.json", sanitize_filename(name));
    let Some(dest) = app
        .dialog()
        .file()
        .set_title("Export fuzzing data")
        .set_file_name(&default_name)
        .add_filter("JSON", &["json"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let dest = dest
        .into_path()
        .map_err(|e| format!("invalid save path: {e}"))?;
    std::fs::write(&dest, json).map_err(|e| format!("write export: {e}"))?;
    Ok(Some(dest.to_string_lossy().to_string()))
}

/// Report export formats available on this host (always includes md + html;
/// docx/pdf when pandoc and a PDF engine are installed).
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn report_formats(state: tauri::State<'_, crate::state::AppState>) -> Vec<String> {
    state.container.report_formats()
}

/// Compose the report for a target and save it in `format` (md/html/pdf/docx)
/// via a native save dialog with the matching extension. Returns the saved path
/// or `None` if the dialog was cancelled.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn export_report(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
    format: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let ext = match format.trim().to_ascii_lowercase().as_str() {
        "md" | "markdown" => "md",
        "html" | "htm" => "html",
        "pdf" => "pdf",
        "docx" | "doc" => "docx",
        other => return Err(format!("unknown report format: {other}")),
    };
    let default_name = format!("hobot_fuzz_report_{}.{ext}", sanitize_filename(&target));
    let Some(path) = app
        .dialog()
        .file()
        .set_title("Export fuzzing report")
        .set_file_name(&default_name)
        .add_filter(ext.to_uppercase(), &[ext])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|e| format!("invalid save path: {e}"))?;
    state
        .container
        .export_report(std::path::Path::new(&project), &target, ext, &path)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().to_string()))
}

/// Export already-composed report `content` (e.g. a saved draft) in `format`
/// via a native save dialog. Returns the saved path or `None` if cancelled.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn export_markdown(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    content: String,
    title: String,
    format: String,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let ext = match format.trim().to_ascii_lowercase().as_str() {
        "md" | "markdown" => "md",
        "html" | "htm" => "html",
        "pdf" => "pdf",
        "docx" | "doc" => "docx",
        other => return Err(format!("unknown report format: {other}")),
    };
    let default_name = format!("{}.{ext}", sanitize_filename(&title));
    let Some(path) = app
        .dialog()
        .file()
        .set_title("Export report")
        .set_file_name(&default_name)
        .add_filter(ext.to_uppercase(), &[ext])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let path = path
        .into_path()
        .map_err(|e| format!("invalid save path: {e}"))?;
    state
        .container
        .export_markdown(&content, &title, ext, &path)
        .map_err(|e| e.to_string())?;
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

/// Run a real syzkaller campaign through the service layer.
///
/// Thin presentation wrapper: all orchestration (mount assembly, `manager.cfg`
/// synthesis, sandboxed `syz-manager` invocation) lives in
/// [`hf_service::ServiceContainer::run_syzkaller`], which routes through the
/// `hf-runtime` sandbox. This command only maps options in and streams
/// [`FuzzProgress`] back to the GUI as `run:progress` events.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn run_syzkaller(
    state: tauri::State<'_, crate::state::AppState>,
    app: tauri::AppHandle,
    opts: SyzkallerOpts,
) -> Result<serde_json::Value, String> {
    use tauri::Emitter;

    let app_handle = app.clone();
    let on_progress = move |p: FuzzProgress| {
        let (ty, data) = match p {
            FuzzProgress::EdgesCovered(v) => ("EdgesCovered", serde_json::json!(v)),
            FuzzProgress::ExecsPerSec(v) => ("ExecsPerSec", serde_json::json!(v)),
            FuzzProgress::CrashesFound(n) => ("CrashesFound", serde_json::json!(n)),
            FuzzProgress::LogLine(s) => ("LogLine", serde_json::json!(s)),
            FuzzProgress::Done => ("Done", serde_json::Value::Null),
        };
        let _ = app_handle.emit(
            "run:progress",
            serde_json::json!({ "type": ty, "data": data }),
        );
    };

    let svc_opts = hf_service::SyzkallerRunOpts {
        project: opts.project,
        arch: opts.arch,
        duration_secs: opts.duration,
        kernel_image: opts.kernel_image,
        disk_image: opts.disk_image,
        ssh_key: opts.ssh_key,
        manager_cfg: opts.manager_cfg,
        vm_count: opts.vm_count,
    };

    // The explicit launch is the human approval for this sandboxed run; auto-
    // approve so the agent-oriented HITL gate does not block it (mirrors
    // `run_fuzzer`).
    let container = state.container.clone().with_guardrails(Guardrails::new(
        GuardrailPolicy::default(),
        std::sync::Arc::new(AutoApproveGate),
    ));

    match container.run_syzkaller(&svc_opts, &on_progress).await {
        Ok(summary) => Ok(serde_json::json!({
            "edges": summary.edges,
            "crashes": summary.crashes,
            "execs": summary.execs,
            "exit_code": summary.exit_code,
        })),
        Err(e) => Err(e.to_string()),
    }
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
