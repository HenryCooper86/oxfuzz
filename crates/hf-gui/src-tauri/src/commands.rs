//! Tauri commands -- thin wrappers around `hf-service::ServiceContainer`.
//!
//! Per AGENTS.md 2.9: no domain logic here. All business logic lives in
//! `hf-service`; these commands handle I/O, Tauri event emission, and
//! argument marshalling only.

use std::path::PathBuf;

use hf_service::{
    Action, ApprovalGate, EngineKind, FuzzProgress, GuardrailPolicy, Guardrails, Message, Role,
    SessionId, SkillDefinition, TargetLanguage,
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
        return system_status().await;
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
        return system_status().await;
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

    system_status().await
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Compute the current system status by probing Docker + the sandbox image.
pub async fn system_status() -> SystemStatus {
    hf_service::system_status().await
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

/// Report whether this application build includes Semgrep enrichment.
#[tauri::command]
#[must_use]
pub const fn semgrep_available() -> bool {
    cfg!(feature = "semgrep-enrichment")
}

/// Start explicit Semgrep enrichment for a persisted C or C++ inventory.
#[cfg(feature = "semgrep-enrichment")]
#[tauri::command]
pub async fn semgrep_enrich(
    state: tauri::State<'_, crate::state::AppState>,
    project: PathBuf,
    lang: String,
) -> Result<uuid::Uuid, String> {
    let language = parse_lang(&lang)?;
    state
        .container
        .start_semgrep_enrichment(project, language)
        .await
        .map_err(|error| error.to_string())
}

/// Read one exact service-owned Semgrep operation.
#[cfg(feature = "semgrep-enrichment")]
#[tauri::command]
pub async fn semgrep_status(
    state: tauri::State<'_, crate::state::AppState>,
    operation_id: uuid::Uuid,
) -> Result<hf_service::SemgrepOperationView, String> {
    state
        .container
        .semgrep_operation(operation_id)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Semgrep operation not found".to_owned())
}

/// Request cancellation of one exact service-owned Semgrep operation.
#[cfg(feature = "semgrep-enrichment")]
#[tauri::command]
pub async fn semgrep_cancel(
    state: tauri::State<'_, crate::state::AppState>,
    operation_id: uuid::Uuid,
) -> Result<hf_service::SemgrepCancelOutcome, String> {
    state
        .container
        .request_semgrep_cancel(operation_id)
        .await
        .map_err(|error| error.to_string())
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
        "status": if smoke.summary.passed { "SmokePassed" } else { "SmokeFailed" },
        "duration_secs": smoke.summary.duration_secs,
        "execs_per_sec": smoke.summary.execs_per_sec,
        "crashes": smoke.summary.crashes,
        "passed": smoke.summary.passed,
        // Deterministic self-verification verdict (grok-build L2): lets the UI
        // warn on a hollow pass instead of treating every "passed" as qualified.
        "verdict": smoke.verdict,
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
        .await
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
    let crashes = state
        .container
        .all_crashes()
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(&crashes).map_err(|e| e.to_string())
}

/// Every corpus entry persisted to the store, across all targets.
#[tauri::command]
pub async fn all_corpus(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<serde_json::Value, String> {
    let entries = state
        .container
        .all_corpus_entries()
        .await
        .map_err(|error| error.to_string())?;
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
        .await
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

/// On-demand LLM verdict for one crash (L2 4c). Verifying is opt-in per crash so
/// a "Scan for Crashes" pass is not blocked on a model call for every crash; the
/// operator asks for a verdict on the specific crash they care about.
#[tauri::command]
pub async fn verify_crash(
    state: tauri::State<'_, crate::state::AppState>,
    target: String,
    crash: hf_service::Crash,
) -> Result<serde_json::Value, String> {
    let verdict = state.container.verify_crash(&target, &crash).await;
    serde_json::to_value(verdict).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn system_status_cmd() -> SystemStatus {
    system_status().await
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

/// The host's native sandbox platform, e.g. "linux/arm64".
#[tauri::command]
#[must_use]
pub fn host_arch() -> String {
    hf_service::host_platform()
}

// ---------------------------------------------------------------------------
// Chat (LLM-backed)
// ---------------------------------------------------------------------------

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

/// Everything `oxfuzz` has learned about your projects, read from the
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

/// Live service-owned system snapshot for the Observability panel.
#[tauri::command]
pub async fn system_snapshot(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<hf_service::SystemSnapshot, String> {
    state
        .container
        .system_snapshot()
        .await
        .map_err(|error| error.to_string())
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
    state
        .container
        .workbench_dashboard(project_path, target)
        .await
        .map_err(|error| error.to_string())
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
    state
        .container
        .harness_review_queue(project_path, target)
        .await
        .map_err(|error| error.to_string())
}

/// Build an issue draft/prefilled URL for a triaged crash, targeting the fuzzed
/// project's configured GitHub/GitLab repository.
#[tauri::command]
pub async fn issue_export(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    crash_id: String,
) -> Result<hf_service::IssueExport, String> {
    state
        .container
        .issue_export(std::path::Path::new(&project), &crash_id)
        .await
        .map_err(|e| e.to_string())
}

/// File a triaged crash as an issue via the configured provider's API; returns
/// the created issue's URL.
#[tauri::command]
pub async fn file_issue(
    state: tauri::State<'_, crate::state::AppState>,
    crash_id: String,
) -> Result<hf_service::CreatedIssue, String> {
    state
        .container
        .file_issue(&crash_id)
        .await
        .map_err(|e| e.to_string())
}

/// Verify the issue-tracker host + token without filing anything.
#[tauri::command]
pub async fn issue_tracker_test_connection(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<bool, String> {
    state
        .container
        .issue_tracker_test_connection()
        .await
        .map(|()| true)
        .map_err(|e| e.to_string())
}

/// Whether a usable `DefectDojo` config is present (drives the settings UI state).
#[tauri::command]
pub async fn defectdojo_configured(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<bool, String> {
    Ok(state.container.defectdojo_configured())
}

/// State of the `DefectDojo` instance: configured, installed, running, reachable.
/// Drives the Health panel row and the embedded view's gate.
#[tauri::command]
pub async fn defectdojo_status() -> hf_service::DefectDojoStatus {
    hf_service::defectdojo_lifecycle::status().await
}

/// On launch, start the local `DefectDojo` if the config asks for it, narrating
/// each transition over `defectdojo:status` so the UI can show it booting rather
/// than an empty rectangle. Must run after Docker is up.
pub(crate) async fn autostart_defectdojo(app: &tauri::AppHandle) {
    use tauri::Emitter;
    let app = app.clone();
    hf_service::defectdojo_lifecycle::autostart(&move |status| {
        let _ = app.emit("defectdojo:status", status);
    })
    .await;
}

/// Start the local Docker `DefectDojo` and wait for it to answer. Also invoked
/// on launch (see `lib.rs`), so this is the manual retry of that.
#[tauri::command]
pub async fn defectdojo_start() -> Result<hf_service::DefectDojoStatus, String> {
    hf_service::defectdojo_lifecycle::start()
        .await
        .map_err(|e| e.to_string())
}

/// Stop the local Docker `DefectDojo`, leaving its data intact.
#[tauri::command]
pub async fn defectdojo_stop() -> Result<hf_service::DefectDojoStatus, String> {
    hf_service::defectdojo_lifecycle::stop()
        .await
        .map_err(|e| e.to_string())
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
    path: String,
) -> Result<(), String> {
    state
        .container
        .delete_corpus_entry(&sha256, std::path::Path::new(&path))
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
pub fn clear_workspace(state: tauri::State<'_, crate::state::AppState>) -> Result<(), String> {
    state.container.clear_workspace().map_err(|e| e.to_string())
}

/// Aggregated LLM cost/usage recorded this session (diagnostics).
#[tauri::command]
pub async fn diagnostics_cost_summary(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<hf_service::diagnostics::CostSummary, String> {
    state
        .container
        .cost_summary()
        .await
        .map_err(|error| error.to_string())
}

/// Runs interrupted by a prior crash/quit, awaiting recovery.
#[tauri::command]
#[must_use]
pub fn interrupted_runs(
    state: tauri::State<'_, crate::state::AppState>,
) -> Vec<hf_service::recovery::InterruptedRun> {
    state.container.interrupted_runs()
}

/// Dismiss an interrupted run; returns the updated list.
#[tauri::command]
pub fn dismiss_interrupted_run(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<Vec<hf_service::recovery::InterruptedRun>, String> {
    state
        .container
        .dismiss_interrupted_run(&run_id)
        .map_err(|error| error.to_string())?;
    Ok(state.container.interrupted_runs())
}

/// List all scheduled fuzz campaigns.
#[tauri::command]
pub async fn schedule_list(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    state
        .scheduler
        .list_views()
        .await
        .map_err(|error| error.to_string())
}

/// List one-time campaign receipts that require operator acknowledgement.
#[tauri::command]
pub async fn schedule_recovery_list(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Vec<hf_service::scheduler::OneTimeRecoveryView>, String> {
    state
        .scheduler
        .list_one_time_recoveries()
        .await
        .map_err(recovery_command_error)
}

/// Record an eligible one-time recovery outcome as cancelled.
#[tauri::command]
pub async fn schedule_recovery_acknowledge(
    state: tauri::State<'_, crate::state::AppState>,
    occurrence_id: String,
) -> Result<hf_service::scheduler::OneTimeRecoveryView, String> {
    state
        .scheduler
        .acknowledge_one_time_recovery(&occurrence_id)
        .await
        .map_err(recovery_command_error)
}

fn recovery_command_error(error: hf_service::scheduler::CampaignSchedulerError) -> String {
    error.into_public_recovery_error().to_string()
}

/// Recent scheduled-campaign executions (newest first).
#[tauri::command]
pub async fn schedule_history(
    state: tauri::State<'_, crate::state::AppState>,
    limit: Option<usize>,
) -> Result<Vec<hf_service::scheduler::ExecutionView>, String> {
    state
        .scheduler
        .recent_executions(limit.unwrap_or(20))
        .await
        .map_err(|error| error.to_string())
}

/// Clear the scheduled-campaign execution history.
#[tauri::command]
pub async fn schedule_history_clear(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<u64, String> {
    state
        .scheduler
        .clear_history()
        .await
        .map_err(|error| error.to_string())
}

/// Targets in `project` a campaign can be scheduled against: those with a
/// promoted harness. The engine and language ride along, so the schedule is
/// created with the combination the harness was qualified for.
#[tauri::command]
pub async fn schedule_targets(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
) -> Result<Vec<hf_service::SchedulableTarget>, String> {
    state
        .container
        .schedulable_targets(std::path::Path::new(&project))
        .await
        .map_err(|e| e.to_string())
}

/// Create a scheduled fuzz campaign; returns the updated list. An empty `target`
/// makes a portfolio campaign that rotates through all promoted targets.
#[tauri::command]
pub async fn schedule_create(
    state: tauri::State<'_, crate::state::AppState>,
    name: String,
    project: String,
    target: Option<String>,
    engine: String,
    lang: String,
    duration_secs: u64,
    trigger_kind: String,
    trigger_value: String,
    max_runs: Option<u32>,
    max_total_secs: Option<u64>,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    let trigger = hf_service::scheduler::parse_trigger(&trigger_kind, &trigger_value)?;
    let params = hf_service::scheduler::CampaignParams {
        project,
        target: target.filter(|t| !t.is_empty()),
        engine,
        lang,
        duration_secs,
        max_runs,
        max_total_secs,
        schedule_id: String::new(),
    };
    state
        .scheduler
        .try_create(&name, &params, trigger)
        .await
        .map_err(|error| error.to_string())?;
    state
        .scheduler
        .list_views()
        .await
        .map_err(|error| error.to_string())
}

/// Both scheduler concurrency caps and their effective fuzz-run ceiling.
#[tauri::command]
pub async fn schedule_concurrency_limits(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<hf_service::scheduler::CampaignConcurrencyLimits, String> {
    Ok(state.scheduler.concurrency_limits())
}

/// Set the global concurrent-campaign cap; returns the applied value.
#[tauri::command]
pub async fn schedule_concurrency_set(
    state: tauri::State<'_, crate::state::AppState>,
    max_concurrent: usize,
) -> Result<usize, String> {
    state
        .scheduler
        .try_set_max_concurrent(max_concurrent)
        .map_err(|error| error.to_string())?;
    Ok(state.scheduler.max_concurrent())
}

/// Delete a scheduled campaign; returns the updated list.
#[tauri::command]
pub async fn schedule_delete(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    if !state
        .scheduler
        .try_remove(&id)
        .await
        .map_err(|error| error.to_string())?
    {
        return Err(format!("no scheduled campaign with id '{id}'"));
    }
    state
        .scheduler
        .list_views()
        .await
        .map_err(|error| error.to_string())
}

/// Enable or disable a scheduled campaign; returns the updated list.
#[tauri::command]
pub async fn schedule_set_enabled(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
    enabled: bool,
) -> Result<Vec<hf_service::scheduler::CampaignView>, String> {
    if !state
        .scheduler
        .try_set_enabled(&id, enabled)
        .await
        .map_err(|error| error.to_string())?
    {
        return Err(format!("no scheduled campaign with id '{id}'"));
    }
    state
        .scheduler
        .list_views()
        .await
        .map_err(|error| error.to_string())
}

/// Index a project's source files into its BM25 knowledge base.
#[tauri::command]
pub fn knowledge_index(project: String) -> Result<hf_service::knowledge::KnowledgeStats, String> {
    hf_service::knowledge::index_project(std::path::Path::new(&project)).map_err(|e| e.to_string())
}

/// Read-only status of a project's knowledge base (no reindex): index size and
/// build time, ingested-document count, and the active retrieval config.
#[tauri::command]
#[must_use]
pub fn knowledge_stats(project: String) -> hf_service::knowledge::KnowledgeIndexStatus {
    hf_service::knowledge::stats_project(std::path::Path::new(&project))
}

/// Convert a document (PDF/Office/HTML/...) to Markdown via markitdown in the
/// sandbox and index it into the project knowledge base.
#[tauri::command]
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

#[tauri::command]
pub fn agent_info(
    state: tauri::State<'_, crate::state::AppState>,
) -> hf_service::AgentRegistryInfo {
    state.container.agent_registry_info()
}

/// List all skills -- built-in fuzzing skills plus any user-authored ones.
#[tauri::command]
#[must_use]
pub fn list_skills(state: tauri::State<'_, crate::state::AppState>) -> Vec<SkillDefinition> {
    state.container.list_skill_definitions()
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
pub fn read_skill(
    state: tauri::State<'_, crate::state::AppState>,
    name: String,
) -> Option<SkillDefinition> {
    state.container.get_skill_definition(&name)
}

/// Create or update a user skill (writes `skills/<name>/{skill.toml,root.md}`).
/// Overriding a built-in name shadows it until reset via `delete_skill`.
#[tauri::command]
pub fn save_skill(
    state: tauri::State<'_, crate::state::AppState>,
    definition: SkillDefinition,
) -> Result<(), String> {
    state
        .container
        .save_skill_definition(definition)
        .map_err(|error| error.to_string())
}

/// Delete a user skill, or reset a built-in override to its shipped version.
#[tauri::command]
pub fn delete_skill(
    state: tauri::State<'_, crate::state::AppState>,
    name: String,
) -> Result<(), String> {
    state
        .container
        .delete_skill_definition(&name)
        .map_err(|error| error.to_string())
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
pub fn list_agents(
    state: tauri::State<'_, crate::state::AppState>,
) -> Vec<hf_service::AgentDefinition> {
    state.container.list_agent_definitions()
}

/// The runtime tool roster an agent may be granted, for the editor checklist.
#[tauri::command]
#[must_use]
pub fn agent_tools(
    state: tauri::State<'_, crate::state::AppState>,
) -> Vec<hf_service::AgentToolDefinition> {
    state.container.agent_tool_definitions()
}

/// Create or update a user agent (writes `config/agents/<id>.toml`). Overriding
/// a built-in id shadows it until deleted.
#[tauri::command]
pub fn save_agent(
    state: tauri::State<'_, crate::state::AppState>,
    definition: hf_service::AgentDefinition,
) -> Result<(), String> {
    state
        .container
        .save_agent_definition(definition)
        .map_err(|error| error.to_string())
}

/// Delete a user agent, or reset a built-in override to its shipped version.
#[tauri::command]
pub fn delete_agent(
    state: tauri::State<'_, crate::state::AppState>,
    id: String,
) -> Result<(), String> {
    state
        .container
        .delete_agent_definition(&id)
        .map_err(|error| error.to_string())
}

/// Create a new persistent conversation session and return its id.
///
/// Returns `None` when no database is configured (chat still works, but turns
/// are not persisted server-side).
#[tauri::command]
pub async fn create_session(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<Option<String>, String> {
    state
        .container
        .create_chat_session(None)
        .await
        .map_err(|error| error.to_string())
}

/// Roll back the most recent chat turn for a session, truncating the persisted
/// transcript. Returns the number of messages removed.
#[tauri::command]
pub async fn chat_rollback(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<usize, String> {
    let id = SessionId(session_id);
    state
        .container
        .chat_rollback_last(&id)
        .await
        .map_err(|error| error.to_string())
}

/// List the per-turn checkpoints for a chat session (the rollback picker).
#[tauri::command]
pub async fn chat_checkpoints(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<hf_service::checkpoints::CheckpointView>, String> {
    let id = SessionId(session_id);
    state
        .container
        .chat_checkpoints(&id)
        .await
        .map_err(|error| error.to_string())
}

/// Roll back a chat session to a specific checkpoint. Returns messages removed.
#[tauri::command]
pub async fn chat_rollback_to(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
    checkpoint_id: String,
) -> Result<usize, String> {
    let id = SessionId(session_id);
    state
        .container
        .chat_rollback_to(&id, &checkpoint_id)
        .await
        .map_err(|error| error.to_string())
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
) -> Result<String, String> {
    let id = SessionId(session_id);
    state
        .container
        .chat_branch(&id, fork_count, title.filter(|t| !t.is_empty()))
        .await
        .map_err(|error| error.to_string())
}

/// Delete a chat session and its transcript (the "clear history" action).
/// Returns whether a session was deleted.
#[tauri::command]
pub async fn delete_session(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<bool, String> {
    let id = SessionId(session_id);
    state
        .container
        .delete_chat_session(&id)
        .await
        .map_err(|error| error.to_string())
}

/// Load a session's transcript as chat turns (for switching branches).
#[tauri::command]
pub async fn chat_history(
    state: tauri::State<'_, crate::state::AppState>,
    session_id: String,
) -> Result<Vec<ChatTurn>, String> {
    let id = SessionId(session_id);
    let messages = state
        .container
        .chat_history(&id)
        .await
        .map_err(|error| error.to_string())?;
    Ok(messages
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
    state
        .container
        .chat_branches(&id)
        .await
        .map_err(|error| error.to_string())
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
    display_message: Option<String>,
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
                display_message,
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
        return Ok(serde_json::json!({
            "run_id": serde_json::Value::Null,
            "edges": 0,
            "crashes": 0,
            "execs": 0.0,
            "termination": "completed",
            "exit_code": 0
        }));
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

    match result {
        Ok(summary) => Ok(serde_json::json!({
            "run_id": summary.run_id,
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
            "termination": summary.termination,
            // RunSummary records the termination kind but not the process exit
            // code, so report null (unknown) exactly like the HTTP transport
            // instead of fabricating 0 for every uninterrupted run.
            "exit_code": serde_json::Value::Null,
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
pub fn cancel_run(state: tauri::State<'_, crate::state::AppState>) -> usize {
    // The active-run registry is shared (Arc) across container clones, so the
    // base container sees runs started by the guardrail-adjusted clone in
    // `run_fuzzer`.
    state.container.cancel_all_runs()
}

/// Compose the Markdown campaign report for a target and return it as a string,
/// so the GUI can preview or download it. `language` is the caller's UI locale
/// (`en` / `zh`); omitting it composes in English.
#[tauri::command]
pub async fn generate_report(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
    language: Option<String>,
) -> Result<String, String> {
    let language = match language {
        Some(value) => value
            .parse::<hf_service::ReportLanguage>()
            .map_err(|error| error.to_string())?,
        None => hf_service::ReportLanguage::default(),
    };
    state
        .container
        .generate_report(std::path::Path::new(&project), &target, language)
        .await
        .map_err(|e| e.to_string())
}

/// Reveal a file or directory in the OS file manager (Finder / Explorer).
#[tauri::command]
pub fn reveal_path(app: tauri::AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .reveal_item_in_dir(&path)
        .map_err(|e| e.to_string())
}

/// Open a file or directory with the OS default handler (e.g. `$EDITOR`).
#[tauri::command]
pub fn open_path(app: tauri::AppHandle, path: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_path(path, None::<&str>)
        .map_err(|e| e.to_string())
}

/// Open a URL in the OS default browser. `window.open` is a no-op inside the
/// Tauri webview, so external links (GitLab issue drafts, docs) must go through
/// the opener instead.
#[tauri::command]
pub fn open_url(app: tauri::AppHandle, url: String) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

/// Open the `DefectDojo` web UI at the configured URL. With `in_browser`, hands it
/// to the OS default browser (a full, separate browser session). Otherwise opens
/// it in a dedicated, natively-decorated in-app window (title bar + close button;
/// reused/focused if already open), so the user can log in and browse findings
/// without leaving `oxfuzz`. The URL comes from the saved config, so callers
/// (sidebar, dashboard, settings) never pass it.
#[tauri::command]
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
    // Reuse a healthy existing window rather than spawning duplicates. If a stale
    // handle lingers after the window was closed (focusing it fails), tear it down
    // so the label is free to recreate -- otherwise a close-then-reopen could no-op
    // on a dead handle and open nothing.
    if let Some(win) = app.get_webview_window("defectdojo") {
        let _ = win.unminimize();
        if win.set_focus().is_ok() {
            return Ok(());
        }
        let _ = win.destroy();
    }
    let parsed = tauri::Url::parse(&url).map_err(|e| format!("invalid DefectDojo URL: {e}"))?;
    tauri::WebviewWindowBuilder::new(&app, "defectdojo", tauri::WebviewUrl::External(parsed))
        .title("DefectDojo")
        .inner_size(1280.0, 840.0)
        .min_inner_size(720.0, 500.0)
        .decorations(true)
        .focused(true)
        .center()
        .build()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Embed (or reposition) the `DefectDojo` web UI as a child webview inside the
/// main window, filling the logical rectangle the in-app view reports for its
/// content region. `DefectDojo` sends `X-Frame-Options: DENY`, so a native child
/// webview is the only way to render it in-app; it overlays the region below the
/// view's toolbar and tracks it on resize.
#[tauri::command]
pub fn defectdojo_embed(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    state.dd_embed_wanted.store(true, Ordering::SeqCst);
    let position = tauri::LogicalPosition::new(x, y);
    let size = tauri::LogicalSize::new(width.max(1.0), height.max(1.0));
    // Reposition/resize an existing embed instead of stacking duplicates.
    if let Some(view) = app.get_webview("dd-embed") {
        view.set_position(position).map_err(|e| e.to_string())?;
        view.set_size(size).map_err(|e| e.to_string())?;
        return Ok(());
    }
    let url = state.container.defectdojo_url().ok_or_else(|| {
        "DefectDojo is not configured -- set the URL in Settings first".to_owned()
    })?;
    let parsed = tauri::Url::parse(&url).map_err(|e| format!("invalid DefectDojo URL: {e}"))?;
    let main = app
        .get_window("main")
        .ok_or_else(|| "main window not available".to_owned())?;
    let view = main
        .add_child(
            tauri::webview::WebviewBuilder::new("dd-embed", tauri::WebviewUrl::External(parsed)),
            position,
            size,
        )
        .map_err(|e| e.to_string())?;
    // The view may have unmounted while we were creating the webview (a close
    // raced ahead and found nothing to close). Honor that and tear it down now,
    // so the embed never strands itself over another view.
    if !state.dd_embed_wanted.load(Ordering::SeqCst) {
        let _ = view.close();
    }
    Ok(())
}

/// Remove the embedded `DefectDojo` webview (when leaving the in-app view).
#[tauri::command]
pub fn defectdojo_embed_close(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<(), String> {
    use std::sync::atomic::Ordering;
    // Mark "not wanted" first so an in-flight create (see `defectdojo_embed`)
    // that completes after this closes itself instead of leaking.
    state.dd_embed_wanted.store(false, Ordering::SeqCst);
    if let Some(view) = app.get_webview("dd-embed") {
        // Move it fully off-screen before closing: `close()` removes it from the
        // manager, but parking it out of view first guarantees it is never left
        // painted over another view even if teardown is delayed for any reason.
        let _ = view.set_position(tauri::LogicalPosition::new(-100_000.0, -100_000.0));
        view.close().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Reload the embedded `DefectDojo` webview.
#[tauri::command]
pub fn defectdojo_embed_reload(app: tauri::AppHandle) -> Result<(), String> {
    if let Some(view) = app.get_webview("dd-embed") {
        view.reload().map_err(|e| e.to_string())?;
    }
    Ok(())
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
    state
        .container
        .run_history(path)
        .await
        .map_err(|error| error.to_string())
}

/// The intra-run coverage/throughput curve for a single run (empty if none was
/// recorded).
#[tauri::command]
pub async fn run_coverage_series(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<Vec<hf_service::CoverageSample>, String> {
    state
        .container
        .run_coverage_series(&run_id)
        .await
        .map_err(|error| error.to_string())
}

/// The harness source a run used, for diffing between harness revisions.
#[tauri::command]
pub async fn run_harness_source(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
) -> Result<String, String> {
    state
        .container
        .run_harness_source(&run_id)
        .await
        .map_err(|error| error.to_string())
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
    state
        .container
        .project_auto_revert_override(std::path::Path::new(&project))
        .await
        .map_err(|error| error.to_string())
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
    state
        .container
        .auto_revert_events(
            path.as_deref().map(std::path::Path::new),
            limit.unwrap_or(200),
        )
        .await
        .map_err(|error| error.to_string())
}

/// The persisted guardrail authorization trail (newest first). `limit` caps the
/// rows; the service prunes older decisions on write. Mirrors the REST
/// `/policy/decisions` route so both transports show the same records.
#[tauri::command]
pub async fn policy_decisions(
    state: tauri::State<'_, crate::state::AppState>,
    limit: Option<usize>,
) -> Result<Vec<hf_service::GuardrailDecisionRecord>, String> {
    state
        .container
        .policy_decisions(limit.unwrap_or(200))
        .await
        .map_err(|error| error.to_string())
}

/// The active project's effective auto-revert policy (override merged over the
/// global default) plus whether an override applies, for the Workbench badge.
#[tauri::command]
pub async fn effective_auto_revert_policy(
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
) -> Result<hf_service::EffectiveAutoRevert, String> {
    state
        .container
        .effective_auto_revert_view(std::path::Path::new(&project))
        .await
        .map_err(|error| error.to_string())
}

/// Every project's auto-revert override, keyed by project root, for badging the
/// projects overview.
#[tauri::command]
pub async fn project_auto_revert_overrides(
    state: tauri::State<'_, crate::state::AppState>,
) -> Result<std::collections::HashMap<String, hf_service::ProjectAutoRevert>, String> {
    state
        .container
        .project_auto_revert_overrides()
        .await
        .map_err(|error| error.to_string())
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
    let bundle = state
        .container
        .export_project_data(path)
        .await
        .map_err(|error| error.to_string())?;
    let json = serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())?;
    let name = path
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("all");
    let default_name = format!("oxfuzz_export_{}.json", sanitize_filename(name));
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
pub fn report_formats(state: tauri::State<'_, crate::state::AppState>) -> Vec<String> {
    state.container.report_formats()
}

/// Compose the report for a target and save it in `format` (md/html/pdf/docx)
/// via a native save dialog with the matching extension. Returns the saved path
/// or `None` if the dialog was cancelled.
#[tauri::command]
pub async fn export_report(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
    format: String,
    language: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let language = match language {
        Some(value) => value
            .parse::<hf_service::ReportLanguage>()
            .map_err(|error| error.to_string())?,
        None => hf_service::ReportLanguage::default(),
    };
    let ext = match format.trim().to_ascii_lowercase().as_str() {
        "md" | "markdown" => "md",
        "html" | "htm" => "html",
        "pdf" => "pdf",
        "docx" | "doc" => "docx",
        other => return Err(format!("unknown report format: {other}")),
    };
    let default_name = format!("oxfuzz_report_{}.{ext}", sanitize_filename(&target));
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
        .export_report(
            std::path::Path::new(&project),
            &target,
            ext,
            &path,
            language,
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(path.to_string_lossy().to_string()))
}

/// Export a self-contained reproduction bundle (harness + crash input +
/// REPRODUCE.md) for a crash from the target's latest run, into a folder chosen
/// via a native folder picker. Returns the bundle path or `None` if cancelled.
#[tauri::command]
pub async fn export_repro(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    project: String,
    target: String,
    engine: String,
    lang: String,
    crash: Option<String>,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;

    let engine = parse_engine(&engine)?;
    let lang = parse_lang(&lang)?;
    let Some(folder) = app
        .dialog()
        .file()
        .set_title("Choose a folder for the reproduction bundle")
        .blocking_pick_folder()
    else {
        return Ok(None);
    };
    let folder = folder
        .into_path()
        .map_err(|e| format!("invalid folder path: {e}"))?;
    let dest = folder.join(format!("oxfuzz_repro_{}", sanitize_filename(&target)));
    let written = state
        .container
        .export_repro_bundle_for_latest(
            std::path::Path::new(&project),
            &target,
            engine,
            lang,
            crash.as_deref(),
            &dest,
        )
        .await
        .map_err(|e| e.to_string())?;
    Ok(Some(written.to_string_lossy().to_string()))
}

/// Return a side-effect-free campaign proposal and its supporting evidence.
#[cfg(feature = "proof-carrying")]
#[tauri::command]
pub fn campaign_advice(
    state: tauri::State<'_, crate::state::AppState>,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let request = serde_json::from_value(request).map_err(|error| error.to_string())?;
    let advice = state
        .container
        .campaign_advice(&request)
        .map_err(|error| error.to_string())?;
    serde_json::to_value(advice).map_err(|error| error.to_string())
}

/// Explain that campaign intelligence was excluded from this build.
#[cfg(not(feature = "proof-carrying"))]
#[tauri::command]
pub fn campaign_advice(
    state: tauri::State<'_, crate::state::AppState>,
    request: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let _ = (state, request);
    Err(proof_carrying_feature_unavailable())
}

/// Assemble final proof-carrying evidence for a terminal campaign.
#[cfg(feature = "proof-carrying")]
#[tauri::command]
pub async fn campaign_evidence(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
    compute_usd_per_hour: f64,
    model_cost_usd: f64,
) -> Result<serde_json::Value, String> {
    let run_id = uuid::Uuid::parse_str(&run_id).map_err(|error| error.to_string())?;
    let evidence = state
        .container
        .campaign_evidence_manifest(
            run_id,
            hf_service::evidence::CampaignEvidencePricing {
                compute_usd_per_hour,
                model_cost_usd,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(evidence).map_err(|error| error.to_string())
}

/// Explain that campaign evidence was excluded from this build.
#[cfg(not(feature = "proof-carrying"))]
#[tauri::command]
pub async fn campaign_evidence(
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
    compute_usd_per_hour: f64,
    model_cost_usd: f64,
) -> Result<serde_json::Value, String> {
    let _ = (state, run_id, compute_usd_per_hour, model_cost_usd);
    Err(proof_carrying_feature_unavailable())
}

/// Export a draft remediation bundle into a directory selected by the user.
#[cfg(feature = "proof-carrying")]
#[tauri::command]
pub async fn export_remediation_draft(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
    finding_id: String,
    patch: String,
    compute_usd_per_hour: f64,
    model_cost_usd: f64,
) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt as _;

    let run_id = uuid::Uuid::parse_str(&run_id).map_err(|error| error.to_string())?;
    let finding_id = uuid::Uuid::parse_str(&finding_id).map_err(|error| error.to_string())?;
    let Some(folder) = app
        .dialog()
        .file()
        .set_title("Choose a folder for the remediation handoff")
        .blocking_pick_folder()
    else {
        return Ok(None);
    };
    let folder = folder
        .into_path()
        .map_err(|error| format!("invalid folder path: {error}"))?;
    let short_id: String = finding_id.simple().to_string().chars().take(12).collect();
    let destination = folder.join(format!("oxfuzz_remediation_{short_id}"));
    state
        .container
        .export_remediation_draft(
            run_id,
            finding_id,
            &patch,
            &destination,
            hf_service::evidence::CampaignEvidencePricing {
                compute_usd_per_hour,
                model_cost_usd,
            },
        )
        .await
        .map_err(|error| error.to_string())?;
    Ok(Some(destination.to_string_lossy().into_owned()))
}

/// Explain that remediation handoffs were excluded from this build.
#[cfg(not(feature = "proof-carrying"))]
#[tauri::command]
pub async fn export_remediation_draft(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::state::AppState>,
    run_id: String,
    finding_id: String,
    patch: String,
    compute_usd_per_hour: f64,
    model_cost_usd: f64,
) -> Result<Option<String>, String> {
    let _ = (
        app,
        state,
        run_id,
        finding_id,
        patch,
        compute_usd_per_hour,
        model_cost_usd,
    );
    Err(proof_carrying_feature_unavailable())
}

#[cfg(not(feature = "proof-carrying"))]
fn proof_carrying_feature_unavailable() -> String {
    "proof-carrying campaign intelligence is not included in this application build".to_owned()
}

/// Export already-composed report `content` (e.g. a saved draft) in `format`
/// via a native save dialog. Returns the saved path or `None` if cancelled.
#[tauri::command]
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

pub use hf_service::config::{AppPaths, ModelInfo, ProviderConfig};

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

/// Load the service-validated fuzzing policy used by subsequent operations.
#[tauri::command]
pub fn get_fuzzing_settings() -> Result<hf_service::config::FuzzingSettings, String> {
    hf_service::config::effective_fuzzing_settings()
}

/// Load the typed automotive policy used by the next sandboxed sidecar call.
#[tauri::command]
pub fn get_automotive_settings() -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        hf_service::config::AutomotiveConfigStore::default()
            .get()
            .and_then(|settings| serde_json::to_value(settings).map_err(|error| error.to_string()))
    }
    #[cfg(not(feature = "automotive-scapy"))]
    Err(automotive_feature_unavailable())
}

/// Validate and persist only the typed automotive policy table.
#[tauri::command]
pub fn set_automotive_settings(settings: serde_json::Value) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let settings = serde_json::from_value(settings).map_err(|error| error.to_string())?;
        hf_service::config::AutomotiveConfigStore::default()
            .set(settings)
            .and_then(|saved| serde_json::to_value(saved).map_err(|error| error.to_string()))
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        drop(settings);
        Err(automotive_feature_unavailable())
    }
}

/// Inspect capabilities of the configured pinned automotive sidecar.
#[tauri::command]
pub async fn automotive_capabilities(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let outcome = state
            .container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::Capabilities,
                approval: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root);
        Err(automotive_feature_unavailable())
    }
}

/// Analyze one operator-selected capture through the sandboxed sidecar.
#[tauri::command]
pub async fn automotive_analyze_capture(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    protocol: String,
    capture_path: PathBuf,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let protocol = serde_json::from_value(serde_json::Value::String(protocol))
            .map_err(|error| error.to_string())?;
        let outcome = state
            .container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::AnalyzeCapture {
                    protocol,
                    capture_path,
                },
                approval: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root, protocol, capture_path);
        Err(automotive_feature_unavailable())
    }
}

/// Generate deterministic automotive mutations through the sandboxed sidecar.
#[tauri::command]
pub async fn automotive_generate_mutations(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    protocol: String,
    source_path: PathBuf,
    deterministic_seed: u64,
    mutation_count: u32,
    media_type: String,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let protocol = serde_json::from_value(serde_json::Value::String(protocol))
            .map_err(|error| error.to_string())?;
        let outcome = state
            .container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::GenerateMutations {
                    protocol,
                    source_path,
                    deterministic_seed,
                    mutation_count,
                    media_type,
                },
                approval: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (
            state,
            project_root,
            protocol,
            source_path,
            deterministic_seed,
            mutation_count,
            media_type,
        );
        Err(automotive_feature_unavailable())
    }
}

/// Build a typed automotive replay plan without contacting an interface.
#[tauri::command]
pub async fn automotive_build_replay_plan(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    protocol: String,
    source_path: PathBuf,
    target_mode: String,
    deterministic_seed: u64,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let protocol = serde_json::from_value(serde_json::Value::String(protocol))
            .map_err(|error| error.to_string())?;
        let target_mode = serde_json::from_value(serde_json::Value::String(target_mode))
            .map_err(|error| error.to_string())?;
        let outcome = state
            .container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::BuildReplayPlan {
                    protocol,
                    source_path,
                    target_mode,
                    deterministic_seed,
                },
                approval: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (
            state,
            project_root,
            protocol,
            source_path,
            target_mode,
            deterministic_seed,
        );
        Err(automotive_feature_unavailable())
    }
}

/// Execute a service-validated replay plan through the sandboxed sidecar.
#[tauri::command]
pub async fn automotive_execute_replay(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    mode: serde_json::Value,
    plan: serde_json::Value,
    approval: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let mode = serde_json::from_value(mode).map_err(|error| error.to_string())?;
        let plan = serde_json::from_value(plan).map_err(|error| error.to_string())?;
        let approval = approval
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| error.to_string())?;
        // Invoking this dedicated workflow command is the operator's approval
        // for the bounded sandbox replay. Physical mode still requires the
        // independent, plan-scoped approval evidence enforced by hf-service.
        let container = state.container.clone().with_guardrails(Guardrails::new(
            GuardrailPolicy::default(),
            std::sync::Arc::new(AutoApproveGate),
        ));
        let outcome = container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::ExecuteReplay { mode, plan },
                approval,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root, mode, plan, approval);
        Err(automotive_feature_unavailable())
    }
}

/// List public automotive operation summaries for one project.
#[tauri::command]
pub async fn list_automotive_operations(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    limit: Option<u32>,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let operations = state
            .container
            .list_automotive_operations(&project_root, limit.unwrap_or(50))
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(operations).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root, limit);
        Err(automotive_feature_unavailable())
    }
}

/// Compose the service-owned automotive campaign report without invoking the
/// sidecar or contacting an interface.
#[tauri::command]
pub async fn generate_automotive_report(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    include_ai: bool,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let report = state
            .container
            .generate_automotive_report(&project_root, include_ai)
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(report).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root, include_ai);
        Err(automotive_feature_unavailable())
    }
}

/// Import and analyze an operator-selected capture file offline (no sidecar):
/// parse frames, compute bus statistics and the per-byte sniffer change map, and
/// optionally decode signals with a supplied DBC database.
#[tauri::command]
pub fn automotive_import_capture(
    state: tauri::State<'_, crate::state::AppState>,
    capture_path: PathBuf,
    format: String,
    dbc_path: Option<PathBuf>,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let import = state
            .container
            .automotive_import_capture(&capture_path, &format, dbc_path.as_deref())
            .map_err(|error| error.to_string())?;
        serde_json::to_value(import).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, capture_path, format, dbc_path);
        Err(automotive_feature_unavailable())
    }
}

/// Compare two operator-selected captures of the same format offline.
#[tauri::command]
pub fn automotive_diff_captures(
    state: tauri::State<'_, crate::state::AppState>,
    first_path: PathBuf,
    second_path: PathBuf,
    format: String,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let diff = state
            .container
            .automotive_diff_captures(&first_path, &second_path, &format)
            .map_err(|error| error.to_string())?;
        serde_json::to_value(diff).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, first_path, second_path, format);
        Err(automotive_feature_unavailable())
    }
}

/// Run a bounded, read-only live capture ("monitor"/sniffer) on an allowlisted
/// virtual CAN interface through the sandboxed sidecar. Retains the evidence.
#[tauri::command]
pub async fn automotive_live_monitor(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    interface: String,
    protocol: String,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let protocol = serde_json::from_value(serde_json::Value::String(protocol))
            .map_err(|error| error.to_string())?;
        let outcome = state
            .container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::LiveMonitor {
                    mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                    protocol,
                },
                approval: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root, interface, protocol);
        Err(automotive_feature_unavailable())
    }
}

/// Run a read-only UDS ECU/service discovery scan on an allowlisted virtual CAN
/// interface through the sandboxed sidecar. Only read-only discovery services
/// are permitted; the service denies any dangerous service before dispatch.
#[tauri::command]
pub async fn automotive_scan_uds(
    state: tauri::State<'_, crate::state::AppState>,
    project_root: PathBuf,
    interface: String,
    request_ids: Vec<u32>,
    services: Vec<u8>,
) -> Result<serde_json::Value, String> {
    #[cfg(feature = "automotive-scapy")]
    {
        let outcome = state
            .container
            .execute_automotive(hf_service::automotive::AutomotiveOperationRequest {
                project_root,
                command: hf_service::automotive::AutomotiveCommand::ScanUds {
                    mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                    protocol: hf_service::automotive::AutomotiveProtocol::Uds,
                    request_ids,
                    services,
                },
                approval: None,
            })
            .await
            .map_err(|error| error.to_string())?;
        serde_json::to_value(outcome).map_err(|error| error.to_string())
    }
    #[cfg(not(feature = "automotive-scapy"))]
    {
        let _ = (state, project_root, interface, request_ids, services);
        Err(automotive_feature_unavailable())
    }
}

#[cfg(not(feature = "automotive-scapy"))]
fn automotive_feature_unavailable() -> String {
    "automotive Scapy support is not included in this application build".to_owned()
}

/// Load browser-compatible `DefectDojo` settings without returning protected values.
#[tauri::command]
pub fn get_defectdojo_config() -> Result<hf_service::config::DefectDojoPublicConfig, String> {
    hf_service::config::IntegrationConfigStore::default().defectdojo()
}

/// Merge and persist a typed `DefectDojo` settings patch.
#[tauri::command]
pub fn patch_defectdojo_config(
    patch: hf_service::config::DefectDojoConfigPatch,
) -> Result<hf_service::config::DefectDojoPublicConfig, String> {
    hf_service::config::IntegrationConfigStore::default().patch_defectdojo(patch)
}

/// Load browser-compatible issue-tracker settings without protected values.
#[tauri::command]
pub fn get_issue_tracker_config() -> Result<hf_service::config::IssueTrackerPublicConfig, String> {
    hf_service::config::IntegrationConfigStore::default().issue_tracker()
}

/// Merge and persist a typed issue-tracker settings patch.
#[tauri::command]
pub fn patch_issue_tracker_config(
    patch: hf_service::config::IssueTrackerConfigPatch,
) -> Result<hf_service::config::IssueTrackerPublicConfig, String> {
    hf_service::config::IntegrationConfigStore::default().patch_issue_tracker(patch)
}

/// Persist the provider pool from the settings form back to `providers.toml`,
/// then reload it into the live container so the change applies immediately --
/// no app restart needed.
#[tauri::command]
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
pub async fn provider_test(provider: ProviderConfig) -> Result<String, String> {
    hf_service::config::test_provider(provider).await
}

/// Read a config section's raw TOML.
#[tauri::command]
pub fn read_config(name: String) -> Result<String, String> {
    hf_service::config::read_config(&name)
}

/// Write a config section's raw TOML to its live file.
#[tauri::command]
pub fn write_config(name: String, content: String) -> Result<(), String> {
    hf_service::config::write_config(&name, &content)
}

/// Parse raw TOML into a JSON value, for driving a structured settings form.
#[tauri::command]
pub fn config_toml_to_value(content: String) -> Result<serde_json::Value, String> {
    hf_service::config::toml_to_json(&content)
}

/// Serialize a settings form's JSON value back into TOML text.
#[tauri::command]
pub fn config_value_to_toml(value: serde_json::Value) -> Result<String, String> {
    hf_service::config::json_to_toml(&value)
}

#[cfg(test)]
mod recovery_command_tests {
    use hf_service::scheduler::CampaignSchedulerError;

    use super::recovery_command_error;

    #[test]
    fn tauri_recovery_error_excludes_sql_diagnostics() {
        let public = recovery_command_error(CampaignSchedulerError::OccurrenceJournal(
            "SQL_PRIVATE_MARKER: SELECT secret_json FROM schedule_occurrences".to_owned(),
        ));

        assert_eq!(
            public,
            "one-time recovery is temporarily unavailable".to_owned()
        );
        assert!(!public.contains("SQL_PRIVATE_MARKER"));
        assert!(!public.contains("SELECT"));
    }
}
