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

/// Clone the service container, always preferring the current provider config
/// from disk. This makes Settings -> Providers edits (key, base URL, model)
/// take effect on the next chat without restarting the app, even if the startup
/// bootstrap had cached a different (or broken) provider.
fn container_with_provider(state: &crate::state::AppState) -> hf_service::ServiceContainer {
    let container = state.container.clone();
    if let Some(pool) = hf_service::provider_pool_from_config() {
        return container.with_provider_pool(pool);
    }
    container
}

/// Send a single-turn chat message to the LLM provider pool (no tools).
#[tauri::command]
pub async fn chat_send(
    state: tauri::State<'_, crate::state::AppState>,
    message: String,
) -> Result<String, String> {
    container_with_provider(&state)
        .chat_send(&message)
        .await
        .map_err(|e| e.to_string())
}

/// A prior chat message passed from the frontend as agent history.
#[derive(Debug, Deserialize)]
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
                })
            })
            .collect(),
    })
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

/// One bundled skill's metadata from `skills/<name>/skill.toml`.
#[derive(Debug, Serialize)]
pub struct SkillInfo {
    pub name: String,
    pub description: String,
    pub version: String,
    pub domain: Vec<String>,
}

/// List the bundled, file-backed skills from the repo's `skills/` directory.
#[tauri::command]
pub fn list_skills() -> Vec<SkillInfo> {
    let skills_dir = hf_service::repo_root()
        .map_or_else(|| std::path::PathBuf::from("skills"), |r| r.join("skills"));
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&skills_dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let toml_path = entry.path().join("skill.toml");
        let Ok(text) = std::fs::read_to_string(&toml_path) else {
            continue;
        };
        let Ok(parsed) = toml::from_str::<toml::Value>(&text) else {
            continue;
        };
        let skill = parsed.get("skill");
        let get = |k: &str| {
            skill
                .and_then(|s| s.get(k))
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let domain = skill
            .and_then(|s| s.get("classification"))
            .and_then(|c| c.get("domain"))
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        let name = get("name");
        if name.is_empty() {
            continue;
        }
        out.push(SkillInfo {
            name,
            description: get("description"),
            version: get("version"),
            domain,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
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

// -- Skills CRUD ------------------------------------------------------------

/// A skill's full content for editing: metadata + the root.md markdown body.
#[derive(Debug, Default, Serialize)]
pub struct SkillDetail {
    pub name: String,
    pub description: String,
    pub version: String,
    pub domain: Vec<String>,
    pub content: String,
}

/// Read a skill's metadata + root.md content for editing.
#[tauri::command]
pub async fn read_skill(name: String) -> Result<SkillDetail, String> {
    let name = safe_name(&name)?;
    let dir = skills_dir().join(&name);
    let text = std::fs::read_to_string(dir.join("skill.toml")).map_err(|e| e.to_string())?;
    let parsed: toml::Value = toml::from_str(&text).map_err(|e| e.to_string())?;
    let skill = parsed.get("skill");
    let get = |k: &str| {
        skill
            .and_then(|s| s.get(k))
            .and_then(toml::Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let domain = skill
        .and_then(|s| s.get("classification"))
        .and_then(|c| c.get("domain"))
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let root_rel = skill
        .and_then(|s| s.get("root"))
        .and_then(|r| r.get("path"))
        .and_then(toml::Value::as_str)
        .unwrap_or("root.md");
    let content = std::fs::read_to_string(dir.join(root_rel)).unwrap_or_default();
    Ok(SkillDetail {
        name,
        description: get("description"),
        version: get("version"),
        domain,
        content,
    })
}

/// Create or update a skill: writes `skills/<name>/skill.toml` + `root.md`.
#[tauri::command]
pub async fn save_skill(
    name: String,
    description: String,
    version: String,
    domain: Vec<String>,
    content: String,
) -> Result<(), String> {
    let name = safe_name(&name)?;
    let dir = skills_dir().join(&name);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let version = if version.trim().is_empty() {
        "0.1.0".to_owned()
    } else {
        version
    };
    let doc = SkillFileOut {
        skill: SkillInnerOut {
            name: name.clone(),
            version,
            description,
            author: "hobot_fuzz".to_owned(),
            source_format: "markdown".to_owned(),
            classification: SkillClassOut {
                kind: "llm_reasoning".to_owned(),
                domain,
                atomic: true,
            },
            root: SkillRootOut {
                path: "root.md".to_owned(),
            },
        },
    };
    let toml_str = toml::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("skill.toml"), toml_str).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("root.md"), content).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Serialize)]
struct SkillFileOut {
    skill: SkillInnerOut,
}
#[derive(Serialize)]
struct SkillInnerOut {
    name: String,
    version: String,
    description: String,
    author: String,
    source_format: String,
    classification: SkillClassOut,
    root: SkillRootOut,
}
#[derive(Serialize)]
struct SkillClassOut {
    #[serde(rename = "type")]
    kind: String,
    domain: Vec<String>,
    atomic: bool,
}
#[derive(Serialize)]
struct SkillRootOut {
    path: String,
}

/// Delete a skill directory.
#[tauri::command]
pub async fn delete_skill(name: String) -> Result<(), String> {
    let name = safe_name(&name)?;
    let dir = skills_dir().join(&name);
    if dir.is_dir() {
        std::fs::remove_dir_all(&dir).map_err(|e| e.to_string())?;
    }
    Ok(())
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
    use hf_core::session::SessionStore;
    let Some(sessions) = state.container.session_store() else {
        return Ok(None);
    };
    let id = sessions.create(None).await.map_err(|e| e.to_string())?;
    Ok(Some(id.0.to_string()))
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
    use hf_core::session::SessionStore;
    let project = project.filter(|p| !p.is_empty()).map(PathBuf::from);

    // Resolve a persistent session if one was requested and available.
    let session = session_id
        .filter(|s| !s.is_empty())
        .and_then(|s| uuid::Uuid::parse_str(&s).ok())
        .map(hf_core::types::Id)
        .zip(state.container.session_store());

    let history: Vec<hf_core::types::Message> = if let Some((id, sessions)) = session {
        sessions.history(id).await.map_err(|e| e.to_string())?
    } else {
        history
            .unwrap_or_default()
            .into_iter()
            .map(|t| hf_core::types::Message {
                role: parse_role(&t.role),
                content: t.content,
            })
            .collect()
    };

    // Run with an interactive guardrail gate: high-risk tool calls (e.g. run a
    // fuzzer) prompt the user via `chat:permission_request` before executing.
    let gate = std::sync::Arc::new(GuiApprovalGate {
        app: app.clone(),
        pending: state.pending_approvals.clone(),
    });
    let guardrails =
        hf_guardrails::Guardrails::new(hf_guardrails::GuardrailPolicy::default(), gate);
    let container = container_with_provider(&state).with_guardrails(guardrails);

    // Drive the chat with the chosen agent (default: orchestrator). Its
    // definition sets the system prompt, the callable tools, model routing, and
    // the iteration budget.
    let registry = hf_agent::AgentRegistry::with_user_dir(agents_dir());
    let definition = agent_id
        .filter(|s| !s.is_empty())
        .and_then(|id| registry.get(&id).cloned())
        .unwrap_or_else(|| registry.default_agent());
    let agent = hf_agent::Agent::with_definition(container, project, definition);
    let sink = TauriEventSink { app };
    let answer = agent
        .run_turn(history, &message, &sink)
        .await
        .map_err(|e| e.to_string())?;

    // Persist the turn (user + assistant) when a session is active.
    if let Some((id, sessions)) = session {
        let _ = sessions
            .append(
                id,
                hf_core::types::Message {
                    role: hf_core::types::Role::User,
                    content: message,
                },
            )
            .await;
        let _ = sessions
            .append(
                id,
                hf_core::types::Message {
                    role: hf_core::types::Role::Assistant,
                    content: answer.clone(),
                },
            )
            .await;
    }

    Ok(answer)
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

    let result = state
        .container
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

/// Persist the provider pool from the settings form back to `providers.toml`.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_providers(providers: Vec<ProviderConfig>) -> Result<(), String> {
    hf_service::config::set_providers(&providers)
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
