//! Tauri commands -- thin wrappers around `hf-service::ServiceContainer`.
//!
//! Per AGENTS.md 2.9: no domain logic here. All business logic lives in
//! `hf-service`; these commands handle I/O, Tauri event emission, and
//! argument marshalling only.

use std::path::PathBuf;

use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::target::TargetLanguage;
use serde::{Deserialize, Serialize};
use std::fmt::Write;
use tauri::Manager;

use crate::state::config_dir;

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

fn parse_lang(s: &str) -> TargetLanguage {
    match s.to_ascii_lowercase().as_str() {
        "cpp" | "c++" => TargetLanguage::Cpp,
        "rust" | "rs" => TargetLanguage::Rust,
        "go" => TargetLanguage::Go,
        "python" | "py" => TargetLanguage::Python,
        _ => TargetLanguage::C,
    }
}

fn parse_engine(s: &str) -> EngineKind {
    match s.to_ascii_lowercase().as_str() {
        "afl++" | "aflplusplus" => EngineKind::AflPlusPlus,
        "honggfuzz" | "hfuzz" => EngineKind::Honggfuzz,
        "clusterfuzzlite" | "cfl" => EngineKind::ClusterFuzzLite,
        "syzkaller" | "syz" => EngineKind::Syzkaller,
        _ => EngineKind::LibFuzzer,
    }
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
    let lang = parse_lang(&lang);
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
    let engine_kind = parse_engine(&engine);
    let lang = lang.as_deref().map_or(TargetLanguage::C, parse_lang);
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
    let engine_kind = parse_engine(&engine);
    let lang = lang.as_deref().map_or(TargetLanguage::C, parse_lang);
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

    let agent = hf_agent::Agent::new(state.container.clone(), project);
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

    let engine_kind = parse_engine(&engine);
    let emit = |ty: &str, data: serde_json::Value| {
        let _ = app.emit(
            "run:progress",
            serde_json::json!({ "type": ty, "data": data }),
        );
    };

    // syzkaller is a kernel fuzzer: it drives a VM against a coverage-enabled
    // kernel via `syz-manager`, not a per-target harness binary. Surface what
    // a campaign needs instead of trying to run a harness.
    if engine == "syzkaller" {
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
        let kernel = kernel_image.expect("kernel_image present");
        let disk = disk_image.expect("disk_image present");
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

/// Known config sections. Whitelisted to prevent path traversal: only these
/// names map to a `config/<name>.toml` file.
const CONFIG_SECTIONS: &[&str] = &[
    "hobot-fuzz",
    "providers",
    "engines",
    "runtime",
    "guardrails",
    "storage",
    "session",
    "tools",
];

/// One editable config section, as surfaced to the GUI.
#[derive(Serialize)]
pub struct ConfigSection {
    pub name: String,
    pub exists: bool,
}

/// Validate that `name` is a known section before touching the filesystem.
fn validated_section(name: &str) -> Result<&'static str, String> {
    CONFIG_SECTIONS
        .iter()
        .copied()
        .find(|s| *s == name)
        .ok_or_else(|| format!("unknown config section: {name}"))
}

/// Resolved on-disk locations surfaced in the General settings page.
#[derive(Serialize)]
pub struct AppPaths {
    pub config_dir: String,
    pub data_dir: String,
}

#[tauri::command]
#[must_use]
pub fn app_paths() -> AppPaths {
    let data = hf_service::repo_root().map_or_else(
        || {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("data")
        },
        |r| r.join("data"),
    );
    AppPaths {
        config_dir: config_dir().display().to_string(),
        data_dir: data.display().to_string(),
    }
}

/// A model offered by a configured provider in the pool.
#[derive(Serialize)]
pub struct ModelInfo {
    pub id: String,
    pub provider_type: String,
    pub model: String,
}

/// List the models from the configured provider pool (`providers.toml`,
/// falling back to the `.example.toml`). Drives the chat model selector.
#[tauri::command]
#[must_use]
pub fn list_models() -> Vec<ModelInfo> {
    let raw = read_config("providers".to_string()).unwrap_or_default();
    let parsed: toml::Value =
        toml::from_str(&raw).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
    let mut out = Vec::new();
    if let Some(arr) = parsed.get("providers").and_then(toml::Value::as_array) {
        for p in arr {
            let model = p
                .get("model")
                .and_then(toml::Value::as_str)
                .unwrap_or_default();
            if model.is_empty() {
                continue;
            }
            out.push(ModelInfo {
                id: p
                    .get("id")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                provider_type: p
                    .get("provider_type")
                    .and_then(toml::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                model: model.to_string(),
            });
        }
    }
    out
}

/// One provider as surfaced to / received from the Providers settings form.
#[derive(Serialize, Deserialize, Clone)]
pub struct ProviderConfigGui {
    pub id: String,
    #[serde(default)]
    pub provider_type: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub api_key_env: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub http_protocol: String,
    #[serde(default)]
    pub tool_calling_mode: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_concurrency")]
    pub max_concurrency: u32,
    #[serde(default = "default_context_window")]
    pub context_window: u64,
}

const fn default_true() -> bool {
    true
}
const fn default_concurrency() -> u32 {
    3
}
const fn default_context_window() -> u64 {
    128_000
}

/// Quote/escape a value as a TOML basic string.
fn toml_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Load the provider pool as structured data for the settings form.
#[tauri::command]
#[must_use]
pub fn get_providers() -> Vec<ProviderConfigGui> {
    let raw = read_config("providers".to_string()).unwrap_or_default();
    let parsed: toml::Value =
        toml::from_str(&raw).unwrap_or_else(|_| toml::Value::Table(toml::map::Map::new()));
    let mut out = Vec::new();
    let Some(arr) = parsed.get("providers").and_then(toml::Value::as_array) else {
        return out;
    };
    for p in arr {
        let get = |k: &str| {
            p.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let provider_type = {
            let t = get("provider_type");
            if t.is_empty() {
                "openai-compat".to_string()
            } else {
                t
            }
        };
        let http_protocol = {
            let h = get("http_protocol");
            if h.is_empty() {
                "http1".to_string()
            } else {
                h
            }
        };
        let tags = p
            .get("tags")
            .and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        out.push(ProviderConfigGui {
            id: get("id"),
            provider_type,
            model: get("model"),
            base_url: get("base_url"),
            api_key: get("api_key"),
            api_key_env: get("api_key_env"),
            enabled: p
                .get("enabled")
                .and_then(toml::Value::as_bool)
                .unwrap_or(true),
            http_protocol,
            tool_calling_mode: get("tool_calling_mode"),
            tags,
            max_concurrency: u32::try_from(
                p.get("max_concurrency")
                    .and_then(toml::Value::as_integer)
                    .unwrap_or(3),
            )
            .unwrap_or(3),
            context_window: u64::try_from(
                p.get("context_window")
                    .and_then(toml::Value::as_integer)
                    .unwrap_or(128_000),
            )
            .unwrap_or(128_000),
        });
    }
    out
}

/// Persist the provider pool from the settings form back to `providers.toml`.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn set_providers(providers: Vec<ProviderConfigGui>) -> Result<(), String> {
    let existing = read_config("providers".to_string()).unwrap_or_default();
    let preamble = existing.find("[[providers]]").map_or_else(
        || {
            "# hobot_fuzz -- LLM Provider Pool Configuration\n\
             default_freeze_duration_secs = 60\n\
             max_freeze_duration_secs = 3600\n\
             health_check_interval_secs = 30\n\n"
                .to_string()
        },
        |idx| existing[..idx].to_string(),
    );

    let mut body = String::new();
    for p in &providers {
        body.push_str("[[providers]]\n");
        let _ = writeln!(body, "id = {}", toml_string(&p.id));
        let _ = writeln!(body, "provider_type = {}", toml_string(&p.provider_type));
        let _ = writeln!(body, "model = {}", toml_string(&p.model));
        if !p.base_url.is_empty() {
            let _ = writeln!(body, "base_url = {}", toml_string(&p.base_url));
        }
        if !p.api_key.is_empty() {
            let _ = writeln!(body, "api_key = {}", toml_string(&p.api_key));
        }
        if !p.api_key_env.is_empty() {
            let _ = writeln!(body, "api_key_env = {}", toml_string(&p.api_key_env));
        }
        let _ = writeln!(body, "enabled = {}", p.enabled);
        if !p.http_protocol.is_empty() {
            let _ = writeln!(body, "http_protocol = {}", toml_string(&p.http_protocol));
        }
        if !p.tool_calling_mode.is_empty() {
            let _ = writeln!(
                body,
                "tool_calling_mode = {}",
                toml_string(&p.tool_calling_mode)
            );
        }
        let tags = p
            .tags
            .iter()
            .map(|t| toml_string(t))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(body, "tags = [{tags}]");
        let _ = writeln!(body, "max_concurrency = {}", p.max_concurrency);
        let _ = writeln!(body, "context_window = {}\n", p.context_window);
    }

    let content = format!("{preamble}{body}");
    toml::from_str::<toml::Value>(&content).map_err(|e| format!("invalid TOML: {e}"))?;
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("providers.toml"), content).map_err(|e| e.to_string())
}

/// List the editable config sections and whether each has a live file.
#[tauri::command]
#[must_use]
pub fn list_configs() -> Vec<ConfigSection> {
    let dir = config_dir();
    CONFIG_SECTIONS
        .iter()
        .map(|name| ConfigSection {
            name: (*name).to_string(),
            exists: dir.join(format!("{name}.toml")).is_file(),
        })
        .collect()
}

/// Read a config section's raw TOML.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn read_config(name: String) -> Result<String, String> {
    let section = validated_section(&name)?;
    let dir = config_dir();
    let live = dir.join(format!("{section}.toml"));
    let example = dir.join(format!("{section}.example.toml"));
    if live.is_file() {
        std::fs::read_to_string(&live).map_err(|e| e.to_string())
    } else if example.is_file() {
        std::fs::read_to_string(&example).map_err(|e| e.to_string())
    } else {
        Ok(String::new())
    }
}

/// Write a config section's raw TOML to its live file.
#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn write_config(name: String, content: String) -> Result<(), String> {
    let section = validated_section(&name)?;
    toml::from_str::<toml::Value>(&content).map_err(|e| format!("invalid TOML: {e}"))?;
    let dir = config_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::write(dir.join(format!("{section}.toml")), content).map_err(|e| e.to_string())
}
