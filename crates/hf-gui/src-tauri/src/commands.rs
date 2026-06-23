//! Tauri commands -- thin wrappers around `hobot_fuzz` domain crates.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct DiscoverArgs {
    pub project: PathBuf,
    pub lang: String,
}

#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct SystemStatus {
    pub docker: bool,
    pub clang: bool,
    pub afl: bool,
    pub honggfuzz: bool,
}

#[tauri::command]
pub async fn discover(args: DiscoverArgs) -> Result<serde_json::Value, String> {
    let lang = match args.lang.to_lowercase().as_str() {
        "cpp" => hf_core::target::TargetLanguage::Cpp,
        _ => hf_core::target::TargetLanguage::C,
    };
    let inv = hf_discovery::discover(&args.project, lang)
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

#[tauri::command]
pub async fn corpus_list(_project: String, _target: String) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let corpus_dir = workspace.join("corpus");
    let corpus = hf_corpus::list(&corpus_dir).map_err(|e| e.to_string())?;
    serde_json::to_value(&corpus.entries).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn corpus_seed(_project: String, _target: String) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let corpus_dir = workspace.join("corpus");
    let seeds = vec![
        (b"{}".to_vec(), "seed_empty".to_owned()),
        (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
    ];
    let corpus = hf_corpus::seed(Uuid::new_v4(), &corpus_dir, seeds)
        .await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"seeded": corpus.entries.len()}))
}

#[tauri::command]
pub async fn corpus_grow(_project: String, _target: String) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let corpus_dir = workspace.join("corpus");
    let out_dir = workspace.join("out");
    let corpus = hf_corpus::grow(&corpus_dir, &out_dir).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"entries": corpus.entries.len()}))
}

#[tauri::command]
pub async fn corpus_prune(_project: String, _target: String) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let corpus_dir = workspace.join("corpus");
    let corpus = hf_corpus::list(&corpus_dir).map_err(|e| e.to_string())?;
    let pruned = hf_corpus::prune(corpus).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({"entries": pruned.entries.len()}))
}

#[tauri::command]
pub async fn triage(project: String, target: String) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let out_dir = workspace.join("out");
    let inv = hf_discovery::discover(
        std::path::Path::new(&project),
        hf_core::target::TargetLanguage::C,
    )
    .await
    .map_err(|e| e.to_string())?;
    let target_id = inv
        .candidates
        .iter()
        .find(|c| c.symbol == target)
        .map(|c| c.id)
        .unwrap_or_default();
    let run_id = Uuid::new_v4();
    let crashes = hf_crash::ingest(&out_dir, run_id, target_id).map_err(|e| e.to_string())?;
    let deduped = hf_crash::dedup(crashes);
    serde_json::to_value(&deduped).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn system_status() -> SystemStatus {
    SystemStatus {
        docker: which("docker"),
        clang: which("clang"),
        afl: which("afl-fuzz"),
        honggfuzz: which("honggfuzz"),
    }
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn show_window(app: tauri::AppHandle) {
    use tauri::Manager;
    if let Some(win) = app.get_webview_window("main") {
        win.show().ok();
    }
}

fn which(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}
