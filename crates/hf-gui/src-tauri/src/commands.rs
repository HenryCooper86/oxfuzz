//! Tauri commands -- thin wrappers around `hobot_fuzz` domain crates.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helper functions (must come before items to satisfy clippy)
// ---------------------------------------------------------------------------

fn which(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn generate_includes(candidate: &hf_core::target::TargetCandidate) -> String {
    let file = &candidate.location.file;
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    format!("#include \"{stem}.h\"")
}

fn copy_project_sources(project: &std::path::Path, workspace: &std::path::Path) {
    let exts = ["c", "h", "cc", "cpp", "cxx", "hpp"];
    if let Ok(entries) = std::fs::read_dir(project) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if exts.contains(&ext) {
                        let _ = std::fs::copy(&path, workspace.join(entry.file_name()));
                    }
                }
            }
        }
    }
}

fn list_c_sources(workspace: &std::path::Path) -> String {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(workspace) {
        for entry in entries.flatten() {
            if let Some(ext) = entry.path().extension().and_then(|s| s.to_str()) {
                if ext == "c" && entry.file_name() != "harness.c" {
                    files.push(format!("/work/{}", entry.file_name().to_string_lossy()));
                }
            }
        }
    }
    files.join(" ")
}

fn generate_target_seeds(target: &str) -> Vec<(Vec<u8>, String)> {
    let lower = target.to_ascii_lowercase();
    if lower.contains("json") || lower.contains("parse") {
        vec![
            (b"{}".to_vec(), "seed_empty_obj".to_owned()),
            (b"[]".to_vec(), "seed_empty_arr".to_owned()),
            (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
            (b"\"hello\"".to_vec(), "seed_string".to_owned()),
            (b"true".to_vec(), "seed_bool".to_owned()),
            (b"null".to_vec(), "seed_null".to_owned()),
            (b"42".to_vec(), "seed_number".to_owned()),
            (b"{\"key\":\"value\"}".to_vec(), "seed_object".to_owned()),
            (b"{\"nested\":{\"a\":1}}".to_vec(), "seed_nested".to_owned()),
            (b"\"".to_vec(), "seed_truncated_string".to_owned()),
            (b"[".to_vec(), "seed_truncated_array".to_owned()),
            (b"{".to_vec(), "seed_truncated_object".to_owned()),
        ]
    } else if lower.contains("xml") {
        vec![
            (b"<root/>".to_vec(), "seed_empty_xml".to_owned()),
            (b"<root>text</root>".to_vec(), "seed_simple_xml".to_owned()),
            (b"<a><b/></a>".to_vec(), "seed_nested_xml".to_owned()),
        ]
    } else if lower.contains("csv") {
        vec![
            (b"a,b,c\n1,2,3\n".to_vec(), "seed_simple_csv".to_owned()),
            (
                b"\"quoted\",\"fields\"\n".to_vec(),
                "seed_quoted_csv".to_owned(),
            ),
        ]
    } else {
        vec![
            (b"\x00".to_vec(), "seed_null_byte".to_owned()),
            (b"\xff".to_vec(), "seed_high_byte".to_owned()),
            (b"AAAA".to_vec(), "seed_repeated".to_owned()),
            ("".as_bytes().to_vec(), "seed_empty".to_owned()),
            (b"test".to_vec(), "seed_ascii".to_owned()),
        ]
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

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

#[derive(Debug, Deserialize)]
pub struct HarnessDraftArgs {
    pub project: PathBuf,
    pub target: String,
    pub engine: String,
}

#[derive(Debug, Deserialize)]
pub struct CompileHarnessArgs {
    pub source: String,
    pub project: PathBuf,
    pub engine: String,
    pub target: String,
}

#[derive(Debug, Deserialize)]
pub struct GenerateSeedsArgs {
    pub target: String,
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

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
pub async fn harness_draft(args: HarnessDraftArgs) -> Result<serde_json::Value, String> {
    let lang = hf_core::target::TargetLanguage::C;
    let inv = hf_discovery::discover(&args.project, lang)
        .await
        .map_err(|e| e.to_string())?;
    let candidate = inv
        .candidates
        .iter()
        .find(|c| c.symbol == args.target)
        .ok_or_else(|| format!("target '{}' not found", args.target))?
        .clone();
    let engine_kind = match args.engine.as_str() {
        "afl++" => hf_core::engine::EngineKind::AflPlusPlus,
        "honggfuzz" => hf_core::engine::EngineKind::Honggfuzz,
        "clusterfuzzlite" => hf_core::engine::EngineKind::ClusterFuzzLite,
        _ => hf_core::engine::EngineKind::LibFuzzer,
    };
    let build_cmd = hf_harness::build_command(
        engine_kind,
        candidate.language,
        &format!("fuzz_{}", args.target),
    );
    let source = format!(
        r"// Auto-generated harness for {symbol}
// Engine: {engine}
// Target: {file}:{line}
#include <stdint.h>
#include <stddef.h>
{includes}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // TODO: Map fuzzer input to target function call.
    // The target signature is:
    //   {sig}
    // Adjust the call below to match the target's parameters.
    {symbol}((const char *)data, size);
    return 0;
}}
",
        symbol = candidate.symbol,
        engine = args.engine,
        file = candidate.location.file.display(),
        line = candidate.location.line,
        includes = generate_includes(&candidate),
        sig = candidate.signature.as_deref().unwrap_or("(unknown)"),
    );
    Ok(serde_json::json!({
        "source": source,
        "target": candidate.symbol,
        "engine": args.engine,
        "build_cmd": {
            "compiler": build_cmd.compiler,
            "args": build_cmd.args,
        },
        "status": "Draft",
    }))
}

#[tauri::command]
pub async fn harness_compile(args: CompileHarnessArgs) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    std::fs::create_dir_all(&workspace).map_err(|e| e.to_string())?;
    let harness_path = workspace.join("harness.c");
    std::fs::write(&harness_path, &args.source).map_err(|e| e.to_string())?;
    copy_project_sources(&args.project, &workspace);
    let engine_kind = match args.engine.as_str() {
        "afl++" => hf_core::engine::EngineKind::AflPlusPlus,
        "honggfuzz" => hf_core::engine::EngineKind::Honggfuzz,
        "clusterfuzzlite" => hf_core::engine::EngineKind::ClusterFuzzLite,
        _ => hf_core::engine::EngineKind::LibFuzzer,
    };
    let build_cmd = hf_harness::build_command(
        engine_kind,
        hf_core::target::TargetLanguage::C,
        &format!("fuzz_{}", args.target),
    );
    let docker_ok = which("docker");
    if !docker_ok {
        return Ok(serde_json::json!({
            "status": "Draft",
            "message": "Docker not available -- harness source ready but not compiled.",
            "compile_cmd": format!("{} {} -I{} harness.c {} -o fuzz_{}", build_cmd.compiler, build_cmd.args.join(" "), workspace.display(), list_c_sources(&workspace), args.target),
        }));
    }
    let compile_script = format!(
        "{compiler} {cflags} -I/work /work/harness.c {sources} -o /tmp/fuzz_{target} && cp /tmp/fuzz_{target} /work/fuzz_{target} && chmod +x /work/fuzz_{target}",
        compiler = build_cmd.compiler,
        cflags = build_cmd.args.join(" "),
        sources = list_c_sources(&workspace),
        target = args.target,
    );
    let output = std::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--memory=4096m",
            "--cpus=2",
            "-v",
            &format!("{}:/work", workspace.display()),
            "-w",
            "/work",
            "hobot/fuzz-sandbox:latest",
            "bash",
            "-c",
            &compile_script,
        ])
        .output()
        .map_err(|e| format!("docker run: {e}"))?;
    if output.status.code() == Some(0) {
        Ok(serde_json::json!({
            "status": "Compiled",
            "message": "Harness compiled successfully in sandbox.",
        }))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Ok(serde_json::json!({
            "status": "Failed",
            "message": format!("Compile failed: {}", stderr.chars().take(500).collect::<String>()),
        }))
    }
}

#[tauri::command]
pub async fn generate_seeds(args: GenerateSeedsArgs) -> Result<serde_json::Value, String> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let corpus_dir = workspace.join("corpus");
    std::fs::create_dir_all(&corpus_dir).map_err(|e| e.to_string())?;
    let seeds = generate_target_seeds(&args.target);
    let mut entries = Vec::new();
    for (data, name) in seeds {
        let path = corpus_dir.join(&name);
        std::fs::write(&path, &data).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let sha = format!("{:x}", hasher.finalize());
        entries.push(serde_json::json!({
            "name": name,
            "size": data.len(),
            "sha256": sha,
        }));
    }
    Ok(serde_json::json!({"seeds": entries}))
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
