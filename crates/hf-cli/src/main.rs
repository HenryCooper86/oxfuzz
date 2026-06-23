//! hobot-fuzz CLI entry point.

mod tui;

use clap::{Parser, Subcommand};
use hf_core::engine::EngineKind;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::TargetLanguage;
use hf_provider::{OpenAiCompatProvider, ProviderConfig};
use std::path::PathBuf;

/// AI fuzzing agent.
#[derive(Parser)]
#[command(name = "hobot-fuzz", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize configuration.
    Init,
    /// Discover fuzzing targets in a project.
    Discover {
        /// Project root path.
        project: PathBuf,
        /// Target language (c, cpp, rust, go, python).
        #[arg(long)]
        lang: String,
        /// Enable LLM-assisted ranking (requires `HF_PROVIDER_API_KEY`).
        #[arg(long)]
        rank: bool,
    },
    /// Generate a harness for a target.
    Harness {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine (afl++, honggfuzz, libfuzzer, clusterfuzzlite).
        #[arg(long)]
        engine: String,
        /// Skip compile and smoke fuzz (draft only).
        #[arg(long)]
        draft_only: bool,
    },
    /// Run a fuzz campaign.
    Run {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine.
        #[arg(long)]
        engine: String,
        /// Duration (e.g. 60m).
        #[arg(long)]
        duration: Option<String>,
    },
    /// Triage crashes from a run.
    Triage {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
    },
    /// Manage the fuzzing corpus for a target.
    Corpus {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Operation: seed, grow, prune, list.
        #[arg(long)]
        op: String,
    },
    /// Start the web server (REST API).
    Serve {
        /// Port to listen on.
        #[arg(long, default_value = "8081")]
        port: u16,
    },
    /// Launch the TUI (terminal user interface).
    Tui {
        /// Project root path.
        project: PathBuf,
    },
}

fn parse_lang(s: &str) -> Result<TargetLanguage, anyhow::Error> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "c" => TargetLanguage::C,
        "cpp" | "c++" => TargetLanguage::Cpp,
        "rust" | "rs" => TargetLanguage::Rust,
        "go" => TargetLanguage::Go,
        "python" | "py" => TargetLanguage::Python,
        other => anyhow::bail!("unsupported language: {other}"),
    })
}

fn parse_engine(s: &str) -> Result<EngineKind, anyhow::Error> {
    Ok(match s.to_ascii_lowercase().as_str() {
        "afl++" | "aflplusplus" => EngineKind::AflPlusPlus,
        "honggfuzz" | "hfuzz" => EngineKind::Honggfuzz,
        "libfuzzer" | "libfuzz" => EngineKind::LibFuzzer,
        "clusterfuzzlite" | "cfl" => EngineKind::ClusterFuzzLite,
        other => anyhow::bail!("unsupported engine: {other}"),
    })
}

/// Build a provider from env vars, if configured.
fn provider_from_env() -> Option<OpenAiCompatProvider> {
    let api_key = std::env::var("HF_PROVIDER_API_KEY").ok()?;
    let model = std::env::var("HF_PROVIDER_MODEL").unwrap_or_else(|_| "gpt-4o".to_owned());
    let base_url = std::env::var("HF_PROVIDER_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_owned());
    let cfg = ProviderConfig {
        id: "cli".to_owned(),
        model,
        api_key,
        base_url,
        tags: vec![
            "general".to_owned(),
            "reasoning".to_owned(),
            "code".to_owned(),
        ],
        max_concurrency: 1,
        context_window: 128_000,
    };
    Some(OpenAiCompatProvider::new(cfg))
}

/// Parse a human duration string like "60m", "2h", "30s".
fn parse_duration(s: &str) -> Result<u64, anyhow::Error> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix("s") {
        return Ok(n.parse()?);
    }
    if let Some(n) = s.strip_suffix("m") {
        return Ok(n.parse::<u64>()? * 60);
    }
    if let Some(n) = s.strip_suffix("h") {
        return Ok(n.parse::<u64>()? * 3600);
    }
    // Fallback: parse as raw seconds.
    Ok(s.parse()?)
}

/// Build the sandbox runtime. Uses Docker if available, else falls back to
/// the stub runtime (which returns errors for all operations).
fn build_runtime(workspace: &std::path::Path) -> Box<dyn hf_core::runtime::RuntimeAdapter> {
    let use_docker = std::env::var("HF_USE_DOCKER").map_or(true, |v| v != "0" && v != "false");
    if use_docker && which_docker() {
        let cfg = hf_runtime::RuntimeConfig::default();
        Box::new(hf_runtime::docker::DockerRuntime::new(cfg, workspace))
    } else {
        eprintln!("warning: Docker not available; using StubRuntime (commands will fail)");
        Box::new(hf_runtime::StubRuntime)
    }
}

fn which_docker() -> bool {
    std::process::Command::new("docker")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Copy C/C++ source and header files from a project into the workspace
/// so the sandbox can compile the harness + target together.
fn copy_project_sources(project: &std::path::Path, workspace: &std::path::Path) {
    let exts = ["c", "h", "cc", "cpp", "cxx", "hpp"];
    if let Ok(entries) = std::fs::read_dir(project) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if exts.contains(&ext) {
                    let dest = workspace.join(entry.file_name());
                    let _ = std::fs::copy(&path, &dest);
                }
            }
        }
    }
}

/// Handle the `run` subcommand: discover -> draft harness -> compile -> run engine.
async fn run_command(
    project: &std::path::Path,
    target: &str,
    engine: &str,
    duration: Option<&str>,
) -> Result<(), anyhow::Error> {
    let engine_kind = parse_engine(engine)?;
    let duration_secs = duration.map(parse_duration).transpose()?.unwrap_or(3600);
    let inv = hf_discovery::discover(project, TargetLanguage::C).await?;
    let candidate = inv
        .candidates
        .iter()
        .find(|c| c.symbol == target)
        .ok_or_else(|| anyhow::anyhow!("target '{target}' not found in project"))?
        .clone();
    let provider = provider_from_env().ok_or_else(|| {
        anyhow::anyhow!("no LLM provider configured; set HF_PROVIDER_API_KEY to generate a harness")
    })?;
    let draft = hf_harness::draft(&candidate, engine_kind, Box::new(provider)).await?;
    let build_cmd =
        hf_harness::build_command(engine_kind, candidate.language, &format!("fuzz_{target}"));
    let harness = Harness {
        id: uuid::Uuid::new_v4(),
        target_id: candidate.id,
        engine: engine_kind,
        source: draft.source,
        language: candidate.language,
        build_cmd,
        sanitizer: hf_core::target::Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    };
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    std::fs::create_dir_all(&workspace)?;
    let corpus_dir = workspace.join("corpus");
    let out_dir = workspace.join("out");
    std::fs::create_dir_all(&corpus_dir)?;
    std::fs::create_dir_all(&out_dir)?;
    std::fs::write(corpus_dir.join("seed_empty"), b"{}")?;
    std::fs::write(corpus_dir.join("seed_array"), b"[1,2,3]")?;
    std::fs::write(corpus_dir.join("seed_string"), b"\"hello\"")?;
    copy_project_sources(project, &workspace);
    let rt = build_runtime(&workspace);
    println!("--- Compiling harness in sandbox ---");
    let compiled = hf_harness::compile(harness, rt.as_ref(), &workspace).await?;
    println!("compile: status={:?}", compiled.status);
    let binary_name = compiled
        .build_cmd
        .output
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let binary = format!("/work/{binary_name}");
    let run_cfg = hf_core::engine::FuzzRunConfig {
        harness_id: compiled.id,
        engine: engine_kind,
        duration: Some(std::time::Duration::from_secs(duration_secs)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: Some(corpus_dir.clone()),
        sanitizer: hf_core::target::Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
    };
    println!("\n--- Running {engine} for {duration_secs}s ---");
    let runner = hf_engine::runner::EngineRunner::new();
    match runner
        .run(
            engine_kind,
            &run_cfg,
            &binary,
            "/work/corpus",
            "/work/out",
            rt.as_ref(),
            &workspace,
        )
        .await
    {
        Ok(result) => {
            println!("\n--- Run summary ---");
            let execs: Vec<f64> = result
                .progress
                .iter()
                .filter_map(|p| match p {
                    hf_core::engine::FuzzProgress::ExecsPerSec(e) => Some(*e),
                    _ => None,
                })
                .collect();
            let crashes = result
                .progress
                .iter()
                .filter(|p| matches!(p, hf_core::engine::FuzzProgress::CrashesFound(_)))
                .count();
            if let Some(last) = execs.last() {
                println!("  execs/sec: {last:.0}");
            }
            println!("  crashes detected: {crashes}");
            println!("  edges covered: {}", result.coverage.edges);
        }
        Err(e) => eprintln!("run failed: {e}"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            println!("init: not implemented");
        }
        Commands::Discover {
            project,
            lang,
            rank,
        } => {
            let lang = parse_lang(&lang)?;
            let mut inv = hf_discovery::discover(&project, lang).await?;
            if rank {
                if let Some(provider) = provider_from_env() {
                    inv = hf_discovery::rank(inv, Box::new(provider)).await?;
                } else {
                    eprintln!("warning: --rank requested but HF_PROVIDER_API_KEY not set; using heuristic scores only");
                }
            }
            let json = serde_json::to_string_pretty(&inv)?;
            println!("{json}");
        }
        Commands::Harness {
            project,
            target,
            engine,
            draft_only,
        } => {
            let engine = parse_engine(&engine)?;
            // Discover to find the target.
            let inv = hf_discovery::discover(&project, TargetLanguage::C).await?;
            let candidate = inv
                .candidates
                .iter()
                .find(|c| c.symbol == target)
                .ok_or_else(|| anyhow::anyhow!("target '{target}' not found in project"))?
                .clone();
            // Draft using LLM if available.
            let provider = provider_from_env().ok_or_else(|| {
                anyhow::anyhow!(
                    "no LLM provider configured; set HF_PROVIDER_API_KEY to generate a harness"
                )
            })?;
            let draft = hf_harness::draft(&candidate, engine, Box::new(provider)).await?;
            println!("--- Harness draft ---");
            println!("{}", draft.source);
            if draft_only {
                return Ok(());
            }
            // Compile + smoke (requires sandbox).
            let build_cmd: BuildCommand =
                hf_harness::build_command(engine, candidate.language, &format!("fuzz_{target}"));
            let harness = Harness {
                id: uuid::Uuid::new_v4(),
                target_id: candidate.id,
                engine,
                source: draft.source,
                language: candidate.language,
                build_cmd,
                sanitizer: hf_core::target::Sanitizer::Address,
                status: HarnessStatus::Draft,
                smoke_run: None,
            };
            println!("\n--- Compiling in sandbox ---");
            let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
            std::fs::create_dir_all(&workspace)?;
            let rt = build_runtime(&workspace);
            match hf_harness::compile(harness, rt.as_ref(), &workspace).await {
                Ok(h) => {
                    println!("compile: status={:?}", h.status);
                    println!("\n--- Smoke fuzz ---");
                    match hf_harness::smoke_fuzz(h, rt.as_ref(), &workspace).await {
                        Ok(h) => {
                            println!("smoke: status={:?}", h.status);
                            if let Some(sr) = &h.smoke_run {
                                println!(
                                    "  execs/sec={:.0} crashes={} passed={}",
                                    sr.execs_per_sec, sr.crashes, sr.passed
                                );
                            }
                        }
                        Err(e) => eprintln!("smoke fuzz failed: {e}"),
                    }
                }
                Err(e) => eprintln!("compile failed: {e}"),
            }
        }
        Commands::Run {
            project,
            target,
            engine,
            duration,
        } => {
            run_command(&project, &target, &engine, duration.as_deref()).await?;
        }
        Commands::Triage { project, target } => {
            let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
            let out_dir = workspace.join("out");
            // Discover to find the target ID.
            let inv = hf_discovery::discover(&project, TargetLanguage::C).await?;
            let candidate = inv
                .candidates
                .iter()
                .find(|c| c.symbol == target)
                .ok_or_else(|| anyhow::anyhow!("target '{target}' not found in project"))?;
            let target_id = candidate.id;
            let run_id = uuid::Uuid::new_v4();
            println!("Scanning {} for crash artifacts...", out_dir.display());
            let crashes = hf_crash::ingest(&out_dir, run_id, target_id)
                .map_err(|e| anyhow::anyhow!("ingest failed: {e}"))?;
            if crashes.is_empty() {
                println!("No crash artifacts found in {}.", out_dir.display());
                return Ok(());
            }
            println!(
                "Found {} crash artifact(s); deduplicating...",
                crashes.len()
            );
            let deduped = hf_crash::dedup(crashes);
            println!("{} unique crash(es) after dedup.", deduped.len());
            // Draft bug reports if LLM is configured.
            let provider = provider_from_env();
            let mut reports: Vec<serde_json::Value> = Vec::new();
            for crash in &deduped {
                if let Some(ref _provider) = provider {
                    // Would call draft_report here; needs the crash log.
                    // For now, just attach the crash metadata.
                    reports.push(serde_json::json!({
                        "id": crash.id,
                        "kind": format!("{:?}", crash.kind),
                        "summary": crash.summary,
                        "stack_signature": crash.stack_signature,
                        "input_path": crash.input_path,
                        "minimized": crash.minimized,
                    }));
                } else {
                    reports.push(serde_json::json!({
                        "id": crash.id,
                        "kind": format!("{:?}", crash.kind),
                        "summary": crash.summary,
                        "stack_signature": crash.stack_signature,
                        "input_path": crash.input_path,
                        "minimized": crash.minimized,
                    }));
                }
            }
            let json = serde_json::to_string_pretty(&reports)?;
            println!("\n{json}");
        }
        Commands::Corpus {
            project,
            target,
            op,
        } => {
            let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
            let corpus_dir = workspace.join("corpus");
            let out_dir = workspace.join("out");
            match op.as_str() {
                "seed" => {
                    std::fs::create_dir_all(&corpus_dir)?;
                    let seeds = vec![
                        (b"{}".to_vec(), "seed_empty".to_owned()),
                        (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
                        (b"\"hello\"".to_vec(), "seed_string".to_owned()),
                    ];
                    let corpus = hf_corpus::seed(uuid::Uuid::new_v4(), &corpus_dir, seeds)
                        .await
                        .map_err(|e| anyhow::anyhow!("seed failed: {e}"))?;
                    println!("Seeded {} entries.", corpus.entries.len());
                }
                "grow" => {
                    let corpus = hf_corpus::grow(&corpus_dir, &out_dir)
                        .map_err(|e| anyhow::anyhow!("grow failed: {e}"))?;
                    println!("Corpus now has {} entries.", corpus.entries.len());
                }
                "prune" => {
                    let corpus = hf_corpus::list(&corpus_dir)
                        .map_err(|e| anyhow::anyhow!("list failed: {e}"))?;
                    let pruned = hf_corpus::prune(corpus)
                        .map_err(|e| anyhow::anyhow!("prune failed: {e}"))?;
                    println!("Pruned to {} entries.", pruned.entries.len());
                }
                "list" => {
                    let corpus = hf_corpus::list(&corpus_dir)
                        .map_err(|e| anyhow::anyhow!("list failed: {e}"))?;
                    let json = serde_json::to_string_pretty(&corpus.entries)?;
                    println!("{json}");
                }
                other => anyhow::bail!("unknown corpus op: {other} (use seed|grow|prune|list)"),
            }
            let _ = &project;
            let _ = &target;
        }
        Commands::Serve { port } => {
            let app = hf_web::build();
            let addr = format!("0.0.0.0:{port}");
            println!("hobot-fuzz web server listening on http://{addr}");
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Tui { project } => {
            tui::Tui::run(&project).await?;
        }
    }
    Ok(())
}
