//! hobot-fuzz CLI entry point.
//!
//! The CLI is a thin presentation layer (AGENTS.md 2.9): every command builds
//! the canonical [`hf_service::ServiceContainer`] via `bootstrap()` and calls
//! service methods through it. No domain logic lives here.

mod tui;

use clap::{Parser, Subcommand};
use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
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
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
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
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
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
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
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
        "syzkaller" | "syz" => EngineKind::Syzkaller,
        other => anyhow::bail!("unsupported engine: {other}"),
    })
}

/// Parse a human duration string like "60m", "2h", "30s".
fn parse_duration(s: &str) -> Result<u64, anyhow::Error> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        return Ok(n.parse()?);
    }
    if let Some(n) = s.strip_suffix('m') {
        return Ok(n.parse::<u64>()? * 60);
    }
    if let Some(n) = s.strip_suffix('h') {
        return Ok(n.parse::<u64>()? * 3600);
    }
    // Fallback: parse as raw seconds.
    Ok(s.parse()?)
}

async fn cmd_discover(project: PathBuf, lang: &str, rank: bool) -> anyhow::Result<()> {
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    let mut inv = container.discover(&project, lang).await?;
    if rank {
        if container.provider_pool().is_some() {
            inv = container.rank(inv).await?;
        } else {
            eprintln!(
                "warning: --rank requested but HF_PROVIDER_API_KEY not set; using heuristic scores only"
            );
        }
    }
    println!("{}", serde_json::to_string_pretty(&inv)?);
    Ok(())
}

async fn cmd_harness(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    draft_only: bool,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    let draft = container
        .harness_draft(&project, target, engine, lang)
        .await?;
    println!("--- Harness draft ---");
    println!("{}", draft.source);
    if draft_only {
        return Ok(());
    }
    println!("\n--- Compiling in sandbox ---");
    let outcome = container
        .harness_compile(draft.source, &project, engine, target, lang)
        .await?;
    println!("compile: status={:?}", outcome.status);
    println!("\n--- Smoke fuzz ---");
    match container
        .harness_smoke(&project, target, engine, lang)
        .await
    {
        Ok(sr) => println!(
            "smoke: execs/sec={:.0} crashes={} passed={}",
            sr.execs_per_sec, sr.crashes, sr.passed
        ),
        Err(e) => eprintln!("smoke fuzz failed: {e}"),
    }
    Ok(())
}

async fn cmd_run(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    duration: Option<&str>,
) -> anyhow::Result<()> {
    let engine_kind = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let duration_secs = duration.map(parse_duration).transpose()?.unwrap_or(3600);
    let container = ServiceContainer::bootstrap().await;

    let draft = container
        .harness_draft(&project, target, engine_kind, lang)
        .await?;
    println!("--- Compiling harness in sandbox ---");
    let outcome = container
        .harness_compile(draft.source, &project, engine_kind, target, lang)
        .await?;
    println!("compile: status={:?}", outcome.status);
    // Ensure a seed corpus exists before running.
    let _ = container.generate_seeds(&project, target);

    println!("\n--- Running {engine} for {duration_secs}s ---");
    let summary = container
        .run_fuzzer(&project, target, engine_kind, duration_secs, &|_p| {})
        .await?;
    println!("\n--- Run summary ---");
    println!("  execs/sec: {:.0}", summary.execs);
    println!("  crashes detected: {}", summary.crashes);
    println!("  edges covered: {}", summary.edges);
    Ok(())
}

async fn cmd_triage(project: PathBuf, target: &str, lang: &str) -> anyhow::Result<()> {
    // Language is validated for a clear error, though triage works off the
    // already-compiled workspace.
    let _lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    let crashes = container.triage(&project, target).await?;
    if crashes.is_empty() {
        println!("No crash artifacts found.");
        return Ok(());
    }
    println!("{} unique crash(es) after dedup.", crashes.len());
    let reports: Vec<serde_json::Value> = crashes
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "kind": format!("{:?}", c.kind),
                "summary": c.summary,
                "stack_signature": c.stack_signature,
                "input_path": c.input_path,
                "minimized": c.minimized,
            })
        })
        .collect();
    println!("\n{}", serde_json::to_string_pretty(&reports)?);
    Ok(())
}

async fn cmd_corpus(project: PathBuf, target: &str, op: &str) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        "seed" => {
            let n = container.corpus_seed(&project, target).await?;
            println!("Seeded {n} entries.");
        }
        "grow" => {
            let n = container.corpus_grow(&project, target)?;
            println!("Corpus now has {n} entries.");
        }
        "prune" => {
            let n = container.corpus_prune(&project, target)?;
            println!("Pruned to {n} entries.");
        }
        "list" => {
            let corpus = container.corpus_list(&project, target)?;
            println!("{}", serde_json::to_string_pretty(&corpus.entries)?);
        }
        other => anyhow::bail!("unknown corpus op: {other} (use seed|grow|prune|list)"),
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => {
            let report = hf_service::init_workspace().await?;
            println!("Initialized hobot_fuzz workspace.");
            println!("  config dir: {}", report.config_dir.display());
            if report.created_configs.is_empty() {
                println!("  config: all files already present");
            } else {
                println!("  created: {}", report.created_configs.join(", "));
            }
            println!("  database: {}", report.db_path.display());
        }
        Commands::Discover {
            project,
            lang,
            rank,
        } => cmd_discover(project, &lang, rank).await?,
        Commands::Harness {
            project,
            target,
            engine,
            lang,
            draft_only,
        } => cmd_harness(project, &target, &engine, &lang, draft_only).await?,
        Commands::Run {
            project,
            target,
            engine,
            lang,
            duration,
        } => cmd_run(project, &target, &engine, &lang, duration.as_deref()).await?,
        Commands::Triage {
            project,
            target,
            lang,
        } => cmd_triage(project, &target, &lang).await?,
        Commands::Corpus {
            project,
            target,
            op,
        } => cmd_corpus(project, &target, &op).await?,
        Commands::Serve { port } => {
            let app = hf_web::build_bootstrapped().await;
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
