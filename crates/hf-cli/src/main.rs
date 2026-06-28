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
        /// Operation: seed, grow, prune, minimize, absorb, list.
        #[arg(long)]
        op: String,
    },
    /// Report line/function/region coverage for a target's corpus.
    Coverage {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
    },
    /// CI gate: harness + short fuzz + triage; write SARIF and exit non-zero
    /// if any crash is found. Intended for PR pipelines.
    Ci {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine. Defaults to libfuzzer.
        #[arg(long, default_value = "libfuzzer")]
        engine: String,
        /// Target language (c, cpp). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Fuzz duration (e.g. 120s, 5m). Defaults to 120s.
        #[arg(long, default_value = "120s")]
        duration: String,
        /// SARIF output path. Defaults to `hobot_fuzz.sarif`.
        #[arg(long, default_value = "hobot_fuzz.sarif")]
        sarif: PathBuf,
    },
    /// Export the latest run's crashes as SARIF (`GitHub` code scanning).
    Sarif {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Write SARIF to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Replay stored crashes against the current harness (regression check).
    Regress {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
    },
    /// Ingest a document (PDF/Office/HTML/...) into the project knowledge base.
    Ingest {
        /// Project root path.
        project: PathBuf,
        /// Document file to convert and index.
        #[arg(long)]
        file: PathBuf,
    },
    /// Compose a detailed Markdown campaign report for a target.
    Report {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Write the report to this file instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
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
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn parse_engine(s: &str) -> Result<EngineKind, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
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
    let container = std::sync::Arc::new(ServiceContainer::bootstrap().await);

    let draft = container
        .harness_draft(&project, target, engine_kind, lang)
        .await?;
    println!("--- Compiling harness in sandbox ---");
    let outcome = container
        .harness_compile(draft.source, &project, engine_kind, target, lang)
        .await?;
    println!("compile: status={:?}", outcome.status);
    // Ensure a seed corpus exists before running. A failure here is not fatal
    // (the engine can still run on an empty corpus) but must not be silent.
    if let Err(e) = container.generate_seeds(&project, target) {
        eprintln!("warning: could not generate seed corpus: {e}");
    }

    println!("\n--- Running {engine} for {duration_secs}s (live, Ctrl-C to stop) ---");
    // Run on a task so a Ctrl-C can cancel it cooperatively: the run keeps
    // executing long enough to tear down the sandbox cleanly and return its
    // partial results, rather than being dropped mid-flight.
    let mut handle = {
        let container = std::sync::Arc::clone(&container);
        let project = project.clone();
        let target = target.to_owned();
        tokio::spawn(async move {
            let on_progress = |p: hf_core::engine::FuzzProgress| match p {
                hf_core::engine::FuzzProgress::LogLine(line) => println!("  {line}"),
                hf_core::engine::FuzzProgress::CrashesFound(_) => println!("  >> crash found"),
                _ => {}
            };
            container
                .run_fuzzer(&project, &target, engine_kind, duration_secs, &on_progress)
                .await
        })
    };

    let summary = tokio::select! {
        res = &mut handle => res?,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("\n--- Ctrl-C received: cancelling run ---");
            container.cancel_all_runs();
            handle.await?
        }
    }?;
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
            let n = container.corpus_grow(&project, target).await?;
            println!("Corpus now has {n} entries.");
        }
        "prune" => {
            let n = container.corpus_prune(&project, target)?;
            println!("Pruned to {n} entries.");
        }
        "minimize" | "cmin" => {
            let outcome = container.corpus_minimize(&project, target).await?;
            println!("Minimized {} -> {} entries.", outcome.before, outcome.after);
        }
        "absorb" => {
            let n = container.corpus_absorb_crashes(&project, target).await?;
            println!("Absorbed {n} crash reproducer(s) into the corpus.");
        }
        "list" => {
            let corpus = container.corpus_list(&project, target)?;
            println!("{}", serde_json::to_string_pretty(&corpus.entries)?);
        }
        other => {
            anyhow::bail!("unknown corpus op: {other} (use seed|grow|prune|minimize|absorb|list)")
        }
    }
    Ok(())
}

async fn cmd_coverage(project: PathBuf, target: &str) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match container.coverage_summary(&project, target).await {
        Some(s) => {
            println!("Coverage for {target}:");
            println!(
                "  lines:     {}/{} ({:.1}%)",
                s.lines_covered,
                s.lines_total,
                s.line_percent()
            );
            println!(
                "  functions: {}/{} ({:.1}%)",
                s.functions_covered,
                s.functions_total,
                s.function_percent()
            );
            println!(
                "  regions:   {}/{} ({:.1}%)",
                s.regions_covered,
                s.regions_total,
                s.region_percent()
            );
        }
        None => {
            eprintln!(
                "No coverage available -- compile a harness and build a corpus first, \
                 and ensure the sandbox has clang/llvm-cov."
            );
        }
    }
    Ok(())
}

async fn cmd_ci(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    duration: &str,
    sarif: &std::path::Path,
) -> anyhow::Result<()> {
    let engine_kind = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let duration_secs = parse_duration(duration)?;
    // CI is a non-interactive, deliberately-automated run. Set permissive
    // guardrails for this process so the high-risk run/triage steps proceed
    // without an interactive approval (safe-by-default still applies elsewhere).
    if std::env::var_os("HF_GUARDRAILS").is_none() {
        std::env::set_var("HF_GUARDRAILS", "permissive");
    }
    let container = ServiceContainer::bootstrap().await;

    println!("[ci] drafting + compiling harness for {target}...");
    let draft = container
        .harness_draft(&project, target, engine_kind, lang)
        .await?;
    let outcome = container
        .harness_compile(draft.source, &project, engine_kind, target, lang)
        .await?;
    println!("[ci] compile: {:?}", outcome.status);
    if let Err(e) = container.generate_seeds(&project, target) {
        eprintln!("[ci] warning: seed generation failed: {e}");
    }

    println!("[ci] fuzzing {target} for {duration_secs}s...");
    let on_progress = |p: hf_core::engine::FuzzProgress| {
        if let hf_core::engine::FuzzProgress::CrashesFound(_) = p {
            println!("[ci] >> crash found");
        }
    };
    container
        .run_fuzzer(&project, target, engine_kind, duration_secs, &on_progress)
        .await?;

    println!("[ci] triaging...");
    let crashes = container.triage(&project, target).await?;

    // Always emit SARIF (even with zero results) so code scanning can clear
    // stale alerts when a bug is fixed.
    let doc = container.export_sarif(&project, target).await?;
    std::fs::write(sarif, &doc)?;
    println!("[ci] SARIF written to {}", sarif.display());

    if crashes.is_empty() {
        println!("[ci] PASS: no crashes found.");
        Ok(())
    } else {
        eprintln!("[ci] FAIL: {} crash(es) found.", crashes.len());
        for c in &crashes {
            eprintln!("[ci]   {:?}: {}", c.kind, c.summary);
        }
        // Non-zero exit gates the PR; SARIF was already written + can be uploaded.
        std::process::exit(1);
    }
}

async fn cmd_sarif(
    project: PathBuf,
    target: &str,
    out: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let sarif = container.export_sarif(&project, target).await?;
    match out {
        Some(path) => {
            std::fs::write(path, &sarif)?;
            println!("SARIF written to {}", path.display());
        }
        None => println!("{sarif}"),
    }
    Ok(())
}

async fn cmd_ingest(project: PathBuf, file: &std::path::Path) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let stats = container.ingest_document(&project, file).await?;
    println!(
        "Ingested {} -> knowledge base now has {} file(s), {} chunk(s).",
        file.display(),
        stats.files,
        stats.chunks
    );
    Ok(())
}

async fn cmd_regress(project: PathBuf, target: &str) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let results = container.verify_regressions(&project, target).await?;
    if results.is_empty() {
        println!("No stored crashes to replay.");
        return Ok(());
    }
    let still = results.iter().filter(|r| r.still_crashes).count();
    println!(
        "Replayed {} crash(es): {still} still crashing, {} fixed.",
        results.len(),
        results.len() - still
    );
    for r in &results {
        let tag = if r.still_crashes {
            "STILL CRASHES"
        } else {
            "fixed"
        };
        let id = if r.crash_id.is_empty() {
            ""
        } else {
            &r.crash_id[..r.crash_id.len().min(8)]
        };
        println!("  [{tag}] {id} {} -- {}", r.input, r.summary);
    }
    Ok(())
}

async fn cmd_report(
    project: PathBuf,
    target: &str,
    out: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let markdown = container.generate_report(&project, target).await?;
    match out {
        Some(path) => {
            std::fs::write(path, &markdown)?;
            println!("Report written to {}", path.display());
        }
        None => println!("{markdown}"),
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
        Commands::Coverage { project, target } => cmd_coverage(project, &target).await?,
        Commands::Ci {
            project,
            target,
            engine,
            lang,
            duration,
            sarif,
        } => cmd_ci(project, &target, &engine, &lang, &duration, &sarif).await?,
        Commands::Regress { project, target } => cmd_regress(project, &target).await?,
        Commands::Ingest { project, file } => cmd_ingest(project, &file).await?,
        Commands::Sarif {
            project,
            target,
            out,
        } => cmd_sarif(project, &target, out.as_deref()).await?,
        Commands::Report {
            project,
            target,
            out,
        } => cmd_report(project, &target, out.as_deref()).await?,
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
