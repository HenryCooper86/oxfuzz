//! hobot-fuzz CLI entry point.
//!
//! The CLI is a thin presentation layer (AGENTS.md 2.9): every command builds
//! the canonical [`hf_service::ServiceContainer`] via `bootstrap()` and calls
//! service methods through it. No domain logic lives here.

mod tui;

use clap::{Parser, Subcommand};
use hf_service::{EngineKind, FuzzProgress, ServiceContainer, SessionId, TargetLanguage};
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
        /// Auto-repair: on a compile failure, feed the diagnostics back to the
        /// LLM and retry up to N times before giving up (0 = no repair).
        #[arg(long, default_value_t = 0)]
        repair: usize,
        /// Coverage-guided refinement: reshape the EXISTING harness to reach the
        /// target's still-uncovered reachable functions, then recompile.
        #[arg(long)]
        refine: bool,
        /// Explicitly approve the revision for full campaigns after a clean
        /// persisted smoke run.
        #[arg(long)]
        promote: bool,
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
    /// Run an approved campaign: discover -> require promoted harness -> seed
    /// -> run -> triage, end to end.
    Campaign {
        /// Project root path.
        project: PathBuf,
        /// Target symbol to fuzz. Omit to auto-pick the top-ranked target.
        #[arg(long)]
        target: Option<String>,
        /// Fuzzing engine.
        #[arg(long, default_value = "libfuzzer")]
        engine: String,
        /// Target language (c, cpp). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Per-iteration fuzz duration in seconds.
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,
        /// Max run -> triage -> refine iterations.
        #[arg(long, default_value_t = 3)]
        iterations: usize,
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
    /// Push the latest run's triaged crashes to `DefectDojo` as findings.
    Defectdojo {
        /// Project root path.
        project: PathBuf,
        /// Target symbol (used as the `DefectDojo` test title). Optional.
        #[arg(long)]
        target: Option<String>,
        /// Only verify the configured URL + token; do not push.
        #[arg(long)]
        test: bool,
    },
    /// Export a reproducibility/evidence bundle for hand-off and CI artifacts.
    Export {
        /// Optional project root; omit to export all persisted projects.
        project: Option<PathBuf>,
        /// Output JSON bundle path.
        #[arg(short, long, default_value = "hobot_fuzz_export.json")]
        output: PathBuf,
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
        /// IP address to listen on. Non-loopback addresses require `HF_WEB_TOKEN`.
        #[arg(long, default_value = "127.0.0.1")]
        host: std::net::IpAddr,
        /// Port to listen on.
        #[arg(long, default_value = "8081")]
        port: u16,
    },
    /// Launch the TUI (terminal user interface).
    Tui {
        /// Project root path.
        project: PathBuf,
    },
    /// Run one autonomous agent turn over a project (the same agent loop the
    /// GUI and web API use). Requires an LLM provider (`HF_PROVIDER_API_KEY`).
    Agent {
        /// The user message / instruction for the agent.
        message: String,
        /// Project root the agent operates on.
        #[arg(long)]
        project: Option<PathBuf>,
        /// Agent definition id (default: the orchestrator).
        #[arg(long)]
        agent: Option<String>,
    },
    /// Knowledge-base operations (see also `ingest`).
    Knowledge {
        #[command(subcommand)]
        op: KnowledgeOp,
    },
    /// Campaign scheduling for headless recurring runs.
    Schedule {
        #[command(subcommand)]
        op: ScheduleOp,
    },
    /// Chat session management.
    Session {
        #[command(subcommand)]
        op: SessionOp,
    },
}

#[derive(Subcommand)]
enum KnowledgeOp {
    /// Index a project's source files into its BM25 knowledge base.
    Index { project: PathBuf },
    /// Search a project's knowledge base.
    Search {
        project: PathBuf,
        query: String,
        #[arg(long, default_value = "10")]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum ScheduleOp {
    /// List scheduled campaigns.
    List,
    /// Show recent campaign execution history.
    History {
        #[arg(long, default_value = "20")]
        limit: usize,
    },
    /// Create a scheduled campaign.
    Create {
        /// Display name.
        name: String,
        #[arg(long)]
        project: PathBuf,
        /// Promoted target to fuzz. Omit (or empty) for a portfolio campaign that
        /// rotates through every promoted target in the project.
        #[arg(long, default_value = "")]
        target: String,
        #[arg(long, default_value = "libfuzzer")]
        engine: String,
        /// Target language of the promoted harness: c | cpp | rust | go | python.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Trigger kind: interval | cron | once.
        #[arg(long)]
        trigger_kind: String,
        /// Trigger value (interval seconds, a cron expr, or an RFC3339 time).
        #[arg(long)]
        trigger_value: String,
        /// Per-run duration (e.g. 30m, 1h).
        #[arg(long, default_value = "1h")]
        duration: String,
        /// Budget: stop after this many completed runs.
        #[arg(long)]
        max_runs: Option<u32>,
        /// Budget: stop after this much cumulative fuzz time (seconds).
        #[arg(long)]
        max_total_secs: Option<u64>,
    },
    /// Delete a scheduled campaign by id.
    Delete { id: String },
    /// Enable a scheduled campaign by id.
    Enable { id: String },
    /// Disable a scheduled campaign by id.
    Disable { id: String },
}

#[derive(Subcommand)]
enum SessionOp {
    /// Create a new chat session, printing its id.
    New {
        #[arg(long)]
        title: Option<String>,
    },
    /// Print a session's transcript.
    History { id: String },
    /// List a session's per-turn checkpoints.
    Checkpoints { id: String },
    /// List the branches in a session's tree.
    Branches { id: String },
    /// Roll back the last turn of a session.
    Rollback { id: String },
}

fn parse_lang(s: &str) -> Result<TargetLanguage, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn parse_engine(s: &str) -> Result<EngineKind, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

async fn cmd_export(project: Option<PathBuf>, output: PathBuf) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let bundle = container.export_project_data(project.as_deref()).await;
    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&output, json)?;
    println!("Exported evidence bundle to {}", output.display());
    Ok(())
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

/// An [`EventSink`](hf_service::EventSink) that renders agent progress to stderr,
/// keeping stdout reserved for the final answer (so it can be piped).
struct CliEventSink;

#[async_trait::async_trait]
impl hf_service::EventSink for CliEventSink {
    async fn emit(&self, event: hf_service::AgentEvent) {
        match event {
            hf_service::AgentEvent::Thinking { text } => eprintln!("[thinking] {text}"),
            hf_service::AgentEvent::ToolCall { name, args } => {
                eprintln!("[tool] {name} {args}");
            }
            hf_service::AgentEvent::ToolResult { name, summary } => {
                eprintln!("[result] {name}: {summary}");
            }
            hf_service::AgentEvent::Error { message } => eprintln!("[error] {message}"),
            hf_service::AgentEvent::Started | hf_service::AgentEvent::Complete { .. } => {}
        }
    }
}

async fn cmd_agent(
    message: &str,
    project: Option<PathBuf>,
    agent: Option<&str>,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    if container.provider_pool().is_none() {
        anyhow::bail!("agent requires an LLM provider; set HF_PROVIDER_API_KEY");
    }
    let sink = CliEventSink;
    let answer = container
        .run_chat_turn(
            hf_service::AgentTurnRequest {
                project,
                agent_id: agent.map(str::to_owned),
                session: None,
                history_fallback: Vec::new(),
                message: message.to_owned(),
                display_message: None,
            },
            &sink,
        )
        .await?;
    println!("{answer}");
    Ok(())
}

fn cmd_knowledge(op: KnowledgeOp) -> anyhow::Result<()> {
    match op {
        KnowledgeOp::Index { project } => {
            let stats = hf_service::knowledge::index_project(&project)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!(
                "Indexed {} file(s), {} chunk(s).",
                stats.files, stats.chunks
            );
        }
        KnowledgeOp::Search {
            project,
            query,
            limit,
        } => {
            // The BM25 index is process-local (in-memory), so a fresh CLI
            // process must build it before searching -- a `knowledge index` run
            // in a separate process left no on-disk index to reuse.
            if !hf_service::knowledge::is_indexed(&project) {
                hf_service::knowledge::index_project(&project)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            }
            let hits = hf_service::knowledge::search_project(&project, &query, limit);
            if hits.is_empty() {
                println!("No results.");
            }
            for h in hits {
                println!("{:.3}  {}", h.score, h.file);
                println!("    {}", h.snippet.replace('\n', " "));
            }
        }
    }
    Ok(())
}

/// Start a campaign scheduler for a one-shot CLI operation. Background ticking
/// stops when the process exits; persisted schedules live under the user data
/// dir (shared with the GUI and web server).
async fn start_scheduler() -> hf_service::scheduler::CampaignScheduler {
    let container = ServiceContainer::bootstrap().await;
    let store_path = hf_service::init::user_app_dir().join("schedules.json");
    hf_service::scheduler::CampaignScheduler::start(container, store_path, None).await
}

async fn cmd_schedule(op: ScheduleOp) -> anyhow::Result<()> {
    let scheduler = start_scheduler().await;
    match op {
        ScheduleOp::List => {
            let views = scheduler.list_views().await;
            if views.is_empty() {
                println!("No scheduled campaigns.");
            }
            for v in views {
                let target = v.target.as_deref().unwrap_or("all promoted targets");
                let budget = v
                    .max_runs
                    .map(|m| format!(" runs={}/{m}", v.runs_done))
                    .or_else(|| {
                        v.max_total_secs
                            .map(|m| format!(" secs={}/{m}", v.secs_done))
                    })
                    .unwrap_or_default();
                println!(
                    "{}  {}  [{}]  {}  target={target} engine={} {}s{budget}  last={}",
                    v.id,
                    v.name,
                    if v.enabled { "enabled" } else { "disabled" },
                    v.trigger,
                    v.engine,
                    v.duration_secs,
                    v.last_fire.unwrap_or_else(|| "never".to_owned()),
                );
            }
        }
        ScheduleOp::History { limit } => {
            for e in scheduler.recent_executions(limit).await {
                println!(
                    "{}  {}  {}  {}",
                    e.triggered_at, e.campaign, e.status, e.summary
                );
            }
        }
        ScheduleOp::Create {
            name,
            project,
            target,
            engine,
            lang,
            trigger_kind,
            trigger_value,
            duration,
            max_runs,
            max_total_secs,
        } => {
            let trigger = hf_service::scheduler::parse_trigger(&trigger_kind, &trigger_value)
                .map_err(|e| anyhow::anyhow!(e))?;
            let params = hf_service::scheduler::CampaignParams {
                // Empty target = portfolio campaign over all promoted targets.
                target: (!target.trim().is_empty()).then_some(target),
                project: project.display().to_string(),
                engine,
                lang,
                duration_secs: parse_duration(&duration)?,
                max_runs,
                max_total_secs,
                schedule_id: String::new(),
            };
            scheduler.create(&name, &params, trigger).await;
            println!("Created schedule '{name}'.");
        }
        ScheduleOp::Delete { id } => {
            let msg = if scheduler.remove(&id).await {
                "Deleted."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
        ScheduleOp::Enable { id } => {
            let msg = if scheduler.set_enabled(&id, true).await {
                "Enabled."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
        ScheduleOp::Disable { id } => {
            let msg = if scheduler.set_enabled(&id, false).await {
                "Disabled."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
    }
    Ok(())
}

async fn cmd_session(op: SessionOp) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        SessionOp::New { title } => match container.create_chat_session(title).await? {
            Some(id) => println!("{id}"),
            None => {
                println!("No database configured (set HF_DB_PATH); cannot persist sessions.");
            }
        },
        SessionOp::History { id } => {
            let sid = SessionId(id);
            for m in container.chat_history(&sid).await? {
                println!("[{:?}] {}", m.role, m.content);
            }
        }
        SessionOp::Checkpoints { id } => {
            let sid = SessionId(id);
            for c in container.chat_checkpoints(&sid).await? {
                println!("{c:?}");
            }
        }
        SessionOp::Branches { id } => {
            let sid = SessionId(id);
            for b in container.chat_branches(&sid).await? {
                println!("{b:?}");
            }
        }
        SessionOp::Rollback { id } => {
            let sid = SessionId(id);
            let n = container.chat_rollback_last(&sid).await?;
            println!("Rolled back {n} message(s).");
        }
    }
    Ok(())
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
    repair: usize,
    refine: bool,
    promote: bool,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;

    // With --refine, reshape the existing harness toward uncovered reachable
    // functions (coverage-guided), then recompile with auto-repair.
    if refine {
        println!("--- Refining harness (coverage-guided) ---");
        let outcome = container
            .harness_refine(&project, target, engine, lang, repair.max(1))
            .await?;
        println!(
            "refined: status={:?} repairs_used={}",
            outcome.status, outcome.repairs_used
        );
        // Refine must recompile to measure coverage, but --draft-only still means
        // "stop before smoke qualification and promotion".
        if draft_only {
            println!(
                "--draft-only: refined and recompiled; skipping smoke qualification and promotion."
            );
            return Ok(());
        }
        qualify_harness(&container, &project, target, engine, lang, promote).await?;
        return Ok(());
    }

    // With --repair, use the draft -> compile -> repair loop, which recovers
    // harnesses that fail to build on the first draft.
    if repair > 0 && !draft_only {
        println!("--- Generating harness (auto-repair up to {repair}x) ---");
        let outcome = container
            .harness_generate(&project, target, engine, lang, repair)
            .await?;
        println!(
            "compile: status={:?} repairs_used={}",
            outcome.status, outcome.repairs_used
        );
        qualify_harness(&container, &project, target, engine, lang, promote).await?;
        return Ok(());
    }

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
    qualify_harness(&container, &project, target, engine, lang, promote).await?;
    Ok(())
}

async fn qualify_harness(
    container: &ServiceContainer,
    project: &std::path::Path,
    target: &str,
    engine: EngineKind,
    lang: TargetLanguage,
    promote: bool,
) -> anyhow::Result<()> {
    println!("\n--- Smoke qualification ---");
    let smoke = container
        .harness_smoke(project, target, engine, lang)
        .await?;
    println!(
        "smoke: execs/sec={:.0} crashes={} passed={}",
        smoke.execs_per_sec, smoke.crashes, smoke.passed
    );
    if promote {
        let harness = container.harness_promote(project, target, engine).await?;
        println!("promotion: {:?} ({})", harness.status, harness.id);
    } else {
        println!(
            "promotion required: review the harness and rerun this command with --promote before a full campaign"
        );
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
    // `run` drives the already-built harness, which carries its own language, so
    // the value is not threaded further. Still validate it (like triage/ci) so an
    // invalid `--lang` is rejected up front rather than silently ignored.
    parse_lang(lang)?;
    let duration_secs = duration.map(parse_duration).transpose()?.unwrap_or(3600);
    let container = std::sync::Arc::new(ServiceContainer::bootstrap().await);
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
            let on_progress = |p: FuzzProgress| match p {
                FuzzProgress::LogLine(line) => println!("  {line}"),
                FuzzProgress::CrashesFound(_) => println!("  >> crash found"),
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
    if let Some(proposal) = &summary.stagnation {
        println!("  coverage stalled: {proposal:?} -- consider regenerating the harness or adding seeds/a dictionary");
    }
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
        "llmseed" => {
            let entries = container
                .generate_seeds_llm(&project, target, TargetLanguage::C, 12)
                .await?;
            println!("Generated {} LLM seed(s).", entries.len());
        }
        "grow" => {
            let n = container.corpus_grow(&project, target).await?;
            println!("Corpus now has {n} entries.");
        }
        "prune" => {
            let n = container.corpus_prune(&project, target)?;
            println!("Pruned to {n} entries.");
        }
        "cprune" => {
            let outcome = container.corpus_prune_coverage(&project, target).await?;
            println!(
                "Coverage-pruned {} -> {} entries.",
                outcome.before, outcome.after
            );
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
            anyhow::bail!(
                "unknown corpus op: {other} \
                 (use seed|llmseed|grow|prune|cprune|minimize|absorb|list)"
            )
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
    let _lang = parse_lang(lang)?;
    let duration_secs = parse_duration(duration)?;
    // CI is a non-interactive, deliberately-automated run. Set permissive
    // guardrails for this process so the high-risk run/triage steps proceed
    // without an interactive approval (safe-by-default still applies elsewhere).
    if std::env::var_os("HF_GUARDRAILS").is_none() {
        std::env::set_var("HF_GUARDRAILS", "permissive");
    }
    let container = ServiceContainer::bootstrap().await;

    println!("[ci] requiring a previously smoke-qualified and promoted harness for {target}...");
    if let Err(e) = container.generate_seeds(&project, target) {
        eprintln!("[ci] warning: seed generation failed: {e}");
    }

    println!("[ci] fuzzing {target} for {duration_secs}s...");
    let on_progress = |p: FuzzProgress| {
        if let FuzzProgress::CrashesFound(_) = p {
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

async fn cmd_defectdojo(
    project: PathBuf,
    target: Option<&str>,
    test_only: bool,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    if test_only {
        container.defectdojo_test_connection().await?;
        println!("DefectDojo connection OK.");
        return Ok(());
    }
    let outcome = container.push_to_defectdojo(&project, target).await?;
    println!(
        "Pushed {} finding(s) to DefectDojo{}{}.",
        outcome.findings_pushed,
        if outcome.reimported {
            " (reimport)"
        } else {
            ""
        },
        outcome
            .url
            .as_ref()
            .map(|u| format!(" -- {u}"))
            .unwrap_or_default()
    );
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

async fn cmd_campaign(
    project: PathBuf,
    target: Option<&str>,
    engine: &str,
    lang: &str,
    duration_secs: u64,
    iterations: usize,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    println!("--- Running autonomous campaign ---");
    let outcome = container
        .run_campaign(&project, target, engine, lang, duration_secs, 2, iterations)
        .await?;
    println!(
        "target={} harness={:?} repairs={} iterations={} edges={} crashes={}",
        outcome.target,
        outcome.harness_status,
        outcome.repairs_used,
        outcome.iterations,
        outcome.edges,
        outcome.crashes
    );
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
            repair,
            refine,
            promote,
        } => {
            cmd_harness(
                project, &target, &engine, &lang, draft_only, repair, refine, promote,
            )
            .await?;
        }
        Commands::Run {
            project,
            target,
            engine,
            lang,
            duration,
        } => cmd_run(project, &target, &engine, &lang, duration.as_deref()).await?,
        Commands::Campaign {
            project,
            target,
            engine,
            lang,
            duration_secs,
            iterations,
        } => {
            cmd_campaign(
                project,
                target.as_deref(),
                &engine,
                &lang,
                duration_secs,
                iterations,
            )
            .await?;
        }
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
        Commands::Defectdojo {
            project,
            target,
            test,
        } => cmd_defectdojo(project, target.as_deref(), test).await?,
        Commands::Export { project, output } => cmd_export(project, output).await?,
        Commands::Report {
            project,
            target,
            out,
        } => cmd_report(project, &target, out.as_deref()).await?,
        Commands::Serve { host, port } => {
            let security = hf_web::WebSecurityConfig::from_env();
            let addr = std::net::SocketAddr::new(host, port);
            hf_web::validate_bind_addr(addr, security.token_configured())?;
            let app = hf_web::build_bootstrapped_with_security(security).await;
            println!("hobot-fuzz web server listening on http://{addr}");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Tui { project } => {
            tui::Tui::run(&project).await?;
        }
        Commands::Agent {
            message,
            project,
            agent,
        } => cmd_agent(&message, project, agent.as_deref()).await?,
        Commands::Knowledge { op } => cmd_knowledge(op)?,
        Commands::Schedule { op } => cmd_schedule(op).await?,
        Commands::Session { op } => cmd_session(op).await?,
    }
    Ok(())
}
