//! oxfuzz CLI entry point.
//!
//! The CLI is a thin presentation layer (AGENTS.md 2.9): every command builds
//! the canonical [`hf_service::ServiceContainer`] via `bootstrap()` and calls
//! service methods through it. No domain logic lives here.

mod tui;

use clap::{Parser, Subcommand};
use hf_service::scheduler::{CampaignScheduler, CampaignSchedulerError};
use hf_service::{
    EngineKind, FuzzProgress, ServiceContainer, SessionId, TargetLanguage, VerdictLevel,
};
use std::path::PathBuf;

/// AI fuzzing agent.
#[derive(Parser)]
#[command(name = "oxfuzz", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize configuration.
    Init,
    /// Check whether the mandatory sandbox and at least one fuzzing engine are ready.
    Doctor {
        /// Emit the service-owned status as JSON.
        #[arg(long)]
        json: bool,
    },
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
        /// Enrich persisted C/C++ targets with advisory Semgrep signals.
        #[cfg(feature = "semgrep-enrichment")]
        #[arg(long)]
        semgrep: bool,
    },
    /// Generate a harness for a target.
    Harness {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine (afl++, honggfuzz, libfuzzer, syzkaller).
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
        /// Target symbol. Required unless `--replay` is given (the recorded
        /// run carries its target).
        #[arg(long, required_unless_present = "replay")]
        target: Option<String>,
        /// Fuzzing engine. Required unless `--replay` is given.
        #[arg(long, required_unless_present = "replay")]
        engine: Option<String>,
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Duration (e.g. 60m).
        #[arg(long)]
        duration: Option<String>,
        /// Replay a persisted run with its recorded engine, duration, and
        /// deterministic seed.
        #[arg(long)]
        replay: Option<String>,
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
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Per-iteration fuzz duration in seconds.
        #[arg(long, default_value_t = 60)]
        duration_secs: u64,
        /// Max run -> triage iterations.
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
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Fuzz duration (e.g. 120s, 5m). Defaults to 120s.
        #[arg(long, default_value = "120s")]
        duration: String,
        /// SARIF output path. Defaults to `oxfuzz.sarif`.
        #[arg(long, default_value = "oxfuzz.sarif")]
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
    /// Export a self-contained reproduction bundle (harness + crash input +
    /// REPRODUCE.md) for a crash from the target's latest run.
    Repro {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine. Defaults to libfuzzer.
        #[arg(long, default_value = "libfuzzer")]
        engine: String,
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Crash id (or unique prefix) to bundle; defaults to the first crash.
        #[arg(long)]
        crash: Option<String>,
        /// Output directory for the bundle.
        #[arg(long, default_value = "oxfuzz_repro")]
        out: PathBuf,
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
        #[arg(short, long, default_value = "oxfuzz_export.json")]
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
        /// Report language: en or zh. Defaults to en.
        ///
        /// Named `--report-lang` rather than `--lang` because `--lang` already
        /// means the target's source language on `discover` and `harness`.
        #[arg(long, default_value = "en")]
        report_lang: String,
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
    /// Inspect and manage LLM providers. With no subcommand, list provider
    /// ids with their frozen/healthy state.
    Providers {
        #[command(subcommand)]
        op: Option<ProvidersOp>,
    },
    /// Guardrail policy audit trail.
    Policy {
        #[command(subcommand)]
        op: PolicyOp,
    },
    /// Sandboxed automotive protocol analysis and replay preparation.
    #[cfg(feature = "automotive-scapy")]
    Automotive {
        #[command(subcommand)]
        op: AutomotiveOp,
    },
}

#[cfg(feature = "automotive-scapy")]
#[derive(Subcommand)]
enum AutomotiveOp {
    /// Print the validated automotive policy as JSON.
    Settings,
    /// Enable the runtime automotive policy without changing its limits.
    Enable,
    /// Disable the runtime automotive policy.
    Disable,
    /// Inspect capabilities of the configured pinned sidecar.
    Capabilities { project: PathBuf },
    /// Analyze an immutable PCAP capture.
    Analyze {
        project: PathBuf,
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        capture: PathBuf,
    },
    /// Import and analyze a CAN log offline (`candump`, `vector_asc`, `crtd`,
    /// `gvret_csv`), optionally decoding signals with a DBC database. Prints JSON.
    Import {
        capture: PathBuf,
        #[arg(long, default_value = "candump")]
        format: String,
        #[arg(long)]
        dbc: Option<PathBuf>,
    },
    /// Compare two CAN logs of the same format offline and report per-id
    /// differences. Prints JSON.
    Diff {
        first: PathBuf,
        second: PathBuf,
        #[arg(long, default_value = "candump")]
        format: String,
    },
    /// Run a bounded, read-only live capture ("monitor"/sniffer) on an
    /// allowlisted virtual CAN interface. Retains the captured evidence.
    Monitor {
        project: PathBuf,
        #[arg(long, default_value = "vcan0")]
        interface: String,
        #[arg(long, default_value = "can")]
        protocol: String,
    },
    /// Run a read-only UDS ECU/service discovery scan on a virtual CAN
    /// interface. Only read-only discovery services are permitted. Prints JSON.
    Scan {
        project: PathBuf,
        #[arg(long, default_value = "vcan0")]
        interface: String,
        /// Comma-separated request arbitration ids (hex `0x` accepted).
        #[arg(long, default_value = "0x7e0")]
        request_ids: String,
        /// Comma-separated read-only service ids (hex `0x` accepted).
        #[arg(long, default_value = "0x3e,0x22")]
        services: String,
    },
    /// Generate a deterministic field-aware mutation artifact.
    Mutate {
        project: PathBuf,
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value_t = 64)]
        count: u32,
        #[arg(long, default_value_t = 0)]
        seed: u64,
        #[arg(long, default_value = "application/octet-stream")]
        media_type: String,
    },
    /// Build a typed replay plan without contacting an interface.
    Plan {
        project: PathBuf,
        #[arg(long)]
        protocol: String,
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "virtual_can")]
        mode: String,
        #[arg(long, default_value_t = 0)]
        seed: u64,
    },
    /// Execute a typed replay plan only on an allowlisted virtual CAN interface.
    Replay {
        project: PathBuf,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long, default_value = "vcan0")]
        interface: String,
    },
    /// List retained automotive evidence for a project.
    Operations {
        project: PathBuf,
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// Compose an evidence-backed automotive campaign report.
    Report {
        project: PathBuf,
        /// Append a grounded provider interpretation when a provider is configured.
        #[arg(long)]
        ai: bool,
        /// Export format used with --output: md, html, pdf, or docx.
        #[arg(long, default_value = "md")]
        format: String,
        /// Write the report to a file instead of printing Markdown to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Report language: en or zh. Defaults to en.
        ///
        /// Named `--report-lang` rather than `--lang` because `--lang` already
        /// means the target's source language on `discover` and `harness`, and
        /// to match `oxfuzz report`.
        #[arg(long, default_value = "en")]
        report_lang: String,
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
    /// Inspect or acknowledge ambiguous one-time occurrences.
    Recovery {
        #[command(subcommand)]
        op: ScheduleRecoveryOp,
    },
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
        /// Trigger kind: interval | cron | once | event.
        #[arg(long)]
        trigger_kind: String,
        /// Trigger value: interval seconds, a cron expr, an RFC3339 time, or an
        /// event type (crash.found, run.completed, run.failed).
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
enum ScheduleRecoveryOp {
    /// List one-time occurrences requiring operator acknowledgement.
    List,
    /// Record an unknown prior outcome as cancelled. This does not terminate a process.
    Acknowledge { occurrence_id: String },
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

#[derive(Subcommand)]
enum ProvidersOp {
    /// Thaw a frozen provider after a verifying health check.
    Thaw {
        /// Provider id (see `oxfuzz providers`).
        id: String,
    },
}

#[derive(Subcommand)]
enum PolicyOp {
    /// List recorded guardrail authorization decisions, newest first.
    Decisions {
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

fn parse_lang(s: &str) -> Result<TargetLanguage, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn parse_engine(s: &str) -> Result<EngineKind, anyhow::Error> {
    s.parse().map_err(|e: String| anyhow::anyhow!(e))
}

fn doctor_lines(status: &hf_service::SystemStatus) -> Vec<String> {
    let required =
        |ready: bool, label: &str| format!("{}  {label}", if ready { "READY" } else { "MISSING" });
    let engine = |ready: bool, label: &str| {
        format!("{}  {label}", if ready { "READY" } else { "UNAVAILABLE" })
    };

    vec![
        required(status.docker.is_ready(), "Docker daemon"),
        required(status.sandbox_image.is_ready(), "sandbox image"),
        engine(status.libfuzzer.is_ready(), "libFuzzer"),
        engine(status.aflplusplus.is_ready(), "AFL++"),
        engine(status.honggfuzz.is_ready(), "honggfuzz"),
        engine(status.syzkaller.is_ready(), "syzkaller"),
        format!(
            "{}  DefectDojo",
            if status.defectdojo.is_ready() {
                "READY"
            } else {
                "OPTIONAL"
            }
        ),
    ]
}

/// One line per provider: readiness state, id, cumulative request/error
/// counts, and the freeze reason when frozen (mirrors `doctor_lines`).
fn provider_status_lines(statuses: &[hf_service::ProviderStatus]) -> Vec<String> {
    statuses
        .iter()
        .map(|s| {
            let state = if s.is_frozen { "FROZEN" } else { "READY" };
            let reason = s
                .freeze_reason
                .as_ref()
                .map_or(String::new(), |r| format!("  (reason: {r})"));
            format!(
                "{state}  {}  requests={} errors={}{reason}",
                s.id.0, s.total_requests, s.total_errors
            )
        })
        .collect()
}

async fn cmd_doctor(json: bool) -> anyhow::Result<()> {
    let status = hf_service::system_status().await;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("oxfuzz sandbox readiness");
        for line in doctor_lines(&status) {
            println!("{line}");
        }
    }

    if !status.fuzzing_ready() {
        anyhow::bail!(
            "fuzzing is not ready: start Docker, build the sandbox image, and verify at least one engine"
        );
    }
    Ok(())
}

async fn cmd_export(project: Option<PathBuf>, output: PathBuf) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let bundle = container.export_project_data(project.as_deref()).await?;
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
async fn start_scheduler() -> Result<CampaignScheduler, CampaignSchedulerError> {
    let container = ServiceContainer::bootstrap().await;
    let store_path = hf_service::init::user_app_dir().join("schedules.json");
    CampaignScheduler::try_start(container, store_path, None).await
}

fn recovery_cli_error(error: CampaignSchedulerError) -> anyhow::Error {
    anyhow::Error::new(error.into_public_recovery_error())
}

async fn cmd_schedule(op: ScheduleOp) -> anyhow::Result<()> {
    let recovery_command = matches!(&op, ScheduleOp::Recovery { .. });
    let scheduler = match start_scheduler().await {
        Ok(scheduler) => scheduler,
        Err(error) if recovery_command => return Err(recovery_cli_error(error)),
        Err(error) => return Err(error.into()),
    };
    match op {
        ScheduleOp::List => {
            let views = scheduler.list_views().await?;
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
        ScheduleOp::Recovery {
            op: ScheduleRecoveryOp::List,
        } => {
            for recovery in scheduler
                .list_one_time_recoveries()
                .await
                .map_err(recovery_cli_error)?
            {
                println!(
                    "{}  {}  {}  {}  {}",
                    recovery.occurrence_id,
                    recovery
                        .schedule_name
                        .as_deref()
                        .unwrap_or("<deleted schedule>"),
                    recovery.triggered_at,
                    recovery.state,
                    recovery
                        .recovery_detail
                        .as_deref()
                        .unwrap_or("unknown outcome"),
                );
            }
        }
        ScheduleOp::Recovery {
            op: ScheduleRecoveryOp::Acknowledge { occurrence_id },
        } => {
            let recovery = scheduler
                .acknowledge_one_time_recovery(&occurrence_id)
                .await
                .map_err(recovery_cli_error)?;
            println!(
                "{} recorded as {}. This did not terminate or adopt an orphaned sandbox process.",
                recovery.occurrence_id, recovery.state,
            );
        }
        ScheduleOp::History { limit } => {
            for e in scheduler.recent_executions(limit).await? {
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
            scheduler.try_create(&name, &params, trigger).await?;
            println!("Created schedule '{name}'.");
        }
        ScheduleOp::Delete { id } => {
            let msg = if scheduler.try_remove(&id).await? {
                "Deleted."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
        ScheduleOp::Enable { id } => {
            let msg = if scheduler.try_set_enabled(&id, true).await? {
                "Enabled."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
        ScheduleOp::Disable { id } => {
            let msg = if scheduler.try_set_enabled(&id, false).await? {
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

async fn cmd_providers(op: Option<ProvidersOp>) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        None => {
            let statuses = container.provider_statuses().await;
            if statuses.is_empty() {
                println!("No providers configured.");
            } else {
                for line in provider_status_lines(&statuses) {
                    println!("{line}");
                }
            }
        }
        Some(ProvidersOp::Thaw { id }) => {
            container.thaw_provider(&id).await?;
            println!("Provider '{id}' passed the health check and was thawed.");
        }
    }
    Ok(())
}

async fn cmd_policy(op: PolicyOp) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        PolicyOp::Decisions { limit } => {
            let decisions = container.policy_decisions(limit).await?;
            if decisions.is_empty() {
                println!("No guardrail decisions recorded.");
            }
            for d in decisions {
                let detail = d.detail.map(|s| format!("  ({s})")).unwrap_or_default();
                println!(
                    "{}  {}  {}  {}  {}{detail}",
                    d.decided_at.to_rfc3339(),
                    d.decision,
                    d.risk_tier,
                    d.action,
                    d.origin,
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(feature = "semgrep-enrichment"))]
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

#[cfg(feature = "semgrep-enrichment")]
async fn bootstrap_discover_service<S, Bootstrap, BootstrapFuture>(
    lang: &str,
    bootstrap: Bootstrap,
) -> anyhow::Result<(TargetLanguage, S)>
where
    Bootstrap: FnOnce() -> BootstrapFuture,
    BootstrapFuture: std::future::Future<Output = S>,
{
    let language = parse_lang(lang)?;
    let service = bootstrap().await;
    Ok((language, service))
}

#[cfg(feature = "semgrep-enrichment")]
async fn cmd_discover(
    project: PathBuf,
    lang: &str,
    rank: bool,
    semgrep: bool,
) -> anyhow::Result<()> {
    let (language, container) =
        bootstrap_discover_service(lang, ServiceContainer::bootstrap).await?;
    let mut output = ConsoleDiscoverOutput;
    run_discover_command(
        &container,
        project,
        language,
        rank,
        semgrep,
        &mut output,
        tokio::signal::ctrl_c(),
        || tokio::time::sleep(std::time::Duration::from_millis(250)),
    )
    .await
}

#[cfg(feature = "semgrep-enrichment")]
#[async_trait::async_trait]
trait DiscoverCommandService {
    async fn discover_targets(
        &self,
        project: &std::path::Path,
        language: TargetLanguage,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError>;

    async fn rank_targets(
        &self,
        inventory: hf_service::TargetInventory,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError>;

    fn has_provider(&self) -> bool;

    async fn start_semgrep(
        &self,
        project: PathBuf,
        language: TargetLanguage,
    ) -> Result<uuid::Uuid, hf_service::ClassifiedError>;

    async fn semgrep_status(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<Option<hf_service::SemgrepOperationView>, hf_service::ClassifiedError>;

    async fn cancel_semgrep(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<hf_service::SemgrepCancelOutcome, hf_service::ClassifiedError>;
}

#[cfg(feature = "semgrep-enrichment")]
#[async_trait::async_trait]
impl DiscoverCommandService for ServiceContainer {
    async fn discover_targets(
        &self,
        project: &std::path::Path,
        language: TargetLanguage,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError> {
        self.discover(project, language).await
    }

    async fn rank_targets(
        &self,
        inventory: hf_service::TargetInventory,
    ) -> Result<hf_service::TargetInventory, hf_service::ClassifiedError> {
        self.rank(inventory).await
    }

    fn has_provider(&self) -> bool {
        self.provider_pool().is_some()
    }

    async fn start_semgrep(
        &self,
        project: PathBuf,
        language: TargetLanguage,
    ) -> Result<uuid::Uuid, hf_service::ClassifiedError> {
        self.start_semgrep_enrichment(project, language).await
    }

    async fn semgrep_status(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<Option<hf_service::SemgrepOperationView>, hf_service::ClassifiedError> {
        self.semgrep_operation(operation_id).await
    }

    async fn cancel_semgrep(
        &self,
        operation_id: uuid::Uuid,
    ) -> Result<hf_service::SemgrepCancelOutcome, hf_service::ClassifiedError> {
        self.request_semgrep_cancel(operation_id).await
    }
}

#[cfg(feature = "semgrep-enrichment")]
trait DiscoverCommandOutput {
    fn stdout_line(&mut self, line: String);
    fn stderr_line(&mut self, line: String);
}

#[cfg(feature = "semgrep-enrichment")]
struct ConsoleDiscoverOutput;

#[cfg(feature = "semgrep-enrichment")]
impl DiscoverCommandOutput for ConsoleDiscoverOutput {
    fn stdout_line(&mut self, line: String) {
        println!("{line}");
    }

    fn stderr_line(&mut self, line: String) {
        eprintln!("{line}");
    }
}

#[cfg(feature = "semgrep-enrichment")]
enum SemgrepPollAction {
    Continue,
    Complete(hf_service::SemgrepInventoryView),
    Fail(String),
}

#[cfg(feature = "semgrep-enrichment")]
fn semgrep_state_name(state: hf_service::SemgrepOperationState) -> &'static str {
    match state {
        hf_service::SemgrepOperationState::Staging => "staging",
        hf_service::SemgrepOperationState::Scanning => "scanning",
        hf_service::SemgrepOperationState::Validating => "validating",
        hf_service::SemgrepOperationState::Persisting => "persisting",
        hf_service::SemgrepOperationState::Done => "done",
        hf_service::SemgrepOperationState::Failed => "failed",
        hf_service::SemgrepOperationState::Cancelled => "cancelled",
    }
}

#[cfg(feature = "semgrep-enrichment")]
fn semgrep_poll_action(view: hf_service::SemgrepOperationView) -> SemgrepPollAction {
    match view.state {
        hf_service::SemgrepOperationState::Done => match view.result {
            Some(result) => SemgrepPollAction::Complete(result),
            None => SemgrepPollAction::Fail(
                "Semgrep enrichment completed without an exact result".to_owned(),
            ),
        },
        hf_service::SemgrepOperationState::Failed
        | hf_service::SemgrepOperationState::Cancelled => {
            SemgrepPollAction::Fail(view.failure_message.unwrap_or_else(|| {
                format!("Semgrep enrichment {}", semgrep_state_name(view.state))
            }))
        }
        _ => SemgrepPollAction::Continue,
    }
}

#[cfg(feature = "semgrep-enrichment")]
async fn wait_for_semgrep<S, O, Signal, Delay, DelayFuture>(
    service: &S,
    operation_id: uuid::Uuid,
    output: &mut O,
    mut signal: std::pin::Pin<&mut Signal>,
    delay: &mut Delay,
) -> anyhow::Result<hf_service::SemgrepInventoryView>
where
    S: DiscoverCommandService,
    O: DiscoverCommandOutput,
    Signal: std::future::Future<Output = std::io::Result<()>>,
    Delay: FnMut() -> DelayFuture,
    DelayFuture: std::future::Future<Output = ()>,
{
    let mut previous_state = None;
    let mut cancellation_requested = false;
    loop {
        let status = if cancellation_requested {
            service.semgrep_status(operation_id).await?
        } else {
            tokio::select! {
                signal_result = signal.as_mut() => {
                    signal_result?;
                    output.stderr_line("Semgrep enrichment: cancellation requested".to_owned());
                    let _ = service.cancel_semgrep(operation_id).await?;
                    cancellation_requested = true;
                    continue;
                }
                status = service.semgrep_status(operation_id) => status?,
            }
        };
        let view = status
            .ok_or_else(|| anyhow::anyhow!("Semgrep operation {operation_id} was not found"))?;
        if previous_state != Some(view.state) {
            output.stderr_line(format!(
                "Semgrep enrichment: {}",
                semgrep_state_name(view.state)
            ));
            previous_state = Some(view.state);
        }
        match semgrep_poll_action(view) {
            SemgrepPollAction::Continue => {}
            SemgrepPollAction::Complete(result) => return Ok(result),
            SemgrepPollAction::Fail(message) => anyhow::bail!("{message}"),
        }

        if cancellation_requested {
            delay().await;
        } else {
            let delay_future = delay();
            tokio::pin!(delay_future);
            tokio::select! {
                () = &mut delay_future => {}
                signal_result = signal.as_mut() => {
                    signal_result?;
                    output.stderr_line("Semgrep enrichment: cancellation requested".to_owned());
                    let _ = service.cancel_semgrep(operation_id).await?;
                    cancellation_requested = true;
                }
            }
        }
    }
}

#[cfg(feature = "semgrep-enrichment")]
async fn run_discover_command<S, O, Signal, Delay, DelayFuture>(
    service: &S,
    project: PathBuf,
    language: TargetLanguage,
    rank: bool,
    semgrep: bool,
    output: &mut O,
    signal: Signal,
    mut delay: Delay,
) -> anyhow::Result<()>
where
    S: DiscoverCommandService,
    O: DiscoverCommandOutput,
    Signal: std::future::Future<Output = std::io::Result<()>>,
    Delay: FnMut() -> DelayFuture,
    DelayFuture: std::future::Future<Output = ()>,
{
    let mut inventory = service.discover_targets(&project, language).await?;
    if rank {
        if service.has_provider() {
            inventory = service.rank_targets(inventory).await?;
        } else {
            output.stderr_line(
                "warning: --rank requested but HF_PROVIDER_API_KEY not set; using heuristic scores only"
                    .to_owned(),
            );
        }
    }
    if !semgrep {
        output.stdout_line(serde_json::to_string_pretty(&inventory)?);
        return Ok(());
    }
    if !matches!(language, TargetLanguage::C | TargetLanguage::Cpp) {
        anyhow::bail!("Semgrep enrichment supports only C and C++ target inventories");
    }
    let operation_id = service.start_semgrep(project, language).await?;
    tokio::pin!(signal);
    let result =
        wait_for_semgrep(service, operation_id, output, signal.as_mut(), &mut delay).await?;
    output.stderr_line("Semgrep static-analysis signals".to_owned());
    output.stdout_line(serde_json::to_string_pretty(&result)?);
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
    // --draft-only stops before compile/smoke/promotion, so flags that only
    // take effect in those stages must not be silently ignored. (--refine is
    // exempt: it honors --repair during its recompile.)
    if draft_only && !refine && repair > 0 {
        eprintln!("warning: --repair is ignored with --draft-only (the harness is not compiled)");
    }
    if draft_only && promote {
        eprintln!("warning: --promote is ignored with --draft-only (no smoke qualification runs)");
    }
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
        smoke.summary.execs_per_sec, smoke.summary.crashes, smoke.summary.passed
    );
    // Surface the deterministic verdict so a hollow pass -- compiled and "passed"
    // yet never actually exercising the target -- is not silently promoted.
    match smoke.verdict.level {
        VerdictLevel::Pass => {}
        VerdictLevel::Suspect => println!(
            "  SUSPECT (verify before promoting): {}",
            smoke.verdict.reasons.join("; ")
        ),
        VerdictLevel::Fail => {
            println!("  FAIL: {}", smoke.verdict.reasons.join("; "));
        }
    }
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
    target: Option<&str>,
    engine: Option<&str>,
    lang: &str,
    duration: Option<&str>,
    replay: Option<&str>,
) -> anyhow::Result<()> {
    let container = std::sync::Arc::new(ServiceContainer::bootstrap().await);
    let on_progress = |p: FuzzProgress| match p {
        FuzzProgress::LogLine(line) => println!("  {line}"),
        FuzzProgress::CrashesFound(_) => println!("  >> crash found"),
        _ => {}
    };

    let summary = if let Some(run_id) = replay {
        // Replay pins the recorded engine/duration/seed; target/engine/duration
        // flags are intentionally not required in this mode.
        let run_id = uuid::Uuid::parse_str(run_id)
            .map_err(|e| anyhow::anyhow!("invalid --replay run id {run_id:?}: {e}"))?;
        println!("\n--- Replaying run {run_id} (live, Ctrl-C to stop) ---");
        let mut handle = {
            let container = std::sync::Arc::clone(&container);
            tokio::spawn(async move { container.replay_run(run_id, &on_progress).await })
        };
        tokio::select! {
            res = &mut handle => res?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n--- Ctrl-C received: cancelling run ---");
                container.cancel_all_runs();
                handle.await?
            }
        }?
    } else {
        let (Some(target), Some(engine)) = (target, engine) else {
            anyhow::bail!("--target and --engine are required unless --replay is given");
        };
        let engine_kind = parse_engine(engine)?;
        // `run` drives the already-built harness, which carries its own language, so
        // the value is not threaded further. Still validate it (like triage/ci) so an
        // invalid `--lang` is rejected up front rather than silently ignored.
        parse_lang(lang)?;
        let duration_secs = duration.map(parse_duration).transpose()?.unwrap_or(3600);
        // Ensure a seed corpus exists before running. A failure here is not fatal
        // (the engine can still run on an empty corpus) but must not be silent.
        if let Err(e) = container.generate_seeds(&project, target).await {
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
                container
                    .run_fuzzer(&project, &target, engine_kind, duration_secs, &on_progress)
                    .await
            })
        };
        tokio::select! {
            res = &mut handle => res?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n--- Ctrl-C received: cancelling run ---");
                container.cancel_all_runs();
                handle.await?
            }
        }?
    };
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
    // Advisory per-crash LLM verdict (best-effort: None when no provider is
    // configured; the verdict never reclassifies a crash, only informs review).
    let verdicts = container.verify_crashes(target, &crashes).await;
    let reports: Vec<serde_json::Value> = crashes
        .iter()
        .zip(verdicts)
        .map(|(c, verdict)| {
            serde_json::json!({
                "id": c.id,
                "kind": format!("{:?}", c.kind),
                "summary": c.summary,
                "stack_signature": c.stack_signature,
                "input_path": c.input_path,
                "minimized": c.minimized,
                "verdict": verdict,
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
            let n = container.corpus_prune(&project, target).await?;
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
    let container = ServiceContainer::bootstrap().await;

    println!("[ci] requiring a previously smoke-qualified and promoted harness for {target}...");
    println!("[ci] fuzzing {target} for {duration_secs}s...");
    let on_progress = |p: FuzzProgress| {
        if let FuzzProgress::CrashesFound(_) = p {
            println!("[ci] >> crash found");
        }
    };
    let outcome = container
        .run_ci_gate(
            hf_service::sarif::CiGateRequest {
                project: &project,
                target,
                engine: engine_kind,
                duration_secs,
            },
            &on_progress,
        )
        .await?;
    if let Some(warning) = &outcome.seed_warning {
        eprintln!("[ci] warning: seed generation failed: {warning}");
    }

    // Always emit SARIF (even with zero results) so code scanning can clear
    // stale alerts when a bug is fixed.
    std::fs::write(sarif, &outcome.sarif)?;
    println!("[ci] SARIF written to {}", sarif.display());

    if outcome.passed() {
        println!("[ci] PASS: no crashes found.");
        Ok(())
    } else {
        eprintln!("[ci] FAIL: {} crash(es) found.", outcome.findings.len());
        for finding in &outcome.findings {
            eprintln!("[ci]   {}: {}", finding.kind, finding.summary);
        }
        anyhow::bail!("CI fuzzing gate found crashing inputs")
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

async fn cmd_repro(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    crash: Option<&str>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    let dir = container
        .export_repro_bundle_for_latest(&project, target, engine, lang, crash, out)
        .await?;
    println!("Reproduction bundle written to {}", dir.display());
    println!("  Build and reproduce: see {}/REPRODUCE.md", dir.display());
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
    let fixed = results
        .iter()
        .filter(|r| r.verified && !r.still_crashes)
        .count();
    let inconclusive = results.iter().filter(|r| !r.verified).count();
    println!(
        "Replayed {} crash(es): {still} still crashing, {fixed} fixed, {inconclusive} inconclusive.",
        results.len(),
    );
    for r in &results {
        let tag = if r.still_crashes {
            "STILL CRASHES"
        } else if !r.verified {
            "INCONCLUSIVE"
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
        .run_campaign(&project, target, engine, lang, duration_secs, iterations)
        .await?;
    println!(
        "target={} harness={:?} iterations={} edges={} crashes={} termination={:?}",
        outcome.target,
        outcome.harness_status,
        outcome.iterations,
        outcome.edges,
        outcome.crashes,
        outcome.termination
    );
    if let Some(refine) = &outcome.refine {
        // A coverage plateau proposed a targeted refined harness. It is only
        // Compiled (never promoted/auto-run); the operator reviews and promotes.
        println!("  coverage-plateau refine: {}", refine.note);
    }
    Ok(())
}

/// The single service call `oxfuzz report` makes. Behind a trait so a test can
/// observe the language the command hands over without bootstrapping a real
/// container -- the parse and the hand-off are otherwise unobservable together.
#[async_trait::async_trait]
trait ReportCommandService {
    async fn compose_report(
        &self,
        project: &std::path::Path,
        target: &str,
        language: hf_service::ReportLanguage,
    ) -> Result<String, hf_service::ClassifiedError>;
}

#[async_trait::async_trait]
impl ReportCommandService for ServiceContainer {
    async fn compose_report(
        &self,
        project: &std::path::Path,
        target: &str,
        language: hf_service::ReportLanguage,
    ) -> Result<String, hf_service::ClassifiedError> {
        self.generate_report(project, target, language).await
    }
}

/// Parse the language, build the service, compose, then emit. `bootstrap` is
/// injected rather than called directly so the whole path -- flag string in,
/// `ReportLanguage` at the service boundary, document out -- is one testable
/// unit, and so a rejected language is provably free of bootstrap side effects.
async fn run_report_command<S, Bootstrap, BootstrapFuture>(
    project: &std::path::Path,
    target: &str,
    out: Option<&std::path::Path>,
    lang: &str,
    bootstrap: Bootstrap,
) -> anyhow::Result<()>
where
    S: ReportCommandService + Sync,
    Bootstrap: FnOnce() -> BootstrapFuture,
    BootstrapFuture: std::future::Future<Output = S>,
{
    // An unknown identifier is rejected here, before any composition work.
    let language = lang.parse::<hf_service::ReportLanguage>()?;
    let service = bootstrap().await;
    let markdown = service.compose_report(project, target, language).await?;
    match out {
        Some(path) => {
            std::fs::write(path, &markdown)?;
            println!("Report written to {}", path.display());
        }
        None => println!("{markdown}"),
    }
    Ok(())
}

async fn cmd_report(
    project: PathBuf,
    target: &str,
    out: Option<&std::path::Path>,
    lang: &str,
) -> anyhow::Result<()> {
    run_report_command(&project, target, out, lang, ServiceContainer::bootstrap).await
}

/// Parse a comma-separated list of unsigned integers, each decimal or `0x` hex.
#[cfg(feature = "automotive-scapy")]
fn parse_u32_list(input: &str) -> anyhow::Result<Vec<u32>> {
    input
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(|token| {
            token
                .strip_prefix("0x")
                .or_else(|| token.strip_prefix("0X"))
                .map_or_else(|| token.parse::<u32>(), |hex| u32::from_str_radix(hex, 16))
                .map_err(|_| anyhow::anyhow!("invalid integer '{token}'"))
        })
        .collect()
}

#[cfg(feature = "automotive-scapy")]
fn parse_automotive_protocol(
    value: &str,
) -> anyhow::Result<hf_service::automotive::AutomotiveProtocol> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| anyhow::anyhow!("invalid automotive protocol '{value}': {error}"))
}

#[cfg(feature = "automotive-scapy")]
fn parse_automotive_mode(value: &str) -> anyhow::Result<hf_service::automotive::AutomotiveMode> {
    let mode = serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| anyhow::anyhow!("invalid automotive mode '{value}': {error}"))?;
    if mode == hf_service::automotive::AutomotiveMode::OfflinePcap {
        anyhow::bail!("replay plans must target virtual_can or physical_bench");
    }
    Ok(mode)
}

#[cfg(feature = "automotive-scapy")]
fn parse_virtual_replay_plan(encoded: &str) -> anyhow::Result<hf_service::automotive::ReplayPlan> {
    let plan: hf_service::automotive::ReplayPlan = serde_json::from_str(encoded)
        .map_err(|error| anyhow::anyhow!("invalid automotive replay plan: {error}"))?;
    if plan.mode != hf_service::automotive::AutomotiveMode::VirtualCan {
        anyhow::bail!("the CLI replay command accepts only virtual_can plans");
    }
    Ok(plan)
}

#[cfg(feature = "automotive-scapy")]
async fn cmd_automotive(op: AutomotiveOp) -> anyhow::Result<()> {
    use hf_service::automotive::{
        AutomotiveCommand, AutomotiveOperationRequest, AutomotiveOperationSummary,
    };

    match op {
        AutomotiveOp::Settings => {
            let settings = hf_service::config::AutomotiveConfigStore::default()
                .get()
                .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        command @ (AutomotiveOp::Enable | AutomotiveOp::Disable) => {
            let enabled = matches!(command, AutomotiveOp::Enable);
            let store = hf_service::config::AutomotiveConfigStore::default();
            let mut settings = store.get().map_err(anyhow::Error::msg)?;
            settings.enabled = enabled;
            let settings = store.set(settings).map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        AutomotiveOp::Capabilities { project } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::Capabilities,
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Analyze {
            project,
            protocol,
            capture,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::AnalyzeCapture {
                        protocol: parse_automotive_protocol(&protocol)?,
                        capture_path: capture,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Import {
            capture,
            format,
            dbc,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let import = container.automotive_import_capture(&capture, &format, dbc.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&import)?);
        }
        AutomotiveOp::Diff {
            first,
            second,
            format,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let diff = container.automotive_diff_captures(&first, &second, &format)?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        AutomotiveOp::Monitor {
            project,
            interface,
            protocol,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::LiveMonitor {
                        mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                        protocol: parse_automotive_protocol(&protocol)?,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Scan {
            project,
            interface,
            request_ids,
            services,
        } => {
            let request_ids = parse_u32_list(&request_ids)?;
            let services = parse_u32_list(&services)?
                .into_iter()
                .map(|value| {
                    u8::try_from(value)
                        .map_err(|_| anyhow::anyhow!("service id out of range: {value}"))
                })
                .collect::<anyhow::Result<Vec<u8>>>()?;
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::ScanUds {
                        mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                        protocol: parse_automotive_protocol("uds")?,
                        request_ids,
                        services,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Mutate {
            project,
            protocol,
            source,
            count,
            seed,
            media_type,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::GenerateMutations {
                        protocol: parse_automotive_protocol(&protocol)?,
                        source_path: source,
                        deterministic_seed: seed,
                        mutation_count: count,
                        media_type,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Plan {
            project,
            protocol,
            source,
            mode,
            seed,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::BuildReplayPlan {
                        protocol: parse_automotive_protocol(&protocol)?,
                        source_path: source,
                        target_mode: parse_automotive_mode(&mode)?,
                        deterministic_seed: seed,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Replay {
            project,
            plan,
            interface,
        } => {
            let encoded = std::fs::read_to_string(&plan).map_err(|error| {
                anyhow::anyhow!("read automotive replay plan {}: {error}", plan.display())
            })?;
            let plan = parse_virtual_replay_plan(&encoded)?;
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::ExecuteReplay {
                        mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                        plan,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Operations { project, limit } => {
            let container = ServiceContainer::bootstrap().await;
            let operations: Vec<AutomotiveOperationSummary> = container
                .list_automotive_operations(&project, limit)
                .await?;
            println!("{}", serde_json::to_string_pretty(&operations)?);
        }
        AutomotiveOp::Report {
            project,
            ai,
            format,
            output,
            report_lang,
        } => {
            run_automotive_report_command(
                &project,
                ai,
                &format,
                output.as_deref(),
                &report_lang,
                &mut std::io::stdout(),
                ServiceContainer::bootstrap,
            )
            .await?;
        }
    }
    Ok(())
}

/// The two service calls `oxfuzz automotive report` makes. Behind a trait so a
/// test can observe the language the command hands over and the title it
/// exports under, without bootstrapping a real container.
#[cfg(feature = "automotive-scapy")]
#[async_trait::async_trait]
trait AutomotiveReportCommandService {
    async fn compose_automotive_report(
        &self,
        project: &std::path::Path,
        include_ai: bool,
        language: hf_service::ReportLanguage,
    ) -> Result<hf_service::automotive_report::AutomotiveCampaignReport, hf_service::ClassifiedError>;

    fn export_automotive_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &std::path::Path,
        language: hf_service::ReportLanguage,
    ) -> Result<(), hf_service::ClassifiedError>;
}

#[cfg(feature = "automotive-scapy")]
#[async_trait::async_trait]
impl AutomotiveReportCommandService for ServiceContainer {
    async fn compose_automotive_report(
        &self,
        project: &std::path::Path,
        include_ai: bool,
        language: hf_service::ReportLanguage,
    ) -> Result<hf_service::automotive_report::AutomotiveCampaignReport, hf_service::ClassifiedError>
    {
        self.generate_automotive_report(project, include_ai, language)
            .await
    }

    fn export_automotive_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &std::path::Path,
        language: hf_service::ReportLanguage,
    ) -> Result<(), hf_service::ClassifiedError> {
        self.export_markdown(markdown, title, format, out_path, language)
    }
}

/// Parse the language, build the service, compose, then emit. `bootstrap` is
/// injected for the same reason `run_report_command` injects it: the whole path
/// -- flag string in, `ReportLanguage` at the service boundary, document out --
/// becomes one testable unit. `sink` is the emission target for the same
/// reason: without it neither the printed Markdown nor the printed export path
/// is observable, so deleting either changes nothing a test can see.
#[cfg(feature = "automotive-scapy")]
async fn run_automotive_report_command<S, Bootstrap, BootstrapFuture>(
    project: &std::path::Path,
    include_ai: bool,
    format: &str,
    output: Option<&std::path::Path>,
    lang: &str,
    sink: &mut dyn std::io::Write,
    bootstrap: Bootstrap,
) -> anyhow::Result<()>
where
    S: AutomotiveReportCommandService + Sync,
    Bootstrap: FnOnce() -> BootstrapFuture,
    BootstrapFuture: std::future::Future<Output = S>,
{
    // An unknown identifier is rejected here, before any composition work.
    let language = lang.parse::<hf_service::ReportLanguage>()?;
    let service = bootstrap().await;
    let report = service
        .compose_automotive_report(project, include_ai, language)
        .await?;
    if let Some(output) = output {
        // The exported document's title is metadata rather than report body
        // content, so the renderer never writes it -- but it is still prose, and
        // is assembled from the same label set the body was rendered from
        // instead of from a second literal that only one language could satisfy.
        let labels = hf_service::automotive_report::AutomotiveLabels::for_language(language);
        let title = format!(
            "{}{}{}",
            labels.title_prefix, labels.label_colon, report.project_name
        );
        // The report was composed here, so its language is known and the
        // exported document declares it rather than the global English default.
        service.export_automotive_markdown(&report.markdown, &title, format, output, language)?;
        writeln!(sink, "{}", output.display())?;
    } else {
        if !matches!(format, "md" | "markdown") {
            anyhow::bail!("--format requires --output for automotive reports");
        }
        writeln!(sink, "{}", report.markdown)?;
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
            println!("Initialized oxfuzz workspace.");
            println!("  config dir: {}", report.config_dir.display());
            if report.created_configs.is_empty() {
                println!("  config: all files already present");
            } else {
                println!("  created: {}", report.created_configs.join(", "));
            }
            println!("  database: {}", report.db_path.display());
        }
        Commands::Doctor { json } => cmd_doctor(json).await?,
        Commands::Discover {
            project,
            lang,
            rank,
            #[cfg(feature = "semgrep-enrichment")]
            semgrep,
        } => {
            cmd_discover(
                project,
                &lang,
                rank,
                #[cfg(feature = "semgrep-enrichment")]
                semgrep,
            )
            .await?;
        }
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
            replay,
        } => {
            cmd_run(
                project,
                target.as_deref(),
                engine.as_deref(),
                &lang,
                duration.as_deref(),
                replay.as_deref(),
            )
            .await?;
        }
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
        Commands::Repro {
            project,
            target,
            engine,
            lang,
            crash,
            out,
        } => cmd_repro(project, &target, &engine, &lang, crash.as_deref(), &out).await?,
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
            report_lang,
        } => cmd_report(project, &target, out.as_deref(), &report_lang).await?,
        Commands::Serve { host, port } => {
            let security = hf_web::WebSecurityConfig::from_env();
            let addr = std::net::SocketAddr::new(host, port);
            hf_web::validate_bind_addr(addr, security.token_configured())?;
            let app = hf_web::build_bootstrapped_with_security(security).await?;
            println!("oxfuzz web server listening on http://{addr}");
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
        Commands::Providers { op } => cmd_providers(op).await?,
        Commands::Policy { op } => cmd_policy(op).await?,
        #[cfg(feature = "automotive-scapy")]
        Commands::Automotive { op } => cmd_automotive(op).await?,
    }
    Ok(())
}

#[cfg(all(test, feature = "automotive-scapy"))]
mod automotive_tests {
    use clap::Parser as _;

    use super::{parse_virtual_replay_plan, AutomotiveOp, Cli, Commands};

    fn plan(mode: &str) -> String {
        format!(
            r#"{{"protocol":"uds","mode":"{mode}","deterministic_seed":7,"steps":[{{"sequence":0,"delay_micros":0,"action":"send","message":{{"protocol":"uds","payload_hex":"221234","fields":{{"arbitration_id":"0x7e0","service":"0x22"}}}}}}]}}"#
        )
    }

    #[test]
    fn cli_replay_accepts_only_typed_virtual_can_plans() {
        let parsed = parse_virtual_replay_plan(&plan("virtual_can")).unwrap();
        assert_eq!(parsed.steps.len(), 1);

        let error = parse_virtual_replay_plan(&plan("physical_bench")).unwrap_err();
        assert!(error.to_string().contains("virtual_can"));

        assert!(parse_virtual_replay_plan("{not-json").is_err());
    }

    #[test]
    fn cli_exposes_ai_assisted_automotive_report_export() {
        let cli = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "report",
            "/tmp/project",
            "--ai",
            "--format",
            "html",
            "--output",
            "/tmp/automotive-report.html",
        ])
        .unwrap();

        let Commands::Automotive {
            op:
                AutomotiveOp::Report {
                    project,
                    ai,
                    format,
                    output,
                    report_lang,
                },
        } = cli.command
        else {
            panic!("expected the automotive report command");
        };
        assert_eq!(project, std::path::PathBuf::from("/tmp/project"));
        assert!(ai);
        assert_eq!(format, "html");
        assert_eq!(
            output,
            Some(std::path::PathBuf::from("/tmp/automotive-report.html"))
        );
        // Omitting the flag composes in English, so an existing invocation is
        // unaffected.
        assert_eq!(report_lang, "en");
    }

    #[test]
    fn the_automotive_report_language_flag_does_not_collide_with_the_source_language() {
        // `--lang` already means the target's *source* language on `discover`
        // and `harness`. The report language is a separate axis and takes its
        // own name, matching `oxfuzz report`.
        let cli = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "report",
            "/tmp/project",
            "--report-lang",
            "zh",
        ])
        .unwrap();

        let Commands::Automotive {
            op: AutomotiveOp::Report { report_lang, .. },
        } = cli.command
        else {
            panic!("expected the automotive report command");
        };
        assert_eq!(
            report_lang.parse::<hf_service::ReportLanguage>().unwrap(),
            hf_service::ReportLanguage::Zh
        );

        assert!(
            Cli::try_parse_from([
                "oxfuzz",
                "automotive",
                "report",
                "/tmp/project",
                "--lang",
                "zh"
            ])
            .is_err(),
            "--lang must not silently be accepted as the report language"
        );
    }
}

#[cfg(all(test, feature = "automotive-scapy"))]
mod automotive_report_cli_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use hf_service::automotive_report::{AutomotiveCampaignReport, AutomotiveReportAiStatus};

    use super::{run_automotive_report_command, AutomotiveReportCommandService};

    /// Everything the command handed to the service, so each argument it
    /// forwards can be asserted on its own.
    #[derive(Clone, Debug, Default)]
    struct Handoff {
        language: Option<hf_service::ReportLanguage>,
        include_ai: Option<bool>,
        exported_title: Option<String>,
        exported_format: Option<String>,
        exported_language: Option<hf_service::ReportLanguage>,
    }

    /// Records what the command handed to the service.
    #[derive(Default)]
    struct RecordingAutomotiveReportService {
        handoff: Arc<Mutex<Handoff>>,
    }

    #[async_trait::async_trait]
    impl AutomotiveReportCommandService for RecordingAutomotiveReportService {
        async fn compose_automotive_report(
            &self,
            _project: &std::path::Path,
            include_ai: bool,
            language: hf_service::ReportLanguage,
        ) -> Result<AutomotiveCampaignReport, hf_service::ClassifiedError> {
            {
                let mut handoff = self.handoff.lock().unwrap();
                handoff.language = Some(language);
                handoff.include_ai = Some(include_ai);
            }
            Ok(AutomotiveCampaignReport {
                generated_at: "2026-07-16T09:00:00Z".to_owned(),
                project_name: "vehicle-gateway".to_owned(),
                ai_status: AutomotiveReportAiStatus::NotRequested,
                ai_model: None,
                operation_count: 0,
                failed_operation_count: 0,
                unique_state_count: 0,
                promoted_state_count: 0,
                markdown: format!("# composed as {language:?}\n"),
            })
        }

        fn export_automotive_markdown(
            &self,
            _markdown: &str,
            title: &str,
            format: &str,
            _out_path: &std::path::Path,
            language: hf_service::ReportLanguage,
        ) -> Result<(), hf_service::ClassifiedError> {
            let mut handoff = self.handoff.lock().unwrap();
            handoff.exported_title = Some(title.to_owned());
            handoff.exported_format = Some(format.to_owned());
            handoff.exported_language = Some(language);
            Ok(())
        }
    }

    /// Drive the command and return what the service saw alongside everything
    /// written to the command's emission sink.
    async fn drive(
        include_ai: bool,
        format: &str,
        output: Option<&std::path::Path>,
        flag: &str,
    ) -> anyhow::Result<(Handoff, String)> {
        let service = RecordingAutomotiveReportService::default();
        let handoff = Arc::clone(&service.handoff);
        let mut sink = Vec::new();

        run_automotive_report_command(
            std::path::Path::new("/tmp/project"),
            include_ai,
            format,
            output,
            flag,
            &mut sink,
            move || std::future::ready(service),
        )
        .await?;

        let recorded = handoff.lock().unwrap().clone();
        Ok((recorded, String::from_utf8(sink).unwrap()))
    }

    /// Drive the export path and report the language the service saw together
    /// with the title the document was exported under.
    async fn export_under(flag: &str) -> (hf_service::ReportLanguage, String) {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("report.html");
        let (handoff, emitted) = drive(false, "html", Some(&out), flag).await.unwrap();

        // The export path reports where it wrote. Deleting that line would
        // otherwise be invisible.
        assert_eq!(emitted, format!("{}\n", out.display()));
        (
            handoff.language.unwrap(),
            handoff.exported_title.clone().unwrap(),
        )
    }

    #[tokio::test]
    async fn the_report_language_flag_reaches_the_service() {
        // The hand-off, not the parse: `--report-lang zh` must arrive at
        // generate_automotive_report rather than being parsed and discarded.
        assert_eq!(export_under("zh").await.0, hf_service::ReportLanguage::Zh);
        assert_eq!(export_under("en").await.0, hf_service::ReportLanguage::En);
    }

    #[tokio::test]
    async fn the_exported_document_title_follows_the_report_language() {
        // The title is document metadata the renderer never writes, so it is
        // the one piece of prose on this path that a second English literal
        // could leave behind on a Chinese report.
        assert_eq!(
            export_under("zh").await.1,
            "汽车协议模糊测试活动报告：vehicle-gateway"
        );
        // Byte-identical to the literal it replaced: the English export does
        // not move.
        assert_eq!(
            export_under("en").await.1,
            "Automotive Fuzzing Campaign Report: vehicle-gateway"
        );
    }

    #[tokio::test]
    async fn the_exported_document_declares_the_report_language() {
        // The title being Chinese does not make the document Chinese. The
        // `lang` attribute assistive technology reads comes from this argument,
        // and until it was threaded a Chinese report was served as English.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("report.html");

        let (chinese, _) = drive(false, "html", Some(&out), "zh").await.unwrap();
        assert_eq!(
            chinese.exported_language,
            Some(hf_service::ReportLanguage::Zh)
        );
        // And the format reaches the export unchanged, so the assertion above
        // cannot be satisfied by an export that ignored its arguments.
        assert_eq!(chinese.exported_format.as_deref(), Some("html"));

        let (english, _) = drive(false, "html", Some(&out), "en").await.unwrap();
        assert_eq!(
            english.exported_language,
            Some(hf_service::ReportLanguage::En)
        );
    }

    #[tokio::test]
    async fn the_ai_flag_reaches_the_service() {
        // `--ai` is the difference between a deterministic fact sheet and one
        // carrying a provider interpretation. Silently ignoring it would have
        // passed every other test here.
        assert_eq!(
            drive(true, "md", None, "en").await.unwrap().0.include_ai,
            Some(true)
        );
        assert_eq!(
            drive(false, "md", None, "en").await.unwrap().0.include_ai,
            Some(false)
        );
    }

    #[tokio::test]
    async fn the_stdout_path_emits_the_composed_markdown() {
        let (handoff, emitted) = drive(false, "md", None, "zh").await.unwrap();
        assert_eq!(handoff.language, Some(hf_service::ReportLanguage::Zh));
        assert_eq!(emitted, "# composed as Zh\n\n");
        // Nothing was exported: the stdout path must not write a file.
        assert_eq!(handoff.exported_title, None);
    }

    #[tokio::test]
    async fn a_non_markdown_format_without_an_output_path_is_rejected() {
        // A user-facing error: `--format html` alone silently printing Markdown
        // would be worse than refusing.
        for format in ["html", "pdf", "docx"] {
            let error = drive(false, format, None, "en").await.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("--format requires --output for automotive reports"),
                "{format}: {error}"
            );
        }
        // And the two formats that mean Markdown are accepted.
        for format in ["md", "markdown"] {
            assert!(drive(false, format, None, "en").await.is_ok(), "{format}");
        }
    }

    #[tokio::test]
    async fn an_unknown_report_language_is_rejected_before_any_bootstrap() {
        let bootstrapped = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&bootstrapped);
        let mut sink = Vec::new();

        let error = run_automotive_report_command(
            std::path::Path::new("/tmp/project"),
            false,
            "md",
            None,
            "fr",
            &mut sink,
            move || {
                called.store(true, Ordering::SeqCst);
                std::future::ready(RecordingAutomotiveReportService::default())
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("'en' and 'zh'"), "{error}");
        assert!(
            !bootstrapped.load(Ordering::SeqCst),
            "a rejected language must not bootstrap the service"
        );
    }
}

#[cfg(test)]
mod report_cli_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use clap::Parser as _;

    use super::{run_report_command, Cli, Commands, ReportCommandService};

    /// Records the language the command handed to the service.
    #[derive(Default)]
    struct RecordingReportService {
        received: Arc<Mutex<Option<hf_service::ReportLanguage>>>,
    }

    #[async_trait::async_trait]
    impl ReportCommandService for RecordingReportService {
        async fn compose_report(
            &self,
            _project: &std::path::Path,
            target: &str,
            language: hf_service::ReportLanguage,
        ) -> Result<String, hf_service::ClassifiedError> {
            *self.received.lock().unwrap() = Some(language);
            Ok(format!("# report for {target} composed as {language:?}\n"))
        }
    }

    /// Drive the command end to end and report which language the service saw.
    async fn language_handed_to_the_service(flag: &str) -> hf_service::ReportLanguage {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("report.md");
        let received = Arc::new(Mutex::new(None));
        let service = RecordingReportService {
            received: Arc::clone(&received),
        };

        run_report_command(
            std::path::Path::new("/tmp/project"),
            "parse_header",
            Some(&out),
            flag,
            move || std::future::ready(service),
        )
        .await
        .unwrap();

        // The composed document is what reaches the file, so this also pins
        // that the service's output is the thing written out.
        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains("parse_header"), "{written}");

        let language = received.lock().unwrap().unwrap();
        assert!(
            written.contains(&format!("{language:?}")),
            "the written document must be the one the service composed: {written}"
        );
        language
    }

    #[tokio::test]
    async fn the_parsed_language_reaches_the_service() {
        // The hand-off, not the parse: `--lang zh` must arrive at
        // generate_report rather than being parsed and then discarded.
        assert_eq!(
            language_handed_to_the_service("zh").await,
            hf_service::ReportLanguage::Zh
        );
        assert_eq!(
            language_handed_to_the_service("en").await,
            hf_service::ReportLanguage::En
        );
    }

    #[tokio::test]
    async fn an_unknown_language_is_rejected_before_any_bootstrap() {
        let bootstrapped = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&bootstrapped);

        let error = run_report_command(
            std::path::Path::new("/tmp/project"),
            "parse_header",
            None,
            "fr",
            move || {
                called.store(true, Ordering::SeqCst);
                std::future::ready(RecordingReportService::default())
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("unknown report language 'fr'"));
        assert!(
            !bootstrapped.load(Ordering::SeqCst),
            "an unusable language must cost nothing: no container is built"
        );
    }

    #[test]
    fn report_language_defaults_to_english_and_accepts_chinese() {
        let default_cli =
            Cli::try_parse_from(["oxfuzz", "report", "/tmp/project", "--target", "parse"]).unwrap();
        let Commands::Report { report_lang, .. } = default_cli.command else {
            panic!("expected the report command");
        };
        assert_eq!(
            report_lang.parse::<hf_service::ReportLanguage>().unwrap(),
            hf_service::ReportLanguage::En
        );

        let chinese = Cli::try_parse_from([
            "oxfuzz",
            "report",
            "/tmp/project",
            "--target",
            "parse",
            "--report-lang",
            "zh",
        ])
        .unwrap();
        let Commands::Report { report_lang, .. } = chinese.command else {
            panic!("expected the report command");
        };
        assert_eq!(
            report_lang.parse::<hf_service::ReportLanguage>().unwrap(),
            hf_service::ReportLanguage::Zh
        );
    }

    #[test]
    fn an_unknown_report_language_names_the_accepted_values() {
        let error = "fr".parse::<hf_service::ReportLanguage>().unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("'en'") && message.contains("'zh'"),
            "{message}"
        );
    }
}

#[cfg(test)]
mod doctor_tests {
    #[cfg(feature = "semgrep-enrichment")]
    use clap::Parser as _;
    use hf_service::system::StatusFlag;
    use hf_service::SystemStatus;

    use super::{doctor_lines, parse_engine, parse_lang};
    #[cfg(feature = "semgrep-enrichment")]
    use super::{Cli, Commands};

    #[test]
    #[cfg(feature = "semgrep-enrichment")]
    fn cli_parses_semgrep_opt_in() {
        let cli = Cli::try_parse_from([
            "oxfuzz",
            "discover",
            "/tmp/project",
            "--lang",
            "c",
            "--semgrep",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Commands::Discover { semgrep: true, .. }
        ));
    }

    #[test]
    fn doctor_output_distinguishes_required_and_optional_checks() {
        let status = SystemStatus {
            docker: StatusFlag::from(true),
            sandbox_image: StatusFlag::from(true),
            libfuzzer: StatusFlag::from(true),
            aflplusplus: StatusFlag::from(false),
            honggfuzz: StatusFlag::from(false),
            syzkaller: StatusFlag::from(false),
            defectdojo: StatusFlag::from(false),
        };

        let output = doctor_lines(&status).join("\n");
        assert!(output.contains("READY  Docker daemon"));
        assert!(output.contains("READY  sandbox image"));
        assert!(output.contains("READY  libFuzzer"));
        assert!(output.contains("UNAVAILABLE  AFL++"));
        assert!(output.contains("UNAVAILABLE  honggfuzz"));
        assert!(output.contains("UNAVAILABLE  syzkaller"));
        let retired_engine_label = ["Cluster", "Fuzz", "Lite"].concat();
        assert!(!output.contains(&retired_engine_label));
        assert!(output.contains("OPTIONAL  DefectDojo"));
        assert!(status.fuzzing_ready());
    }

    #[test]
    fn cli_rejects_the_retired_engine_with_an_actionable_error() {
        let retired_engine_id = ["cluster", "fuzz", "lite"].concat();
        let error = parse_engine(&retired_engine_id).unwrap_err();
        assert!(error.to_string().contains("has been retired"));
    }

    #[test]
    fn cli_accepts_languages_with_a_production_discovery_pipeline() {
        assert!(parse_lang("c").is_ok());
        assert!(parse_lang("cpp").is_ok());
        assert!(parse_lang("rust").is_ok());
        assert!(parse_lang("go").is_ok());
        assert!(parse_lang("python").is_ok());
        assert!(parse_lang("cobol").is_err());
    }
}

#[cfg(test)]
mod providers_tests {
    use clap::Parser as _;
    use hf_service::{ProviderId, ProviderStatus};

    use super::{provider_status_lines, Cli, Commands, ProvidersOp};

    #[test]
    fn providers_command_parses_bare_list_and_thaw() {
        let cli = Cli::try_parse_from(["oxfuzz", "providers"]).unwrap();
        assert!(matches!(cli.command, Commands::Providers { op: None }));

        let cli = Cli::try_parse_from(["oxfuzz", "providers", "thaw", "openai-main"]).unwrap();
        let Commands::Providers {
            op: Some(ProvidersOp::Thaw { id }),
        } = cli.command
        else {
            panic!("expected providers thaw");
        };
        assert_eq!(id, "openai-main");
    }

    #[test]
    fn provider_status_lines_distinguish_frozen_and_healthy() {
        let statuses = vec![
            ProviderStatus {
                id: ProviderId::from_string("openai-main"),
                is_frozen: false,
                frozen_since: None,
                thaw_at: None,
                freeze_reason: None,
                active_requests: 0,
                total_requests: 12,
                total_errors: 0,
            },
            ProviderStatus {
                id: ProviderId::from_string("anthropic-main"),
                is_frozen: true,
                frozen_since: None,
                thaw_at: None,
                freeze_reason: Some("invalid api key".into()),
                active_requests: 0,
                total_requests: 3,
                total_errors: 3,
            },
        ];

        let lines = provider_status_lines(&statuses);

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("READY") && lines[0].contains("openai-main"));
        assert!(lines[0].contains("requests=12"));
        assert!(lines[1].contains("FROZEN") && lines[1].contains("anthropic-main"));
        assert!(lines[1].contains("invalid api key"));
    }
}

#[cfg(test)]
mod policy_tests {
    use clap::Parser as _;

    use super::{Cli, Commands, PolicyOp};

    #[test]
    fn policy_decisions_parses_with_a_bounded_limit() {
        let cli = Cli::try_parse_from(["oxfuzz", "policy", "decisions"]).unwrap();
        let Commands::Policy {
            op: PolicyOp::Decisions { limit },
        } = cli.command
        else {
            panic!("expected policy decisions");
        };
        assert_eq!(limit, 50);

        let cli = Cli::try_parse_from(["oxfuzz", "policy", "decisions", "--limit", "5"]).unwrap();
        let Commands::Policy {
            op: PolicyOp::Decisions { limit },
        } = cli.command
        else {
            panic!("expected policy decisions");
        };
        assert_eq!(limit, 5);
    }
}

#[cfg(all(test, feature = "semgrep-enrichment"))]
mod semgrep_cli_tests {
    use std::collections::{HashMap, VecDeque};
    use std::future::Future;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use hf_service::{
        ClassifiedError, SemgrepCancelOutcome, SemgrepInventoryView, SemgrepOperationState,
        SemgrepOperationView, SemgrepOverlayState, TargetInventory, TargetLanguage,
    };
    use uuid::Uuid;

    use super::{
        bootstrap_discover_service, run_discover_command, semgrep_poll_action, semgrep_state_name,
        DiscoverCommandOutput, DiscoverCommandService, SemgrepPollAction,
    };

    enum StatusStep {
        View(Box<SemgrepOperationView>),
        Pending,
    }

    struct FakeDiscoverService {
        events: Mutex<Vec<String>>,
        provider_available: bool,
        discovered: TargetInventory,
        ranked: TargetInventory,
        operation_id: Uuid,
        statuses: Mutex<VecDeque<StatusStep>>,
        cancelled: Mutex<Vec<Uuid>>,
        pending_status_entered: Arc<tokio::sync::Notify>,
    }

    impl FakeDiscoverService {
        fn new(language: TargetLanguage, statuses: Vec<StatusStep>) -> Self {
            let discovered = inventory(language, "/tmp/project");
            let mut ranked = discovered.clone();
            ranked.project_root = PathBuf::from("/tmp/project-ranked");
            Self {
                events: Mutex::new(Vec::new()),
                provider_available: true,
                discovered,
                ranked,
                operation_id: Uuid::from_u128(0x1234),
                statuses: Mutex::new(statuses.into()),
                cancelled: Mutex::new(Vec::new()),
                pending_status_entered: Arc::new(tokio::sync::Notify::new()),
            }
        }

        fn event_names(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }

        fn cancelled_ids(&self) -> Vec<Uuid> {
            self.cancelled.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl DiscoverCommandService for FakeDiscoverService {
        async fn discover_targets(
            &self,
            _project: &std::path::Path,
            _language: TargetLanguage,
        ) -> Result<TargetInventory, ClassifiedError> {
            self.events.lock().unwrap().push("discover".to_owned());
            Ok(self.discovered.clone())
        }

        async fn rank_targets(
            &self,
            _inventory: TargetInventory,
        ) -> Result<TargetInventory, ClassifiedError> {
            self.events.lock().unwrap().push("rank".to_owned());
            Ok(self.ranked.clone())
        }

        fn has_provider(&self) -> bool {
            self.provider_available
        }

        async fn start_semgrep(
            &self,
            _project: PathBuf,
            language: TargetLanguage,
        ) -> Result<Uuid, ClassifiedError> {
            self.events
                .lock()
                .unwrap()
                .push(format!("start:{}", language.as_str()));
            Ok(self.operation_id)
        }

        async fn semgrep_status(
            &self,
            operation_id: Uuid,
        ) -> Result<Option<SemgrepOperationView>, ClassifiedError> {
            assert_eq!(operation_id, self.operation_id);
            self.events.lock().unwrap().push("status".to_owned());
            let step = self.statuses.lock().unwrap().pop_front().unwrap();
            match step {
                StatusStep::View(view) => Ok(Some(*view)),
                StatusStep::Pending => {
                    self.pending_status_entered.notify_one();
                    std::future::pending().await
                }
            }
        }

        async fn cancel_semgrep(
            &self,
            operation_id: Uuid,
        ) -> Result<SemgrepCancelOutcome, ClassifiedError> {
            self.events.lock().unwrap().push("cancel".to_owned());
            self.cancelled.lock().unwrap().push(operation_id);
            Ok(SemgrepCancelOutcome::Accepted)
        }
    }

    #[derive(Default)]
    struct RecordingOutput {
        stdout: Vec<String>,
        stderr: Vec<String>,
    }

    impl DiscoverCommandOutput for RecordingOutput {
        fn stdout_line(&mut self, line: String) {
            self.stdout.push(line);
        }

        fn stderr_line(&mut self, line: String) {
            self.stderr.push(line);
        }
    }

    fn inventory(_language: TargetLanguage, project: &str) -> TargetInventory {
        TargetInventory {
            project_root: PathBuf::from(project),
            candidates: Vec::new(),
            call_graph: HashMap::new(),
        }
    }

    fn result(operation_id: Uuid) -> SemgrepInventoryView {
        SemgrepInventoryView {
            project_root: PathBuf::from("/tmp/project"),
            language: TargetLanguage::C,
            scan_id: Some(operation_id),
            source_sha256: Some("1".repeat(64)),
            overlay_state: SemgrepOverlayState::Current,
            candidates: Vec::new(),
            findings: Vec::new(),
            call_graph: HashMap::new(),
        }
    }

    fn operation(state: SemgrepOperationState) -> SemgrepOperationView {
        SemgrepOperationView {
            operation_id: Uuid::from_u128(0x1234),
            project_root: "/tmp/project".to_owned(),
            language: "c".to_owned(),
            state,
            active: true,
            started_at: "2026-07-29T00:00:00Z".to_owned(),
            ended_at: None,
            failure_code: None,
            failure_message: None,
            result: None,
        }
    }

    fn pending_signal() -> impl Future<Output = std::io::Result<()>> {
        std::future::pending()
    }

    fn immediate_delay() -> impl Future<Output = ()> {
        std::future::ready(())
    }

    #[tokio::test]
    async fn invalid_discovery_language_rejects_before_bootstrap_side_effects() {
        let bootstrap_called = Arc::new(AtomicBool::new(false));
        let called_from_bootstrap = Arc::clone(&bootstrap_called);

        let error = bootstrap_discover_service("invalid", move || {
            called_from_bootstrap.store(true, Ordering::SeqCst);
            std::future::ready(())
        })
        .await
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("unknown target language 'invalid'"));
        assert!(!bootstrap_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn discover_without_semgrep_preserves_the_existing_inventory_output() {
        let service = FakeDiscoverService::new(TargetLanguage::C, Vec::new());
        let expected = serde_json::to_string_pretty(&service.discovered).unwrap();
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::C,
            false,
            false,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(service.event_names(), ["discover"]);
        assert_eq!(output.stdout, [expected]);
        assert!(output.stderr.is_empty());
    }

    #[tokio::test]
    async fn discover_without_a_provider_preserves_the_existing_rank_warning() {
        let mut service = FakeDiscoverService::new(TargetLanguage::C, Vec::new());
        service.provider_available = false;
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::C,
            true,
            false,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(service.event_names(), ["discover"]);
        assert_eq!(
            output.stderr,
            ["warning: --rank requested but HF_PROVIDER_API_KEY not set; using heuristic scores only"]
        );
    }

    #[tokio::test]
    async fn discover_ranks_before_semgrep_and_prints_the_exact_service_result() {
        let operation_id = Uuid::from_u128(0x1234);
        let exact_result = result(operation_id);
        let mut done = operation(SemgrepOperationState::Done);
        done.active = false;
        done.result = Some(exact_result.clone());
        let service = FakeDiscoverService::new(
            TargetLanguage::C,
            vec![
                StatusStep::View(Box::new(operation(SemgrepOperationState::Scanning))),
                StatusStep::View(Box::new(done)),
            ],
        );
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::C,
            true,
            true,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(
            service.event_names(),
            ["discover", "rank", "start:c", "status", "status"]
        );
        assert_eq!(
            output.stdout,
            [serde_json::to_string_pretty(&exact_result).unwrap()]
        );
        assert_eq!(
            output.stderr.last().map(String::as_str),
            Some("Semgrep static-analysis signals")
        );
    }

    #[tokio::test]
    async fn semgrep_language_validation_runs_after_discovery_and_optional_ranking() {
        let service = FakeDiscoverService::new(TargetLanguage::Rust, Vec::new());
        let mut output = RecordingOutput::default();

        let error = run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::Rust,
            true,
            true,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("only C and C++"));
        assert_eq!(service.event_names(), ["discover", "rank"]);
        assert!(output.stdout.is_empty());
    }

    #[tokio::test]
    async fn semgrep_language_validation_accepts_cpp_after_discovery() {
        let mut done = operation(SemgrepOperationState::Done);
        done.active = false;
        done.result = Some(result(Uuid::from_u128(0x1234)));
        let service =
            FakeDiscoverService::new(TargetLanguage::Cpp, vec![StatusStep::View(Box::new(done))]);
        let mut output = RecordingOutput::default();

        run_discover_command(
            &service,
            PathBuf::from("/tmp/project"),
            TargetLanguage::Cpp,
            false,
            true,
            &mut output,
            pending_signal(),
            immediate_delay,
        )
        .await
        .unwrap();

        assert_eq!(service.event_names(), ["discover", "start:cpp", "status"]);
    }

    #[tokio::test]
    async fn semgrep_signal_cancels_the_exact_uuid_while_status_is_pending() {
        let mut cancelled = operation(SemgrepOperationState::Cancelled);
        cancelled.active = false;
        cancelled.failure_message = Some("cancelled by test".to_owned());
        let service = FakeDiscoverService::new(
            TargetLanguage::C,
            vec![StatusStep::Pending, StatusStep::View(Box::new(cancelled))],
        );
        let pending_status_entered = Arc::clone(&service.pending_status_entered);
        let signal = async move {
            pending_status_entered.notified().await;
            Ok(())
        };
        let mut output = RecordingOutput::default();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_discover_command(
                &service,
                PathBuf::from("/tmp/project"),
                TargetLanguage::C,
                false,
                true,
                &mut output,
                signal,
                immediate_delay,
            ),
        )
        .await
        .expect("Ctrl-C must be observed while status retrieval is pending")
        .unwrap_err();

        assert_eq!(error.to_string(), "cancelled by test");
        assert_eq!(service.cancelled_ids(), [service.operation_id]);
        assert_eq!(
            service.event_names(),
            ["discover", "start:c", "status", "cancel", "status"]
        );
    }

    #[tokio::test]
    async fn semgrep_signal_cancels_the_exact_uuid_while_poll_delay_is_pending() {
        let mut cancelled = operation(SemgrepOperationState::Cancelled);
        cancelled.active = false;
        cancelled.failure_message = Some("cancelled during delay".to_owned());
        let service = FakeDiscoverService::new(
            TargetLanguage::C,
            vec![
                StatusStep::View(Box::new(operation(SemgrepOperationState::Scanning))),
                StatusStep::View(Box::new(cancelled)),
            ],
        );
        let delay_started = Arc::new(tokio::sync::Notify::new());
        let signal_started = Arc::clone(&delay_started);
        let delay_notifier = Arc::clone(&delay_started);
        let signal = async move {
            signal_started.notified().await;
            Ok(())
        };
        let delay = move || {
            delay_notifier.notify_one();
            std::future::pending::<()>()
        };
        let mut output = RecordingOutput::default();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_discover_command(
                &service,
                PathBuf::from("/tmp/project"),
                TargetLanguage::C,
                false,
                true,
                &mut output,
                signal,
                delay,
            ),
        )
        .await
        .expect("Ctrl-C must be observed while the poll delay is pending")
        .unwrap_err();

        assert_eq!(error.to_string(), "cancelled during delay");
        assert_eq!(service.cancelled_ids(), [service.operation_id]);
    }

    #[test]
    fn semgrep_polling_uses_exact_results_and_fails_closed_at_terminals() {
        for state in [
            SemgrepOperationState::Staging,
            SemgrepOperationState::Scanning,
            SemgrepOperationState::Validating,
            SemgrepOperationState::Persisting,
        ] {
            assert!(matches!(
                semgrep_poll_action(operation(state)),
                SemgrepPollAction::Continue
            ));
        }

        let mut done = operation(SemgrepOperationState::Done);
        done.result = Some(SemgrepInventoryView {
            project_root: PathBuf::from("/tmp/project"),
            language: TargetLanguage::C,
            scan_id: Some(Uuid::nil()),
            source_sha256: Some("1".repeat(64)),
            overlay_state: SemgrepOverlayState::Current,
            candidates: Vec::new(),
            findings: Vec::new(),
            call_graph: HashMap::new(),
        });
        let SemgrepPollAction::Complete(result) = semgrep_poll_action(done) else {
            panic!("done operation must return its exact result");
        };
        assert_eq!(result.scan_id, Some(Uuid::nil()));

        let missing = semgrep_poll_action(operation(SemgrepOperationState::Done));
        let SemgrepPollAction::Fail(message) = missing else {
            panic!("done operation without a result must fail closed");
        };
        assert!(message.contains("completed without an exact result"));

        let mut failed = operation(SemgrepOperationState::Failed);
        failed.failure_message = Some("bounded service failure".to_owned());
        let SemgrepPollAction::Fail(message) = semgrep_poll_action(failed) else {
            panic!("failed operation must return an error");
        };
        assert_eq!(message, "bounded service failure");

        assert!(matches!(
            semgrep_poll_action(operation(SemgrepOperationState::Cancelled)),
            SemgrepPollAction::Fail(message) if message.contains("cancelled")
        ));
    }

    #[test]
    fn semgrep_state_labels_are_canonical_lowercase() {
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Staging),
            "staging"
        );
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Scanning),
            "scanning"
        );
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Validating),
            "validating"
        );
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Persisting),
            "persisting"
        );
        assert_eq!(semgrep_state_name(SemgrepOperationState::Done), "done");
        assert_eq!(semgrep_state_name(SemgrepOperationState::Failed), "failed");
        assert_eq!(
            semgrep_state_name(SemgrepOperationState::Cancelled),
            "cancelled"
        );
    }
}

#[cfg(all(test, not(feature = "semgrep-enrichment")))]
mod semgrep_absence_tests {
    use clap::Parser as _;

    use super::Cli;

    #[test]
    fn cli_omits_semgrep_opt_in_without_the_feature() {
        let parsed = Cli::try_parse_from([
            "oxfuzz",
            "discover",
            "/tmp/project",
            "--lang",
            "c",
            "--semgrep",
        ]);
        assert!(parsed.is_err());
    }
}

#[cfg(test)]
mod schedule_cli_tests {
    use clap::Parser as _;
    use hf_service::scheduler::CampaignSchedulerError;

    use super::{recovery_cli_error, Cli, Commands, ScheduleOp, ScheduleRecoveryOp};

    #[test]
    fn schedule_recovery_commands_parse() {
        let list = Cli::try_parse_from(["oxfuzz", "schedule", "recovery", "list"]).unwrap();
        assert!(matches!(
            list.command,
            Commands::Schedule {
                op: ScheduleOp::Recovery {
                    op: ScheduleRecoveryOp::List
                }
            }
        ));

        let acknowledge =
            Cli::try_parse_from(["oxfuzz", "schedule", "recovery", "acknowledge", "occ-123"])
                .unwrap();
        let Commands::Schedule {
            op:
                ScheduleOp::Recovery {
                    op: ScheduleRecoveryOp::Acknowledge { occurrence_id },
                },
        } = acknowledge.command
        else {
            panic!("expected recovery acknowledgement");
        };
        assert_eq!(occurrence_id, "occ-123");
    }

    #[test]
    fn cli_recovery_error_excludes_stored_json_diagnostics() {
        let public = recovery_cli_error(CampaignSchedulerError::History(
            r#"STORED_JSON_PRIVATE_MARKER: {"project":"/private/source"}"#.to_owned(),
        ))
        .to_string();

        assert_eq!(public, "one-time recovery is temporarily unavailable");
        assert!(!public.contains("STORED_JSON_PRIVATE_MARKER"));
        assert!(!public.contains("/private/source"));
    }
}
