use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// AI fuzzing agent.
/// Which harness generator to use, as a command-line value.
///
/// Mirrors [`hf_service::AiPolicy`]: the CLI parses, the service decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum AiOption {
    /// Use the model where it is available; carry on without it otherwise.
    Auto,
    /// Require the model: an unavailable one is an error, not a silent
    /// downgrade to whatever answers instead.
    Require,
    /// Never call a model, even when one is configured.
    Off,
}

#[derive(Parser)]
#[command(name = "oxfuzz", version, about)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Initialize configuration.
    Init,
    /// Check whether the mandatory sandbox and at least one fuzzing engine are ready.
    Doctor(DoctorArgs),
    /// Diagnose and configure project builds.
    Build(BuildArgs),
    /// Discover fuzzing targets in a project.
    Discover(DiscoverArgs),
    /// Generate a harness for a target.
    Harness(HarnessArgs),
    /// Run a fuzz campaign.
    Run(RunArgs),
    /// Run an approved campaign: discover -> require promoted harness -> seed
    /// -> run -> triage, end to end.
    Campaign(CampaignArgs),
    /// Triage crashes from a run.
    Triage(TriageArgs),
    /// Manage the fuzzing corpus for a target.
    Corpus(CorpusArgs),
    /// Report line/function/region coverage for a target's corpus.
    Coverage(CoverageArgs),
    /// Audit which claims about a finished run its retained evidence supports.
    /// Reads only; starts no build, run, or coverage measurement.
    #[cfg(feature = "campaign-trust")]
    Trust(TrustArgs),
    /// Rank entry points no retained coverage measurement has ever covered.
    /// Reads cached measurements; never triggers one.
    #[cfg(feature = "unreached-surface")]
    Unreached(UnreachedArgs),
    /// Attribute every discovered target against retained coverage and order
    /// the result for the next harness: untouched first, partial frontier
    /// next, saturated last. Reads cached measurements; never triggers one.
    #[cfg(feature = "unreached-surface")]
    Attribution(AttributionArgs),
    /// Report campaign health conditions for a run. Reads retained state;
    /// never stops, restarts, or resizes a campaign.
    #[cfg(feature = "campaign-health")]
    Health(HealthArgs),
    /// Run the post-run analysis chain for a finished run: triage, minimize,
    /// corpus absorb, coverage, blockers, disposition, trust report. Resumes at
    /// the first step that never finished.
    #[cfg(feature = "run-closeout")]
    Closeout(CloseoutArgs),
    /// Manage durable harness work orders.
    #[cfg(feature = "harness-work-order")]
    WorkOrder(WorkOrderArgs),
    /// CI gate: harness + short fuzz + triage; write SARIF and exit non-zero
    /// if any crash is found. Intended for PR pipelines.
    Ci(CiArgs),
    /// Export the latest run's crashes as SARIF (`GitHub` code scanning).
    Sarif(SarifArgs),
    /// Export a self-contained reproduction bundle (harness + crash input +
    /// REPRODUCE.md) for a crash from the target's latest run.
    Repro(ReproArgs),
    /// Push the latest run's triaged crashes to `DefectDojo` as findings.
    Defectdojo(DefectdojoArgs),
    /// Export a reproducibility/evidence bundle for hand-off and CI artifacts.
    Export(ExportArgs),
    /// Replay stored crashes against the current harness (regression check).
    Regress(RegressArgs),
    /// Ingest a document (PDF/Office/HTML/...) into the project knowledge base.
    Ingest(IngestArgs),
    /// Compose a detailed Markdown campaign report for a target.
    Report(ReportArgs),
    /// Start the web server (REST API).
    Serve(ServeArgs),
    /// Authorize a running server to act on work restored after a restart.
    ///
    /// A scheduler starts disarmed on every process start: recovery restores
    /// what it was doing, and missed occurrences a catch-up or backfill policy
    /// would replay are held rather than fired. This releases them.
    Arm(ArmArgs),
    /// Launch the TUI (terminal user interface).
    Tui(TuiArgs),
    /// Run one autonomous agent turn over a project (the same agent loop the
    /// GUI and web API use). Requires an LLM provider (`HF_PROVIDER_API_KEY`).
    Agent(AgentArgs),
    /// Knowledge-base operations (see also `ingest`).
    Knowledge(KnowledgeArgs),
    /// Campaign scheduling for headless recurring runs.
    Schedule(ScheduleArgs),
    /// Chat session management.
    Session(SessionArgs),
    /// Inspect and manage LLM providers. With no subcommand, list provider
    /// ids with their frozen/healthy state.
    Providers(ProvidersArgs),
    /// Guardrail policy audit trail.
    Policy(PolicyArgs),
    /// Sandboxed automotive protocol analysis and replay preparation.
    #[cfg(feature = "automotive-scapy")]
    Automotive(AutomotiveArgs),
}

/// Check whether the mandatory sandbox and at least one fuzzing engine are ready.
#[derive(clap::Args)]
pub(crate) struct DoctorArgs {
    /// Check this engine and its current campaign policy instead of any engine.
    #[arg(long)]
    pub(crate) engine: Option<String>,
    /// Validate this duration against campaign policy.
    #[arg(long, requires = "engine")]
    pub(crate) duration: Option<String>,
    /// Require configured model access without contacting a provider.
    #[arg(long, requires = "engine")]
    pub(crate) require_provider: bool,
    /// Emit the service-owned status as JSON.
    #[arg(long)]
    pub(crate) json: bool,
}

/// Diagnose and configure project builds.
#[derive(clap::Args)]
pub(crate) struct BuildArgs {
    #[command(subcommand)]
    pub(crate) command: BuildCommand,
}

/// Discover fuzzing targets in a project.
#[derive(clap::Args)]
pub(crate) struct DiscoverArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target language (c, cpp, rust, go, python).
    #[arg(long)]
    pub(crate) lang: String,
    /// Enable LLM-assisted ranking (requires `HF_PROVIDER_API_KEY`).
    #[arg(long)]
    pub(crate) rank: bool,
    /// How `--rank` may use the model: `auto` warns and keeps heuristic
    /// scores when none is configured, `require` fails instead.
    #[arg(long, value_enum, default_value_t = AiOption::Auto)]
    pub(crate) ai: AiOption,
    /// Enrich persisted C/C++ targets with advisory Semgrep signals.
    #[cfg(feature = "semgrep-enrichment")]
    #[arg(long)]
    pub(crate) semgrep: bool,
}

/// Generate a harness for a target.
#[derive(clap::Args)]
pub(crate) struct HarnessArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Generated function harnesses support AFL++, honggfuzz, and
    /// libFuzzer only.
    ///
    /// Syzkaller kernel campaigns use the local desktop application's
    /// dedicated kernel-campaign workflow with operator approval and
    /// handoff.
    #[arg(long)]
    pub(crate) engine: String,
    /// Target language (c, cpp, rust, go, python). Defaults to c.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
    #[command(flatten)]
    pub(crate) draft: HarnessDraftArgs,
    /// Which generator writes the harness: `auto` uses the model when one
    /// is configured, `require` fails rather than substituting the
    /// template, `off` never calls a model.
    #[arg(long, value_enum, default_value_t = AiOption::Auto)]
    pub(crate) ai: AiOption,
    /// Auto-repair: on a compile failure, feed the diagnostics back to the
    /// LLM and retry up to N times before giving up (0 = no repair).
    #[arg(long, default_value_t = 0)]
    pub(crate) repair: usize,
    /// Coverage-guided refinement: reshape the EXISTING harness to reach the
    /// target's still-uncovered reachable functions, then recompile.
    #[arg(long)]
    pub(crate) refine: bool,
    /// Explicitly approve the revision for full campaigns after a clean
    /// persisted smoke run.
    #[arg(long)]
    pub(crate) promote: bool,
}

/// Controls for emitting harness drafts without execution.
#[derive(clap::Args)]
pub(crate) struct HarnessDraftArgs {
    /// Emit the draft as JSON; never compile, refine, repair or promote.
    #[arg(long, requires = "draft_only", conflicts_with_all = ["repair", "refine", "promote"])]
    pub(crate) json: bool,
    /// Skip compile and smoke fuzz (draft only).
    #[arg(long)]
    pub(crate) draft_only: bool,
}

/// Run a fuzz campaign.
#[derive(clap::Args)]
pub(crate) struct RunArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol. Required unless `--replay` is given (the recorded
    /// run carries its target).
    #[arg(long, required_unless_present = "replay")]
    pub(crate) target: Option<String>,
    /// Fuzzing engine. Required unless `--replay` is given.
    #[arg(long, required_unless_present = "replay")]
    pub(crate) engine: Option<String>,
    /// Target language (c, cpp, rust, go, python). Defaults to c.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
    /// Duration (e.g. 60m). Defaults to the configured fuzzing duration.
    #[arg(long)]
    pub(crate) duration: Option<String>,
    /// Replay a persisted run with its recorded engine, duration, and
    /// deterministic seed.
    #[arg(long)]
    pub(crate) replay: Option<String>,
}

/// Run an approved campaign: discover -> require promoted harness -> seed
/// -> run -> triage, end to end.
#[derive(clap::Args)]
pub(crate) struct CampaignArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol to fuzz. Omit to auto-pick the top-ranked target.
    #[arg(long)]
    pub(crate) target: Option<String>,
    /// Fuzzing engine.
    #[arg(long, default_value = "libfuzzer")]
    pub(crate) engine: String,
    /// Target language (c, cpp, rust, go, python). Defaults to c.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
    /// Per-iteration fuzz duration in seconds.
    #[arg(long, default_value_t = 60)]
    pub(crate) duration_secs: u64,
    /// Max run -> triage iterations.
    #[arg(long, default_value_t = 3)]
    pub(crate) iterations: usize,
    /// How the campaign may use the model. It reaches one in four places:
    /// seed generation, the run dictionary, triage bug reports, and the
    /// coverage-plateau harness refine. (Target auto-pick is a
    /// deterministic fit-score sort, not a model call.) `off` calls no
    /// model at all; `require` refuses to start when none is configured or
    /// all are frozen, but cannot promise a mid-run outage did not degrade
    /// a step, since each one warns and continues by design.
    #[arg(long, value_enum, default_value_t = AiOption::Auto)]
    pub(crate) ai: AiOption,
}

/// Triage crashes from a run.
#[derive(clap::Args)]
pub(crate) struct TriageArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Target language (c, cpp, rust, go, python). Defaults to c.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
}

/// Manage the fuzzing corpus for a target.
#[derive(clap::Args)]
pub(crate) struct CorpusArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Operation: seed, llmseed, grow, prune, cprune, survival, regen,
    /// minimize, absorb, concolic, import, list.
    #[arg(long)]
    pub(crate) op: String,
    /// Source directory for `import` (an external corpus, e.g. OSS-Fuzz).
    #[arg(long)]
    pub(crate) from: Option<PathBuf>,
}

/// Report line/function/region coverage for a target's corpus.
#[derive(clap::Args)]
pub(crate) struct CoverageArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
}

/// Audit which claims about a finished run its retained evidence supports.
/// Reads only; starts no build, run, or coverage measurement.
#[cfg(feature = "campaign-trust")]
#[derive(clap::Args)]
pub(crate) struct TrustArgs {
    /// Run identifier to audit.
    #[arg(long)]
    pub(crate) run: String,
}

/// Rank entry points no retained coverage measurement has ever covered.
/// Reads cached measurements; never triggers one.
#[cfg(feature = "unreached-surface")]
#[derive(clap::Args)]
pub(crate) struct UnreachedArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Source language.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
}

/// Attribute every discovered target against retained coverage and order
/// the result for the next harness: untouched first, partial frontier
/// next, saturated last. Reads cached measurements; never triggers one.
#[cfg(feature = "unreached-surface")]
#[derive(clap::Args)]
pub(crate) struct AttributionArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Source language.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
}

/// Report campaign health conditions for a run. Reads retained state;
/// never stops, restarts, or resizes a campaign.
#[cfg(feature = "campaign-health")]
#[derive(clap::Args)]
pub(crate) struct HealthArgs {
    /// Run identifier to assess.
    #[arg(long)]
    pub(crate) run: String,
}

/// Run the post-run analysis chain for a finished run: triage, minimize,
/// corpus absorb, coverage, blockers, disposition, trust report. Resumes at
/// the first step that never finished.
#[cfg(feature = "run-closeout")]
#[derive(clap::Args)]
pub(crate) struct CloseoutArgs {
    /// Run identifier to close out.
    #[arg(long)]
    pub(crate) run: String,
}

/// Manage durable harness work orders.
#[cfg(feature = "harness-work-order")]
#[derive(clap::Args)]
pub(crate) struct WorkOrderArgs {
    #[command(subcommand)]
    pub(crate) command: crate::work_order::WorkOrderCommand,
}

/// CI gate: harness + short fuzz + triage; write SARIF and exit non-zero
/// if any crash is found. Intended for PR pipelines.
#[derive(clap::Args)]
pub(crate) struct CiArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Fuzzing engine. Defaults to libfuzzer.
    #[arg(long, default_value = "libfuzzer")]
    pub(crate) engine: String,
    /// Target language (c, cpp, rust, go, python). Defaults to c.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
    /// Fuzz duration (e.g. 120s, 5m). Defaults to 120s.
    #[arg(long, default_value = "120s")]
    pub(crate) duration: String,
    /// SARIF output path. Defaults to `oxfuzz.sarif`.
    #[arg(long, default_value = "oxfuzz.sarif")]
    pub(crate) sarif: PathBuf,
    /// How the gate may use the model. It reaches one in two places: the
    /// run dictionary and triage bug reports. (Its seeds are the heuristic
    /// generator, not the model.) `off` calls no model at all; `require`
    /// refuses to start when none is configured or all are frozen. `off` is
    /// the exact side of this flag: a CI gate that must not spend tokens
    /// wants it.
    #[arg(long, value_enum, default_value_t = AiOption::Auto)]
    pub(crate) ai: AiOption,
}

/// Export the latest run's crashes as SARIF (`GitHub` code scanning).
#[derive(clap::Args)]
pub(crate) struct SarifArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Write SARIF to this file instead of stdout.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
}

/// Export a self-contained reproduction bundle (harness + crash input +
/// REPRODUCE.md) for a crash from the target's latest run.
#[derive(clap::Args)]
pub(crate) struct ReproArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Fuzzing engine. Defaults to libfuzzer.
    #[arg(long, default_value = "libfuzzer")]
    pub(crate) engine: String,
    /// Target language (c, cpp, rust, go, python). Defaults to c.
    #[arg(long, default_value = "c")]
    pub(crate) lang: String,
    /// Crash id (or unique prefix) to bundle; defaults to the first crash.
    #[arg(long)]
    pub(crate) crash: Option<String>,
    /// Output directory for the bundle.
    #[arg(long, default_value = "oxfuzz_repro")]
    pub(crate) out: PathBuf,
}

/// Push the latest run's triaged crashes to `DefectDojo` as findings.
#[derive(clap::Args)]
pub(crate) struct DefectdojoArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol (used as the `DefectDojo` test title). Optional.
    #[arg(long)]
    pub(crate) target: Option<String>,
    /// Only verify the configured URL + token; do not push.
    #[arg(long)]
    pub(crate) test: bool,
}

/// Export a reproducibility/evidence bundle for hand-off and CI artifacts.
#[derive(clap::Args)]
pub(crate) struct ExportArgs {
    /// Optional project root; omit to export all persisted projects.
    pub(crate) project: Option<PathBuf>,
    /// Output JSON bundle path.
    #[arg(short, long, default_value = "oxfuzz_export.json")]
    pub(crate) output: PathBuf,
}

/// Replay stored crashes against the current harness (regression check).
#[derive(clap::Args)]
pub(crate) struct RegressArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
}

/// Ingest a document (PDF/Office/HTML/...) into the project knowledge base.
#[derive(clap::Args)]
pub(crate) struct IngestArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Document file to convert and index.
    #[arg(long)]
    pub(crate) file: PathBuf,
}

/// Compose a detailed Markdown campaign report for a target.
#[derive(clap::Args)]
pub(crate) struct ReportArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
    /// Target symbol.
    #[arg(long)]
    pub(crate) target: String,
    /// Write the report to this file instead of stdout.
    #[arg(long)]
    pub(crate) out: Option<PathBuf>,
    /// Report language: en or zh. Defaults to en.
    ///
    /// Named `--report-lang` rather than `--lang` because `--lang` already
    /// means the target's source language on `discover` and `harness`.
    #[arg(long, default_value = "en")]
    pub(crate) report_lang: String,
}

/// Start the web server (REST API).
#[derive(clap::Args)]
pub(crate) struct ServeArgs {
    /// IP address to listen on. Non-loopback addresses require `HF_WEB_TOKEN`.
    #[arg(long, default_value = "127.0.0.1")]
    pub(crate) host: std::net::IpAddr,
    /// Port to listen on.
    #[arg(long, default_value = "8081")]
    pub(crate) port: u16,
}

/// Authorize a running server to act on work restored after a restart.
///
/// A scheduler starts disarmed on every process start: recovery restores
/// what it was doing, and missed occurrences a catch-up or backfill policy
/// would replay are held rather than fired. This releases them.
#[derive(clap::Args)]
pub(crate) struct ArmArgs {
    /// Base URL of the running oxfuzz server.
    #[arg(long, default_value = "http://127.0.0.1:8081")]
    pub(crate) url: String,
    /// Withdraw authorization instead of granting it.
    #[arg(long, conflicts_with = "status")]
    pub(crate) off: bool,
    /// Report whether the server is armed, changing nothing.
    #[arg(long)]
    pub(crate) status: bool,
}

/// Launch the TUI (terminal user interface).
#[derive(clap::Args)]
pub(crate) struct TuiArgs {
    /// Project root path.
    pub(crate) project: PathBuf,
}

/// Run one autonomous agent turn over a project (the same agent loop the
/// GUI and web API use). Requires an LLM provider (`HF_PROVIDER_API_KEY`).
#[derive(clap::Args)]
pub(crate) struct AgentArgs {
    /// The user message / instruction for the agent.
    pub(crate) message: String,
    /// Project root the agent operates on.
    #[arg(long)]
    pub(crate) project: Option<PathBuf>,
    /// Agent definition id (default: the orchestrator).
    #[arg(long)]
    pub(crate) agent: Option<String>,
}

/// Knowledge-base operations (see also `ingest`).
#[derive(clap::Args)]
pub(crate) struct KnowledgeArgs {
    #[command(subcommand)]
    pub(crate) op: KnowledgeOp,
}

/// Campaign scheduling for headless recurring runs.
#[derive(clap::Args)]
pub(crate) struct ScheduleArgs {
    #[command(subcommand)]
    pub(crate) op: ScheduleOp,
}

/// Chat session management.
#[derive(clap::Args)]
pub(crate) struct SessionArgs {
    #[command(subcommand)]
    pub(crate) op: SessionOp,
}

/// Inspect and manage LLM providers. With no subcommand, list provider
/// ids with their frozen/healthy state.
#[derive(clap::Args)]
pub(crate) struct ProvidersArgs {
    #[command(subcommand)]
    pub(crate) op: Option<ProvidersOp>,
}

/// Guardrail policy audit trail.
#[derive(clap::Args)]
pub(crate) struct PolicyArgs {
    #[command(subcommand)]
    pub(crate) op: PolicyOp,
}

/// Sandboxed automotive protocol analysis and replay preparation.
#[cfg(feature = "automotive-scapy")]
#[derive(clap::Args)]
pub(crate) struct AutomotiveArgs {
    #[command(subcommand)]
    pub(crate) op: AutomotiveOp,
}

#[cfg(feature = "automotive-scapy")]
#[derive(Subcommand)]
pub(crate) enum AutomotiveOp {
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
    /// Read one retained automotive operation by its service-owned id.
    Operation {
        project: PathBuf,
        #[arg(long)]
        id: uuid::Uuid,
    },
    /// Promote one verified operation artifact into the protocol-state corpus.
    ///
    /// The typed promotion request (project binding, state signature) is read
    /// from `--request`; `--input-artifact` or `--output-artifact` selects the
    /// artifact the operation's evidence names.
    PromoteState {
        project: PathBuf,
        #[arg(long)]
        operation: uuid::Uuid,
        #[arg(long)]
        request: PathBuf,
        #[arg(long, conflicts_with = "output_artifact")]
        input_artifact: Option<String>,
        #[arg(long)]
        output_artifact: Option<String>,
    },
    /// List promoted protocol-state corpus entries for a project.
    StateCorpus {
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
pub(crate) enum KnowledgeOp {
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
pub(crate) enum ScheduleOp {
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
pub(crate) enum ScheduleRecoveryOp {
    /// List one-time occurrences requiring operator acknowledgement.
    List,
    /// Record an unknown prior outcome as cancelled. This does not terminate a process.
    Acknowledge { occurrence_id: String },
}

#[derive(Subcommand)]
pub(crate) enum SessionOp {
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
pub(crate) enum ProvidersOp {
    /// Thaw a frozen provider after a verifying health check.
    Thaw {
        /// Provider id (see `oxfuzz providers`).
        id: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PolicyOp {
    /// List recorded guardrail authorization decisions, newest first.
    Decisions {
        #[arg(long, default_value = "50")]
        limit: usize,
    },
}

#[cfg(test)]
mod harness_help_tests {
    use clap::CommandFactory as _;

    use super::Cli;

    #[test]
    fn generated_harness_help_lists_only_userspace_engines() {
        let mut command = Cli::command();
        let harness = command
            .find_subcommand_mut("harness")
            .expect("harness subcommand");
        let help = harness.render_long_help().to_string();

        assert!(
            help.contains("AFL++, honggfuzz, and libFuzzer only"),
            "{help}"
        );
        assert!(!help.contains("libfuzzer, syzkaller"), "{help}");
        assert!(!help.contains("run_syzkaller"), "{help}");
        assert!(help.contains("local desktop application"), "{help}");
        assert!(help.contains("kernel-campaign workflow"), "{help}");
        assert!(help.contains("operator approval"), "{help}");
    }
}

#[cfg(test)]
mod ai_option_tests {
    use clap::Parser as _;

    use super::{AiOption, Cli, Commands};

    /// Every command that can reach a model takes the same flag, with the same
    /// default, so one word does not mean three things.
    #[test]
    fn every_ai_capable_command_defaults_to_auto() {
        let harness = Cli::try_parse_from([
            "oxfuzz",
            "harness",
            "/p",
            "--target",
            "t",
            "--engine",
            "libfuzzer",
        ])
        .unwrap();
        let Commands::Harness(crate::args::HarnessArgs { ai, .. }) = harness.command else {
            panic!("expected harness");
        };
        assert_eq!(ai, AiOption::Auto);

        let campaign = Cli::try_parse_from(["oxfuzz", "campaign", "/p"]).unwrap();
        let Commands::Campaign(crate::args::CampaignArgs { ai, .. }) = campaign.command else {
            panic!("expected campaign");
        };
        assert_eq!(ai, AiOption::Auto);

        let ci = Cli::try_parse_from(["oxfuzz", "ci", "/p", "--target", "t"]).unwrap();
        let Commands::Ci(crate::args::CiArgs { ai, .. }) = ci.command else {
            panic!("expected ci");
        };
        assert_eq!(ai, AiOption::Auto);

        let discover = Cli::try_parse_from(["oxfuzz", "discover", "/p", "--lang", "c"]).unwrap();
        let Commands::Discover(crate::args::DiscoverArgs { ai, .. }) = discover.command else {
            panic!("expected discover");
        };
        assert_eq!(ai, AiOption::Auto);
    }

    #[test]
    fn the_three_choices_parse_on_the_composite_commands() {
        for (value, expected) in [
            ("auto", AiOption::Auto),
            ("require", AiOption::Require),
            ("off", AiOption::Off),
        ] {
            let campaign =
                Cli::try_parse_from(["oxfuzz", "campaign", "/p", "--ai", value]).unwrap();
            let Commands::Campaign(crate::args::CampaignArgs { ai, .. }) = campaign.command else {
                panic!("expected campaign");
            };
            assert_eq!(ai, expected, "campaign --ai {value}");

            let ci = Cli::try_parse_from(["oxfuzz", "ci", "/p", "--target", "t", "--ai", value])
                .unwrap();
            let Commands::Ci(crate::args::CiArgs { ai, .. }) = ci.command else {
                panic!("expected ci");
            };
            assert_eq!(ai, expected, "ci --ai {value}");
        }

        // A value outside the three is refused rather than silently defaulted.
        assert!(Cli::try_parse_from(["oxfuzz", "campaign", "/p", "--ai", "maybe"]).is_err());
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

#[cfg(all(test, feature = "build-doctor"))]
mod build_surface_tests {
    use super::*;

    #[test]
    fn build_commands_accept_explicit_reviewed_inputs() {
        for args in [
            vec!["oxfuzz", "build", "diagnose", "/project", "--json"],
            vec!["oxfuzz", "build", "profile", "show", "/project", "--json"],
            vec!["oxfuzz", "build", "profile", "clear", "/project"],
            vec![
                "oxfuzz", "build", "history", "/project", "--limit", "3", "--json",
            ],
            vec![
                "oxfuzz",
                "build",
                "run",
                "/project",
                "--expected-profile-sha256",
                "reviewed-digest",
            ],
            vec![
                "oxfuzz",
                "build",
                "profile",
                "set",
                "/project",
                "--component-root",
                "parser",
                "--build-system",
                "cmake",
                "--compile-database-path",
                "build/compile_commands.json",
                "--define",
                "BUILD_TESTING=OFF",
                "--dependency",
                "command:clang",
                "--dependency",
                "pkg_config:zlib",
            ],
        ] {
            assert!(Cli::try_parse_from(&args).is_ok(), "{args:?}");
        }
        assert!(Cli::try_parse_from(["oxfuzz", "build", "run", "/project"]).is_err());
        assert!(Cli::try_parse_from([
            "oxfuzz",
            "build",
            "profile",
            "set",
            "/project",
            "--build-system",
            "meson"
        ])
        .is_err());
    }
}

#[derive(Subcommand)]
pub(crate) enum BuildCommand {
    /// Diagnose current build prerequisites without building the project.
    Diagnose {
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Read or explicitly change the optional build profile.
    Profile {
        #[command(subcommand)]
        command: BuildProfileCommand,
    },
    /// Read retained diagnosis and build output.
    History {
        project: PathBuf,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Execute the exact previously reviewed profile in the sandbox.
    Run {
        project: PathBuf,
        #[arg(long)]
        expected_profile_sha256: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum BuildProfileCommand {
    /// Display the retained configuration.
    Show {
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate and save an explicit configuration.
    Set {
        project: PathBuf,
        #[arg(long)]
        component_root: String,
        #[arg(long, value_enum)]
        build_system: ProfileSystemArg,
        #[arg(long)]
        compile_database_path: String,
        /// Repeat `NAME=VALUE` for each `CMake` definition.
        #[arg(long = "define")]
        definitions: Vec<String>,
        /// Repeat `command:NAME` or `pkg_config:MODULE`.
        #[arg(long = "dependency")]
        dependencies: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Remove the current profile, retaining operation history.
    Clear {
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
pub(crate) enum ProfileSystemArg {
    Cmake,
    Make,
}

#[cfg(all(test, not(feature = "build-doctor")))]
mod build_read_feature_off_tests {
    use super::*;
    #[test]
    fn profile_show_is_available_without_build_doctor() {
        assert!(
            Cli::try_parse_from(["oxfuzz", "build", "profile", "show", "/project", "--json"])
                .is_ok()
        );
    }
}

#[cfg(test)]
mod demo_cli_tests {
    use super::Cli;
    use clap::Parser as _;

    #[test]
    fn draft_json_requires_a_nonexecuting_draft() {
        let base = [
            "oxfuzz",
            "harness",
            "/tmp/project",
            "--target",
            "parse",
            "--engine",
            "libfuzzer",
        ];
        let mut args = base.to_vec();
        args.extend(["--draft-only", "--json"]);
        assert!(Cli::try_parse_from(&args).is_ok());
        for flag in ["--refine", "--promote"] {
            let mut invalid = args.clone();
            invalid.push(flag);
            assert!(Cli::try_parse_from(invalid).is_err());
        }
        let mut invalid = args.clone();
        invalid.extend(["--repair", "1"]);
        assert!(Cli::try_parse_from(invalid).is_err());
        let mut invalid = base.to_vec();
        invalid.push("--json");
        assert!(Cli::try_parse_from(invalid).is_err());
    }

    #[test]
    fn selected_doctor_accepts_campaign_inputs_and_requires_engine_scope() {
        assert!(Cli::try_parse_from([
            "oxfuzz",
            "doctor",
            "--engine",
            "libfuzzer",
            "--duration",
            "30s",
            "--require-provider",
            "--json"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["oxfuzz", "doctor", "--require-provider"]).is_err());
        assert!(Cli::try_parse_from(["oxfuzz", "doctor", "--duration", "30s"]).is_err());
    }

    #[cfg(feature = "harness-work-order")]
    #[test]
    fn work_order_json_export_excludes_markdown_output() {
        let mut args = vec![
            "oxfuzz",
            "work-order",
            "export",
            "/tmp/project",
            "--target",
            "parse",
            "--engine",
            "libfuzzer",
            "--lang",
            "c",
            "--json",
        ];
        assert!(Cli::try_parse_from(&args).is_ok());
        args.extend(["--out", "packet.md"]);
        assert!(Cli::try_parse_from(args).is_err());
    }
}
