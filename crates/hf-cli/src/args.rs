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
        /// How `--rank` may use the model: `auto` warns and keeps heuristic
        /// scores when none is configured, `require` fails instead.
        #[arg(long, value_enum, default_value_t = AiOption::Auto)]
        ai: AiOption,
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
        /// Generated function harnesses support AFL++, honggfuzz, and
        /// libFuzzer only.
        ///
        /// Syzkaller kernel campaigns use the local desktop application's
        /// dedicated kernel-campaign workflow with operator approval and
        /// handoff.
        #[arg(long)]
        engine: String,
        /// Target language (c, cpp, rust, go, python). Defaults to c.
        #[arg(long, default_value = "c")]
        lang: String,
        /// Skip compile and smoke fuzz (draft only).
        #[arg(long)]
        draft_only: bool,
        /// Which generator writes the harness: `auto` uses the model when one
        /// is configured, `require` fails rather than substituting the
        /// template, `off` never calls a model.
        #[arg(long, value_enum, default_value_t = AiOption::Auto)]
        ai: AiOption,
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
        /// How the campaign may use the model. It reaches one in four places:
        /// seed generation, the run dictionary, triage bug reports, and the
        /// coverage-plateau harness refine. (Target auto-pick is a
        /// deterministic fit-score sort, not a model call.) `off` calls no
        /// model at all; `require` refuses to start when none is configured or
        /// all are frozen, but cannot promise a mid-run outage did not degrade
        /// a step, since each one warns and continues by design.
        #[arg(long, value_enum, default_value_t = AiOption::Auto)]
        ai: AiOption,
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
        /// Operation: seed, llmseed, grow, prune, cprune, survival, regen,
        /// minimize, absorb, concolic, import, list.
        #[arg(long)]
        op: String,
        /// Source directory for `import` (an external corpus, e.g. OSS-Fuzz).
        #[arg(long)]
        from: Option<PathBuf>,
    },
    /// Report line/function/region coverage for a target's corpus.
    Coverage {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
    },
    /// Audit which claims about a finished run its retained evidence supports.
    /// Reads only; starts no build, run, or coverage measurement.
    #[cfg(feature = "campaign-trust")]
    Trust {
        /// Run identifier to audit.
        #[arg(long)]
        run: String,
    },
    /// Rank entry points no retained coverage measurement has ever covered.
    /// Reads cached measurements; never triggers one.
    #[cfg(feature = "unreached-surface")]
    Unreached {
        /// Project root path.
        project: PathBuf,
        /// Source language.
        #[arg(long, default_value = "c")]
        lang: String,
    },
    /// Attribute every discovered target against retained coverage and order
    /// the result for the next harness: untouched first, partial frontier
    /// next, saturated last. Reads cached measurements; never triggers one.
    #[cfg(feature = "unreached-surface")]
    Attribution {
        /// Project root path.
        project: PathBuf,
        /// Source language.
        #[arg(long, default_value = "c")]
        lang: String,
    },
    /// Report campaign health conditions for a run. Reads retained state;
    /// never stops, restarts, or resizes a campaign.
    #[cfg(feature = "campaign-health")]
    Health {
        /// Run identifier to assess.
        #[arg(long)]
        run: String,
    },
    /// Run the post-run analysis chain for a finished run: triage, minimize,
    /// corpus absorb, coverage, blockers, disposition, trust report. Resumes at
    /// the first step that never finished.
    #[cfg(feature = "run-closeout")]
    Closeout {
        /// Run identifier to close out.
        #[arg(long)]
        run: String,
    },
    /// Manage durable harness work orders.
    #[cfg(feature = "harness-work-order")]
    WorkOrder {
        #[command(subcommand)]
        command: crate::work_order::WorkOrderCommand,
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
        /// How the gate may use the model. It reaches one in two places: the
        /// run dictionary and triage bug reports. (Its seeds are the heuristic
        /// generator, not the model.) `off` calls no model at all; `require`
        /// refuses to start when none is configured or all are frozen. `off` is
        /// the exact side of this flag: a CI gate that must not spend tokens
        /// wants it.
        #[arg(long, value_enum, default_value_t = AiOption::Auto)]
        ai: AiOption,
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
    /// Authorize a running server to act on work restored after a restart.
    ///
    /// A scheduler starts disarmed on every process start: recovery restores
    /// what it was doing, and missed occurrences a catch-up or backfill policy
    /// would replay are held rather than fired. This releases them.
    Arm {
        /// Base URL of the running oxfuzz server.
        #[arg(long, default_value = "http://127.0.0.1:8081")]
        url: String,
        /// Withdraw authorization instead of granting it.
        #[arg(long, conflicts_with = "status")]
        off: bool,
        /// Report whether the server is armed, changing nothing.
        #[arg(long)]
        status: bool,
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
        let Commands::Harness { ai, .. } = harness.command else {
            panic!("expected harness");
        };
        assert_eq!(ai, AiOption::Auto);

        let campaign = Cli::try_parse_from(["oxfuzz", "campaign", "/p"]).unwrap();
        let Commands::Campaign { ai, .. } = campaign.command else {
            panic!("expected campaign");
        };
        assert_eq!(ai, AiOption::Auto);

        let ci = Cli::try_parse_from(["oxfuzz", "ci", "/p", "--target", "t"]).unwrap();
        let Commands::Ci { ai, .. } = ci.command else {
            panic!("expected ci");
        };
        assert_eq!(ai, AiOption::Auto);

        let discover = Cli::try_parse_from(["oxfuzz", "discover", "/p", "--lang", "c"]).unwrap();
        let Commands::Discover { ai, .. } = discover.command else {
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
            let Commands::Campaign { ai, .. } = campaign.command else {
                panic!("expected campaign");
            };
            assert_eq!(ai, expected, "campaign --ai {value}");

            let ci = Cli::try_parse_from(["oxfuzz", "ci", "/p", "--target", "t", "--ai", value])
                .unwrap();
            let Commands::Ci { ai, .. } = ci.command else {
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
