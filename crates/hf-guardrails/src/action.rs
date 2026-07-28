//! The action taxonomy guardrails reason about, and their risk tiers.

use serde::{Deserialize, Serialize};

/// A privileged operation the agent or service may attempt. Guardrails assess
/// each action's risk before it executes (AGENTS.md 2.5 / 2.12).
///
/// `ShellExec` is a deliberate deny sentinel and `WriteHostFile` is reserved
/// for a future host-write tool: neither is wired to a service entry point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Scan a project for fuzzing targets (read-only).
    Discover,
    /// Analyze project source with one service-owned static analyzer.
    AnalyzeSource {
        /// Stable analyzer identifier.
        analyzer: String,
    },
    /// Ask the LLM to draft harness source (no execution).
    DraftHarness,
    /// Compile untrusted harness + target source in the sandbox.
    CompileHarness,
    /// Execute a compiled harness binary (smoke fuzz) in the sandbox.
    RunHarness,
    /// Launch a fuzzing campaign that runs untrusted code under an engine.
    RunFuzzer {
        /// The fuzzing engine.
        engine: String,
        /// Requested wall-clock duration in seconds.
        duration_secs: u64,
    },
    /// Parse or transform automotive artifacts without opening a bus interface.
    AutomotiveOffline {
        /// Sidecar operation such as `analyze_pcap` or `generate_mutations`.
        operation: String,
    },
    /// Exchange automotive frames only through an isolated virtual CAN device.
    AutomotiveVirtualCan {
        /// Primary automotive protocol.
        protocol: String,
        /// Maximum session duration in seconds.
        duration_secs: u64,
    },
    /// Exchange frames through an allowlisted physical bench CAN interface.
    AutomotivePhysicalBench {
        /// Host interface exposed to the sandbox.
        interface: String,
        /// Primary automotive protocol.
        protocol: String,
        /// Maximum session duration in seconds.
        duration_secs: u64,
    },
    /// Parse untrusted crash artifacts produced by a fuzzer.
    Triage,
    /// A corpus filesystem operation within the workspace.
    CorpusOp,
    /// A free-form chat turn with the model.
    Chat,
    /// Execute an arbitrary shell command (highest risk).
    ShellExec {
        /// The command line that would run.
        command: String,
    },
    /// Write a file on the host outside the managed workspace.
    WriteHostFile {
        /// The destination path.
        path: String,
    },
    /// An agent tool invocation gated for approval because the driving agent
    /// runs with manual autonomy (every action needs operator consent). This is
    /// a tighten-only signal -- it only ever asks; it never auto-allows.
    AgentTool {
        /// The tool the agent wants to run.
        name: String,
    },
}

impl Action {
    /// The stable `snake_case` kind of this action, matching its serde tag.
    /// Used for durable audit records where the human-readable [`Self::label`]
    /// (which embeds parameters) would not group cleanly.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Action::Discover => "discover",
            Action::AnalyzeSource { .. } => "analyze_source",
            Action::DraftHarness => "draft_harness",
            Action::CompileHarness => "compile_harness",
            Action::RunHarness => "run_harness",
            Action::RunFuzzer { .. } => "run_fuzzer",
            Action::AutomotiveOffline { .. } => "automotive_offline",
            Action::AutomotiveVirtualCan { .. } => "automotive_virtual_can",
            Action::AutomotivePhysicalBench { .. } => "automotive_physical_bench",
            Action::Triage => "triage",
            Action::CorpusOp => "corpus_op",
            Action::Chat => "chat",
            Action::ShellExec { .. } => "shell_exec",
            Action::WriteHostFile { .. } => "write_host_file",
            Action::AgentTool { .. } => "agent_tool",
        }
    }

    /// A short, human-readable label for prompts and audit logs.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Action::Discover => "discover targets".to_owned(),
            Action::AnalyzeSource { analyzer } => format!("analyze source with {analyzer}"),
            Action::DraftHarness => "draft harness".to_owned(),
            Action::CompileHarness => "compile harness in sandbox".to_owned(),
            Action::RunHarness => "run harness (smoke fuzz)".to_owned(),
            Action::RunFuzzer {
                engine,
                duration_secs,
            } => format!("run {engine} for {duration_secs}s"),
            Action::AutomotiveOffline { operation } => {
                format!("automotive offline {operation}")
            }
            Action::AutomotiveVirtualCan {
                protocol,
                duration_secs,
            } => format!("automotive virtual CAN {protocol} for {duration_secs}s"),
            Action::AutomotivePhysicalBench {
                interface,
                protocol,
                duration_secs,
            } => format!(
                "automotive physical CAN interface {interface} using {protocol} for {duration_secs}s"
            ),
            Action::Triage => "triage crash artifacts".to_owned(),
            Action::CorpusOp => "corpus operation".to_owned(),
            Action::Chat => "chat turn".to_owned(),
            Action::ShellExec { command } => format!("shell: {command}"),
            Action::WriteHostFile { path } => format!("write host file: {path}"),
            Action::AgentTool { name } => format!("agent tool: {name}"),
        }
    }

    /// The inherent risk tier of this action.
    #[must_use]
    pub fn risk(&self) -> RiskTier {
        match self {
            Action::Discover | Action::DraftHarness | Action::CorpusOp | Action::Chat => {
                RiskTier::Low
            }
            Action::CompileHarness
            | Action::AnalyzeSource { .. }
            | Action::Triage
            | Action::AutomotiveOffline { .. }
            | Action::AgentTool { .. } => RiskTier::Medium,
            Action::RunHarness
            | Action::RunFuzzer { .. }
            | Action::AutomotiveVirtualCan { .. }
            | Action::AutomotivePhysicalBench { .. }
            | Action::WriteHostFile { .. } => RiskTier::High,
            Action::ShellExec { .. } => RiskTier::Critical,
        }
    }
}

/// Risk tiers, ordered from least to most dangerous. The derived `Ord` follows
/// declaration order, so comparisons (`tier >= RiskTier::High`) work directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Read-only or in-workspace, no untrusted execution.
    Low,
    /// Builds or parses untrusted input in the sandbox.
    Medium,
    /// Executes untrusted code or writes outside the workspace.
    High,
    /// Arbitrary command execution.
    Critical,
}

impl RiskTier {
    /// The stable lowercase name of this tier, matching its serde form. Used
    /// for durable audit records.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskTier::Low => "low",
            RiskTier::Medium => "medium",
            RiskTier::High => "high",
            RiskTier::Critical => "critical",
        }
    }
}
