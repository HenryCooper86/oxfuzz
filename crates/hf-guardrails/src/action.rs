//! The action taxonomy guardrails reason about, and their risk tiers.

use serde::{Deserialize, Serialize};

/// A privileged operation the agent or service may attempt. Guardrails assess
/// each action's risk before it executes (AGENTS.md 2.5 / 2.12).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// Scan a project for fuzzing targets (read-only).
    Discover,
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
    /// A short, human-readable label for prompts and audit logs.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Action::Discover => "discover targets".to_owned(),
            Action::DraftHarness => "draft harness".to_owned(),
            Action::CompileHarness => "compile harness in sandbox".to_owned(),
            Action::RunHarness => "run harness (smoke fuzz)".to_owned(),
            Action::RunFuzzer {
                engine,
                duration_secs,
            } => format!("run {engine} for {duration_secs}s"),
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
            Action::CompileHarness | Action::Triage | Action::AgentTool { .. } => RiskTier::Medium,
            Action::RunHarness | Action::RunFuzzer { .. } | Action::WriteHostFile { .. } => {
                RiskTier::High
            }
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
