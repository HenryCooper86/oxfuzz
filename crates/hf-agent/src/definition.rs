//! The agent definition: the single source of truth for what an agent is.
//!
//! One flat-TOML struct determines an agent's role prompt, tools, model routing,
//! and limits. A definition is parsed from a `config/agents/<id>.toml` file or
//! from a built-in embedded in the binary; the same struct models both.

use serde::{Deserialize, Serialize};

/// The fuzzing-pipeline role an agent specializes in. Informational (drives the
/// GUI icon/grouping); the concrete capability is set by `allowed_tools`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentRole {
    /// Drives the whole campaign across every stage.
    Orchestrator,
    /// Finds and ranks fuzzable targets.
    Discovery,
    /// Writes and compiles harnesses.
    HarnessAuthor,
    /// Configures and runs fuzzers.
    RunOperator,
    /// Classifies crashes and drafts bug reports.
    Triage,
    /// Watches coverage and stagnation.
    Coverage,
    /// Seeds, grows, prunes, and merges corpora.
    Corpus,
}

impl AgentRole {
    /// A short, stable label for presentation.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Orchestrator => "Orchestrator",
            Self::Discovery => "Discovery",
            Self::HarnessAuthor => "Harness Author",
            Self::RunOperator => "Run Operator",
            Self::Triage => "Triage",
            Self::Coverage => "Coverage",
            Self::Corpus => "Corpus",
        }
    }
}

/// How much the agent may act without human confirmation. Surfaced to the user
/// and (via the container's guardrails) governs whether risky tool calls prompt
/// for approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Autonomy {
    /// Every privileged action requires explicit approval.
    Manual,
    /// Reads/analysis run freely; builds and runs prompt for approval.
    #[default]
    Assist,
    /// Runs the whole pipeline without prompting (trusted, local use).
    Auto,
}

/// Provenance of a definition: a shipped built-in or a user-authored file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Ships with `hobot_fuzz`; embedded in the binary, resettable.
    BuiltIn,
    /// Authored or overridden by the user under `config/agents/`.
    #[default]
    UserDefined,
}

const fn default_max_iterations() -> usize {
    12
}
const fn default_user_callable() -> bool {
    true
}

/// A rule that an agent must call a specific tool before its turn may end. When a
/// turn tries to finish without having called `tool`, the loop injects `reminder`
/// (via the L5 system-reminder channel) and retries, up to a bounded number of
/// attempts, before giving up and accepting the answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompletionRequirement {
    /// The tool that must be called before the turn ends.
    pub tool: String,
    /// The reminder injected when the turn tries to end without having called it.
    pub reminder: String,
}

/// A complete agent: identity, the system prompt that defines its behavior, the
/// tools it may call, and its model-routing and iteration limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDefinition {
    /// Stable identifier (kebab-case; the TOML file stem).
    pub id: String,
    /// Human-facing name.
    pub name: String,
    /// One-line summary shown in the roster.
    pub description: String,
    /// The fuzzing role this agent specializes in.
    pub role: AgentRole,
    /// Optional short icon/emoji for the GUI.
    #[serde(default)]
    pub icon: Option<String>,
    /// The role-specific prompt. The runtime wraps it with the invariant
    /// identity and security rules, active project boundary, selected skills,
    /// executable tool catalogs, and tool-call protocol.
    pub system_prompt: String,
    /// The tool names this agent may call (must match the runtime roster:
    /// `discover`, `harness`, `run`, `triage`, `corpus`).
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    /// Skill names whose playbooks are injected into this agent's context.
    #[serde(default)]
    pub skills: Vec<String>,
    /// Provider-routing tags. Empty falls back to the default route.
    #[serde(default)]
    pub model_tags: Vec<String>,
    /// Sampling temperature passed to the provider (if set).
    #[serde(default)]
    pub temperature: Option<f64>,
    /// Hard cap on reason/act iterations per turn.
    #[serde(default = "default_max_iterations")]
    pub max_iterations: usize,
    /// How much the agent may act without confirmation.
    #[serde(default)]
    pub autonomy: Autonomy,
    /// Free-form capability tags (searchable in the GUI).
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Whether the user can pick this agent to drive a chat.
    #[serde(default = "default_user_callable")]
    pub user_callable: bool,
    /// Provenance. Set by the registry on load; never read from the file.
    #[serde(default, skip_serializing)]
    pub trust_tier: TrustTier,
    /// Optional rule requiring a specific tool be called before the turn may end
    /// (L4). Absent for most agents; the loop enforces it only when present.
    #[serde(default)]
    pub completion_requirement: Option<CompletionRequirement>,
}

impl AgentDefinition {
    /// Parse a definition from TOML.
    ///
    /// # Errors
    /// Returns the `toml` error if the document is malformed or missing a
    /// required field.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }

    /// Serialize the definition to TOML for persistence.
    ///
    /// # Errors
    /// Returns the `toml` serialization error (e.g. an unrepresentable value).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// The provider-routing tags as borrowed slices, for the provider pool.
    #[must_use]
    pub fn route_tags(&self) -> Vec<&str> {
        self.model_tags.iter().map(String::as_str).collect()
    }
}
