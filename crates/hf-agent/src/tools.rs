//! Model-facing catalog for fuzzing tools dispatched by [`crate::AgentBackend`].

/// The agent's tools as `(name, description)` pairs -- the authoritative roster
/// the agent can call. Presentation layers render this for the Agents view.
pub const TOOL_SPECS: &[(&str, &str)] = &[
    ("discover", "Scan the project and rank fuzzable targets"),
    (
        "harness",
        "Draft, sandbox-compile, and smoke-test a harness for operator review",
    ),
    ("run", "Drive a fuzzing engine against a compiled harness"),
    ("triage", "Reproduce, classify, and deduplicate crashes"),
    ("corpus", "Seed, grow, prune, or list the corpus"),
];

/// Per-tool usage lines for the system-prompt catalog, keyed by tool name.
const TOOL_USAGE: &[(&str, &str)] = &[
    (
        "discover",
        r#"- discover {"lang": "c|cpp|rust|go|python"} -> ranked fuzzing targets in the project"#,
    ),
    (
        "harness",
        r#"- harness {"target": "<symbol>", "engine": "libfuzzer|afl++|honggfuzz|clusterfuzzlite", "lang": "c"} -> draft, compile, and smoke-test a harness; a human must promote it"#,
    ),
    (
        "run",
        r#"- run {"target": "<symbol>", "engine": "libfuzzer", "duration_secs": 60} -> run a fuzz campaign (requires a promoted harness)"#,
    ),
    (
        "triage",
        r#"- triage {"target": "<symbol>"} -> ingest and deduplicate crash artifacts"#,
    ),
    (
        "corpus",
        r#"- corpus {"target": "<symbol>", "op": "seed|grow|prune|list"} -> manage the corpus"#,
    ),
    (
        "delegate",
        r#"- delegate {"agent": "target-scout|harness-author|run-operator|crash-triager|coverage-analyst|corpus-curator", "task": "<instruction>"} -> hand a scoped subtask to a specialist sub-agent and get its result"#,
    ),
];

/// The full tool catalog (all tools), for the default/orchestrator agent.
pub const TOOL_CATALOG: &str = r#"Available tools (call one per step):
- discover {"lang": "c|cpp|rust|go|python"} -> ranked fuzzing targets in the project
- harness {"target": "<symbol>", "engine": "libfuzzer|afl++|honggfuzz|clusterfuzzlite", "lang": "c"} -> draft, compile, and smoke-test a harness; a human must promote it
- run {"target": "<symbol>", "engine": "libfuzzer", "duration_secs": 60} -> run a fuzz campaign (requires a promoted harness)
- triage {"target": "<symbol>"} -> ingest and deduplicate crash artifacts
- corpus {"target": "<symbol>", "op": "seed|grow|prune|list"} -> manage the corpus"#;

/// Build a tool catalog limited to `allowed` tools, for an agent that may only
/// call a subset. Unknown names are ignored; an empty result means no tools.
#[must_use]
pub fn catalog_for(allowed: &[String]) -> String {
    let lines: Vec<&str> = TOOL_USAGE
        .iter()
        .filter(|(name, _)| allowed.iter().any(|a| a == name))
        .map(|(_, usage)| *usage)
        .collect();
    if lines.is_empty() {
        return "This agent has no tools; answer the user directly.".to_owned();
    }
    format!("Available tools (call one per step):\n{}", lines.join("\n"))
}
