//! Model-facing catalog for fuzzing tools dispatched by [`crate::AgentBackend`].

/// The agent's tools as `(name, description)` pairs -- the authoritative roster
/// the agent can call. Presentation layers render this for the Agents view.
pub const TOOL_SPECS: &[(&str, &str)] = &[
    ("discover", "Scan the project and rank fuzzable targets"),
    (
        "harness",
        "Draft, sandbox-compile, and smoke-test a harness for operator review",
    ),
    (
        "refine",
        "Reshape the current harness toward uncovered code and recompile a proposal",
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
        "refine",
        r#"- refine {"target": "<symbol>", "engine": "libfuzzer", "lang": "c"} -> reshape the CURRENT harness toward uncovered code and recompile a proposal; then re-run smoke qualification. Use this when a smoke verdict is not a clean pass. A human still promotes."#,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refine_is_a_first_class_tool_in_the_catalog() {
        // The orchestrator can only act on a hollow-pass verdict if `refine` is a
        // callable tool it can both see and be permitted. Lock the roster and the
        // per-agent usage catalog together.
        assert!(
            TOOL_SPECS.iter().any(|(name, _)| *name == "refine"),
            "refine must be in the authoritative tool roster"
        );
        let catalog = catalog_for(&["refine".to_owned()]);
        assert!(
            catalog.contains("refine"),
            "an agent allowed `refine` must see it in its usage catalog: {catalog}"
        );
    }

    #[test]
    fn catalog_omits_tools_an_agent_is_not_allowed() {
        // Gating is by allow-list: a harness-only agent must not see run/triage.
        let catalog = catalog_for(&["harness".to_owned(), "refine".to_owned()]);
        assert!(catalog.contains("harness") && catalog.contains("refine"));
        assert!(
            !catalog.contains("triage"),
            "unlisted tools stay hidden: {catalog}"
        );
    }
}
