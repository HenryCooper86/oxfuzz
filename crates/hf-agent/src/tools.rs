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

/// The JSON Schema for a fuzzing tool's arguments, or `None` for a tool without
/// one. Kept alongside the model-facing catalog (`TOOL_USAGE`) so the advertised
/// argument shape and the validated shape cannot drift.
#[must_use]
pub fn fuzzing_tool_schema(name: &str) -> Option<serde_json::Value> {
    use serde_json::json;
    // Schemas mirror the dispatcher's argument handling: `target` is required
    // wherever dispatch reads it as mandatory; `engine`/`lang` are optional
    // strings; the numeric args are integers. Types are constrained (not values)
    // so the dispatcher's own parsers still own enum errors, and unknown
    // properties are tolerated (the dispatcher ignores them).
    let schema = match name {
        "discover" => json!({
            "type": "object",
            "properties": { "lang": { "type": "string" } },
        }),
        "harness" => json!({
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string" },
                "engine": { "type": "string" },
                "lang": { "type": "string" },
            },
        }),
        "refine" => json!({
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string" },
                "engine": { "type": "string" },
                "lang": { "type": "string" },
                "max_repairs": { "type": "integer", "minimum": 1 },
            },
        }),
        "run" => json!({
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string" },
                "engine": { "type": "string" },
                "duration_secs": { "type": "integer", "minimum": 1 },
            },
        }),
        "triage" => json!({
            "type": "object",
            "required": ["target"],
            "properties": { "target": { "type": "string" } },
        }),
        "corpus" => json!({
            "type": "object",
            "required": ["target"],
            "properties": {
                "target": { "type": "string" },
                "op": { "type": "string" },
            },
        }),
        _ => return None,
    };
    Some(schema)
}

/// Validate a tool call's arguments against its schema (L1). Tools without a
/// schema -- delegate, inspection reads, or an unknown name -- validate
/// vacuously. On mismatch the error is a structured message the model can read
/// and correct, so a hallucinated or wrong-typed argument is rejected instead of
/// being silently mis-parsed or defaulted by the dispatcher.
///
/// # Errors
/// Returns the schema-validation error message when `args` does not conform.
pub fn validate_tool_args(name: &str, args: &serde_json::Value) -> Result<(), String> {
    let Some(schema) = fuzzing_tool_schema(name) else {
        return Ok(());
    };
    hf_tools::JsonSchemaValidator::new()
        .validate(&schema, args)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
    fn schema_requires_target_for_the_tools_that_need_it() {
        for tool in ["harness", "run", "triage", "corpus", "refine"] {
            let missing = validate_tool_args(tool, &json!({}));
            assert!(
                missing.is_err(),
                "{tool} must require `target`: {missing:?}"
            );
            let ok = validate_tool_args(tool, &json!({ "target": "parse" }));
            assert!(ok.is_ok(), "{tool} accepts a valid target: {ok:?}");
        }
    }

    #[test]
    fn schema_rejects_wrong_types_instead_of_silently_mis_parsing() {
        // Today these are swallowed by as_str()/as_u64() and silently defaulted.
        assert!(validate_tool_args("harness", &json!({"target": "p", "engine": 7})).is_err());
        assert!(validate_tool_args("run", &json!({"target": "p", "duration_secs": "60"})).is_err());
        assert!(validate_tool_args("discover", &json!({"lang": 5})).is_err());
    }

    #[test]
    fn schema_accepts_valid_args_and_leaves_unschemaed_tools_alone() {
        assert!(validate_tool_args(
            "harness",
            &json!({"target": "p", "engine": "libfuzzer", "lang": "c"})
        )
        .is_ok());
        assert!(validate_tool_args("run", &json!({"target": "p", "duration_secs": 60})).is_ok());
        assert!(
            validate_tool_args("discover", &json!({})).is_ok(),
            "discover has no required args"
        );
        // A tool with no schema (unknown, delegate, or an inspection read) is vacuous.
        assert!(validate_tool_args("nonexistent", &json!({})).is_ok());
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
