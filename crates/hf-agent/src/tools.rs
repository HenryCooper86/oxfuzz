//! The fuzzing toolset the agent can invoke, bound to a [`ServiceContainer`].

use std::path::Path;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use serde_json::Value;

/// The agent's tools as `(name, description)` pairs -- the authoritative roster
/// the agent can call. Presentation layers render this for the Agents view.
pub const TOOL_SPECS: &[(&str, &str)] = &[
    ("discover", "Scan the project and rank fuzzable targets"),
    (
        "harness",
        "Draft + compile a harness for a target in the sandbox",
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
        r#"- harness {"target": "<symbol>", "engine": "libfuzzer|afl++|honggfuzz|clusterfuzzlite", "lang": "c"} -> draft + compile a harness in the sandbox"#,
    ),
    (
        "run",
        r#"- run {"target": "<symbol>", "engine": "libfuzzer", "lang": "c", "duration_secs": 60} -> run a fuzz campaign (requires a compiled harness)"#,
    ),
    (
        "triage",
        r#"- triage {"target": "<symbol>"} -> ingest and deduplicate crash artifacts"#,
    ),
    (
        "corpus",
        r#"- corpus {"target": "<symbol>", "op": "seed|grow|prune|list"} -> manage the corpus"#,
    ),
];

/// The full tool catalog (all tools), for the default/orchestrator agent.
pub const TOOL_CATALOG: &str = r#"Available tools (call one per step):
- discover {"lang": "c|cpp|rust|go|python"} -> ranked fuzzing targets in the project
- harness {"target": "<symbol>", "engine": "libfuzzer|afl++|honggfuzz|clusterfuzzlite", "lang": "c"} -> draft + compile a harness in the sandbox
- run {"target": "<symbol>", "engine": "libfuzzer", "lang": "c", "duration_secs": 60} -> run a fuzz campaign (requires a compiled harness)
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

// Parse via the canonical `FromStr` impls in `hf-core` so the agent accepts the
// exact same engine/language aliases as the CLI, web, and GUI layers -- a local
// copy here had drifted to a narrower alias set (rejecting e.g. `afl`, `golang`,
// `lf`), making the shared agent path less capable than the layers it unifies.
fn parse_lang(s: &str) -> Result<TargetLanguage, ClassifiedError> {
    s.parse().map_err(ClassifiedError::Validation)
}

fn parse_engine(s: &str) -> Result<EngineKind, ClassifiedError> {
    s.parse().map_err(ClassifiedError::Validation)
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, ClassifiedError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ClassifiedError::Validation(format!("missing string arg '{key}'")))
}

/// Execute a tool call and return a compact JSON/text result for the model.
///
/// # Errors
/// Returns `ClassifiedError` if the tool is unknown, arguments are invalid, no
/// project is set, or the underlying service call fails (including guardrail
/// denials, surfaced as validation errors).
pub async fn dispatch(
    container: &ServiceContainer,
    project: Option<&Path>,
    name: &str,
    args: &Value,
) -> Result<String, ClassifiedError> {
    let project = project.ok_or_else(|| {
        ClassifiedError::Validation("no project selected; choose a project folder first".to_owned())
    })?;

    match name {
        "discover" => {
            let lang = parse_lang(arg_str(args, "lang").unwrap_or("c"))?;
            let inv = container.discover(project, lang).await?;
            let top: Vec<Value> = inv
                .ranked()
                .into_iter()
                .take(10)
                .map(|c| {
                    serde_json::json!({
                        "symbol": c.symbol,
                        "fit_score": c.fit_score,
                        "kind": format!("{:?}", c.kind),
                        "location": format!("{}:{}", c.location.file.display(), c.location.line),
                    })
                })
                .collect();
            Ok(serde_json::json!({ "targets": top }).to_string())
        }
        "harness" => {
            let target = arg_str(args, "target")?;
            let engine = parse_engine(arg_str(args, "engine").unwrap_or("libfuzzer"))?;
            let lang = parse_lang(arg_str(args, "lang").unwrap_or("c"))?;
            let draft = container
                .harness_draft(project, target, engine, lang)
                .await?;
            let outcome = container
                .harness_compile(draft.source, project, engine, target, lang)
                .await?;
            Ok(serde_json::json!({
                "compiled": format!("{:?}", outcome.status),
                "binary": outcome.binary_name,
            })
            .to_string())
        }
        "run" => {
            let target = arg_str(args, "target")?;
            let engine = parse_engine(arg_str(args, "engine").unwrap_or("libfuzzer"))?;
            let duration_secs = args
                .get("duration_secs")
                .and_then(Value::as_u64)
                .unwrap_or(60);
            let summary = container
                .run_fuzzer(project, target, engine, duration_secs, &|_p| {})
                .await?;
            Ok(serde_json::json!({
                "edges": summary.edges,
                "execs_per_sec": summary.execs,
                "crashes": summary.crashes,
            })
            .to_string())
        }
        "triage" => {
            let target = arg_str(args, "target")?;
            let crashes = container.triage(project, target).await?;
            let items: Vec<Value> = crashes
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "kind": format!("{:?}", c.kind),
                        "summary": c.summary,
                        "stack_signature": c.stack_signature,
                        "minimized": c.minimized,
                    })
                })
                .collect();
            Ok(serde_json::json!({ "unique_crashes": items.len(), "crashes": items }).to_string())
        }
        "corpus" => {
            let target = arg_str(args, "target")?;
            let op = arg_str(args, "op").unwrap_or("list");
            let result = match op {
                "seed" => format!(
                    "seeded {} entries",
                    container.corpus_seed(project, target).await?
                ),
                "grow" => format!(
                    "corpus now {} entries",
                    container.corpus_grow(project, target).await?
                ),
                "prune" => format!(
                    "pruned to {} entries",
                    container.corpus_prune(project, target)?
                ),
                "list" => format!(
                    "{} entries",
                    container.corpus_list(project, target)?.entries.len()
                ),
                other => {
                    return Err(ClassifiedError::Validation(format!(
                        "unknown corpus op: {other}"
                    )))
                }
            };
            Ok(serde_json::json!({ "result": result }).to_string())
        }
        other => Err(ClassifiedError::Validation(format!(
            "unknown tool: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_engine, parse_lang};
    use hf_core::engine::EngineKind;
    use hf_core::target::TargetLanguage;

    #[test]
    fn parsers_accept_canonical_aliases() {
        // These aliases were rejected by the old hand-rolled matchers but are
        // accepted by every other layer's canonical FromStr.
        assert_eq!(parse_engine("afl").unwrap(), EngineKind::AflPlusPlus);
        assert_eq!(parse_engine("lf").unwrap(), EngineKind::LibFuzzer);
        assert_eq!(parse_engine("cflite").unwrap(), EngineKind::ClusterFuzzLite);
        assert_eq!(parse_lang("golang").unwrap(), TargetLanguage::Go);
        assert_eq!(parse_lang("cxx").unwrap(), TargetLanguage::Cpp);
    }

    #[test]
    fn parsers_reject_unknown() {
        assert!(parse_engine("nope").is_err());
        assert!(parse_lang("cobol").is_err());
    }
}
