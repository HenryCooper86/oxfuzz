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

/// The tool catalog injected into the system prompt. Kept terse to stay within
/// the token budget (AGENTS.md 2.4).
pub const TOOL_CATALOG: &str = r#"Available tools (call one per step):
- discover {"lang": "c|cpp|rust|go|python"} -> ranked fuzzing targets in the project
- harness {"target": "<symbol>", "engine": "libfuzzer|afl++|honggfuzz|clusterfuzzlite", "lang": "c"} -> draft + compile a harness in the sandbox
- run {"target": "<symbol>", "engine": "libfuzzer", "lang": "c", "duration_secs": 60} -> run a fuzz campaign (requires a compiled harness)
- triage {"target": "<symbol>"} -> ingest and deduplicate crash artifacts
- corpus {"target": "<symbol>", "op": "seed|grow|prune|list"} -> manage the corpus"#;

fn parse_lang(s: &str) -> Result<TargetLanguage, ClassifiedError> {
    match s.to_ascii_lowercase().as_str() {
        "c" => Ok(TargetLanguage::C),
        "cpp" | "c++" => Ok(TargetLanguage::Cpp),
        "rust" | "rs" => Ok(TargetLanguage::Rust),
        "go" => Ok(TargetLanguage::Go),
        "python" | "py" => Ok(TargetLanguage::Python),
        other => Err(ClassifiedError::Validation(format!(
            "unsupported language: {other}"
        ))),
    }
}

fn parse_engine(s: &str) -> Result<EngineKind, ClassifiedError> {
    match s.to_ascii_lowercase().as_str() {
        "afl++" | "aflplusplus" => Ok(EngineKind::AflPlusPlus),
        "honggfuzz" | "hfuzz" => Ok(EngineKind::Honggfuzz),
        "libfuzzer" | "libfuzz" => Ok(EngineKind::LibFuzzer),
        "clusterfuzzlite" | "cfl" => Ok(EngineKind::ClusterFuzzLite),
        "syzkaller" | "syz" => Ok(EngineKind::Syzkaller),
        other => Err(ClassifiedError::Validation(format!(
            "unsupported engine: {other}"
        ))),
    }
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
