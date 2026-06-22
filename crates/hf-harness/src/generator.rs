//! Harness generator: draft -> compile -> smoke fuzz.

use std::path::{Path, PathBuf};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessDraft, HarnessStatus, SmokeRunSummary};
use hf_core::provider::LlmProvider;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{TargetCandidate, TargetLanguage};
use hf_core::types::{Message, Role};
use hf_prompt::render_harness_prompt;
use uuid::Uuid;

/// Draft a harness for a target using the LLM.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails or the response contains
/// no fenced code block.
pub async fn draft(
    target: &TargetCandidate,
    engine: EngineKind,
    llm: Box<dyn LlmProvider>,
) -> Result<HarnessDraft, ClassifiedError> {
    let prompt = render_harness_prompt(target, engine);
    let messages = vec![Message {
        role: Role::User,
        content: prompt,
    }];
    let resp = llm.complete(messages).await?;
    let source = extract_code_block(&resp.content).ok_or_else(|| {
        ClassifiedError::Harness("LLM response contained no fenced code block".to_owned())
    })?;
    Ok(HarnessDraft {
        target_id: target.id,
        engine,
        source,
        rationale: String::new(),
    })
}

/// Compile a harness in the sandbox.
///
/// # Errors
/// Returns `ClassifiedError` if the build command returns a non-zero exit
/// code.
pub async fn compile(
    mut harness: Harness,
    rt: &dyn RuntimeAdapter,
    workspace: &Path,
) -> Result<Harness, ClassifiedError> {
    let src_path = workspace.join("harness.c");
    rt.write_file(&src_path, &harness.source).await?;
    let mut cmd = vec![harness.build_cmd.compiler.clone()];
    cmd.extend(harness.build_cmd.args.clone());
    cmd.push(src_path.to_string_lossy().to_string());
    cmd.push("-o".to_owned());
    cmd.push(harness.build_cmd.output.to_string_lossy().to_string());
    let limits = hf_core::runtime::ResourceLimits {
        max_mem_mb: 4096,
        max_cpus: 2,
        max_duration_secs: 120,
        env: std::collections::HashMap::new(),
    };
    let result = rt.run_command(&cmd, workspace, &limits).await?;
    if result.exit_code != 0 {
        return Err(ClassifiedError::Harness(format!(
            "compile failed (exit {}): {}",
            result.exit_code, result.stderr
        )));
    }
    harness.status = HarnessStatus::Compiled;
    Ok(harness)
}

/// Run a 60-second smoke fuzz on a compiled harness.
///
/// # Errors
/// Returns `ClassifiedError` if the smoke run finds 0 execs/sec or crashes
/// on empty input.
pub async fn smoke_fuzz(
    mut harness: Harness,
    rt: &dyn RuntimeAdapter,
    workspace: &Path,
) -> Result<Harness, ClassifiedError> {
    let binary = harness.build_cmd.output.to_string_lossy().to_string();
    let cmd = vec![binary, "-max_total_time=60".to_owned()];
    let limits = hf_core::runtime::ResourceLimits {
        max_mem_mb: 2048,
        max_cpus: 1,
        max_duration_secs: 90,
        env: std::collections::HashMap::new(),
    };
    let result = rt.run_command(&cmd, workspace, &limits).await?;
    let execs = parse_execs_per_sec(&result.stdout);
    let crashes = parse_crashes(&result.stdout);
    if execs <= 0.0 {
        return Err(ClassifiedError::Harness(format!(
            "smoke fuzz: 0 execs/sec; stdout: {}",
            result.stdout
        )));
    }
    let passed = crashes == 0;
    let summary = SmokeRunSummary {
        duration_secs: 60,
        execs_per_sec: execs,
        crashes,
        passed,
    };
    harness.smoke_run = Some(summary);
    harness.status = if passed {
        HarnessStatus::SmokePassed
    } else {
        HarnessStatus::Failed
    };
    Ok(harness)
}

/// Construct a build command for an engine + language.
#[must_use]
pub fn build_command(engine: EngineKind, _lang: TargetLanguage, output_name: &str) -> BuildCommand {
    match engine {
        EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite => BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![
                "-fsanitize=fuzzer".to_owned(),
                "-fsanitize=address".to_owned(),
                "-g".to_owned(),
            ],
            output: PathBuf::from(output_name),
        },
        EngineKind::AflPlusPlus => BuildCommand {
            compiler: "afl-clang-fast".to_owned(),
            args: vec!["-fsanitize=address".to_owned(), "-g".to_owned()],
            output: PathBuf::from(output_name),
        },
        EngineKind::Honggfuzz => BuildCommand {
            compiler: "hfuzz-cc".to_owned(),
            args: vec!["-fsanitize=address".to_owned(), "-g".to_owned()],
            output: PathBuf::from(output_name),
        },
    }
}

/// Extract the first fenced code block from a string.
fn extract_code_block(s: &str) -> Option<String> {
    let start = s.find("```")?;
    let after_start = &s[start + 3..];
    // Skip the language tag line (e.g. "c\n").
    let after_lang = after_start
        .find('\n')
        .map_or(after_start, |i| &after_start[i + 1..]);
    let end = after_lang.find("```")?;
    Some(after_lang[..end].to_owned())
}

/// Parse execs/sec from fuzzer stdout.
fn parse_execs_per_sec(stdout: &str) -> f64 {
    // Look for patterns like "5000 execs/sec" or "execs_per_sec : 500.0".
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some(pos) = lower.find("execs") {
            // Try to find a number before "execs" (e.g. "5000 execs/sec").
            let before = &line[..pos];
            if let Some(n) = last_number(before) {
                return n;
            }
            // Try after "execs" (e.g. "execs_per_sec : 500.0").
            let after = &line[pos + "execs".len()..];
            if let Some(n) = first_number(after) {
                return n;
            }
        }
    }
    0.0
}

fn last_number(s: &str) -> Option<f64> {
    let tokens = s
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .filter(|t| !t.is_empty());
    let mut last = None;
    for t in tokens {
        if let Ok(v) = t.parse::<f64>() {
            last = Some(v);
        }
    }
    last
}

fn first_number(s: &str) -> Option<f64> {
    s.split(|c: char| !c.is_ascii_digit() && c != '.')
        .find(|t| !t.is_empty())
        .and_then(|t| t.parse::<f64>().ok())
}

/// Parse the number of crashes from fuzzer stdout.
fn parse_crashes(stdout: &str) -> u32 {
    let mut count = 0u32;
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("crash") || lower.contains("sum") && lower.contains("bug") {
            count += 1;
        }
    }
    count
}

#[allow(dead_code)]
fn _ensure_uuid_used(_u: Uuid) {}
