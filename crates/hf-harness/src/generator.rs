//! Harness generator: draft -> compile -> smoke fuzz.

use std::path::{Path, PathBuf};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessDraft, HarnessStatus, SmokeRunSummary};
use hf_core::provider::{ChatRequest, LlmProvider};
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{TargetCandidate, TargetLanguage};
use hf_core::types::Message;
use hf_prompt::render_harness_prompt;

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
    let messages = vec![Message::user(prompt)];
    let req = ChatRequest::from_messages(messages);
    let resp = llm.chat_completion(&req).await?;
    let source = extract_code_block(resp.text()).ok_or_else(|| {
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
    // Write the harness source to the host workspace (the Docker mount
    // makes it visible inside the container at container_workspace). Use a
    // language-appropriate filename so the compiler treats it correctly
    // (e.g. C++ harnesses must not be compiled as C).
    let source_name = source_filename(harness.language);
    let src_path = workspace.join(source_name);
    rt.write_file(&src_path, &harness.source).await?;

    // Build the compile command using container-internal paths.
    // The DockerRuntime mounts `workspace` at `/work`, so all file
    // references must use `/work/...` paths.
    // Use bash -c to compile to /tmp (some Docker volumes don't support
    // direct linker output) then copy to /work in a single container.
    //
    // Use the engine-correct compiler/args computed by `build_command`
    // (`afl-clang-fast` for AFL++, `hfuzz-cc` for honggfuzz, ...): compiling
    // with a literal `clang` would silently drop the engine's instrumentation.
    let container_ws = "/work";
    let output_name = harness
        .build_cmd
        .output
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let compile_script = format!(
        "{compiler} {args} -I{container_ws} {container_ws}/{source_name} {extra_sources} -o /tmp/{output_name} && cp /tmp/{output_name} {container_ws}/{output_name} && chmod +x {container_ws}/{output_name}",
        compiler = harness.build_cmd.compiler,
        args = harness.build_cmd.args.join(" "),
        container_ws = container_ws,
        source_name = source_name,
        output_name = output_name,
        extra_sources = list_c_files(workspace, container_ws, source_name),
    );
    let cmd = vec!["bash".to_owned(), "-c".to_owned(), compile_script];
    let limits = hf_core::runtime::ResourceLimits {
        max_mem_mb: 4096,
        max_cpus: 2,
        max_duration_secs: 120,
        env: std::collections::HashMap::new(),
        ptrace: false,
    };
    let result = rt.run_command(&cmd, workspace, &limits).await?;
    if result.exit_code != 0 {
        return Err(ClassifiedError::Harness(format!(
            "compile failed (exit {}): {}",
            result.exit_code, result.stderr
        )));
    }
    // Update the output path to the host workspace path so the binary
    // can be referenced by subsequent run steps.
    harness.build_cmd.output = workspace.join(output_name);
    harness.status = HarnessStatus::Compiled;
    Ok(harness)
}

/// Run a 60-second smoke fuzz on a compiled harness.
///
/// The harness is considered valid if the fuzzer actually ran (any exec/s,
/// libFuzzer init/done markers, or a crash). A crash found during smoke marks
/// `passed = false` but is still a working harness; `# Errors` is only returned
/// when no fuzzer activity is detected at all (e.g. the binary failed to exec).
///
/// # Errors
/// Returns `ClassifiedError` if the sandbox command fails or no fuzzer activity
/// is detected in the output.
pub async fn smoke_fuzz(
    mut harness: Harness,
    rt: &dyn RuntimeAdapter,
    workspace: &Path,
) -> Result<Harness, ClassifiedError> {
    // Reference the binary by its container-internal path: the runtime mounts
    // the workspace at `/work` (matching `EngineRunner`), so the host path is
    // not valid inside the sandbox.
    let binary_name = harness
        .build_cmd
        .output
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fuzz_target")
        .to_string();
    let binary = format!("/work/{binary_name}");
    let cmd = vec![binary, "-max_total_time=60".to_owned()];
    let limits = hf_core::runtime::ResourceLimits {
        max_mem_mb: 2048,
        max_cpus: 1,
        max_duration_secs: 90,
        env: std::collections::HashMap::new(),
        ptrace: false,
    };
    let result = rt.run_command(&cmd, workspace, &limits).await?;
    // libFuzzer writes progress/crashes to stderr; parse both streams.
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    let execs = parse_execs_per_sec(&combined);
    let crashes = parse_crashes(&combined);
    // The harness is valid if the fuzzer actually ran. A campaign that finds a
    // crash immediately (so it reports 0 exec/s) still proves the harness
    // exercises the target -- the crash is reported, not treated as a failure.
    let lower = combined.to_ascii_lowercase();
    let ran = execs > 0.0
        || crashes > 0
        || lower.contains("exec/s")
        || lower.contains("inited")
        || lower.contains("done");
    if !ran {
        return Err(ClassifiedError::Harness(format!(
            "smoke fuzz: no fuzzer activity detected; output: {}",
            combined.chars().take(800).collect::<String>()
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
        // syzkaller fuzzes a kernel built with coverage instrumentation rather
        // than a per-function harness binary; this represents the kernel build.
        EngineKind::Syzkaller => BuildCommand {
            compiler: "make".to_owned(),
            args: vec!["CONFIG_KCOV=y".to_owned(), "CONFIG_DEBUG_INFO=y".to_owned()],
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
    // Match libFuzzer's "exec/s: N" as well as "5000 execs/sec" and
    // "execs_per_sec : 500.0". libFuzzer prints exec/s many times (starting at
    // 0 in the first sub-second window), so report the peak observed.
    let mut max = 0.0_f64;
    for line in stdout.lines() {
        let lower = line.to_ascii_lowercase();
        // libFuzzer: "#1024 pulse cov: .. exec/s: 5000 ..".
        if let Some(pos) = lower.find("exec/s") {
            let after = &line[pos + "exec/s".len()..];
            if let Some(n) = first_number(after) {
                max = max.max(n);
            }
        } else if let Some(pos) = lower.find("execs") {
            // "5000 execs/sec" (number before) or "execs_per_sec : 500.0".
            let before = &line[..pos];
            let after = &line[pos + "execs".len()..];
            if let Some(n) = last_number(before).or_else(|| first_number(after)) {
                max = max.max(n);
            }
        }
    }
    max
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

/// The source filename to write the harness to, by language. The extension
/// drives how the compiler front-end parses the file (C vs C++), so it must
/// match the harness language rather than always being `.c`.
fn source_filename(lang: TargetLanguage) -> &'static str {
    match lang {
        TargetLanguage::Cpp => "harness.cc",
        TargetLanguage::Rust => "harness.rs",
        TargetLanguage::Go => "harness.go",
        TargetLanguage::Python => "harness.py",
        TargetLanguage::C => "harness.c",
    }
}

/// List all C/C++ source files in the workspace (excluding the harness source
/// itself) as container-internal paths, so multi-file targets link correctly.
fn list_c_files(workspace: &Path, container_ws: &str, source_name: &str) -> String {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(workspace) {
        for entry in entries.flatten() {
            if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                let is_source = matches!(ext, "c" | "cc" | "cpp" | "cxx");
                if is_source && entry.file_name() != source_name {
                    files.push(format!(
                        "{container_ws}/{}",
                        entry.file_name().to_string_lossy()
                    ));
                }
            }
        }
    }
    files.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_libfuzzer_exec_per_sec_peak() {
        // libFuzzer writes "exec/s:" to stderr, starting at 0, then ramping up.
        let log = "\
#2 INITED cov: 12 ft: 13 corp: 1/1b exec/s: 0 rss: 30Mb
#1024 pulse cov: 40 ft: 50 corp: 5/9b exec/s: 51200 rss: 35Mb
#4096 pulse cov: 60 ft: 70 corp: 9/40b exec/s: 48000 rss: 36Mb";
        // Reports the peak, not the first (0) sample.
        assert!((parse_execs_per_sec(log) - 51200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn parses_generic_execs_phrasing() {
        assert!((parse_execs_per_sec("ran at 5000 execs/sec total") - 5000.0).abs() < f64::EPSILON);
        assert!((parse_execs_per_sec("execs_per_sec : 500") - 500.0).abs() < f64::EPSILON);
        assert!(parse_execs_per_sec("no throughput here").abs() < f64::EPSILON);
    }

    #[test]
    fn counts_libfuzzer_crash_artifacts() {
        let log =
            "Test unit written to ./crash-abc\nSUMMARY: AddressSanitizer: heap-buffer-overflow";
        assert!(parse_crashes(log) >= 1);
    }
}
