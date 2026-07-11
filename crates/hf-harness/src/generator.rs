//! Harness generator: draft -> compile -> smoke fuzz.

use std::path::{Path, PathBuf};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessDraft, HarnessStatus, SmokeRunSummary};
use hf_core::provider::{ChatRequest, LlmProvider};
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{TargetCandidate, TargetLanguage};
use hf_core::types::Message;
use hf_prompt::{
    render_harness_prompt, render_harness_refine_prompt, render_harness_repair_prompt,
    render_seed_prompt,
};

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
        build_cmd: build_command(engine, target.language, &format!("fuzz_{}", target.symbol)),
    })
}

/// Maximum characters of build diagnostics to feed back into a repair prompt.
/// Compiler output can be huge; the first errors are the actionable ones and a
/// bounded slice keeps the prompt inside the model's context budget.
pub const MAX_REPAIR_DIAGNOSTICS_CHARS: usize = 4000;

/// Re-draft a harness that failed to build, given the failing source and the
/// compiler/smoke diagnostics. This is one repair step; the caller decides how
/// many attempts to make.
///
/// `diagnostics` is truncated to [`MAX_REPAIR_DIAGNOSTICS_CHARS`] before being
/// sent, so an enormous compiler dump does not blow the context window.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails or the response contains no
/// fenced code block.
pub async fn repair(
    target: &TargetCandidate,
    engine: EngineKind,
    failing_source: &str,
    diagnostics: &str,
    llm: Box<dyn LlmProvider>,
) -> Result<HarnessDraft, ClassifiedError> {
    let diagnostics = truncate_diagnostics(diagnostics);
    let prompt = render_harness_repair_prompt(target, engine, failing_source, diagnostics);
    let messages = vec![Message::user(prompt)];
    let req = ChatRequest::from_messages(messages);
    let resp = llm.chat_completion(&req).await?;
    let source = extract_code_block(resp.text()).ok_or_else(|| {
        ClassifiedError::Harness("repair response contained no fenced code block".to_owned())
    })?;
    Ok(HarnessDraft {
        target_id: target.id,
        engine,
        source,
        rationale: "repair".to_owned(),
        build_cmd: build_command(engine, target.language, &format!("fuzz_{}", target.symbol)),
    })
}

/// Re-draft a harness that runs but has left `uncovered` reachable functions
/// unexercised, asking the LLM to reshape the input handling so the fuzzer can
/// drive into them. One refinement step; the caller loops on coverage feedback.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails or the response contains no
/// fenced code block.
pub async fn refine(
    target: &TargetCandidate,
    engine: EngineKind,
    current_source: &str,
    uncovered: &[String],
    llm: Box<dyn LlmProvider>,
) -> Result<HarnessDraft, ClassifiedError> {
    let prompt = render_harness_refine_prompt(target, engine, current_source, uncovered);
    let req = ChatRequest::from_messages(vec![Message::user(prompt)]);
    let resp = llm.chat_completion(&req).await?;
    let source = extract_code_block(resp.text()).ok_or_else(|| {
        ClassifiedError::Harness("refine response contained no fenced code block".to_owned())
    })?;
    Ok(HarnessDraft {
        target_id: target.id,
        engine,
        source,
        rationale: "refine".to_owned(),
        build_cmd: build_command(engine, target.language, &format!("fuzz_{}", target.symbol)),
    })
}

/// Generate structural seed inputs for a target using the LLM.
///
/// Returns the decoded seed byte strings (at most `count`). A good seed corpus
/// lets a coverage-guided fuzzer start deep in the input format rather than
/// rediscovering it byte by byte. The caller writes the seeds to disk and may
/// fall back to heuristic seeds when this returns an empty vec.
///
/// # Errors
/// Returns `ClassifiedError` if the LLM call fails. A response that parses to
/// no seeds is returned as an empty vec (not an error) so the caller can fall
/// back gracefully.
pub async fn generate_seeds(
    target: &TargetCandidate,
    count: usize,
    llm: Box<dyn LlmProvider>,
) -> Result<Vec<Vec<u8>>, ClassifiedError> {
    let prompt = render_seed_prompt(target, count);
    let req = ChatRequest::from_messages(vec![Message::user(prompt)]);
    let resp = llm.chat_completion(&req).await?;
    Ok(parse_seed_array(resp.text(), count))
}

/// Parse an LLM seed response into raw seed byte strings. The model is asked for
/// a JSON array of hex strings; each element is hex-decoded, falling back to the
/// element's UTF-8 bytes when it is not valid hex. At most `max` non-empty seeds
/// are returned.
fn parse_seed_array(text: &str, max: usize) -> Vec<Vec<u8>> {
    let Some(start) = text.find('[') else {
        return Vec::new();
    };
    let mut iter = serde_json::Deserializer::from_str(&text[start..]).into_iter::<Vec<String>>();
    let Some(Ok(items)) = iter.next() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        let decoded = decode_hex(&item).unwrap_or_else(|| item.into_bytes());
        if !decoded.is_empty() {
            out.push(decoded);
        }
        if out.len() >= max {
            break;
        }
    }
    out
}

/// Decode an even-length ASCII-hex string to bytes, or `None` if it is not
/// valid hex.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        out.push(hex_nibble(bytes[i]) * 16 + hex_nibble(bytes[i + 1]));
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Truncate build diagnostics to the repair-prompt budget, keeping the head
/// (where the first, most actionable compiler errors appear).
fn truncate_diagnostics(diagnostics: &str) -> &str {
    if diagnostics.len() <= MAX_REPAIR_DIAGNOSTICS_CHARS {
        return diagnostics;
    }
    // Cut on a char boundary at or below the limit.
    let mut end = MAX_REPAIR_DIAGNOSTICS_CHARS;
    while end > 0 && !diagnostics.is_char_boundary(end) {
        end -= 1;
    }
    &diagnostics[..end]
}

/// A build that ran in the sandbox but returned a non-zero exit code. Carries
/// the diagnostics a repair step needs; distinct from an infrastructure error
/// (Docker unavailable, write failure), which surfaces as `ClassifiedError`.
#[derive(Debug, Clone)]
pub struct CompileFailure {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CompileFailure {
    /// The combined stdout+stderr, the signal a repair prompt is built from.
    #[must_use]
    pub fn diagnostics(&self) -> String {
        if self.stdout.trim().is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

/// The result of a compile attempt: either a compiled harness or a structured
/// build failure. Only infrastructure problems return `Err`.
#[derive(Debug)]
pub enum CompileResult {
    Ok(Box<Harness>),
    Failed(CompileFailure),
}

/// Compile a harness in the sandbox.
///
/// # Errors
/// Returns `ClassifiedError` if the build command returns a non-zero exit
/// code (or the sandbox itself fails).
pub async fn compile(
    harness: Harness,
    rt: &dyn RuntimeAdapter,
    workspace: &Path,
) -> Result<Harness, ClassifiedError> {
    match try_compile(harness, rt, workspace).await? {
        CompileResult::Ok(h) => Ok(*h),
        CompileResult::Failed(f) => Err(ClassifiedError::Harness(format!(
            "compile failed (exit {}): {}",
            f.exit_code, f.stderr
        ))),
    }
}

/// Compile a harness in the sandbox, returning a structured [`CompileResult`]
/// so callers can inspect the diagnostics (e.g. to drive a repair attempt)
/// rather than only receiving an opaque error string.
///
/// # Errors
/// Returns `ClassifiedError` only for infrastructure failures (cannot write the
/// source, sandbox cannot run). A non-zero compiler exit is `CompileResult::Failed`.
pub async fn try_compile(
    mut harness: Harness,
    rt: &dyn RuntimeAdapter,
    workspace: &Path,
) -> Result<CompileResult, ClassifiedError> {
    // Rust fuzz targets take the cargo-fuzz path (project scaffold + `cargo fuzz
    // build`) rather than the single-file compile below, which assumes a C-style
    // `compiler args source -o output` invocation.
    if harness.language == TargetLanguage::Rust {
        return try_compile_cargo_fuzz(harness, rt, workspace).await;
    }
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
    // `source_name`/`output_name` derive from the (user-influenced) target
    // symbol and are interpolated into a `bash -c` script, so shell-quote them.
    // The `/work` prefix and compiler/args are values we control.
    let source_q = sh_quote(source_name);
    let output_q = sh_quote(&output_name);
    let compile_script = format!(
        "{compiler} {args} -I{container_ws} {container_ws}/{source_q} {extra_sources} -o /tmp/{output_q} && cp /tmp/{output_q} {container_ws}/{output_q} && chmod +x {container_ws}/{output_q}",
        compiler = harness.build_cmd.compiler,
        args = harness.build_cmd.args.join(" "),
        container_ws = container_ws,
        source_q = source_q,
        output_q = output_q,
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
        return Ok(CompileResult::Failed(CompileFailure {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        }));
    }
    // Update the output path to the host workspace path so the binary
    // can be referenced by subsequent run steps.
    harness.build_cmd.output = workspace.join(output_name);
    harness.status = HarnessStatus::Compiled;
    Ok(CompileResult::Ok(Box::new(harness)))
}

/// Compile a Rust harness with cargo-fuzz: scaffold `fuzz/Cargo.toml` +
/// `fuzz/fuzz_targets/<name>.rs` beside the staged crate under test, then run
/// `cargo fuzz build`, copying the produced libFuzzer binary to the workspace
/// under the `output` name the run step expects.
///
/// The crate under test must already be staged into `workspace` (its
/// `Cargo.toml` + `src/`); its package name is read from that `Cargo.toml` so the
/// fuzz manifest's path dependency resolves.
async fn try_compile_cargo_fuzz(
    mut harness: Harness,
    rt: &dyn RuntimeAdapter,
    workspace: &Path,
) -> Result<CompileResult, ClassifiedError> {
    let output_name = harness
        .build_cmd
        .output
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let target_name = crate::cargo_fuzz::sanitize_target_name(&output_name);

    // Derive the crate-under-test's package name from its staged Cargo.toml so
    // the fuzz manifest can depend on it by path. Without a staged crate there is
    // nothing to fuzz, so surface a clear validation error rather than a cryptic
    // cargo failure.
    let crate_toml_path = workspace.join("Cargo.toml");
    let crate_toml = std::fs::read_to_string(&crate_toml_path).map_err(|e| {
        ClassifiedError::Validation(format!(
            "Rust harness needs the target crate staged at {}, but its Cargo.toml \
             could not be read: {e}",
            crate_toml_path.display()
        ))
    })?;
    let crate_name =
        crate::cargo_fuzz::crate_name_from_cargo_toml(&crate_toml).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "could not find [package] name in {}",
                crate_toml_path.display()
            ))
        })?;

    // Lay out the cargo-fuzz project inside the workspace (Docker-mounted at
    // /work). fuzz_targets/<name>.rs is the generated `fuzz_target!` harness.
    rt.write_file(
        &workspace.join("fuzz").join("Cargo.toml"),
        &crate::cargo_fuzz::fuzz_cargo_toml(&crate_name, &target_name),
    )
    .await?;
    rt.write_file(
        &workspace
            .join("fuzz")
            .join("fuzz_targets")
            .join(format!("{target_name}.rs")),
        &harness.source,
    )
    .await?;

    let script = crate::cargo_fuzz::build_script(&target_name, &output_name, "/work");
    let cmd = vec!["bash".to_owned(), "-c".to_owned(), script];
    let limits = hf_core::runtime::ResourceLimits {
        max_mem_mb: 4096,
        max_cpus: 2,
        // cargo-fuzz compiles the crate + libfuzzer-sys from source; give it more
        // headroom than a single-file C build.
        max_duration_secs: 600,
        env: std::collections::HashMap::new(),
        ptrace: false,
    };
    let result = rt.run_command(&cmd, workspace, &limits).await?;
    if result.exit_code != 0 {
        return Ok(CompileResult::Failed(CompileFailure {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        }));
    }
    harness.build_cmd.output = workspace.join(&output_name);
    harness.status = HarnessStatus::Compiled;
    Ok(CompileResult::Ok(Box::new(harness)))
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

    // Every engine writes crash artifacts into the canonical `out` directory
    // so the subsequent Triage action can ingest the exact smoke findings.
    // LibFuzzer otherwise defaults to the process working directory, which
    // made Smoke Test report a crash while Triage appeared empty.
    let out_dir = workspace.join("out");
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| ClassifiedError::Harness(format!("smoke fuzz: cannot create out dir: {e}")))?;

    // AFL++/honggfuzz drive the binary through their own fuzzer process, which
    // also needs an input directory on the mounted workspace. Create it (and
    // an AFL++ seed, which the driver requires) before launching.
    let corpus_container = "/work/corpus";
    let out_container = "/work/out";
    if matches!(
        harness.engine,
        EngineKind::AflPlusPlus | EngineKind::Honggfuzz
    ) {
        let corpus_dir = workspace.join("corpus");
        std::fs::create_dir_all(&corpus_dir).map_err(|e| {
            ClassifiedError::Harness(format!("smoke fuzz: cannot create corpus dir: {e}"))
        })?;
        // AFL++ refuses to start with an empty input dir; ensure one seed.
        let seed = corpus_dir.join("seed");
        if !seed.exists() {
            std::fs::write(&seed, b"hobot_fuzz_smoke").map_err(|e| {
                ClassifiedError::Harness(format!("smoke fuzz: cannot write seed: {e}"))
            })?;
        }
    }

    let mut cmd = smoke_command(harness.engine, &binary, corpus_container, out_container)?;
    if matches!(
        harness.engine,
        EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite
    ) {
        cmd.push("-artifact_prefix=/work/out/".to_owned());
    }
    let limits = hf_core::runtime::ResourceLimits {
        max_mem_mb: 2048,
        max_cpus: 1,
        max_duration_secs: 90,
        env: std::collections::HashMap::new(),
        ptrace: false,
    };
    let result = rt.run_command(&cmd, workspace, &limits).await?;
    // Fuzzers write progress/crashes to stderr (libFuzzer) or stdout; parse both.
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
    // `SmokePassed` means the harness is viable -- it built and the fuzzer
    // actually exercised the target. A crash found during smoke does NOT make
    // the harness `Failed`: a harness that drives the target well enough to find
    // a bug is a working harness (and the crash is worth triaging). The crash
    // signal lives in `smoke_run.passed`/`crashes`, not in the status. Only a
    // harness the fuzzer could not run at all is `Failed`, and that path already
    // returned `Err` above.
    harness.status = HarnessStatus::SmokePassed;
    Ok(harness)
}

/// Bounded smoke-fuzz duration, in seconds.
const SMOKE_SECS: u64 = 60;

/// Build the engine-appropriate smoke-fuzz command.
///
/// libFuzzer and `ClusterFuzzLite` compile a libFuzzer-style binary that is run
/// directly; AFL++ and honggfuzz are driven through their own fuzzer processes
/// (reusing the real `hf-engine` adapter argument builders so smoke matches the
/// production run). Syzkaller has no userspace-harness smoke run.
///
/// # Errors
/// Returns `ClassifiedError::Harness` for engines that cannot be smoke-fuzzed
/// (currently syzkaller).
fn smoke_command(
    engine: EngineKind,
    binary: &str,
    corpus: &str,
    out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    match engine {
        EngineKind::LibFuzzer | EngineKind::ClusterFuzzLite => Ok(vec![
            binary.to_owned(),
            format!("-max_total_time={SMOKE_SECS}"),
        ]),
        EngineKind::AflPlusPlus => Ok(hf_engine::afl::build_run_args(
            &smoke_cfg(engine),
            binary,
            corpus,
            out,
        )),
        EngineKind::Honggfuzz => Ok(hf_engine::honggfuzz::build_run_args(
            &smoke_cfg(engine),
            binary,
            corpus,
            out,
        )),
        EngineKind::Syzkaller => Err(ClassifiedError::Harness(
            "smoke fuzz does not apply to syzkaller: it fuzzes an instrumented \
             kernel image, not a userspace harness binary"
                .to_owned(),
        )),
    }
}

/// A minimal [`FuzzRunConfig`](hf_core::engine::FuzzRunConfig) for a bounded
/// smoke run. Only `duration`/`env`/`extra_args` are read by the adapter
/// argument builders; the rest are placeholders.
fn smoke_cfg(engine: EngineKind) -> hf_core::engine::FuzzRunConfig {
    hf_core::engine::FuzzRunConfig {
        harness_id: uuid::Uuid::nil(),
        engine,
        duration: Some(std::time::Duration::from_secs(SMOKE_SECS)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: None,
        sanitizer: hf_core::target::Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
    }
}

/// Construct a build command for an engine + language.
///
/// Rust targets are always built with cargo-fuzz (libfuzzer-sys), regardless of
/// the requested engine, since that is the only supported Rust fuzzing backend;
/// the produced libFuzzer binary is then driven by the libFuzzer run path. C/C++
/// targets use the engine-correct instrumenting compiler.
#[must_use]
pub fn build_command(engine: EngineKind, lang: TargetLanguage, output_name: &str) -> BuildCommand {
    if lang == TargetLanguage::Rust {
        return BuildCommand {
            compiler: "cargo".to_owned(),
            args: vec![
                "fuzz".to_owned(),
                "build".to_owned(),
                crate::cargo_fuzz::sanitize_target_name(output_name),
            ],
            output: PathBuf::from(output_name),
        };
    }
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
///
/// A single crash emits several finding-signal lines -- the sanitizer report,
/// the `SUMMARY:` line, and the artifact-save line -- so counting every line
/// that [`line_reports_finding`](hf_engine::progress::line_reports_finding)
/// matches would report one crash as two or more. Instead count distinct saved
/// artifacts: libFuzzer prints exactly one `Test unit written to <path>` per
/// saved finding, and the `crash-<hash>` filename token appears once per
/// artifact. When a finding is signalled but no per-artifact line is present
/// (e.g. honggfuzz naming a `SIG...` file), fall back to "at least one".
///
/// Like the production run parser, this does NOT count AFL++/honggfuzz periodic
/// status counters (`uniq crashes : N`, `Crashes : N`) as crashes -- doing so
/// marked every clean non-libFuzzer smoke run as `Failed`.
fn parse_crashes(stdout: &str) -> u32 {
    let artifacts = stdout
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("test unit written") || lower.contains("crash-")
        })
        .count();
    if artifacts > 0 {
        return u32::try_from(artifacts).unwrap_or(u32::MAX);
    }
    // A finding was reported (sanitizer/signal phrasing) but no per-artifact
    // line was emitted: report a single crash rather than zero.
    u32::from(
        stdout
            .lines()
            .any(hf_engine::progress::line_reports_finding),
    )
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
                    // The filename is attacker-influenced (it comes from the
                    // project under test), and this string is interpolated into
                    // a `bash -c` script, so each path must be shell-quoted to
                    // prevent command injection. The `/work` prefix is a literal
                    // we control, so only the filename component needs quoting.
                    files.push(format!(
                        "{container_ws}/{}",
                        sh_quote(&entry.file_name().to_string_lossy())
                    ));
                }
            }
        }
    }
    files.join(" ")
}

/// Single-quote a string for safe interpolation into a POSIX shell command.
///
/// Wraps the value in single quotes (which suppress every shell metacharacter)
/// and renders any embedded single quote as the standard `'\''` sequence.
fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, SourceLocation, TargetKind};
    use hf_test_utils::mock_provider::MockProvider;

    fn sample_target() -> TargetCandidate {
        TargetCandidate {
            id: uuid::Uuid::nil(),
            project_root: PathBuf::from("/proj"),
            language: TargetLanguage::C,
            symbol: "parse_header".to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from("src/parse.c"),
                line: 1,
                col: 1,
            },
            signature: Some("int parse_header(const uint8_t*, size_t)".to_owned()),
            input_surface: InputSurface::Bytes,
            complexity: 3,
            fit_score: 0.5,
            sanitizers: Vec::new(),
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 3,
        }
    }

    #[tokio::test]
    async fn repair_extracts_corrected_source_from_fenced_block() {
        let target = sample_target();
        // The model returns a corrected harness in a fenced block.
        let llm = MockProvider::fixed(
            "Here is the fix:\n```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){return 0;}\n```",
        );
        let draft = repair(
            &target,
            EngineKind::LibFuzzer,
            "int LLVMFuzzerTestOneInput(){ frobnicate(); }",
            "error: implicit declaration of function 'frobnicate'",
            Box::new(llm),
        )
        .await
        .expect("repair should succeed");
        assert!(draft
            .source
            .contains("LLVMFuzzerTestOneInput(const uint8_t"));
        assert_eq!(draft.rationale, "repair");
    }

    #[tokio::test]
    async fn repair_errors_when_no_code_block() {
        let target = sample_target();
        let llm = MockProvider::fixed("I cannot fix this.");
        let err = repair(
            &target,
            EngineKind::LibFuzzer,
            "bad source",
            "some error",
            Box::new(llm),
        )
        .await;
        assert!(err.is_err());
    }

    /// A runtime whose compile command returns a fixed exit code + output, so
    /// the compile-failure path is exercised without Docker.
    struct ScriptedRuntime {
        exit_code: i32,
        stderr: String,
    }

    #[async_trait::async_trait]
    impl RuntimeAdapter for ScriptedRuntime {
        async fn run_command(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &hf_core::runtime::ResourceLimits,
        ) -> Result<hf_core::runtime::CommandResult, ClassifiedError> {
            Ok(hf_core::runtime::CommandResult {
                exit_code: self.exit_code,
                stdout: String::new(),
                stderr: self.stderr.clone(),
                workspace: cwd.to_path_buf(),
            })
        }
        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            Ok(())
        }
        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            Ok(String::new())
        }
    }

    fn sample_harness() -> Harness {
        Harness {
            id: uuid::Uuid::nil(),
            target_id: uuid::Uuid::nil(),
            engine: EngineKind::LibFuzzer,
            source: "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}".to_owned(),
            language: TargetLanguage::C,
            build_cmd: build_command(EngineKind::LibFuzzer, TargetLanguage::C, "fuzz_t"),
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Draft,
            smoke_run: None,
        }
    }

    #[tokio::test]
    async fn try_compile_reports_structured_failure_on_nonzero_exit() {
        let dir = tempfile::tempdir().unwrap();
        let rt = ScriptedRuntime {
            exit_code: 1,
            stderr: "harness.c:1:5: error: implicit declaration of 'frob'".to_owned(),
        };
        let result = try_compile(sample_harness(), &rt, dir.path())
            .await
            .expect("infra ok");
        match result {
            CompileResult::Failed(f) => {
                assert_eq!(f.exit_code, 1);
                assert!(f.diagnostics().contains("implicit declaration of 'frob'"));
            }
            CompileResult::Ok(_) => panic!("expected a compile failure"),
        }
    }

    #[tokio::test]
    async fn try_compile_returns_compiled_harness_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let rt = ScriptedRuntime {
            exit_code: 0,
            stderr: String::new(),
        };
        let result = try_compile(sample_harness(), &rt, dir.path())
            .await
            .expect("infra ok");
        match result {
            CompileResult::Ok(h) => assert_eq!(h.status, HarnessStatus::Compiled),
            CompileResult::Failed(_) => panic!("expected success"),
        }
    }

    #[tokio::test]
    async fn refine_extracts_improved_source() {
        let target = sample_target();
        let llm = MockProvider::fixed(
            "```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ if(n>0) decode_frame(d,n); return 0; }\n```",
        );
        let draft = refine(
            &target,
            EngineKind::LibFuzzer,
            "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}",
            &["decode_frame".to_owned()],
            Box::new(llm),
        )
        .await
        .expect("refine should succeed");
        assert!(draft.source.contains("decode_frame"));
        assert_eq!(draft.rationale, "refine");
    }

    #[tokio::test]
    async fn generate_seeds_decodes_hex_array() {
        let target = sample_target();
        // "89504e47" = PNG magic; "7b7d" = "{}".
        let llm = MockProvider::fixed("Sure: [\"89504e47\", \"7b7d\"]");
        let seeds = generate_seeds(&target, 8, Box::new(llm)).await.unwrap();
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0], vec![0x89, 0x50, 0x4e, 0x47]);
        assert_eq!(seeds[1], b"{}".to_vec());
    }

    #[test]
    fn parse_seed_array_falls_back_to_utf8_and_caps() {
        // "PNG" is not even-length hex -> treated as UTF-8 bytes.
        let seeds = parse_seed_array("[\"PNG\", \"7b7d\", \"00\"]", 2);
        assert_eq!(seeds.len(), 2, "capped at max");
        assert_eq!(seeds[0], b"PNG".to_vec());
        assert_eq!(seeds[1], b"{}".to_vec());
    }

    #[test]
    fn parse_seed_array_empty_on_no_array() {
        assert!(parse_seed_array("no json here", 8).is_empty());
    }

    #[test]
    fn truncate_diagnostics_caps_length_on_char_boundary() {
        let big = "e".repeat(MAX_REPAIR_DIAGNOSTICS_CHARS + 500);
        assert_eq!(
            truncate_diagnostics(&big).len(),
            MAX_REPAIR_DIAGNOSTICS_CHARS
        );
        let small = "short";
        assert_eq!(truncate_diagnostics(small), "short");
    }

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
        // One crash: an artifact-save line plus a SUMMARY line. Must count as
        // exactly 1, not 2 -- the SUMMARY line is part of the same crash.
        let log =
            "Test unit written to ./crash-abc\nSUMMARY: AddressSanitizer: heap-buffer-overflow";
        assert_eq!(parse_crashes(log), 1);

        // Two distinct saved artifacts => 2, even amid extra signal lines.
        let two = "==ERROR: AddressSanitizer: heap-buffer-overflow\n\
                   Test unit written to ./crash-abc\n\
                   SUMMARY: AddressSanitizer: heap-buffer-overflow\n\
                   Test unit written to ./crash-def\n\
                   SUMMARY: AddressSanitizer: heap-buffer-overflow";
        assert_eq!(parse_crashes(two), 2);

        // A finding with no per-artifact line still reports at least one.
        let no_artifact = "==1== ERROR: AddressSanitizer: SEGV on unknown address";
        assert_eq!(parse_crashes(no_artifact), 1);
    }

    #[test]
    fn clean_afl_and_honggfuzz_smoke_reports_zero_crashes() {
        // A clean AFL++/honggfuzz run prints crash *labels* on every status
        // tick. None of these are real crashes; a clean smoke run must report 0
        // so the harness is promoted (it was previously marked Failed).
        let afl = "\
american fuzzy lop ++4.0
 last uniq crash : none seen yet
   uniq crashes : 0
    saved crashes : 0
   exec speed : 1234/sec";
        assert_eq!(parse_crashes(afl), 0);

        let honggfuzz = "\
Iterations : 12345
     Crashes : 0 (unique: 0, blacklist: 0, verified: 0)
    Timeouts : 0
 Corpus Size : 42";
        assert_eq!(parse_crashes(honggfuzz), 0);
    }

    #[test]
    fn sh_quote_wraps_and_escapes() {
        assert_eq!(sh_quote("simple.c"), "'simple.c'");
        // A single quote is rendered as the standard '\'' break-out sequence.
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        // Shell metacharacters are inert inside single quotes.
        assert_eq!(sh_quote("a; rm -rf /"), "'a; rm -rf /'");
    }

    #[test]
    fn list_c_files_quotes_malicious_filenames() {
        let dir = tempfile::tempdir().unwrap();
        // A source file whose name carries a shell-injection payload.
        let evil = "evil; touch pwned.c";
        std::fs::write(dir.path().join(evil), "int x;").unwrap();
        std::fs::write(dir.path().join("plain.c"), "int y;").unwrap();

        let listed = list_c_files(dir.path(), "/work", "harness.c");

        // The dangerous name is single-quoted so the `;` cannot break the shell.
        assert!(
            listed.contains("/work/'evil; touch pwned.c'"),
            "payload not quoted: {listed}"
        );
        // A normal file is also quoted (uniform, still injection-safe).
        assert!(
            listed.contains("/work/'plain.c'"),
            "missing plain: {listed}"
        );
    }

    #[test]
    fn smoke_command_libfuzzer_runs_binary_directly() {
        let cmd = smoke_command(
            EngineKind::LibFuzzer,
            "/work/fuzz",
            "/work/corpus",
            "/work/out",
        )
        .unwrap();
        assert_eq!(cmd, vec!["/work/fuzz", "-max_total_time=60"]);
    }

    #[test]
    fn smoke_command_clusterfuzzlite_uses_libfuzzer_binary_smoke() {
        // CFL compiles a libFuzzer-style binary, so its smoke is a direct run.
        let cmd = smoke_command(
            EngineKind::ClusterFuzzLite,
            "/work/fuzz",
            "/work/corpus",
            "/work/out",
        )
        .unwrap();
        assert_eq!(cmd, vec!["/work/fuzz", "-max_total_time=60"]);
    }

    #[test]
    fn smoke_command_afl_uses_afl_fuzz_driver() {
        let cmd = smoke_command(
            EngineKind::AflPlusPlus,
            "/work/fuzz",
            "/work/corpus",
            "/work/out",
        )
        .unwrap();
        assert_eq!(cmd.first().map(String::as_str), Some("afl-fuzz"));
        // Bounded smoke duration and the binary after the `--` separator.
        assert!(
            cmd.windows(2).any(|w| w == ["-V", "60"]),
            "no -V 60: {cmd:?}"
        );
        assert!(
            cmd.contains(&"/work/corpus".to_owned()),
            "no corpus: {cmd:?}"
        );
        let dd = cmd.iter().position(|a| a == "--").expect("no -- separator");
        assert_eq!(cmd.get(dd + 1).map(String::as_str), Some("/work/fuzz"));
    }

    #[test]
    fn smoke_command_honggfuzz_uses_honggfuzz_driver() {
        let cmd = smoke_command(
            EngineKind::Honggfuzz,
            "/work/fuzz",
            "/work/corpus",
            "/work/out",
        )
        .unwrap();
        assert_eq!(cmd.first().map(String::as_str), Some("honggfuzz"));
        assert!(
            cmd.contains(&"--run_time=60".to_owned()),
            "no bounded run_time: {cmd:?}"
        );
        assert!(cmd.contains(&"/work/fuzz".to_owned()), "no binary: {cmd:?}");
    }

    #[test]
    fn smoke_command_syzkaller_is_rejected() {
        // Syzkaller fuzzes a kernel image, not a userspace harness binary.
        let err = smoke_command(
            EngineKind::Syzkaller,
            "/work/fuzz",
            "/work/corpus",
            "/work/out",
        );
        assert!(err.is_err());
    }
}
