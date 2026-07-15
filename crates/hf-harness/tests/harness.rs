//! Tests for harness generation.

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, FinishReason, LlmProvider, ProviderError,
    ProviderMetadata,
};
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_core::types::TokenUsage;
use hf_harness::{
    compile, draft, smoke_fuzz, smoke_fuzz_in, smoke_fuzz_in_paths, smoke_fuzz_in_paths_with_config,
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct MockLlm {
    response: String,
}

#[async_trait::async_trait]
impl LlmProvider for MockLlm {
    async fn chat_completion(&self, _request: &ChatRequest) -> Result<ChatResponse, ProviderError> {
        Ok(ChatResponse {
            id: "mock".to_owned(),
            model: "mock".to_owned(),
            content: Some(self.response.clone()),
            reasoning_content: None,
            tool_calls: Vec::new(),
            usage: TokenUsage::default(),
            finish_reason: FinishReason::Stop,
            raw_request: None,
            raw_response: None,
            provider_id: None,
            generated_images: Vec::new(),
        })
    }
    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "no stream".to_owned(),
        })
    }
    fn metadata(&self) -> &ProviderMetadata {
        mock_provider_metadata()
    }
}

fn mock_provider_metadata() -> &'static ProviderMetadata {
    use hf_core::provider::{ProviderCapability, ProviderType, ToolCallingMode};
    static M: std::sync::OnceLock<ProviderMetadata> = std::sync::OnceLock::new();
    M.get_or_init(|| ProviderMetadata {
        id: hf_core::types::ProviderId::from_string("mock"),
        provider_type: ProviderType::Custom,
        model: "mock".to_owned(),
        tags: Vec::new(),
        capabilities: vec![ProviderCapability::Text],
        max_concurrency: 1,
        context_window: 128_000,
        cost_per_1k_input: 0.0,
        cost_per_1k_output: 0.0,
        tool_calling_mode: ToolCallingMode::Native,
    })
}

struct MockRuntime {
    exit_code: i32,
    stdout: String,
}

struct ArtifactRuntime;

#[derive(Default)]
struct SmokePolicyRuntime {
    command: std::sync::Mutex<Vec<String>>,
    limits: std::sync::Mutex<Option<ResourceLimits>>,
}

#[async_trait::async_trait]
impl RuntimeAdapter for SmokePolicyRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        *self.command.lock().unwrap() = cmd.to_vec();
        *self.limits.lock().unwrap() = Some(limits.clone());
        Ok(CommandResult {
            exit_code: 0,
            stdout: "stats: 5000 execs/sec".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for ArtifactRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::write(cwd.join("runs/smoke/out/crash-late"), b"crash").unwrap();
        Ok(CommandResult {
            exit_code: 77,
            stdout: "stats: 5000 execs/sec".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for MockRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(CommandResult {
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

fn target() -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from("/p"),
        language: TargetLanguage::C,
        symbol: "parse_value".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/json.c"),
            line: 42,
            col: 1,
        },
        signature: Some("int parse_value(const char *buf, size_t len);".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 10,
        fit_score: 0.9,
        sanitizers: vec![Sanitizer::Address],
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    }
}

#[cfg(unix)]
fn compiled_harness(engine: EngineKind) -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine,
        source: String::new(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    }
}

#[tokio::test]
async fn draft_extracts_code_block_from_llm_response() {
    let llm = MockLlm {
        response: r"Here is the harness:
```c
#include <stdint.h>
#include <stddef.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_value((const char *)data, size, 0);
    return 0;
}
```
That's it."
            .to_owned(),
    };
    let draft = draft(&target(), EngineKind::LibFuzzer, Box::new(llm))
        .await
        .expect("draft should succeed");
    assert!(draft.source.contains("LLVMFuzzerTestOneInput"));
    assert!(draft.source.contains("parse_value"));
    assert!(
        !draft.source.contains("```"),
        "fenced code block markers should be stripped"
    );
}

#[tokio::test]
async fn compile_transitions_status_on_success() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: String::new(),
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput() {}".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec!["-fsanitize=fuzzer".to_owned()],
            output: PathBuf::from("fuzz_parse_value"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    };
    let workspace = tempfile::tempdir().expect("temp workspace");
    let compiled = compile(harness, &rt, workspace.path())
        .await
        .expect("compile should succeed");
    assert_eq!(compiled.status, HarnessStatus::Compiled);
}

#[tokio::test]
async fn compile_returns_error_on_failure() {
    let rt = MockRuntime {
        exit_code: 1,
        stdout: String::new(),
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: "bad code".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    };
    let workspace = tempfile::tempdir().expect("temp workspace");
    let result = compile(harness, &rt, workspace.path()).await;
    assert!(result.is_err(), "compile should fail on exit code 1");
}

#[tokio::test]
async fn smoke_fuzz_passes_with_positive_execs() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "INFO: Loaded 1 module   (1): 1 inline 8-bit counters.\nINFO: 1024 edges covered.\nstats: 5000 execs/sec\n".to_owned(),
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: String::new(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    };
    // A real host directory: `smoke_fuzz` creates the `out/` dir the fuzzer
    // writes crashes into. `/work` is where the *sandbox* mounts the workspace,
    // not a path that exists on the host.
    let workspace = tempfile::tempdir().expect("temp workspace");
    let smoked = smoke_fuzz_in(
        harness,
        &rt,
        workspace.path(),
        std::path::Path::new("runs/smoke/out"),
    )
    .await
    .expect("smoke should succeed");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed);
    let sr = smoked.smoke_run.expect("smoke run summary should be set");
    assert!(sr.passed);
    assert!(sr.execs_per_sec > 0.0);
    assert!(
        workspace.path().join("runs/smoke/out").is_dir(),
        "smoke fuzz must create the run-owned output directory"
    );
    assert!(!workspace.path().join("out").exists());
}

#[tokio::test]
async fn smoke_fuzz_uses_one_resolved_config_for_command_runtime_and_summary() {
    let rt = SmokePolicyRuntime::default();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: String::new(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    };
    let cfg = FuzzRunConfig {
        harness_id: harness.id,
        engine: harness.engine,
        duration: Some(std::time::Duration::from_secs(17)),
        max_mem_mb: 3072,
        max_cpus: 3,
        seed_corpus: None,
        sanitizer: harness.sanitizer,
        env: Vec::new(),
        extra_args: Vec::new(),
    };
    let workspace = tempfile::tempdir().expect("temp workspace");

    let smoked = smoke_fuzz_in_paths_with_config(
        harness,
        &rt,
        workspace.path(),
        Path::new("runs/smoke/corpus"),
        Path::new("runs/smoke/out"),
        &cfg,
    )
    .await
    .expect("configured smoke should succeed");

    assert!(rt
        .command
        .lock()
        .unwrap()
        .iter()
        .any(|arg| arg == "-max_total_time=17"));
    let limits = rt.limits.lock().unwrap().clone().unwrap();
    assert_eq!(limits.max_mem_mb, 3072);
    assert_eq!(limits.max_cpus, 3);
    assert_eq!(limits.max_duration_secs, 17);
    assert_eq!(smoked.smoke_run.unwrap().duration_secs, 17);
}

#[tokio::test]
async fn smoke_fuzz_counts_a_fresh_artifact_even_without_a_log_marker() {
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: String::new(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    };
    let workspace = tempfile::tempdir().expect("temp workspace");

    let smoked = smoke_fuzz_in(
        harness,
        &ArtifactRuntime,
        workspace.path(),
        Path::new("runs/smoke/out"),
    )
    .await
    .unwrap();

    let summary = smoked.smoke_run.unwrap();
    assert_eq!(summary.crashes, 1);
    assert!(!summary.passed);
}

#[cfg(unix)]
#[tokio::test]
async fn smoke_fuzz_rejects_symlinked_corpus_and_output_directories() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "stats: 5000 execs/sec".to_owned(),
    };
    let workspace = tempfile::tempdir().expect("temp workspace");
    let outside = tempfile::tempdir().expect("outside workspace");
    std::fs::create_dir_all(workspace.path().join("runs/smoke")).unwrap();
    std::os::unix::fs::symlink(outside.path(), workspace.path().join("runs/smoke/out")).unwrap();

    let output_error = smoke_fuzz_in_paths(
        compiled_harness(EngineKind::LibFuzzer),
        &rt,
        workspace.path(),
        Path::new("runs/smoke/corpus"),
        Path::new("runs/smoke/out"),
    )
    .await
    .expect_err("a symlinked output directory must fail closed");
    assert!(output_error.to_string().contains("output path"));

    std::fs::remove_file(workspace.path().join("runs/smoke/out")).unwrap();
    std::os::unix::fs::symlink(outside.path(), workspace.path().join("runs/smoke/corpus")).unwrap();
    let corpus_error = smoke_fuzz_in_paths(
        compiled_harness(EngineKind::LibFuzzer),
        &rt,
        workspace.path(),
        Path::new("runs/smoke/corpus"),
        Path::new("runs/smoke/out"),
    )
    .await
    .expect_err("a symlinked corpus directory must fail closed");
    assert!(corpus_error.to_string().contains("corpus path"));
}

#[tokio::test]
async fn smoke_fuzz_fails_on_zero_execs() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "no execs here\n".to_owned(),
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: String::new(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    };
    let workspace = tempfile::tempdir().expect("temp workspace");
    let err = smoke_fuzz(harness, &rt, workspace.path())
        .await
        .expect_err("smoke should fail when the fuzzer never ran");
    // Assert *why* it failed. Passing a container path as the host workspace made
    // this test pass on a filesystem error instead of the check it names, so it
    // would have kept passing with the zero-activity logic deleted.
    assert!(
        err.to_string().contains("no fuzzer activity"),
        "expected the no-activity rejection, got: {err}"
    );
}

#[tokio::test]
async fn smoke_fuzz_rejects_libfuzzer_inited_without_execs() {
    // A harness that deadlocks right after libFuzzer prints its INITED banner
    // (no `exec/s` line, no crash) must NOT be promoted. Previously the bare
    // "INITED"/"DONE" markers made it pass with 0 exec/s.
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "INFO: Seed: 12345\nINFO: Loaded 1 module\n#0\tINITED cov: 1 ft: 1\n".to_owned(),
    };
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: Uuid::new_v4(),
        engine: EngineKind::LibFuzzer,
        source: String::new(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec![],
            output: PathBuf::from("fuzz"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    };
    let workspace = tempfile::tempdir().expect("temp workspace");
    let err = smoke_fuzz(harness, &rt, workspace.path())
        .await
        .expect_err("a harness that only reached INITED must be rejected");
    assert!(
        err.to_string().contains("no fuzzer activity"),
        "expected the no-activity rejection, got: {err}"
    );
}

#[test]
fn build_command_for_libfuzzer_has_fuzzer_flag() {
    let cmd =
        hf_harness::build_command(EngineKind::LibFuzzer, TargetLanguage::C, "fuzz_parse_value");
    assert!(cmd.args.contains(&"-fsanitize=fuzzer".to_owned()));
}

#[test]
fn build_command_for_afl_uses_afl_compiler() {
    let cmd = hf_harness::build_command(
        EngineKind::AflPlusPlus,
        TargetLanguage::C,
        "fuzz_parse_value",
    );
    assert!(cmd.compiler.contains("afl"));
    assert!(
        cmd.args.contains(&"-fsanitize=fuzzer".to_owned()),
        "AFL++ libFuzzer-compatible harnesses need AFLDriver linked"
    );
}
