//! Tests for harness generation.

use hf_core::engine::EngineKind;
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
use hf_harness::{compile, draft, smoke_fuzz};
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
    let smoked = smoke_fuzz(harness, &rt, workspace.path())
        .await
        .expect("smoke should succeed");
    assert_eq!(smoked.status, HarnessStatus::SmokePassed);
    let sr = smoked.smoke_run.expect("smoke run summary should be set");
    assert!(sr.passed);
    assert!(sr.execs_per_sec > 0.0);
    assert!(
        workspace.path().join("out").is_dir(),
        "smoke fuzz must create the out/ dir the fuzzer writes crashes into"
    );
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
}
