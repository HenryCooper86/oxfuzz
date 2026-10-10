//! The configured `fuzzing.default_sanitizer` selects the sanitizer of newly
//! built harnesses (an explicit per-build request overrides it). Separate from
//! `sanitizer_selection.rs` because `HF_CONFIG_DIR` is process-global and this
//! file's fixture writes a different `default_sanitizer`. No Docker, no
//! network, no real LLM: a recording stub runtime and a fixed-reply provider
//! pool.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::{Sanitizer, TargetLanguage};
use hf_service::ServiceContainer;

/// Fixture C project: a parser-shaped fuzz target.
const FIXTURE: &str = r"
#include <stddef.h>
#include <stdint.h>

int parse_value(const uint8_t *data, size_t len) {
    if (len >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        return 1;
    }
    return 0;
}
";

/// Fixed LLM reply for the harness draft: a fenced C block driving the target.
const HARNESS_REPLY: &str = r"```c
#include <stddef.h>
#include <stdint.h>

int parse_value(const uint8_t *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)parse_value(data, size);
    return 0;
}
```";

fn completed(exit_code: i32, stdout: &str, cwd: &Path) -> CommandResult {
    CommandResult {
        exit_code,
        stdout: stdout.to_owned(),
        stderr: String::new(),
        workspace: cwd.to_path_buf(),
        termination: CommandTermination::Completed,
    }
}

/// A runtime that records every command so tests can inspect the exact
/// compile script and run argv a stage dispatched. Compilation leaves a
/// harness binary behind; smoke is a clean measured pass.
#[derive(Default)]
struct RecordingRuntime {
    commands: Mutex<Vec<Vec<String>>>,
}

impl RecordingRuntime {
    /// Every recorded `bash -c` script (harness compiles).
    fn scripts(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|cmd| cmd.first().is_some_and(|part| part == "bash"))
            .map(|cmd| cmd.join(" "))
            .collect()
    }
}

#[async_trait]
impl RuntimeAdapter for RecordingRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_value"), b"mock compiled harness").unwrap();
        Ok(completed(0, "", cwd))
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        _opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        self.commands.lock().unwrap().push(cmd.to_vec());
        if cmd.iter().any(|argument| argument.contains(" -o ")) {
            return self.run_command(cmd, cwd, limits).await;
        }
        // Smoke qualification: a clean, measured pass.
        Ok(completed(
            0,
            "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128",
            cwd,
        ))
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.commands.lock().unwrap().push(cmd.to_vec());
        let _ = (limits, opts);
        on_line("#1 pulse cov: 42 ft: 84 exec/s: 256");
        on_line("DONE cov: 42 ft: 84 corp: 3/24b exec/s: 256");
        Ok(completed(0, "", cwd))
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// A pool that answers every completion with the fixed harness-source reply
/// and approves the mandatory pre-execution harness review.
struct HarnessDraftPool;

#[async_trait]
impl hf_core::provider::ProviderPool for HarnessDraftPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        Ok(hf_test_utils::fixtures::make_chat_response(HARNESS_REPLY))
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "unused".to_owned(),
        })
    }
    fn report_error(
        &self,
        _provider_id: &hf_core::types::ProviderId,
        _error: &hf_core::provider::ProviderError,
    ) {
    }
    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}
    async fn thaw(
        &self,
        _provider_id: &hf_core::types::ProviderId,
    ) -> Result<(), hf_core::provider::ProviderError> {
        Ok(())
    }
}

/// Isolate the config directory and pin a fuzzing policy; `extra_fuzzing`
/// appends lines to the `[fuzzing]` table.
fn write_fuzzing_policy(config_dir: &Path, extra_fuzzing: &str) {
    std::env::set_var("HF_CONFIG_DIR", config_dir);
    hf_service::config::write_config(
        "oxfuzz",
        &format!(
            "[fuzzing]\n\
             enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\"]\n\
             default_engine = \"libfuzzer\"\n\
             default_duration_secs = 30\n\
             {extra_fuzzing}\n\
             [fuzzing.sandbox]\n\
             max_mem_mb = 1024\n\
             max_cpus = 1\n\
             max_duration_secs = 600\n"
        ),
    )
    .expect("write fuzzing policy");
}

async fn fixture(
    extra_fuzzing: &str,
) -> (
    tempfile::TempDir,
    Arc<hf_storage::Store>,
    ServiceContainer,
    Arc<RecordingRuntime>,
) {
    let _workspace_root = common::install_managed_workspace("oxfuzz_sanitizer_it");
    let dir = tempfile::tempdir().unwrap();
    write_fuzzing_policy(&dir.path().join("config"), extra_fuzzing);
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), FIXTURE).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("sanitizer.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(RecordingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(HarnessDraftPool)))
        .with_store(Arc::clone(&store));
    (dir, store, container, runtime)
}

/// Compile + smoke + promote a harness for `parse_value`, returning nothing:
/// the persisted harness record is the interesting output.
async fn qualify(container: &ServiceContainer, project: &Path, sanitizer: Option<Sanitizer>) {
    container
        .harness_generate(
            project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            sanitizer,
        )
        .await
        .expect("prepare harness");
    container
        .harness_smoke(
            project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(project, "parse_value", EngineKind::LibFuzzer)
        .await
        .expect("operator promotes harness");
}

/// The promoted harness revision's build sanitizer, read from the store.
async fn promoted_sanitizer(store: &Arc<hf_storage::Store>, project: &Path) -> Sanitizer {
    let target_id = store
        .list_targets(&project.canonicalize().unwrap().to_string_lossy())
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.symbol == "parse_value")
        .map(|candidate| candidate.id)
        .expect("target persisted");
    let harnesses = store.list_harnesses(target_id).await.unwrap();
    harnesses
        .iter()
        .find(|harness| harness.status == hf_core::harness::HarnessStatus::Promoted)
        .expect("a promoted harness exists")
        .sanitizer
}

#[tokio::test]
async fn the_configured_default_sanitizer_applies_to_new_builds() {
    let (_dir, store, container, runtime) = fixture("default_sanitizer = \"undefined\"").await;
    let project = _dir.path().join("proj");

    qualify(&container, &project, None).await;

    assert!(
        runtime
            .scripts()
            .iter()
            .any(|script| script.contains("-fsanitize=undefined")),
        "the configured default reaches the build script: {:?}",
        runtime.scripts()
    );
    assert_eq!(
        promoted_sanitizer(&store, &project).await,
        Sanitizer::Undefined
    );
}

#[tokio::test]
async fn an_explicit_build_request_overrides_the_configured_default() {
    let (_dir, store, container, runtime) = fixture("default_sanitizer = \"undefined\"").await;
    let project = _dir.path().join("proj");

    qualify(&container, &project, Some(Sanitizer::Address)).await;

    assert!(
        runtime
            .scripts()
            .iter()
            .any(|script| script.contains("-fsanitize=address")),
        "the explicit request wins over the configured default: {:?}",
        runtime.scripts()
    );
    assert_eq!(
        promoted_sanitizer(&store, &project).await,
        Sanitizer::Address
    );
}
