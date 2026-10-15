//! Integration coverage for AFL++ CmpLog/redqueen: a `--cmplog` harness build
//! compiles the companion binary (`AFL_LLVM_CMPLOG=1`) and records it on the
//! harness revision, and a `--cmplog` run drives it via `afl-fuzz -c`. An
//! opted-in run against a companion-less revision fails loud, naming the build
//! that produces the companion. No Docker, no network, no real LLM: a
//! recording stub runtime and a fixed-reply provider pool.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

/// Fixture C project: a magic-byte parser (the bug class `CmpLog` answers).
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

/// One recorded sandbox invocation: the argv and the environment it carried.
type RecordedCommand = (Vec<String>, std::collections::HashMap<String, String>);

/// A runtime that records every command (with the sandbox env it carried) so
/// tests can inspect the exact compile scripts and run argv a stage
/// dispatched. Compilations materialize the binary their script names; smoke
/// is a clean measured pass; campaign runs complete immediately.
#[derive(Default)]
struct RecordingRuntime {
    commands: Mutex<Vec<RecordedCommand>>,
}

impl RecordingRuntime {
    /// Every recorded `bash -c` compile script.
    fn compile_scripts(&self) -> Vec<String> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|(cmd, _)| cmd.first().is_some_and(|part| part == "bash"))
            .map(|(cmd, _)| cmd.join(" "))
            .collect()
    }

    /// The sandbox env of every recorded `bash -c` compile.
    fn compile_envs(&self) -> Vec<std::collections::HashMap<String, String>> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|(cmd, _)| cmd.first().is_some_and(|part| part == "bash"))
            .map(|(_, env)| env.clone())
            .collect()
    }

    /// Every recorded `afl-fuzz` argv.
    fn afl_runs(&self) -> Vec<Vec<String>> {
        self.commands
            .lock()
            .unwrap()
            .iter()
            .filter(|(cmd, _)| cmd.first().is_some_and(|part| part == "afl-fuzz"))
            .map(|(cmd, _)| cmd.clone())
            .collect()
    }

    /// Materialize the binary a compile script names (`-o /tmp/<name>`, then
    /// the script copies it into the mounted workspace).
    fn materialize_compile_output(script: &str, cwd: &Path) {
        let marker = "-o /tmp/";
        if let Some(at) = script.find(marker) {
            let name = script[at + marker.len()..]
                .split_whitespace()
                .next()
                .unwrap_or("fuzz_value")
                .trim_matches('\'')
                .to_owned();
            std::fs::write(cwd.join(&name), format!("binary:{name}")).unwrap();
        }
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
        Ok(completed(0, "", cwd))
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        _opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::create_dir_all(cwd).unwrap();
        self.commands
            .lock()
            .unwrap()
            .push((cmd.to_vec(), limits.env.clone()));
        if cmd.first().is_some_and(|part| part == "bash") {
            Self::materialize_compile_output(&cmd.join(" "), cwd);
            return Ok(completed(0, "", cwd));
        }
        // Smoke qualification: a clean, measured AFL++ pass.
        Ok(completed(0, "exec speed : 512/sec\ncycles done : 1", cwd))
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        _opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.commands
            .lock()
            .unwrap()
            .push((cmd.to_vec(), limits.env.clone()));
        on_line("exec speed : 1024/sec");
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

/// A pool that answers the harness draft with the fixed source and approves
/// the mandatory pre-execution harness review.
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

fn write_fuzzing_policy(config_dir: &Path) {
    std::env::set_var("HF_CONFIG_DIR", config_dir);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\n\
         enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\"]\n\
         default_engine = \"afl++\"\n\
         default_duration_secs = 30\n\
         [fuzzing.sandbox]\n\
         max_mem_mb = 1024\n\
         max_cpus = 1\n\
         max_duration_secs = 600\n",
    )
    .expect("write fuzzing policy");
}

async fn fixture() -> (
    tempfile::TempDir,
    Arc<hf_storage::Store>,
    ServiceContainer,
    Arc<RecordingRuntime>,
    std::path::PathBuf,
) {
    let workspace_root = common::install_managed_workspace("oxfuzz_cmplog_it");
    let dir = tempfile::tempdir().unwrap();
    write_fuzzing_policy(&dir.path().join("config"));
    let project = dir.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), FIXTURE).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("cmplog.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(RecordingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(HarnessDraftPool)))
        .with_store(Arc::clone(&store));
    (dir, store, container, runtime, workspace_root)
}

/// Build (with or without a `CmpLog` companion), smoke, and promote a harness
/// for `parse_value`.
async fn qualify(container: &ServiceContainer, project: &Path, cmplog: bool) {
    container
        .harness_generate(
            project,
            "parse_value",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            1,
            None,
            cmplog,
            false,
        )
        .await
        .expect("prepare harness");
    container
        .harness_smoke(
            project,
            "parse_value",
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(project, "parse_value", EngineKind::AflPlusPlus)
        .await
        .expect("operator promotes harness");
}

/// The promoted harness revision for `parse_value`, read from the store.
async fn promoted_harness(
    store: &Arc<hf_storage::Store>,
    project: &Path,
) -> hf_core::harness::Harness {
    let target_id = store
        .list_targets(&project.canonicalize().unwrap().to_string_lossy())
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.symbol == "parse_value")
        .map(|candidate| candidate.id)
        .expect("target persisted");
    store
        .list_harnesses(target_id)
        .await
        .unwrap()
        .into_iter()
        .find(|harness| harness.status == hf_core::harness::HarnessStatus::Promoted)
        .expect("a promoted harness exists")
}

#[tokio::test]
async fn cmplog_build_compiles_a_companion_and_the_run_drives_it() {
    let (dir, store, container, runtime, _workspace) = fixture().await;
    let project = dir.path().join("proj");

    qualify(&container, &project, true).await;

    // The build ran two compiles: the plain main binary and the CmpLog
    // companion, and only the companion carried the CmpLog instrumentation env.
    let scripts = runtime.compile_scripts();
    assert_eq!(scripts.len(), 2, "main build plus companion: {scripts:?}");
    assert!(
        scripts
            .iter()
            .all(|script| script.contains("afl-clang-fast")),
        "both builds use the AFL++ driver: {scripts:?}"
    );
    assert!(
        scripts
            .iter()
            .any(|script| script.contains("fuzz_parse_value.cmplog")),
        "the companion output is named beside the main binary: {scripts:?}"
    );
    let envs = runtime.compile_envs();
    assert!(
        !envs[0].contains_key("AFL_LLVM_CMPLOG"),
        "main build is plain"
    );
    assert_eq!(
        envs[1].get("AFL_LLVM_CMPLOG").map(String::as_str),
        Some("1"),
        "the companion build sets AFL_LLVM_CMPLOG=1"
    );

    // The revision records the companion and its exact digest, and the
    // companion binary exists in the workspace.
    let harness = promoted_harness(&store, &project).await;
    let companion = harness.cmplog.as_ref().expect("companion record");
    let digest = companion
        .binary_sha256
        .as_deref()
        .expect("a completed build records the digest");
    assert_eq!(digest.len(), 64);
    let workspace = hf_service::workspace_dir(&project, "parse_value");
    assert!(workspace.join("fuzz_parse_value.cmplog").is_file());

    // An opted-in run drives the companion: the afl-fuzz argv carries -c with
    // the staged companion path, and the run records the choice.
    let summary = container
        .run_fuzzer(
            &project,
            "parse_value",
            EngineKind::AflPlusPlus,
            30,
            None,
            None,
            None,
            None,
            Some(true),
            // CmpLog probe carries no explicit seed.
            None,
            &|_| {},
        )
        .await
        .expect("cmplog run");
    assert!(summary.cmplog, "the summary notes an active CmpLog run");
    let run = store.get_run(summary.run_id).await.unwrap().unwrap();
    assert!(
        run.config.as_ref().expect("run config").cmplog,
        "the run records the CmpLog choice"
    );
    let runs = runtime.afl_runs();
    let campaign = runs.last().expect("campaign run argv");
    let flag = campaign
        .iter()
        .position(|arg| arg == "-c")
        .expect("-c flag");
    assert!(
        campaign[flag + 1].ends_with("/input/harness.cmplog"),
        "-c names the staged companion: {campaign:?}"
    );
    // The retained inputs seal the companion in: it sits beside the staged
    // main binary in the run's input directory.
    let staged = workspace
        .join("runs")
        .join(summary.run_id.to_string())
        .join("input")
        .join("harness.cmplog");
    assert!(staged.is_file(), "companion staged at {staged:?}");
}

#[tokio::test]
async fn cmplog_run_against_a_companionless_harness_fails_loud() {
    let (dir, store, container, runtime, _workspace) = fixture().await;
    let project = dir.path().join("proj");

    qualify(&container, &project, false).await;
    // Smoke qualification legitimately ran afl-fuzz; nothing may launch after
    // the refused campaign request.
    let launches_before = runtime.afl_runs().len();

    let error = container
        .run_fuzzer(
            &project,
            "parse_value",
            EngineKind::AflPlusPlus,
            30,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            &|_| {},
        )
        .await
        .expect_err("a companion-less harness must not serve a --cmplog run");
    let message = error.to_string();
    assert!(message.contains("--cmplog"), "{message}");
    assert!(
        message.contains("oxfuzz harness --target parse_value --engine afl++ --cmplog"),
        "the failure names the build that produces the companion: {message}"
    );
    assert!(
        store
            .list_runs(None)
            .await
            .unwrap()
            .iter()
            .all(|run| run.kind != hf_storage::RunKind::Campaign),
        "no campaign run may persist past the refusal"
    );
    // The refusal happens before any engine launch.
    assert_eq!(
        runtime.afl_runs().len(),
        launches_before,
        "no afl-fuzz invocation survives the refusal"
    );
}

#[tokio::test]
async fn cmplog_request_on_a_non_afl_engine_fails_at_policy_resolution() {
    let (dir, _store, container, _runtime, _workspace) = fixture().await;
    let project = dir.path().join("proj");

    let error = container
        .run_fuzzer(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            30,
            None,
            None,
            None,
            None,
            Some(true),
            None,
            &|_| {},
        )
        .await
        .expect_err("libFuzzer has no CmpLog companion path");
    let message = error.to_string();
    assert!(message.contains("--cmplog"), "{message}");
    assert!(message.contains("afl++"), "{message}");
}

#[tokio::test]
async fn fuzz_cmplog_rebuilds_a_companionless_promoted_harness() {
    let (dir, store, container, _runtime, _workspace) = fixture().await;
    let project = dir.path().join("proj");
    let request = |cmplog| hf_service::FuzzRequest {
        project: &project,
        target: Some("parse_value"),
        engine: EngineKind::AflPlusPlus,
        lang: Some(TargetLanguage::C),
        duration_secs: 1,
        iterations: 1,
        timeout_ms: None,
        resume: None,
        review_bypass: hf_service::HarnessReviewBypass::NotRequested,
        fresh: false,
        sanitizer: None,
        cmplog,
        seed: None,
    };

    let plain = container
        .fuzz_onboard(request(false), &|_| {}, &|_| {})
        .await
        .expect("plain pipeline");
    assert!(!plain.harness_reused);
    let plain_harness = store
        .get_harness(plain.harness_id)
        .await
        .unwrap()
        .expect("harness persisted");
    assert!(plain_harness.cmplog.is_none());

    // A CmpLog request must not reuse the companion-less revision: the
    // pipeline drafts and qualifies a fresh one carrying the companion.
    let cmplog_run = container
        .fuzz_onboard(request(true), &|_| {}, &|_| {})
        .await
        .expect("cmplog pipeline rebuilds");
    assert!(
        !cmplog_run.harness_reused,
        "a companion-less promoted harness is not reused for CmpLog"
    );
    assert_ne!(cmplog_run.harness_id, plain.harness_id);
    let cmplog_harness = store
        .get_harness(cmplog_run.harness_id)
        .await
        .unwrap()
        .expect("cmplog harness persisted");
    assert!(cmplog_harness.cmplog.is_some());

    // A second CmpLog run reuses the companion-carrying revision.
    let reused = container
        .fuzz_onboard(request(true), &|_| {}, &|_| {})
        .await
        .expect("a companion-carrying harness is reusable");
    assert!(reused.harness_reused);
    assert_eq!(reused.harness_id, cmplog_run.harness_id);
}
