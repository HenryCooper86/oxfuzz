//! Integration test for deterministic run seeds and `ServiceContainer::replay_run`:
//! a campaign run persists a seed, a replay re-executes with that exact seed
//! under a new run id linked to the original, and a legacy run without a
//! recorded seed replays with the seed derived from its run id. No Docker, no
//! network, no real LLM: the sandbox is a recording stub runtime and the LLM a
//! fixed-reply pool.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use hf_storage::RunStatus;
use uuid::Uuid;

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

/// A runtime that records every streaming campaign command so tests can
/// inspect the exact argv a run (or its replay) dispatched to the engine.
/// Compilation leaves a harness binary, smoke is a clean measured pass, and a
/// campaign run streams libFuzzer progress lines.
#[derive(Default)]
struct RecordingRuntime {
    commands: Mutex<Vec<Vec<String>>>,
}

impl RecordingRuntime {
    /// The recorded campaign argv for one run. The runner addresses run-owned
    /// directories by container path, which embeds the run id.
    fn campaign_args(&self, run_id: Uuid) -> Vec<String> {
        let marker = format!("/work/runs/{run_id}");
        self.commands
            .lock()
            .unwrap()
            .iter()
            .find(|cmd| cmd.iter().any(|part| part.contains(&marker)))
            .unwrap_or_else(|| panic!("no recorded command for run {run_id}"))
            .clone()
    }
}

#[async_trait]
impl RuntimeAdapter for RecordingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        // Harness compilation: the stubbed compiler leaves a binary behind.
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_value"), b"mock compiled harness").unwrap();
        Ok(completed(0, "", cwd))
    }

    async fn run_command_opts(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        // Smoke qualification: a clean, measured libFuzzer pass.
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
        _limits: &ResourceLimits,
        _opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.commands.lock().unwrap().push(cmd.to_vec());
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

/// A pool that answers every completion with the fixed harness-source reply.
struct HarnessDraftPool;

#[async_trait]
impl hf_core::provider::ProviderPool for HarnessDraftPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
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

#[tokio::test]
async fn run_records_a_seed_and_replay_reexecutes_with_it() {
    common::install_managed_workspace("oxfuzz_run_replay_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("replay_project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), FIXTURE).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("replay.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(RecordingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(HarnessDraftPool)))
        .with_store(Arc::clone(&store));

    container
        .harness_generate(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        )
        .await
        .expect("prepare harness");
    container
        .harness_smoke(
            &project,
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(&project, "parse_value", EngineKind::LibFuzzer)
        .await
        .expect("operator promotes harness");

    // A campaign run records a deterministic seed, derived from its run id by
    // default, and the engine adapter receives exactly that seed.
    let summary = container
        .run_fuzzer(&project, "parse_value", EngineKind::LibFuzzer, 60, &|_| {})
        .await
        .unwrap();
    let run = store.get_run(summary.run_id).await.unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Done);
    let config = run.config.clone().expect("campaign run config");
    let seed = config.seed.expect("campaign run must record a seed");
    assert_eq!(
        seed,
        hf_engine::seed::derive_run_seed(summary.run_id),
        "the default seed derives deterministically from the run id"
    );
    assert_eq!(config.replay_of, None);
    let run_args = runtime.campaign_args(summary.run_id);
    assert!(
        run_args.iter().any(|arg| arg == &format!("-seed={seed}")),
        "the adapter must receive the recorded seed: {}",
        run_args.join(" ")
    );

    // Replay: a new run row, the same seed on the argv, a link to the original.
    let replay = container.replay_run(summary.run_id, &|_| {}).await.unwrap();
    assert_ne!(replay.run_id, summary.run_id);
    let replayed = store.get_run(replay.run_id).await.unwrap().unwrap();
    assert_eq!(replayed.status, RunStatus::Done);
    let replayed_config = replayed.config.clone().expect("replayed run config");
    assert_eq!(
        replayed_config.seed,
        Some(seed),
        "replay must re-execute with the original run's seed"
    );
    assert_eq!(
        replayed_config.replay_of,
        Some(summary.run_id),
        "the replayed run must link back to the original"
    );
    let replay_args = runtime.campaign_args(replay.run_id);
    assert!(
        replay_args
            .iter()
            .any(|arg| arg == &format!("-seed={seed}")),
        "the replayed run must dispatch the original seed: {}",
        replay_args.join(" ")
    );

    // The original run's persisted state is undisturbed by the replay.
    let original_after = store.get_run(summary.run_id).await.unwrap().unwrap();
    assert_eq!(original_after.status, RunStatus::Done);
    let original_config = original_after.config.expect("original run config");
    assert_eq!(original_config.seed, Some(seed));
    assert_eq!(original_config.replay_of, None);

    // A legacy run persisted before seeds were recorded replays with the seed
    // derived from its own run id -- the same derivation the original run path
    // would have applied.
    let mut legacy_config = config;
    legacy_config.seed = None;
    legacy_config.replay_of = None;
    let mut legacy = hf_storage::RunRecord::new(
        run.project_root.clone(),
        EngineKind::LibFuzzer,
        Some(legacy_config),
        chrono::Utc::now(),
    );
    legacy.status = RunStatus::Done;
    legacy.ended_at = Some(chrono::Utc::now());
    store.insert_run(&legacy).await.unwrap();
    let legacy_replay = container.replay_run(legacy.id, &|_| {}).await.unwrap();
    let legacy_replayed_config = store
        .get_run(legacy_replay.run_id)
        .await
        .unwrap()
        .unwrap()
        .config
        .expect("legacy replay run config");
    assert_eq!(
        legacy_replayed_config.seed,
        Some(hf_engine::seed::derive_run_seed(legacy.id)),
        "an absent recorded seed must derive deterministically from the original run id"
    );
    assert_eq!(legacy_replayed_config.replay_of, Some(legacy.id));

    // Replaying an unknown run is a validation error, not a panic.
    let unknown = container.replay_run(Uuid::new_v4(), &|_| {}).await;
    assert!(
        matches!(unknown, Err(ClassifiedError::Validation(_))),
        "unknown run id must be rejected: {unknown:?}"
    );

    let workspace = hf_service::workspace_dir(&project, "parse_value");
    std::fs::remove_dir_all(&workspace).ok();
}

#[test]
fn legacy_config_json_without_a_seed_still_deserializes() {
    // Rows persisted before the seed fields existed carry no `seed`/`replay_of`
    // keys in their config_json blob; both must default to `None` so no storage
    // migration is required.
    let legacy_json = serde_json::json!({
        "harness_id": Uuid::nil(),
        "engine": "LibFuzzer",
        "duration": {"secs": 60, "nanos": 0},
        "max_mem_mb": 512,
        "max_cpus": 1,
        "seed_corpus": null,
        "sanitizer": "Address",
        "env": [],
        "extra_args": []
    });
    let parsed: FuzzRunConfig =
        serde_json::from_value(legacy_json).expect("legacy config_json must deserialize");
    assert_eq!(parsed.seed, None);
    assert_eq!(parsed.replay_of, None);

    // And the current shape round-trips the seed fields.
    let seeded_json = serde_json::json!({
        "harness_id": Uuid::nil(),
        "engine": "AflPlusPlus",
        "duration": {"secs": 60, "nanos": 0},
        "max_mem_mb": 512,
        "max_cpus": 1,
        "seed_corpus": null,
        "sanitizer": "Address",
        "env": [],
        "extra_args": [],
        "seed": 42,
        "replay_of": Uuid::nil()
    });
    let parsed: FuzzRunConfig =
        serde_json::from_value(seeded_json).expect("seeded config_json must deserialize");
    assert_eq!(parsed.seed, Some(42));
    assert_eq!(parsed.replay_of, Some(Uuid::nil()));
}
