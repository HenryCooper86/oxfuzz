//! Integration test for cross-engine corpus sharing: every engine run for a
//! target seeds from the one canonical retained corpus (`<workspace>/corpus`),
//! engine discoveries merge back into it, and crash survivors absorbed from
//! one engine's run feed the next engine's run -- findings compound across
//! engines. Persisted corpus rows must reconcile exactly against the canonical
//! survivor set at every step. No Docker, no network, no real LLM.

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

/// A runtime that simulates real engine behavior by engine kind: libFuzzer
/// campaign runs add a new-coverage unit in place to the run corpus snapshot,
/// while an AFL++ campaign run drops a queue unit and a crash input into its
/// run output. Compilation leaves a binary; smoke is a clean measured pass.
#[derive(Default)]
struct SharingRuntime {
    libfuzzer_runs: Mutex<u32>,
}

#[async_trait]
impl RuntimeAdapter for SharingRuntime {
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
        _limits: &ResourceLimits,
        opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        let mount = |suffix: &str| {
            opts.extra_mounts
                .iter()
                .find(|mount| mount.container_path.ends_with(suffix))
                .unwrap_or_else(|| panic!("run mount ending in {suffix}"))
                .host_path
                .clone()
        };
        if cmd.iter().any(|part| part == "afl-fuzz") {
            // AFL++ keeps new coverage in out/<instance>/queue and crashes in
            // out/<instance>/crashes.
            let out = mount("/out");
            let queue = out.join("default").join("queue");
            std::fs::create_dir_all(&queue).unwrap();
            std::fs::write(queue.join("afl-queue-unit"), b"QUEUE").unwrap();
            let crashes = out.join("default").join("crashes");
            std::fs::create_dir_all(&crashes).unwrap();
            std::fs::write(crashes.join("id:000000,sig:06"), b"CRASH").unwrap();
        } else {
            // libFuzzer writes new-coverage units in place into its corpus dir.
            let run = self.libfuzzer_runs.lock().unwrap().to_string();
            std::fs::write(mount("/corpus").join(format!("lf-discovery-{run}")), b"LF").unwrap();
            *self.libfuzzer_runs.lock().unwrap() += 1;
        }
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

/// The persisted corpus rows for a target must reconcile exactly against the
/// canonical on-disk survivor set (the repo's corpus invariant).
async fn assert_rows_match_survivors(
    store: &hf_storage::Store,
    target_id: Uuid,
    canonical: &Path,
    stage: &str,
) {
    let survivors = hf_corpus::list(canonical).unwrap();
    let mut on_disk: Vec<String> = survivors
        .entries
        .iter()
        .map(|entry| entry.sha256.clone())
        .collect();
    on_disk.sort();
    let rows = store.list_corpus_entries(target_id).await.unwrap();
    let mut persisted: Vec<String> = rows.iter().map(|entry| entry.sha256.clone()).collect();
    persisted.sort();
    assert_eq!(
        persisted, on_disk,
        "persisted corpus rows must match the canonical survivor set after {stage}"
    );
}

/// Compile, smoke-qualify, and promote the fixture harness for one engine,
/// switching the target's active harness to that engine.
async fn promote_for_engine(container: &ServiceContainer, project: &Path, engine: EngineKind) {
    container
        .harness_generate(project, "parse_value", engine, TargetLanguage::C, 1)
        .await
        .expect("prepare harness");
    container
        .harness_smoke(project, "parse_value", engine, TargetLanguage::C)
        .await
        .expect("smoke harness");
    container
        .harness_promote(project, "parse_value", engine)
        .await
        .expect("operator promotes harness");
}

#[tokio::test]
async fn engines_share_one_canonical_corpus_and_absorbed_crashes() {
    common::install_managed_workspace("oxfuzz_corpus_sharing_it");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("sharing_project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), FIXTURE).unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("sharing.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(SharingRuntime::default()),
        Some(Arc::new(HarnessDraftPool)),
    )
    .with_store(Arc::clone(&store));

    promote_for_engine(&container, &project, EngineKind::LibFuzzer).await;

    // Initial heuristic seeds land in the one canonical corpus root shared by
    // every engine.
    container
        .generate_seeds(&project, "parse_value")
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(&project, "parse_value");
    let canonical = workspace.join("corpus");
    let initial = hf_corpus::list(&canonical).unwrap();
    assert!(
        !initial.entries.is_empty(),
        "heuristic seeds must populate the canonical corpus"
    );
    let project_key = project
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let target_id = store
        .list_targets(&project_key)
        .await
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.symbol == "parse_value")
        .expect("persisted parse_value target")
        .id;
    assert_rows_match_survivors(&store, target_id, &canonical, "seeding").await;

    // Run A (libFuzzer): its in-place discovery merges back into the canonical
    // root after the run.
    let run_a = container
        .run_fuzzer(&project, "parse_value", EngineKind::LibFuzzer, 60, &|_| {})
        .await
        .unwrap();
    assert!(
        canonical.join("lf-discovery-0").is_file(),
        "libFuzzer's run discovery must merge into the canonical corpus"
    );
    assert_rows_match_survivors(&store, target_id, &canonical, "run A merge").await;

    // Run B (AFL++): it must seed from the canonical root -- including run A's
    // merged discovery and the initial seeds, none of which may be lost.
    promote_for_engine(&container, &project, EngineKind::AflPlusPlus).await;
    let run_b = container
        .run_fuzzer(
            &project,
            "parse_value",
            EngineKind::AflPlusPlus,
            60,
            &|_| {},
        )
        .await
        .unwrap();
    let staged_b = workspace
        .join("runs")
        .join(run_b.run_id.to_string())
        .join("corpus");
    assert!(
        staged_b.join("lf-discovery-0").is_file(),
        "the AFL++ run must seed from the canonical corpus, including run A's discovery"
    );
    for entry in &initial.entries {
        let name = entry.path.file_name().unwrap();
        assert!(
            staged_b.join(name).is_file(),
            "initial seed {} must survive into the AFL++ run's seed snapshot",
            name.to_string_lossy()
        );
    }
    assert_ne!(run_a.run_id, run_b.run_id);
    assert!(
        canonical.join("afl-queue-unit").is_file(),
        "the AFL++ queue discovery must merge into the canonical corpus"
    );
    assert_rows_match_survivors(&store, target_id, &canonical, "run B merge").await;

    // Absorb engine B's crash survivor back into the canonical root.
    let added = container
        .corpus_absorb_crashes_for_run(&project, "parse_value", run_b.run_id)
        .await
        .unwrap();
    assert_eq!(added, 1, "the AFL++ crash survivor must be absorbed");
    assert!(
        canonical.join("crash_id:000000,sig:06").is_file(),
        "the absorbed crash input must land in the canonical corpus"
    );
    assert_rows_match_survivors(&store, target_id, &canonical, "crash absorb").await;

    // Run C (libFuzzer again): it seeds from the canonical root, so the crash
    // survivor from engine B's run and engine B's queue discovery both feed it.
    promote_for_engine(&container, &project, EngineKind::LibFuzzer).await;
    let run_c = container
        .run_fuzzer(&project, "parse_value", EngineKind::LibFuzzer, 60, &|_| {})
        .await
        .unwrap();
    let staged_c = workspace
        .join("runs")
        .join(run_c.run_id.to_string())
        .join("corpus");
    assert!(
        staged_c.join("crash_id:000000,sig:06").is_file(),
        "the crash survivor absorbed from the AFL++ run must seed the next libFuzzer run"
    );
    assert!(
        staged_c.join("afl-queue-unit").is_file(),
        "the AFL++ queue discovery must seed the next libFuzzer run"
    );

    // No pre-existing corpus content was destroyed anywhere in the transition
    // across engines: the initial seeds are still live in the canonical root.
    for entry in &initial.entries {
        let name = entry.path.file_name().unwrap();
        assert!(
            canonical.join(name).is_file(),
            "initial seed {} must not be lost across engine runs",
            name.to_string_lossy()
        );
    }
    assert_rows_match_survivors(&store, target_id, &canonical, "run C merge").await;

    std::fs::remove_dir_all(&workspace).ok();
}
