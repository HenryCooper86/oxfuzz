//! Integration tests for opt-in AFL++ session resume (`--resume` /
//! `fuzzing.default_resume`): the newest compatible prior output tree is
//! copied into the new run's staging and afl-fuzz continues it under
//! `AFL_AUTORESUME=1` (injected by the runner, never argv).

mod common;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hf_core::engine::EngineKind;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

const TARGET: &str = "parse_entry";
/// The queue entry the fake engine "produces"; a resumed run must see the
/// donor's copy in its own output tree before it starts.
const MARKER: &str = "id:000000,orig:seed";

/// What the fake engine observed at launch: the sandbox environment, and
/// whether its output tree already held the donor session's queue marker.
#[derive(Debug, Clone)]
struct Launch {
    env: HashMap<String, String>,
    resumed_marker: bool,
}

/// A runtime that reports every compile/smoke command as a clean success and
/// plays an AFL++ fuzz run: it records the launch environment, checks the
/// bind-mounted output tree for the donor marker, then writes its own session
/// tree (`default/fuzzer_stats` + `default/queue/<MARKER>`) the way afl-fuzz
/// would.
struct AflSessionRuntime {
    launches: Mutex<Vec<Launch>>,
    write_crash: std::sync::atomic::AtomicBool,
}

impl AflSessionRuntime {
    fn launches(&self) -> Vec<Launch> {
        self.launches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn out_mount(opts: &SandboxOptions) -> Option<PathBuf> {
        opts.extra_mounts
            .iter()
            .find(|mount| mount.container_path.ends_with("/out"))
            .map(|mount| mount.host_path.clone())
    }

    fn write_session_tree(&self, out: &Path) {
        let instance = out.join("default");
        std::fs::create_dir_all(instance.join("queue")).unwrap();
        std::fs::write(
            instance.join("fuzzer_stats"),
            "start_time : 100\nlast_update : 200\nexecs_done : 50\ncycles_done : 1\ncorpus_count : 3\nsaved_crashes : 0\nsaved_hangs : 0\n",
        )
        .unwrap();
        std::fs::write(instance.join("queue").join(MARKER), b"session input").unwrap();
        if self.write_crash.load(std::sync::atomic::Ordering::Relaxed) {
            std::fs::create_dir_all(instance.join("crashes")).unwrap();
            std::fs::write(
                instance.join("crashes").join("id:000001,sig:06"),
                b"crashing input",
            )
            .unwrap();
        }
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for AflSessionRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn run_command_streaming_opts(
        &self,
        _cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        let out = Self::out_mount(opts).expect("fuzz runs mount their output tree");
        self.launches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Launch {
                env: limits.env.clone(),
                resumed_marker: out.join("default/queue").join(MARKER).is_file(),
            });
        self.write_session_tree(&out);
        on_line("DONE");
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        path: &Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, content)
            .map_err(|error| hf_core::error::ClassifiedError::Internal(error.to_string()))
    }

    async fn read_file(&self, path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// A fenced C harness for drafting, an approving review for smoke.
struct CodeBlockPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for CodeBlockPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        Ok(hf_test_utils::fixtures::make_chat_response(
            "```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return 0; }\n```",
        ))
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

/// A promoted AFL++ harness over a stub runtime, ready for campaign runs.
async fn afl_project(
    prefix: &str,
    write_crash: bool,
) -> (
    tempfile::TempDir,
    PathBuf,
    Arc<hf_storage::Store>,
    ServiceContainer,
    Arc<AflSessionRuntime>,
) {
    common::install_managed_workspace(prefix);
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("resume_proj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("resume.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(AflSessionRuntime {
        launches: Mutex::new(Vec::new()),
        write_crash: std::sync::atomic::AtomicBool::new(write_crash),
    });
    let container = ServiceContainer::new(
        Arc::clone(&runtime) as Arc<dyn RuntimeAdapter>,
        Some(Arc::new(CodeBlockPool)),
    )
    .with_store(Arc::clone(&store));
    container
        .harness_generate(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            1,
            None,
        )
        .await
        .expect("generate harness");
    let workspace = hf_service::workspace_dir(&project, TARGET);
    std::fs::write(workspace.join(format!("fuzz_{TARGET}")), b"#!/bin/true").unwrap();
    container
        .harness_smoke(&project, TARGET, EngineKind::AflPlusPlus, TargetLanguage::C)
        .await
        .expect("smoke harness");
    container
        .harness_promote(&project, TARGET, EngineKind::AflPlusPlus)
        .await
        .expect("operator promotes harness");
    (dir, project, store, container, runtime)
}

#[tokio::test]
async fn resume_continues_the_prior_session_tree() {
    let (_dir, project, store, container, runtime) =
        afl_project("oxfuzz_afl_resume_a", false).await;
    let sink = |_: hf_service::FuzzProgress| {};

    let first = container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            Some(true),
            None,
            &sink,
        )
        .await
        .expect("first run");
    let second = container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            Some(true),
            None,
            &sink,
        )
        .await
        .expect("second run resumes the first");

    let launches = runtime.launches();
    assert_eq!(launches.len(), 2, "two fuzz launches: {launches:?}");
    // First run: resume was requested but no donor exists, so it cold-starts --
    // still under AFL_AUTORESUME, which is a no-op on a fresh tree.
    assert!(!launches[0].resumed_marker, "first run starts cold");
    assert_eq!(
        launches[0].env.get("AFL_AUTORESUME").map(String::as_str),
        Some("1")
    );
    // Second run: the donor tree (the first run's queue marker) is in place
    // before the engine starts, under the same env contract.
    assert!(
        launches[1].resumed_marker,
        "the donor tree must be staged before launch"
    );
    assert_eq!(
        launches[1].env.get("AFL_AUTORESUME").map(String::as_str),
        Some("1")
    );

    for run_id in [first.run_id, second.run_id] {
        let record = store.get_run(run_id).await.unwrap().expect("persisted run");
        let config = record.config.expect("persisted config");
        assert!(
            config.resume,
            "the persisted config records the resume choice"
        );
    }
    // The continued tree is real evidence: the donor's queue input landed in
    // the second run's own output directory.
    let workspace = hf_service::workspace_dir(&project, TARGET);
    let second_out = workspace
        .join("runs")
        .join(second.run_id.to_string())
        .join("out");
    assert!(
        second_out.join("default/queue").join(MARKER).is_file(),
        "the resumed run owns its continued tree"
    );
}

#[tokio::test]
async fn without_resume_every_run_cold_starts() {
    let (_dir, project, _store, container, runtime) =
        afl_project("oxfuzz_afl_resume_b", false).await;
    let sink = |_: hf_service::FuzzProgress| {};

    container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            None,
            None,
            &sink,
        )
        .await
        .expect("first run");
    container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            None,
            None,
            &sink,
        )
        .await
        .expect("second run");

    let launches = runtime.launches();
    assert_eq!(launches.len(), 2);
    for launch in &launches {
        assert!(!launch.resumed_marker, "no resume, no donor tree");
        assert!(!launch.env.contains_key("AFL_AUTORESUME"));
    }
}

#[tokio::test]
async fn resume_on_a_non_afl_engine_fails_loud() {
    common::install_managed_workspace("oxfuzz_afl_resume_c");
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("reject_proj");
    std::fs::create_dir_all(&project).unwrap();
    let container = ServiceContainer::new(
        Arc::new(AflSessionRuntime {
            launches: Mutex::new(Vec::new()),
            write_crash: std::sync::atomic::AtomicBool::new(false),
        }),
        None,
    );

    let error = container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::LibFuzzer,
            1,
            None,
            None,
            Some(true),
            None,
            &|_: hf_service::FuzzProgress| {},
        )
        .await
        .expect_err("resume is AFL++-only");
    assert!(error.to_string().contains("afl++"), "{error}");
    assert!(error.to_string().contains("resume"), "{error}");
}

#[tokio::test]
async fn campaign_iterations_chain_through_resume() {
    let (_dir, project, _store, container, runtime) =
        afl_project("oxfuzz_afl_resume_d", false).await;
    let sink = |_: hf_service::FuzzProgress| {};

    let outcome = container
        .run_campaign_observed(
            &project,
            Some(TARGET),
            EngineKind::AflPlusPlus,
            TargetLanguage::C,
            1,
            None,
            Some(true),
            None,
            2,
            &sink,
        )
        .await
        .expect("campaign completes");

    assert_eq!(outcome.iterations, 2, "{outcome:?}");
    let launches = runtime.launches();
    assert_eq!(launches.len(), 2, "one fuzz launch per iteration");
    assert!(!launches[0].resumed_marker, "iteration 1 cold-starts");
    assert!(
        launches[1].resumed_marker,
        "iteration 2 continues iteration 1's tree"
    );
}

#[tokio::test]
async fn a_resumed_tree_still_ingests_its_prior_crashes() {
    let (_dir, project, store, container, runtime) = afl_project("oxfuzz_afl_resume_e", true).await;
    let sink = |_: hf_service::FuzzProgress| {};

    let first = container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            None,
            None,
            &sink,
        )
        .await
        .expect("first run");
    let triaged = container
        .triage_run(&project, TARGET, first.run_id)
        .await
        .expect("triage first run");
    assert_eq!(triaged.len(), 1, "the session's crash ingests: {triaged:?}");

    // The resumed run writes no crash of its own: the crash its triage sees is
    // the one copied forward with the donor tree.
    runtime
        .write_crash
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let resumed = container
        .run_fuzzer(
            &project,
            TARGET,
            EngineKind::AflPlusPlus,
            1,
            None,
            None,
            Some(true),
            None,
            &sink,
        )
        .await
        .expect("resumed run");
    let triaged = container
        .triage_run(&project, TARGET, resumed.run_id)
        .await
        .expect("triage resumed run");
    assert_eq!(
        triaged.len(),
        1,
        "the copied crash artifact ingests for the resumed run: {triaged:?}"
    );

    // Re-triaging the resumed run replaces rather than duplicates its rows.
    let again = container
        .triage_run(&project, TARGET, resumed.run_id)
        .await
        .expect("re-triage resumed run");
    assert_eq!(again.len(), 1, "triage is idempotent: {again:?}");
    let resumed_rows = store
        .list_crashes_by_run(resumed.run_id)
        .await
        .expect("resumed run crashes");
    assert_eq!(
        resumed_rows.len(),
        1,
        "one crash row for the resumed run: {resumed_rows:?}"
    );
    assert!(
        resumed_rows[0].input_path.ends_with("id:000001,sig:06"),
        "the row is the copied artifact: {:?}",
        resumed_rows[0].input_path
    );
}
