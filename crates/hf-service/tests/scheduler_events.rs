//! Event-triggered schedules fire when the service emits campaign events:
//! a crash found at triage completion, or a run terminating.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::scheduler::{
    parse_trigger, CampaignParams, CampaignScheduler, EVENT_CRASH_FOUND, EVENT_RUN_COMPLETED,
    EVENT_RUN_FAILED,
};
use hf_service::ServiceContainer;

/// A runtime with no CASR whose crash reproduction reports an `AddressSanitizer`
/// error, so the legacy triage path classifies one crash from the run's
/// evidence directory (same shape as the crash-minimization tests).
struct TriageRuntime;

#[async_trait]
impl RuntimeAdapter for TriageRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _options: &SandboxOptions,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        if cmd.first().is_some_and(|part| part.starts_with("casr-")) {
            return Err(hf_core::error::ClassifiedError::Sandbox(
                "CASR unavailable in test".to_owned(),
            ));
        }
        Ok(CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "ERROR: AddressSanitizer: heap-buffer-overflow\n#0 parse_input".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    project: PathBuf,
    target: TargetCandidate,
    run: hf_storage::RunRecord,
    store: Arc<hf_storage::Store>,
}

/// One project with a promoted harness and a completed run that owns a crash
/// input in its evidence directory.
async fn fixture(name: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    common::install_managed_workspace("hobot_fuzz_scheduler_events_tests");
    let project = root.path().join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&project).unwrap();
    let target = TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: project.clone(),
        language: TargetLanguage::C,
        symbol: "parse_input".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("parse.c"),
            line: 1,
            col: 1,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: "test".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    };
    let harness = hf_core::harness::Harness {
        id: uuid::Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return n && d[0]; }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: hf_core::harness::BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_input"),
        },
        sanitizer: Sanitizer::Address,
        status: hf_core::harness::HarnessStatus::Promoted,
        smoke_run: None,
    };
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: Some(std::time::Duration::from_secs(1)),
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        }),
        chrono::Utc::now(),
    );
    run.status = hf_storage::RunStatus::Done;
    run.ended_at = Some(chrono::Utc::now());
    run.evidence_dir = Some(format!("runs/{}/out", run.id));

    let workspace = hf_service::workspace_dir(&project, &target.symbol);
    let output_dir = workspace.join("runs").join(run.id.to_string()).join("out");
    std::fs::create_dir_all(&output_dir).unwrap();
    // No `binary_rev`: triage falls back to the workspace-level harness binary
    // (and skips the minimization phase).
    std::fs::write(workspace.join("fuzz_parse_input"), b"immutable run binary").unwrap();
    std::fs::write(output_dir.join("crash-original"), b"crashing input").unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("service.db"))
            .await
            .unwrap(),
    );
    store
        .upsert_target(&target, chrono::Utc::now())
        .await
        .unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();

    Fixture {
        root,
        project,
        target,
        run,
        store,
    }
}

fn campaign_params(project: &Path, target: &str) -> CampaignParams {
    CampaignParams {
        project: project.to_string_lossy().into_owned(),
        target: Some(target.to_owned()),
        engine: "libfuzzer".to_owned(),
        lang: "c".to_owned(),
        duration_secs: 60,
        ..CampaignParams::default()
    }
}

/// Wait until the persisted execution history lists `schedule_id`.
async fn wait_for_execution(scheduler: &CampaignScheduler, schedule_id: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let executions = scheduler
                .recent_executions(20)
                .await
                .expect("execution history readable");
            if executions.iter().any(|e| e.schedule_id == schedule_id) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("event schedule did not record an execution");
}

#[tokio::test]
async fn crash_found_at_triage_completion_fires_matching_event_schedule() {
    let fixture = fixture("crash-event").await;
    let container =
        ServiceContainer::new(Arc::new(TriageRuntime), None).with_store(Arc::clone(&fixture.store));
    let scheduler = CampaignScheduler::try_start(
        container.clone(),
        fixture.root.path().join("schedules.json"),
        None,
    )
    .await
    .expect("scheduler starts");

    let params = campaign_params(&fixture.project, &fixture.target.symbol);
    let on_crash = scheduler
        .try_create(
            "on-crash",
            &params,
            parse_trigger("event", EVENT_CRASH_FOUND).unwrap(),
        )
        .await
        .expect("crash.found schedule created");
    // A listener for a different event type must stay quiet.
    let on_run_failed = scheduler
        .try_create(
            "on-run-failed",
            &params,
            parse_trigger("event", EVENT_RUN_FAILED).unwrap(),
        )
        .await
        .expect("run.failed schedule created");

    let crashes = container
        .triage_run(&fixture.project, &fixture.target.symbol, fixture.run.id)
        .await
        .expect("triage completes");
    assert_eq!(crashes.len(), 1, "fixture triage finds the planted crash");

    wait_for_execution(&scheduler, &on_crash.id).await;
    scheduler.stop().await;

    let executions = scheduler.recent_executions(20).await.unwrap();
    assert_eq!(
        executions
            .iter()
            .filter(|e| e.schedule_id == on_crash.id)
            .count(),
        1,
        "crash.found must fire the matching schedule exactly once: {executions:?}"
    );
    assert!(
        executions.iter().all(|e| e.schedule_id != on_run_failed.id),
        "no run failed, so the run.failed listener must not fire: {executions:?}"
    );

    // last_fire is recorded for event fires exactly like cron fires.
    let stored = scheduler
        .list()
        .await
        .into_iter()
        .find(|s| s.id == on_crash.id)
        .unwrap();
    assert!(stored.last_fire.is_some());
}

#[tokio::test]
async fn persisted_event_schedule_loads_on_restart_and_evaluates() {
    let fixture = fixture("restart-event").await;
    let container =
        ServiceContainer::new(Arc::new(TriageRuntime), None).with_store(Arc::clone(&fixture.store));
    let schedules_path = fixture.root.path().join("schedules.json");

    let schedule_id = {
        let scheduler =
            CampaignScheduler::try_start(container.clone(), schedules_path.clone(), None)
                .await
                .expect("scheduler starts");
        let schedule = scheduler
            .try_create(
                "on-crash",
                &campaign_params(&fixture.project, &fixture.target.symbol),
                parse_trigger("event", EVENT_CRASH_FOUND).unwrap(),
            )
            .await
            .expect("event schedule created");
        let id = schedule.id.clone();
        assert!(matches!(
            schedule.trigger,
            hf_scheduler::TriggerConfig::Event { .. }
        ));
        scheduler.stop().await;
        id
    };

    // Restart: the persisted event schedule must load and keep evaluating.
    let scheduler = CampaignScheduler::try_start(container.clone(), schedules_path, None)
        .await
        .expect("scheduler restarts");
    let loaded = scheduler
        .list()
        .await
        .into_iter()
        .find(|s| s.id == schedule_id)
        .expect("event schedule survived the restart");
    assert!(matches!(
        loaded.trigger,
        hf_scheduler::TriggerConfig::Event { .. }
    ));

    let crashes = container
        .triage_run(&fixture.project, &fixture.target.symbol, fixture.run.id)
        .await
        .expect("triage completes after restart");
    assert_eq!(crashes.len(), 1);

    wait_for_execution(&scheduler, &schedule_id).await;
    scheduler.stop().await;
}

// ---------------------------------------------------------------------------
// Run termination events (run.completed / run.failed) through a real campaign
// ---------------------------------------------------------------------------

/// A runtime that writes files for real and reports smoke/fuzz success, and
/// can be switched to fail the fuzz engine command (for `run.failed`).
struct CampaignRuntime {
    fail_fuzz: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl RuntimeAdapter for CampaignRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _options: &SandboxOptions,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        // Once armed, every command fails: the first engine-stage command of
        // the fuzz run errors, terminating the started run with a failure.
        if self.fail_fuzz.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(hf_core::error::ClassifiedError::Sandbox(format!(
                "engine exploded in test: {cmd:?}"
            )));
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
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
            .map_err(|e| hf_core::error::ClassifiedError::Internal(e.to_string()))
    }

    async fn read_file(&self, path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// Returns a fenced C harness for every completion (used for draft/seed steps).
struct CodeBlockPool;

#[async_trait]
impl hf_core::provider::ProviderPool for CodeBlockPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
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

struct CampaignFixture {
    root: tempfile::TempDir,
    project: PathBuf,
    container: ServiceContainer,
    runtime: Arc<CampaignRuntime>,
}

/// A project with a promoted, smoke-qualified harness, ready for `run_campaign`
/// (the same pipeline shape as the campaign integration tests).
async fn campaign_fixture(name: &str) -> CampaignFixture {
    let root = tempfile::tempdir().unwrap();
    common::install_managed_workspace("hobot_fuzz_scheduler_events_tests");
    let project = root.path().join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("campaign.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CampaignRuntime {
        fail_fuzz: std::sync::atomic::AtomicBool::new(false),
    });
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::clone(&store));
    container
        .harness_generate(
            &project,
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        )
        .await
        .expect("prepare harness");
    // Pre-create the compiled harness binary the runner checks for (a real
    // build would produce it; the fake runtime does not).
    let workspace = hf_service::workspace_dir(&project, "parse_entry");
    std::fs::write(workspace.join("fuzz_parse_entry"), b"#!/bin/true").unwrap();
    container
        .harness_smoke(
            &project,
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(&project, "parse_entry", EngineKind::LibFuzzer)
        .await
        .expect("operator promotes harness");

    CampaignFixture {
        root,
        project,
        container,
        runtime,
    }
}

async fn start_scheduler_with_listeners(
    fixture: &CampaignFixture,
) -> (
    CampaignScheduler,
    hf_scheduler::Schedule,
    hf_scheduler::Schedule,
) {
    let scheduler = CampaignScheduler::try_start(
        fixture.container.clone(),
        fixture.root.path().join("schedules.json"),
        None,
    )
    .await
    .expect("scheduler starts");
    let params = campaign_params(&fixture.project, "parse_entry");
    let on_completed = scheduler
        .try_create(
            "on-run-completed",
            &params,
            parse_trigger("event", EVENT_RUN_COMPLETED).unwrap(),
        )
        .await
        .expect("run.completed schedule created");
    let on_failed = scheduler
        .try_create(
            "on-run-failed",
            &params,
            parse_trigger("event", EVENT_RUN_FAILED).unwrap(),
        )
        .await
        .expect("run.failed schedule created");
    (scheduler, on_completed, on_failed)
}

#[tokio::test]
async fn run_completed_fires_matching_event_schedule() {
    let fixture = campaign_fixture("run-completed-event").await;
    let (scheduler, on_completed, on_failed) = start_scheduler_with_listeners(&fixture).await;

    fixture
        .container
        .run_campaign(
            &fixture.project,
            Some("parse_entry"),
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            1,
        )
        .await
        .expect("campaign completes");

    wait_for_execution(&scheduler, &on_completed.id).await;
    scheduler.stop().await;

    let executions = scheduler.recent_executions(20).await.unwrap();
    assert_eq!(
        executions
            .iter()
            .filter(|e| e.schedule_id == on_completed.id)
            .count(),
        1,
        "run.completed must fire its listener exactly once: {executions:?}"
    );
    assert!(
        executions.iter().all(|e| e.schedule_id != on_failed.id),
        "a successful run must not fire run.failed listeners: {executions:?}"
    );
}

#[tokio::test]
async fn run_failed_fires_matching_event_schedule() {
    let fixture = campaign_fixture("run-failed-event").await;
    let (scheduler, on_completed, on_failed) = start_scheduler_with_listeners(&fixture).await;

    // The harness is promoted; now the engine itself starts failing.
    fixture
        .runtime
        .fail_fuzz
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let outcome = fixture
        .container
        .run_campaign(
            &fixture.project,
            Some("parse_entry"),
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            1,
        )
        .await;
    assert!(outcome.is_err(), "the campaign run must fail");

    wait_for_execution(&scheduler, &on_failed.id).await;
    scheduler.stop().await;

    let executions = scheduler.recent_executions(20).await.unwrap();
    assert_eq!(
        executions
            .iter()
            .filter(|e| e.schedule_id == on_failed.id)
            .count(),
        1,
        "run.failed must fire its listener exactly once: {executions:?}"
    );
    assert!(
        executions.iter().all(|e| e.schedule_id != on_completed.id),
        "a failed run must not fire run.completed listeners: {executions:?}"
    );
}
