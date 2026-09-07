//! Run Closeout persistence and resume.
//!
//! Step outcomes are durable, so a second pass does not redo terminal work.

#![cfg(feature = "run-closeout")]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::{CloseoutAvailability, CloseoutStep, ServiceContainer, StepOutcome};
use hf_storage::{RunKind, RunRecord, RunStatus, Store};
use uuid::Uuid;

async fn container() -> (ServiceContainer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("closeout.db"))
            .await
            .unwrap(),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    (container, dir)
}

async fn seeded_run(container: &ServiceContainer) -> Uuid {
    seeded_run_at(container, PathBuf::from("/proj")).await
}

async fn seeded_run_at(container: &ServiceContainer, project: PathBuf) -> Uuid {
    let store = container.store().unwrap().clone();
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.clone(),
        language: TargetLanguage::C,
        symbol: "parse_packet".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/parser.c"),
            line: 42,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("int parse_packet(const uint8_t*, size_t)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 9,
        fit_score: 0.91,
        sanitizers: vec![Sanitizer::Address],
        rationale: "untrusted packet parser".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();

    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, size_t n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::SmokePassed,
        smoke_run: None,
    };
    store.upsert_harness(&harness).await.unwrap();

    let mut run = RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: None,
            max_mem_mb: 512,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        }),
        Utc::now(),
    );
    run.status = RunStatus::Done;
    store.insert_run(&run).await.unwrap();
    run.id
}

#[derive(Default)]
struct CountingRuntime {
    calls: AtomicUsize,
}

struct BlockingRuntime {
    calls: AtomicUsize,
    entered: tokio::sync::Semaphore,
    release: tokio::sync::Semaphore,
}

impl BlockingRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
        })
    }
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for BlockingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.entered.add_permits(1);
            self.release.acquire().await.unwrap().forget();
        }
        Ok(hf_core::runtime::CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "controlled failure".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for CountingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(hf_core::runtime::CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "controlled failure".to_owned(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn a_closeout_records_every_step_and_the_second_pass_resumes() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    container
        .store()
        .unwrap()
        .record_closeout_step(run_id, "Triage", "completed", "0 crash(es) attributed")
        .await
        .unwrap();

    let first = container.close_out_run(run_id).await.unwrap();
    assert_eq!(
        first.steps.len(),
        hf_service::closeout_ladder().len(),
        "every step is accounted for, including the ones that were skipped"
    );
    assert_eq!(first.resumed_at, Some(CloseoutStep::Minimize));

    // A run with no crashes has nothing to minimize; that is an answer.
    let minimize = first
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::Minimize)
        .unwrap();
    assert!(
        matches!(minimize.outcome, StepOutcome::Skipped { .. }),
        "expected a skip with a reason, got {:?}",
        minimize.outcome
    );

    // Terminal outcomes are durable, so the second pass repeats none of them.
    let second = container.close_out_run(run_id).await.unwrap();
    for record in &second.steps {
        let before = first
            .steps
            .iter()
            .find(|item| item.step == record.step)
            .unwrap();
        if before.outcome.is_terminal() {
            assert_eq!(
                record.outcome, before.outcome,
                "{:?} reached a terminal outcome and must not be redone",
                record.step
            );
        }
    }
}

#[tokio::test]
async fn an_unknown_run_cannot_be_closed_out() {
    let (container, _dir) = container().await;

    assert!(container.close_out_run(Uuid::from_u128(404)).await.is_err());
}

#[tokio::test]
async fn step_outcomes_survive_a_new_container_over_the_same_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("closeout.db");

    let run_id = {
        let store = Arc::new(Store::connect(&path).await.unwrap());
        let container =
            ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
        let run_id = seeded_run(&container).await;
        container.close_out_run(run_id).await.unwrap();
        run_id
    };

    // A restart reads the recorded outcomes rather than starting over.
    let store = Arc::new(Store::connect(&path).await.unwrap());
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    let resumed = container.close_out_run(run_id).await.unwrap();

    assert_eq!(resumed.steps.len(), hf_service::closeout_ladder().len());
}

#[tokio::test]
async fn retained_closeout_reads_pending_state_without_executing() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;

    let retained = container.retained_run_closeout(run_id).await.unwrap();

    assert_eq!(retained.availability, CloseoutAvailability::Available);
    assert!(retained.steps.is_empty());
    assert_eq!(retained.resumed_at, None);
}

#[tokio::test]
async fn dependency_skip_from_schema_v1_is_read_as_retryable_blocked() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    container
        .store()
        .unwrap()
        .record_closeout_step(
            run_id,
            "Minimize",
            "skipped",
            "Triage failed, and this step reads its output",
        )
        .await
        .unwrap();

    let retained = container.retained_run_closeout(run_id).await.unwrap();

    assert!(matches!(
        retained.steps[0].outcome,
        StepOutcome::Blocked {
            dependency: CloseoutStep::Triage
        }
    ));
}

#[tokio::test]
async fn unknown_retained_outcome_fails_without_starting_closeout() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    container
        .store()
        .unwrap()
        .record_closeout_step(run_id, "Triage", "future_value", "opaque")
        .await
        .unwrap();

    let error = container.retained_run_closeout(run_id).await.unwrap_err();

    assert!(error
        .to_string()
        .contains("decode retained closeout outcome"));
}

#[tokio::test]
async fn unknown_retained_step_fails_without_starting_closeout() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    container
        .store()
        .unwrap()
        .record_closeout_step(run_id, "FutureStep", "completed", "opaque")
        .await
        .unwrap();

    let error = container.retained_run_closeout(run_id).await.unwrap_err();

    assert!(error.to_string().contains("decode retained closeout step"));
}

#[tokio::test]
async fn retained_blocked_dependency_must_be_valid_for_its_step() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    container
        .store()
        .unwrap()
        .record_closeout_step(run_id, "Blockers", "blocked", "Triage")
        .await
        .unwrap();

    let error = container.retained_run_closeout(run_id).await.unwrap_err();

    assert!(error
        .to_string()
        .contains("decode retained closeout outcome"));
}

#[tokio::test]
async fn closeout_rejects_active_smoke_and_missing_scope_runs() {
    let (container, _dir) = container().await;
    let store = container.store().unwrap().clone();

    let running_id = seeded_run(&container).await;
    sqlx::query("UPDATE runs SET status = 'Running' WHERE id = ?1")
        .bind(running_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(container.close_out_run(running_id).await.is_err());

    let smoke_id = seeded_run(&container).await;
    sqlx::query("UPDATE runs SET run_kind = 'Smoke' WHERE id = ?1")
        .bind(smoke_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(container.close_out_run(smoke_id).await.is_err());

    let mut no_scope = RunRecord::new("/proj", EngineKind::Syzkaller, None, Utc::now());
    no_scope.kind = RunKind::Campaign;
    no_scope.status = RunStatus::Done;
    store.insert_run(&no_scope).await.unwrap();

    let retained = container.retained_run_closeout(no_scope.id).await.unwrap();
    assert!(matches!(
        retained.availability,
        CloseoutAvailability::Unavailable { ref reason }
            if reason.contains("harness-backed target")
    ));
    assert!(container.close_out_run(no_scope.id).await.is_err());
}

#[tokio::test]
async fn a_second_closeout_owner_is_busy_and_retry_succeeds_after_release() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    let lock_dir = hf_service::init::user_app_dir().join("locks");
    std::fs::create_dir_all(&lock_dir).unwrap();
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_dir.join(format!("run-closeout-{run_id}.lock")))
        .unwrap();
    lease.try_lock().unwrap();

    let error = container.close_out_run(run_id).await.unwrap_err();
    assert!(error.to_string().contains("closeout is already active"));

    drop(lease);
    assert!(container.close_out_run(run_id).await.is_ok());
}

#[tokio::test]
async fn closeout_rejects_a_target_owned_by_another_project() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    let store = container.store().unwrap();
    let mut target = store.list_all_targets().await.unwrap().remove(0);
    target.project_root = PathBuf::from("/another-project");
    store.upsert_target(&target, Utc::now()).await.unwrap();

    let retained = container.retained_run_closeout(run_id).await.unwrap();
    assert!(matches!(
        retained.availability,
        CloseoutAvailability::Unavailable { ref reason }
            if reason.contains("target project does not match")
    ));
    assert!(container.close_out_run(run_id).await.is_err());
}

#[tokio::test]
async fn coverage_and_blocker_steps_do_not_read_the_current_workspace() {
    common::install_managed_workspace("oxfuzz_closeout_audit");
    let directory = tempfile::tempdir().unwrap();
    let project = std::fs::canonicalize(directory.path()).unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("audit.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CountingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let run_id = seeded_run_at(&container, project.clone()).await;
    for (step, outcome, detail) in [
        ("Triage", "completed", "done"),
        ("Minimize", "skipped", "nothing to minimize"),
        ("CorpusAbsorb", "completed", "done"),
        ("Disposition", "completed", "done"),
    ] {
        store
            .record_closeout_step(run_id, step, outcome, detail)
            .await
            .unwrap();
    }
    let workspace = hf_service::workspace_dir(&project, "parse_packet");
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(workspace.join("harness.c"), "int harness;").unwrap();

    let report = container.close_out_run(run_id).await.unwrap();

    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    for step in [CloseoutStep::Coverage, CloseoutStep::Blockers] {
        assert!(matches!(
            report.steps.iter().find(|record| record.step == step).unwrap().outcome,
            StepOutcome::Skipped { ref reason } if reason.contains("exact run-bound")
        ));
    }
}

#[tokio::test]
async fn retrying_upstream_work_replaces_a_stale_trust_result() {
    let (container, _dir) = container().await;
    let run_id = seeded_run(&container).await;
    let store = container.store().unwrap();
    store
        .record_closeout_step(run_id, "Triage", "failed", "old failure")
        .await
        .unwrap();
    store
        .record_closeout_step(run_id, "TrustReport", "completed", "stale trust")
        .await
        .unwrap();

    let report = container.close_out_run(run_id).await.unwrap();
    let trust = report
        .steps
        .iter()
        .find(|record| record.step == CloseoutStep::TrustReport)
        .unwrap();

    assert_ne!(
        trust.outcome,
        StepOutcome::Completed {
            detail: "stale trust".to_owned()
        }
    );
}

#[tokio::test]
async fn legacy_workspace_evidence_is_read_as_unavailable_and_refreshed_only_on_resume() {
    common::install_managed_workspace("oxfuzz_closeout_legacy_read");
    let directory = tempfile::tempdir().unwrap();
    let project = std::fs::canonicalize(directory.path()).unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("legacy.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(CountingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let run_id = seeded_run_at(&container, project).await;
    for (step, detail) in [
        ("Triage", "0 crash(es) attributed"),
        ("Minimize", "nothing to minimize"),
        ("CorpusAbsorb", "0 input(s) absorbed"),
        ("Coverage", "91.0% of lines covered"),
        ("Blockers", "0 blocker(s)"),
        ("Disposition", "0 crash(es) dispositioned"),
        ("TrustReport", "Trusted"),
    ] {
        store
            .record_closeout_step(run_id, step, "completed", detail)
            .await
            .unwrap();
    }

    let retained = container.retained_run_closeout(run_id).await.unwrap();
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
    for step in [CloseoutStep::Coverage, CloseoutStep::Blockers] {
        assert!(matches!(
            retained.steps.iter().find(|record| record.step == step).unwrap().outcome,
            StepOutcome::Skipped { ref reason } if reason.contains("exact run-bound")
        ));
    }
    assert!(matches!(
        retained
            .steps
            .iter()
            .find(|record| record.step == CloseoutStep::TrustReport)
            .unwrap()
            .outcome,
        StepOutcome::Blocked {
            dependency: CloseoutStep::Coverage
        }
    ));
    let durable = store.closeout_steps(run_id).await.unwrap();
    assert!(durable.iter().any(|(step, outcome, detail)| {
        step == "TrustReport" && outcome == "completed" && detail == "Trusted"
    }));

    let resumed = container.close_out_run(run_id).await.unwrap();
    assert_ne!(
        resumed
            .steps
            .iter()
            .find(|record| record.step == CloseoutStep::TrustReport)
            .unwrap()
            .outcome,
        StepOutcome::Completed {
            detail: "Trusted".to_owned()
        }
    );
}

#[tokio::test]
async fn overlapping_closeout_executors_admit_only_one_owner() {
    common::install_managed_workspace("oxfuzz_closeout_concurrent");
    let directory = tempfile::tempdir().unwrap();
    let project = std::fs::canonicalize(directory.path()).unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("concurrent.db"))
            .await
            .unwrap(),
    );
    let runtime = BlockingRuntime::new();
    let first_container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let second_container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let run_id = seeded_run_at(&first_container, project.clone()).await;
    let workspace = hf_service::workspace_dir(&project, "parse_packet");
    std::fs::create_dir_all(workspace.join("out")).unwrap();
    std::fs::write(workspace.join("fuzz_parse_packet"), b"controlled binary").unwrap();
    std::fs::write(workspace.join("out/crash-input"), b"crash").unwrap();

    let first = tokio::spawn(async move { first_container.close_out_run(run_id).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), runtime.entered.acquire())
        .await
        .expect("first closeout did not enter the controlled runtime")
        .unwrap()
        .forget();

    let duplicate = second_container.close_out_run(run_id).await.unwrap_err();
    assert!(duplicate.to_string().contains("closeout is already active"));

    runtime.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(2), first)
        .await
        .expect("first closeout did not finish after runtime release")
        .unwrap()
        .unwrap();
    assert!(second_container.close_out_run(run_id).await.is_ok());
}

#[tokio::test]
async fn cancelling_a_closeout_releases_its_lease() {
    common::install_managed_workspace("oxfuzz_closeout_cancelled");
    let directory = tempfile::tempdir().unwrap();
    let project = std::fs::canonicalize(directory.path()).unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("cancelled.db"))
            .await
            .unwrap(),
    );
    let runtime = BlockingRuntime::new();
    let first_container = ServiceContainer::new(runtime.clone(), None).with_store(store.clone());
    let second_container = ServiceContainer::new(runtime.clone(), None).with_store(store);
    let run_id = seeded_run_at(&first_container, project.clone()).await;
    let workspace = hf_service::workspace_dir(&project, "parse_packet");
    std::fs::create_dir_all(workspace.join("out")).unwrap();
    std::fs::write(workspace.join("fuzz_parse_packet"), b"controlled binary").unwrap();
    std::fs::write(workspace.join("out/crash-input"), b"crash").unwrap();

    let first = tokio::spawn(async move { first_container.close_out_run(run_id).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), runtime.entered.acquire())
        .await
        .expect("first closeout did not enter the controlled runtime")
        .unwrap()
        .forget();
    first.abort();
    let cancelled = first.await.unwrap_err();
    assert!(cancelled.is_cancelled());

    runtime.release.add_permits(1);
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        second_container.close_out_run(run_id),
    )
    .await
    .expect("retry remained blocked after cancellation")
    .unwrap();
}
