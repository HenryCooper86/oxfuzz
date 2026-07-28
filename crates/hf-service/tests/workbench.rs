//! Tests for internal-team workbench service summaries.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus, SmokeRunSummary};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::ServiceContainer;
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

async fn test_container() -> (ServiceContainer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("workbench.db"))
            .await
            .unwrap(),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    (container, dir)
}

fn sample_target(project: &str) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from(project),
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
    }
}

fn sample_harness(target_id: Uuid) -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec!["-fsanitize=fuzzer,address".to_owned()],
            output: PathBuf::from("fuzz_parse_packet"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Compiled,
        smoke_run: None,
    }
}

fn sample_run(project: &str, harness_id: Uuid) -> RunRecord {
    let mut run = RunRecord::new(
        project,
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id,
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
    run.context_rev = Some("test-comparison-context".to_owned());
    run
}

#[tokio::test]
async fn dashboard_summarizes_targets_harnesses_runs_and_crashes() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();
    let target = sample_target("/proj");
    let harness = sample_harness(target.id);
    let run = sample_run("/proj", harness.id);
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target.id,
        input_path: PathBuf::from("out/crash-1"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
    };

    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();
    store.upsert_crash(&crash).await.unwrap();

    let project = PathBuf::from("/proj");
    let dashboard = container
        .workbench_dashboard(Some(project.as_path()), Some("parse_packet"))
        .await
        .unwrap();

    assert_eq!(dashboard.totals.targets, 1);
    assert_eq!(dashboard.totals.harnesses, 1);
    assert_eq!(dashboard.totals.harnesses_needing_review, 1);
    assert_eq!(dashboard.totals.runs, 1);
    assert_eq!(dashboard.totals.crashes, 1);
    assert_eq!(dashboard.top_targets[0].symbol, "parse_packet");
    assert_eq!(dashboard.harness_reviews[0].next_action, "Run smoke fuzz");
    assert_eq!(dashboard.crash_reviews[0].kind, "Asan");
}

#[tokio::test]
async fn dashboard_target_filter_scopes_runs_through_harness_config() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();
    let first_target = sample_target("/proj");
    let mut second_target = sample_target("/proj");
    second_target.id = Uuid::new_v4();
    second_target.symbol = "parse_header".to_owned();

    let first_harness = sample_harness(first_target.id);
    let second_harness = sample_harness(second_target.id);
    let first_run = sample_run("/proj", first_harness.id);
    let second_run = sample_run("/proj", second_harness.id);

    store
        .upsert_target(&first_target, Utc::now())
        .await
        .unwrap();
    store
        .upsert_target(&second_target, Utc::now())
        .await
        .unwrap();
    store.upsert_harness(&first_harness).await.unwrap();
    store.upsert_harness(&second_harness).await.unwrap();
    store.insert_run(&first_run).await.unwrap();
    store.insert_run(&second_run).await.unwrap();

    let project = PathBuf::from("/proj");
    let dashboard = container
        .workbench_dashboard(Some(project.as_path()), Some("parse_packet"))
        .await
        .unwrap();

    assert_eq!(dashboard.totals.targets, 1);
    assert_eq!(dashboard.totals.runs, 1);
    assert_eq!(dashboard.recent_runs[0].id, first_run.id.to_string());
}

#[tokio::test]
async fn run_history_exposes_service_owned_comparison_groups() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();
    let target = sample_target("/proj");
    let first_harness = sample_harness(target.id);
    let mut second_harness = sample_harness(target.id);
    second_harness.source = "second revision".to_owned();
    let mut first_run = sample_run("/proj", first_harness.id);
    first_run.status = RunStatus::Done;
    let mut second_run = sample_run("/proj", second_harness.id);
    second_run.status = RunStatus::Done;

    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&first_harness).await.unwrap();
    store.upsert_harness(&second_harness).await.unwrap();
    store.insert_run(&first_run).await.unwrap();
    store.insert_run(&second_run).await.unwrap();

    let history = container
        .run_history(Some(Path::new("/proj")))
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert!(history
        .iter()
        .all(|run| run.target.as_deref() == Some("parse_packet")));
    assert!(history.iter().all(|run| run.comparison_key.is_some()));
    assert_eq!(history[0].comparison_key, history[1].comparison_key);
}

#[tokio::test]
async fn dashboard_project_filter_does_not_leak_other_project_reviews() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();
    let target = sample_target("/other");
    let run = RunRecord::new("/other", EngineKind::LibFuzzer, None, Utc::now());
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target.id,
        input_path: PathBuf::from("out/crash-other"),
        stack_signature: "other".to_owned(),
        kind: CrashKind::Asan,
        summary: "other project crash".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };

    store.upsert_target(&target, Utc::now()).await.unwrap();
    store
        .upsert_harness(&sample_harness(target.id))
        .await
        .unwrap();
    store.insert_run(&run).await.unwrap();
    store.upsert_crash(&crash).await.unwrap();

    let project = PathBuf::from("/proj");
    let dashboard = container
        .workbench_dashboard(Some(project.as_path()), None)
        .await
        .unwrap();

    assert_eq!(dashboard.totals.targets, 0);
    assert_eq!(dashboard.totals.harnesses, 0);
    assert_eq!(dashboard.totals.crashes, 0);
    assert!(dashboard.harness_reviews.is_empty());
    assert!(dashboard.crash_reviews.is_empty());
}

#[tokio::test]
async fn dashboard_readiness_tracks_operational_state() {
    let (container, _dir) = test_container().await;
    let project = PathBuf::from("/proj");

    let empty = container
        .workbench_dashboard(Some(project.as_path()), None)
        .await
        .unwrap();

    assert_eq!(empty.readiness.state, "setup_required");
    assert!(empty.readiness.score < 50);
    assert!(empty
        .readiness
        .blockers
        .iter()
        .any(|blocker| blocker.contains("targets")));

    let store = container.store().unwrap();
    let target = sample_target("/proj");
    let mut harness = sample_harness(target.id);
    harness.status = HarnessStatus::Promoted;
    harness.smoke_run = Some(SmokeRunSummary {
        duration_secs: 60,
        execs_per_sec: 1_250.0,
        crashes: 0,
        passed: true,
        source_sha256: None,
        binary_sha256: None,
        run_id: None,
    });
    let mut run = sample_run("/proj", harness.id);
    run.status = RunStatus::Done;
    run.ended_at = Some(Utc::now());

    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();
    store.insert_run(&run).await.unwrap();

    let ready = container
        .workbench_dashboard(Some(project.as_path()), None)
        .await
        .unwrap();

    assert_eq!(ready.readiness.state, "ready");
    assert!(ready.readiness.score >= 80);
    assert!(ready.readiness.blockers.is_empty());
}

#[tokio::test]
async fn issue_export_returns_reviewable_payload() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();
    let target = sample_target("/proj");
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target.id,
        input_path: PathBuf::from("out/crash-2"),
        stack_signature: "stack".to_owned(),
        kind: CrashKind::Segv,
        summary: "segmentation fault".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };

    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.insert_run(&run).await.unwrap();
    store.upsert_crash(&crash).await.unwrap();

    let project = PathBuf::from("/proj");
    let export = container
        .issue_export(project.as_path(), &crash.id.to_string())
        .await
        .unwrap();

    assert!(export.title.contains("parse_packet"));
    assert!(export.description.contains("segmentation fault"));
    assert!(export.labels.contains(&"oxfuzz".to_owned()));
    // The payload is provider-tagged (the provider-specific URL building is
    // unit-tested hermetically in issue_tracker.rs).
    assert!(
        export.provider == "gitlab" || export.provider == "github",
        "unexpected provider: {}",
        export.provider
    );
}

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_workbench_it");
}

#[tokio::test]
async fn delete_project_removes_db_records_and_workspace_and_isolates_others() {
    isolate_workspace();
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();

    // Seed two projects in the store, each with a target + harness + run.
    for root in ["/gone", "/kept"] {
        let mut target = sample_target(root);
        target.id = Uuid::new_v4();
        target.project_root = PathBuf::from(root);
        let harness = sample_harness(target.id);
        let run = sample_run(root, harness.id);
        store.upsert_target(&target, Utc::now()).await.unwrap();
        store.upsert_harness(&harness).await.unwrap();
        store.insert_run(&run).await.unwrap();
    }

    // Give each project an on-disk workspace directory.
    let gone_dir = hf_service::project_workspace_dir(Path::new("/gone"));
    let kept_dir = hf_service::project_workspace_dir(Path::new("/kept"));
    std::fs::create_dir_all(&gone_dir).unwrap();
    std::fs::create_dir_all(&kept_dir).unwrap();
    std::fs::write(gone_dir.join("marker"), b"x").unwrap();

    container.delete_project(Path::new("/gone")).await.unwrap();

    // DB rows for the deleted project are gone; the kept project is intact.
    assert!(store.list_targets("/gone").await.unwrap().is_empty());
    assert!(store.list_runs(Some("/gone")).await.unwrap().is_empty());
    assert_eq!(store.list_targets("/kept").await.unwrap().len(), 1);
    // No orphaned harnesses linger (only the kept project's harness remains).
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);

    // On-disk workspace for the deleted project is removed; the other survives.
    assert!(!gone_dir.exists());
    assert!(kept_dir.exists());
}

#[tokio::test]
async fn dashboard_without_active_project_is_empty_not_global_aggregate() {
    let (container, _dir) = test_container().await;
    let store = container.store().unwrap();

    // Persist work under a real project.
    let target = sample_target("/proj");
    let harness = sample_harness(target.id);
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.upsert_harness(&harness).await.unwrap();

    // With no project selected the workbench shows nothing (not a whole-DB roll-up).
    let dashboard = container.workbench_dashboard(None, None).await.unwrap();
    assert_eq!(dashboard.totals.targets, 0);
    assert_eq!(dashboard.totals.harnesses, 0);
    assert!(dashboard.top_targets.is_empty());
    assert!(dashboard.harness_reviews.is_empty());
    assert!(dashboard.active_project.is_none());

    // Selecting the project surfaces its data.
    let scoped = container
        .workbench_dashboard(Some(Path::new("/proj")), None)
        .await
        .unwrap();
    assert_eq!(scoped.totals.targets, 1);
    assert_eq!(scoped.totals.harnesses, 1);
}
