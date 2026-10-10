//! Run lifecycle read/control operations backing the CLI `runs` commands:
//! id resolution (full UUID or unambiguous prefix) and the single-run detail
//! view. Uses a real SQLite store; no Docker, no live engines.

use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_service::{RunCancelOutcome, RunLifecycleStatus, ServiceContainer};
use hf_storage::{RunRecord, RunStatus, Store};
use uuid::Uuid;

fn stored_run(project: &str, engine: EngineKind, status: RunStatus, id: Uuid) -> RunRecord {
    let mut run = RunRecord::new(project, engine, None, Utc::now());
    run.id = id;
    run.status = status;
    if matches!(
        status,
        RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
    ) {
        run.ended_at = Some(Utc::now());
    }
    run
}

async fn store_with_runs(runs: &[RunRecord]) -> (tempfile::TempDir, Arc<Store>) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("runs.db"))
            .await
            .unwrap(),
    );
    for run in runs {
        store.insert_run(run).await.unwrap();
    }
    (directory, store)
}

#[tokio::test]
async fn resolve_run_id_accepts_a_full_uuid_and_an_unambiguous_prefix() {
    let id = Uuid::parse_str("aaaaaaaa-1111-2222-3333-444444444444").unwrap();
    let other = Uuid::parse_str("bbbbbbbb-1111-2222-3333-444444444444").unwrap();
    let (_dir, store) = store_with_runs(&[
        stored_run("/p", EngineKind::LibFuzzer, RunStatus::Done, id),
        stored_run("/p", EngineKind::AflPlusPlus, RunStatus::Done, other),
    ])
    .await;
    let container = ServiceContainer::stubbed().with_store(store);

    assert_eq!(container.resolve_run_id(&id.to_string()).await.unwrap(), id);
    assert_eq!(container.resolve_run_id("aaaaaaaa-1").await.unwrap(), id);
    assert_eq!(container.resolve_run_id("bbbbbbbb").await.unwrap(), other);
}

#[tokio::test]
async fn resolve_run_id_rejects_unknown_ambiguous_and_empty_ids() {
    let first = Uuid::parse_str("aaaaaaaa-1111-2222-3333-444444444444").unwrap();
    let second = Uuid::parse_str("aaaaaaaa-9999-2222-3333-444444444444").unwrap();
    let (_dir, store) = store_with_runs(&[
        stored_run("/p", EngineKind::LibFuzzer, RunStatus::Done, first),
        stored_run("/p", EngineKind::Honggfuzz, RunStatus::Running, second),
    ])
    .await;
    let container = ServiceContainer::stubbed().with_store(store);

    let unknown = Uuid::new_v4();
    let error = container
        .resolve_run_id(&unknown.to_string())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("not found"),
        "unexpected error: {error}"
    );

    let error = container.resolve_run_id("cccccccc").await.unwrap_err();
    assert!(
        error.to_string().contains("no run id matches"),
        "unexpected error: {error}"
    );

    let error = container.resolve_run_id("aaaaaaaa").await.unwrap_err();
    let message = error.to_string();
    assert!(message.contains("ambiguous"), "unexpected error: {message}");
    assert!(
        message.contains('2'),
        "ambiguity must name the match count: {message}"
    );

    let error = container.resolve_run_id("   ").await.unwrap_err();
    assert!(
        error.to_string().contains("must not be empty"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn resolve_run_id_requires_the_persistent_store() {
    let container = ServiceContainer::stubbed();
    let error = container
        .resolve_run_id(&Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("persistent store"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn run_detail_reports_terminal_metrics_without_live_telemetry() {
    let id = Uuid::new_v4();
    let (_dir, store) =
        store_with_runs(&[stored_run("/p", EngineKind::LibFuzzer, RunStatus::Done, id)]).await;
    store.set_run_stats(id, 1523, 842.5, 3).await.unwrap();
    let container = ServiceContainer::stubbed().with_store(store);

    let detail = container.run_detail(&id.to_string()).await.unwrap();

    assert_eq!(detail.run.id, id.to_string());
    assert_eq!(detail.run.engine, "LibFuzzer");
    assert_eq!(detail.run.status, "Done");
    assert_eq!(detail.run.crashes, 3);
    assert_eq!(detail.run.edges, Some(1523));
    assert_eq!(detail.run.execs, Some(842.5));
    assert!(detail.run.duration_secs.is_some());
    assert!(
        !detail.active_in_this_process,
        "a finished run is never active"
    );
    assert!(detail.telemetry.is_none());
}

#[tokio::test]
async fn run_detail_surfaces_the_latest_retained_telemetry_snapshot() {
    let id = Uuid::new_v4();
    let (_dir, store) = store_with_runs(&[stored_run(
        "/p",
        EngineKind::AflPlusPlus,
        RunStatus::Running,
        id,
    )])
    .await;
    let observed_at = Utc::now();
    store
        .upsert_run_telemetry(&hf_storage::RunTelemetryRecord {
            run_id: id,
            observed_at,
            last_progress_at: Some(observed_at),
            samples_json: "[]".to_owned(),
            current_execs: Some(1200.0),
            mean_execs: Some(1000.0),
            peak_execs: Some(1300.0),
            edges: Some(777),
            throughput_sample_count: 4,
            throughput_sample_sum: 4000.0,
            managed_invocations_expected: 1,
            managed_invocations_alive: 1,
            free_disk_bytes: Some(1_048_576),
        })
        .await
        .unwrap();
    let container = ServiceContainer::stubbed().with_store(store);

    let detail = container.run_detail("detail-prefix-unused").await.err();
    assert!(detail.is_some(), "a non-matching id must fail");

    let detail = container.run_detail(&id.to_string()).await.unwrap();
    let telemetry = detail.telemetry.expect("retained telemetry snapshot");
    assert_eq!(telemetry.edges, Some(777));
    assert_eq!(telemetry.current_execs, Some(1200.0));
    assert_eq!(telemetry.mean_execs, Some(1000.0));
    assert_eq!(telemetry.peak_execs, Some(1300.0));
    assert_eq!(telemetry.free_disk_bytes, Some(1_048_576));
    assert_eq!(telemetry.observed_at, observed_at.to_rfc3339());
    assert!(
        !detail.active_in_this_process,
        "the token registry of a fresh container is empty: the run is owned elsewhere"
    );
}

#[tokio::test]
async fn run_detail_rejects_an_unknown_run() {
    let (_dir, store) = store_with_runs(&[]).await;
    let container = ServiceContainer::stubbed().with_store(store);
    let error = container
        .run_detail(&Uuid::new_v4().to_string())
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("not found"),
        "unexpected error: {error}"
    );
}

/// Pin the cross-process contract the CLI `runs stop` rendering relies on: a
/// durable `Running` row whose cancellation token lives in another process
/// reads as `active = false`, and a cancel request against it reports
/// `Inactive` rather than pretending to signal anything.
#[tokio::test]
async fn a_running_run_owned_by_another_process_is_inactive_for_cancel() {
    let id = Uuid::new_v4();
    let (_dir, store) = store_with_runs(&[stored_run(
        "/p",
        EngineKind::LibFuzzer,
        RunStatus::Running,
        id,
    )])
    .await;
    let container = ServiceContainer::stubbed().with_store(store);

    let status = container
        .run_control_status(id)
        .await
        .unwrap()
        .expect("durable run");
    assert_eq!(status.status, RunLifecycleStatus::Running);
    assert!(!status.active);

    assert_eq!(
        container.request_run_cancel(id).await.unwrap(),
        RunCancelOutcome::Inactive
    );
}
