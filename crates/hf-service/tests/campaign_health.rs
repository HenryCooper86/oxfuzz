//! Campaign Health domain contract.
//!
//! A stall is a coverage question. A fuzzer executing millions of inputs per
//! second against a harness that rejects all of them can sustain positive
//! throughput while learning nothing.

#![cfg(feature = "campaign-health")]

use std::collections::HashSet;

use chrono::SubsecRound;
use hf_service::campaign_health::{
    assess_campaign_health, undelivered, CampaignHealthInput, CampaignHealthSettings,
    HealthCondition, PlateauCheck, RunTelemetryRegistry,
};
use hf_service::{CoverageSample, FuzzProgress};
use hf_storage::RunStatus;
use std::sync::Arc;
use uuid::Uuid;

fn retained_event(
    run_id: Uuid,
    condition: &str,
    key: String,
    observed_at: chrono::DateTime<chrono::Utc>,
) -> hf_storage::CampaignHealthEventRecord {
    let evidence = hf_storage::CampaignHealthEvidenceRecord {
        schema_version: 2,
        run_id,
        condition: condition.to_owned(),
        observed_at,
        run_status: RunStatus::Running,
        plateau_window: 3,
        stale_progress_secs: 180,
        disk_floor_bytes: 3 * 1024 * 1024 * 1024,
        coverage_samples: Vec::new(),
        last_progress_at: None,
        progress_stale_secs: None,
        current_execs: None,
        mean_execs: None,
        peak_execs: None,
        throughput_sample_count: 0,
        throughput_sample_sum: 0.0,
        managed_invocations_expected: 0,
        managed_invocations_alive: 0,
        free_disk_bytes: None,
    };
    hf_storage::CampaignHealthEventRecord {
        schema_version: 2,
        id: Uuid::new_v4(),
        run_id,
        dedup_key: key,
        condition: condition.to_owned(),
        severity: "warning".to_owned(),
        detail: "retained condition".to_owned(),
        evidence_json: serde_json::to_string(&evidence).unwrap(),
        observed_at,
    }
}

fn settings() -> CampaignHealthSettings {
    CampaignHealthSettings {
        plateau_window: 3,
        stale_progress_secs: 180,
        disk_floor_bytes: 3 * 1024 * 1024 * 1024,
        assessment_interval_secs: 30,
        max_live_samples: 120,
        event_retention_days: 30,
        morning_summary_lookback_hours: 24,
    }
}

/// A series whose edge count follows `edges`, with execution always moving.
fn series(edges: &[u64]) -> Vec<CoverageSample> {
    edges
        .iter()
        .enumerate()
        .map(|(index, count)| CoverageSample {
            t: index as f64 * 10.0,
            edges: *count,
            execs: 50_000.0,
        })
        .collect()
}

#[test]
fn steady_positive_throughput_with_flat_edges_is_a_plateau() {
    let mut input = healthy();
    input.coverage_series = series(&[7, 7, 7, 7]);

    let report = assess_campaign_health(&input, &settings());

    assert!(report
        .events
        .iter()
        .any(|event| event.condition == HealthCondition::CoveragePlateau));
}

#[test]
fn exactly_the_configured_number_of_samples_is_evaluable() {
    let mut input = healthy();
    input.coverage_series = series(&[7, 7, 7]);

    let report = assess_campaign_health(&input, &settings());

    assert_eq!(report.plateau_check, PlateauCheck::Evaluated { window: 3 });
    assert!(report
        .events
        .iter()
        .any(|event| event.condition == HealthCondition::CoveragePlateau));
}

fn healthy() -> CampaignHealthInput {
    CampaignHealthInput {
        run_id: Uuid::from_u128(1),
        observed_at: chrono::DateTime::parse_from_rfc3339("2026-09-07T00:10:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        run_status: RunStatus::Running,
        coverage_series: series(&[10, 20, 30, 40]),
        current_execs: Some(50_000.0),
        mean_execs: Some(50_000.0),
        peak_execs: Some(50_000.0),
        throughput_sample_count: 4,
        throughput_sample_sum: 200_000.0,
        managed_invocations_expected: 1,
        managed_invocations_alive: 1,
        last_progress_at: None,
        progress_stale_secs: Some(5),
        free_disk_bytes: Some(50 * 1024 * 1024 * 1024),
    }
}

fn conditions(input: &CampaignHealthInput) -> Vec<HealthCondition> {
    assess_campaign_health(input, &settings())
        .events
        .into_iter()
        .map(|event| event.condition)
        .collect()
}

#[test]
fn a_growing_campaign_reports_nothing() {
    assert!(
        conditions(&healthy()).is_empty(),
        "health is queryable; only conditions are emitted"
    );
}

#[test]
fn postprocessing_without_an_active_invocation_is_not_worker_staleness() {
    let mut input = healthy();
    input.managed_invocations_expected = 0;
    input.managed_invocations_alive = 0;
    input.progress_stale_secs = Some(settings().stale_progress_secs + 1);

    assert!(!conditions(&input).contains(&HealthCondition::WorkerStatsStale));
}

#[test]
fn flat_coverage_under_continued_execution_is_a_plateau() {
    let mut input = healthy();
    input.coverage_series = series(&[100, 100, 100, 100]);

    assert!(conditions(&input).contains(&HealthCondition::CoveragePlateau));
}

#[test]
fn varying_positive_throughput_does_not_rescue_a_plateau() {
    // Throughput changes do not establish learning when coverage stays flat.
    let mut input = healthy();
    input.coverage_series = vec![
        CoverageSample {
            t: 0.0,
            edges: 100,
            execs: 10_000.0,
        },
        CoverageSample {
            t: 10.0,
            edges: 100,
            execs: 40_000.0,
        },
        CoverageSample {
            t: 20.0,
            edges: 100,
            execs: 90_000.0,
        },
        CoverageSample {
            t: 30.0,
            edges: 100,
            execs: 150_000.0,
        },
    ];

    assert!(conditions(&input).contains(&HealthCondition::CoveragePlateau));
}

#[test]
fn a_stopped_fuzzer_is_not_a_plateau() {
    // Flat coverage and flat execution means stopped, not stalled; the worker
    // conditions name that, and reporting both would be two names for one fact.
    let mut input = healthy();
    input.coverage_series = vec![
        CoverageSample {
            t: 0.0,
            edges: 100,
            execs: 0.0,
        },
        CoverageSample {
            t: 10.0,
            edges: 100,
            execs: 0.0,
        },
        CoverageSample {
            t: 20.0,
            edges: 100,
            execs: 0.0,
        },
        CoverageSample {
            t: 30.0,
            edges: 100,
            execs: 0.0,
        },
    ];

    assert!(!conditions(&input).contains(&HealthCondition::CoveragePlateau));
}

#[test]
fn coverage_flat_for_less_than_the_window_is_not_yet_a_plateau() {
    let mut input = healthy();
    input.coverage_series = series(&[10, 20, 20]);

    assert!(!conditions(&input).contains(&HealthCondition::CoveragePlateau));
}

#[test]
fn with_no_retained_series_the_plateau_check_is_unavailable_not_negative() {
    let mut input = healthy();
    input.coverage_series = Vec::new();

    let report = assess_campaign_health(&input, &settings());

    assert!(matches!(
        report.plateau_check,
        PlateauCheck::Unavailable { .. }
    ));
    assert!(!conditions(&input).contains(&HealthCondition::CoveragePlateau));
}

#[test]
fn explicit_missing_managed_invocation_is_a_condition() {
    let mut input = healthy();
    input.managed_invocations_alive = 0;

    assert!(conditions(&input).contains(&HealthCondition::ManagedInvocationMissing));
}

#[test]
fn stale_progress_is_only_a_condition_while_the_run_is_active() {
    let mut input = healthy();
    input.progress_stale_secs = Some(600);
    assert!(conditions(&input).contains(&HealthCondition::WorkerStatsStale));

    input.run_status = RunStatus::Done;
    assert!(
        !conditions(&input).contains(&HealthCondition::WorkerStatsStale),
        "a finished run's progress is supposed to stop moving"
    );
}

#[test]
fn free_space_below_the_configured_floor_is_a_condition() {
    let mut input = healthy();
    input.free_disk_bytes = Some(1024 * 1024 * 1024);

    assert!(conditions(&input).contains(&HealthCondition::DiskPressure));
}

#[test]
fn a_failed_run_is_a_condition() {
    let mut input = healthy();
    input.run_status = RunStatus::Failed;

    assert!(conditions(&input).contains(&HealthCondition::RunFailed));
}

#[test]
fn the_same_condition_for_identical_state_is_delivered_once() {
    let mut input = healthy();
    input.managed_invocations_alive = 0;

    let first = assess_campaign_health(&input, &settings()).events;
    let mut emitted: HashSet<String> = first.iter().map(|event| event.dedup_key.clone()).collect();
    assert_eq!(first.len(), 1);

    let second = assess_campaign_health(&input, &settings()).events;
    assert!(
        undelivered(&second, &emitted).is_empty(),
        "an unchanged condition must not alert twice"
    );

    // Worsening state carries a different key, so it is delivered again.
    input.managed_invocations_expected = 2;
    let third = assess_campaign_health(&input, &settings()).events;
    let fresh = undelivered(&third, &emitted);
    assert_eq!(
        fresh.len(),
        1,
        "a condition that worsens is worth saying again"
    );

    emitted.extend(fresh.iter().map(|event| event.dedup_key.clone()));
    let fourth = assess_campaign_health(&input, &settings()).events;
    assert!(undelivered(&fourth, &emitted).is_empty());
}

#[test]
fn a_dedup_key_is_scoped_to_its_run() {
    let mut a = healthy();
    a.managed_invocations_alive = 0;
    let mut b = healthy();
    b.run_id = Uuid::from_u128(2);
    b.managed_invocations_alive = 0;

    let key_a = assess_campaign_health(&a, &settings()).events[0]
        .dedup_key
        .clone();
    let key_b = assess_campaign_health(&b, &settings()).events[0]
        .dedup_key
        .clone();

    assert_ne!(
        key_a, key_b,
        "one run's condition must not silence another's"
    );
}

#[test]
fn every_condition_carries_a_dedup_key_and_a_sentence() {
    let mut input = healthy();
    input.run_status = RunStatus::Failed;
    input.managed_invocations_alive = 0;
    input.progress_stale_secs = Some(9_000);
    input.free_disk_bytes = Some(1);
    input.coverage_series = series(&[7, 7, 7, 7]);

    let report = assess_campaign_health(&input, &settings());

    assert!(report.events.len() >= 4);
    for event in &report.events {
        assert!(!event.dedup_key.trim().is_empty());
        assert!(!event.detail.trim().is_empty());
        assert_eq!(event.run_id, input.run_id);
        assert_eq!(event.schema_version, 2);
        assert_eq!(event.observed_at, input.observed_at);
        assert_eq!(event.evidence.run_id, input.run_id);
        assert_eq!(event.evidence.condition, event.condition.to_string());
    }
}

/// Thresholds are validated configuration, so an operator edit that would make
/// the plateau check meaningless fails closed instead of quietly reverting.
#[test]
fn threshold_validation_rejects_a_window_that_would_call_everything_a_plateau() {
    use hf_service::config::CampaignHealthSettings as Settings;

    let default = Settings::default();
    assert!(default.plateau_window >= 2);

    for (window, why) in [(0usize, "zero"), (1usize, "one")] {
        let toml = format!("[campaign_health]\nplateau_window = {window}\n");
        assert!(
            hf_service::config::parse_campaign_health_settings(&toml).is_err(),
            "a plateau window of {why} must be rejected: a single sample is \
             trivially equal to itself"
        );
    }

    let ok = hf_service::config::parse_campaign_health_settings(
        "[campaign_health]\nplateau_window = 5\n",
    )
    .expect("a window of five is valid");
    assert_eq!(ok.plateau_window, 5);
}

#[test]
fn monitoring_retention_and_summary_settings_are_explicit_and_validated() {
    use hf_service::config::CampaignHealthSettings as Settings;

    let defaults = Settings::default();
    assert!(defaults.assessment_interval_secs > 0);
    assert!(defaults.max_live_samples >= 2);
    assert!(defaults.event_retention_days > 0);
    assert!(defaults.morning_summary_lookback_hours > 0);

    for (field, value) in [
        ("assessment_interval_secs", 0_u64),
        ("max_live_samples", 1),
        ("event_retention_days", 0),
        ("morning_summary_lookback_hours", 0),
    ] {
        let raw = format!("[campaign_health]\n{field} = {value}\n");
        assert!(
            hf_service::config::parse_campaign_health_settings(&raw).is_err(),
            "campaign_health.{field}={value} must be rejected"
        );
    }

    assert!(hf_service::config::parse_campaign_health_settings(
        "[campaign_health]\nplateau_window = 5\nmax_live_samples = 4\n"
    )
    .is_err());
    assert!(hf_service::config::parse_campaign_health_settings(
        "[campaign_health]\nplateau_window = 257\nmax_live_samples = 257\n"
    )
    .is_err());
    assert!(hf_service::config::parse_campaign_health_settings(
        "[campaign_health]\nplateau_window = 256\nmax_live_samples = 256\n"
    )
    .is_ok());
    assert!(hf_service::config::parse_campaign_health_settings(
        "[campaign_health]\nevent_retention_days = 9223372036854775807\n"
    )
    .is_err());
    assert!(hf_service::config::parse_campaign_health_settings(
        "[campaign_health]\nmorning_summary_lookback_hours = 9223372036854775807\n"
    )
    .is_err());
}

#[test]
fn live_registry_retains_a_bounded_series_and_whole_run_sample_mean() {
    let run_id = Uuid::from_u128(30);
    let registry = RunTelemetryRegistry::new(2);
    let start = chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert!(registry.prepare(run_id));

    for (offset, edges, execs) in [(1, 10, 100.0), (2, 20, 25.0), (3, 30, 75.0)] {
        let observed_at = start + chrono::Duration::seconds(offset);
        registry.observe_progress(run_id, &FuzzProgress::EdgesCovered(edges), observed_at);
        registry.observe_progress(run_id, &FuzzProgress::ExecsPerSec(execs), observed_at);
    }

    let snapshot = registry.snapshot(run_id).expect("prepared run");
    assert_eq!(
        snapshot
            .coverage_series
            .iter()
            .map(|sample| (sample.edges, sample.execs))
            .collect::<Vec<_>>(),
        [(20, 25.0), (30, 75.0)]
    );
    assert_eq!(snapshot.current_execs, Some(75.0));
    assert_eq!(snapshot.mean_execs, Some(200.0 / 3.0));
    assert_eq!(snapshot.peak_execs, Some(100.0));
    assert_eq!(snapshot.throughput_sample_count, 3);
    assert!((snapshot.throughput_sample_sum - 200.0).abs() < f64::EPSILON);
    assert_eq!(snapshot.edges, Some(30));
    assert_eq!(
        snapshot.last_progress_at,
        Some(start + chrono::Duration::seconds(3))
    );
}

#[test]
fn live_registry_rejects_aggregate_overflow_without_partial_state() {
    let run_id = Uuid::from_u128(33);
    let registry = RunTelemetryRegistry::new(3);
    let start = chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    registry.prepare(run_id);
    registry.observe_progress(run_id, &FuzzProgress::EdgesCovered(9), start);
    registry.observe_progress(
        run_id,
        &FuzzProgress::ExecsPerSec(f64::MAX),
        start + chrono::Duration::seconds(1),
    );
    let before = registry.snapshot(run_id).unwrap();

    registry.observe_progress(
        run_id,
        &FuzzProgress::ExecsPerSec(f64::MAX),
        start + chrono::Duration::seconds(2),
    );

    assert_eq!(registry.snapshot(run_id).unwrap(), before);
}

#[test]
fn throughput_before_the_first_edge_does_not_fabricate_an_edge_sample() {
    let run_id = Uuid::from_u128(34);
    let registry = RunTelemetryRegistry::new(3);
    let observed_at = chrono::Utc::now();
    registry.prepare(run_id);

    registry.observe_progress(run_id, &FuzzProgress::ExecsPerSec(25.0), observed_at);

    let snapshot = registry.snapshot(run_id).unwrap();
    assert_eq!(snapshot.current_execs, Some(25.0));
    assert_eq!(snapshot.edges, None);
    assert!(snapshot.coverage_series.is_empty());
    assert_eq!(snapshot.last_progress_at, Some(observed_at));
}

#[test]
fn logs_and_invalid_throughput_do_not_refresh_metric_time_or_reopen_closed_state() {
    let run_id = Uuid::from_u128(31);
    let registry = RunTelemetryRegistry::new(3);
    let start = chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    registry.prepare(run_id);
    registry.observe_progress(run_id, &FuzzProgress::EdgesCovered(4), start);
    registry.observe_progress(
        run_id,
        &FuzzProgress::LogLine("still noisy".to_owned()),
        start + chrono::Duration::seconds(1),
    );
    registry.observe_progress(
        run_id,
        &FuzzProgress::ExecsPerSec(f64::NAN),
        start + chrono::Duration::seconds(2),
    );
    assert_eq!(
        registry.snapshot(run_id).unwrap().last_progress_at,
        Some(start)
    );

    registry.close_progress(run_id);
    registry.observe_progress(
        run_id,
        &FuzzProgress::ExecsPerSec(50.0),
        start + chrono::Duration::seconds(3),
    );
    let closed = registry.snapshot(run_id).unwrap();
    assert_eq!(closed.current_execs, None);
    assert!(closed.coverage_series.is_empty());
    registry.remove(run_id);
    registry.observe_progress(
        run_id,
        &FuzzProgress::EdgesCovered(99),
        start + chrono::Duration::seconds(4),
    );
    assert!(registry.snapshot(run_id).is_none());
}

#[test]
fn managed_invocation_registration_moves_expected_and_alive_together() {
    let run_id = Uuid::from_u128(32);
    let registry = Arc::new(RunTelemetryRegistry::new(3));
    registry.prepare(run_id);
    let before = registry.snapshot(run_id).unwrap();
    assert_eq!(
        (
            before.managed_invocations_expected,
            before.managed_invocations_alive
        ),
        (0, 0)
    );

    let invocation = registry
        .register_invocation(run_id)
        .expect("one managed invocation");
    let running = registry.snapshot(run_id).unwrap();
    assert_eq!(
        (
            running.managed_invocations_expected,
            running.managed_invocations_alive,
        ),
        (1, 1)
    );
    assert!(registry.register_invocation(run_id).is_err());

    drop(invocation);
    let finished = registry.snapshot(run_id).unwrap();
    assert_eq!(
        (
            finished.managed_invocations_expected,
            finished.managed_invocations_alive,
        ),
        (0, 0)
    );
    registry.close_progress(run_id);
    assert!(registry.register_invocation(run_id).is_err());
}

#[tokio::test]
async fn service_retains_and_deduplicates_events_and_rejects_an_older_assessment() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("health.db"))
            .await
            .unwrap(),
    );
    let observed_at = chrono::Utc::now().trunc_subsecs(0);
    let mut run = hf_storage::RunRecord::new(
        "/projects/health",
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        observed_at,
    );
    run.status = RunStatus::Running;
    store.insert_run(&run).await.unwrap();
    let samples = vec![
        hf_storage::RetainedHealthSample {
            elapsed_secs: 0.0,
            edges: 7,
            execs: 50.0,
        },
        hf_storage::RetainedHealthSample {
            elapsed_secs: 1.0,
            edges: 7,
            execs: 50.0,
        },
        hf_storage::RetainedHealthSample {
            elapsed_secs: 2.0,
            edges: 7,
            execs: 50.0,
        },
    ];
    store
        .upsert_run_telemetry(&hf_storage::RunTelemetryRecord {
            run_id: run.id,
            observed_at,
            last_progress_at: Some(observed_at),
            samples_json: serde_json::to_string(&samples).unwrap(),
            current_execs: Some(50.0),
            mean_execs: Some(50.0),
            peak_execs: Some(50.0),
            edges: Some(7),
            throughput_sample_count: 3,
            throughput_sample_sum: 150.0,
            managed_invocations_expected: 1,
            managed_invocations_alive: 1,
            free_disk_bytes: None,
        })
        .await
        .unwrap();
    let container = hf_service::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));

    let candidate = container.campaign_health(run.id).await.unwrap();
    assert_eq!(candidate.events.len(), 1);
    assert_eq!(candidate.events[0].id, None);

    assert!(container
        .assess_and_emit_campaign_health(run.id, observed_at - chrono::Duration::seconds(1))
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .list_campaign_health_events(Some(run.id), 20)
        .await
        .unwrap()
        .is_empty());

    let first = container
        .assess_and_emit_campaign_health(run.id, observed_at)
        .await
        .unwrap();
    assert_eq!(first.len(), 1);
    assert!(first[0].id.is_some());
    assert_eq!(first[0].condition, HealthCondition::CoveragePlateau);
    assert!(container
        .assess_and_emit_campaign_health(run.id, observed_at)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_campaign_health_events(Some(run.id), 20)
            .await
            .unwrap()
            .len(),
        1
    );
    let retained = container.campaign_health_events(run.id).await.unwrap();
    assert_eq!(retained, first);

    let owner = container.run_owner(run.id).await.unwrap();
    assert_eq!(owner.run_id, run.id);
    assert_eq!(owner.project_root, "/projects/health");
    assert_eq!(owner.target, None);
    assert_eq!(owner.kind, "campaign");
    assert_eq!(owner.status, "running");
    assert_eq!(owner.started_at, observed_at);

    let summary = container
        .morning_health_summary(std::path::Path::new("/projects/health"), observed_at)
        .await
        .unwrap();
    assert!(summary.failed.is_empty());
    assert_eq!(summary.stalled, vec![run.id]);
    assert!(summary.interrupted.is_empty());
    assert!(summary.unprocessed.is_empty());
}

#[tokio::test]
async fn historical_syzkaller_execution_total_does_not_become_a_peak_rate() {
    let directory = tempfile::tempdir().unwrap();
    let project = std::fs::canonicalize(directory.path()).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("historical-kernel.db"))
            .await
            .unwrap(),
    );
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        hf_core::engine::EngineKind::Syzkaller,
        None,
        chrono::Utc::now(),
    );
    run.status = RunStatus::Done;
    run.execs = Some(1_000_000.0);
    run.edges = Some(700);
    store.insert_run(&run).await.unwrap();
    let container = hf_service::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(store);

    let telemetry = container.campaign_telemetry(run.id).await.unwrap();

    assert_eq!(telemetry.current_execs, None);
    assert_eq!(telemetry.mean_execs, None);
    assert_eq!(telemetry.peak_execs, None);
    assert_eq!(telemetry.throughput_sample_count, 0);
    assert!(telemetry.throughput_sample_sum.abs() < f64::EPSILON);
    assert_eq!(telemetry.edges, Some(700));
}

#[tokio::test]
async fn retained_event_pagination_and_summary_recover_a_stall_older_than_one_page() {
    let directory = tempfile::tempdir().unwrap();
    let project = std::fs::canonicalize(directory.path()).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("paged-health.db"))
            .await
            .unwrap(),
    );
    let base = chrono::Utc::now().trunc_subsecs(0) - chrono::Duration::minutes(10);
    let mut run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        base,
    );
    run.status = RunStatus::Running;
    store.insert_run(&run).await.unwrap();
    let plateau = retained_event(
        run.id,
        "coverage_plateau",
        "plateau:oldest".to_owned(),
        base,
    );
    store.insert_campaign_health_event(&plateau).await.unwrap();
    for offset in 1..=101 {
        store
            .insert_campaign_health_event(&retained_event(
                run.id,
                "disk_pressure",
                format!("disk:{offset}"),
                base + chrono::Duration::seconds(offset),
            ))
            .await
            .unwrap();
    }
    let container = hf_service::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(store);

    let first = container
        .campaign_health_event_page(run.id, None, 100)
        .await
        .unwrap();
    assert_eq!(first.events.len(), 100);
    let second = container
        .campaign_health_event_page(run.id, first.next_cursor, 100)
        .await
        .unwrap();
    assert!(second
        .events
        .iter()
        .any(|event| event.id == Some(plateau.id)));
    assert_eq!(second.next_cursor, None);
    let summary = container
        .morning_health_summary(&project, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(summary.stalled, vec![run.id]);
}
