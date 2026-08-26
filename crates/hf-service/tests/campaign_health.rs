//! Campaign Health domain contract.
//!
//! A stall is a coverage question, not an exec-count question. A fuzzer
//! executing millions of inputs per second against a harness that rejects all
//! of them has a rising exec count and is learning nothing.

#![cfg(feature = "campaign-health")]

use std::collections::HashSet;

use hf_service::campaign_health::{
    assess_campaign_health, undelivered, CampaignHealthInput, CampaignHealthSettings,
    HealthCondition, PlateauCheck,
};
use hf_service::CoverageSample;
use hf_storage::RunStatus;
use uuid::Uuid;

fn settings() -> CampaignHealthSettings {
    CampaignHealthSettings {
        plateau_window: 3,
        stale_progress_secs: 180,
        disk_floor_bytes: 3 * 1024 * 1024 * 1024,
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

fn healthy() -> CampaignHealthInput {
    CampaignHealthInput {
        run_id: Uuid::from_u128(1),
        run_status: RunStatus::Running,
        coverage_series: series(&[10, 20, 30, 40]),
        workers_expected: 2,
        workers_alive: 2,
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
fn flat_coverage_under_continued_execution_is_a_plateau() {
    let mut input = healthy();
    input.coverage_series = series(&[100, 100, 100, 100]);

    assert!(conditions(&input).contains(&HealthCondition::CoveragePlateau));
}

#[test]
fn a_rising_exec_count_does_not_rescue_a_plateau() {
    // The exact case an exec-counter stall check calls healthy: throughput is
    // climbing and the fuzzer is learning nothing.
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
fn fewer_live_workers_than_expected_is_a_condition() {
    let mut input = healthy();
    input.workers_alive = 1;

    assert!(conditions(&input).contains(&HealthCondition::WorkersMissing));
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
    input.workers_alive = 1;

    let first = assess_campaign_health(&input, &settings()).events;
    let mut emitted: HashSet<String> = first.iter().map(|event| event.dedup_key.clone()).collect();
    assert_eq!(first.len(), 1);

    let second = assess_campaign_health(&input, &settings()).events;
    assert!(
        undelivered(&second, &emitted).is_empty(),
        "an unchanged condition must not alert twice"
    );

    // Worsening state carries a different key, so it is delivered again.
    input.workers_alive = 0;
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
    a.workers_alive = 1;
    let mut b = healthy();
    b.run_id = Uuid::from_u128(2);
    b.workers_alive = 1;

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
    input.workers_alive = 0;
    input.progress_stale_secs = Some(9_000);
    input.free_disk_bytes = Some(1);
    input.coverage_series = series(&[7, 7, 7, 7]);

    let report = assess_campaign_health(&input, &settings());

    assert!(report.events.len() >= 4);
    for event in &report.events {
        assert!(!event.dedup_key.trim().is_empty());
        assert!(!event.detail.trim().is_empty());
        assert_eq!(event.run_id, input.run_id);
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
