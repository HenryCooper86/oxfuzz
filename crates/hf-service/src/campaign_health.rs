//! Service-owned campaign health conditions.
//!
//! A long campaign fails quietly: workers die, the disk fills, or the fuzzer
//! keeps executing at full rate while learning nothing. This module names those
//! conditions from retained run state, once each, with the evidence behind them.
//!
//! See `docs/design/campaign-health-design.md`.
//!
//! It reports. It does not stop, restart, or resize a campaign: run control has
//! an approval path, and a health reporter that restarts a crashing harness
//! hides the harness defect (AGENTS.md 2.19).

use std::collections::HashSet;

use serde::Serialize;
use uuid::Uuid;

use crate::container::CoverageSample;
use hf_storage::RunStatus;

/// Current serialized Campaign Health schema.
pub const CAMPAIGN_HEALTH_SCHEMA_VERSION: u32 = 1;

/// A named campaign condition worth an operator's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCondition {
    /// Coverage stopped growing while execution continued.
    CoveragePlateau,
    /// Fewer live engine processes than the run expects.
    WorkersMissing,
    /// An engine's progress record has not advanced within its interval.
    WorkerStatsStale,
    /// Free space in the fuzz workspace is below the configured floor.
    DiskPressure,
    /// The run reached a terminal failure state.
    RunFailed,
}

/// How loudly a condition should be carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    /// The campaign is degraded and still producing.
    Warning,
    /// The campaign is not producing usable evidence.
    Error,
}

/// One condition, with the key that prevents it being said twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthEvent {
    /// Serialization version of this event.
    pub schema_version: u32,
    /// The run the condition belongs to.
    pub run_id: Uuid,
    /// What is wrong.
    pub condition: HealthCondition,
    /// How loudly to carry it.
    pub severity: HealthSeverity,
    /// Identity of this condition *in this state*. Scoped to the run, so one
    /// run's condition never silences another's, and carrying the triggering
    /// state so a condition that worsens is delivered again rather than being
    /// suppressed as a repeat.
    pub dedup_key: String,
    /// What is wrong, in a sentence.
    pub detail: String,
}

/// Whether there was a coverage series to judge a plateau against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PlateauCheck {
    /// No coverage series is retained for the run.
    Unavailable {
        /// Stable reason code.
        reason: String,
    },
    /// The series was long enough to evaluate.
    Evaluated {
        /// Measurements compared.
        window: usize,
    },
}

pub use crate::config::CampaignHealthSettings;

/// Retained run state the assessment reads.
#[derive(Debug, Clone, PartialEq)]
pub struct CampaignHealthInput {
    /// The run being assessed.
    pub run_id: Uuid,
    /// Its lifecycle state.
    pub run_status: RunStatus,
    /// The retained coverage series, oldest first.
    pub coverage_series: Vec<CoverageSample>,
    /// Engine processes the run expects.
    pub workers_expected: usize,
    /// Engine processes observed alive.
    pub workers_alive: usize,
    /// Seconds since the progress record last advanced, when known.
    pub progress_stale_secs: Option<u64>,
    /// Free bytes in the fuzz workspace, when known.
    pub free_disk_bytes: Option<u64>,
}

/// One assessment of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CampaignHealthReport {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// The run assessed.
    pub run_id: Uuid,
    /// Whether a plateau could be judged at all.
    pub plateau_check: PlateauCheck,
    /// Conditions found. Empty is the healthy case: alerting on the absence of
    /// a problem trains operators to ignore the channel.
    pub events: Vec<HealthEvent>,
}

/// Assess one run against the operator thresholds.
#[must_use]
pub fn assess_campaign_health(
    input: &CampaignHealthInput,
    settings: &CampaignHealthSettings,
) -> CampaignHealthReport {
    let mut events = Vec::new();
    let active = matches!(input.run_status, RunStatus::Running | RunStatus::Pending);

    if input.run_status == RunStatus::Failed {
        events.push(event(
            input.run_id,
            HealthCondition::RunFailed,
            HealthSeverity::Error,
            "failed",
            "The run terminated with an error; its evidence is incomplete.",
        ));
    }

    let plateau_check = evaluate_plateau(input, settings, &mut events);

    if input.workers_expected > 0 && input.workers_alive < input.workers_expected {
        events.push(event(
            input.run_id,
            HealthCondition::WorkersMissing,
            HealthSeverity::Error,
            &format!("{}of{}", input.workers_alive, input.workers_expected),
            &format!(
                "{} of {} expected engine processes are alive.",
                input.workers_alive, input.workers_expected
            ),
        ));
    }

    // A finished run's progress is supposed to stop moving, so staleness is
    // only a condition while the run is still meant to be producing.
    if active {
        if let Some(stale) = input.progress_stale_secs {
            if stale > settings.stale_progress_secs {
                events.push(event(
                    input.run_id,
                    HealthCondition::WorkerStatsStale,
                    HealthSeverity::Error,
                    &format!("{}s", stale / settings.stale_progress_secs.max(1)),
                    &format!("The engine progress record has not advanced for {stale}s."),
                ));
            }
        }
    }

    if let Some(free) = input.free_disk_bytes {
        if free < settings.disk_floor_bytes {
            events.push(event(
                input.run_id,
                HealthCondition::DiskPressure,
                HealthSeverity::Error,
                &format!("{}", free / (1024 * 1024)),
                &format!(
                    "Free workspace space is {} MiB, below the configured floor of {} MiB.",
                    free / (1024 * 1024),
                    settings.disk_floor_bytes / (1024 * 1024)
                ),
            ));
        }
    }

    CampaignHealthReport {
        schema_version: CAMPAIGN_HEALTH_SCHEMA_VERSION,
        run_id: input.run_id,
        plateau_check,
        events,
    }
}

/// The conditions in `events` that `already_emitted` has not carried.
///
/// Dedup is by key rather than by condition, so a condition whose triggering
/// state worsens is delivered again.
#[must_use]
pub fn undelivered<S: std::hash::BuildHasher>(
    events: &[HealthEvent],
    already_emitted: &HashSet<String, S>,
) -> Vec<HealthEvent> {
    events
        .iter()
        .filter(|event| !already_emitted.contains(&event.dedup_key))
        .cloned()
        .collect()
}

/// Judge a plateau from the coverage series.
///
/// Keys on coverage rather than on the exec counter: a fuzzer executing
/// millions of inputs per second against a harness that rejects all of them has
/// a rising exec count and is learning nothing. Execution is still evidence --
/// a plateau is only reported while execution is progressing, because a run
/// whose execs are also flat is stopped rather than stalled, and the worker
/// conditions name that instead.
fn evaluate_plateau(
    input: &CampaignHealthInput,
    settings: &CampaignHealthSettings,
    events: &mut Vec<HealthEvent>,
) -> PlateauCheck {
    let window = settings.plateau_window.max(1);
    if input.coverage_series.len() <= window {
        return PlateauCheck::Unavailable {
            reason: if input.coverage_series.is_empty() {
                "no_retained_coverage_series".to_owned()
            } else {
                "series_shorter_than_plateau_window".to_owned()
            },
        };
    }

    let tail = &input.coverage_series[input.coverage_series.len() - window..];
    let edges_flat = tail.iter().all(|sample| sample.edges == tail[0].edges);
    let executing = tail.iter().any(|sample| sample.execs > 0.0);

    if edges_flat && executing {
        events.push(event(
            input.run_id,
            HealthCondition::CoveragePlateau,
            HealthSeverity::Warning,
            &format!("{}edges{window}", tail[0].edges),
            &format!(
                "Coverage held at {} edges across the last {window} measurements while \
                 execution continued.",
                tail[0].edges
            ),
        ));
    }
    PlateauCheck::Evaluated { window }
}

fn event(
    run_id: Uuid,
    condition: HealthCondition,
    severity: HealthSeverity,
    state: &str,
    detail: &str,
) -> HealthEvent {
    let code = serde_json::to_value(condition)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        // `HealthCondition` is a fieldless enum with a snake_case rename, so it
        // always serializes to a string; the fallback is unreachable and exists
        // only so this stays total.
        .unwrap_or_else(|| format!("{condition:?}"));
    HealthEvent {
        schema_version: CAMPAIGN_HEALTH_SCHEMA_VERSION,
        run_id,
        condition,
        severity,
        dedup_key: format!("{run_id}:{code}:{state}"),
        detail: detail.to_owned(),
    }
}
