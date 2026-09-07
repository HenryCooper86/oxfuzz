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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::container::CoverageSample;
use hf_storage::{CampaignHealthEvidenceRecord, RetainedHealthSample, RunStatus};

pub use crate::container::health_monitor::{
    ManagedInvocationGuard, RunTelemetryObservation, RunTelemetryRegistry,
};

/// Current serialized Campaign Health schema.
pub const CAMPAIGN_HEALTH_SCHEMA_VERSION: u32 = 2;

/// A named campaign condition worth an operator's attention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthCondition {
    /// Coverage stopped growing while execution continued.
    CoveragePlateau,
    /// Explicit invocation evidence reports fewer live awaits than expected.
    ManagedInvocationMissing,
    /// An engine's progress record has not advanced within its interval.
    WorkerStatsStale,
    /// Free space in the fuzz workspace is below the configured floor.
    DiskPressure,
    /// The run reached a terminal failure state.
    RunFailed,
}

impl HealthCondition {
    /// Stable persisted and wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoveragePlateau => "coverage_plateau",
            Self::ManagedInvocationMissing => "managed_invocation_missing",
            Self::WorkerStatsStale => "worker_stats_stale",
            Self::DiskPressure => "disk_pressure",
            Self::RunFailed => "run_failed",
        }
    }
}

impl std::fmt::Display for HealthCondition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How loudly a condition should be carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthSeverity {
    /// The campaign is degraded and still producing.
    Warning,
    /// The campaign is not producing usable evidence.
    Error,
}

impl HealthSeverity {
    /// Stable persisted and wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// One condition, with the key that prevents it being said twice.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HealthEvent {
    /// Serialization version of this event.
    pub schema_version: u32,
    /// Stable durable event identifier, present only after `SQLite` admission.
    pub id: Option<Uuid>,
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
    /// Time the condition was assessed.
    pub observed_at: DateTime<Utc>,
    /// Exact version 2 input and thresholds retained with the event.
    pub evidence: CampaignHealthEvidenceRecord,
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
    /// Time this input was assembled.
    pub observed_at: DateTime<Utc>,
    /// Its lifecycle state.
    pub run_status: RunStatus,
    /// The retained coverage series, oldest first.
    pub coverage_series: Vec<CoverageSample>,
    /// Latest finite executions-per-second report.
    pub current_execs: Option<f64>,
    /// Whole-run arithmetic mean of valid throughput reports.
    pub mean_execs: Option<f64>,
    /// Peak finite executions-per-second report.
    pub peak_execs: Option<f64>,
    /// Number of reports included in the whole-run mean.
    pub throughput_sample_count: u64,
    /// Sum paired with `throughput_sample_count`.
    pub throughput_sample_sum: f64,
    /// Service-managed invocations explicitly expected at this instant.
    pub managed_invocations_expected: u32,
    /// Expected invocations still within their runtime await.
    pub managed_invocations_alive: u32,
    /// Latest valid structured metric observation.
    pub last_progress_at: Option<DateTime<Utc>>,
    /// Seconds since the progress record last advanced, when known.
    pub progress_stale_secs: Option<u64>,
    /// Free bytes in the fuzz workspace, when known.
    pub free_disk_bytes: Option<u64>,
}

/// One assessment of a run.
#[derive(Debug, Clone, PartialEq, Serialize)]
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

/// One bounded newest-first page of retained health events.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CampaignHealthEventPage {
    /// Strictly decoded retained events.
    pub events: Vec<HealthEvent>,
    /// Last returned event to pass when requesting the next older page.
    pub next_cursor: Option<Uuid>,
}

/// Authoritative cumulative telemetry for one live or retained campaign.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CampaignTelemetryView {
    /// Current schema version.
    pub schema_version: u32,
    /// Durable run identifier.
    pub run_id: Uuid,
    /// Time of the service-owned snapshot.
    pub observed_at: DateTime<Utc>,
    /// Latest valid structured metric time.
    pub last_progress_at: Option<DateTime<Utc>>,
    /// Bounded coverage/throughput series.
    pub coverage_series: Vec<CoverageSample>,
    /// Latest finite executions per second.
    pub current_execs: Option<f64>,
    /// Whole-run arithmetic mean of valid throughput reports.
    pub mean_execs: Option<f64>,
    /// Peak finite executions per second.
    pub peak_execs: Option<f64>,
    /// Number of reports included in the whole-run mean.
    pub throughput_sample_count: u64,
    /// Finite sum paired with `throughput_sample_count`.
    pub throughput_sample_sum: f64,
    /// Latest edge observation.
    pub edges: Option<u64>,
    /// Explicitly expected service-managed invocations.
    pub managed_invocations_expected: u32,
    /// Expected invocations still inside the runtime await.
    pub managed_invocations_alive: u32,
    /// Free fuzz-workspace bytes, when available.
    pub free_disk_bytes: Option<u64>,
}

/// Retained overnight campaign categories for one project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MorningHealthSummary {
    /// Current schema version.
    pub schema_version: u32,
    /// Canonical requested project.
    pub project_root: String,
    /// Inclusive lookback start.
    pub since: DateTime<Utc>,
    /// Failed campaign runs.
    pub failed: Vec<Uuid>,
    /// Runs with retained plateau, stale-stat, or missing-invocation evidence.
    pub stalled: Vec<Uuid>,
    /// Runs left open in the recovery journal.
    pub interrupted: Vec<Uuid>,
    /// Terminal runs whose closeout remains pending or retryable.
    pub unprocessed: Vec<Uuid>,
}

/// Assess one run against the operator thresholds.
#[must_use]
pub fn assess_campaign_health(
    input: &CampaignHealthInput,
    settings: &CampaignHealthSettings,
) -> CampaignHealthReport {
    let mut events = Vec::new();
    let invocation_active = matches!(input.run_status, RunStatus::Running | RunStatus::Pending)
        && input.managed_invocations_expected > 0
        && input.managed_invocations_alive > 0;

    if input.run_status == RunStatus::Failed {
        events.push(event(
            input,
            settings,
            HealthCondition::RunFailed,
            HealthSeverity::Error,
            "failed",
            "The run terminated with an error; its evidence is incomplete.",
        ));
    }

    let plateau_check = evaluate_plateau(input, settings, &mut events);

    if input.managed_invocations_expected > 0
        && input.managed_invocations_alive < input.managed_invocations_expected
    {
        events.push(event(
            input,
            settings,
            HealthCondition::ManagedInvocationMissing,
            HealthSeverity::Error,
            &format!(
                "{}of{}",
                input.managed_invocations_alive, input.managed_invocations_expected
            ),
            &format!(
                "{} of {} explicitly admitted managed invocations are active.",
                input.managed_invocations_alive, input.managed_invocations_expected
            ),
        ));
    }

    // A finished run's progress is supposed to stop moving, so staleness is
    // only a condition while the run is still meant to be producing.
    if invocation_active {
        if let Some(stale) = input.progress_stale_secs {
            if stale > settings.stale_progress_secs {
                events.push(event(
                    input,
                    settings,
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
                input,
                settings,
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
/// Keys on coverage rather than on throughput: a fuzzer executing
/// millions of inputs per second against a harness that rejects all of them has
/// positive throughput and is learning nothing. Execution is still evidence:
/// a plateau requires at least one positive throughput sample in the window.
fn evaluate_plateau(
    input: &CampaignHealthInput,
    settings: &CampaignHealthSettings,
    events: &mut Vec<HealthEvent>,
) -> PlateauCheck {
    let window = settings.plateau_window.max(1);
    if input.coverage_series.len() < window {
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
            input,
            settings,
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
    input: &CampaignHealthInput,
    settings: &CampaignHealthSettings,
    condition: HealthCondition,
    severity: HealthSeverity,
    state: &str,
    detail: &str,
) -> HealthEvent {
    let code = condition.as_str();
    let evidence = CampaignHealthEvidenceRecord {
        schema_version: CAMPAIGN_HEALTH_SCHEMA_VERSION,
        run_id: input.run_id,
        condition: code.to_owned(),
        observed_at: input.observed_at,
        run_status: input.run_status,
        plateau_window: settings.plateau_window,
        stale_progress_secs: settings.stale_progress_secs,
        disk_floor_bytes: settings.disk_floor_bytes,
        coverage_samples: input
            .coverage_series
            .iter()
            .map(|sample| RetainedHealthSample {
                elapsed_secs: sample.t,
                edges: sample.edges,
                execs: sample.execs,
            })
            .collect(),
        last_progress_at: input.last_progress_at,
        progress_stale_secs: input.progress_stale_secs,
        current_execs: input.current_execs,
        mean_execs: input.mean_execs,
        peak_execs: input.peak_execs,
        throughput_sample_count: input.throughput_sample_count,
        throughput_sample_sum: input.throughput_sample_sum,
        managed_invocations_expected: input.managed_invocations_expected,
        managed_invocations_alive: input.managed_invocations_alive,
        free_disk_bytes: input.free_disk_bytes,
    };
    HealthEvent {
        schema_version: CAMPAIGN_HEALTH_SCHEMA_VERSION,
        id: None,
        run_id: input.run_id,
        condition,
        severity,
        dedup_key: format!("{}:{code}:{state}", input.run_id),
        detail: detail.to_owned(),
        observed_at: input.observed_at,
        evidence,
    }
}
