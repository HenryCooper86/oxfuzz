//! Scheduled fuzz campaigns, backed by `hf-scheduler`.
//!
//! A campaign is a persisted [`Schedule`] (cron / interval / one-time trigger)
//! whose `parameter_values` carry [`CampaignParams`] (project/target/engine/
//! duration). [`CampaignScheduler`] installs a dispatcher that runs the campaign
//! headlessly through the [`ServiceContainer`] when a schedule fires, ticks in
//! the background, and persists schedules to JSON so they survive restarts.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hf_core::engine::{EngineKind, FuzzProgress};
use hf_guardrails::Guardrails;
use hf_scheduler::dispatcher::{DispatchError, DispatchResult, WorkflowDispatcher};
use hf_scheduler::{Schedule, SchedulerManager, TriggerConfig};
use serde::{Deserialize, Serialize};

use crate::container::ServiceContainer;

/// How often the scheduler evaluates triggers.
const TICK: Duration = Duration::from_secs(30);
/// Constant `workflow_id` for all fuzz-campaign schedules (the dispatcher reads
/// the campaign from `parameter_values`, not the id).
const CAMPAIGN_KIND: &str = "fuzz-campaign";

/// Parameters for a scheduled fuzz campaign (stored in `Schedule.parameter_values`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CampaignParams {
    pub project: String,
    pub target: String,
    pub engine: String,
    pub duration_secs: u64,
}

/// A presentation-friendly view of a scheduled campaign for the GUI.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignView {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// Human-readable trigger summary (e.g. "every 3600s", "cron: 0 2 * * *").
    pub trigger: String,
    pub project: String,
    pub target: String,
    pub engine: String,
    pub duration_secs: u64,
    /// Last time the campaign fired (RFC3339), if ever.
    pub last_fire: Option<String>,
}

/// Map a stored [`Schedule`] to a [`CampaignView`].
fn view_of(schedule: &Schedule) -> CampaignView {
    let params: CampaignParams =
        serde_json::from_value(schedule.parameter_values.clone()).unwrap_or_default();
    let trigger = match &schedule.trigger {
        TriggerConfig::Interval { interval_secs } => format!("every {interval_secs}s"),
        TriggerConfig::Cron { expression, .. } => format!("cron: {expression}"),
        TriggerConfig::OneTime { at } => format!("once at {}", at.to_rfc3339()),
        TriggerConfig::Event { event_type, .. } => format!("on {event_type}"),
    };
    CampaignView {
        id: schedule.id.clone(),
        name: schedule.name.clone(),
        enabled: schedule.enabled,
        trigger,
        project: params.project,
        target: params.target,
        engine: params.engine,
        duration_secs: params.duration_secs,
        last_fire: schedule.last_fire.map(|t| t.to_rfc3339()),
    }
}

/// Build a [`TriggerConfig`] from a kind + value pair (the GUI's trigger form).
///
/// - `interval` + seconds, e.g. `("interval", "3600")`
/// - `cron` + expression, e.g. `("cron", "0 2 * * *")`
/// - `once` + RFC3339 timestamp, e.g. `("once", "2026-07-01T02:00:00Z")`
///
/// # Errors
/// Returns a message when the kind is unknown or the value cannot be parsed.
pub fn parse_trigger(kind: &str, value: &str) -> Result<TriggerConfig, String> {
    match kind {
        "interval" => {
            let secs: u64 = value
                .trim()
                .parse()
                .map_err(|_| format!("invalid interval seconds: {value:?}"))?;
            if secs == 0 {
                return Err("interval must be > 0 seconds".to_owned());
            }
            Ok(TriggerConfig::Interval {
                interval_secs: secs,
            })
        }
        "cron" => {
            if value.trim().is_empty() {
                return Err("cron expression is empty".to_owned());
            }
            Ok(TriggerConfig::Cron {
                expression: value.trim().to_owned(),
                timezone: "UTC".to_owned(),
            })
        }
        "once" => {
            let at = value
                .trim()
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_err(|e| format!("invalid RFC3339 time {value:?}: {e}"))?;
            Ok(TriggerConfig::OneTime { at })
        }
        other => Err(format!("unknown trigger kind: {other}")),
    }
}

/// Runs due campaigns headlessly through the service container.
struct FuzzCampaignDispatcher {
    container: ServiceContainer,
}

#[async_trait]
impl WorkflowDispatcher for FuzzCampaignDispatcher {
    async fn dispatch(
        &self,
        workflow_id: &str,
        parameter_values: serde_json::Value,
    ) -> Result<DispatchResult, DispatchError> {
        let params: CampaignParams =
            serde_json::from_value(parameter_values).map_err(|e| DispatchError::ParseError {
                message: format!("campaign params: {e}"),
            })?;
        let engine: EngineKind = params
            .engine
            .parse()
            .map_err(|e: String| DispatchError::ParseError { message: e })?;
        tracing::info!(
            "scheduled campaign {workflow_id} firing: {} via {} for {}s",
            params.target,
            params.engine,
            params.duration_secs
        );
        let noop = |_: FuzzProgress| {};
        let started = std::time::Instant::now();
        let result = self
            .container
            .run_fuzzer(
                Path::new(&params.project),
                &params.target,
                engine,
                params.duration_secs,
                &noop,
            )
            .await;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(summary) => Ok(DispatchResult {
                success: true,
                summary: format!("{} crashes, {} edges", summary.crashes, summary.edges),
                output: serde_json::json!({
                    "crashes": summary.crashes,
                    "edges": summary.edges,
                    "execs": summary.execs,
                }),
                duration_ms,
                error: None,
            }),
            Err(e) => Ok(DispatchResult {
                success: false,
                summary: "campaign failed".to_owned(),
                output: serde_json::Value::Null,
                duration_ms,
                error: Some(e.to_string()),
            }),
        }
    }
}

/// Manages scheduled fuzz campaigns: a background tick loop plus JSON-persisted
/// schedules.
pub struct CampaignScheduler {
    manager: Arc<SchedulerManager>,
    store_path: PathBuf,
}

impl CampaignScheduler {
    /// Start the scheduler: install the dispatcher, reload persisted schedules,
    /// and begin ticking. Campaigns run with permissive guardrails -- creating a
    /// schedule is the human authorization for its future headless runs.
    pub async fn start(container: ServiceContainer, store_path: PathBuf) -> Self {
        let manager = Arc::new(SchedulerManager::with_defaults());
        let dispatcher = Arc::new(FuzzCampaignDispatcher {
            container: container.with_guardrails(Guardrails::permissive()),
        });
        manager.set_dispatcher(dispatcher).await;
        for schedule in load_schedules(&store_path) {
            manager.register(schedule).await;
        }
        manager.start(TICK).await;
        Self {
            manager,
            store_path,
        }
    }

    /// All scheduled campaigns.
    pub async fn list(&self) -> Vec<Schedule> {
        self.manager.list_schedules().await
    }

    /// All scheduled campaigns as GUI-friendly views.
    pub async fn list_views(&self) -> Vec<CampaignView> {
        self.manager
            .list_schedules()
            .await
            .iter()
            .map(view_of)
            .collect()
    }

    /// Create + register + persist a new campaign schedule.
    pub async fn create(
        &self,
        name: &str,
        params: &CampaignParams,
        trigger: TriggerConfig,
    ) -> Schedule {
        let id = uuid::Uuid::new_v4().to_string();
        let schedule = Schedule::new(id, name, trigger, CAMPAIGN_KIND)
            .with_params(serde_json::to_value(params).unwrap_or_default());
        self.manager.register(schedule.clone()).await;
        self.persist().await;
        schedule
    }

    /// Remove a schedule by id.
    pub async fn remove(&self, id: &str) -> bool {
        let removed = self.manager.remove(id).await;
        if removed {
            self.persist().await;
        }
        removed
    }

    /// Enable or disable a schedule by id.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> bool {
        let ok = if enabled {
            self.manager.resume(id).await
        } else {
            self.manager.pause(id).await
        };
        if ok {
            self.persist().await;
        }
        ok
    }

    async fn persist(&self) {
        let schedules = self.manager.list_schedules().await;
        let Ok(json) = serde_json::to_string_pretty(&schedules) else {
            return;
        };
        if let Some(parent) = self.store_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&self.store_path, json) {
            tracing::warn!("failed to persist schedules: {e}");
        }
    }
}

/// Load persisted schedules (best-effort; empty on missing/corrupt file).
fn load_schedules(path: &Path) -> Vec<Schedule> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trigger_handles_each_kind() {
        assert!(matches!(
            parse_trigger("interval", "3600"),
            Ok(TriggerConfig::Interval {
                interval_secs: 3600
            })
        ));
        assert!(matches!(
            parse_trigger("cron", "0 2 * * *"),
            Ok(TriggerConfig::Cron { .. })
        ));
        assert!(matches!(
            parse_trigger("once", "2026-07-01T02:00:00Z"),
            Ok(TriggerConfig::OneTime { .. })
        ));
        assert!(parse_trigger("interval", "0").is_err());
        assert!(parse_trigger("interval", "abc").is_err());
        assert!(parse_trigger("nope", "x").is_err());
    }

    #[test]
    fn schedules_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedules.json");
        let params = CampaignParams {
            project: "/p".to_owned(),
            target: "t".to_owned(),
            engine: "libfuzzer".to_owned(),
            duration_secs: 60,
        };
        let sched = Schedule::new(
            "id1",
            "nightly",
            parse_trigger("interval", "60").unwrap(),
            CAMPAIGN_KIND,
        )
        .with_params(serde_json::to_value(&params).unwrap());
        std::fs::write(&path, serde_json::to_string(&vec![sched]).unwrap()).unwrap();

        let loaded = load_schedules(&path);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "nightly");
        let p: CampaignParams = serde_json::from_value(loaded[0].parameter_values.clone()).unwrap();
        assert_eq!(p.target, "t");
        assert_eq!(p.duration_secs, 60);
    }
}
