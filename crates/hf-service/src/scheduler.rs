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
use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_guardrails::Guardrails;
use hf_scheduler::dispatcher::{DispatchError, DispatchResult, WorkflowDispatcher};
use hf_scheduler::{
    PersistenceError, Schedule, ScheduleExecution, SchedulerManager, SchedulerPersistence,
    TriggerConfig,
};
use hf_storage::Store;
use serde::{Deserialize, Serialize};

use crate::container::ServiceContainer;

/// Persists scheduler executions to the database so history survives restarts.
struct DbSchedulerPersistence {
    store: Arc<Store>,
}

impl DbSchedulerPersistence {
    async fn upsert(&self, ex: &ScheduleExecution) -> Result<(), PersistenceError> {
        let data = serde_json::to_string(ex).map_err(|e| PersistenceError::new(e.to_string()))?;
        self.store
            .upsert_schedule_execution(
                &ex.execution_id,
                &ex.schedule_id,
                &ex.triggered_at.to_rfc3339(),
                &ex.status.to_string(),
                &data,
            )
            .await
            .map_err(|e| PersistenceError::new(e.to_string()))
    }
}

#[async_trait]
impl SchedulerPersistence for DbSchedulerPersistence {
    async fn record_execution(
        &self,
        execution: &ScheduleExecution,
    ) -> Result<(), PersistenceError> {
        self.upsert(execution).await
    }
    async fn update_execution(
        &self,
        execution: &ScheduleExecution,
    ) -> Result<(), PersistenceError> {
        self.upsert(execution).await
    }
    async fn update_last_fire(
        &self,
        _schedule_id: &str,
        _last_fire: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), PersistenceError> {
        // last_fire is derived from the persisted executions, not stored separately.
        Ok(())
    }
}

/// How often the scheduler evaluates triggers.
const TICK: Duration = Duration::from_secs(30);
/// Constant `workflow_id` for all fuzz-campaign schedules (the dispatcher reads
/// the campaign from `parameter_values`, not the id).
const CAMPAIGN_KIND: &str = "fuzz-campaign";

/// Parameters for a scheduled fuzz campaign (stored in `Schedule.parameter_values`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignParams {
    pub project: String,
    pub target: String,
    pub engine: String,
    pub duration_secs: u64,
    /// Target language, taken from the promoted harness at schedule time.
    /// Defaults to C so schedules persisted before this field existed still load
    /// (they could only ever have been C -- the dispatcher hardcoded it).
    #[serde(default = "default_lang")]
    pub lang: String,
}

/// The language a campaign persisted before `lang` existed must have run as.
fn default_lang() -> String {
    TargetLanguage::C.as_str().to_owned()
}

impl Default for CampaignParams {
    /// Hand-written so the fallback used when stored params fail to parse still
    /// carries a parseable language; a derived `Default` would leave it empty.
    fn default() -> Self {
        Self {
            project: String::new(),
            target: String::new(),
            engine: String::new(),
            duration_secs: 0,
            lang: default_lang(),
        }
    }
}

/// Pin the project to an absolute path before persisting a schedule.
///
/// A workspace is keyed by a hash of the project *path string*, so a schedule
/// stored as `tests/fixtures/sample_c` looks for its compiled harness in a
/// different workspace than the absolute path the harness was compiled under --
/// and fails every single fire with "compiled harness not found", hours after
/// anyone was watching. Canonicalizing once, at creation, makes that class of
/// schedule unrepresentable. A path that does not resolve is left alone: the
/// campaign's own error is clearer than one invented here.
fn with_absolute_project(params: &CampaignParams) -> CampaignParams {
    let mut pinned = params.clone();
    if let Ok(absolute) = std::fs::canonicalize(&pinned.project) {
        pinned.project = absolute.display().to_string();
    }
    pinned
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
    /// Canonical language id the campaign runs as (`c`, `cpp`, `rust`).
    pub lang: String,
    pub duration_secs: u64,
    /// Last time the campaign fired (RFC3339), if ever.
    pub last_fire: Option<String>,
}

/// A past campaign execution for the GUI history view.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionView {
    pub execution_id: String,
    pub schedule_id: String,
    /// Campaign name (resolved from the schedule).
    pub campaign: String,
    /// When the trigger fired (RFC3339).
    pub triggered_at: String,
    /// "pending" | "running" | "completed" | "failed" | "skipped".
    pub status: String,
    /// Result summary (e.g. "3 crashes, 120 edges") or the error message.
    pub summary: String,
}

/// Map a [`ScheduleExecution`] to an [`ExecutionView`]. The campaign name is
/// read from the execution's own request summary (so history survives the
/// schedule being deleted), falling back to `campaign`.
fn view_of_execution(ex: &ScheduleExecution, campaign: &str) -> ExecutionView {
    let summary = ex
        .error_message
        .clone()
        .or_else(|| {
            ex.response_summary
                .get("summary")
                .and_then(|v| v.as_str())
                .map(ToOwned::to_owned)
        })
        .unwrap_or_default();
    let name = ex
        .request_summary
        .get("schedule_name")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map_or_else(|| campaign.to_owned(), ToOwned::to_owned);
    ExecutionView {
        execution_id: ex.execution_id.clone(),
        schedule_id: ex.schedule_id.clone(),
        campaign: name,
        triggered_at: ex.triggered_at.to_rfc3339(),
        status: ex.status.to_string(),
        summary,
    }
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
        lang: params.lang,
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
        // The language comes from the harness the campaign was scheduled against.
        // Assuming C here (as this dispatcher once did) makes every Rust or C++
        // campaign fail the harness-language check at fire time, hours later.
        let lang: TargetLanguage = params
            .lang
            .parse()
            .map_err(|e: String| DispatchError::ParseError { message: e })?;
        tracing::info!(
            "scheduled campaign {workflow_id} firing: {} via {} ({}) for {}s",
            params.target,
            params.engine,
            params.lang,
            params.duration_secs
        );
        let started = std::time::Instant::now();
        // Run the full autonomous campaign (discover -> harness+repair -> seed ->
        // run -> triage -> refine), not just a single fixed run. A named target
        // pins the campaign; an empty one lets it pick the top-ranked target.
        let target = if params.target.trim().is_empty() {
            None
        } else {
            Some(params.target.as_str())
        };
        let result = self
            .container
            .run_campaign(
                Path::new(&params.project),
                target,
                engine,
                lang,
                params.duration_secs,
                2,
                3,
            )
            .await;
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(outcome) => Ok(DispatchResult {
                success: true,
                summary: format!(
                    "{} crash(es), {} edges over {} iteration(s) on {}{}",
                    outcome.crashes,
                    outcome.edges,
                    outcome.iterations,
                    outcome.target,
                    if outcome.auto_reverts > 0 {
                        format!(", {} auto-revert(s)", outcome.auto_reverts)
                    } else {
                        String::new()
                    },
                ),
                output: serde_json::json!({
                    "target": outcome.target,
                    "crashes": outcome.crashes,
                    "edges": outcome.edges,
                    "iterations": outcome.iterations,
                    "repairs_used": outcome.repairs_used,
                    "auto_reverts": outcome.auto_reverts,
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
    /// Database for persisted execution history (when configured).
    store: Option<Arc<Store>>,
}

impl CampaignScheduler {
    /// Start the scheduler: install the dispatcher, reload persisted schedules,
    /// and begin ticking. Campaigns run with permissive guardrails -- creating a
    /// schedule is the human authorization for its future headless runs.
    pub async fn start(container: ServiceContainer, store_path: PathBuf) -> Self {
        let manager = Arc::new(SchedulerManager::with_defaults());
        // Grab the DB handle (for persisted execution history) before the
        // container is moved into the dispatcher.
        let store = container.store().cloned();
        let dispatcher = Arc::new(FuzzCampaignDispatcher {
            container: container.with_guardrails(Guardrails::permissive()),
        });
        manager.set_dispatcher(dispatcher).await;
        if let Some(store) = &store {
            manager
                .set_persistence(Arc::new(DbSchedulerPersistence {
                    store: Arc::clone(store),
                }))
                .await;
        }
        for schedule in load_schedules(&store_path) {
            manager.register(schedule).await;
        }
        manager.start(TICK).await;
        Self {
            manager,
            store_path,
            store,
        }
    }

    /// All scheduled campaigns.
    pub async fn list(&self) -> Vec<Schedule> {
        self.manager.list_schedules().await
    }

    /// All scheduled campaigns as GUI-friendly views. After a restart the
    /// in-memory `last_fire` is gone, so it is back-filled from the latest
    /// persisted execution per schedule.
    pub async fn list_views(&self) -> Vec<CampaignView> {
        let schedules = self.manager.list_schedules().await;
        let fires: std::collections::HashMap<String, String> = match &self.store {
            Some(store) => store
                .latest_schedule_fires()
                .await
                .unwrap_or_default()
                .into_iter()
                .collect(),
            None => std::collections::HashMap::new(),
        };
        schedules
            .iter()
            .map(|s| {
                let mut view = view_of(s);
                if view.last_fire.is_none() {
                    view.last_fire = fires.get(&s.id).cloned();
                }
                view
            })
            .collect()
    }

    /// Recent campaign executions, newest first. Reads persisted history (which
    /// survives restarts) when a database is configured, else the in-memory log.
    pub async fn recent_executions(&self, limit: usize) -> Vec<ExecutionView> {
        if let Some(store) = &self.store {
            if let Ok(rows) = store
                .list_schedule_executions(i64::try_from(limit).unwrap_or(50))
                .await
            {
                return rows
                    .iter()
                    .filter_map(|j| serde_json::from_str::<ScheduleExecution>(j).ok())
                    .map(|ex| view_of_execution(&ex, ""))
                    .collect();
            }
        }
        // In-memory fallback (no database configured).
        let schedules = self.manager.list_schedules().await;
        let names: std::collections::HashMap<String, String> = schedules
            .iter()
            .map(|s| (s.id.clone(), s.name.clone()))
            .collect();
        let mut all = Vec::new();
        for schedule in &schedules {
            for ex in self.manager.execution_history(&schedule.id).await {
                let name = names.get(&ex.schedule_id).map_or("", String::as_str);
                all.push(view_of_execution(&ex, name));
            }
        }
        all.sort_by(|a, b| b.triggered_at.cmp(&a.triggered_at));
        all.truncate(limit);
        all
    }

    /// Create + register + persist a new campaign schedule.
    pub async fn create(
        &self,
        name: &str,
        params: &CampaignParams,
        trigger: TriggerConfig,
    ) -> Schedule {
        let id = uuid::Uuid::new_v4().to_string();
        let params = with_absolute_project(params);
        let schedule = Schedule::new(id, name, trigger, CAMPAIGN_KIND)
            .with_params(serde_json::to_value(&params).unwrap_or_default());
        self.manager.register(schedule.clone()).await;
        self.persist().await;
        schedule
    }

    /// Clear the persisted execution history, returning how many rows went.
    ///
    /// History outlives the schedule that produced it, so a campaign deleted
    /// months ago can still be the only thing an operator sees in "Recent runs".
    pub async fn clear_history(&self) -> u64 {
        let Some(store) = &self.store else {
            return 0;
        };
        store.clear_schedule_executions().await.unwrap_or(0)
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
    fn a_relative_project_is_pinned_to_an_absolute_path() {
        // The whole reason scheduled campaigns failed every fire: a relative
        // path hashes to a different workspace than the one holding the harness.
        let params = CampaignParams {
            project: ".".to_owned(),
            target: "parse".to_owned(),
            engine: "libfuzzer".to_owned(),
            lang: "c".to_owned(),
            duration_secs: 60,
        };
        let pinned = with_absolute_project(&params);
        assert!(
            Path::new(&pinned.project).is_absolute(),
            "expected an absolute project path, got {}",
            pinned.project
        );
    }

    #[test]
    fn an_unresolvable_project_is_left_alone() {
        let params = CampaignParams {
            project: "/no/such/project".to_owned(),
            ..CampaignParams::default()
        };
        assert_eq!(with_absolute_project(&params).project, "/no/such/project");
    }

    #[test]
    fn campaign_params_persisted_before_lang_load_as_c() {
        // Schedules stored by an older build have no `lang` key; they could only
        // ever have run as C, because the dispatcher hardcoded it.
        let legacy = serde_json::json!({
            "project": "/p", "target": "t", "engine": "libfuzzer", "duration_secs": 60
        });
        let params: CampaignParams = serde_json::from_value(legacy).expect("legacy params load");
        assert_eq!(params.lang, "c");
        assert_eq!(
            params.lang.parse::<TargetLanguage>(),
            Ok(TargetLanguage::C),
            "the default must be parseable by the dispatcher"
        );
    }

    #[test]
    fn default_campaign_params_carry_a_parseable_language() {
        assert!(CampaignParams::default()
            .lang
            .parse::<TargetLanguage>()
            .is_ok());
    }

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
            lang: "c".to_owned(),
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
