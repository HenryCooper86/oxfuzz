//! Scheduled fuzz campaigns, backed by `hf-scheduler`.
//!
//! A campaign is a persisted [`Schedule`] (cron / interval / one-time trigger)
//! whose `parameter_values` carry [`CampaignParams`] (project/target/engine/
//! duration). [`CampaignScheduler`] installs a dispatcher that runs the campaign
//! headlessly through the [`ServiceContainer`] when a schedule fires, ticks in
//! the background, and persists schedules to JSON so they survive restarts.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetLanguage;
use hf_guardrails::Guardrails;
use hf_scheduler::dispatcher::{DispatchError, DispatchResult, WorkflowDispatcher};
use hf_scheduler::{
    OneTimeAcknowledgement, OneTimeOccurrence, OneTimeOccurrenceState, OneTimeOccurrenceTransition,
    OneTimeReservation, OneTimeRuntimeStatus, OneTimeTransitionResult, PersistenceError, Schedule,
    ScheduleExecution, SchedulerManager, SchedulerPersistence, TriggerConfig,
};
use hf_storage::{
    NewScheduleOccurrence, ScheduleOccurrenceAcknowledgement, ScheduleOccurrenceRecord,
    ScheduleOccurrenceReservation, ScheduleOccurrenceTransition,
    ScheduleOccurrenceTransitionResult, StorageError, Store,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use crate::campaign_state::{
    atomic_write_json, read_json_file, CampaignRuntimeState, CampaignStateStore, ConcurrencyGate,
    StateFileError,
};
use crate::container::{SchedulableTarget, ServiceContainer};

/// Notified to the presentation layer when a scheduled campaign finds crashes,
/// so a headless run can raise a toast. Set by the Tauri shell; `None` elsewhere.
pub type CampaignNotifier = Arc<dyn Fn(CampaignNotice) + Send + Sync>;

/// A late-bindable notifier slot: the desktop shell only has an `AppHandle` to
/// emit with *after* the scheduler is built, so it fills this in during setup.
type NotifierSlot = Arc<Mutex<Option<CampaignNotifier>>>;

/// What a scheduled campaign found, for a UI notification.
#[derive(Debug, Clone, Serialize)]
pub struct CampaignNotice {
    pub schedule_id: String,
    pub campaign: String,
    pub project: String,
    pub target: String,
    pub crashes: usize,
    /// A report draft was saved for the crashes.
    pub report_saved: bool,
    /// The crashes were pushed to `DefectDojo`.
    pub defectdojo_pushed: bool,
}

/// Serialized, atomic repository for persisted schedule definitions.
struct ScheduleFileStore {
    path: PathBuf,
    write_lock: AsyncMutex<()>,
}

impl ScheduleFileStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            write_lock: AsyncMutex::new(()),
        }
    }

    fn load(&self) -> Result<Vec<Schedule>, StateFileError> {
        load_schedules(&self.path)
    }

    async fn replace(&self, schedules: &[Schedule]) -> Result<(), StateFileError> {
        let _guard = self.write_lock.lock().await;
        atomic_write_schedules(&self.path, schedules)
    }

    async fn replace_from_manager(&self, manager: &SchedulerManager) -> Result<(), StateFileError> {
        let _guard = self.write_lock.lock().await;
        let schedules = manager.list_schedules().await;
        atomic_write_schedules(&self.path, &schedules)
    }

    async fn upsert(&self, schedule: &Schedule) -> Result<(), StateFileError> {
        let _guard = self.write_lock.lock().await;
        let mut schedules = load_schedules(&self.path)?;
        schedules.retain(|existing| existing.id != schedule.id);
        schedules.push(schedule.clone());
        atomic_write_schedules(&self.path, &schedules)
    }
}

/// Persists scheduler definitions atomically and execution history to the
/// database when one is configured.
struct CampaignSchedulerPersistence {
    store: Option<Arc<Store>>,
    schedules: Arc<ScheduleFileStore>,
    history_retention_limit: usize,
}

impl CampaignSchedulerPersistence {
    async fn upsert(&self, ex: &ScheduleExecution) -> Result<(), PersistenceError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        let data = serde_json::to_string(ex).map_err(|e| PersistenceError::new(e.to_string()))?;
        store
            .upsert_schedule_execution(
                &ex.execution_id,
                &ex.schedule_id,
                &ex.triggered_at.to_rfc3339(),
                &ex.status.to_string(),
                &data,
            )
            .await
            .map_err(|e| PersistenceError::new(e.to_string()))?;
        if self.history_retention_limit > 0 {
            store
                .prune_schedule_executions(&ex.schedule_id, self.history_retention_limit)
                .await
                .map_err(|e| PersistenceError::new(e.to_string()))?;
        }
        Ok(())
    }

    fn occurrence_store(&self) -> Result<&Store, PersistenceError> {
        self.store.as_deref().ok_or_else(|| {
            PersistenceError::new("SQLite storage is required for durable one-time scheduling")
        })
    }
}

fn row_to_occurrence(
    row: &ScheduleOccurrenceRecord,
) -> Result<OneTimeOccurrence, PersistenceError> {
    let state = row
        .state
        .parse::<OneTimeOccurrenceState>()
        .map_err(|error| PersistenceError::new(error.to_string()))?;
    let occurrence = OneTimeOccurrence {
        id: row.id.clone(),
        schedule_id: row.schedule_id.clone(),
        execution_id: row.execution_id.clone(),
        triggered_at: row
            .triggered_at
            .parse()
            .map_err(|_| PersistenceError::new("invalid occurrence trigger timestamp"))?,
        state,
        owner_id: row.owner_id.clone(),
        lease_expires_at: row
            .lease_expires_at
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| PersistenceError::new("invalid occurrence lease timestamp"))?,
        recovery_detail: row.recovery_detail.clone(),
    };
    occurrence
        .validate()
        .map_err(|error| PersistenceError::new(error.to_string()))?;

    validate_row_execution(row, &occurrence)?;
    Ok(occurrence)
}

fn validate_row_execution(
    row: &ScheduleOccurrenceRecord,
    occurrence: &OneTimeOccurrence,
) -> Result<Option<ScheduleExecution>, PersistenceError> {
    let expected_status = match occurrence.state {
        OneTimeOccurrenceState::Reserved => "pending",
        OneTimeOccurrenceState::Running => "running",
        OneTimeOccurrenceState::Completed => "completed",
        OneTimeOccurrenceState::Failed => "failed",
        OneTimeOccurrenceState::Cancelled => "cancelled",
    };
    match (&row.execution_status, &row.execution_data_json) {
        (None, None) if occurrence.terminal() => Ok(None),
        (None, None) => {
            Err(PersistenceError::new(
                "non-terminal occurrence is missing its execution",
            ))
        }
        (Some(_), None) | (None, Some(_)) => {
            Err(PersistenceError::new(
                "occurrence execution record is incomplete",
            ))
        }
        (Some(actual), Some(_)) if actual != expected_status => {
            Err(PersistenceError::new(
                "occurrence and execution states do not match",
            ))
        }
        (Some(_), Some(data)) => {
            let execution: ScheduleExecution = serde_json::from_str(data)
                .map_err(|_| PersistenceError::new("invalid occurrence execution data"))?;
            if execution.execution_id != row.execution_id
                || execution.schedule_id != row.schedule_id
                || execution.triggered_at != occurrence.triggered_at
                || execution.status.to_string() != expected_status
            {
                return Err(PersistenceError::new(
                    "occurrence and execution identities do not match",
                ));
            }
            Ok(Some(execution))
        }
    }
}

#[async_trait]
impl SchedulerPersistence for CampaignSchedulerPersistence {
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
    async fn update_schedule(&self, schedule: &Schedule) -> Result<(), PersistenceError> {
        self.schedules
            .upsert(schedule)
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))
    }

    async fn executions_started_since(
        &self,
        schedule_id: &str,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, PersistenceError> {
        let Some(store) = &self.store else {
            return Ok(0);
        };
        store
            .count_schedule_executions_since(schedule_id, &since.to_rfc3339())
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))
    }

    async fn reserve_one_time_occurrence(
        &self,
        occurrence: &OneTimeOccurrence,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeReservation, PersistenceError> {
        let store = self.occurrence_store()?;
        let execution_data_json = serde_json::to_string(execution)
            .map_err(|error| PersistenceError::new(error.to_string()))?;
        let new = NewScheduleOccurrence {
            id: occurrence.id.clone(),
            schedule_id: occurrence.schedule_id.clone(),
            execution_id: occurrence.execution_id.clone(),
            triggered_at: occurrence.triggered_at.to_rfc3339(),
            owner_id: occurrence.owner_id.clone(),
            lease_expires_at: occurrence
                .lease_expires_at
                .ok_or_else(|| PersistenceError::new("reservation lease is missing"))?
                .to_rfc3339(),
            execution_status: execution.status.to_string(),
            execution_data_json,
        };
        match store
            .reserve_schedule_occurrence(&new)
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))?
        {
            ScheduleOccurrenceReservation::Reserved(row) => {
                row_to_occurrence(&row).map(OneTimeReservation::Reserved)
            }
            ScheduleOccurrenceReservation::Existing(row) => {
                row_to_occurrence(&row).map(OneTimeReservation::Existing)
            }
        }
    }

    async fn transition_one_time_occurrence(
        &self,
        transition: &OneTimeOccurrenceTransition,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeTransitionResult, PersistenceError> {
        let store = self.occurrence_store()?;
        let request = ScheduleOccurrenceTransition {
            occurrence_id: transition.occurrence_id.clone(),
            schedule_id: transition.schedule_id.clone(),
            execution_id: transition.execution_id.clone(),
            owner_id: transition.owner_id.clone(),
            from_state: transition.from.to_string(),
            to_state: transition.to.to_string(),
            lease_expires_at: transition
                .lease_expires_at
                .map(|lease_expires_at| lease_expires_at.to_rfc3339()),
            recovery_detail: transition.recovery_detail.clone(),
            execution_status: execution.status.to_string(),
            execution_data_json: serde_json::to_string(execution)
                .map_err(|error| PersistenceError::new(error.to_string()))?,
        };
        match store
            .transition_schedule_occurrence(&request)
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))?
        {
            ScheduleOccurrenceTransitionResult::Applied(row) => {
                row_to_occurrence(&row).map(OneTimeTransitionResult::Applied)
            }
            ScheduleOccurrenceTransitionResult::Idempotent(row) => {
                row_to_occurrence(&row).map(OneTimeTransitionResult::Idempotent)
            }
            ScheduleOccurrenceTransitionResult::Conflict(row) => {
                row_to_occurrence(&row).map(OneTimeTransitionResult::Conflict)
            }
            ScheduleOccurrenceTransitionResult::Missing => Ok(OneTimeTransitionResult::Missing),
        }
    }

    async fn renew_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        lease_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, PersistenceError> {
        self.occurrence_store()?
            .renew_schedule_occurrence_lease(
                occurrence_id,
                owner_id,
                &lease_expires_at.to_rfc3339(),
            )
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))
    }

    async fn release_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        released_at: chrono::DateTime<chrono::Utc>,
        recovery_detail: &str,
    ) -> Result<bool, PersistenceError> {
        self.occurrence_store()?
            .release_schedule_occurrence_lease(
                occurrence_id,
                owner_id,
                &released_at.to_rfc3339(),
                recovery_detail,
            )
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))
    }

    async fn load_one_time_occurrences(&self) -> Result<Vec<OneTimeOccurrence>, PersistenceError> {
        self.occurrence_store()?
            .list_schedule_occurrences()
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))?
            .iter()
            .map(row_to_occurrence)
            .collect()
    }

    async fn get_one_time_occurrence(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<OneTimeOccurrence>, PersistenceError> {
        self.occurrence_store()?
            .schedule_occurrence(occurrence_id)
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))?
            .as_ref()
            .map(row_to_occurrence)
            .transpose()
    }

    async fn get_one_time_execution(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<ScheduleExecution>, PersistenceError> {
        let Some(row) = self
            .occurrence_store()?
            .schedule_occurrence(occurrence_id)
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))?
        else {
            return Ok(None);
        };
        let occurrence = row_to_occurrence(&row)?;
        validate_row_execution(&row, &occurrence)
    }

    async fn acknowledge_one_time_occurrence(
        &self,
        occurrence_id: &str,
        acknowledged_at: chrono::DateTime<chrono::Utc>,
        recovery_detail: &str,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeAcknowledgement, PersistenceError> {
        let execution_data_json = serde_json::to_string(execution)
            .map_err(|error| PersistenceError::new(error.to_string()))?;
        match self
            .occurrence_store()?
            .acknowledge_schedule_occurrence(
                occurrence_id,
                &acknowledged_at.to_rfc3339(),
                recovery_detail,
                &execution.status.to_string(),
                &execution_data_json,
            )
            .await
            .map_err(|error| PersistenceError::new(error.to_string()))?
        {
            ScheduleOccurrenceAcknowledgement::Acknowledged(row) => {
                row_to_occurrence(&row).map(OneTimeAcknowledgement::Acknowledged)
            }
            ScheduleOccurrenceAcknowledgement::AlreadyCancelled(row) => {
                row_to_occurrence(&row).map(OneTimeAcknowledgement::AlreadyCancelled)
            }
            ScheduleOccurrenceAcknowledgement::Conflict(row) => {
                row_to_occurrence(&row).map(OneTimeAcknowledgement::Conflict)
            }
            ScheduleOccurrenceAcknowledgement::Missing => Ok(OneTimeAcknowledgement::Missing),
        }
    }
}

/// How often the scheduler evaluates triggers.
const TICK: Duration = Duration::from_secs(30);
/// Constant `workflow_id` for all fuzz-campaign schedules (the dispatcher reads
/// the campaign from `parameter_values`, not the id).
const CAMPAIGN_KIND: &str = "fuzz-campaign";

/// Event type emitted when triage completes with newly classified crashes.
pub const EVENT_CRASH_FOUND: &str = "crash.found";
/// Event type emitted when a fuzz run terminates successfully (including a
/// cooperative cancellation, which is carried in the payload).
pub const EVENT_RUN_COMPLETED: &str = "run.completed";
/// Event type emitted when a started fuzz run terminates with a failure.
pub const EVENT_RUN_FAILED: &str = "run.failed";

/// Every event type an event-driven schedule may listen for.
///
/// These are the events the service genuinely emits today; schedule creation
/// rejects anything else so a typo can never silently arm a schedule that can
/// never fire.
pub const KNOWN_EVENT_TYPES: &[&str] = &[EVENT_CRASH_FOUND, EVENT_RUN_COMPLETED, EVENT_RUN_FAILED];

/// Parameters for a scheduled fuzz campaign (stored in `Schedule.parameter_values`).
///
/// A campaign is a *portfolio*: `target: None` fuzzes every promoted target in the
/// project, rotating priority-first across fires; `Some` pins one target (the
/// original behaviour). Either way it only ever runs a human-promoted harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignParams {
    pub project: String,
    /// `None` = rotate through all promoted targets in the project; `Some` = a
    /// single fixed target. Deserialises an old bare-string `target` as `Some`.
    #[serde(default)]
    pub target: Option<String>,
    /// Engine for a single-target campaign (display only in all-targets mode,
    /// where each promoted harness carries its own).
    #[serde(default)]
    pub engine: String,
    /// Target language, taken from the promoted harness at schedule time.
    /// Defaults to C so schedules persisted before this field existed still load
    /// (they could only ever have been C -- the dispatcher hardcoded it).
    #[serde(default = "default_lang")]
    pub lang: String,
    /// Duration of one target's fuzz run.
    pub duration_secs: u64,
    /// Budget: stop after this many completed runs (`None` = unbounded).
    #[serde(default)]
    pub max_runs: Option<u32>,
    /// Budget: stop after this much measured campaign work (`None` = unbounded).
    #[serde(default)]
    pub max_total_secs: Option<u64>,
    /// The owning schedule's id, injected at creation so the headless dispatcher
    /// (which is handed only the constant workflow kind) can key rotation and
    /// budget state. Empty for legacy schedules, which never rotate.
    #[serde(default)]
    pub schedule_id: String,
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
            target: None,
            engine: String::new(),
            lang: default_lang(),
            duration_secs: 0,
            max_runs: None,
            max_total_secs: None,
            schedule_id: String::new(),
        }
    }
}

/// Order promoted targets by priority: highest fit score first, then symbol, then
/// engine, so the rotation is deterministic and high-value targets lead each cycle.
fn priority_order(mut targets: Vec<SchedulableTarget>) -> Vec<SchedulableTarget> {
    targets.sort_by(|a, b| {
        b.fit_score
            .partial_cmp(&a.fit_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.target.cmp(&b.target))
            .then_with(|| a.engine.cmp(&b.engine))
    });
    targets
}

/// The target a given fire fuzzes: round-robin over the priority order, so every
/// target is eventually covered and the cursor survives restarts.
fn rotate(ordered: &[SchedulableTarget], cursor: u64) -> Option<&SchedulableTarget> {
    if ordered.is_empty() {
        return None;
    }
    let idx = usize::try_from(cursor % ordered.len() as u64).unwrap_or(0);
    ordered.get(idx)
}

/// Whether the campaign has spent its budget; the message names which limit hit.
fn budget_skip_reason(state: &CampaignRuntimeState, params: &CampaignParams) -> Option<String> {
    if let Some(max) = params.max_runs {
        if state.runs_done >= max {
            return Some(format!("budget reached: {max} run(s) completed"));
        }
    }
    if let Some(max) = params.max_total_secs {
        if state.secs_done >= max {
            return Some(format!(
                "budget reached: {}s of the {max}s fuzzing budget spent",
                state.secs_done
            ));
        }
    }
    None
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

fn validate_campaign_fuzzing_policy(params: &CampaignParams) -> Result<(), CampaignSchedulerError> {
    let engine = if params.engine.trim().is_empty() {
        None
    } else {
        Some(
            params
                .engine
                .parse::<EngineKind>()
                .map_err(CampaignSchedulerError::Validation)?,
        )
    };
    crate::config::resolve_fuzzing_run(engine, Some(params.duration_secs))
        .map(|_| ())
        .map_err(CampaignSchedulerError::Validation)
}

/// A presentation-friendly view of a scheduled campaign for the GUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignDurabilityStatus {
    Ready,
    Consumed,
    RecoveryRequired,
}

/// Presentation-safe recovery evidence for an ambiguous one-time occurrence.
#[derive(Debug, Clone, Serialize)]
pub struct OneTimeRecoveryView {
    pub occurrence_id: String,
    pub schedule_id: String,
    pub schedule_name: Option<String>,
    pub execution_id: String,
    pub triggered_at: String,
    pub state: String,
    pub recovery_detail: Option<String>,
    pub schedule_exists: bool,
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
    /// `None` = a portfolio campaign rotating through all promoted targets.
    pub target: Option<String>,
    pub engine: String,
    /// Canonical language id the campaign runs as (`c`, `cpp`, `rust`).
    pub lang: String,
    pub duration_secs: u64,
    /// Budget: max completed runs, if bounded.
    pub max_runs: Option<u32>,
    /// Budget: max cumulative fuzz seconds, if bounded.
    pub max_total_secs: Option<u64>,
    /// Completed runs so far (progress against the budget).
    pub runs_done: u32,
    /// Cumulative measured campaign-work seconds so far.
    pub secs_done: u64,
    /// Last time the campaign fired (RFC3339), if ever.
    pub last_fire: Option<String>,
    /// Durability state for one-time dispatch admission and recovery.
    pub durability_status: CampaignDurabilityStatus,
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
    /// "pending" | "running" | "completed" | "failed" | "skipped" | "cancelled".
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
        max_runs: params.max_runs,
        max_total_secs: params.max_total_secs,
        // Progress is filled in by `list_views` from the state store.
        runs_done: 0,
        secs_done: 0,
        last_fire: schedule.last_fire.map(|t| t.to_rfc3339()),
        durability_status: CampaignDurabilityStatus::Ready,
    }
}

/// Build a [`TriggerConfig`] from a kind + value pair (the GUI's trigger form).
///
/// - `interval` + seconds, e.g. `("interval", "3600")`
/// - `cron` + expression, e.g. `("cron", "0 2 * * *")`
/// - `once` + RFC3339 timestamp, e.g. `("once", "2026-07-01T02:00:00Z")`
/// - `event` + event type, e.g. `("event", "crash.found")` — fires when the
///   service emits that event; see [`KNOWN_EVENT_TYPES`].
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
            let value = value.trim();
            if value.is_empty() {
                return Err("cron expression is empty".to_owned());
            }
            let (timezone, expression) = if let Some(rest) = value.strip_prefix("CRON_TZ=") {
                let Some((timezone, expression)) = rest.split_once(char::is_whitespace) else {
                    return Err(
                        "timezone cron must use CRON_TZ=<IANA zone> <expression>".to_owned()
                    );
                };
                let timezone = timezone.trim();
                let expression = expression.trim();
                if timezone.is_empty() || expression.is_empty() {
                    return Err(
                        "timezone cron must use CRON_TZ=<IANA zone> <expression>".to_owned()
                    );
                }
                (timezone, expression)
            } else {
                ("UTC", value)
            };
            let cron = hf_scheduler::CronSchedule::new(expression).with_timezone(timezone);
            if !cron.is_timezone_valid() {
                return Err(format!("unknown cron timezone: {timezone}"));
            }
            if !cron.is_valid() {
                return Err(format!("invalid cron expression: {expression:?}"));
            }
            Ok(TriggerConfig::Cron {
                expression: expression.to_owned(),
                timezone: timezone.to_owned(),
            })
        }
        "once" => {
            let at = value
                .trim()
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_err(|e| format!("invalid RFC3339 time {value:?}: {e}"))?;
            Ok(TriggerConfig::OneTime { at })
        }
        "event" => {
            let event_type = value.trim();
            if event_type.is_empty() {
                return Err("event type is empty".to_owned());
            }
            if !KNOWN_EVENT_TYPES.contains(&event_type) {
                return Err(format!(
                    "unknown event type: {event_type:?} (known: {})",
                    KNOWN_EVENT_TYPES.join(", ")
                ));
            }
            Ok(TriggerConfig::Event {
                event_type: event_type.to_owned(),
                debounce_secs: 0,
                filter: None,
            })
        }
        other => Err(format!("unknown trigger kind: {other}")),
    }
}

/// Runs due campaigns headlessly through the service container.
///
/// A portfolio campaign resolves the project's promoted targets on each fire and
/// fuzzes the next one in priority-weighted rotation, under a global concurrency
/// cap and a per-campaign budget. Only promoted harnesses are ever run.
struct FuzzCampaignDispatcher {
    container: ServiceContainer,
    state: Arc<CampaignStateStore>,
    gate: Arc<ConcurrencyGate>,
    notifier: NotifierSlot,
    /// Weak so the manager <-> dispatcher cycle does not leak; used to pause a
    /// campaign once its budget is spent.
    manager: Weak<SchedulerManager>,
}

/// A fire that ran nothing (budget spent or concurrency full). Recorded as a
/// completed execution whose summary explains why; it never advances state.
fn skip_result(reason: &str) -> DispatchResult {
    DispatchResult {
        success: true,
        summary: format!("skipped: {reason}"),
        output: serde_json::json!({ "skipped": true, "reason": reason }),
        duration_ms: 0,
        error: None,
    }
}

impl FuzzCampaignDispatcher {
    /// The promoted targets this campaign may fuzz, in priority order. A single
    /// campaign narrows to its one target; a portfolio takes them all.
    async fn resolve_targets(
        &self,
        params: &CampaignParams,
    ) -> Result<Vec<SchedulableTarget>, String> {
        let all = self
            .container
            .schedulable_targets(Path::new(&params.project))
            .await
            .map_err(|e| e.to_string())?;
        let selected: Vec<SchedulableTarget> =
            match params.target.as_deref().filter(|t| !t.is_empty()) {
                Some(sym) => all.into_iter().filter(|t| t.target == sym).collect(),
                None => all,
            };
        Ok(priority_order(selected))
    }

    /// Best-effort follow-up when a scheduled run finds crashes: save a report
    /// draft, push to `DefectDojo` if configured, and notify the UI. Failures are
    /// logged, never propagated -- the campaign already did its job.
    async fn on_crashes(&self, params: &CampaignParams, target: &str, crashes: usize) {
        let project = Path::new(&params.project);
        let report_saved = self.save_crash_report(project, target, crashes).await;

        let defectdojo_pushed = if self.container.defectdojo_configured() {
            match self
                .container
                .push_to_defectdojo(project, Some(target))
                .await
            {
                Ok(outcome) => outcome.findings_pushed > 0,
                Err(e) => {
                    tracing::warn!("scheduled campaign DefectDojo push failed: {e}");
                    false
                }
            }
        } else {
            false
        };

        // Clone the callback out of the lock, then call it unlocked.
        let notifier = self.notifier.lock().ok().and_then(|slot| slot.clone());
        if let Some(notify) = notifier {
            notify(CampaignNotice {
                schedule_id: params.schedule_id.clone(),
                campaign: params.schedule_id.clone(),
                project: params.project.clone(),
                target: target.to_owned(),
                crashes,
                report_saved,
                defectdojo_pushed,
            });
        }
    }

    async fn save_crash_report(&self, project: &Path, target: &str, crashes: usize) -> bool {
        let markdown = match self.container.generate_report(project, target).await {
            Ok(md) => md,
            Err(e) => {
                tracing::warn!("scheduled campaign report generation failed: {e}");
                return false;
            }
        };
        let title = format!("{target} - {crashes} crash(es) (scheduled)");
        match self.container.save_report_draft(
            None,
            &title,
            &project.to_string_lossy(),
            Some(target),
            "Needs Review",
            &markdown,
        ) {
            Ok(_) => true,
            Err(e) => {
                tracing::warn!("scheduled campaign report save failed: {e}");
                false
            }
        }
    }

    /// Pause a campaign whose budget is spent, so it stops firing skips forever.
    /// Fire-and-forget: dispatch runs after the manager released its store lock.
    fn pause_self(&self, schedule_id: &str) {
        if schedule_id.is_empty() {
            return;
        }
        let manager = self.manager.clone();
        let id = schedule_id.to_owned();
        tokio::spawn(async move {
            if let Some(manager) = manager.upgrade() {
                manager.pause(&id).await;
            }
        });
    }

    /// Advance the target-rotation cursor after a failed fire, best-effort.
    ///
    /// A persistence failure here is logged rather than masking the original
    /// campaign failure; the next fire simply retries the advance.
    fn advance_rotation_after_failure(&self, schedule_id: &str) {
        if let Err(error) = self.state.advance_cursor(schedule_id) {
            tracing::warn!(
                "could not persist rotation advance after a failed fire on {schedule_id}: {error}"
            );
        }
    }
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

        // 1. Budget. Spent -> record one skip and pause, so it stops re-firing.
        let state = self.state.snapshot(&params.schedule_id);
        if let Some(reason) = budget_skip_reason(&state, &params) {
            self.pause_self(&params.schedule_id);
            return Ok(skip_result(&reason));
        }

        // 2. Concurrency. Full -> skip this fire (never queue: short intervals
        // over long runs would pile up unbounded background work).
        let Some(_permit) = self.gate.try_enter() else {
            return Ok(skip_result(&format!(
                "max concurrent campaigns reached ({})",
                self.gate.limit()
            )));
        };

        // 3. Pick the next target in priority rotation (promoted only).
        let targets = match self.resolve_targets(&params).await {
            Ok(t) => t,
            Err(e) => {
                return Ok(DispatchResult {
                    success: false,
                    summary: "could not resolve promoted targets".to_owned(),
                    output: serde_json::Value::Null,
                    duration_ms: 0,
                    error: Some(e),
                });
            }
        };
        let Some(pick) = rotate(&targets, state.cursor).cloned() else {
            let hint = params.target.as_deref().map_or_else(
                || "project has no promoted harness yet".to_owned(),
                |t| format!("target '{t}' has no promoted harness"),
            );
            return Ok(DispatchResult {
                success: false,
                summary: format!("no target to fuzz: {hint}"),
                output: serde_json::Value::Null,
                duration_ms: 0,
                error: Some(hint),
            });
        };
        let (Ok(engine), Ok(lang)) = (
            pick.engine.parse::<EngineKind>(),
            pick.language.parse::<TargetLanguage>(),
        ) else {
            // This target can never run; advance past it so the rotation is not
            // pinned here forever, starving the other promoted targets.
            self.advance_rotation_after_failure(&params.schedule_id);
            return Ok(DispatchResult {
                success: false,
                summary: format!("target '{}' has an unparseable engine/lang", pick.target),
                output: serde_json::Value::Null,
                duration_ms: 0,
                error: Some(format!("{}/{}", pick.engine, pick.language)),
            });
        };

        tracing::info!(
            "campaign {workflow_id} [{}] firing: {} via {engine:?} ({lang:?}) for {}s ({} of {} target(s))",
            params.schedule_id,
            pick.target,
            params.duration_secs,
            (state.cursor % targets.len() as u64) + 1,
            targets.len(),
        );

        // 4. Run one promoted target. A successful outcome advances the rotation
        // and charges its actual iterations/measured elapsed time; a failed fire
        // advances the cursor only (no charge) so a target that keeps failing
        // yields to the next instead of pinning the rotation.
        let started = std::time::Instant::now();
        let result = self
            .container
            .run_campaign(
                Path::new(&params.project),
                Some(&pick.target),
                engine,
                lang,
                params.duration_secs,
                3,
            )
            .await;
        let elapsed = started.elapsed();
        let duration_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);

        match result {
            Ok(outcome)
                if outcome.termination == hf_core::runtime::CommandTermination::Cancelled =>
            {
                Ok(DispatchResult {
                    success: false,
                    summary: format!("campaign cancelled on {}", outcome.target),
                    output: serde_json::json!({
                        "target": outcome.target,
                        "edges": outcome.edges,
                        "iterations": outcome.iterations,
                        "termination": outcome.termination,
                    }),
                    duration_ms,
                    error: Some("campaign cancelled".to_owned()),
                })
            }
            Ok(outcome) => {
                let advanced = self
                    .state
                    .record_success(&params.schedule_id, outcome.iterations, elapsed)
                    .map_err(|error| {
                        DispatchError::Internal(format!(
                            "campaign completed but progress could not be persisted: {error}"
                        ))
                    })?;
                if outcome.crashes > 0 {
                    self.on_crashes(&params, &outcome.target, outcome.crashes)
                        .await;
                }
                let budget = budget_note(&advanced, &params);
                Ok(DispatchResult {
                    success: true,
                    summary: format!(
                        "{} crash(es), {} edges over {} iteration(s) on {}{}{budget}",
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
                        "auto_reverts": outcome.auto_reverts,
                        "termination": outcome.termination,
                        "runs_done": advanced.runs_done,
                    }),
                    duration_ms,
                    error: None,
                })
            }
            Err(e) => {
                // The target's harness could not build/run; advance the cursor so
                // the next fire tries a different target rather than re-picking
                // this one forever.
                self.advance_rotation_after_failure(&params.schedule_id);
                Ok(DispatchResult {
                    success: false,
                    summary: format!("campaign failed on {}", pick.target),
                    output: serde_json::Value::Null,
                    duration_ms,
                    error: Some(e.to_string()),
                })
            }
        }
    }
}

/// A short " -- N/M runs" suffix for the history summary when a budget is set.
fn budget_note(state: &CampaignRuntimeState, params: &CampaignParams) -> String {
    if let Some(max) = params.max_runs {
        format!(" -- {}/{max} runs", state.runs_done)
    } else if let Some(max) = params.max_total_secs {
        format!(" -- {}/{max}s", state.secs_done)
    } else {
        String::new()
    }
}

/// Read-only concurrency limits safe to expose through presentation transports.
/// The two source limits remain independent; the effective fuzz-run ceiling is
/// their minimum because every active fuzz run consumes one slot from each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CampaignConcurrencyLimits {
    /// Live, sidecar-persisted limit enforced by the campaign gate.
    pub active_fuzz_campaign_limit: usize,
    /// Startup limit enforced by the scheduler workflow-dispatch semaphore.
    pub scheduler_workflow_dispatch_limit: usize,
    /// Maximum concurrent fuzz runs permitted by both independent limits.
    pub effective_max_concurrent_fuzz_runs: usize,
}

/// Manages scheduled fuzz campaigns: a background tick loop plus JSON-persisted
/// schedules.
pub struct CampaignScheduler {
    manager: Arc<SchedulerManager>,
    schedules: Arc<ScheduleFileStore>,
    /// Database for persisted execution history (when configured).
    store: Option<Arc<Store>>,
    /// Durable one-time occurrence journal adapter shared with the manager.
    occurrences: Arc<CampaignSchedulerPersistence>,
    /// Rotation cursor + budget consumption per campaign (JSON sidecar).
    state: Arc<CampaignStateStore>,
    /// Live cap on active fuzz-campaign runs.
    gate: Arc<ConcurrencyGate>,
    /// Scheduler workflow-dispatch cap resolved once at startup.
    scheduler_workflow_dispatch_limit: usize,
    /// Late-bound crash notifier (filled by the desktop shell after setup).
    notifier: NotifierSlot,
}

/// Durable scheduler startup or mutation error.
#[derive(Debug, thiserror::Error)]
pub enum CampaignSchedulerError {
    /// A schedule requests an invalid or disabled fuzzing policy value.
    #[error("invalid campaign settings: {0}")]
    Validation(String),
    /// Schedule or campaign sidecar I/O/JSON failure.
    #[error(transparent)]
    State(#[from] StateFileError),
    /// Persisted execution history could not be inspected.
    #[error("scheduler history error: {0}")]
    History(String),
    /// A persisted history timestamp was invalid.
    #[error("invalid persisted last-fire timestamp for schedule {schedule_id}: {value}")]
    InvalidLastFire { schedule_id: String, value: String },
    #[error("durable one-time scheduling is unavailable: {0}")]
    DurabilityUnavailable(String),
    #[error("one-time occurrence journal error: {0}")]
    OccurrenceJournal(String),
    #[error("one-time occurrence not found: {0}")]
    OccurrenceNotFound(String),
    #[error("one-time occurrence conflict: {0}")]
    OccurrenceConflict(String),
}

impl From<CampaignSchedulerError> for ClassifiedError {
    fn from(error: CampaignSchedulerError) -> Self {
        match error {
            CampaignSchedulerError::Validation(message) => Self::Validation(message),
            other => Self::Storage(other.to_string()),
        }
    }
}

const JOURNAL_UNAVAILABLE_REASON: &str = "one-time occurrence journal is unavailable";
const JOURNAL_CORRUPT_REASON: &str = "one-time occurrence journal is corrupt";
const CURSOR_RECONCILIATION_REASON: &str = "one-time schedule cursor reconciliation failed";

fn occurrence_journal_error(_error: PersistenceError) -> CampaignSchedulerError {
    CampaignSchedulerError::OccurrenceJournal(
        "durable occurrence journal operation failed".to_owned(),
    )
}

/// The campaign runtime-state sidecar lives beside `schedules.json`.
fn campaign_state_path(schedules_path: &Path) -> PathBuf {
    schedules_path.parent().map_or_else(
        || PathBuf::from("campaign_state.json"),
        |p| p.join("campaign_state.json"),
    )
}

impl CampaignScheduler {
    /// Start the scheduler: install the dispatcher, reload persisted schedules,
    /// and begin ticking. Campaigns run with permissive guardrails -- creating a
    /// schedule is the human authorization for its future headless runs.
    ///
    /// `notifier` (set by the desktop shell) is called when a scheduled run finds
    /// crashes, so the UI can toast; pass `None` for headless CLI/web.
    ///
    /// # Panics
    /// Panics when persisted schedule, campaign, or execution-history state is
    /// corrupt or unreadable. Use [`Self::try_start`] to handle the error.
    pub async fn start(
        container: ServiceContainer,
        store_path: PathBuf,
        notifier: Option<CampaignNotifier>,
    ) -> Self {
        match Self::try_start(container, store_path, notifier).await {
            Ok(scheduler) => scheduler,
            Err(error) => panic!("campaign scheduler cannot start: {error}"),
        }
    }

    /// Start the scheduler while returning corrupt or unreadable persisted state
    /// to the caller instead of silently resetting it.
    ///
    /// # Errors
    /// Returns a durable-state or history error before the scheduler begins
    /// ticking.
    pub async fn try_start(
        container: ServiceContainer,
        store_path: PathBuf,
        notifier: Option<CampaignNotifier>,
    ) -> Result<Self, CampaignSchedulerError> {
        let scheduler_config = crate::config::effective_scheduler_config();
        let history_retention_limit = scheduler_config.history_retention_limit;
        let scheduler_workflow_dispatch_limit = scheduler_config.max_concurrent_executions.max(1);
        let manager = Arc::new(SchedulerManager::new(scheduler_config));
        let schedules = Arc::new(ScheduleFileStore::new(store_path.clone()));
        // Grab the DB handle (for persisted execution history) before the
        // container is moved into the dispatcher.
        let store = container.store().cloned();
        let state = Arc::new(CampaignStateStore::try_load(campaign_state_path(
            &store_path,
        ))?);
        let gate = Arc::new(ConcurrencyGate::new(state.max_concurrent()));
        let notifier: NotifierSlot = Arc::new(Mutex::new(notifier));
        // Let every clone of the service container emit scheduler events
        // (crash found, run terminated) into this manager's event bridge.
        container.bind_scheduler_events(&manager);
        let dispatcher = Arc::new(FuzzCampaignDispatcher {
            container: container.with_guardrails(Guardrails::permissive()),
            state: Arc::clone(&state),
            gate: Arc::clone(&gate),
            notifier: Arc::clone(&notifier),
            manager: Arc::downgrade(&manager),
        });
        manager.set_dispatcher(dispatcher).await;
        let occurrences = Arc::new(CampaignSchedulerPersistence {
            store: store.clone(),
            schedules: Arc::clone(&schedules),
            history_retention_limit,
        });
        manager
            .set_persistence(Arc::clone(&occurrences) as Arc<dyn SchedulerPersistence>)
            .await;

        let mut loaded = schedules.load()?;
        let mut restored = false;
        let mut receipt_cursor_restored = false;
        let journal_readable = if let Some(store) = &store {
            match store.list_schedule_occurrences().await {
                Ok(rows) => {
                    let receipts = rows
                        .iter()
                        .map(row_to_occurrence)
                        .collect::<Result<Vec<_>, _>>();
                    match receipts {
                        Ok(receipts)
                            if receipts.iter().all(|receipt| {
                                loaded
                                    .iter()
                                    .find(|schedule| schedule.id == receipt.schedule_id)
                                    .is_none_or(|schedule| {
                                        matches!(schedule.trigger, TriggerConfig::OneTime { .. })
                                    })
                            }) =>
                        {
                            let now = chrono::Utc::now();
                            for schedule in &mut loaded {
                                if !matches!(schedule.trigger, TriggerConfig::OneTime { .. }) {
                                    continue;
                                }
                                let receipt = receipts
                                    .iter()
                                    .find(|receipt| receipt.schedule_id == schedule.id);
                                match receipt {
                                    Some(receipt) if receipt.recovery_eligible(now) => {
                                        manager.record_expired_one_time_occurrence();
                                        let reconciled = schedule
                                            .last_fire
                                            .map_or(receipt.triggered_at, |last| {
                                                last.max(receipt.triggered_at)
                                            });
                                        if schedule.last_fire != Some(reconciled) {
                                            schedule.last_fire = Some(reconciled);
                                            restored = true;
                                            receipt_cursor_restored = true;
                                        }
                                        manager
                                            .mark_one_time_recovery_required(
                                                &schedule.id,
                                                receipt.recovery_detail.clone().unwrap_or_else(
                                                    || "expired non-terminal occurrence".to_owned(),
                                                ),
                                            )
                                            .await;
                                    }
                                    Some(receipt) => {
                                        let reconciled = schedule
                                            .last_fire
                                            .map_or(receipt.triggered_at, |last| {
                                                last.max(receipt.triggered_at)
                                            });
                                        if schedule.last_fire != Some(reconciled) {
                                            schedule.last_fire = Some(reconciled);
                                            restored = true;
                                            receipt_cursor_restored = true;
                                        }
                                        manager.mark_one_time_consumed(&schedule.id).await;
                                    }
                                    None if schedule.last_fire.is_some() => {
                                        manager.mark_one_time_consumed(&schedule.id).await;
                                    }
                                    None => {}
                                }
                            }
                            true
                        }
                        Ok(_) | Err(_) => {
                            manager.record_corrupt_one_time_journal();
                            manager.block_one_time(JOURNAL_CORRUPT_REASON).await;
                            true
                        }
                    }
                }
                Err(error) => {
                    if matches!(
                        error,
                        StorageError::InvalidData(_)
                            | StorageError::Serde(_)
                            | StorageError::Timestamp(_)
                    ) {
                        manager.record_corrupt_one_time_journal();
                        manager.block_one_time(JOURNAL_CORRUPT_REASON).await;
                        true
                    } else {
                        manager.block_one_time(JOURNAL_UNAVAILABLE_REASON).await;
                        false
                    }
                }
            }
        } else {
            manager
                .block_one_time("SQLite storage is not configured")
                .await;
            false
        };

        if let Some(store) = &store {
            let fires = if journal_readable {
                store
                    .latest_schedule_fires()
                    .await
                    .map_err(|error| CampaignSchedulerError::History(error.to_string()))?
            } else {
                Vec::new()
            };
            let fires: std::collections::HashMap<_, _> = fires.into_iter().collect();
            for schedule in &mut loaded {
                if !matches!(schedule.trigger, TriggerConfig::OneTime { .. })
                    && schedule.last_fire.is_none()
                {
                    if let Some(value) = fires.get(&schedule.id) {
                        schedule.last_fire = Some(value.parse().map_err(|_| {
                            CampaignSchedulerError::InvalidLastFire {
                                schedule_id: schedule.id.clone(),
                                value: value.clone(),
                            }
                        })?);
                        restored = true;
                    }
                }
            }
        }
        if restored {
            if let Err(error) = schedules.replace(&loaded).await {
                if receipt_cursor_restored {
                    manager.block_one_time(CURSOR_RECONCILIATION_REASON).await;
                } else {
                    return Err(error.into());
                }
            }
        }
        for schedule in loaded {
            manager.register(schedule).await;
        }
        manager.start(TICK).await;
        Ok(Self {
            manager,
            schedules,
            store,
            occurrences,
            state,
            gate,
            scheduler_workflow_dispatch_limit,
            notifier,
        })
    }

    /// Bind the crash notifier after construction (the desktop shell only has an
    /// `AppHandle` to emit with once Tauri has set up).
    pub fn set_notifier(&self, notifier: CampaignNotifier) {
        if let Ok(mut slot) = self.notifier.lock() {
            *slot = Some(notifier);
        }
    }

    /// The live active fuzz-campaign limit enforced by the campaign gate.
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.gate.limit()
    }

    /// Return both independently configured concurrency limits and the
    /// effective ceiling that applies to active fuzz runs.
    #[must_use]
    pub fn concurrency_limits(&self) -> CampaignConcurrencyLimits {
        let active_fuzz_campaign_limit = self.gate.limit();
        CampaignConcurrencyLimits {
            active_fuzz_campaign_limit,
            scheduler_workflow_dispatch_limit: self.scheduler_workflow_dispatch_limit,
            effective_max_concurrent_fuzz_runs: active_fuzz_campaign_limit
                .min(self.scheduler_workflow_dispatch_limit),
        }
    }

    /// Set the active fuzz-campaign limit (persisted; applies immediately).
    ///
    /// # Panics
    /// Panics when the new limit cannot be persisted. Use
    /// [`Self::try_set_max_concurrent`] to handle the error.
    pub fn set_max_concurrent(&self, n: usize) {
        if let Err(error) = self.try_set_max_concurrent(n) {
            panic!("campaign concurrency cannot be persisted: {error}");
        }
    }

    /// Set the active fuzz-campaign limit transactionally.
    ///
    /// # Errors
    /// Returns a state-file error without applying the new live limit when the
    /// sidecar cannot be persisted.
    pub fn try_set_max_concurrent(&self, n: usize) -> Result<(), CampaignSchedulerError> {
        self.state.try_set_max_concurrent(n)?;
        self.gate.set_limit(self.state.max_concurrent());
        Ok(())
    }

    /// All scheduled campaigns.
    pub async fn list(&self) -> Vec<Schedule> {
        self.manager.list_schedules().await
    }

    /// All scheduled campaigns as GUI-friendly views. After a restart the
    /// in-memory `last_fire` is gone, so it is back-filled from the latest
    /// persisted execution per schedule.
    ///
    /// # Errors
    /// Returns a history error when the configured database cannot supply the
    /// persisted last-fire cursors.
    pub async fn list_views(&self) -> Result<Vec<CampaignView>, CampaignSchedulerError> {
        let schedules = self.manager.list_schedules().await;
        let fires: std::collections::HashMap<String, String> = match &self.store {
            Some(store) => store
                .latest_schedule_fires()
                .await
                .map_err(|error| CampaignSchedulerError::History(error.to_string()))?
                .into_iter()
                .collect(),
            None => std::collections::HashMap::new(),
        };
        let mut views = Vec::with_capacity(schedules.len());
        for schedule in &schedules {
            let mut view = view_of(schedule);
            if view.last_fire.is_none() {
                view.last_fire = fires.get(&schedule.id).cloned();
            }
            let progress = self.state.snapshot(&schedule.id);
            view.runs_done = progress.runs_done;
            view.secs_done = progress.secs_done;
            if matches!(&schedule.trigger, TriggerConfig::OneTime { .. }) {
                view.durability_status =
                    match self.manager.one_time_runtime_status(&schedule.id).await {
                        OneTimeRuntimeStatus::Ready if schedule.last_fire.is_some() => {
                            CampaignDurabilityStatus::Consumed
                        }
                        OneTimeRuntimeStatus::Ready => CampaignDurabilityStatus::Ready,
                        OneTimeRuntimeStatus::Consumed => CampaignDurabilityStatus::Consumed,
                        OneTimeRuntimeStatus::RecoveryRequired { .. } => {
                            CampaignDurabilityStatus::RecoveryRequired
                        }
                    };
            }
            views.push(view);
        }
        Ok(views)
    }

    /// List expired, non-terminal one-time receipts that require acknowledgement.
    ///
    /// # Errors
    /// Returns an occurrence-journal error when durable evidence cannot be read
    /// or validated.
    pub async fn list_one_time_recoveries(
        &self,
    ) -> Result<Vec<OneTimeRecoveryView>, CampaignSchedulerError> {
        let schedules = self.manager.list_schedules().await;
        let names: std::collections::HashMap<_, _> = schedules
            .iter()
            .map(|schedule| (schedule.id.clone(), schedule.name.clone()))
            .collect();
        let now = chrono::Utc::now();
        let mut recoveries: Vec<_> = self
            .occurrences
            .load_one_time_occurrences()
            .await
            .map_err(occurrence_journal_error)?
            .into_iter()
            .filter(|occurrence| occurrence.recovery_eligible(now))
            .map(|occurrence| OneTimeRecoveryView {
                schedule_name: names.get(&occurrence.schedule_id).cloned(),
                schedule_exists: names.contains_key(&occurrence.schedule_id),
                occurrence_id: occurrence.id,
                schedule_id: occurrence.schedule_id,
                execution_id: occurrence.execution_id,
                triggered_at: occurrence.triggered_at.to_rfc3339(),
                state: occurrence.state.to_string(),
                recovery_detail: occurrence.recovery_detail,
            })
            .collect();
        recoveries.sort_by(|left, right| {
            left.triggered_at
                .cmp(&right.triggered_at)
                .then_with(|| left.occurrence_id.cmp(&right.occurrence_id))
        });
        Ok(recoveries)
    }

    /// Acknowledge an expired ambiguous outcome as cancelled without adopting
    /// or restarting any prior process.
    ///
    /// # Errors
    /// Returns a not-found, conflict, journal, or schedule-state persistence
    /// error when the cancellation acknowledgement cannot be completed.
    pub async fn acknowledge_one_time_recovery(
        &self,
        occurrence_id: &str,
    ) -> Result<OneTimeRecoveryView, CampaignSchedulerError> {
        let occurrence = self
            .occurrences
            .get_one_time_occurrence(occurrence_id)
            .await
            .map_err(occurrence_journal_error)?
            .ok_or_else(|| CampaignSchedulerError::OccurrenceNotFound(occurrence_id.to_owned()))?;

        if occurrence.state == OneTimeOccurrenceState::Cancelled {
            return self.finish_one_time_acknowledgement(&occurrence).await;
        }
        if self.manager.has_active_occurrence(occurrence_id)
            || !occurrence.recovery_eligible(chrono::Utc::now())
        {
            return Err(CampaignSchedulerError::OccurrenceConflict(
                "the occurrence is terminal or still owns a live lease".to_owned(),
            ));
        }

        let mut execution = self
            .occurrences
            .get_one_time_execution(occurrence_id)
            .await
            .map_err(occurrence_journal_error)?
            .ok_or_else(|| {
                CampaignSchedulerError::OccurrenceJournal(
                    "non-terminal occurrence is missing its execution".to_owned(),
                )
            })?;
        let acknowledged_at = chrono::Utc::now();
        let reason = "operator acknowledged unknown prior outcome as cancelled";
        execution.status = hf_scheduler::ExecutionStatus::Cancelled;
        execution.completed_at = Some(acknowledged_at);
        execution.error_message = Some(reason.to_owned());
        execution.response_summary = serde_json::json!({
            "status": "cancelled",
            "reason": reason,
        });

        let (acknowledged, newly_applied) = match self
            .occurrences
            .acknowledge_one_time_occurrence(occurrence_id, acknowledged_at, reason, &execution)
            .await
            .map_err(occurrence_journal_error)?
        {
            OneTimeAcknowledgement::Acknowledged(occurrence) => (occurrence, true),
            OneTimeAcknowledgement::AlreadyCancelled(occurrence) => (occurrence, false),
            OneTimeAcknowledgement::Conflict(_) => {
                return Err(CampaignSchedulerError::OccurrenceConflict(
                    "the occurrence is terminal or still owns a live lease".to_owned(),
                ));
            }
            OneTimeAcknowledgement::Missing => {
                return Err(CampaignSchedulerError::OccurrenceNotFound(
                    occurrence_id.to_owned(),
                ));
            }
        };
        if newly_applied {
            self.manager.record_one_time_acknowledgement();
        }
        self.finish_one_time_acknowledgement(&acknowledged).await
    }

    async fn finish_one_time_acknowledgement(
        &self,
        occurrence: &OneTimeOccurrence,
    ) -> Result<OneTimeRecoveryView, CampaignSchedulerError> {
        self.manager
            .mark_one_time_consumed(&occurrence.schedule_id)
            .await;
        if let Some(mut schedule) = self.manager.get_schedule(&occurrence.schedule_id).await {
            schedule.last_fire = Some(schedule.last_fire.map_or(occurrence.triggered_at, |last| {
                last.max(occurrence.triggered_at)
            }));
            self.manager.register(schedule).await;
            self.persist().await?;
        }
        Ok(self.recovery_view(occurrence).await)
    }

    async fn recovery_view(&self, occurrence: &OneTimeOccurrence) -> OneTimeRecoveryView {
        let schedule = self.manager.get_schedule(&occurrence.schedule_id).await;
        OneTimeRecoveryView {
            occurrence_id: occurrence.id.clone(),
            schedule_id: occurrence.schedule_id.clone(),
            schedule_name: schedule.as_ref().map(|schedule| schedule.name.clone()),
            execution_id: occurrence.execution_id.clone(),
            triggered_at: occurrence.triggered_at.to_rfc3339(),
            state: occurrence.state.to_string(),
            recovery_detail: occurrence.recovery_detail.clone(),
            schedule_exists: schedule.is_some(),
        }
    }

    /// Recent campaign executions, newest first. Reads persisted history (which
    /// survives restarts) when a database is configured, else the in-memory log.
    ///
    /// # Errors
    /// Returns a history error when configured storage cannot be read or a row
    /// cannot be decoded as a scheduler execution.
    pub async fn recent_executions(
        &self,
        limit: usize,
    ) -> Result<Vec<ExecutionView>, CampaignSchedulerError> {
        if let Some(store) = &self.store {
            let rows = store
                .list_schedule_executions(i64::try_from(limit).unwrap_or(i64::MAX))
                .await
                .map_err(|error| CampaignSchedulerError::History(error.to_string()))?;
            return rows
                .iter()
                .map(|json| {
                    serde_json::from_str::<ScheduleExecution>(json)
                        .map(|execution| view_of_execution(&execution, ""))
                        .map_err(|error| CampaignSchedulerError::History(error.to_string()))
                })
                .collect();
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
        Ok(all)
    }

    /// Create + register + persist a new campaign schedule.
    ///
    /// # Panics
    /// Panics when the schedule cannot be persisted. Use [`Self::try_create`] to
    /// handle the error.
    pub async fn create(
        &self,
        name: &str,
        params: &CampaignParams,
        trigger: TriggerConfig,
    ) -> Schedule {
        match self.try_create(name, params, trigger).await {
            Ok(schedule) => schedule,
            Err(error) => panic!("campaign schedule cannot be created: {error}"),
        }
    }

    /// Create, register, and atomically persist a campaign schedule.
    ///
    /// # Errors
    /// Returns a state-file error and rolls the in-memory registration back when
    /// persistence fails.
    pub async fn try_create(
        &self,
        name: &str,
        params: &CampaignParams,
        trigger: TriggerConfig,
    ) -> Result<Schedule, CampaignSchedulerError> {
        if matches!(&trigger, TriggerConfig::OneTime { .. }) {
            if self.store.is_none() {
                return Err(CampaignSchedulerError::DurabilityUnavailable(
                    "SQLite storage is not configured".to_owned(),
                ));
            }
            if let Some(reason) = self.manager.one_time_block_reason().await {
                return Err(CampaignSchedulerError::DurabilityUnavailable(reason));
            }
        }
        validate_campaign_fuzzing_policy(params)?;
        let id = uuid::Uuid::new_v4().to_string();
        let mut params = with_absolute_project(params);
        // Inject the id so the dispatcher (handed only the constant kind) can key
        // this campaign's rotation and budget state.
        params.schedule_id.clone_from(&id);
        let schedule = Schedule::new(id, name, trigger, CAMPAIGN_KIND)
            .with_params(serde_json::to_value(&params).unwrap_or_default());
        self.manager.register(schedule.clone()).await;
        if let Err(error) = self.persist().await {
            self.manager.remove(&schedule.id).await;
            return Err(error.into());
        }
        Ok(schedule)
    }

    /// Clear the persisted execution history, returning how many rows went.
    ///
    /// History outlives the schedule that produced it, so a campaign deleted
    /// months ago can still be the only thing an operator sees in "Recent runs".
    ///
    /// # Errors
    /// Returns a history error when configured storage cannot clear the rows.
    pub async fn clear_history(&self) -> Result<u64, CampaignSchedulerError> {
        let Some(store) = &self.store else {
            return Ok(0);
        };
        store
            .clear_schedule_executions()
            .await
            .map_err(|error| CampaignSchedulerError::History(error.to_string()))
    }

    /// Remove a schedule by id, discarding its rotation/budget state so a
    /// recreated campaign starts fresh.
    ///
    /// # Panics
    /// Panics when the updated scheduler state cannot be persisted. Use
    /// [`Self::try_remove`] to handle the error.
    pub async fn remove(&self, id: &str) -> bool {
        match self.try_remove(id).await {
            Ok(removed) => removed,
            Err(error) => panic!("campaign schedule cannot be removed: {error}"),
        }
    }

    /// Remove and atomically persist a schedule.
    ///
    /// # Errors
    /// Returns a state-file error and restores the in-memory schedule if the
    /// definition file cannot be replaced.
    pub async fn try_remove(&self, id: &str) -> Result<bool, CampaignSchedulerError> {
        let previous = self.manager.get_schedule(id).await;
        let removed = self.manager.remove(id).await;
        if removed {
            if let Err(error) = self.persist().await {
                if let Some(schedule) = previous {
                    self.manager.register(schedule).await;
                }
                return Err(error.into());
            }
            self.state.try_forget(id)?;
        }
        Ok(removed)
    }

    /// Enable or disable a schedule by id.
    ///
    /// # Panics
    /// Panics when the updated definition cannot be persisted. Use
    /// [`Self::try_set_enabled`] to handle the error.
    pub async fn set_enabled(&self, id: &str, enabled: bool) -> bool {
        match self.try_set_enabled(id, enabled).await {
            Ok(changed) => changed,
            Err(error) => panic!("campaign schedule cannot be updated: {error}"),
        }
    }

    /// Enable or disable a schedule and atomically persist the definition list.
    ///
    /// # Errors
    /// Returns a state-file error if the durable definition cannot be replaced.
    pub async fn try_set_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<bool, CampaignSchedulerError> {
        let previous = self.manager.get_schedule(id).await;
        let ok = if enabled {
            self.manager.resume(id).await
        } else {
            self.manager.pause(id).await
        };
        if ok {
            if let Err(error) = self.persist().await {
                if let Some(previous) = previous {
                    if previous.enabled {
                        self.manager.resume(id).await;
                    } else {
                        self.manager.pause(id).await;
                    }
                }
                return Err(error.into());
            }
        }
        Ok(ok)
    }

    async fn persist(&self) -> Result<(), StateFileError> {
        self.schedules.replace_from_manager(&self.manager).await
    }

    /// Stop trigger production and cancel all active campaign tasks.
    pub async fn stop(&self) {
        self.manager.stop().await;
    }
}

fn atomic_write_schedules(path: &Path, schedules: &[Schedule]) -> Result<(), StateFileError> {
    atomic_write_json(path, &schedules)
}

/// Load persisted schedules, treating absence as empty and damage as an error.
fn load_schedules(path: &Path) -> Result<Vec<Schedule>, StateFileError> {
    Ok(read_json_file(path)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use hf_scheduler::{ExecutionStatus, OneTimeOccurrenceState};
    use hf_storage::ScheduleOccurrenceRecord;

    use super::*;

    fn schedule_execution(
        execution_id: &str,
        schedule_id: &str,
        triggered_at: DateTime<Utc>,
        status: ExecutionStatus,
    ) -> ScheduleExecution {
        let started = !matches!(status, ExecutionStatus::Pending);
        let completed = matches!(
            status,
            ExecutionStatus::Completed | ExecutionStatus::Failed | ExecutionStatus::Cancelled
        );
        ScheduleExecution {
            execution_id: execution_id.to_owned(),
            schedule_id: schedule_id.to_owned(),
            triggered_at,
            started_at: started.then_some(triggered_at),
            completed_at: completed.then_some(triggered_at),
            status,
            workflow_execution_id: None,
            request_summary: serde_json::json!({}),
            response_summary: serde_json::json!({}),
            error_message: None,
        }
    }

    fn occurrence_row(state: &str, execution_status: &str) -> ScheduleOccurrenceRecord {
        let triggered_at = Utc::now();
        let status = match execution_status {
            "pending" => ExecutionStatus::Pending,
            "running" => ExecutionStatus::Running,
            "completed" => ExecutionStatus::Completed,
            "failed" => ExecutionStatus::Failed,
            "cancelled" => ExecutionStatus::Cancelled,
            other => panic!("unsupported fixture execution status: {other}"),
        };
        let execution = schedule_execution("exec-1", "schedule-1", triggered_at, status);
        ScheduleOccurrenceRecord {
            id: "occ-1".to_owned(),
            schedule_id: "schedule-1".to_owned(),
            execution_id: "exec-1".to_owned(),
            triggered_at: triggered_at.to_rfc3339(),
            state: state.to_owned(),
            owner_id: "owner-1".to_owned(),
            lease_expires_at: matches!(state, "reserved" | "running")
                .then(|| (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()),
            recovery_detail: None,
            execution_status: Some(execution_status.to_owned()),
            execution_data_json: Some(serde_json::to_string(&execution).unwrap()),
        }
    }

    #[test]
    fn occurrence_row_rejects_unknown_state_and_invalid_timestamp() {
        let mut row = occurrence_row("reserved", "pending");
        row.state = "invented".to_owned();
        assert!(row_to_occurrence(&row).is_err());

        let mut row = occurrence_row("reserved", "pending");
        row.triggered_at = "not-a-timestamp".to_owned();
        assert!(row_to_occurrence(&row).is_err());
    }

    #[test]
    fn occurrence_row_requires_matching_non_terminal_execution() {
        let mut missing = occurrence_row("running", "running");
        missing.execution_status = None;
        missing.execution_data_json = None;
        assert!(row_to_occurrence(&missing).is_err());

        let mismatched = occurrence_row("running", "completed");
        assert!(row_to_occurrence(&mismatched).is_err());
    }

    #[test]
    fn terminal_receipt_remains_valid_after_history_clear() {
        let mut row = occurrence_row("completed", "completed");
        row.execution_status = None;
        row.execution_data_json = None;
        assert_eq!(
            row_to_occurrence(&row).unwrap().state,
            OneTimeOccurrenceState::Completed
        );
    }

    struct SchedulerFixture {
        _directory: tempfile::TempDir,
        schedules_path: PathBuf,
        store: Option<Arc<Store>>,
    }

    impl SchedulerFixture {
        fn params(&self) -> CampaignParams {
            CampaignParams {
                project: self._directory.path().display().to_string(),
                target: Some("parser".to_owned()),
                engine: "libfuzzer".to_owned(),
                lang: "c".to_owned(),
                duration_secs: 1,
                max_runs: Some(1),
                max_total_secs: None,
                schedule_id: String::new(),
            }
        }

        fn push_schedule(&self, schedule: Schedule) {
            let mut schedules = load_schedules(&self.schedules_path).unwrap();
            schedules.retain(|existing| existing.id != schedule.id);
            schedules.push(schedule);
            atomic_write_schedules(&self.schedules_path, &schedules).unwrap();
        }

        fn write_due_one_time(&self, id: &str) {
            self.push_schedule(
                Schedule::new(
                    id,
                    id,
                    TriggerConfig::OneTime {
                        at: Utc::now() - chrono::Duration::seconds(1),
                    },
                    CAMPAIGN_KIND,
                )
                .with_params(serde_json::to_value(self.params()).unwrap()),
            );
        }

        fn write_interval(&self, id: &str) {
            let mut schedule = Schedule::new(
                id,
                id,
                TriggerConfig::Interval { interval_secs: 1 },
                CAMPAIGN_KIND,
            )
            .with_params(serde_json::to_value(self.params()).unwrap());
            schedule.policies.missed_policy = Some(hf_scheduler::MissedPolicy::CatchUp);
            schedule.last_fire = Some(Utc::now() - chrono::Duration::seconds(2));
            self.push_schedule(schedule);
        }

        async fn start(&self) -> Result<CampaignScheduler, CampaignSchedulerError> {
            let mut container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
            if let Some(store) = &self.store {
                container = container.with_store(Arc::clone(store));
            }
            CampaignScheduler::try_start(container, self.schedules_path.clone(), None).await
        }

        async fn seed_receipt(
            &self,
            schedule_id: &str,
            occurrence_id: &str,
            execution_id: &str,
            state: OneTimeOccurrenceState,
            expired: bool,
        ) {
            let store = self.store.as_ref().expect("fixture has SQLite");
            let triggered_at = Utc::now() - chrono::Duration::seconds(1);
            let owner_id = "fixture-owner";
            let pending = schedule_execution(
                execution_id,
                schedule_id,
                triggered_at,
                ExecutionStatus::Pending,
            );
            let new = hf_storage::NewScheduleOccurrence {
                id: occurrence_id.to_owned(),
                schedule_id: schedule_id.to_owned(),
                execution_id: execution_id.to_owned(),
                triggered_at: triggered_at.to_rfc3339(),
                owner_id: owner_id.to_owned(),
                lease_expires_at: (Utc::now() + chrono::Duration::seconds(60)).to_rfc3339(),
                execution_status: "pending".to_owned(),
                execution_data_json: serde_json::to_string(&pending).unwrap(),
            };
            store.reserve_schedule_occurrence(&new).await.unwrap();

            let apply =
                |from: &str, to: &str, status: ExecutionStatus, lease: Option<DateTime<Utc>>| {
                    let execution =
                        schedule_execution(execution_id, schedule_id, triggered_at, status);
                    hf_storage::ScheduleOccurrenceTransition {
                        occurrence_id: occurrence_id.to_owned(),
                        schedule_id: schedule_id.to_owned(),
                        execution_id: execution_id.to_owned(),
                        owner_id: owner_id.to_owned(),
                        from_state: from.to_owned(),
                        to_state: to.to_owned(),
                        lease_expires_at: lease.map(|value| value.to_rfc3339()),
                        recovery_detail: None,
                        execution_status: status.to_string(),
                        execution_data_json: serde_json::to_string(&execution).unwrap(),
                    }
                };

            if matches!(
                state,
                OneTimeOccurrenceState::Running
                    | OneTimeOccurrenceState::Completed
                    | OneTimeOccurrenceState::Failed
            ) {
                store
                    .transition_schedule_occurrence(&apply(
                        "reserved",
                        "running",
                        ExecutionStatus::Running,
                        Some(Utc::now() + chrono::Duration::seconds(60)),
                    ))
                    .await
                    .unwrap();
            }
            match state {
                OneTimeOccurrenceState::Completed => {
                    store
                        .transition_schedule_occurrence(&apply(
                            "running",
                            "completed",
                            ExecutionStatus::Completed,
                            None,
                        ))
                        .await
                        .unwrap();
                }
                OneTimeOccurrenceState::Failed => {
                    store
                        .transition_schedule_occurrence(&apply(
                            "running",
                            "failed",
                            ExecutionStatus::Failed,
                            None,
                        ))
                        .await
                        .unwrap();
                }
                OneTimeOccurrenceState::Cancelled => {
                    store
                        .transition_schedule_occurrence(&apply(
                            "reserved",
                            "cancelled",
                            ExecutionStatus::Cancelled,
                            None,
                        ))
                        .await
                        .unwrap();
                }
                OneTimeOccurrenceState::Reserved | OneTimeOccurrenceState::Running => {}
            }
            if expired
                && matches!(
                    state,
                    OneTimeOccurrenceState::Reserved | OneTimeOccurrenceState::Running
                )
            {
                store
                    .release_schedule_occurrence_lease(
                        occurrence_id,
                        owner_id,
                        &Utc::now().to_rfc3339(),
                        "fixture lease released",
                    )
                    .await
                    .unwrap();
            }
        }

        async fn reserve_receipt(
            &self,
            schedule_id: &str,
            occurrence_id: &str,
            execution_id: &str,
            state: OneTimeOccurrenceState,
        ) {
            self.seed_receipt(schedule_id, occurrence_id, execution_id, state, false)
                .await;
        }

        async fn reserve_expired_receipt(
            &self,
            schedule_id: &str,
            occurrence_id: &str,
            execution_id: &str,
            state: OneTimeOccurrenceState,
        ) {
            self.seed_receipt(schedule_id, occurrence_id, execution_id, state, true)
                .await;
        }

        async fn reserve_live_receipt(
            &self,
            schedule_id: &str,
            occurrence_id: &str,
            execution_id: &str,
        ) {
            self.seed_receipt(
                schedule_id,
                occurrence_id,
                execution_id,
                OneTimeOccurrenceState::Reserved,
                false,
            )
            .await;
        }
    }

    async fn scheduler_fixture_with_store() -> SchedulerFixture {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            Store::connect(directory.path().join("scheduler.db"))
                .await
                .unwrap(),
        );
        SchedulerFixture {
            schedules_path: directory.path().join("schedules.json"),
            store: Some(store),
            _directory: directory,
        }
    }

    async fn scheduler_fixture_without_store() -> SchedulerFixture {
        let directory = tempfile::tempdir().unwrap();
        SchedulerFixture {
            schedules_path: directory.path().join("schedules.json"),
            store: None,
            _directory: directory,
        }
    }

    fn due_trigger() -> TriggerConfig {
        TriggerConfig::OneTime {
            at: Utc::now() - chrono::Duration::seconds(1),
        }
    }

    #[tokio::test]
    async fn startup_reconciles_receipt_before_a_stale_one_time_cursor_can_fire() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("once");
        fixture
            .reserve_receipt("once", "occ-1", "exec-1", OneTimeOccurrenceState::Completed)
            .await;

        let scheduler = fixture.start().await.unwrap();
        let schedule = scheduler
            .list()
            .await
            .into_iter()
            .find(|schedule| schedule.id == "once")
            .unwrap();
        assert!(schedule.last_fire.is_some());
        assert_eq!(
            scheduler.list_views().await.unwrap()[0].durability_status,
            CampaignDurabilityStatus::Consumed
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn expired_running_receipt_is_recovery_required_and_never_redispatched() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("once");
        fixture
            .reserve_expired_receipt("once", "occ-1", "exec-1", OneTimeOccurrenceState::Running)
            .await;

        let scheduler = fixture.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let recoveries = scheduler.list_one_time_recoveries().await.unwrap();
        assert_eq!(recoveries.len(), 1);
        assert_eq!(recoveries[0].occurrence_id, "occ-1");
        assert_eq!(
            scheduler.list_views().await.unwrap()[0].durability_status,
            CampaignDurabilityStatus::RecoveryRequired
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn unavailable_journal_blocks_one_time_but_keeps_recurring_scheduler_live() {
        let fixture = scheduler_fixture_without_store().await;
        fixture.write_due_one_time("once");
        fixture.write_interval("recurring");
        let scheduler = fixture.start().await.unwrap();

        assert!(scheduler.manager.is_running());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !scheduler
                .manager
                .execution_history("recurring")
                .await
                .is_empty(),
            "recurring schedule must continue while one-time durability is blocked"
        );
        assert!(matches!(
            scheduler
                .try_create("new once", &fixture.params(), due_trigger())
                .await,
            Err(CampaignSchedulerError::DurabilityUnavailable(_))
        ));
        let views = scheduler.list_views().await.unwrap();
        assert_eq!(
            views
                .iter()
                .find(|view| view.id == "once")
                .unwrap()
                .durability_status,
            CampaignDurabilityStatus::RecoveryRequired
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn legacy_one_time_cursor_without_receipt_remains_consumed() {
        let fixture = scheduler_fixture_with_store().await;
        let mut legacy = Schedule::new("legacy-once", "legacy-once", due_trigger(), CAMPAIGN_KIND)
            .with_params(serde_json::to_value(fixture.params()).unwrap());
        legacy.last_fire = Some(Utc::now() - chrono::Duration::seconds(1));
        fixture.push_schedule(legacy);
        let scheduler = fixture.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            scheduler.list_views().await.unwrap()[0].durability_status,
            CampaignDurabilityStatus::Consumed
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schedule_occurrences")
                .fetch_one(fixture.store.as_ref().unwrap().pool())
                .await
                .unwrap(),
            0
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn acknowledgement_cancels_expired_receipt_and_survives_restart() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("once");
        fixture
            .reserve_expired_receipt("once", "occ-1", "exec-1", OneTimeOccurrenceState::Running)
            .await;
        let scheduler = fixture.start().await.unwrap();

        let acknowledged = scheduler
            .acknowledge_one_time_recovery("occ-1")
            .await
            .unwrap();
        assert_eq!(acknowledged.state, "cancelled");
        assert!(scheduler
            .list_one_time_recoveries()
            .await
            .unwrap()
            .is_empty());
        scheduler.stop().await;

        let restarted = fixture.start().await.unwrap();
        assert!(restarted
            .list_one_time_recoveries()
            .await
            .unwrap()
            .is_empty());
        assert_eq!(
            restarted.list_views().await.unwrap()[0].durability_status,
            CampaignDurabilityStatus::Consumed
        );
        restarted.stop().await;
    }

    #[tokio::test]
    async fn acknowledgement_rejects_live_or_terminal_non_cancelled_receipts() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("once");
        fixture
            .reserve_live_receipt("once", "occ-live", "exec-live")
            .await;
        let scheduler = fixture.start().await.unwrap();
        assert!(matches!(
            scheduler.acknowledge_one_time_recovery("occ-live").await,
            Err(CampaignSchedulerError::OccurrenceConflict(_))
        ));
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn deleted_schedule_does_not_hide_recovery_receipt() {
        let fixture = scheduler_fixture_with_store().await;
        fixture
            .reserve_expired_receipt(
                "deleted",
                "occ-deleted",
                "exec-deleted",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let scheduler = fixture.start().await.unwrap();
        let recovery = scheduler
            .list_one_time_recoveries()
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(recovery.schedule_name, None);
        assert!(!recovery.schedule_exists);
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn every_durable_occurrence_state_suppresses_restart_redispatch() {
        for state in [
            OneTimeOccurrenceState::Reserved,
            OneTimeOccurrenceState::Running,
            OneTimeOccurrenceState::Completed,
            OneTimeOccurrenceState::Failed,
            OneTimeOccurrenceState::Cancelled,
        ] {
            let fixture = scheduler_fixture_with_store().await;
            fixture.write_due_one_time("restart-once");
            if matches!(
                state,
                OneTimeOccurrenceState::Reserved | OneTimeOccurrenceState::Running
            ) {
                fixture
                    .reserve_expired_receipt("restart-once", "occ-restart", "exec-restart", state)
                    .await;
            } else {
                fixture
                    .reserve_receipt("restart-once", "occ-restart", "exec-restart", state)
                    .await;
            }
            let first = fixture.start().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            first.stop().await;
            let restarted = fixture.start().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
            restarted.stop().await;

            let store = fixture.store.as_ref().unwrap();
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM schedule_executions
                     WHERE schedule_id = 'restart-once'",
                )
                .fetch_one(store.pool())
                .await
                .unwrap(),
                1,
                "state {state:?} must remain consumed across restart"
            );
        }
    }

    #[tokio::test]
    async fn corrupt_receipt_blocks_one_time_and_allows_recurring_recovery() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("corrupt-once");
        fixture.write_interval("healthy-interval");
        let store = fixture.store.as_ref().unwrap();
        sqlx::query(
            "INSERT INTO schedule_occurrences
                (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
             VALUES
                ('occ-corrupt', 'corrupt-once', 'exec-corrupt', 'not-rfc3339',
                 'reserved', 'old-owner', '2099-01-01T00:00:00Z')",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO schedule_executions
                (id, schedule_id, triggered_at, status, data_json)
             VALUES
                ('exec-corrupt', 'corrupt-once', 'not-rfc3339', 'pending', '{}')",
        )
        .execute(store.pool())
        .await
        .unwrap();

        let scheduler = fixture.start().await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(matches!(
            scheduler
                .manager
                .one_time_runtime_status("corrupt-once")
                .await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
        assert!(!scheduler
            .manager
            .execution_history("healthy-interval")
            .await
            .is_empty());
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn structurally_invalid_receipt_records_a_corrupt_journal_block() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("invalid-once");
        let store = fixture.store.as_ref().unwrap();
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO schedule_occurrences
                (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
             VALUES
                ('occ-invalid', 'invalid-once', 'exec-invalid', '2026-07-30T00:00:00Z',
                 'invented', 'old-owner', '2099-01-01T00:00:00Z')",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            scheduler
                .manager
                .occurrence_metrics()
                .corrupt_journal_blocks,
            1
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn two_service_schedulers_dispatch_one_time_at_most_once() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("raced-once");
        let database_path = fixture._directory.path().join("scheduler.db");
        let first_store = Arc::new(Store::connect(&database_path).await.unwrap());
        let second_store = Arc::new(Store::connect(&database_path).await.unwrap());
        let first_container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&first_store));
        let second_container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&second_store));
        let (first, second) = tokio::join!(
            CampaignScheduler::try_start(first_container, fixture.schedules_path.clone(), None,),
            CampaignScheduler::try_start(second_container, fixture.schedules_path.clone(), None,),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let store = fixture.store.as_ref().unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM schedule_occurrences WHERE schedule_id = 'raced-once'",
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'raced-once'",
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
            1
        );
        first.stop().await;
        second.stop().await;
    }

    #[test]
    fn a_relative_project_is_pinned_to_an_absolute_path() {
        // The whole reason scheduled campaigns failed every fire: a relative
        // path hashes to a different workspace than the one holding the harness.
        let params = CampaignParams {
            project: ".".to_owned(),
            target: Some("parse".to_owned()),
            engine: "libfuzzer".to_owned(),
            lang: "c".to_owned(),
            duration_secs: 60,
            ..CampaignParams::default()
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
        // An old bare-string `target` still loads as a single-target campaign.
        assert_eq!(params.target.as_deref(), Some("t"));
        assert!(params.max_runs.is_none() && params.max_total_secs.is_none());
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
    fn schedule_creation_rejects_invalid_engine_and_duration_policy() {
        let mut params = CampaignParams {
            project: "/p".to_owned(),
            target: Some("t".to_owned()),
            engine: "not-an-engine".to_owned(),
            lang: "c".to_owned(),
            duration_secs: 60,
            ..CampaignParams::default()
        };
        assert!(matches!(
            validate_campaign_fuzzing_policy(&params),
            Err(CampaignSchedulerError::Validation(_))
        ));

        params.engine = "libfuzzer".to_owned();
        params.duration_secs = 7201;
        assert!(matches!(
            validate_campaign_fuzzing_policy(&params),
            Err(CampaignSchedulerError::Validation(_))
        ));
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
    fn parse_trigger_preserves_and_validates_cron_timezone() {
        let trigger = parse_trigger("cron", "CRON_TZ=Asia/Shanghai 0 9 * * *").unwrap();
        assert!(matches!(
            trigger,
            TriggerConfig::Cron { expression, timezone }
                if expression == "0 9 * * *" && timezone == "Asia/Shanghai"
        ));
        assert!(parse_trigger("cron", "CRON_TZ=Mars/Olympus 0 9 * * *").is_err());
        assert!(parse_trigger("cron", "CRON_TZ=Asia/Shanghai invalid").is_err());
        assert!(parse_trigger("cron", "CRON_TZ= 0 9 * * *").is_err());
    }

    #[test]
    fn parse_trigger_accepts_event_kinds_and_rejects_unknown_event_types() {
        for event_type in KNOWN_EVENT_TYPES {
            let trigger = parse_trigger("event", event_type).unwrap();
            assert!(matches!(
                trigger,
                TriggerConfig::Event {
                    debounce_secs: 0,
                    filter: None,
                    ..
                }
            ));
        }
        assert!(matches!(
            parse_trigger("event", EVENT_CRASH_FOUND),
            Ok(TriggerConfig::Event { ref event_type, .. }) if event_type == EVENT_CRASH_FOUND
        ));
        let error = parse_trigger("event", "disk.full").unwrap_err();
        assert!(
            error.contains("unknown event type"),
            "rejection must name the problem: {error}"
        );
        assert!(parse_trigger("event", "   ").is_err());
    }

    #[test]
    fn event_trigger_schedule_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedules.json");
        let schedule = Schedule::new(
            "evt",
            "on crash",
            parse_trigger("event", EVENT_CRASH_FOUND).unwrap(),
            CAMPAIGN_KIND,
        );
        atomic_write_schedules(&path, std::slice::from_ref(&schedule)).unwrap();

        let loaded = load_schedules(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(matches!(
            &loaded[0].trigger,
            TriggerConfig::Event { event_type, debounce_secs: 0, filter: None }
                if event_type == EVENT_CRASH_FOUND
        ));
    }

    #[test]
    fn schedules_persisted_before_event_triggers_still_load() {
        // A schedule file written by an older build: no `policies`,
        // `description`, or `tags` keys, and a trigger without `filter`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedules.json");
        let legacy = serde_json::json!([{
            "id": "old",
            "name": "old nightly",
            "enabled": true,
            "trigger": { "type": "interval", "interval_secs": 3600 },
            "workflow_id": CAMPAIGN_KIND,
            "parameter_values": {
                "project": "/p", "target": "t", "engine": "libfuzzer", "duration_secs": 60
            },
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "last_fire": null
        }]);
        std::fs::write(&path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let loaded = load_schedules(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(matches!(
            loaded[0].trigger,
            TriggerConfig::Interval {
                interval_secs: 3600
            }
        ));
    }

    #[test]
    fn scheduler_state_errors_use_the_storage_transport_classification() {
        let classified = ClassifiedError::from(CampaignSchedulerError::History("closed".into()));
        assert!(matches!(classified, ClassifiedError::Storage(_)));
    }

    #[tokio::test]
    async fn scheduler_concurrency_limits_report_both_caps_and_the_live_effective_minimum() {
        let dir = tempfile::tempdir().unwrap();
        let workflow_dispatch_limit =
            crate::config::effective_scheduler_config().max_concurrent_executions;
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
        let scheduler =
            CampaignScheduler::try_start(container, dir.path().join("schedules.json"), None)
                .await
                .unwrap();

        let campaign_limit = workflow_dispatch_limit.saturating_add(3);
        scheduler.try_set_max_concurrent(campaign_limit).unwrap();
        let limits = scheduler.concurrency_limits();
        assert_eq!(limits.active_fuzz_campaign_limit, campaign_limit);
        assert_eq!(
            limits.scheduler_workflow_dispatch_limit,
            workflow_dispatch_limit
        );
        assert_eq!(
            limits.effective_max_concurrent_fuzz_runs,
            campaign_limit.min(workflow_dispatch_limit)
        );
        assert_eq!(
            serde_json::to_value(limits).unwrap(),
            serde_json::json!({
                "active_fuzz_campaign_limit": campaign_limit,
                "scheduler_workflow_dispatch_limit": workflow_dispatch_limit,
                "effective_max_concurrent_fuzz_runs": campaign_limit.min(workflow_dispatch_limit),
            })
        );

        scheduler.try_set_max_concurrent(1).unwrap();
        let changed = scheduler.concurrency_limits();
        assert_eq!(changed.active_fuzz_campaign_limit, 1);
        assert_eq!(changed.effective_max_concurrent_fuzz_runs, 1);
        scheduler.stop().await;
    }

    #[test]
    fn schedules_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedules.json");
        let params = CampaignParams {
            project: "/p".to_owned(),
            target: Some("t".to_owned()),
            engine: "libfuzzer".to_owned(),
            lang: "c".to_owned(),
            duration_secs: 60,
            ..CampaignParams::default()
        };
        let sched = Schedule::new(
            "id1",
            "nightly",
            parse_trigger("interval", "60").unwrap(),
            CAMPAIGN_KIND,
        )
        .with_params(serde_json::to_value(&params).unwrap());
        atomic_write_schedules(&path, &[sched]).unwrap();

        let loaded = load_schedules(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "nightly");
        let p: CampaignParams = serde_json::from_value(loaded[0].parameter_values.clone()).unwrap();
        assert_eq!(p.target.as_deref(), Some("t"));
        assert_eq!(p.duration_secs, 60);
    }

    #[test]
    fn corrupt_schedule_file_is_reported_and_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedules.json");
        std::fs::write(&path, "[{broken").unwrap();

        let error = load_schedules(&path).expect_err("corrupt schedules must fail startup");

        assert!(error.to_string().contains("decode"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "[{broken");
    }

    #[tokio::test]
    async fn last_fire_update_is_written_back_to_schedule_definitions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schedules.json");
        let mut schedule = Schedule::new(
            "persisted-fire",
            "persisted fire",
            TriggerConfig::Interval { interval_secs: 60 },
            CAMPAIGN_KIND,
        );
        atomic_write_schedules(&path, &[schedule.clone()]).unwrap();
        let repository = Arc::new(ScheduleFileStore::new(path.clone()));
        let persistence = CampaignSchedulerPersistence {
            store: None,
            schedules: repository,
            history_retention_limit: 100,
        };

        let fired_at = chrono::Utc::now();
        schedule.last_fire = Some(fired_at);
        persistence.update_schedule(&schedule).await.unwrap();

        let loaded = load_schedules(&path).unwrap();
        assert_eq!(loaded[0].last_fire, Some(fired_at));
    }

    #[tokio::test]
    async fn scheduler_persistence_prunes_old_history_beyond_retention() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::connect(dir.path().join("history.db")).await.unwrap());
        let repository = Arc::new(ScheduleFileStore::new(dir.path().join("schedules.json")));
        let persistence = CampaignSchedulerPersistence {
            store: Some(Arc::clone(&store)),
            schedules: repository,
            history_retention_limit: 2,
        };
        let now = chrono::Utc::now();
        for index in 0..3 {
            let at = if index == 0 {
                now - chrono::Duration::hours(2)
            } else {
                now + chrono::Duration::seconds(index)
            };
            let execution = ScheduleExecution {
                execution_id: format!("retained-{index}"),
                schedule_id: "limited".to_owned(),
                triggered_at: at,
                started_at: Some(at),
                completed_at: Some(at),
                status: hf_scheduler::ExecutionStatus::Completed,
                workflow_execution_id: None,
                request_summary: serde_json::Value::Null,
                response_summary: serde_json::Value::Null,
                error_message: None,
            };
            persistence.record_execution(&execution).await.unwrap();
        }

        let rows = store.list_schedule_executions(10).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert!(!rows.iter().any(|row| row.contains("retained-0")));
    }

    #[tokio::test]
    async fn scheduler_history_read_and_clear_errors_are_propagated() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::connect(dir.path().join("closed.db")).await.unwrap());
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&store));
        let scheduler =
            CampaignScheduler::try_start(container, dir.path().join("schedules.json"), None)
                .await
                .unwrap();
        store
            .upsert_schedule_execution(
                "malformed",
                "schedule",
                &chrono::Utc::now().to_rfc3339(),
                "completed",
                "{not-json",
            )
            .await
            .unwrap();
        assert!(matches!(
            scheduler.recent_executions(10).await,
            Err(CampaignSchedulerError::History(_))
        ));
        assert_eq!(scheduler.clear_history().await.unwrap(), 1);

        store.pool().close().await;

        assert!(matches!(
            scheduler.list_views().await,
            Err(CampaignSchedulerError::History(_))
        ));
        assert!(matches!(
            scheduler.recent_executions(10).await,
            Err(CampaignSchedulerError::History(_))
        ));
        assert!(matches!(
            scheduler.clear_history().await,
            Err(CampaignSchedulerError::History(_))
        ));
        scheduler.stop().await;
    }

    fn target(sym: &str, fit: f64) -> SchedulableTarget {
        SchedulableTarget {
            target: sym.to_owned(),
            engine: "libfuzzer".to_owned(),
            language: "c".to_owned(),
            fit_score: fit,
        }
    }

    #[test]
    fn priority_order_is_highest_fit_first_then_stable() {
        let ordered = priority_order(vec![
            target("low", 0.2),
            target("high", 0.9),
            target("mid", 0.5),
        ]);
        let syms: Vec<&str> = ordered.iter().map(|t| t.target.as_str()).collect();
        assert_eq!(syms, vec!["high", "mid", "low"]);
    }

    #[test]
    fn rotation_covers_every_target_and_wraps() {
        let ordered = priority_order(vec![target("a", 0.9), target("b", 0.5), target("c", 0.1)]);
        // Cursor 0,1,2 sweep all three in priority order; 3 wraps back to the top.
        let picks: Vec<&str> = (0..4)
            .map(|c| rotate(&ordered, c).unwrap().target.as_str())
            .collect();
        assert_eq!(picks, vec!["a", "b", "c", "a"]);
        assert!(rotate(&[], 0).is_none(), "no targets -> nothing to fuzz");
    }

    #[test]
    fn budget_stops_on_runs_then_on_time() {
        let mut params = CampaignParams {
            max_runs: Some(3),
            ..CampaignParams::default()
        };
        let under = CampaignRuntimeState {
            runs_done: 2,
            ..CampaignRuntimeState::default()
        };
        assert!(budget_skip_reason(&under, &params).is_none());
        let at = CampaignRuntimeState {
            runs_done: 3,
            ..CampaignRuntimeState::default()
        };
        assert!(budget_skip_reason(&at, &params).unwrap().contains("run(s)"));

        params.max_runs = None;
        params.max_total_secs = Some(600);
        let spent = CampaignRuntimeState {
            secs_done: 600,
            ..CampaignRuntimeState::default()
        };
        assert!(budget_skip_reason(&spent, &params)
            .unwrap()
            .contains("budget"));
        // Unbounded campaign never hits a budget skip.
        assert!(budget_skip_reason(&spent, &CampaignParams::default()).is_none());
    }
}
