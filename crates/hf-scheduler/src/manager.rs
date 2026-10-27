//! `SchedulerManager`: top-level entry point that owns the async trigger loop.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::{ConcurrencyPolicy, MissedPolicy, SchedulerConfig};
use crate::dispatcher::WorkflowDispatcher;
use crate::event_bridge::{EventBridge, IncomingEvent};
use crate::executor::{ExecutionStatus, ExecutionStore, ScheduleExecution, ScheduleExecutor};
use crate::occurrence::{
    OneTimeAcknowledgement, OneTimeOccurrence, OneTimeOccurrenceState, OneTimeOccurrenceTransition,
    OneTimeReservation, OneTimeRuntimeStatus, OneTimeTransitionResult, ONE_TIME_HEARTBEAT,
    ONE_TIME_LEASE,
};
use crate::queue::{trigger_queue, TriggerReceiver, TriggerSender};
use crate::recovery;
use crate::store::{Schedule, ScheduleStore};
use crate::trigger::{evaluate_all, FiredTrigger};

/// Persistence errors emitted by scheduler state adapters.
#[derive(Debug, Clone, thiserror::Error)]
#[error("scheduler persistence error: {message}")]
pub struct PersistenceError {
    message: String,
}

impl PersistenceError {
    /// Create a new persistence error from a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Persistence adapter for schedule state and execution history.
#[async_trait::async_trait]
pub trait SchedulerPersistence: Send + Sync {
    /// Persist a newly created execution record.
    async fn record_execution(&self, execution: &ScheduleExecution)
        -> Result<(), PersistenceError>;

    /// Persist an updated execution record.
    async fn update_execution(&self, execution: &ScheduleExecution)
        -> Result<(), PersistenceError>;

    /// Persist a changed schedule definition, including its latest fire cursor.
    async fn update_schedule(&self, schedule: &Schedule) -> Result<(), PersistenceError>;

    /// Persist a changed schedule definition, including its enabled state.
    async fn update_schedule_definition(
        &self,
        schedule: &Schedule,
    ) -> Result<(), PersistenceError> {
        self.update_schedule(schedule).await
    }

    /// Persist a completed recovery, clearing only the expected checkpoint.
    async fn complete_recovery(
        &self,
        schedule: &Schedule,
        _checkpoint: &recovery::RecoveryCheckpoint,
    ) -> Result<(), PersistenceError> {
        self.update_schedule(schedule).await
    }

    /// Count executions that started at or after `since` for rate-limit recovery.
    ///
    /// In-memory-only adapters may keep the default zero; the manager combines
    /// this with its live history using `max`, avoiding double-counting mirrored
    /// rows while preserving limits across service restarts.
    async fn executions_started_since(
        &self,
        _schedule_id: &str,
        _since: chrono::DateTime<Utc>,
    ) -> Result<u64, PersistenceError> {
        Ok(0)
    }

    /// Atomically reserve a one-time occurrence and its pending execution.
    async fn reserve_one_time_occurrence(
        &self,
        occurrence: &OneTimeOccurrence,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeReservation, PersistenceError> {
        let _ = (occurrence, execution);
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Atomically transition a one-time occurrence and its execution.
    async fn transition_one_time_occurrence(
        &self,
        transition: &OneTimeOccurrenceTransition,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeTransitionResult, PersistenceError> {
        let _ = (transition, execution);
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Renew a non-terminal one-time occurrence lease owned by this manager.
    async fn renew_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, PersistenceError> {
        let _ = (occurrence_id, owner_id, lease_expires_at);
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Release a one-time occurrence lease for acknowledgement recovery.
    async fn release_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        released_at: DateTime<Utc>,
        recovery_detail: &str,
    ) -> Result<bool, PersistenceError> {
        let _ = (occurrence_id, owner_id, released_at, recovery_detail);
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Load durable one-time occurrence receipts for startup reconciliation.
    async fn load_one_time_occurrences(&self) -> Result<Vec<OneTimeOccurrence>, PersistenceError> {
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Load a one-time occurrence receipt by identifier.
    async fn get_one_time_occurrence(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<OneTimeOccurrence>, PersistenceError> {
        let _ = occurrence_id;
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Load the execution associated with a one-time occurrence receipt.
    async fn get_one_time_execution(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<ScheduleExecution>, PersistenceError> {
        let _ = occurrence_id;
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }

    /// Acknowledge a recovery-eligible occurrence as cancelled.
    async fn acknowledge_one_time_occurrence(
        &self,
        occurrence_id: &str,
        acknowledged_at: DateTime<Utc>,
        recovery_detail: &str,
        execution: &ScheduleExecution,
    ) -> Result<OneTimeAcknowledgement, PersistenceError> {
        let _ = (occurrence_id, acknowledged_at, recovery_detail, execution);
        Err(PersistenceError::new(
            "durable one-time occurrence persistence is unavailable",
        ))
    }
}

struct RecoveryPersistence {
    inner: Arc<dyn SchedulerPersistence>,
    failed: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl SchedulerPersistence for RecoveryPersistence {
    async fn record_execution(
        &self,
        execution: &ScheduleExecution,
    ) -> Result<(), PersistenceError> {
        let result = self.inner.record_execution(execution).await;
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }

    async fn update_execution(
        &self,
        execution: &ScheduleExecution,
    ) -> Result<(), PersistenceError> {
        let result = self.inner.update_execution(execution).await;
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }

    async fn update_schedule(&self, schedule: &Schedule) -> Result<(), PersistenceError> {
        let result = self.inner.update_schedule(schedule).await;
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        result
    }

    async fn executions_started_since(
        &self,
        schedule_id: &str,
        since: DateTime<Utc>,
    ) -> Result<u64, PersistenceError> {
        self.inner
            .executions_started_since(schedule_id, since)
            .await
    }
}

struct TrackedDispatch {
    execution_id: String,
    schedule_id: String,
    occurrence_id: Option<String>,
    owner_id: Option<String>,
    one_time_terminal_allowed: Option<Arc<AtomicBool>>,
    recovery_failed: Option<Arc<AtomicBool>>,
    handle: JoinHandle<()>,
}

struct PendingOneTimeAdmission {
    occurrence_id: String,
    schedule_id: String,
    execution_id: String,
    owner_id: String,
}

type SerialLocks = Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>;
type DispatchTasks = Arc<StdMutex<Vec<TrackedDispatch>>>;
type OneTimeAdmissions = Arc<StdMutex<HashMap<String, PendingOneTimeAdmission>>>;
type RecoveryFailures = Arc<HashMap<String, Arc<AtomicBool>>>;
type SerialRequest =
    std::pin::Pin<Box<dyn std::future::Future<Output = tokio::sync::OwnedMutexGuard<()>> + Send>>;

#[derive(Clone)]
struct RecoveryContext {
    store: Arc<Mutex<ScheduleStore>>,
    executor: Arc<Mutex<ScheduleExecutor>>,
    executions: Arc<Mutex<ExecutionStore>>,
    dispatcher: Arc<Mutex<Option<Arc<dyn WorkflowDispatcher>>>>,
    persistence: Arc<Mutex<Option<Arc<dyn SchedulerPersistence>>>>,
    slots: Arc<Semaphore>,
    serial_locks: SerialLocks,
    admission_locks: SerialLocks,
    tasks: DispatchTasks,
    admissions: OneTimeAdmissions,
    one_time_status: Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
    one_time_global_block: Arc<Mutex<Option<String>>>,
    metrics: Arc<OccurrenceMetrics>,
    owner_id: String,
    max_event_cascade_depth: u32,
    held: Arc<Mutex<HashSet<String>>>,
    failures: RecoveryFailures,
    arm: crate::arming::ArmSignal,
    shutdown: Arc<Notify>,
}

const ONE_TIME_ID_NOT_RESERVED: &str = "not_reserved";
const WORKFLOW_FAILURE_RECOVERY: &str = "workflow_failure";
const DISPATCHER_FAILURE_RECOVERY: &str = "dispatcher_failure";
const ONE_TIME_SKIP_RECOVERY: &str = "one-time dispatch was skipped before its workflow ran; acknowledge to close it or re-create the schedule";

/// Snapshot of scheduler-owned one-time occurrence counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OccurrenceMetricsSnapshot {
    pub reservation_wins: u64,
    pub duplicate_suppressions: u64,
    pub transition_failures: u64,
    pub lease_renewal_failures: u64,
    pub expired_non_terminal: u64,
    pub acknowledgements: u64,
    pub corrupt_journal_blocks: u64,
}

/// Lightweight counters for durable one-time occurrence outcomes.
#[derive(Debug, Default)]
pub struct OccurrenceMetrics {
    reservation_wins: AtomicU64,
    duplicate_suppressions: AtomicU64,
    transition_failures: AtomicU64,
    lease_renewal_failures: AtomicU64,
    expired_non_terminal: AtomicU64,
    acknowledgements: AtomicU64,
    corrupt_journal_blocks: AtomicU64,
}

impl OccurrenceMetrics {
    /// Record a successful durable reservation.
    pub fn record_reservation_win(&self) {
        self.reservation_wins.fetch_add(1, Ordering::Relaxed);
    }

    /// Record suppression caused by an existing durable occurrence.
    pub fn record_duplicate_suppression(&self) {
        self.duplicate_suppressions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a durable occurrence transition failure.
    pub fn record_transition_failure(&self) {
        self.transition_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a durable occurrence lease renewal failure.
    pub fn record_lease_renewal_failure(&self) {
        self.lease_renewal_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an expired non-terminal durable occurrence.
    pub fn record_expired_non_terminal(&self) {
        self.expired_non_terminal.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a recovery acknowledgement.
    pub fn record_acknowledgement(&self) {
        self.acknowledgements.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a global block caused by a corrupt durable journal.
    pub fn record_corrupt_journal_block(&self) {
        self.corrupt_journal_blocks.fetch_add(1, Ordering::Relaxed);
    }

    /// Return a coherent point-in-time view of all counters.
    #[must_use]
    pub fn snapshot(&self) -> OccurrenceMetricsSnapshot {
        OccurrenceMetricsSnapshot {
            reservation_wins: self.reservation_wins.load(Ordering::Relaxed),
            duplicate_suppressions: self.duplicate_suppressions.load(Ordering::Relaxed),
            transition_failures: self.transition_failures.load(Ordering::Relaxed),
            lease_renewal_failures: self.lease_renewal_failures.load(Ordering::Relaxed),
            expired_non_terminal: self.expired_non_terminal.load(Ordering::Relaxed),
            acknowledgements: self.acknowledgements.load(Ordering::Relaxed),
            corrupt_journal_blocks: self.corrupt_journal_blocks.load(Ordering::Relaxed),
        }
    }
}

/// Liveness of the scheduler's long-lived evaluator and executor tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerRuntimeStatus {
    /// No evaluator or executor task is registered.
    Stopped,
    /// Startup is preparing recovery and task registration.
    Starting,
    /// Both long-lived tasks are alive.
    Running,
    /// At least one registered task finished unexpectedly.
    Failed,
}

/// Runtime-owned scheduler state that changes when the trigger loop starts/stops.
struct RuntimeState {
    recovery_handle: Option<JoinHandle<()>>,
    recovery_cancel: Option<tokio::sync::oneshot::Sender<()>>,
    eval_handle: Option<JoinHandle<()>>,
    exec_handle: Option<JoinHandle<()>>,
    shutdown: Arc<Notify>,
    trigger_tx: Option<TriggerSender>,
    starting: bool,
    startup_failed: bool,
}

impl RuntimeState {
    fn new() -> Self {
        Self {
            recovery_handle: None,
            recovery_cancel: None,
            eval_handle: None,
            exec_handle: None,
            shutdown: Arc::new(Notify::new()),
            trigger_tx: None,
            starting: false,
            startup_failed: false,
        }
    }
}

/// The top-level scheduler service.
///
/// Owns the `ScheduleStore`, `ScheduleExecutor`, and runs an async trigger loop
/// that evaluates all active schedules on each tick.
pub struct SchedulerManager {
    /// Authorization to act on work restored by recovery. Disarmed on every
    /// process start, because a restart is not a decision to resume.
    arm: crate::arming::ArmSignal,
    store: Arc<Mutex<ScheduleStore>>,
    executor: Arc<Mutex<ScheduleExecutor>>,
    /// Execution history store.
    execution_store: Arc<Mutex<ExecutionStore>>,
    config: SchedulerConfig,
    /// Runtime lifecycle state for the trigger and executor loops.
    runtime: StdMutex<RuntimeState>,
    /// Serialize startup and shutdown across their asynchronous operations.
    lifecycle: Mutex<()>,
    /// Optional workflow dispatcher injected after construction.
    ///
    /// When `Some`, fired triggers are dispatched through the real workflow
    /// backend instead of the dispatcher-less `ScheduleExecutor` fallback.
    /// Injected via `set_dispatcher()` (same pattern as `AgentRunner` in
    /// `ServiceContainer`); production always installs one.
    dispatcher: Arc<Mutex<Option<Arc<dyn WorkflowDispatcher>>>>,
    /// Optional persistence adapter injected after construction.
    persistence: Arc<Mutex<Option<Arc<dyn SchedulerPersistence>>>>,
    /// Bounded global execution permits. Acquiring before receiving more work
    /// keeps the recovery channel itself as the bounded backlog.
    execution_slots: Arc<Semaphore>,
    /// Matches incoming events against event-driven schedules (debounce state
    /// included). Events arrive via [`SchedulerManager::emit_event`].
    event_bridge: Mutex<EventBridge>,
    /// Backfill and explicit queue policies serialize on a per-schedule lock.
    serial_locks: SerialLocks,
    admission_locks: SerialLocks,
    /// Every dispatched workflow task is retained until reaped or stopped.
    dispatch_tasks: DispatchTasks,
    /// Reserved occurrences that have not yet reached tracked task creation.
    one_time_admissions: OneTimeAdmissions,
    /// Stable identifier for this scheduler process instance.
    owner_id: String,
    /// Process-local per-schedule one-time runtime status.
    one_time_status: Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
    /// Process-local safety block for every one-time schedule.
    one_time_global_block: Arc<Mutex<Option<String>>>,
    /// Lightweight durable occurrence outcome counters.
    occurrence_metrics: Arc<OccurrenceMetrics>,
}

impl SchedulerManager {
    fn cursor_time(fired: &FiredTrigger, now: DateTime<Utc>) -> DateTime<Utc> {
        if fired.is_recovery {
            fired.fired_at
        } else {
            fired.fired_at.max(now)
        }
    }

    /// Create a new scheduler manager with the given configuration.
    pub fn new(config: SchedulerConfig) -> Self {
        let execution_slots = Arc::new(Semaphore::new(config.max_concurrent_executions.max(1)));
        Self {
            arm: crate::arming::ArmSignal::default(),
            store: Arc::new(Mutex::new(ScheduleStore::new())),
            executor: Arc::new(Mutex::new(ScheduleExecutor::new())),
            execution_store: Arc::new(Mutex::new(ExecutionStore::with_retention(
                config.history_retention_limit,
            ))),
            config,
            runtime: StdMutex::new(RuntimeState::new()),
            lifecycle: Mutex::new(()),
            dispatcher: Arc::new(Mutex::new(None)),
            persistence: Arc::new(Mutex::new(None)),
            execution_slots,
            event_bridge: Mutex::new(EventBridge::new()),
            serial_locks: Arc::new(Mutex::new(HashMap::new())),
            admission_locks: Arc::new(Mutex::new(HashMap::new())),
            dispatch_tasks: Arc::new(StdMutex::new(Vec::new())),
            one_time_admissions: Arc::new(StdMutex::new(HashMap::new())),
            owner_id: uuid::Uuid::new_v4().to_string(),
            one_time_status: Arc::new(Mutex::new(HashMap::new())),
            one_time_global_block: Arc::new(Mutex::new(None)),
            occurrence_metrics: Arc::new(OccurrenceMetrics::default()),
        }
    }

    /// Create a scheduler manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SchedulerConfig::default())
    }

    /// Return the random identifier associated with this scheduler instance.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Fail closed by blocking all one-time schedules for a journal condition.
    pub async fn block_one_time(&self, detail: impl Into<String>) {
        *self.one_time_global_block.lock().await = Some(detail.into());
    }

    /// Mark one one-time schedule as permanently consumed.
    pub async fn mark_one_time_consumed(&self, schedule_id: &str) {
        self.one_time_status
            .lock()
            .await
            .insert(schedule_id.to_owned(), OneTimeRuntimeStatus::Consumed);
    }

    /// Mark one one-time schedule as requiring operator recovery.
    pub async fn mark_one_time_recovery_required(
        &self,
        schedule_id: &str,
        detail: impl Into<String>,
    ) {
        self.one_time_status.lock().await.insert(
            schedule_id.to_owned(),
            OneTimeRuntimeStatus::RecoveryRequired {
                detail: detail.into(),
            },
        );
    }

    /// Return the global one-time journal block reason, if present.
    pub async fn one_time_block_reason(&self) -> Option<String> {
        self.one_time_global_block.lock().await.clone()
    }

    /// Return one-time readiness, with a global journal block taking precedence.
    pub async fn one_time_runtime_status(&self, schedule_id: &str) -> OneTimeRuntimeStatus {
        if let Some(detail) = self.one_time_global_block.lock().await.clone() {
            return OneTimeRuntimeStatus::RecoveryRequired { detail };
        }
        self.one_time_status
            .lock()
            .await
            .get(schedule_id)
            .cloned()
            .unwrap_or(OneTimeRuntimeStatus::Ready)
    }

    /// Return whether a tracked task is still active for an occurrence.
    #[must_use]
    pub fn has_active_occurrence(&self, occurrence_id: &str) -> bool {
        let mut tasks = self
            .dispatch_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.handle.is_finished());
        tasks.iter().any(|task| {
            debug_assert!(task
                .owner_id
                .as_deref()
                .is_none_or(|owner_id| !owner_id.is_empty()));
            task.occurrence_id.as_deref() == Some(occurrence_id)
        })
    }

    /// Record an expired non-terminal one-time occurrence.
    pub fn record_expired_one_time_occurrence(&self) {
        self.occurrence_metrics.record_expired_non_terminal();
    }

    /// Record a one-time recovery acknowledgement.
    pub fn record_one_time_acknowledgement(&self) {
        self.occurrence_metrics.record_acknowledgement();
    }

    /// Record a global block caused by corrupt one-time journal data.
    pub fn record_corrupt_one_time_journal(&self) {
        self.occurrence_metrics.record_corrupt_journal_block();
    }

    /// Return current one-time occurrence metrics.
    #[must_use]
    pub fn occurrence_metrics(&self) -> OccurrenceMetricsSnapshot {
        self.occurrence_metrics.snapshot()
    }

    /// Register a schedule.
    pub async fn register(&self, mut schedule: Schedule) {
        schedule.policies.resolve_defaults(
            self.config.default_missed_policy,
            self.config.default_concurrency_policy,
        );
        let mut store = self.store.lock().await;
        info!(schedule_id = %schedule.id, "Registering schedule");
        store.register(schedule);
    }

    /// Remove a schedule by ID. Returns `true` if found and removed.
    pub async fn remove(&self, id: &str) -> bool {
        let mut store = self.store.lock().await;
        info!(schedule_id = %id, "Removing schedule");
        store.remove(id)
    }

    /// Pause a schedule (set enabled = false).
    pub async fn pause(&self, id: &str) -> bool {
        let mut store = self.store.lock().await;
        let changed = store.set_enabled(id, false);
        let schedule = changed.then(|| store.get(id).cloned()).flatten();
        drop(store);
        if let Some(schedule) = &schedule {
            let persistence = self.persistence.lock().await.clone();
            Self::persist_schedule_definition(persistence.as_ref(), schedule).await;
        }
        changed
    }

    /// Resume a schedule (set enabled = true).
    pub async fn resume(&self, id: &str) -> bool {
        let mut store = self.store.lock().await;
        let changed = store.set_enabled(id, true);
        let schedule = changed.then(|| store.get(id).cloned()).flatten();
        drop(store);
        if let Some(schedule) = &schedule {
            let persistence = self.persistence.lock().await.clone();
            Self::persist_schedule_definition(persistence.as_ref(), schedule).await;
        }
        changed
    }

    /// Get a clone of a schedule by ID.
    pub async fn get_schedule(&self, id: &str) -> Option<Schedule> {
        let store = self.store.lock().await;
        store.get(id).cloned()
    }

    /// List all schedules.
    pub async fn list_schedules(&self) -> Vec<Schedule> {
        let store = self.store.lock().await;
        store.list().to_vec()
    }

    /// Get total execution count.
    pub async fn execution_count(&self) -> usize {
        let exec_store = self.execution_store.lock().await;
        exec_store.len()
    }

    /// Get execution history for a schedule (most recent first).
    pub async fn execution_history(&self, schedule_id: &str) -> Vec<ScheduleExecution> {
        let exec_store = self.execution_store.lock().await;
        exec_store
            .get_history(schedule_id)
            .into_iter()
            .cloned()
            .collect()
    }

    /// Get a reference to the execution store for direct access.
    pub fn execution_store(&self) -> &Arc<Mutex<ExecutionStore>> {
        &self.execution_store
    }

    /// Get a reference to the trigger sender for external event injection.
    ///
    /// # Panics
    ///
    /// Panics if the internal scheduler runtime mutex is poisoned.
    pub fn trigger_sender(&self) -> Option<TriggerSender> {
        self.runtime
            .lock()
            .expect("scheduler runtime lock poisoned")
            .trigger_tx
            .clone()
    }

    /// Feed an external event into the scheduler.
    ///
    /// The event is matched against every enabled event-driven schedule
    /// (event type, optional payload filter, debounce); matching schedules
    /// are fired through the same trigger queue and executor loop a cron
    /// fire uses, so `last_fire` and execution history behave identically.
    ///
    /// Matching happens in two phases so the schedule store is never held
    /// across an awaited queue send: triggers are prepared while the store
    /// is synchronously borrowed, then enqueued after the guard is released.
    /// A full trigger queue can delay an enqueue but never blocks store
    /// reads or executor progress.
    ///
    /// Returns the IDs of the schedules that fired. Events emitted while the
    /// scheduler is not running are dropped (nothing can consume them).
    pub async fn emit_event(&self, event: IncomingEvent) -> Vec<String> {
        let Some(tx) = self.trigger_sender() else {
            debug!(
                event_type = %event.event_type,
                "Event dropped: scheduler is not running"
            );
            return Vec::new();
        };
        let mut bridge = self.event_bridge.lock().await;
        // Phase 1: synchronous matching under the store guard. Nothing is
        // awaited while it is held, so queue backpressure can never stall
        // store readers (including the executor loop's schedule loads).
        let prepared = {
            let store = self.store.lock().await;
            bridge.prepare_triggers(&event, &store)
        };
        // Phase 2: enqueue with the store released. The bridge stays locked
        // across both phases, serializing events so debounce windows remain
        // consistent while sends wait for queue capacity.
        bridge.send_triggers(&event, prepared, &tx).await
    }

    /// Inject the workflow dispatcher used to run real executions.
    ///
    /// Called once after the service container is fully initialised (same
    /// pattern as `ServiceContainer::init_agent_runner`). Until this is
    /// called, fired triggers use the dispatcher-less `ScheduleExecutor`
    /// fallback (instant completion).
    pub async fn set_dispatcher(&self, dispatcher: Arc<dyn WorkflowDispatcher>) {
        let mut guard = self.dispatcher.lock().await;
        *guard = Some(dispatcher);
        info!("WorkflowDispatcher injected into SchedulerManager");
    }

    /// Return a clone of the dispatcher, if one has been injected.
    pub async fn dispatcher(&self) -> Option<Arc<dyn WorkflowDispatcher>> {
        self.dispatcher.lock().await.clone()
    }

    /// Inject the persistence adapter used to mirror runtime state to storage.
    pub async fn set_persistence(&self, persistence: Arc<dyn SchedulerPersistence>) {
        let mut guard = self.persistence.lock().await;
        *guard = Some(persistence);
        info!("Scheduler persistence injected into SchedulerManager");
    }

    /// Return a clone of the persistence adapter, if one has been injected.
    pub async fn persistence(&self) -> Option<Arc<dyn SchedulerPersistence>> {
        self.persistence.lock().await.clone()
    }

    /// Start the scheduler — spawns the trigger evaluation loop and executor loop.
    ///
    /// # Panics
    ///
    /// Panics if the internal scheduler runtime mutex is poisoned.
    pub async fn start(&self, tick_interval: Duration) {
        let _lifecycle = self.lifecycle.lock().await;
        let (tx, rx) = trigger_queue();
        let shutdown = {
            let mut runtime = self
                .runtime
                .lock()
                .expect("scheduler runtime lock poisoned");
            if runtime.eval_handle.is_some() || runtime.starting {
                warn!("Scheduler already running");
                return;
            }
            runtime.starting = true;
            runtime.startup_failed = false;
            runtime.trigger_tx = Some(tx.clone());
            Arc::clone(&runtime.shutdown)
        };

        info!(
            "Starting scheduler with tick interval {:?}, max_concurrent={}",
            tick_interval, self.config.max_concurrent_executions
        );

        // Keep cursors for held work unchanged until the operator arms it.
        // Skip cursors can be advanced immediately because they have no work.
        let (recovery_plan, advanced_schedules, held_advances, marked_schedules) = {
            let mut store_guard = self.store.lock().await;
            let recovery_now = Utc::now();
            let one_time_ids: HashSet<String> = store_guard
                .list_enabled()
                .into_iter()
                .filter(|schedule| {
                    matches!(
                        schedule.trigger,
                        crate::store::TriggerConfig::OneTime { .. }
                    )
                })
                .map(|schedule| schedule.id.clone())
                .collect();
            let mut plan = recovery::recover_missed(&store_guard, recovery_now);
            plan.batches
                .retain(|batch| !one_time_ids.contains(&batch.schedule_id));
            plan.advances
                .retain(|advance| !one_time_ids.contains(&advance.schedule_id));
            plan.result
                .caught_up
                .retain(|schedule_id| !one_time_ids.contains(schedule_id));
            plan.result
                .skipped
                .retain(|schedule_id| !one_time_ids.contains(schedule_id));
            plan.result
                .backfilled
                .retain(|(schedule_id, _)| !one_time_ids.contains(schedule_id));
            let held_ids: HashSet<_> = plan
                .batches
                .iter()
                .map(|batch| batch.schedule_id.clone())
                .collect();
            let (held, skipped): (Vec<_>, Vec<_>) = plan
                .advances
                .drain(..)
                .partition(|advance| held_ids.contains(&advance.schedule_id));
            let mut advanced = Vec::with_capacity(skipped.len());
            for advance in &skipped {
                store_guard.update_last_fire(&advance.schedule_id, advance.last_fire);
                if let Some(schedule) = store_guard.get(&advance.schedule_id) {
                    advanced.push(schedule.clone());
                }
            }
            let mut marked = Vec::new();
            for batch in &plan.batches {
                if let Some(mut schedule) = store_guard.get(&batch.schedule_id).cloned() {
                    let Some(advance) = held
                        .iter()
                        .find(|advance| advance.schedule_id == batch.schedule_id)
                    else {
                        continue;
                    };
                    schedule.recovery_pending = Some(recovery::RecoveryCheckpoint {
                        batch: batch.clone(),
                        last_fire: advance.last_fire,
                    });
                    store_guard.update(schedule.clone());
                    marked.push(schedule);
                }
            }
            (plan, advanced, held, marked)
        };

        let persistence_snapshot = self.persistence.lock().await.clone();
        for schedule in &advanced_schedules {
            Self::persist_schedule(persistence_snapshot.as_ref(), schedule).await;
        }
        if let Some(persistence) = persistence_snapshot.as_ref() {
            for schedule in &marked_schedules {
                if let Err(error) = persistence.update_schedule(schedule).await {
                    error!(schedule_id = %schedule.id, %error, "Cannot persist pending recovery; scheduler not started");
                    let mut runtime = self
                        .runtime
                        .lock()
                        .expect("scheduler runtime lock poisoned");
                    runtime.starting = false;
                    runtime.startup_failed = true;
                    runtime.trigger_tx = None;
                    return;
                }
            }
        }
        info!(
            "Recovery: {} caught up, {} skipped, {} backfilled ({} total triggers)",
            recovery_plan.result.caught_up.len(),
            recovery_plan.result.skipped.len(),
            recovery_plan.result.backfilled.len(),
            recovery_plan.trigger_count(),
        );

        // Start the consumer before the recovery producer. The producer expands
        // compact batches into the bounded channel asynchronously, so startup
        // cannot deadlock when more than 256 occurrences were missed.
        let exec_shutdown = shutdown.clone();
        let exec_store = self.store.clone();
        let exec_executor = self.executor.clone();
        let exec_execution_store = self.execution_store.clone();
        let exec_dispatcher = self.dispatcher.clone();
        let exec_persistence = self.persistence.clone();
        let exec_slots = Arc::clone(&self.execution_slots);
        let exec_serial_locks = Arc::clone(&self.serial_locks);
        let exec_admission_locks = Arc::clone(&self.admission_locks);
        let exec_tasks = Arc::clone(&self.dispatch_tasks);
        let exec_one_time_admissions = Arc::clone(&self.one_time_admissions);
        let exec_one_time_status = Arc::clone(&self.one_time_status);
        let exec_one_time_global_block = Arc::clone(&self.one_time_global_block);
        let exec_occurrence_metrics = Arc::clone(&self.occurrence_metrics);
        let exec_owner_id = self.owner_id.clone();
        let held_schedules = Arc::new(Mutex::new(
            held_advances
                .iter()
                .map(|advance| advance.schedule_id.clone())
                .collect::<HashSet<_>>(),
        ));
        let max_event_cascade_depth = self.config.max_event_cascade_depth;
        let recovery_failures = Arc::new(
            held_advances
                .iter()
                .map(|advance| {
                    (
                        advance.schedule_id.clone(),
                        Arc::new(AtomicBool::new(false)),
                    )
                })
                .collect::<HashMap<_, _>>(),
        );
        let exec_recovery_failures = recovery_failures.clone();
        let exec_handle = tokio::spawn(async move {
            Self::executor_loop(
                rx,
                exec_store,
                exec_executor,
                exec_execution_store,
                exec_dispatcher,
                exec_persistence,
                exec_slots,
                exec_serial_locks,
                exec_admission_locks,
                exec_tasks,
                exec_one_time_admissions,
                exec_one_time_status,
                exec_one_time_global_block,
                exec_occurrence_metrics,
                exec_owner_id,
                max_event_cascade_depth,
                exec_recovery_failures,
                exec_shutdown,
            )
            .await;
        });

        let recovery_context = RecoveryContext {
            store: self.store.clone(),
            executor: self.executor.clone(),
            executions: self.execution_store.clone(),
            dispatcher: self.dispatcher.clone(),
            persistence: self.persistence.clone(),
            slots: self.execution_slots.clone(),
            serial_locks: self.serial_locks.clone(),
            admission_locks: self.admission_locks.clone(),
            tasks: self.dispatch_tasks.clone(),
            admissions: self.one_time_admissions.clone(),
            one_time_status: self.one_time_status.clone(),
            one_time_global_block: self.one_time_global_block.clone(),
            metrics: self.occurrence_metrics.clone(),
            owner_id: self.owner_id.clone(),
            max_event_cascade_depth,
            held: held_schedules.clone(),
            failures: recovery_failures,
            arm: self.arm.clone(),
            shutdown: shutdown.clone(),
        };
        let (recovery_cancel, mut recovery_cancelled) = tokio::sync::oneshot::channel();
        let recovery_handle = tokio::spawn(async move {
            let mut jobs = tokio::task::JoinSet::new();
            for batch in recovery_plan.batches {
                if let Some(advance) = held_advances
                    .iter()
                    .find(|advance| advance.schedule_id == batch.schedule_id)
                    .cloned()
                {
                    jobs.spawn(Self::run_recovery_batch(
                        batch,
                        advance,
                        recovery_context.clone(),
                    ));
                }
            }
            while !jobs.is_empty() {
                tokio::select! {
                    _ = &mut recovery_cancelled => {
                        jobs.abort_all();
                        while jobs.join_next().await.is_some() {}
                        return;
                    }
                    result = jobs.join_next() => {
                        if let Some(Err(error)) = result {
                            error!(%error, "Recovery batch task failed");
                        }
                    }
                }
            }
        });

        let store = self.store.clone();

        // Trigger evaluation loop.
        let eval_shutdown = shutdown.clone();
        let eval_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick_interval);
            loop {
                tokio::select! {
                    () = eval_shutdown.notified() => {
                        info!("Trigger evaluation loop shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        let store_guard = store.lock().await;
                        let held = held_schedules.lock().await;
                        let schedules: Vec<Schedule> = store_guard.list_enabled()
                            .into_iter()
                            .filter(|schedule| !held.contains(&schedule.id))
                            .cloned()
                            .map(|mut schedule| {
                                if let Some(checkpoint) = &schedule.recovery_pending {
                                    let covered_until = checkpoint.latest_fire();
                                    schedule.last_fire = Some(schedule.last_fire.map_or(covered_until, |last| last.max(covered_until)));
                                }
                                schedule
                            })
                            .collect();
                        drop(held);
                        drop(store_guard);

                        let now = Utc::now();
                        let fired = evaluate_all(&schedules, now);

                        for trigger in fired {
                            debug!(schedule_id = %trigger.schedule_id, "Trigger fired");
                            if tx.send(trigger).await.is_err() {
                                warn!("Trigger queue closed, stopping evaluation");
                                return;
                            }
                        }
                    }
                }
            }
        });

        let mut runtime = self
            .runtime
            .lock()
            .expect("scheduler runtime lock poisoned");
        runtime.recovery_handle = Some(recovery_handle);
        runtime.recovery_cancel = Some(recovery_cancel);
        runtime.eval_handle = Some(eval_handle);
        runtime.exec_handle = Some(exec_handle);
        runtime.starting = false;
    }

    async fn run_recovery_batch(
        batch: recovery::RecoveryBatch,
        advance: recovery::RecoveryAdvance,
        context: RecoveryContext,
    ) {
        let Some(failed) = context.failures.get(&advance.schedule_id).cloned() else {
            return;
        };
        let checkpoint = {
            let store = context.store.lock().await;
            let Some(checkpoint) = store
                .get(&advance.schedule_id)
                .and_then(|schedule| schedule.recovery_pending.clone())
            else {
                return;
            };
            checkpoint
        };
        let (tx, mut rx) = trigger_queue();
        let count = batch.count;
        let mut producer = tokio::task::JoinSet::new();
        let mut plan = recovery::RecoveryPlan::default();
        plan.batches.push(batch);
        producer.spawn(Self::submit_recovery(
            plan,
            tx,
            context.shutdown.clone(),
            context.arm.clone(),
        ));
        for _ in 0..count {
            loop {
                if failed.load(Ordering::SeqCst) {
                    return;
                }
                let pending = context
                    .executions
                    .lock()
                    .await
                    .pending_count(&advance.schedule_id);
                if pending < crate::queue::DEFAULT_QUEUE_CAPACITY {
                    break;
                }
                tokio::select! {
                    () = context.shutdown.notified() => return,
                    () = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
            let fired = tokio::select! {
                () = context.shutdown.notified() => return,
                fired = rx.recv() => match fired { Some(fired) => fired, None => return },
            };
            loop {
                tokio::select! {
                    () = context.shutdown.notified() => return,
                    () = context.arm.wait_until_armed() => {},
                }
                let schedule = context
                    .store
                    .lock()
                    .await
                    .get(&advance.schedule_id)
                    .cloned();
                match schedule {
                    Some(schedule) if schedule.enabled && context.arm.is_armed() => break,
                    Some(_) => {}
                    None => return,
                }
                tokio::select! {
                    () = context.shutdown.notified() => return,
                    () = tokio::time::sleep(Duration::from_millis(10)) => {},
                }
            }
            let dispatcher = context.dispatcher.lock().await.clone();
            let persistence = context.persistence.lock().await.clone().map(|inner| {
                Arc::new(RecoveryPersistence {
                    inner,
                    failed: failed.clone(),
                }) as Arc<dyn SchedulerPersistence>
            });
            Self::handle_fired_trigger(
                fired,
                &context.store,
                &context.executor,
                &context.executions,
                dispatcher,
                persistence,
                &context.serial_locks,
                &context.admission_locks,
                &context.tasks,
                &context.slots,
                &context.admissions,
                &context.one_time_status,
                &context.one_time_global_block,
                &context.metrics,
                &context.owner_id,
                context.max_event_cascade_depth,
                &failed,
                Some(&checkpoint),
            )
            .await;
            if failed.load(Ordering::SeqCst) {
                return;
            }
        }
        if !matches!(producer.join_next().await, Some(Ok(true))) {
            return;
        }
        context.held.lock().await.remove(&advance.schedule_id);
        loop {
            if failed.load(Ordering::SeqCst) {
                context
                    .held
                    .lock()
                    .await
                    .insert(advance.schedule_id.clone());
                return;
            }
            let active = context
                .tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|task| {
                    task.schedule_id == advance.schedule_id
                        && task
                            .recovery_failed
                            .as_ref()
                            .is_some_and(|state| Arc::ptr_eq(state, &failed))
                        && !task.handle.is_finished()
                });
            let unfinished = context
                .executions
                .lock()
                .await
                .list_recent(usize::MAX)
                .iter()
                .any(|execution| {
                    execution.schedule_id == advance.schedule_id
                        && execution.request_summary["is_recovery"].as_bool() == Some(true)
                        && matches!(
                            execution.status,
                            ExecutionStatus::Pending | ExecutionStatus::Running
                        )
                });
            if !active && !unfinished && !failed.load(Ordering::SeqCst) {
                break;
            }
            tokio::select! {
                () = context.shutdown.notified() => return,
                () = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
        let current = context
            .store
            .lock()
            .await
            .get(&advance.schedule_id)
            .cloned();
        if let Some(mut schedule) = current {
            let Some(checkpoint) = schedule.recovery_pending.clone() else {
                return;
            };
            schedule.last_fire = Some(
                schedule
                    .last_fire
                    .map_or(advance.last_fire, |last| last.max(advance.last_fire)),
            );
            schedule.recovery_pending = None;
            let persistence = context.persistence.lock().await.clone();
            if let Some(persistence) = persistence {
                if let Err(error) = persistence.complete_recovery(&schedule, &checkpoint).await {
                    failed.store(true, Ordering::SeqCst);
                    error!(schedule_id = %schedule.id, %error, "Cannot persist completed recovery; schedule remains held");
                    context
                        .held
                        .lock()
                        .await
                        .insert(advance.schedule_id.clone());
                    return;
                }
            }
            let mut store = context.store.lock().await;
            if let Some(mut current) = store.get(&advance.schedule_id).cloned() {
                if current.recovery_pending.as_ref() != Some(&checkpoint) {
                    failed.store(true, Ordering::SeqCst);
                    return;
                }
                current.last_fire = Some(
                    current
                        .last_fire
                        .map_or(advance.last_fire, |last| last.max(advance.last_fire)),
                );
                current.recovery_pending = None;
                store.update(current);
            }
        }
        context.held.lock().await.remove(&advance.schedule_id);
    }

    async fn submit_recovery(
        plan: recovery::RecoveryPlan,
        tx: TriggerSender,
        shutdown: Arc<Notify>,
        arm: crate::arming::ArmSignal,
    ) -> bool {
        // Recovery restored what this scheduler was doing. Acting on it needs a
        // fresh decision, so the plan is held here rather than discarded: an
        // operator who arms the scheduler gets the missed occurrences, and one
        // who never does gets none of them.
        for batch in plan.batches {
            let mut fired_at = batch.first_fire;
            let mut remaining = batch.count;
            while remaining > 0 {
                let trigger = recovery::trigger_at(&batch, fired_at);
                loop {
                    tokio::select! {
                        () = shutdown.notified() => return false,
                        () = arm.wait_until_armed() => {},
                    }
                    let permit = tokio::select! {
                        () = shutdown.notified() => return false,
                        result = tx.reserve() => match result {
                            Ok(permit) => permit,
                            Err(_) => return false,
                        },
                    };
                    if arm.is_armed() {
                        permit.send(trigger);
                        break;
                    }
                }
                remaining -= 1;
                if remaining > 0 {
                    let Some(next) = batch.next_fire(fired_at) else {
                        warn!(schedule_id = %batch.schedule_id, "Cannot advance recovery schedule");
                        return false;
                    };
                    fired_at = next;
                }
            }
        }
        true
    }

    /// Authorize restored work to run, releasing any recovery held since start.
    ///
    /// This is the fresh decision a restart deliberately does not make on the
    /// operator's behalf. Calling it twice is harmless.
    pub fn arm(&self) {
        self.arm.arm();
    }

    /// Withdraw authorization. Recovery not yet released stays held.
    pub fn disarm(&self) {
        self.arm.disarm();
    }

    /// Whether restored work is currently authorized to run.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.arm.is_armed()
    }

    /// Internal executor consumer loop.
    async fn executor_loop(
        mut rx: TriggerReceiver,
        store: Arc<Mutex<ScheduleStore>>,
        executor: Arc<Mutex<ScheduleExecutor>>,
        execution_store: Arc<Mutex<ExecutionStore>>,
        dispatcher: Arc<Mutex<Option<Arc<dyn WorkflowDispatcher>>>>,
        persistence: Arc<Mutex<Option<Arc<dyn SchedulerPersistence>>>>,
        execution_slots: Arc<Semaphore>,
        serial_locks: SerialLocks,
        admission_locks: SerialLocks,
        dispatch_tasks: DispatchTasks,
        one_time_admissions: OneTimeAdmissions,
        one_time_status: Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        one_time_global_block: Arc<Mutex<Option<String>>>,
        occurrence_metrics: Arc<OccurrenceMetrics>,
        owner_id: String,
        max_event_cascade_depth: u32,
        recovery_failures: RecoveryFailures,
        shutdown: Arc<Notify>,
    ) {
        loop {
            let trigger = tokio::select! {
                () = shutdown.notified() => {
                    info!("Executor loop shutting down");
                    break;
                }
                trigger = rx.recv() => trigger,
            };
            if let Some(mut fired) = trigger {
                fired.is_recovery = false;
                let recovery_failed = recovery_failures
                    .get(&fired.schedule_id)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
                // Re-read the dispatcher on every trigger so that
                // late injection (after loop start) takes effect.
                let current_dispatcher = dispatcher.lock().await.clone();
                let current_persistence = persistence.lock().await.clone();
                Self::handle_fired_trigger(
                    fired,
                    &store,
                    &executor,
                    &execution_store,
                    current_dispatcher,
                    current_persistence,
                    &serial_locks,
                    &admission_locks,
                    &dispatch_tasks,
                    &execution_slots,
                    &one_time_admissions,
                    &one_time_status,
                    &one_time_global_block,
                    &occurrence_metrics,
                    &owner_id,
                    max_event_cascade_depth,
                    &recovery_failed,
                    None,
                )
                .await;
            } else {
                info!("Trigger queue closed, executor stopping");
                break;
            }
        }
    }

    fn schedule_has_active_dispatch(dispatch_tasks: &DispatchTasks, schedule_id: &str) -> bool {
        let mut tasks = dispatch_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.handle.is_finished());
        tasks.iter().any(|task| task.schedule_id == schedule_id)
    }

    async fn mark_consumed(statuses: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>, id: &str) {
        statuses
            .lock()
            .await
            .insert(id.to_owned(), OneTimeRuntimeStatus::Consumed);
    }

    async fn mark_recovery_required(
        statuses: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        id: &str,
        detail: impl Into<String>,
    ) {
        statuses.lock().await.insert(
            id.to_owned(),
            OneTimeRuntimeStatus::RecoveryRequired {
                detail: detail.into(),
            },
        );
    }

    fn log_one_time_reservation(
        occurrence: &OneTimeOccurrence,
        reservation_outcome: &'static str,
        duration_ms: u64,
    ) {
        debug!(
            occurrence_id = %occurrence.id,
            schedule_id = %occurrence.schedule_id,
            execution_id = %occurrence.execution_id,
            reservation_outcome,
            duration_ms,
            "Persisted one-time occurrence reservation"
        );
    }

    async fn one_time_trigger_blocked(
        schedule_id: &str,
        statuses: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        global_block: &Arc<Mutex<Option<String>>>,
    ) -> bool {
        if global_block.lock().await.is_some() {
            warn!(
                occurrence_id = ONE_TIME_ID_NOT_RESERVED,
                schedule_id,
                execution_id = ONE_TIME_ID_NOT_RESERVED,
                recovery_reason = "journal_health",
                "One-time schedule blocked by journal health"
            );
            return true;
        }
        match statuses.lock().await.get(schedule_id).cloned() {
            Some(OneTimeRuntimeStatus::Consumed) => {
                debug!(schedule_id, "Consumed one-time schedule suppressed");
                true
            }
            Some(OneTimeRuntimeStatus::RecoveryRequired { .. }) => {
                warn!(
                    occurrence_id = ONE_TIME_ID_NOT_RESERVED,
                    schedule_id,
                    execution_id = ONE_TIME_ID_NOT_RESERVED,
                    recovery_reason = "runtime_status",
                    "One-time schedule requires recovery"
                );
                true
            }
            Some(OneTimeRuntimeStatus::Ready) | None => false,
        }
    }

    fn register_one_time_admission(admissions: &OneTimeAdmissions, occurrence: &OneTimeOccurrence) {
        admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                occurrence.id.clone(),
                PendingOneTimeAdmission {
                    occurrence_id: occurrence.id.clone(),
                    schedule_id: occurrence.schedule_id.clone(),
                    execution_id: occurrence.execution_id.clone(),
                    owner_id: occurrence.owner_id.clone(),
                },
            );
    }

    fn clear_one_time_admission(admissions: &OneTimeAdmissions, occurrence_id: &str) {
        admissions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(occurrence_id);
    }

    fn take_active_dispatches(
        dispatch_tasks: &DispatchTasks,
        schedule_id: &str,
    ) -> Vec<TrackedDispatch> {
        let mut tasks = dispatch_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut retained = Vec::with_capacity(tasks.len());
        let mut cancelled = Vec::new();
        for task in tasks.drain(..) {
            if task.handle.is_finished() {
                continue;
            }
            if task.schedule_id == schedule_id {
                if let Some(failed) = &task.recovery_failed {
                    failed.store(true, Ordering::SeqCst);
                }
                cancelled.push(task);
            } else {
                retained.push(task);
            }
        }
        *tasks = retained;
        cancelled
    }

    async fn cancel_previous_dispatches(
        dispatch_tasks: &DispatchTasks,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
        schedule_id: &str,
    ) {
        let cancelled = Self::take_active_dispatches(dispatch_tasks, schedule_id);
        for task in &cancelled {
            task.handle.abort();
        }
        for task in cancelled {
            let _ = task.handle.await;
            let updated = {
                let mut executions = execution_store.lock().await;
                executions.update_and_get(&task.execution_id, |record| {
                    if matches!(
                        record.status,
                        ExecutionStatus::Pending | ExecutionStatus::Running
                    ) {
                        record.status = ExecutionStatus::Cancelled;
                        record.completed_at = Some(Utc::now());
                        record.error_message =
                            Some("cancelled by newer schedule trigger".to_owned());
                        record.response_summary = serde_json::json!({
                            "status": "cancelled",
                            "reason": "cancelled by newer schedule trigger",
                        });
                    }
                })
            };
            if let Some(updated) = updated {
                Self::persist_update(persistence, &updated).await;
            }
        }
    }

    async fn record_policy_skip(
        fired: &FiredTrigger,
        schedule: &Schedule,
        reason: String,
        store: &Arc<Mutex<ScheduleStore>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
    ) {
        let now = Utc::now();
        let record = ScheduleExecution {
            execution_id: format!("exec-{}-{}", schedule.id, uuid::Uuid::new_v4()),
            schedule_id: schedule.id.clone(),
            triggered_at: fired.fired_at,
            started_at: None,
            completed_at: Some(now),
            status: ExecutionStatus::Skipped,
            workflow_execution_id: None,
            request_summary: serde_json::json!({
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "workflow_id": schedule.workflow_id,
                "trigger": serde_json::to_value(&schedule.trigger).unwrap_or_default(),
                "parameter_values": schedule.parameter_values,
                "trigger_time": fired.fired_at.to_rfc3339(),
                "cascade_depth": fired.cascade_depth,
                "is_recovery": fired.is_recovery,
            }),
            response_summary: serde_json::json!({
                "status": "skipped",
                "reason": reason,
            }),
            error_message: None,
        };
        execution_store.lock().await.record(record.clone());
        let updated_schedule = {
            let mut schedules = store.lock().await;
            schedules.update_last_fire(&schedule.id, Self::cursor_time(fired, now));
            schedules.get(&schedule.id).cloned()
        };
        if let Some(updated_schedule) = &updated_schedule {
            Self::persist_schedule(persistence, updated_schedule).await;
        }
        Self::persist_record(persistence, &record).await;
    }

    /// Record a trigger whose dispatch failed before the workflow could start
    /// (currently: parameter resolution errors). The failure is visible in
    /// execution history and the fire cursor advances, so a permanently broken
    /// schedule fails once per fire instead of hot-looping on every tick.
    async fn record_dispatch_failure(
        fired: &FiredTrigger,
        schedule: &Schedule,
        message: String,
        store: &Arc<Mutex<ScheduleStore>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
    ) {
        let now = Utc::now();
        let record = ScheduleExecution {
            execution_id: format!("exec-{}-{}", schedule.id, uuid::Uuid::new_v4()),
            schedule_id: schedule.id.clone(),
            triggered_at: fired.fired_at,
            started_at: None,
            completed_at: Some(now),
            status: ExecutionStatus::Failed,
            workflow_execution_id: None,
            request_summary: serde_json::json!({
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "workflow_id": schedule.workflow_id,
                "trigger": serde_json::to_value(&schedule.trigger).unwrap_or_default(),
                "parameter_values": schedule.parameter_values,
                "trigger_time": fired.fired_at.to_rfc3339(),
                "cascade_depth": fired.cascade_depth,
            }),
            response_summary: serde_json::json!({
                "status": "failed",
                "error": message,
            }),
            error_message: Some(message),
        };
        execution_store.lock().await.record(record.clone());
        let updated_schedule = {
            let mut schedules = store.lock().await;
            schedules.update_last_fire(&schedule.id, Self::cursor_time(fired, now));
            schedules.get(&schedule.id).cloned()
        };
        if let Some(updated_schedule) = &updated_schedule {
            Self::persist_schedule(persistence, updated_schedule).await;
        }
        Self::persist_record(persistence, &record).await;
    }

    async fn handle_one_time_trigger(
        fired: FiredTrigger,
        schedule: Schedule,
        store: &Arc<Mutex<ScheduleStore>>,
        executor: &Arc<Mutex<ScheduleExecutor>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        dispatcher: Option<Arc<dyn WorkflowDispatcher>>,
        persistence: Option<Arc<dyn SchedulerPersistence>>,
        serial_locks: &SerialLocks,
        dispatch_tasks: &DispatchTasks,
        execution_slots: &Arc<Semaphore>,
        one_time_admissions: &OneTimeAdmissions,
        one_time_status: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        one_time_global_block: &Arc<Mutex<Option<String>>>,
        occurrence_metrics: &Arc<OccurrenceMetrics>,
        owner_id: &str,
    ) {
        if Self::one_time_trigger_blocked(&schedule.id, one_time_status, one_time_global_block)
            .await
        {
            return;
        }

        let Some(dispatcher) = dispatcher else {
            let detail = "one-time workflow dispatcher is unavailable";
            Self::mark_recovery_required(one_time_status, &schedule.id, detail).await;
            warn!(
                occurrence_id = ONE_TIME_ID_NOT_RESERVED,
                schedule_id = %schedule.id,
                execution_id = ONE_TIME_ID_NOT_RESERVED,
                recovery_reason = "dispatcher_unavailable",
                "One-time schedule dispatch unavailable"
            );
            return;
        };
        let Some(persistence) = persistence else {
            let detail = "durable one-time occurrence persistence is unavailable";
            Self::mark_recovery_required(one_time_status, &schedule.id, detail).await;
            warn!(
                occurrence_id = ONE_TIME_ID_NOT_RESERVED,
                schedule_id = %schedule.id,
                execution_id = ONE_TIME_ID_NOT_RESERVED,
                recovery_reason = "reservation_unavailable",
                "One-time occurrence persistence unavailable"
            );
            return;
        };

        let concurrency_policy = schedule.policies.effective_concurrency_policy();
        match concurrency_policy {
            ConcurrencyPolicy::SkipIfRunning
                if Self::schedule_has_active_dispatch(dispatch_tasks, &schedule.id) =>
            {
                Self::record_policy_skip(
                    &fired,
                    &schedule,
                    "previous execution is still running".to_owned(),
                    store,
                    execution_store,
                    Some(&persistence),
                )
                .await;
                return;
            }
            ConcurrencyPolicy::CancelPrevious => {
                Self::cancel_previous_dispatches(
                    dispatch_tasks,
                    execution_store,
                    Some(&persistence),
                    &schedule.id,
                )
                .await;
            }
            ConcurrencyPolicy::Allow
            | ConcurrencyPolicy::Queue
            | ConcurrencyPolicy::SkipIfRunning => {}
        }

        let sequence = executor.lock().await.next_sequence_for(&schedule.id);
        let context = crate::params::ResolutionContext {
            trigger_time: fired.fired_at,
            trigger_type: fired.trigger_type,
            execution_sequence: sequence,
            event_payload: fired.event_payload.clone(),
        };
        let parameter_values = match crate::params::resolve_parameters(
            &serde_json::json!({}),
            &schedule.parameter_values,
            &context,
        ) {
            Ok(values) => values,
            Err(error) => {
                Self::record_dispatch_failure(
                    &fired,
                    &schedule,
                    format!("parameter resolution failed: {error}"),
                    store,
                    execution_store,
                    Some(&persistence),
                )
                .await;
                return;
            }
        };

        let now = Utc::now();
        let occurrence_id = format!("occ-{}-{}", schedule.id, uuid::Uuid::new_v4());
        let execution_id = format!("exec-{}-{}", schedule.id, uuid::Uuid::new_v4());
        let lease_expires_at = now
            + chrono::Duration::from_std(ONE_TIME_LEASE)
                .expect("one-time lease duration fits chrono");
        let occurrence = OneTimeOccurrence {
            id: occurrence_id,
            schedule_id: schedule.id.clone(),
            execution_id: execution_id.clone(),
            triggered_at: fired.fired_at,
            state: OneTimeOccurrenceState::Reserved,
            owner_id: owner_id.to_owned(),
            lease_expires_at: Some(lease_expires_at),
            recovery_detail: None,
        };
        let request_summary = serde_json::json!({
            "schedule_id": schedule.id,
            "schedule_name": schedule.name,
            "workflow_id": schedule.workflow_id,
            "trigger": serde_json::to_value(&schedule.trigger).unwrap_or_default(),
            "parameter_values": parameter_values,
            "execution_sequence": sequence,
            "trigger_time": fired.fired_at.to_rfc3339(),
                "cascade_depth": fired.cascade_depth,
        });
        let pending = ScheduleExecution {
            execution_id,
            schedule_id: schedule.id.clone(),
            triggered_at: fired.fired_at,
            started_at: None,
            completed_at: None,
            status: ExecutionStatus::Pending,
            workflow_execution_id: None,
            request_summary,
            response_summary: serde_json::json!({}),
            error_message: None,
        };

        let admission_id = occurrence.id.clone();
        Self::register_one_time_admission(one_time_admissions, &occurrence);
        let reservation_started = std::time::Instant::now();
        let reservation_result = persistence
            .reserve_one_time_occurrence(&occurrence, &pending)
            .await;
        let reservation_duration_ms =
            u64::try_from(reservation_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let occurrence = match reservation_result {
            Ok(OneTimeReservation::Reserved(reserved)) => {
                occurrence_metrics.record_reservation_win();
                Self::log_one_time_reservation(&reserved, "reserved", reservation_duration_ms);
                execution_store.lock().await.record(pending.clone());
                reserved
            }
            Ok(OneTimeReservation::Existing(existing)) => {
                occurrence_metrics.record_duplicate_suppression();
                Self::log_one_time_reservation(&existing, "existing", reservation_duration_ms);
                let updated = {
                    let mut schedules = store.lock().await;
                    schedules.update_last_fire(&schedule.id, existing.triggered_at);
                    schedules.get(&schedule.id).cloned()
                };
                if let Some(updated) = updated {
                    if persistence.update_schedule(&updated).await.is_err() {
                        Self::mark_recovery_required(
                            one_time_status,
                            &schedule.id,
                            "receipt exists but the JSON cursor could not be reconciled",
                        )
                        .await;
                        warn!(
                            occurrence_id = %existing.id,
                            schedule_id = %existing.schedule_id,
                            execution_id = %existing.execution_id,
                            recovery_reason = "cursor_persistence",
                            "Existing one-time receipt cursor reconciliation failed"
                        );
                    } else if existing.recovery_eligible(Utc::now()) {
                        Self::mark_recovery_required(
                            one_time_status,
                            &schedule.id,
                            "existing non-terminal one-time occurrence requires acknowledgement",
                        )
                        .await;
                        warn!(
                            occurrence_id = %existing.id,
                            schedule_id = %existing.schedule_id,
                            execution_id = %existing.execution_id,
                            recovery_reason = "expired_non_terminal",
                            "Existing one-time receipt requires recovery"
                        );
                    } else {
                        Self::mark_consumed(one_time_status, &schedule.id).await;
                    }
                }
                Self::clear_one_time_admission(one_time_admissions, &admission_id);
                return;
            }
            Err(_) => {
                let recovered = persistence
                    .get_one_time_occurrence(&occurrence.id)
                    .await
                    .ok()
                    .flatten();
                if let Some(existing) = recovered {
                    let updated = {
                        let mut schedules = store.lock().await;
                        schedules.update_last_fire(&schedule.id, existing.triggered_at);
                        schedules.get(&schedule.id).cloned()
                    };
                    let cursor_durable = match updated {
                        Some(updated) => persistence.update_schedule(&updated).await.is_ok(),
                        None => false,
                    };
                    if !existing.terminal() {
                        let _released = persistence
                            .release_one_time_lease(
                                &existing.id,
                                &existing.owner_id,
                                Utc::now(),
                                "reservation result was ambiguous",
                            )
                            .await;
                    }
                    if existing.terminal() && cursor_durable {
                        Self::mark_consumed(one_time_status, &schedule.id).await;
                    } else {
                        Self::mark_recovery_required(
                            one_time_status,
                            &schedule.id,
                            "reservation committed but dispatch admission is ambiguous",
                        )
                        .await;
                    }
                } else {
                    Self::mark_recovery_required(
                        one_time_status,
                        &schedule.id,
                        "one-time occurrence reservation is unavailable",
                    )
                    .await;
                }
                Self::clear_one_time_admission(one_time_admissions, &admission_id);
                warn!(
                    occurrence_id = %occurrence.id,
                    schedule_id = %schedule.id,
                    execution_id = %occurrence.execution_id,
                    reservation_outcome = "unavailable",
                    duration_ms = reservation_duration_ms,
                    recovery_reason = "reservation_unavailable",
                    "One-time occurrence reservation failed closed"
                );
                return;
            }
        };

        let updated_schedule = {
            let mut schedules = store.lock().await;
            schedules.update_last_fire(&schedule.id, Self::cursor_time(&fired, now));
            schedules.get(&schedule.id).cloned()
        };
        let cursor_persisted = match updated_schedule {
            Some(updated) => persistence.update_schedule(&updated).await.is_ok(),
            None => false,
        };
        if !cursor_persisted {
            let detail = "schedule cursor persistence failed after durable reservation";
            let released_at = Utc::now();
            let _released = persistence
                .release_one_time_lease(&occurrence.id, owner_id, released_at, detail)
                .await;
            Self::mark_recovery_required(one_time_status, &schedule.id, detail).await;
            warn!(
                occurrence_id = %occurrence.id,
                schedule_id = %schedule.id,
                execution_id = %occurrence.execution_id,
                recovery_reason = "cursor_persistence",
                "Reserved one-time occurrence quarantined before dispatch"
            );
            Self::clear_one_time_admission(one_time_admissions, &admission_id);
            return;
        }
        Self::mark_consumed(one_time_status, &schedule.id).await;

        Self::clear_one_time_admission(one_time_admissions, &admission_id);
        Self::spawn_one_time_dispatch(
            schedule,
            pending,
            &occurrence,
            parameter_values,
            concurrency_policy,
            dispatcher,
            persistence,
            serial_locks,
            dispatch_tasks,
            execution_store,
            execution_slots,
            one_time_status,
            occurrence_metrics,
        );
    }

    fn spawn_one_time_dispatch(
        schedule: Schedule,
        pending: ScheduleExecution,
        occurrence: &OneTimeOccurrence,
        parameter_values: serde_json::Value,
        concurrency_policy: ConcurrencyPolicy,
        dispatcher: Arc<dyn WorkflowDispatcher>,
        persistence: Arc<dyn SchedulerPersistence>,
        serial_locks: &SerialLocks,
        dispatch_tasks: &DispatchTasks,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        execution_slots: &Arc<Semaphore>,
        one_time_status: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        occurrence_metrics: &Arc<OccurrenceMetrics>,
    ) {
        let execution_id = pending.execution_id.clone();
        let schedule_id = schedule.id.clone();
        let occurrence_id = occurrence.id.clone();
        let occurrence_owner_id = occurrence.owner_id.clone();
        let occurrence = occurrence.clone();
        let serial_locks = Arc::clone(serial_locks);
        let execution_store = Arc::clone(execution_store);
        let execution_slots = Arc::clone(execution_slots);
        let one_time_status = Arc::clone(one_time_status);
        let occurrence_metrics = Arc::clone(occurrence_metrics);
        let one_time_terminal_allowed = Arc::new(AtomicBool::new(true));
        let terminal_allowed = Arc::clone(&one_time_terminal_allowed);

        let handle = tokio::spawn(async move {
            Self::run_one_time_dispatch(
                schedule,
                pending,
                occurrence,
                parameter_values,
                concurrency_policy,
                dispatcher,
                persistence,
                serial_locks,
                execution_store,
                execution_slots,
                one_time_status,
                occurrence_metrics,
                terminal_allowed,
            )
            .await;
        });
        let mut tasks = dispatch_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tasks.retain(|task| !task.handle.is_finished());
        tasks.push(TrackedDispatch {
            execution_id,
            schedule_id,
            occurrence_id: Some(occurrence_id),
            owner_id: Some(occurrence_owner_id),
            one_time_terminal_allowed: Some(one_time_terminal_allowed),
            recovery_failed: None,
            handle,
        });
    }

    async fn run_one_time_dispatch(
        schedule: Schedule,
        pending: ScheduleExecution,
        occurrence: OneTimeOccurrence,
        parameter_values: serde_json::Value,
        concurrency_policy: ConcurrencyPolicy,
        dispatcher: Arc<dyn WorkflowDispatcher>,
        persistence: Arc<dyn SchedulerPersistence>,
        serial_locks: SerialLocks,
        execution_store: Arc<Mutex<ExecutionStore>>,
        execution_slots: Arc<Semaphore>,
        one_time_status: Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        occurrence_metrics: Arc<OccurrenceMetrics>,
        terminal_allowed: Arc<AtomicBool>,
    ) {
        let schedule_id = schedule.id.clone();
        let workflow_id = schedule.workflow_id;
        let serial_lock = if concurrency_policy == ConcurrencyPolicy::Queue {
            let mut locks = serial_locks.lock().await;
            Some(
                locks
                    .entry(schedule_id.clone())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone(),
            )
        } else {
            None
        };

        let admission = async move {
            let serial_guard = match serial_lock {
                Some(lock) => Some(lock.lock_owned().await),
                None => None,
            };
            let execution_permit = execution_slots
                .acquire_owned()
                .await
                .expect("scheduler execution semaphore is never closed");
            (serial_guard, execution_permit)
        };
        tokio::pin!(admission);
        let mut heartbeat = tokio::time::interval(ONE_TIME_HEARTBEAT);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let (_serial_guard, _execution_permit) = loop {
            tokio::select! {
                guards = &mut admission => break guards,
                _ = heartbeat.tick() => {
                    let next_expiry = Utc::now()
                        + chrono::Duration::from_std(ONE_TIME_LEASE)
                            .expect("one-time lease duration fits chrono");
                    let renewed = persistence
                        .renew_one_time_lease(
                            &occurrence.id,
                            &occurrence.owner_id,
                            next_expiry,
                        )
                        .await;
                    if !matches!(renewed, Ok(true)) {
                        occurrence_metrics.record_lease_renewal_failure();
                        Self::mark_recovery_required(
                            &one_time_status,
                            &occurrence.schedule_id,
                            "one-time ownership lease renewal failed before dispatch",
                        )
                        .await;
                        let _released = persistence
                            .release_one_time_lease(
                                &occurrence.id,
                                &occurrence.owner_id,
                                Utc::now(),
                                "lease renewal failed before dispatcher entry",
                            )
                            .await;
                        error!(
                            occurrence_id = %occurrence.id,
                            schedule_id = %occurrence.schedule_id,
                            execution_id = %occurrence.execution_id,
                            recovery_reason = "lease_renewal",
                            "Lost durable one-time occurrence lease before dispatcher entry"
                        );
                        return;
                    }
                }
            }
        };

        let Some(running) = Self::transition_one_time_to_running(
            &pending,
            &occurrence,
            &persistence,
            &execution_store,
            &one_time_status,
            &occurrence_metrics,
        )
        .await
        else {
            return;
        };

        let dispatch_start = std::time::Instant::now();
        let dispatch = dispatcher.dispatch(&workflow_id, parameter_values);
        tokio::pin!(dispatch);
        let mut heartbeat = tokio::time::interval(ONE_TIME_HEARTBEAT);
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let mut lease_healthy = true;
        let dispatch_result = loop {
            tokio::select! {
                result = &mut dispatch => break result,
                _ = heartbeat.tick(), if lease_healthy => {
                    let next_expiry = Utc::now()
                        + chrono::Duration::from_std(ONE_TIME_LEASE)
                            .expect("one-time lease duration fits chrono");
                    if !matches!(
                        persistence
                            .renew_one_time_lease(
                                &occurrence.id,
                                &occurrence.owner_id,
                                next_expiry,
                            )
                            .await,
                        Ok(true)
                    ) {
                        lease_healthy = false;
                        terminal_allowed.store(false, Ordering::Release);
                        occurrence_metrics.record_lease_renewal_failure();
                        Self::mark_recovery_required(
                            &one_time_status,
                            &occurrence.schedule_id,
                            "one-time ownership lease renewal failed",
                        )
                        .await;
                        error!(
                            occurrence_id = %occurrence.id,
                            schedule_id = %occurrence.schedule_id,
                            execution_id = %occurrence.execution_id,
                            recovery_reason = "lease_renewal",
                            "Lost durable one-time occurrence lease"
                        );
                    }
                }
            }
        };

        let duration_ms = u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let mut terminal_execution = running;
        if let Ok(result) = &dispatch_result {
            if result.skipped {
                // A skip means the dispatcher declined to run the workflow at
                // all (concurrency gate full, allocation not approved).
                // Recording it as `Completed` would terminally consume a
                // one-time occurrence whose scheduled work never ran, so
                // instead record the skipped execution, release the durable
                // lease, and leave the occurrence non-terminal: startup
                // reconciliation then flags the schedule for operator
                // recovery instead of marking it consumed. The durable
                // execution row deliberately stays `running` to match the
                // non-terminal occurrence (the paired-row invariant); the
                // skip itself is visible in the recovery detail.
                terminal_execution.status = ExecutionStatus::Skipped;
                terminal_execution.completed_at = Some(Utc::now());
                terminal_execution.response_summary = serde_json::json!({
                    "status": "skipped",
                    "summary": result.summary,
                    "output": result.output,
                    "duration_ms": duration_ms,
                });
                execution_store
                    .lock()
                    .await
                    .update(&terminal_execution.execution_id, |record| {
                        *record = terminal_execution.clone();
                    });
                if lease_healthy {
                    let _released = persistence
                        .release_one_time_lease(
                            &occurrence.id,
                            &occurrence.owner_id,
                            Utc::now(),
                            ONE_TIME_SKIP_RECOVERY,
                        )
                        .await;
                    Self::mark_recovery_required(
                        &one_time_status,
                        &schedule_id,
                        ONE_TIME_SKIP_RECOVERY,
                    )
                    .await;
                }
                warn!(
                    occurrence_id = %occurrence.id,
                    schedule_id = %schedule_id,
                    execution_id = %occurrence.execution_id,
                    recovery_reason = "dispatch_skipped",
                    "One-time dispatch was skipped; the occurrence stays recoverable instead of consumed"
                );
                return;
            }
        }
        let terminal_recovery_detail = match dispatch_result {
            Ok(result) => {
                let succeeded = result.success;
                terminal_execution.status = if succeeded {
                    ExecutionStatus::Completed
                } else {
                    ExecutionStatus::Failed
                };
                terminal_execution.completed_at = Some(Utc::now());
                terminal_execution.response_summary = serde_json::json!({
                    "status": if succeeded { "completed" } else { "failed" },
                    "summary": result.summary,
                    "output": result.output,
                    "duration_ms": duration_ms,
                });
                if !succeeded {
                    terminal_execution.error_message = result.error;
                }
                (!succeeded).then(|| WORKFLOW_FAILURE_RECOVERY.to_owned())
            }
            Err(error) => {
                terminal_execution.status = ExecutionStatus::Failed;
                terminal_execution.completed_at = Some(Utc::now());
                terminal_execution.response_summary = serde_json::json!({
                    "status": "failed",
                    "error": DISPATCHER_FAILURE_RECOVERY,
                });
                terminal_execution.error_message = Some(error.to_string());
                warn!(
                    occurrence_id = %occurrence.id,
                    schedule_id = %occurrence.schedule_id,
                    execution_id = %occurrence.execution_id,
                    recovery_reason = DISPATCHER_FAILURE_RECOVERY,
                    "Workflow dispatch error"
                );
                Some(DISPATCHER_FAILURE_RECOVERY.to_owned())
            }
        };

        if !lease_healthy {
            return;
        }

        let terminal_state = if terminal_execution.status == ExecutionStatus::Completed {
            OneTimeOccurrenceState::Completed
        } else {
            OneTimeOccurrenceState::Failed
        };
        let terminal_transition = OneTimeOccurrenceTransition {
            occurrence_id: occurrence.id.clone(),
            schedule_id: occurrence.schedule_id.clone(),
            execution_id: occurrence.execution_id.clone(),
            owner_id: occurrence.owner_id.clone(),
            from: OneTimeOccurrenceState::Running,
            to: terminal_state,
            lease_expires_at: None,
            recovery_detail: terminal_recovery_detail,
        };
        let transition_started = std::time::Instant::now();
        let terminal_result = persistence
            .transition_one_time_occurrence(&terminal_transition, &terminal_execution)
            .await;
        let transition_duration_ms =
            u64::try_from(transition_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match terminal_result {
            Ok(OneTimeTransitionResult::Applied(_) | OneTimeTransitionResult::Idempotent(_)) => {
                debug!(
                    occurrence_id = %terminal_transition.occurrence_id,
                    schedule_id = %terminal_transition.schedule_id,
                    execution_id = %terminal_transition.execution_id,
                    from = %terminal_transition.from,
                    to = %terminal_transition.to,
                    duration_ms = transition_duration_ms,
                    "Persisted one-time occurrence transition"
                );
                execution_store
                    .lock()
                    .await
                    .update(&terminal_execution.execution_id, |record| {
                        *record = terminal_execution.clone();
                    });
                Self::mark_consumed(&one_time_status, &schedule_id).await;
                debug!(
                    occurrence_id = %occurrence.id,
                    schedule_id = %occurrence.schedule_id,
                    execution_id = %occurrence.execution_id,
                    "Dispatched one-time workflow completed"
                );
            }
            Ok(OneTimeTransitionResult::Conflict(_) | OneTimeTransitionResult::Missing)
            | Err(_) => {
                occurrence_metrics.record_transition_failure();
                Self::mark_recovery_required(
                    &one_time_status,
                    &schedule_id,
                    "dispatcher finished but terminal occurrence persistence is unknown",
                )
                .await;
                warn!(
                    occurrence_id = %terminal_transition.occurrence_id,
                    schedule_id = %terminal_transition.schedule_id,
                    execution_id = %terminal_transition.execution_id,
                    from = %terminal_transition.from,
                    to = %terminal_transition.to,
                    duration_ms = transition_duration_ms,
                    recovery_reason = "terminal_transition",
                    "One-time terminal transition is ambiguous"
                );
            }
        }
    }

    /// Move a claimed one-time occurrence from Reserved to Running durably.
    ///
    /// Returns the Running execution when the transition applied; None when
    /// it did not, in which case the lease has already been released with a
    /// recovery marker so startup flags the occurrence for recovery instead
    /// of losing the scheduled work.
    async fn transition_one_time_to_running(
        pending: &ScheduleExecution,
        occurrence: &OneTimeOccurrence,
        persistence: &Arc<dyn SchedulerPersistence>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        one_time_status: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        occurrence_metrics: &OccurrenceMetrics,
    ) -> Option<ScheduleExecution> {
        let mut running = pending.clone();
        running.status = ExecutionStatus::Running;
        running.started_at = Some(Utc::now());
        let running_transition = OneTimeOccurrenceTransition {
            occurrence_id: occurrence.id.clone(),
            schedule_id: occurrence.schedule_id.clone(),
            execution_id: occurrence.execution_id.clone(),
            owner_id: occurrence.owner_id.clone(),
            from: OneTimeOccurrenceState::Reserved,
            to: OneTimeOccurrenceState::Running,
            lease_expires_at: Some(
                Utc::now()
                    + chrono::Duration::from_std(ONE_TIME_LEASE)
                        .expect("one-time lease duration fits chrono"),
            ),
            recovery_detail: None,
        };
        let transition_started = std::time::Instant::now();
        let running_result = persistence
            .transition_one_time_occurrence(&running_transition, &running)
            .await;
        let transition_duration_ms =
            u64::try_from(transition_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match running_result {
            Ok(OneTimeTransitionResult::Applied(_) | OneTimeTransitionResult::Idempotent(_)) => {
                debug!(
                    occurrence_id = %running_transition.occurrence_id,
                    schedule_id = %running_transition.schedule_id,
                    execution_id = %running_transition.execution_id,
                    from = %running_transition.from,
                    to = %running_transition.to,
                    duration_ms = transition_duration_ms,
                    "Persisted one-time occurrence transition"
                );
                execution_store
                    .lock()
                    .await
                    .update(&running.execution_id, |record| *record = running.clone());
                Some(running)
            }
            Ok(OneTimeTransitionResult::Conflict(_) | OneTimeTransitionResult::Missing)
            | Err(_) => {
                occurrence_metrics.record_transition_failure();
                Self::mark_recovery_required(
                    one_time_status,
                    &occurrence.schedule_id,
                    "one-time reserved-to-running transition failed",
                )
                .await;
                // The lease is unrecoverable for this attempt, so it is
                // released with the failure reason; nothing else can be
                // reached by holding it (the dispatch never started).
                let _released = persistence
                    .release_one_time_lease(
                        &occurrence.id,
                        &occurrence.owner_id,
                        Utc::now(),
                        "running transition failed before dispatcher entry",
                    )
                    .await;
                warn!(
                    occurrence_id = %running_transition.occurrence_id,
                    schedule_id = %running_transition.schedule_id,
                    execution_id = %running_transition.execution_id,
                    from = %running_transition.from,
                    to = %running_transition.to,
                    duration_ms = transition_duration_ms,
                    recovery_reason = "running_transition",
                    "One-time running transition failed closed"
                );
                None
            }
        }
    }

    async fn load_unblocked_schedule(
        fired: &FiredTrigger,
        store: &Arc<Mutex<ScheduleStore>>,
        one_time_status: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        one_time_global_block: &Arc<Mutex<Option<String>>>,
    ) -> Option<(Schedule, bool)> {
        let schedule = {
            let store_guard = store.lock().await;
            let Some(schedule) = store_guard.get(&fired.schedule_id).cloned() else {
                warn!(schedule_id = %fired.schedule_id, "Schedule not found, skipping");
                return None;
            };
            schedule
        };
        let one_time = matches!(
            schedule.trigger,
            crate::store::TriggerConfig::OneTime { .. }
        );
        if one_time
            && Self::one_time_trigger_blocked(&schedule.id, one_time_status, one_time_global_block)
                .await
        {
            return None;
        }
        Some((schedule, one_time))
    }

    async fn reserve_serial(
        lock: Option<Arc<Mutex<()>>>,
    ) -> (
        Option<tokio::sync::OwnedMutexGuard<()>>,
        Option<SerialRequest>,
    ) {
        let mut request: Option<SerialRequest> =
            lock.map(|lock| Box::pin(lock.lock_owned()) as SerialRequest);
        let guard = if let Some(request) = request.as_mut() {
            match std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(request.as_mut(), cx))
            })
            .await
            {
                std::task::Poll::Ready(guard) => Some(guard),
                std::task::Poll::Pending => None,
            }
        } else {
            None
        };
        if guard.is_some() {
            request = None;
        }
        (guard, request)
    }

    async fn reserve_schedule_serial(
        locks: &SerialLocks,
        schedule_id: &str,
        serialize: bool,
    ) -> (
        Option<tokio::sync::OwnedMutexGuard<()>>,
        Option<SerialRequest>,
    ) {
        let lock = if serialize {
            let mut locks = locks.lock().await;
            Some(
                locks
                    .entry(schedule_id.to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(())))
                    .clone(),
            )
        } else {
            None
        };
        Self::reserve_serial(lock).await
    }

    async fn acquire_execution_permit(
        slots: &Arc<Semaphore>,
        store: &Arc<Mutex<ScheduleStore>>,
        schedule_id: &str,
        recovery_failed: Option<&Arc<AtomicBool>>,
    ) -> Option<tokio::sync::OwnedSemaphorePermit> {
        loop {
            if let Some(failed) = recovery_failed {
                let enabled = store
                    .lock()
                    .await
                    .get(schedule_id)
                    .map(|schedule| schedule.enabled);
                match enabled {
                    Some(true) => {}
                    Some(false) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    None => {
                        failed.store(true, Ordering::SeqCst);
                        return None;
                    }
                }
            }
            let permit = slots
                .clone()
                .acquire_owned()
                .await
                .expect("scheduler execution semaphore is never closed");
            if let Some(failed) = recovery_failed {
                let enabled = store
                    .lock()
                    .await
                    .get(schedule_id)
                    .map(|schedule| schedule.enabled);
                match enabled {
                    Some(true) => {}
                    Some(false) => {
                        drop(permit);
                        continue;
                    }
                    None => {
                        failed.store(true, Ordering::SeqCst);
                        return None;
                    }
                }
            }
            return Some(permit);
        }
    }

    fn pending_execution(
        id: &str,
        schedule: &Schedule,
        fired: &FiredTrigger,
        parameters: &serde_json::Value,
        sequence: u64,
    ) -> ScheduleExecution {
        ScheduleExecution {
            execution_id: id.to_owned(),
            schedule_id: schedule.id.clone(),
            triggered_at: fired.fired_at,
            started_at: None,
            completed_at: None,
            status: ExecutionStatus::Pending,
            workflow_execution_id: None,
            request_summary: serde_json::json!({
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "workflow_id": schedule.workflow_id,
                "trigger": &schedule.trigger,
                "parameter_values": parameters,
                "execution_sequence": sequence,
                "trigger_time": fired.fired_at.to_rfc3339(),
                "cascade_depth": fired.cascade_depth,
                "is_recovery": fired.is_recovery,
            }),
            response_summary: serde_json::json!({}),
            error_message: None,
        }
    }

    fn recovery_admission_allowed(
        schedule: &Schedule,
        fired: &FiredTrigger,
        failed: &AtomicBool,
        expected: Option<&recovery::RecoveryCheckpoint>,
    ) -> bool {
        if schedule.recovery_pending.is_some() && failed.load(Ordering::SeqCst) {
            warn!(schedule_id = %schedule.id, "Trigger denied while recovery persistence is blocked");
            return false;
        }
        if fired.is_recovery
            && (schedule.recovery_pending.as_ref() != expected
                || expected.is_none_or(|checkpoint| !checkpoint.matches_identity(schedule)))
        {
            failed.store(true, Ordering::SeqCst);
            warn!(schedule_id = %schedule.id, "Recovery schedule no longer matches its checkpoint");
            return false;
        }
        true
    }

    /// Handle a single fired trigger.
    ///
    /// When a `WorkflowDispatcher` is available, creates a `Running` execution
    /// record and spawns an async task to run the real workflow. Updates the
    /// record to `Completed` or `Failed` on completion.
    ///
    /// Falls back to the dispatcher-less `ScheduleExecutor` (instant `Completed`)
    /// when no dispatcher has been injected.
    async fn handle_fired_trigger(
        fired: FiredTrigger,
        store: &Arc<Mutex<ScheduleStore>>,
        executor: &Arc<Mutex<ScheduleExecutor>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        dispatcher: Option<Arc<dyn WorkflowDispatcher>>,
        persistence: Option<Arc<dyn SchedulerPersistence>>,
        serial_locks: &SerialLocks,
        admission_locks: &SerialLocks,
        dispatch_tasks: &DispatchTasks,
        execution_slots: &Arc<Semaphore>,
        one_time_admissions: &OneTimeAdmissions,
        one_time_status: &Arc<Mutex<HashMap<String, OneTimeRuntimeStatus>>>,
        one_time_global_block: &Arc<Mutex<Option<String>>>,
        occurrence_metrics: &Arc<OccurrenceMetrics>,
        owner_id: &str,
        max_event_cascade_depth: u32,
        recovery_failed: &Arc<AtomicBool>,
        expected_recovery: Option<&recovery::RecoveryCheckpoint>,
    ) {
        let admission_lock = {
            let mut locks = admission_locks.lock().await;
            locks
                .entry(fired.schedule_id.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _admission = admission_lock.lock().await;
        let Some((schedule, one_time)) =
            Self::load_unblocked_schedule(&fired, store, one_time_status, one_time_global_block)
                .await
        else {
            if fired.is_recovery {
                recovery_failed.store(true, Ordering::SeqCst);
            }
            return;
        };

        if !Self::recovery_admission_allowed(&schedule, &fired, recovery_failed, expected_recovery)
        {
            return;
        }

        if fired.cascade_depth > u64::from(max_event_cascade_depth) {
            Self::record_policy_skip(
                &fired,
                &schedule,
                format!(
                    "event cascade depth {} exceeds limit {max_event_cascade_depth}",
                    fired.cascade_depth
                ),
                store,
                execution_store,
                persistence.as_ref(),
            )
            .await;
            return;
        }

        let now = chrono::Utc::now();
        if !Self::admit_hourly_execution(
            &fired,
            &schedule,
            one_time,
            store,
            execution_store,
            persistence.as_ref(),
            one_time_global_block,
        )
        .await
        {
            return;
        }

        if one_time {
            Self::handle_one_time_trigger(
                fired,
                schedule,
                store,
                executor,
                execution_store,
                dispatcher,
                persistence,
                serial_locks,
                dispatch_tasks,
                execution_slots,
                one_time_admissions,
                one_time_status,
                one_time_global_block,
                occurrence_metrics,
                owner_id,
            )
            .await;
            return;
        }

        if let Some(disp) = dispatcher {
            let concurrency_policy = if fired.is_recovery
                && schedule.policies.effective_missed_policy() == MissedPolicy::Backfill
            {
                ConcurrencyPolicy::Queue
            } else {
                schedule.policies.effective_concurrency_policy()
            };
            match concurrency_policy {
                ConcurrencyPolicy::SkipIfRunning
                    if Self::schedule_has_active_dispatch(dispatch_tasks, &schedule.id) =>
                {
                    Self::record_policy_skip(
                        &fired,
                        &schedule,
                        "previous execution is still running".to_owned(),
                        store,
                        execution_store,
                        persistence.as_ref(),
                    )
                    .await;
                    return;
                }
                ConcurrencyPolicy::CancelPrevious => {
                    Self::cancel_previous_dispatches(
                        dispatch_tasks,
                        execution_store,
                        persistence.as_ref(),
                        &schedule.id,
                    )
                    .await;
                }
                ConcurrencyPolicy::Allow
                | ConcurrencyPolicy::Queue
                | ConcurrencyPolicy::SkipIfRunning => {}
            }

            // Resolve parameters through the documented chain (defaults ->
            // static schedule overrides -> trigger-time expressions) before
            // anything is recorded or dispatched. A template that cannot
            // resolve fails the dispatch visibly instead of leaking a raw
            // `{{ ... }}` string into the workflow.
            let sequence = executor.lock().await.next_sequence_for(&schedule.id);
            let context = crate::params::ResolutionContext {
                trigger_time: fired.fired_at,
                trigger_type: fired.trigger_type,
                execution_sequence: sequence,
                event_payload: fired.event_payload.clone(),
            };
            let parameter_values = match crate::params::resolve_parameters(
                &serde_json::json!({}),
                &schedule.parameter_values,
                &context,
            ) {
                Ok(values) => values,
                Err(error) => {
                    Self::record_dispatch_failure(
                        &fired,
                        &schedule,
                        format!("parameter resolution failed: {error}"),
                        store,
                        execution_store,
                        persistence.as_ref(),
                    )
                    .await;
                    return;
                }
            };

            // Reserve the execution before spawning so the rolling-hour policy
            // cannot over-admit while tasks wait for dispatch capacity.
            let execution_id = format!("exec-{}-{}", schedule.id, uuid::Uuid::new_v4());
            let failed_recovery = fired.is_recovery.then(|| recovery_failed.clone());

            let pending_record = Self::pending_execution(
                &execution_id,
                &schedule,
                &fired,
                &parameter_values,
                sequence,
            );

            {
                let mut exec_store_guard = execution_store.lock().await;
                exec_store_guard.record(pending_record.clone());
            }

            // Advance monotonically. Recovery pre-advances to the latest due
            // occurrence, so individual historical backfill items must not move
            // the durable cursor backwards while they drain.
            let updated_schedule = {
                let mut store_guard = store.lock().await;
                store_guard.update_last_fire(&schedule.id, Self::cursor_time(&fired, now));
                store_guard.get(&schedule.id).cloned()
            };
            if let Some(updated_schedule) = &updated_schedule {
                Self::persist_schedule(persistence.as_ref(), updated_schedule).await;
            }
            Self::persist_record(persistence.as_ref(), &pending_record).await;
            if schedule.recovery_pending.is_some() && recovery_failed.load(Ordering::SeqCst) {
                return;
            }

            // Spawn real execution without blocking the trigger loop.
            let workflow_id = schedule.workflow_id.clone();
            let exec_store_clone = Arc::clone(execution_store);
            let exec_id_clone = execution_id.clone();
            let persistence_clone = persistence.clone();
            let execution_slots_clone = Arc::clone(execution_slots);
            let task_recovery_failed = failed_recovery.clone();
            let schedule_recovery_failed = schedule
                .recovery_pending
                .is_some()
                .then(|| recovery_failed.clone());
            let task_schedule_store = store.clone();
            let task_schedule_id = schedule.id.clone();
            // Register each queued lock request while admission is serialized,
            // before task scheduling can reorder the requests.
            let (immediate_guard, serial_request) = Self::reserve_schedule_serial(
                serial_locks,
                &schedule.id,
                concurrency_policy == ConcurrencyPolicy::Queue,
            )
            .await;

            let handle = tokio::spawn(async move {
                let _serial_guard = match (immediate_guard, serial_request) {
                    (Some(guard), _) => Some(guard),
                    (None, Some(request)) => Some(request.await),
                    (None, None) => None,
                };
                let Some(_execution_permit) = Self::acquire_execution_permit(
                    &execution_slots_clone,
                    &task_schedule_store,
                    &task_schedule_id,
                    task_recovery_failed.as_ref(),
                )
                .await
                else {
                    return;
                };
                if schedule_recovery_failed
                    .as_ref()
                    .is_some_and(|failed| failed.load(Ordering::SeqCst))
                {
                    return;
                }
                let started = {
                    let mut store = exec_store_clone.lock().await;
                    store.update(&exec_id_clone, |record| {
                        record.status = ExecutionStatus::Running;
                        record.started_at = Some(Utc::now());
                    });
                    store.get(&exec_id_clone).cloned()
                };
                if let Some(started) = started {
                    Self::persist_update(persistence_clone.as_ref(), &started).await;
                }
                if schedule_recovery_failed
                    .as_ref()
                    .is_some_and(|failed| failed.load(Ordering::SeqCst))
                {
                    return;
                }
                let dispatch_start = std::time::Instant::now();
                match crate::with_cascade_depth(
                    fired.cascade_depth,
                    disp.dispatch(&workflow_id, parameter_values),
                )
                .await
                {
                    Ok(result) => {
                        let duration_ms =
                            u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(0);
                        let mut store = exec_store_clone.lock().await;
                        let updated = store.update_and_get(&exec_id_clone, |rec| {
                            // A skipped fire declined to run its workflow, so
                            // it is neither completed nor failed: the cursor
                            // already advanced, and the skip is recorded
                            // visibly instead of being counted a success.
                            rec.status = if result.skipped {
                                ExecutionStatus::Skipped
                            } else if result.success {
                                ExecutionStatus::Completed
                            } else {
                                ExecutionStatus::Failed
                            };
                            rec.completed_at = Some(chrono::Utc::now());
                            rec.response_summary = serde_json::json!({
                                "status": if result.skipped { "skipped" } else if result.success { "completed" } else { "failed" },
                                "summary": result.summary,
                                "output": result.output,
                                "duration_ms": duration_ms,
                            });
                            if !result.success {
                                rec.error_message = result.error;
                            }
                        });
                        drop(store);
                        if let Some(updated) = updated {
                            Self::persist_update(persistence_clone.as_ref(), &updated).await;
                        }
                        if result.skipped {
                            debug!(execution_id = %exec_id_clone, "Dispatched workflow skipped");
                        } else {
                            debug!(execution_id = %exec_id_clone, "Dispatched workflow completed");
                        }
                    }
                    Err(e) => {
                        let mut store = exec_store_clone.lock().await;
                        let updated = store.update_and_get(&exec_id_clone, |rec| {
                            rec.status = ExecutionStatus::Failed;
                            rec.completed_at = Some(chrono::Utc::now());
                            rec.response_summary = serde_json::json!({
                                "status": "failed",
                                "error": e.to_string(),
                            });
                            rec.error_message = Some(e.to_string());
                        });
                        drop(store);
                        if let Some(updated) = updated {
                            Self::persist_update(persistence_clone.as_ref(), &updated).await;
                        }
                        warn!(execution_id = %exec_id_clone, error = %e, "Workflow dispatch error");
                    }
                }
            });
            // This lock is synchronous by design: there is no cancellation
            // point between spawning the child and registering its handle.
            let mut tasks = dispatch_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tasks.retain(|task| !task.handle.is_finished());
            tasks.push(TrackedDispatch {
                execution_id,
                schedule_id: schedule.id,
                occurrence_id: None,
                owner_id: None,
                one_time_terminal_allowed: None,
                recovery_failed: failed_recovery,
                handle,
            });
        } else {
            Self::dispatch_fallback(
                &fired,
                &schedule,
                store,
                executor,
                execution_store,
                persistence.as_ref(),
            )
            .await;
        }
    }

    async fn admit_hourly_execution(
        fired: &FiredTrigger,
        schedule: &Schedule,
        one_time: bool,
        store: &Arc<Mutex<ScheduleStore>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
        one_time_global_block: &Arc<Mutex<Option<String>>>,
    ) -> bool {
        let now = chrono::Utc::now();
        let max_per_hour = schedule.policies.max_executions_per_hour;
        if max_per_hour > 0 {
            let since = now - chrono::Duration::hours(1);
            let (live_started, pending) = {
                let executions = execution_store.lock().await;
                (
                    executions.started_since(&schedule.id, since),
                    executions.pending_count(&schedule.id),
                )
            };
            let persisted_started = if let Some(adapter) = persistence {
                match adapter.executions_started_since(&schedule.id, since).await {
                    Ok(count) => usize::try_from(count).unwrap_or(usize::MAX),
                    Err(error) => {
                        warn!(
                            schedule_id = %schedule.id,
                            %error,
                            "Cannot verify hourly schedule limit; skipping trigger"
                        );
                        if one_time {
                            *one_time_global_block.lock().await =
                                Some("one-time hourly execution history is unavailable".to_owned());
                            return false;
                        }
                        Self::record_policy_skip(
                            fired,
                            schedule,
                            "hourly execution history is unavailable".to_owned(),
                            store,
                            execution_store,
                            persistence,
                        )
                        .await;
                        return false;
                    }
                }
            } else {
                0
            };
            let admitted = live_started.max(persisted_started).saturating_add(pending);
            if admitted >= usize::try_from(max_per_hour).unwrap_or(usize::MAX) {
                Self::record_policy_skip(
                    fired,
                    schedule,
                    format!("hourly execution limit reached ({max_per_hour})"),
                    store,
                    execution_store,
                    persistence,
                )
                .await;
                return false;
            }
        }
        true
    }

    async fn dispatch_fallback(
        fired: &FiredTrigger,
        schedule: &Schedule,
        store: &Arc<Mutex<ScheduleStore>>,
        executor: &Arc<Mutex<ScheduleExecutor>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
    ) {
        // Dispatcher-less fallback: instant completion via ScheduleExecutor.
        let mut store_guard = store.lock().await;
        let mut exec_guard = executor.lock().await;
        let mut exec_store_guard = execution_store.lock().await;
        let mut persisted = exec_guard.trigger_execution_at(
            schedule,
            &mut store_guard,
            &mut exec_store_guard,
            Self::cursor_time(fired, Utc::now()),
        );
        persisted.request_summary["cascade_depth"] = serde_json::json!(fired.cascade_depth);
        persisted.request_summary["is_recovery"] = serde_json::json!(fired.is_recovery);
        exec_store_guard.update(&persisted.execution_id, |record| {
            record.request_summary["cascade_depth"] = serde_json::json!(fired.cascade_depth);
            record.request_summary["is_recovery"] = serde_json::json!(fired.is_recovery);
        });
        let updated_schedule = store_guard.get(&schedule.id).cloned();
        debug!(execution_id = %persisted.execution_id, "Dispatcher-less fallback execution triggered");
        drop(exec_store_guard);
        drop(exec_guard);
        drop(store_guard);
        if let Some(updated_schedule) = &updated_schedule {
            Self::persist_schedule(persistence, updated_schedule).await;
        }
        Self::persist_record(persistence, &persisted).await;
    }

    async fn persist_record(
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
        execution: &ScheduleExecution,
    ) {
        if let Some(persistence) = persistence {
            if let Err(error) = persistence.record_execution(execution).await {
                warn!(
                    execution_id = %execution.execution_id,
                    error = %error,
                    "Failed to persist schedule execution"
                );
            }
        }
    }

    async fn persist_update(
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
        execution: &ScheduleExecution,
    ) {
        if let Some(persistence) = persistence {
            if let Err(error) = persistence.update_execution(execution).await {
                warn!(
                    execution_id = %execution.execution_id,
                    error = %error,
                    "Failed to update persisted schedule execution"
                );
            }
        }
    }

    async fn persist_schedule(
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
        schedule: &Schedule,
    ) {
        if let Some(persistence) = persistence {
            if let Err(error) = persistence.update_schedule(schedule).await {
                warn!(
                    schedule_id = %schedule.id,
                    error = %error,
                    "Failed to persist changed schedule"
                );
            }
        }
    }

    async fn persist_schedule_definition(
        persistence: Option<&Arc<dyn SchedulerPersistence>>,
        schedule: &Schedule,
    ) {
        if let Some(persistence) = persistence {
            if let Err(error) = persistence.update_schedule_definition(schedule).await {
                warn!(schedule_id = %schedule.id, %error, "Failed to persist schedule definition");
            }
        }
    }

    /// Stop the scheduler gracefully.
    ///
    /// # Panics
    ///
    /// Panics if the internal scheduler runtime mutex is poisoned.
    pub async fn stop(&self) {
        let _lifecycle = self.lifecycle.lock().await;
        self.arm.disarm();
        let (recovery_handle, recovery_cancel, eval_handle, exec_handle, shutdown) = {
            let mut runtime = self
                .runtime
                .lock()
                .expect("scheduler runtime lock poisoned");
            if runtime.recovery_handle.is_none()
                && runtime.eval_handle.is_none()
                && runtime.exec_handle.is_none()
                && !runtime.starting
            {
                runtime.startup_failed = false;
                return;
            }

            let shutdown = Arc::clone(&runtime.shutdown);
            let recovery_handle = runtime.recovery_handle.take();
            let recovery_cancel = runtime.recovery_cancel.take();
            let eval_handle = runtime.eval_handle.take();
            let exec_handle = runtime.exec_handle.take();
            runtime.trigger_tx = None;
            runtime.starting = false;
            runtime.startup_failed = false;
            runtime.shutdown = Arc::new(Notify::new());
            (
                recovery_handle,
                recovery_cancel,
                eval_handle,
                exec_handle,
                shutdown,
            )
        };

        info!("Stopping scheduler");

        // Wake producers and loops, then abort them so no new dispatch task can
        // be registered while the tracked set is drained below.
        shutdown.notify_waiters();

        if let Some(cancel) = recovery_cancel {
            // The coordinator may already have finished; no worker remains in that case.
            let _ = cancel.send(());
        }
        if let Some(handle) = recovery_handle {
            // Join the coordinator after it cancels and joins every recovery worker.
            let _ = handle.await;
        }
        if let Some(handle) = eval_handle {
            handle.abort();
            let _ = handle.await;
        }
        if let Some(handle) = exec_handle {
            handle.abort();
            let _ = handle.await;
        }

        let admissions: Vec<PendingOneTimeAdmission> = {
            let mut admissions = self
                .one_time_admissions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            admissions.drain().map(|(_, admission)| admission).collect()
        };
        let persistence = self.persistence.lock().await.clone();
        for admission in admissions {
            let detail = "scheduler stopped during one-time admission";
            let release_outcome = if let Some(persistence) = persistence.as_ref() {
                match persistence
                    .release_one_time_lease(
                        &admission.occurrence_id,
                        &admission.owner_id,
                        Utc::now(),
                        detail,
                    )
                    .await
                {
                    Ok(true) => "released",
                    Ok(false) => "not_owned",
                    Err(_) => "unavailable",
                }
            } else {
                "unavailable"
            };
            warn!(
                occurrence_id = %admission.occurrence_id,
                schedule_id = %admission.schedule_id,
                execution_id = %admission.execution_id,
                recovery_reason = "shutdown_admission",
                release_outcome,
                "Interrupted one-time admission requires recovery"
            );
            Self::mark_recovery_required(&self.one_time_status, &admission.schedule_id, detail)
                .await;
        }

        let tracked: Vec<TrackedDispatch> = {
            let mut tasks = self
                .dispatch_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tasks.drain(..).collect()
        };
        let mut cancelled = Vec::new();
        for task in tracked {
            let TrackedDispatch {
                execution_id,
                schedule_id,
                occurrence_id,
                owner_id,
                one_time_terminal_allowed,
                recovery_failed: _,
                handle,
            } = task;
            let was_running = !handle.is_finished();
            if was_running {
                handle.abort();
            }
            let _ = handle.await;
            if was_running {
                cancelled.push((
                    execution_id,
                    schedule_id,
                    occurrence_id,
                    owner_id,
                    one_time_terminal_allowed,
                ));
            }
        }

        for (execution_id, schedule_id, occurrence_id, owner_id, terminal_allowed) in cancelled {
            let current = self
                .execution_store
                .lock()
                .await
                .get(&execution_id)
                .cloned();
            let Some(current) = current else {
                continue;
            };
            if !matches!(
                current.status,
                ExecutionStatus::Pending | ExecutionStatus::Running
            ) {
                continue;
            }

            let mut cancelled_execution = current.clone();
            cancelled_execution.status = ExecutionStatus::Cancelled;
            cancelled_execution.completed_at = Some(Utc::now());
            cancelled_execution.error_message =
                Some("scheduler stopped before completion".to_owned());
            cancelled_execution.response_summary = serde_json::json!({
                "status": "cancelled",
                "reason": "scheduler stopped before completion",
            });

            let Some(occurrence_id) = occurrence_id else {
                self.execution_store
                    .lock()
                    .await
                    .update(&execution_id, |record| {
                        *record = cancelled_execution.clone();
                    });
                Self::persist_update(persistence.as_ref(), &cancelled_execution).await;
                continue;
            };

            let Some(owner_id) = owner_id else {
                Self::mark_recovery_required(
                    &self.one_time_status,
                    &schedule_id,
                    "tracked one-time occurrence owner is unavailable",
                )
                .await;
                warn!(
                    occurrence_id = %occurrence_id,
                    schedule_id = %schedule_id,
                    execution_id = %execution_id,
                    recovery_reason = "terminal_transition",
                    "Tracked one-time occurrence owner is unavailable during scheduler stop"
                );
                continue;
            };
            if !terminal_allowed
                .as_ref()
                .is_some_and(|allowed| allowed.load(Ordering::Acquire))
            {
                continue;
            }

            let from = if current.status == ExecutionStatus::Pending {
                OneTimeOccurrenceState::Reserved
            } else {
                OneTimeOccurrenceState::Running
            };
            let transition = OneTimeOccurrenceTransition {
                occurrence_id,
                schedule_id: schedule_id.clone(),
                execution_id: execution_id.clone(),
                owner_id,
                from,
                to: OneTimeOccurrenceState::Cancelled,
                lease_expires_at: None,
                recovery_detail: Some("scheduler stopped before completion".to_owned()),
            };
            let transition_started = std::time::Instant::now();
            let transition_result = match persistence.as_ref() {
                Some(persistence) => {
                    persistence
                        .transition_one_time_occurrence(&transition, &cancelled_execution)
                        .await
                }
                None => Err(PersistenceError::new(
                    "durable one-time occurrence persistence is unavailable",
                )),
            };
            let transition_duration_ms =
                u64::try_from(transition_started.elapsed().as_millis()).unwrap_or(u64::MAX);
            match transition_result {
                Ok(
                    OneTimeTransitionResult::Applied(_) | OneTimeTransitionResult::Idempotent(_),
                ) => {
                    debug!(
                        occurrence_id = %transition.occurrence_id,
                        schedule_id = %transition.schedule_id,
                        execution_id = %transition.execution_id,
                        from = %transition.from,
                        to = %transition.to,
                        duration_ms = transition_duration_ms,
                        "Persisted one-time occurrence transition"
                    );
                    self.execution_store
                        .lock()
                        .await
                        .update(&execution_id, |record| {
                            *record = cancelled_execution.clone();
                        });
                    Self::mark_consumed(&self.one_time_status, &schedule_id).await;
                }
                Ok(OneTimeTransitionResult::Conflict(_) | OneTimeTransitionResult::Missing)
                | Err(_) => {
                    self.occurrence_metrics.record_transition_failure();
                    let detail = "scheduler stopped before a durable terminal transition";
                    Self::mark_recovery_required(&self.one_time_status, &schedule_id, detail).await;
                    if let Some(persistence) = persistence.as_ref() {
                        let _released = persistence
                            .release_one_time_lease(
                                &transition.occurrence_id,
                                &transition.owner_id,
                                Utc::now(),
                                detail,
                            )
                            .await;
                    }
                    warn!(
                        occurrence_id = %transition.occurrence_id,
                        schedule_id = %transition.schedule_id,
                        execution_id = %transition.execution_id,
                        from = %transition.from,
                        to = %transition.to,
                        duration_ms = transition_duration_ms,
                        recovery_reason = "terminal_transition",
                        "Failed to persist one-time cancellation during scheduler stop"
                    );
                }
            }
        }

        // Admission can be interrupted after recording Pending but before
        // tracking its task. Classify by the retained trigger, not the current
        // registry: removing a one-time schedule must not bypass receipt handling.
        let abandoned: Vec<ScheduleExecution> = self
            .execution_store
            .lock()
            .await
            .pending_records()
            .filter(|record| {
                matches!(
                    record.request_summary["trigger"]["type"].as_str(),
                    Some("cron" | "interval" | "event")
                )
            })
            .cloned()
            .collect();
        for mut cancelled_execution in abandoned {
            let execution_id = cancelled_execution.execution_id.clone();
            cancelled_execution.status = ExecutionStatus::Cancelled;
            cancelled_execution.completed_at = Some(Utc::now());
            cancelled_execution.error_message =
                Some("scheduler stopped before completion".to_owned());
            cancelled_execution.response_summary = serde_json::json!({
                "status": "cancelled",
                "reason": "scheduler stopped before completion",
            });
            self.execution_store
                .lock()
                .await
                .update(&execution_id, |stored| {
                    *stored = cancelled_execution.clone();
                });
            Self::persist_update(persistence.as_ref(), &cancelled_execution).await;
        }

        info!("Scheduler stopped");
    }

    /// Whether the scheduler is currently running.
    ///
    /// # Panics
    ///
    /// Panics if the internal scheduler runtime mutex is poisoned.
    pub fn is_running(&self) -> bool {
        self.runtime_status() == SchedulerRuntimeStatus::Running
    }

    /// Report both long-lived loops; finite recovery submission is not a liveness signal.
    ///
    /// # Panics
    /// Panics if the scheduler runtime mutex is poisoned.
    pub fn runtime_status(&self) -> SchedulerRuntimeStatus {
        let runtime = self
            .runtime
            .lock()
            .expect("scheduler runtime lock poisoned");
        if runtime.starting {
            SchedulerRuntimeStatus::Starting
        } else if runtime.startup_failed {
            SchedulerRuntimeStatus::Failed
        } else {
            match (&runtime.eval_handle, &runtime.exec_handle) {
                (None, None) => SchedulerRuntimeStatus::Stopped,
                (Some(evaluator), Some(executor))
                    if !evaluator.is_finished() && !executor.is_finished() =>
                {
                    SchedulerRuntimeStatus::Running
                }
                _ => SchedulerRuntimeStatus::Failed,
            }
        }
    }
}

impl Default for SchedulerManager {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn runtime_status_requires_both_long_lived_loops() {
        let manager = SchedulerManager::with_defaults();
        assert_eq!(manager.runtime_status(), SchedulerRuntimeStatus::Stopped);
        manager.start(Duration::from_secs(3600)).await;
        assert_eq!(manager.runtime_status(), SchedulerRuntimeStatus::Running);
        let abort = manager
            .runtime
            .lock()
            .unwrap()
            .exec_handle
            .as_ref()
            .unwrap()
            .abort_handle();
        abort.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !manager
                .runtime
                .lock()
                .unwrap()
                .exec_handle
                .as_ref()
                .unwrap()
                .is_finished()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(manager.runtime_status(), SchedulerRuntimeStatus::Failed);
        assert!(!manager.is_running());
        manager.stop().await;
        assert_eq!(manager.runtime_status(), SchedulerRuntimeStatus::Stopped);
    }

    use crate::config::{ConcurrencyPolicy, MissedPolicy};
    use crate::dispatcher::{DispatchError, DispatchResult};
    use crate::occurrence::{
        OneTimeOccurrenceState, OneTimeOccurrenceTransition, OneTimeRuntimeStatus,
        OneTimeTransitionResult, ONE_TIME_HEARTBEAT,
    };
    use crate::store::{SchedulePolicies, TriggerConfig};
    use crate::trigger::TriggerType;
    use chrono::{DateTime, TimeDelta, Utc};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use tokio::sync::{Mutex as AsyncMutex, Notify};

    const SENSITIVE_JOURNAL_DETAIL: &str =
        "/private/targets/customer-a/journal.sqlite credential=journal-secret";
    const SENSITIVE_RUNTIME_DETAIL: &str = "OPENAI_API_KEY=sk-runtime-secret";
    const SENSITIVE_PERSISTENCE_ERROR: &str =
        "DATABASE_URL=postgres://admin:secret@internal/oxfuzz";

    #[derive(Clone, Default)]
    struct EventCapture {
        events: Arc<std::sync::Mutex<Vec<HashMap<String, String>>>>,
        next_span_id: Arc<AtomicU64>,
    }

    impl EventCapture {
        fn events(&self) -> Vec<HashMap<String, String>> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn parallel_safe_dispatch(&self) -> (tracing::Dispatch, tracing::Dispatch) {
            let dispatch = tracing::Dispatch::new(self.clone());
            // Tracing callsite interest is process-global. Keeping a second
            // scoped dispatcher alive makes callsites first reached by another
            // test thread use the dispatcher registry instead of that thread's
            // local default, so this capture cannot silently miss the event.
            let callsite_registration_anchor = tracing::Dispatch::new(Self::default());
            (dispatch, callsite_registration_anchor)
        }
    }

    #[derive(Default)]
    struct EventFieldVisitor {
        fields: HashMap<String, String>,
    }

    impl tracing::field::Visit for EventFieldVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    impl tracing::Subscriber for EventCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(self.next_span_id.fetch_add(1, Ordering::Relaxed) + 1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = EventFieldVisitor::default();
            event.record(&mut visitor);
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(visitor.fields);
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn assert_event_identity_fields(fields: &HashMap<String, String>) {
        for field in ["occurrence_id", "schedule_id", "execution_id"] {
            assert!(
                fields.get(field).is_some_and(|value| !value.is_empty()),
                "structured event omitted {field}: {fields:?}"
            );
        }
    }

    async fn wait_for_transition_events(capture: &EventCapture, expected: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let transition_count = capture
                    .events()
                    .iter()
                    .filter(|fields| fields.contains_key("from") && fields.contains_key("to"))
                    .count();
                if transition_count >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the scheduler must emit its state transitions");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lifecycle_and_recovery_events_include_required_structured_fields() {
        let capture = EventCapture::default();
        let (dispatch, _callsite_registration_anchor) = capture.parallel_safe_dispatch();
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let (success_manager, success_persistence) =
            manager_and_persistence(OccurrenceFailure::None).await;
        attached_counting_dispatcher(&success_manager).await;
        success_manager
            .register(due_one_time("structured-success"))
            .await;
        success_manager.start(Duration::from_millis(10)).await;
        wait_for_state(&success_persistence, OneTimeOccurrenceState::Completed).await;
        // The fake persistence exposes its committed state before the worker
        // resumes to emit the matching event. Wait for that observable event
        // before stop() is allowed to abort any still-running task.
        wait_for_transition_events(&capture, 2).await;
        success_manager.stop().await;

        let statuses = Arc::new(Mutex::new(HashMap::new()));
        let journal_block = Arc::new(Mutex::new(Some(SENSITIVE_JOURNAL_DETAIL.to_owned())));
        assert!(
            SchedulerManager::one_time_trigger_blocked(
                "journal-blocked",
                &statuses,
                &journal_block,
            )
            .await
        );
        statuses.lock().await.insert(
            "runtime-blocked".to_owned(),
            OneTimeRuntimeStatus::RecoveryRequired {
                detail: SENSITIVE_RUNTIME_DETAIL.to_owned(),
            },
        );
        assert!(
            SchedulerManager::one_time_trigger_blocked(
                "runtime-blocked",
                &statuses,
                &Arc::new(Mutex::new(None)),
            )
            .await
        );

        let (dispatcher_missing, _) = manager_and_persistence(OccurrenceFailure::None).await;
        dispatcher_missing
            .register(due_one_time("dispatcher-missing"))
            .await;
        dispatcher_missing.start(Duration::from_millis(10)).await;
        wait_for_one_time_recovery(&dispatcher_missing, "dispatcher-missing").await;
        dispatcher_missing.stop().await;

        let persistence_missing = SchedulerManager::with_defaults();
        attached_counting_dispatcher(&persistence_missing).await;
        persistence_missing
            .register(due_one_time("persistence-missing"))
            .await;
        persistence_missing.start(Duration::from_millis(10)).await;
        wait_for_one_time_recovery(&persistence_missing, "persistence-missing").await;
        persistence_missing.stop().await;

        let (reservation_failure, _) = manager_and_persistence(OccurrenceFailure::Reserve).await;
        attached_counting_dispatcher(&reservation_failure).await;
        reservation_failure
            .register(due_one_time("reservation-failure"))
            .await;
        reservation_failure.start(Duration::from_millis(10)).await;
        wait_for_one_time_recovery(&reservation_failure, "reservation-failure").await;
        reservation_failure.stop().await;

        let (shutdown_manager, shutdown_persistence) =
            manager_and_persistence(OccurrenceFailure::PauseCursor).await;
        attached_counting_dispatcher(&shutdown_manager).await;
        shutdown_manager
            .register(due_one_time("shutdown-admission"))
            .await;
        shutdown_manager.start(Duration::from_millis(10)).await;
        wait_for_occurrence(&shutdown_persistence).await;
        wait_for_cursor_update(&shutdown_persistence).await;
        shutdown_manager.stop().await;

        let events = capture.events();
        let reservations: Vec<_> = events
            .iter()
            .filter(|fields| fields.contains_key("reservation_outcome"))
            .collect();
        assert!(!reservations.is_empty());
        for fields in reservations {
            assert_event_identity_fields(fields);
            assert!(fields.contains_key("duration_ms"));
        }

        let transitions: Vec<_> = events
            .iter()
            .filter(|fields| fields.contains_key("from") && fields.contains_key("to"))
            .collect();
        assert!(transitions.len() >= 2);
        for fields in transitions {
            assert_event_identity_fields(fields);
            assert!(fields.contains_key("duration_ms"));
        }

        for recovery_reason in [
            "journal_health",
            "runtime_status",
            "dispatcher_unavailable",
            "reservation_unavailable",
            "shutdown_admission",
        ] {
            let matching: Vec<_> = events
                .iter()
                .filter(|fields| {
                    fields
                        .get("recovery_reason")
                        .is_some_and(|value| value == recovery_reason)
                })
                .collect();
            assert!(
                !matching.is_empty(),
                "missing recovery event for {recovery_reason}: {events:?}"
            );
            for fields in matching {
                assert_event_identity_fields(fields);
            }
        }

        let recovery_events: Vec<_> = events
            .iter()
            .filter(|fields| fields.contains_key("recovery_reason"))
            .collect();
        for marker in [
            "/private/targets/customer-a",
            "credential=journal-secret",
            "OPENAI_API_KEY",
            "sk-runtime-secret",
            "DATABASE_URL",
            "postgres://admin:secret@internal",
        ] {
            assert!(
                recovery_events
                    .iter()
                    .flat_map(|fields| fields.values())
                    .all(|value| !value.contains(marker)),
                "recovery event exposed sensitive marker {marker}: {recovery_events:?}"
            );
        }
    }

    #[tokio::test]
    async fn global_one_time_block_overrides_schedule_status() {
        let manager = SchedulerManager::with_defaults();
        manager.mark_one_time_consumed("once").await;
        manager.block_one_time("journal is corrupt").await;
        assert_eq!(
            manager.one_time_block_reason().await.as_deref(),
            Some("journal is corrupt")
        );
        assert!(matches!(
            manager.one_time_runtime_status("once").await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
        assert!(matches!(
            manager.one_time_runtime_status("another").await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
    }

    #[test]
    fn occurrence_metrics_snapshot_reports_each_counter() {
        let manager = SchedulerManager::with_defaults();
        manager.record_expired_one_time_occurrence();
        manager.record_one_time_acknowledgement();
        manager.record_corrupt_one_time_journal();
        let snapshot = manager.occurrence_metrics();
        assert_eq!(snapshot.expired_non_terminal, 1);
        assert_eq!(snapshot.acknowledgements, 1);
        assert_eq!(snapshot.corrupt_journal_blocks, 1);
    }

    #[tokio::test]
    async fn test_manager_register_and_get() {
        let mgr = SchedulerManager::with_defaults();

        let schedule = Schedule::new(
            "test-schedule",
            "Test Schedule",
            TriggerConfig::Interval { interval_secs: 60 },
            "wf-1",
        );
        mgr.register(schedule).await;

        let retrieved = mgr.get_schedule("test-schedule").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Schedule");
    }

    #[tokio::test]
    async fn register_materializes_configured_policy_defaults() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            default_missed_policy: MissedPolicy::CatchUp,
            default_concurrency_policy: ConcurrencyPolicy::Allow,
            ..SchedulerConfig::default()
        });
        mgr.register(Schedule::new(
            "defaults",
            "Defaults",
            TriggerConfig::Interval { interval_secs: 60 },
            "wf",
        ))
        .await;

        let schedule = mgr.get_schedule("defaults").await.unwrap();
        assert_eq!(schedule.policies.missed_policy, Some(MissedPolicy::CatchUp));
        assert_eq!(
            schedule.policies.concurrency_policy,
            Some(ConcurrencyPolicy::Allow)
        );
    }

    #[tokio::test]
    async fn test_manager_remove() {
        let mgr = SchedulerManager::with_defaults();
        mgr.register(Schedule::new(
            "s1",
            "S1",
            TriggerConfig::Interval { interval_secs: 60 },
            "wf",
        ))
        .await;
        assert!(mgr.remove("s1").await);
        assert!(mgr.get_schedule("s1").await.is_none());
    }

    #[tokio::test]
    async fn test_manager_pause_resume() {
        let mgr = SchedulerManager::with_defaults();
        mgr.register(Schedule::new(
            "s1",
            "S1",
            TriggerConfig::Interval { interval_secs: 60 },
            "wf",
        ))
        .await;

        mgr.pause("s1").await;
        assert!(!mgr.get_schedule("s1").await.unwrap().enabled);

        mgr.resume("s1").await;
        assert!(mgr.get_schedule("s1").await.unwrap().enabled);
    }

    #[tokio::test]
    async fn test_manager_start_stop() {
        let mgr = SchedulerManager::with_defaults();
        assert!(!mgr.is_running());

        mgr.start(Duration::from_millis(50)).await;
        assert!(mgr.is_running());

        mgr.stop().await;
        assert!(!mgr.is_running());
    }

    struct StartupGate {
        entered: Notify,
        release: Notify,
    }

    struct RecoveryCompletionGate {
        entered: Notify,
        release: Notify,
    }

    struct RecoveryWriteFailure;

    struct RecoveryHistoryWriteFailure;

    struct BlockingWorkerDrop {
        dropping: Arc<Notify>,
        release: Arc<AtomicBool>,
    }

    impl Drop for BlockingWorkerDrop {
        fn drop(&mut self) {
            self.dropping.notify_one();
            while !self.release.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
        }
    }

    struct RecoveryWorkerDropGate {
        entered: Notify,
        dropping: Arc<Notify>,
        release: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for RecoveryWorkerDropGate {
        async fn record_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            let _guard = BlockingWorkerDrop {
                dropping: self.dropping.clone(),
                release: self.release.clone(),
            };
            self.entered.notify_one();
            std::future::pending().await
        }
        async fn update_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_schedule(&self, _: &Schedule) -> Result<(), PersistenceError> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stop_joins_recovery_workers_before_returning() {
        let mgr = Arc::new(SchedulerManager::with_defaults());
        let gate = Arc::new(RecoveryWorkerDropGate {
            entered: Notify::new(),
            dropping: Arc::new(Notify::new()),
            release: Arc::new(AtomicBool::new(false)),
        });
        mgr.set_persistence(gate.clone()).await;
        mgr.set_dispatcher(Arc::new(AlwaysOkDispatcher)).await;
        mgr.register(missed_schedule("worker-drop", 2, MissedPolicy::CatchUp))
            .await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("worker did not enter persistence");
        let mut stopping = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.stop().await })
        };
        tokio::time::timeout(Duration::from_secs(2), gate.dropping.notified())
            .await
            .expect("worker was not cancelled");
        let early = tokio::time::timeout(Duration::from_millis(100), &mut stopping)
            .await
            .is_ok();
        gate.release.store(true, Ordering::SeqCst);
        if !early {
            stopping.await.unwrap();
        }
        assert!(
            !early,
            "stop returned before the recovery worker was joined"
        );
    }

    struct HourlyAdmissionGate {
        entered: Notify,
        release: Notify,
        open: AtomicBool,
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for HourlyAdmissionGate {
        async fn record_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_schedule(&self, _: &Schedule) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn executions_started_since(
            &self,
            _: &str,
            _: DateTime<Utc>,
        ) -> Result<u64, PersistenceError> {
            self.entered.notify_one();
            loop {
                let wait = self.release.notified();
                if self.open.load(Ordering::SeqCst) {
                    break;
                }
                wait.await;
            }
            Ok(0)
        }
    }

    #[tokio::test]
    async fn recovery_and_explicit_trigger_share_hourly_admission() {
        let mgr = SchedulerManager::with_defaults();
        let gate = Arc::new(HourlyAdmissionGate {
            entered: Notify::new(),
            release: Notify::new(),
            open: AtomicBool::new(false),
        });
        mgr.set_persistence(gate.clone()).await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        let mut schedule = policy_schedule("admission-race", ConcurrencyPolicy::Allow, 1);
        schedule.policies.missed_policy = Some(MissedPolicy::CatchUp);
        schedule.last_fire = Some(Utc::now() - TimeDelta::hours(2));
        mgr.register(schedule).await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("first admission did not start");
        send_now(&mgr, "admission-race").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        gate.open.store(true, Ordering::SeqCst);
        gate.release.notify_waiters();
        wait_for_history(&mgr, "admission-race", 2).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        mgr.stop().await;
        assert_eq!(
            dispatcher.total_calls().await,
            1,
            "hourly admission was exceeded"
        );
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for RecoveryHistoryWriteFailure {
        async fn record_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Err(PersistenceError::new("execution write failed"))
        }
        async fn update_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Err(PersistenceError::new("execution write failed"))
        }
        async fn update_schedule(&self, _: &Schedule) -> Result<(), PersistenceError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn recovery_history_failure_keeps_checkpoint() {
        let mgr = SchedulerManager::with_defaults();
        mgr.set_persistence(Arc::new(RecoveryHistoryWriteFailure))
            .await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        mgr.register(missed_schedule("history-failure", 2, MissedPolicy::CatchUp))
            .await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while mgr.execution_count().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recovery admission did not run");
        tokio::time::sleep(Duration::from_millis(100)).await;
        send_now(&mgr, "history-failure").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let checkpoint = mgr
            .get_schedule("history-failure")
            .await
            .unwrap()
            .recovery_pending;
        mgr.stop().await;
        assert!(checkpoint.is_some(), "missing history must retain recovery");
        assert_eq!(
            dispatcher.total_calls().await,
            0,
            "unrecorded work must not dispatch"
        );
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for RecoveryWriteFailure {
        async fn record_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_schedule(&self, _: &Schedule) -> Result<(), PersistenceError> {
            Err(PersistenceError::new("recovery write failed"))
        }
    }

    #[tokio::test]
    async fn recovery_checkpoint_write_failure_reports_failed_startup() {
        let mgr = SchedulerManager::with_defaults();
        mgr.set_persistence(Arc::new(RecoveryWriteFailure)).await;
        mgr.register(missed_schedule("write-failure", 2, MissedPolicy::CatchUp))
            .await;
        mgr.start(Duration::from_mins(1)).await;
        assert_eq!(mgr.runtime_status(), SchedulerRuntimeStatus::Failed);
        assert!(mgr.trigger_sender().is_none());
        mgr.stop().await;
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for RecoveryCompletionGate {
        async fn record_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn update_schedule(&self, _: &Schedule) -> Result<(), PersistenceError> {
            Ok(())
        }
        async fn complete_recovery(
            &self,
            _: &Schedule,
            _: &recovery::RecoveryCheckpoint,
        ) -> Result<(), PersistenceError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn recovery_completion_write_does_not_block_schedule_reads() {
        let mgr = SchedulerManager::with_defaults();
        let gate = Arc::new(RecoveryCompletionGate {
            entered: Notify::new(),
            release: Notify::new(),
        });
        mgr.set_persistence(gate.clone()).await;
        mgr.set_dispatcher(Arc::new(AlwaysOkDispatcher)).await;
        mgr.register(missed_schedule("completion", 2, MissedPolicy::CatchUp))
            .await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("completion was not persisted");
        let read =
            tokio::time::timeout(Duration::from_millis(100), mgr.get_schedule("completion")).await;
        gate.release.notify_one();
        mgr.stop().await;
        assert!(read.is_ok(), "schedule reads blocked on persistence");
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for StartupGate {
        async fn record_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }

        async fn update_execution(&self, _: &ScheduleExecution) -> Result<(), PersistenceError> {
            Ok(())
        }

        async fn update_schedule(&self, _: &Schedule) -> Result<(), PersistenceError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn stop_during_startup_leaves_no_running_scheduler() {
        let mgr = Arc::new(SchedulerManager::with_defaults());
        let gate = Arc::new(StartupGate {
            entered: Notify::new(),
            release: Notify::new(),
        });
        mgr.set_persistence(gate.clone()).await;
        mgr.register(missed_schedule("startup", 5, MissedPolicy::Skip))
            .await;
        let starting = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.start(Duration::from_secs(60)).await })
        };
        tokio::time::timeout(Duration::from_secs(2), gate.entered.notified())
            .await
            .expect("startup did not reach persistence");
        let stopping = {
            let mgr = mgr.clone();
            tokio::spawn(async move { mgr.stop().await })
        };
        tokio::task::yield_now().await;
        gate.release.notify_one();
        starting.await.unwrap();
        stopping.await.unwrap();
        assert_eq!(mgr.runtime_status(), SchedulerRuntimeStatus::Stopped);
        assert!(mgr.trigger_sender().is_none());
        mgr.stop().await;
    }

    #[tokio::test]
    async fn test_manager_executes_interval_schedule() {
        let mgr = SchedulerManager::with_defaults();

        // Register a schedule with a very short interval.
        let schedule = Schedule::new(
            "fast-interval",
            "Fast Interval",
            TriggerConfig::Interval { interval_secs: 1 }, // fires immediately
            "wf",
        );
        mgr.register(schedule).await;

        // Start with a short tick.
        mgr.start(Duration::from_millis(20)).await;
        // The initial occurrence is restored by startup recovery.
        mgr.arm();

        // Wait enough for at least one tick + execution.
        tokio::time::sleep(Duration::from_millis(100)).await;

        mgr.stop().await;

        // Should have fired at least once.
        let count = mgr.execution_count().await;
        assert!(count >= 1, "Expected at least 1 execution, got {count}");
    }

    #[tokio::test]
    async fn test_manager_list_schedules() {
        let mgr = SchedulerManager::with_defaults();
        mgr.register(Schedule::new(
            "s1",
            "S1",
            TriggerConfig::Interval { interval_secs: 60 },
            "wf",
        ))
        .await;
        mgr.register(Schedule::new(
            "s2",
            "S2",
            TriggerConfig::Interval { interval_secs: 120 },
            "wf",
        ))
        .await;

        let list = mgr.list_schedules().await;
        assert_eq!(list.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Dispatcher tests
    // -----------------------------------------------------------------------

    /// Minimal stub dispatcher for testing injection.
    struct AlwaysOkDispatcher;

    #[derive(Default)]
    struct RecordingPersistence {
        recorded: AsyncMutex<Vec<ScheduleExecution>>,
        last_fire_updates: AsyncMutex<Vec<(String, DateTime<Utc>)>>,
        persisted_started: AtomicUsize,
    }

    #[derive(Default)]
    struct CountingDispatcher {
        workflows: AsyncMutex<Vec<String>>,
    }

    enum SensitiveFailureKind {
        Workflow,
        Dispatch,
    }

    struct SensitiveFailureDispatcher {
        kind: SensitiveFailureKind,
        message: String,
    }

    impl CountingDispatcher {
        async fn calls_for(&self, workflow_id: &str) -> usize {
            self.workflows
                .lock()
                .await
                .iter()
                .filter(|seen| seen.as_str() == workflow_id)
                .count()
        }

        async fn total_calls(&self) -> usize {
            self.workflows.lock().await.len()
        }
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for CountingDispatcher {
        async fn dispatch(
            &self,
            workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            self.workflows.lock().await.push(workflow_id.to_owned());
            Ok(DispatchResult {
                success: true,
                skipped: false,
                summary: "ok".to_owned(),
                output: serde_json::Value::Null,
                duration_ms: 1,
                error: None,
            })
        }
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for SensitiveFailureDispatcher {
        async fn dispatch(
            &self,
            _workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            match self.kind {
                SensitiveFailureKind::Workflow => Ok(DispatchResult {
                    success: false,
                    skipped: false,
                    summary: "workflow failed".to_owned(),
                    output: serde_json::Value::Null,
                    duration_ms: 1,
                    error: Some(self.message.clone()),
                }),
                SensitiveFailureKind::Dispatch => {
                    Err(DispatchError::Internal(self.message.clone()))
                }
            }
        }
    }

    /// A dispatcher whose fires are always declined as skips, mirroring a
    /// campaign dispatcher whose concurrency gate is full.
    struct SkippingDispatcher;

    #[async_trait::async_trait]
    impl WorkflowDispatcher for SkippingDispatcher {
        async fn dispatch(
            &self,
            _workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            Ok(DispatchResult {
                success: true,
                skipped: true,
                summary: "skipped: max concurrent campaigns reached (2)".to_owned(),
                output: serde_json::json!({ "skipped": true }),
                duration_ms: 0,
                error: None,
            })
        }
    }

    fn due_one_time(id: &str) -> Schedule {
        Schedule::new(
            id,
            id,
            TriggerConfig::OneTime {
                at: Utc::now() - chrono::Duration::seconds(1),
            },
            id,
        )
    }

    fn future_one_time_with_hourly_limit(id: &str, max_per_hour: u32) -> Schedule {
        Schedule::new(
            id,
            id,
            TriggerConfig::OneTime {
                at: Utc::now() + chrono::Duration::hours(1),
            },
            id,
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Skip),
            concurrency_policy: Some(ConcurrencyPolicy::Allow),
            max_executions_per_hour: max_per_hour,
        })
    }

    pub(super) fn interval_schedule(id: &str) -> Schedule {
        Schedule::new(
            id,
            id,
            TriggerConfig::Interval {
                interval_secs: 3_600,
            },
            id,
        )
    }

    async fn wait_for_dispatches(dispatcher: &CountingDispatcher, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.total_calls().await < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dispatcher did not receive expected calls");
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum OccurrenceFailure {
        None,
        Reserve,
        ReserveCommitted,
        Cursor,
        PauseCursor,
        Running,
        Terminal,
        Renew,
        HourlyHistory,
    }

    struct OccurrenceRecordingPersistence {
        failure: OccurrenceFailure,
        occurrence: AsyncMutex<Option<OneTimeOccurrence>>,
        execution: AsyncMutex<Option<ScheduleExecution>>,
        transitions: AsyncMutex<Vec<(OneTimeOccurrenceState, OneTimeOccurrenceState)>>,
        renewals: AsyncMutex<Vec<(String, String)>>,
        schedule_updates: AsyncMutex<Vec<Schedule>>,
        cursor_update_started: Notify,
        occurrence_calls: AtomicUsize,
    }

    impl OccurrenceRecordingPersistence {
        fn new(failure: OccurrenceFailure) -> Self {
            Self {
                failure,
                occurrence: AsyncMutex::new(None),
                execution: AsyncMutex::new(None),
                transitions: AsyncMutex::new(Vec::new()),
                renewals: AsyncMutex::new(Vec::new()),
                schedule_updates: AsyncMutex::new(Vec::new()),
                cursor_update_started: Notify::new(),
                occurrence_calls: AtomicUsize::new(0),
            }
        }
    }

    fn execution_matches(left: &ScheduleExecution, right: &ScheduleExecution) -> bool {
        left.execution_id == right.execution_id
            && left.schedule_id == right.schedule_id
            && left.triggered_at == right.triggered_at
            && left.started_at == right.started_at
            && left.completed_at == right.completed_at
            && left.status == right.status
            && left.workflow_execution_id == right.workflow_execution_id
            && left.request_summary == right.request_summary
            && left.response_summary == right.response_summary
            && left.error_message == right.error_message
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for RecordingPersistence {
        async fn record_execution(
            &self,
            execution: &ScheduleExecution,
        ) -> Result<(), PersistenceError> {
            self.recorded.lock().await.push(execution.clone());
            Ok(())
        }

        async fn update_execution(
            &self,
            execution: &ScheduleExecution,
        ) -> Result<(), PersistenceError> {
            self.recorded.lock().await.push(execution.clone());
            Ok(())
        }

        async fn update_schedule(&self, schedule: &Schedule) -> Result<(), PersistenceError> {
            self.last_fire_updates.lock().await.push((
                schedule.id.clone(),
                schedule.last_fire.unwrap_or_else(Utc::now),
            ));
            Ok(())
        }

        async fn executions_started_since(
            &self,
            _schedule_id: &str,
            _since: DateTime<Utc>,
        ) -> Result<u64, PersistenceError> {
            Ok(u64::try_from(self.persisted_started.load(Ordering::SeqCst)).unwrap_or(u64::MAX))
        }
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for OccurrenceRecordingPersistence {
        async fn record_execution(
            &self,
            _execution: &ScheduleExecution,
        ) -> Result<(), PersistenceError> {
            Ok(())
        }

        async fn update_execution(
            &self,
            _execution: &ScheduleExecution,
        ) -> Result<(), PersistenceError> {
            Ok(())
        }

        async fn update_schedule(&self, schedule: &Schedule) -> Result<(), PersistenceError> {
            self.schedule_updates.lock().await.push(schedule.clone());
            match self.failure {
                OccurrenceFailure::Cursor => Err(PersistenceError::new("injected cursor failure")),
                OccurrenceFailure::PauseCursor => {
                    self.cursor_update_started.notify_one();
                    std::future::pending().await
                }
                OccurrenceFailure::None
                | OccurrenceFailure::Reserve
                | OccurrenceFailure::ReserveCommitted
                | OccurrenceFailure::Running
                | OccurrenceFailure::Terminal
                | OccurrenceFailure::Renew
                | OccurrenceFailure::HourlyHistory => Ok(()),
            }
        }

        async fn executions_started_since(
            &self,
            _schedule_id: &str,
            _since: DateTime<Utc>,
        ) -> Result<u64, PersistenceError> {
            if self.failure == OccurrenceFailure::HourlyHistory {
                Err(PersistenceError::new(
                    "injected hourly history read failure",
                ))
            } else {
                Ok(0)
            }
        }

        async fn reserve_one_time_occurrence(
            &self,
            candidate: &OneTimeOccurrence,
            execution: &ScheduleExecution,
        ) -> Result<OneTimeReservation, PersistenceError> {
            self.occurrence_calls.fetch_add(1, Ordering::SeqCst);
            if self.failure == OccurrenceFailure::Reserve {
                return Err(PersistenceError::new(SENSITIVE_PERSISTENCE_ERROR));
            }
            let mut stored = self.occurrence.lock().await;
            if let Some(existing) = stored.as_ref() {
                return Ok(OneTimeReservation::Existing(existing.clone()));
            }
            *stored = Some(candidate.clone());
            *self.execution.lock().await = Some(execution.clone());
            if self.failure == OccurrenceFailure::ReserveCommitted {
                Err(PersistenceError::new(
                    "injected error after committed reservation",
                ))
            } else {
                Ok(OneTimeReservation::Reserved(candidate.clone()))
            }
        }

        async fn transition_one_time_occurrence(
            &self,
            transition: &OneTimeOccurrenceTransition,
            execution: &ScheduleExecution,
        ) -> Result<OneTimeTransitionResult, PersistenceError> {
            if (transition.to == OneTimeOccurrenceState::Running
                && self.failure == OccurrenceFailure::Running)
                || (transition.to != OneTimeOccurrenceState::Running
                    && self.failure == OccurrenceFailure::Terminal)
            {
                return Err(PersistenceError::new("injected transition failure"));
            }
            let mut stored = self.occurrence.lock().await;
            let Some(current) = stored.as_mut() else {
                return Ok(OneTimeTransitionResult::Missing);
            };
            if current.state == transition.to {
                let transition_matches = self
                    .transitions
                    .lock()
                    .await
                    .last()
                    .is_some_and(|states| *states == (transition.from, transition.to));
                let paired_execution_matches = self
                    .execution
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(|stored_execution| execution_matches(stored_execution, execution));
                let replay_matches = current.id == transition.occurrence_id
                    && current.schedule_id == transition.schedule_id
                    && current.execution_id == transition.execution_id
                    && current.owner_id == transition.owner_id
                    && current.lease_expires_at == transition.lease_expires_at
                    && current.recovery_detail == transition.recovery_detail
                    && transition_matches
                    && paired_execution_matches;
                return Ok(if replay_matches {
                    OneTimeTransitionResult::Idempotent(current.clone())
                } else {
                    OneTimeTransitionResult::Conflict(current.clone())
                });
            }
            if current.state != transition.from
                || current.id != transition.occurrence_id
                || current.schedule_id != transition.schedule_id
                || current.execution_id != transition.execution_id
                || current.owner_id != transition.owner_id
            {
                return Ok(OneTimeTransitionResult::Conflict(current.clone()));
            }
            self.transitions
                .lock()
                .await
                .push((transition.from, transition.to));
            current.state = transition.to;
            current.lease_expires_at = transition.lease_expires_at;
            current
                .recovery_detail
                .clone_from(&transition.recovery_detail);
            *self.execution.lock().await = Some(execution.clone());
            Ok(OneTimeTransitionResult::Applied(current.clone()))
        }

        async fn renew_one_time_lease(
            &self,
            occurrence_id: &str,
            owner_id: &str,
            lease_expires_at: DateTime<Utc>,
        ) -> Result<bool, PersistenceError> {
            self.renewals
                .lock()
                .await
                .push((occurrence_id.to_owned(), owner_id.to_owned()));
            if self.failure == OccurrenceFailure::Renew {
                return Err(PersistenceError::new("injected renew failure"));
            }
            let mut stored = self.occurrence.lock().await;
            let updated = stored.as_mut().is_some_and(|current| {
                if current.id == occurrence_id
                    && current.owner_id == owner_id
                    && !current.terminal()
                {
                    current.lease_expires_at = Some(lease_expires_at);
                    true
                } else {
                    false
                }
            });
            Ok(updated)
        }

        async fn release_one_time_lease(
            &self,
            occurrence_id: &str,
            owner_id: &str,
            released_at: DateTime<Utc>,
            recovery_detail: &str,
        ) -> Result<bool, PersistenceError> {
            let mut stored = self.occurrence.lock().await;
            let updated = stored.as_mut().is_some_and(|current| {
                if current.id == occurrence_id
                    && current.owner_id == owner_id
                    && !current.terminal()
                {
                    current.lease_expires_at = Some(released_at);
                    current.recovery_detail = Some(recovery_detail.to_owned());
                    true
                } else {
                    false
                }
            });
            Ok(updated)
        }

        async fn get_one_time_occurrence(
            &self,
            occurrence_id: &str,
        ) -> Result<Option<OneTimeOccurrence>, PersistenceError> {
            Ok(self
                .occurrence
                .lock()
                .await
                .clone()
                .filter(|occurrence| occurrence.id == occurrence_id))
        }
    }

    fn fixture_occurrence(state: OneTimeOccurrenceState) -> OneTimeOccurrence {
        OneTimeOccurrence {
            id: "occ-existing".to_owned(),
            schedule_id: "once-existing".to_owned(),
            execution_id: "exec-existing".to_owned(),
            triggered_at: Utc::now() - chrono::Duration::seconds(1),
            state,
            owner_id: "owner-existing".to_owned(),
            lease_expires_at: (!matches!(
                state,
                OneTimeOccurrenceState::Completed
                    | OneTimeOccurrenceState::Failed
                    | OneTimeOccurrenceState::Cancelled
            ))
            .then(|| Utc::now() + chrono::Duration::seconds(60)),
            recovery_detail: None,
        }
    }

    fn fixture_running_execution(occurrence: &OneTimeOccurrence) -> ScheduleExecution {
        ScheduleExecution {
            execution_id: occurrence.execution_id.clone(),
            schedule_id: occurrence.schedule_id.clone(),
            triggered_at: occurrence.triggered_at,
            started_at: Some(occurrence.triggered_at + chrono::Duration::milliseconds(1)),
            completed_at: None,
            status: ExecutionStatus::Running,
            workflow_execution_id: None,
            request_summary: serde_json::json!({"fixture": "running"}),
            response_summary: serde_json::json!({}),
            error_message: None,
        }
    }

    fn repeated_running_transition(occurrence: &OneTimeOccurrence) -> OneTimeOccurrenceTransition {
        OneTimeOccurrenceTransition {
            occurrence_id: occurrence.id.clone(),
            schedule_id: occurrence.schedule_id.clone(),
            execution_id: occurrence.execution_id.clone(),
            owner_id: occurrence.owner_id.clone(),
            from: OneTimeOccurrenceState::Reserved,
            to: OneTimeOccurrenceState::Running,
            lease_expires_at: occurrence.lease_expires_at,
            recovery_detail: occurrence.recovery_detail.clone(),
        }
    }

    async fn persistence_with_running_occurrence() -> (
        OccurrenceRecordingPersistence,
        OneTimeOccurrence,
        ScheduleExecution,
    ) {
        let persistence = OccurrenceRecordingPersistence::new(OccurrenceFailure::None);
        let occurrence = fixture_occurrence(OneTimeOccurrenceState::Reserved);
        let execution = fixture_running_execution(&occurrence);
        let transition = repeated_running_transition(&occurrence);
        *persistence.occurrence.lock().await = Some(occurrence);
        let result = persistence
            .transition_one_time_occurrence(&transition, &execution)
            .await
            .unwrap();
        assert!(matches!(result, OneTimeTransitionResult::Applied(_)));
        let occurrence = persistence.occurrence.lock().await.clone().unwrap();
        (persistence, occurrence, execution)
    }

    #[tokio::test]
    async fn same_destination_with_wrong_owner_is_conflict_not_idempotent() {
        let (persistence, occurrence, execution) = persistence_with_running_occurrence().await;
        let mut transition = repeated_running_transition(&occurrence);
        transition.owner_id = "different-owner".to_owned();

        let result = persistence
            .transition_one_time_occurrence(&transition, &execution)
            .await
            .unwrap();

        assert!(matches!(result, OneTimeTransitionResult::Conflict(_)));
    }

    #[tokio::test]
    async fn same_destination_with_wrong_identity_is_conflict_not_idempotent() {
        let (persistence, occurrence, execution) = persistence_with_running_occurrence().await;
        let mut transitions = [
            repeated_running_transition(&occurrence),
            repeated_running_transition(&occurrence),
            repeated_running_transition(&occurrence),
        ];
        transitions[0].occurrence_id = "different-occurrence".to_owned();
        transitions[1].schedule_id = "different-schedule".to_owned();
        transitions[2].execution_id = "different-execution".to_owned();

        for transition in transitions {
            let result = persistence
                .transition_one_time_occurrence(&transition, &execution)
                .await
                .unwrap();
            assert!(matches!(result, OneTimeTransitionResult::Conflict(_)));
        }
    }

    #[tokio::test]
    async fn same_destination_with_different_execution_is_conflict_not_idempotent() {
        let (persistence, occurrence, mut execution) = persistence_with_running_occurrence().await;
        let transition = repeated_running_transition(&occurrence);
        execution.response_summary = serde_json::json!({"changed": true});

        let result = persistence
            .transition_one_time_occurrence(&transition, &execution)
            .await
            .unwrap();

        assert!(matches!(result, OneTimeTransitionResult::Conflict(_)));
    }

    #[tokio::test]
    async fn exact_transition_replay_is_idempotent() {
        let persistence = OccurrenceRecordingPersistence::new(OccurrenceFailure::None);
        let occurrence = fixture_occurrence(OneTimeOccurrenceState::Reserved);
        let execution = fixture_running_execution(&occurrence);
        let transition = repeated_running_transition(&occurrence);
        *persistence.occurrence.lock().await = Some(occurrence);

        let applied = persistence
            .transition_one_time_occurrence(&transition, &execution)
            .await
            .unwrap();
        let replayed = persistence
            .transition_one_time_occurrence(&transition, &execution)
            .await
            .unwrap();

        assert!(matches!(applied, OneTimeTransitionResult::Applied(_)));
        assert!(matches!(replayed, OneTimeTransitionResult::Idempotent(_)));
    }

    async fn manager_and_persistence(
        failure: OccurrenceFailure,
    ) -> (SchedulerManager, Arc<OccurrenceRecordingPersistence>) {
        let manager = SchedulerManager::with_defaults();
        let persistence = Arc::new(OccurrenceRecordingPersistence::new(failure));
        manager.set_persistence(persistence.clone()).await;
        (manager, persistence)
    }

    async fn manager_with_occurrence_failure(failure: OccurrenceFailure) -> SchedulerManager {
        manager_and_persistence(failure).await.0
    }

    async fn attached_counting_dispatcher(manager: &SchedulerManager) -> Arc<CountingDispatcher> {
        let dispatcher = Arc::new(CountingDispatcher::default());
        manager.set_dispatcher(dispatcher.clone()).await;
        dispatcher
    }

    async fn wait_for_occurrence(persistence: &OccurrenceRecordingPersistence) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while persistence.occurrence.lock().await.is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("occurrence was not reserved");
    }

    async fn wait_for_state(
        persistence: &OccurrenceRecordingPersistence,
        expected: OneTimeOccurrenceState,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while persistence
                .occurrence
                .lock()
                .await
                .as_ref()
                .map(|occurrence| occurrence.state)
                != Some(expected)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("occurrence did not reach expected state");
    }

    async fn wait_for_one_time_status(
        manager: &SchedulerManager,
        schedule_id: &str,
    ) -> OneTimeRuntimeStatus {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let status = manager.one_time_runtime_status(schedule_id).await;
                if status != OneTimeRuntimeStatus::Ready {
                    return status;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("one-time status did not settle")
    }

    async fn wait_for_one_time_recovery(manager: &SchedulerManager, schedule_id: &str) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !matches!(
                manager.one_time_runtime_status(schedule_id).await,
                OneTimeRuntimeStatus::RecoveryRequired { .. }
            ) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("one-time schedule did not require recovery");
    }

    async fn wait_for_cursor_update(persistence: &OccurrenceRecordingPersistence) {
        tokio::time::timeout(
            Duration::from_secs(2),
            persistence.cursor_update_started.notified(),
        )
        .await
        .expect("cursor persistence did not start");
    }

    async fn send_one_time_now(manager: &SchedulerManager, schedule_id: &str) {
        manager
            .trigger_sender()
            .expect("scheduler is running")
            .send(FiredTrigger {
                cascade_depth: 0,
                schedule_id: schedule_id.to_owned(),
                fired_at: Utc::now(),
                trigger_type: TriggerType::OneTime,
                is_recovery: false,
                event_payload: None,
            })
            .await
            .expect("trigger queue accepts one-time occurrence");
    }

    #[tokio::test]
    async fn latched_one_time_block_precedes_mutating_hourly_limit_preflight() {
        let manager = SchedulerManager::with_defaults();
        let persistence = Arc::new(RecordingPersistence {
            persisted_started: AtomicUsize::new(1),
            ..RecordingPersistence::default()
        });
        manager.set_persistence(persistence.clone()).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager
            .register(future_one_time_with_hourly_limit("blocked-once", 1))
            .await;
        manager
            .register(policy_schedule(
                "recurring-sentinel",
                ConcurrencyPolicy::Allow,
                0,
            ))
            .await;
        manager.block_one_time("journal is unavailable").await;
        manager.start(Duration::from_mins(1)).await;

        send_one_time_now(&manager, "blocked-once").await;
        send_now(&manager, "recurring-sentinel").await;
        wait_for_dispatches(&dispatcher, 1).await;

        assert_eq!(dispatcher.calls_for("blocked-once").await, 0);
        assert_eq!(dispatcher.calls_for("wf").await, 1);
        assert_eq!(
            manager
                .get_schedule("blocked-once")
                .await
                .unwrap()
                .last_fire,
            None
        );
        assert!(manager.execution_history("blocked-once").await.is_empty());
        assert!(!persistence
            .last_fire_updates
            .lock()
            .await
            .iter()
            .any(|(schedule_id, _)| schedule_id == "blocked-once"));
        manager.stop().await;
    }

    #[tokio::test]
    async fn one_time_hourly_history_read_failure_latches_without_mutation() {
        let (manager, persistence) =
            manager_and_persistence(OccurrenceFailure::HourlyHistory).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager
            .register(future_one_time_with_hourly_limit(
                "hourly-history-unavailable",
                1,
            ))
            .await;
        manager
            .register(policy_schedule(
                "recurring-sentinel",
                ConcurrencyPolicy::Allow,
                0,
            ))
            .await;
        manager.start(Duration::from_mins(1)).await;

        send_one_time_now(&manager, "hourly-history-unavailable").await;
        send_now(&manager, "recurring-sentinel").await;
        wait_for_dispatches(&dispatcher, 1).await;

        assert_eq!(dispatcher.calls_for("hourly-history-unavailable").await, 0);
        assert_eq!(dispatcher.calls_for("wf").await, 1);
        assert_eq!(
            manager
                .get_schedule("hourly-history-unavailable")
                .await
                .unwrap()
                .last_fire,
            None
        );
        assert!(manager
            .execution_history("hourly-history-unavailable")
            .await
            .is_empty());
        assert_eq!(
            manager.one_time_block_reason().await.as_deref(),
            Some("one-time hourly execution history is unavailable")
        );
        assert_eq!(persistence.occurrence_calls.load(Ordering::SeqCst), 0);
        assert!(!persistence
            .schedule_updates
            .lock()
            .await
            .iter()
            .any(|schedule| schedule.id == "hourly-history-unavailable"));
        manager.stop().await;
    }

    #[tokio::test]
    async fn missing_occurrence_persistence_blocks_only_one_time_dispatch() {
        let manager = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(CountingDispatcher::default());
        manager.set_dispatcher(dispatcher.clone()).await;
        manager.register(due_one_time("once")).await;
        manager.register(interval_schedule("recurring")).await;
        // Restored work needs an armed scheduler; this test intends it to run.
        manager.arm();
        manager.start(Duration::from_millis(10)).await;
        assert!(matches!(
            wait_for_one_time_status(&manager, "once").await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
        wait_for_dispatches(&dispatcher, 1).await;
        manager.stop().await;
        assert_eq!(dispatcher.calls_for("once").await, 0);
        assert!(dispatcher.calls_for("recurring").await >= 1);
    }

    #[tokio::test]
    async fn missing_occurrence_persistence_precedes_parameter_failure_recording() {
        let manager = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(CountingDispatcher::default());
        manager.set_dispatcher(dispatcher.clone()).await;
        manager
            .register(
                due_one_time("once-bad-params")
                    .with_params(serde_json::json!({"value": "{{ unknown.value }}"})),
            )
            .await;
        // Restored work needs an armed scheduler; this test intends it to run.
        manager.arm();
        manager.start(Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        assert_eq!(
            manager
                .get_schedule("once-bad-params")
                .await
                .unwrap()
                .last_fire,
            None
        );
        assert!(manager
            .execution_history("once-bad-params")
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn existing_receipt_suppresses_dispatch_and_consumes_cursor() {
        let manager = SchedulerManager::with_defaults();
        let persistence = Arc::new(OccurrenceRecordingPersistence::new(OccurrenceFailure::None));
        let stored = fixture_occurrence(OneTimeOccurrenceState::Completed);
        *persistence.occurrence.lock().await = Some(stored.clone());
        manager.set_persistence(persistence.clone()).await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        manager.set_dispatcher(dispatcher.clone()).await;
        manager.register(due_one_time(&stored.schedule_id)).await;
        manager.start(Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        assert_eq!(
            manager
                .get_schedule(&stored.schedule_id)
                .await
                .unwrap()
                .last_fire,
            Some(stored.triggered_at)
        );
        assert!(persistence
            .schedule_updates
            .lock()
            .await
            .iter()
            .any(|schedule| {
                schedule.id == stored.schedule_id && schedule.last_fire == Some(stored.triggered_at)
            }));
    }

    #[tokio::test]
    async fn expired_existing_receipt_requires_recovery_after_cursor_reconciliation() {
        let manager = SchedulerManager::with_defaults();
        let persistence = Arc::new(OccurrenceRecordingPersistence::new(OccurrenceFailure::None));
        let mut stored = fixture_occurrence(OneTimeOccurrenceState::Reserved);
        stored.lease_expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        *persistence.occurrence.lock().await = Some(stored.clone());
        manager.set_persistence(persistence.clone()).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time(&stored.schedule_id)).await;
        manager.start(Duration::from_millis(10)).await;
        let status = wait_for_one_time_status(&manager, &stored.schedule_id).await;
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        assert!(matches!(
            status,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
        assert!(persistence
            .schedule_updates
            .lock()
            .await
            .iter()
            .any(|schedule| {
                schedule.id == stored.schedule_id && schedule.last_fire == Some(stored.triggered_at)
            }));
    }

    #[tokio::test]
    async fn reservation_failure_never_advances_cursor_or_dispatches() {
        let manager = manager_with_occurrence_failure(OccurrenceFailure::Reserve).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("reserve-fails")).await;
        manager.start(Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        assert_eq!(
            manager
                .get_schedule("reserve-fails")
                .await
                .unwrap()
                .last_fire,
            None
        );
        assert!(matches!(
            manager.one_time_runtime_status("reserve-fails").await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
    }

    #[tokio::test]
    async fn committed_reservation_error_reconciles_cursor_and_releases_lease() {
        let (manager, persistence) =
            manager_and_persistence(OccurrenceFailure::ReserveCommitted).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("reserve-committed")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_occurrence(&persistence).await;
        let status = wait_for_one_time_status(&manager, "reserve-committed").await;
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        assert!(matches!(
            status,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Reserved);
        assert!(receipt
            .lease_expires_at
            .is_some_and(|lease| lease <= Utc::now()));
        assert_eq!(
            receipt.recovery_detail.as_deref(),
            Some("reservation result was ambiguous")
        );
        assert_eq!(
            manager
                .get_schedule("reserve-committed")
                .await
                .unwrap()
                .last_fire,
            Some(receipt.triggered_at)
        );
        assert!(persistence
            .schedule_updates
            .lock()
            .await
            .iter()
            .any(|schedule| {
                schedule.id == receipt.schedule_id
                    && schedule.last_fire == Some(receipt.triggered_at)
            }));
    }

    #[tokio::test]
    async fn cursor_failure_after_reservation_releases_lease_without_dispatch() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::Cursor).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("cursor-fails")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_occurrence(&persistence).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Reserved).await;
        assert!(matches!(
            wait_for_one_time_status(&manager, "cursor-fails").await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Reserved);
        assert!(receipt
            .lease_expires_at
            .is_some_and(|lease| lease <= Utc::now()));
    }

    #[tokio::test]
    async fn removed_one_time_schedule_keeps_receipt_and_pending_execution_consistent_on_stop() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::Cursor).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("removed-pending")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_one_time_recovery(&manager, "removed-pending").await;

        assert!(manager.remove("removed-pending").await);
        manager.stop().await;

        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        let execution = persistence.execution.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Reserved);
        assert_eq!(execution.status, ExecutionStatus::Pending);
        assert_eq!(
            manager.execution_history("removed-pending").await[0].status,
            ExecutionStatus::Pending
        );
        assert_eq!(dispatcher.total_calls().await, 0);
    }

    #[tokio::test]
    async fn running_transition_failure_makes_zero_dispatch_calls() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::Running).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("running-fails")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_occurrence(&persistence).await;
        wait_for_one_time_recovery(&manager, "running-fails").await;
        manager.stop().await;

        assert_eq!(dispatcher.total_calls().await, 0);
        assert_eq!(
            persistence.occurrence.lock().await.as_ref().unwrap().state,
            OneTimeOccurrenceState::Reserved
        );
        let metrics = manager.occurrence_metrics();
        assert_eq!(metrics.reservation_wins, 1);
        assert_eq!(metrics.duplicate_suppressions, 0);
        assert_eq!(metrics.transition_failures, 1);
        assert!(persistence.transitions.lock().await.is_empty());
    }

    #[tokio::test]
    async fn terminal_transition_failure_dispatches_once_and_never_retries() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::Terminal).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("terminal-fails")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_dispatches(&dispatcher, 1).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Running).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(dispatcher.total_calls().await, 1);

        send_one_time_now(&manager, "terminal-fails").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.stop().await;
        assert_eq!(dispatcher.total_calls().await, 1);
        let metrics = manager.occurrence_metrics();
        assert_eq!(metrics.reservation_wins, 1);
        assert_eq!(metrics.transition_failures, 1);
        assert_eq!(metrics.lease_renewal_failures, 0);
        assert_eq!(
            persistence.transitions.lock().await.as_slice(),
            [(
                OneTimeOccurrenceState::Reserved,
                OneTimeOccurrenceState::Running
            )]
        );
    }

    #[tokio::test]
    async fn skipped_one_time_dispatch_stays_recoverable_instead_of_consumed() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        manager.set_dispatcher(Arc::new(SkippingDispatcher)).await;
        manager.register(due_one_time("skip-once")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_one_time_recovery(&manager, "skip-once").await;
        manager.stop().await;

        // The occurrence must NOT be terminally consumed: it stays non-terminal
        // with a released lease and the skip named in its recovery detail.
        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Running);
        assert!(!receipt.terminal());
        assert!(receipt.recovery_eligible(Utc::now()));
        assert_eq!(
            receipt.recovery_detail.as_deref(),
            Some(ONE_TIME_SKIP_RECOVERY)
        );
        // The only durable transition is reserved -> running; no terminal
        // transition was applied and no execution was paired to a terminal
        // state.
        assert_eq!(
            persistence.transitions.lock().await.as_slice(),
            [(
                OneTimeOccurrenceState::Reserved,
                OneTimeOccurrenceState::Running
            )]
        );
        assert_eq!(
            persistence.execution.lock().await.as_ref().unwrap().status,
            ExecutionStatus::Running
        );
        // The in-process execution history shows the skip visibly.
        let history = manager.execution_history("skip-once").await;
        assert_eq!(history[0].status, ExecutionStatus::Skipped);
        assert_eq!(
            history[0].response_summary["status"],
            serde_json::json!("skipped")
        );
    }

    #[tokio::test]
    async fn skipped_recurring_dispatch_records_a_skipped_execution_and_advances_the_cursor() {
        let manager = SchedulerManager::with_defaults();
        manager.set_dispatcher(Arc::new(SkippingDispatcher)).await;
        let schedule = Schedule::new(
            "skip-interval",
            "Skip Interval",
            TriggerConfig::Interval { interval_secs: 1 },
            "wf",
        );
        manager.register(schedule).await;
        manager.start(Duration::from_millis(20)).await;
        manager.arm();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let history = manager.execution_history("skip-interval").await;
                if history
                    .first()
                    .is_some_and(|record| record.status == ExecutionStatus::Skipped)
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("skipped execution was not recorded");
        manager.stop().await;

        let history = manager.execution_history("skip-interval").await;
        assert_eq!(history[0].status, ExecutionStatus::Skipped);
        assert_eq!(
            history[0].response_summary["status"],
            serde_json::json!("skipped")
        );
        assert!(history[0].completed_at.is_some());
        // The fire advanced the cursor, so the schedule keeps ticking instead
        // of hot-looping on the same instant.
        assert!(manager
            .get_schedule("skip-interval")
            .await
            .expect("schedule retained")
            .last_fire
            .is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn heartbeat_renews_only_the_current_owner_lease() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        let dispatcher = Arc::new(BlockingDispatcher::new());
        manager.set_dispatcher(dispatcher).await;
        manager.register(due_one_time("heartbeat")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Running).await;
        tokio::time::advance(ONE_TIME_HEARTBEAT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let renewals = persistence.renewals.lock().await.clone();
        assert!(!renewals.is_empty());
        assert!(renewals
            .iter()
            .all(|(_, owner)| owner == manager.owner_id()));
        manager.stop().await;
        let metrics = manager.occurrence_metrics();
        assert_eq!(metrics.reservation_wins, 1);
        assert_eq!(metrics.transition_failures, 0);
        assert_eq!(metrics.lease_renewal_failures, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn reserved_occurrence_renews_while_waiting_for_dispatch_capacity() {
        let manager = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let persistence = Arc::new(OccurrenceRecordingPersistence::new(OccurrenceFailure::None));
        manager.set_persistence(persistence.clone()).await;
        let dispatcher = Arc::new(BlockingDispatcher::new());
        manager.set_dispatcher(dispatcher.clone()).await;
        manager
            .register(policy_schedule(
                "capacity-blocker",
                ConcurrencyPolicy::Allow,
                0,
            ))
            .await;
        manager.register(due_one_time("waiting-on-capacity")).await;
        manager.start(Duration::from_secs(60)).await;
        send_now(&manager, "capacity-blocker").await;
        tokio::task::yield_now().await;
        send_one_time_now(&manager, "waiting-on-capacity").await;
        wait_for_occurrence(&persistence).await;

        tokio::time::advance(ONE_TIME_HEARTBEAT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            persistence.occurrence.lock().await.as_ref().unwrap().state,
            OneTimeOccurrenceState::Reserved
        );
        assert!(!persistence.renewals.lock().await.is_empty());
        manager.stop().await;
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_failure_before_dispatch_releases_reserved_lease_and_cancels_admission() {
        let manager = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let persistence = Arc::new(OccurrenceRecordingPersistence::new(
            OccurrenceFailure::Renew,
        ));
        manager.set_persistence(persistence.clone()).await;
        let dispatcher = Arc::new(BlockingDispatcher::new());
        manager.set_dispatcher(dispatcher.clone()).await;
        manager
            .register(policy_schedule(
                "renew-capacity-blocker",
                ConcurrencyPolicy::Allow,
                0,
            ))
            .await;
        manager
            .register(due_one_time("renew-before-dispatch"))
            .await;
        manager.start(Duration::from_secs(60)).await;
        send_now(&manager, "renew-capacity-blocker").await;
        tokio::task::yield_now().await;
        send_one_time_now(&manager, "renew-before-dispatch").await;
        wait_for_occurrence(&persistence).await;

        tokio::time::advance(ONE_TIME_HEARTBEAT + Duration::from_secs(1)).await;
        wait_for_one_time_recovery(&manager, "renew-before-dispatch").await;
        manager.stop().await;

        assert_eq!(dispatcher.calls.load(Ordering::SeqCst), 1);
        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Reserved);
        assert!(receipt
            .lease_expires_at
            .is_some_and(|lease| lease <= Utc::now()));
        assert_eq!(manager.occurrence_metrics().lease_renewal_failures, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn renewal_failure_after_dispatch_leaves_running_receipt_for_recovery() {
        let capture = EventCapture::default();
        let (dispatch, _callsite_registration_anchor) = capture.parallel_safe_dispatch();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::Renew).await;
        let dispatcher = Arc::new(BlockingDispatcher::new());
        let dropped = Arc::clone(&dispatcher.dropped);
        manager.set_dispatcher(dispatcher).await;
        manager.register(due_one_time("renew-after-dispatch")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Running).await;

        tokio::time::advance(ONE_TIME_HEARTBEAT + Duration::from_secs(1)).await;
        wait_for_one_time_recovery(&manager, "renew-after-dispatch").await;
        manager.stop().await;

        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(
            persistence.occurrence.lock().await.as_ref().unwrap().state,
            OneTimeOccurrenceState::Running
        );
        assert_eq!(
            persistence.execution.lock().await.as_ref().unwrap().status,
            ExecutionStatus::Running
        );
        assert_eq!(manager.occurrence_metrics().lease_renewal_failures, 1);
        let lease_event = capture
            .events()
            .into_iter()
            .find(|fields| {
                fields
                    .get("recovery_reason")
                    .is_some_and(|reason| reason == "lease_renewal")
            })
            .expect("lease-renewal recovery event");
        assert_event_identity_fields(&lease_event);
    }

    #[tokio::test]
    async fn successful_one_time_dispatch_persists_exact_terminal_state() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("terminal-success")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_dispatches(&dispatcher, 1).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Completed).await;
        manager.stop().await;

        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Completed);
        assert!(receipt.lease_expires_at.is_none());
        assert_eq!(
            persistence.execution.lock().await.as_ref().unwrap().status,
            ExecutionStatus::Completed
        );
        assert_eq!(
            persistence.transitions.lock().await.as_slice(),
            [
                (
                    OneTimeOccurrenceState::Reserved,
                    OneTimeOccurrenceState::Running
                ),
                (
                    OneTimeOccurrenceState::Running,
                    OneTimeOccurrenceState::Completed
                )
            ]
        );
        assert_eq!(manager.occurrence_metrics().transition_failures, 0);
    }

    #[tokio::test]
    async fn workflow_failure_persists_fixed_recovery_category_for_sensitive_oversized_error() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        let sensitive_error = format!(
            "/private/targets/project token=sk-sensitive-value {}",
            "x".repeat(5_000)
        );
        manager
            .set_dispatcher(Arc::new(SensitiveFailureDispatcher {
                kind: SensitiveFailureKind::Workflow,
                message: sensitive_error,
            }))
            .await;
        manager
            .register(due_one_time("sensitive-workflow-failure"))
            .await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Failed).await;
        manager.stop().await;

        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.recovery_detail.as_deref(), Some("workflow_failure"));
        assert!(!receipt
            .recovery_detail
            .as_deref()
            .is_some_and(|detail| detail.contains("sk-sensitive-value")));
        assert_eq!(
            persistence.execution.lock().await.as_ref().unwrap().status,
            ExecutionStatus::Failed
        );
    }

    #[tokio::test]
    async fn dispatcher_failure_persists_fixed_recovery_category_for_sensitive_oversized_error() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        let sensitive_error = format!(
            "/private/targets/project credential=top-secret {}",
            "y".repeat(5_000)
        );
        manager
            .set_dispatcher(Arc::new(SensitiveFailureDispatcher {
                kind: SensitiveFailureKind::Dispatch,
                message: sensitive_error,
            }))
            .await;
        manager
            .register(due_one_time("sensitive-dispatcher-failure"))
            .await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Failed).await;
        manager.stop().await;

        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(
            receipt.recovery_detail.as_deref(),
            Some("dispatcher_failure")
        );
        assert!(!receipt
            .recovery_detail
            .as_deref()
            .is_some_and(|detail| detail.contains("top-secret")));
        let execution = persistence.execution.lock().await.clone().unwrap();
        assert_eq!(
            execution.response_summary["error"],
            DISPATCHER_FAILURE_RECOVERY
        );
        assert!(execution
            .error_message
            .as_deref()
            .is_some_and(|detail| detail.contains("top-secret")));
    }

    #[tokio::test]
    async fn stop_joins_one_time_task_and_records_cancelled_receipt() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        manager
            .set_dispatcher(Arc::new(BlockingDispatcher::new()))
            .await;
        manager.register(due_one_time("cancel-on-stop")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_state(&persistence, OneTimeOccurrenceState::Running).await;
        manager.stop().await;

        let receipt = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(receipt.state, OneTimeOccurrenceState::Cancelled);
        assert!(receipt.lease_expires_at.is_none());
        assert!(!manager.has_active_occurrence(&receipt.id));
        assert_eq!(
            persistence.transitions.lock().await.as_slice(),
            [
                (
                    OneTimeOccurrenceState::Reserved,
                    OneTimeOccurrenceState::Running
                ),
                (
                    OneTimeOccurrenceState::Running,
                    OneTimeOccurrenceState::Cancelled
                )
            ]
        );
    }

    #[tokio::test]
    async fn stop_during_cursor_admission_releases_untracked_reservation() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::PauseCursor).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager.register(due_one_time("cursor-paused")).await;
        manager.start(Duration::from_millis(10)).await;
        wait_for_occurrence(&persistence).await;
        wait_for_cursor_update(&persistence).await;
        let occurrence = persistence.occurrence.lock().await.clone().unwrap();

        let tracked_before_stop = manager.has_active_occurrence(&occurrence.id);
        manager.stop().await;

        assert!(
            !tracked_before_stop,
            "a dispatch task must not be tracked before the JSON cursor is durable"
        );
        assert_eq!(dispatcher.total_calls().await, 0);
        let released = persistence.occurrence.lock().await.clone().unwrap();
        assert_eq!(released.state, OneTimeOccurrenceState::Reserved);
        assert!(released
            .lease_expires_at
            .is_some_and(|lease| lease <= Utc::now()));
        assert_eq!(
            released.recovery_detail.as_deref(),
            Some("scheduler stopped during one-time admission")
        );
        assert!(matches!(
            manager.one_time_runtime_status("cursor-paused").await,
            OneTimeRuntimeStatus::RecoveryRequired { .. }
        ));
    }

    #[tokio::test]
    async fn repeated_local_one_time_triggers_dispatch_once() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        manager
            .register(Schedule::new(
                "once-local-race",
                "once-local-race",
                TriggerConfig::OneTime {
                    at: Utc::now() + chrono::Duration::hours(1),
                },
                "once-local-race",
            ))
            .await;
        manager.start(Duration::from_mins(1)).await;

        send_one_time_now(&manager, "once-local-race").await;
        send_one_time_now(&manager, "once-local-race").await;
        wait_for_dispatches(&dispatcher, 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        manager.stop().await;

        assert_eq!(dispatcher.calls_for("once-local-race").await, 1);
        assert_eq!(persistence.occurrence_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn recurring_and_event_triggers_do_not_reserve_one_time_occurrences() {
        let (manager, persistence) = manager_and_persistence(OccurrenceFailure::None).await;
        let dispatcher = attached_counting_dispatcher(&manager).await;
        let mut interval = interval_schedule("recurring-interval");
        interval.last_fire = Some(Utc::now());
        let mut cron = Schedule::new(
            "recurring-cron",
            "recurring-cron",
            TriggerConfig::Cron {
                expression: "0 0 1 1 *".to_owned(),
                timezone: "UTC".to_owned(),
            },
            "recurring-cron",
        );
        cron.last_fire = Some(Utc::now());
        manager.register(interval).await;
        manager.register(cron).await;
        manager
            .register(Schedule::new(
                "recurring-event",
                "recurring-event",
                TriggerConfig::Event {
                    event_type: "run.completed".to_owned(),
                    debounce_secs: 0,
                    filter: None,
                },
                "recurring-event",
            ))
            .await;
        manager.start(Duration::from_mins(1)).await;
        persistence.occurrence_calls.store(0, Ordering::SeqCst);
        let sender = manager.trigger_sender().expect("scheduler is running");
        for (schedule_id, trigger_type) in [
            ("recurring-interval", TriggerType::Interval),
            ("recurring-cron", TriggerType::Cron),
        ] {
            sender
                .send(FiredTrigger {
                    cascade_depth: 0,
                    schedule_id: schedule_id.to_owned(),
                    fired_at: Utc::now(),
                    trigger_type,
                    is_recovery: false,
                    event_payload: None,
                })
                .await
                .expect("trigger queue accepts recurring occurrence");
        }
        assert_eq!(
            manager
                .emit_event(IncomingEvent {
                    cascade_depth: 0,
                    event_type: "run.completed".to_owned(),
                    payload: Some(serde_json::json!({"run_id": "run-1"})),
                    timestamp: Utc::now(),
                    source_schedule_id: None,
                })
                .await,
            ["recurring-event".to_owned()]
        );
        wait_for_dispatches(&dispatcher, 3).await;
        manager.stop().await;

        for workflow_id in ["recurring-interval", "recurring-cron", "recurring-event"] {
            assert_eq!(dispatcher.calls_for(workflow_id).await, 1);
        }
        assert_eq!(
            persistence.occurrence_calls.load(Ordering::SeqCst),
            0,
            "recurring and event triggers must not enter one-time persistence"
        );
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for AlwaysOkDispatcher {
        async fn dispatch(
            &self,
            workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            Ok(DispatchResult {
                success: true,
                skipped: false,
                summary: format!("ok: {workflow_id}"),
                output: serde_json::Value::Null,
                duration_ms: 1,
                error: None,
            })
        }
    }

    #[tokio::test]
    async fn test_manager_dispatcher_none_by_default() {
        let mgr = SchedulerManager::with_defaults();
        assert!(mgr.dispatcher().await.is_none());
    }

    #[tokio::test]
    async fn test_manager_set_dispatcher() {
        let mgr = SchedulerManager::with_defaults();
        assert!(mgr.dispatcher().await.is_none());

        mgr.set_dispatcher(Arc::new(AlwaysOkDispatcher)).await;
        assert!(mgr.dispatcher().await.is_some());
    }

    #[tokio::test]
    async fn test_manager_persists_interval_execution() {
        let mgr = SchedulerManager::with_defaults();
        let persistence = Arc::new(RecordingPersistence::default());
        let persistence_trait: Arc<dyn SchedulerPersistence> = persistence.clone();
        mgr.set_persistence(persistence_trait).await;

        mgr.register(Schedule::new(
            "persisted-interval",
            "Persisted Interval",
            TriggerConfig::Interval { interval_secs: 1 },
            "wf",
        ))
        .await;

        mgr.start(Duration::from_millis(20)).await;
        // The initial occurrence is restored by startup recovery.
        mgr.arm();
        tokio::time::sleep(Duration::from_millis(100)).await;
        mgr.stop().await;

        let recorded = persistence.recorded.lock().await;
        assert!(
            !recorded.is_empty(),
            "expected interval execution to be persisted"
        );
        assert!(
            recorded
                .iter()
                .any(|execution| execution.schedule_id == "persisted-interval"),
            "expected a persisted execution for the interval schedule"
        );
        drop(recorded);

        let last_fire_updates = persistence.last_fire_updates.lock().await;
        assert!(
            last_fire_updates
                .iter()
                .any(|(schedule_id, _)| schedule_id == "persisted-interval"),
            "expected last_fire to be persisted for the interval schedule"
        );
    }

    fn missed_schedule(id: &str, count: i32, policy: MissedPolicy) -> Schedule {
        let mut schedule =
            Schedule::new(id, id, TriggerConfig::Interval { interval_secs: 1 }, "wf")
                .with_policies(SchedulePolicies {
                    missed_policy: Some(policy),
                    concurrency_policy: Some(ConcurrencyPolicy::default()),
                    max_executions_per_hour: 0,
                });
        schedule.last_fire = Some(Utc::now() - TimeDelta::seconds(i64::from(count)));
        schedule
    }

    #[tokio::test]
    async fn recovery_larger_than_queue_capacity_does_not_block_start() {
        let mgr = SchedulerManager::with_defaults();
        for id in ["large-backfill-a", "large-backfill-b", "large-backfill-c"] {
            mgr.register(missed_schedule(id, 300, MissedPolicy::Backfill))
                .await;
        }

        tokio::time::timeout(
            Duration::from_millis(250),
            mgr.start(Duration::from_mins(1)),
        )
        .await
        .expect("scheduler startup must not wait for the bounded recovery queue");
        mgr.stop().await;
    }

    #[tokio::test]
    async fn skipped_recovery_advances_without_immediate_execution() {
        let mgr = SchedulerManager::with_defaults();
        let persistence = Arc::new(RecordingPersistence::default());
        let persistence_trait: Arc<dyn SchedulerPersistence> = persistence.clone();
        mgr.set_persistence(persistence_trait).await;
        mgr.register(missed_schedule("skip", 5, MissedPolicy::Skip))
            .await;

        mgr.start(Duration::from_millis(10)).await;
        tokio::time::sleep(Duration::from_millis(80)).await;
        mgr.stop().await;

        assert_eq!(
            mgr.execution_count().await,
            0,
            "Skip must move the recovery cursor instead of firing on the first tick"
        );
        let schedule = mgr.get_schedule("skip").await.expect("schedule retained");
        assert!(
            Utc::now() - schedule.last_fire.expect("skip cursor advanced") < TimeDelta::seconds(1),
            "skip cursor should advance to the latest due occurrence"
        );
        assert!(
            persistence
                .last_fire_updates
                .lock()
                .await
                .iter()
                .any(|(id, _)| id == "skip"),
            "skip cursor advancement must be durable"
        );
    }

    #[tokio::test]
    async fn restart_before_arming_preserves_missed_recovery() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(CountingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        let mut schedule = Schedule::new(
            "restart-recovery",
            "restart-recovery",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "restart-recovery",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::CatchUp),
            ..SchedulePolicies::default()
        });
        schedule.last_fire = Some(Utc::now() - TimeDelta::hours(2));
        mgr.register(schedule).await;

        mgr.start(Duration::from_mins(1)).await;
        let saved =
            serde_json::to_vec(&mgr.get_schedule("restart-recovery").await.unwrap()).unwrap();
        mgr.stop().await;
        let mgr = SchedulerManager::with_defaults();
        mgr.set_dispatcher(dispatcher.clone()).await;
        mgr.register(serde_json::from_slice(&saved).unwrap()).await;
        mgr.start(Duration::from_mins(1)).await;
        mgr.arm();
        let delivered = tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.total_calls().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        mgr.stop().await;
        assert!(delivered.is_ok(), "missed work was lost before arming");
    }

    #[tokio::test]
    async fn paused_checkpoint_resumes_recovery_after_restart() {
        let mgr = SchedulerManager::with_defaults();
        let mut schedule = Schedule::new(
            "paused-recovery",
            "paused-recovery",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "wf",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::CatchUp),
            ..SchedulePolicies::default()
        });
        schedule.last_fire = Some(Utc::now() - TimeDelta::hours(2));
        mgr.register(schedule).await;
        mgr.start(Duration::from_mins(1)).await;
        assert!(mgr.pause("paused-recovery").await);
        let saved =
            serde_json::to_vec(&mgr.get_schedule("paused-recovery").await.unwrap()).unwrap();
        mgr.stop().await;

        let restarted = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(CountingDispatcher::default());
        restarted.set_dispatcher(dispatcher.clone()).await;
        restarted
            .register(serde_json::from_slice(&saved).unwrap())
            .await;
        restarted.start(Duration::from_mins(1)).await;
        restarted.arm();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(dispatcher.total_calls().await, 0);
        assert!(restarted.resume("paused-recovery").await);
        let resumed = tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.total_calls().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        restarted.stop().await;
        assert!(
            resumed.is_ok(),
            "pending recovery was stranded after resume"
        );
    }

    struct SlotGateDispatcher {
        started: Notify,
        release: Notify,
        recovered: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for SlotGateDispatcher {
        async fn dispatch(
            &self,
            workflow_id: &str,
            _: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            if workflow_id == "blocker" {
                self.started.notify_one();
                self.release.notified().await;
            } else {
                self.recovered.fetch_add(1, Ordering::SeqCst);
            }
            Ok(DispatchResult {
                success: true,
                skipped: false,
                summary: "ok".into(),
                output: serde_json::Value::Null,
                duration_ms: 0,
                error: None,
            })
        }
    }

    #[tokio::test]
    async fn paused_recovery_waiting_for_a_slot_does_not_dispatch_until_resumed() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let dispatcher = Arc::new(SlotGateDispatcher {
            started: Notify::new(),
            release: Notify::new(),
            recovered: AtomicUsize::new(0),
        });
        mgr.set_dispatcher(dispatcher.clone()).await;
        let mut blocker = policy_schedule("blocker", ConcurrencyPolicy::Allow, 0);
        blocker.workflow_id = "blocker".into();
        mgr.register(blocker).await;
        let mut recovery = Schedule::new(
            "paused-slot",
            "paused-slot",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "recovery",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::CatchUp),
            ..SchedulePolicies::default()
        });
        recovery.last_fire = Some(Utc::now() - TimeDelta::hours(2));
        mgr.register(recovery).await;
        mgr.start(Duration::from_mins(1)).await;
        send_now(&mgr, "blocker").await;
        tokio::time::timeout(Duration::from_secs(2), dispatcher.started.notified())
            .await
            .expect("blocker did not start");
        mgr.arm();
        wait_for_history(&mgr, "paused-slot", 1).await;
        mgr.pause("paused-slot").await;
        dispatcher.release.notify_one();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let while_paused = dispatcher.recovered.load(Ordering::SeqCst);
        mgr.resume("paused-slot").await;
        let resumed = tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.recovered.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        mgr.stop().await;
        assert_eq!(while_paused, 0);
        assert!(resumed.is_ok(), "recovery did not resume");
    }

    #[tokio::test]
    async fn paused_recovery_does_not_block_other_schedules() {
        let initial = SchedulerManager::with_defaults();
        for id in ["paused", "active"] {
            let mut schedule = Schedule::new(
                id,
                id,
                TriggerConfig::Interval {
                    interval_secs: 3600,
                },
                id,
            )
            .with_policies(SchedulePolicies {
                missed_policy: Some(MissedPolicy::CatchUp),
                ..SchedulePolicies::default()
            });
            schedule.last_fire = Some(Utc::now() - TimeDelta::hours(2));
            initial.register(schedule).await;
        }
        initial.start(Duration::from_mins(1)).await;
        initial.pause("paused").await;
        let saved = serde_json::to_vec(&initial.list_schedules().await).unwrap();
        initial.stop().await;
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(CountingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        for schedule in serde_json::from_slice::<Vec<Schedule>>(&saved).unwrap() {
            mgr.register(schedule).await;
        }
        mgr.start(Duration::from_mins(1)).await;
        mgr.arm();
        let active = tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.calls_for("active").await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let paused = dispatcher.calls_for("paused").await;
        mgr.stop().await;
        assert!(active.is_ok(), "paused recovery blocked another schedule");
        assert_eq!(paused, 0);
    }

    struct SerialRecordingDispatcher {
        active: AtomicUsize,
        maximum: AtomicUsize,
        completed: AtomicUsize,
        completed_notify: Notify,
    }

    impl SerialRecordingDispatcher {
        fn new() -> Self {
            Self {
                active: AtomicUsize::new(0),
                maximum: AtomicUsize::new(0),
                completed: AtomicUsize::new(0),
                completed_notify: Notify::new(),
            }
        }

        async fn wait_for(&self, expected: usize) {
            tokio::time::timeout(Duration::from_secs(2), async {
                while self.completed.load(Ordering::SeqCst) < expected {
                    self.completed_notify.notified().await;
                }
            })
            .await
            .expect("backfill did not complete");
        }
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for SerialRecordingDispatcher {
        async fn dispatch(
            &self,
            _workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            self.completed.fetch_add(1, Ordering::SeqCst);
            self.completed_notify.notify_waiters();
            Ok(DispatchResult {
                success: true,
                skipped: false,
                summary: "ok".to_owned(),
                output: serde_json::Value::Null,
                duration_ms: 10,
                error: None,
            })
        }
    }

    #[tokio::test]
    async fn backfill_is_lossless_and_serialized_per_schedule() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(SerialRecordingDispatcher::new());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(missed_schedule(
            "serial-backfill",
            5,
            MissedPolicy::Backfill,
        ))
        .await;

        // Restored work needs an armed scheduler; this test intends it to run.
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        dispatcher.wait_for(5).await;
        mgr.stop().await;

        assert_eq!(dispatcher.completed.load(Ordering::SeqCst), 5);
        assert_eq!(
            dispatcher.maximum.load(Ordering::SeqCst),
            1,
            "backfill occurrences for one schedule must be explicitly queued"
        );
    }

    #[tokio::test]
    async fn backfill_persists_terminal_records_even_when_memory_retention_prunes_them() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            history_retention_limit: 1,
            ..SchedulerConfig::default()
        });
        let persistence = Arc::new(RecordingPersistence::default());
        mgr.set_persistence(persistence.clone()).await;
        let dispatcher = Arc::new(SerialRecordingDispatcher::new());
        mgr.set_dispatcher(dispatcher.clone()).await;
        mgr.register(missed_schedule(
            "retained-backfill",
            3,
            MissedPolicy::Backfill,
        ))
        .await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        dispatcher.wait_for(3).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        mgr.stop().await;
        let records = persistence.recorded.lock().await;
        let terminal = records
            .iter()
            .filter(|record| {
                record.schedule_id == "retained-backfill"
                    && record.status == ExecutionStatus::Completed
            })
            .count();
        assert_eq!(
            terminal, 3,
            "all completed executions must reach persistence"
        );
    }

    #[tokio::test]
    async fn fallback_persists_completion_even_when_memory_retention_prunes_it() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            history_retention_limit: 1,
            ..SchedulerConfig::default()
        });
        let persistence = Arc::new(RecordingPersistence::default());
        mgr.set_persistence(persistence.clone()).await;
        mgr.register(missed_schedule("fallback-pruned", 1, MissedPolicy::CatchUp))
            .await;
        mgr.execution_store()
            .lock()
            .await
            .record(ScheduleExecution {
                execution_id: "other-pending".into(),
                schedule_id: "fallback-pruned".into(),
                triggered_at: Utc::now(),
                started_at: None,
                completed_at: None,
                status: ExecutionStatus::Pending,
                workflow_execution_id: None,
                request_summary: serde_json::json!({}),
                response_summary: serde_json::json!({}),
                error_message: None,
            });
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let completed = persistence.recorded.lock().await.iter().any(|record| {
            record.schedule_id == "fallback-pruned" && record.status == ExecutionStatus::Completed
        });
        mgr.stop().await;
        assert!(
            completed,
            "fallback completion was pruned before persistence"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn backfill_dispatches_occurrences_in_trigger_order() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        let schedule = missed_schedule("ordered-backfill", 100, MissedPolicy::Backfill)
            .with_params(serde_json::json!({"at": "{{ trigger.time }}"}));
        mgr.register(schedule).await;
        let serial = Arc::new(Mutex::new(()));
        let guard = serial.lock().await;
        mgr.serial_locks
            .lock()
            .await
            .insert("ordered-backfill".into(), serial.clone());
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        wait_for_history(&mgr, "ordered-backfill", 100).await;
        drop(guard);
        wait_for_params(&dispatcher, 100).await;
        mgr.stop().await;
        let received = dispatcher.received.lock().await;
        let times: Vec<_> = received
            .iter()
            .map(|params| params["at"].as_str().unwrap())
            .collect();
        assert!(
            times.windows(2).all(|pair| pair[0] < pair[1]),
            "backfill executed out of order"
        );
    }

    #[tokio::test]
    async fn configured_global_concurrency_bounds_dispatches() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 2,
            ..SchedulerConfig::default()
        });
        let dispatcher = Arc::new(SerialRecordingDispatcher::new());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        for id in ["one", "two", "three"] {
            mgr.register(Schedule::new(
                id,
                id,
                TriggerConfig::Interval { interval_secs: 60 },
                "wf",
            ))
            .await;
        }

        // Restored work needs an armed scheduler; this test intends it to run.
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        dispatcher.wait_for(3).await;
        mgr.stop().await;

        assert!(
            dispatcher.maximum.load(Ordering::SeqCst) <= 2,
            "configured scheduler concurrency was exceeded"
        );
    }

    async fn wait_for_history(mgr: &SchedulerManager, schedule_id: &str, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if mgr.execution_history(schedule_id).await.len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("scheduler history did not reach expected size");
    }

    fn policy_schedule(
        id: &str,
        concurrency_policy: ConcurrencyPolicy,
        max_hourly: u32,
    ) -> Schedule {
        let mut schedule = Schedule::new(
            id,
            id,
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "wf",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Skip),
            concurrency_policy: Some(concurrency_policy),
            max_executions_per_hour: max_hourly,
        });
        schedule.last_fire = Some(Utc::now());
        schedule
    }

    async fn send_now(mgr: &SchedulerManager, schedule_id: &str) {
        mgr.trigger_sender()
            .expect("scheduler started")
            .send(FiredTrigger {
                cascade_depth: 0,
                schedule_id: schedule_id.to_owned(),
                fired_at: Utc::now(),
                trigger_type: crate::trigger::TriggerType::Interval,
                is_recovery: false,
                event_payload: None,
            })
            .await
            .expect("trigger accepted");
    }

    #[tokio::test]
    async fn hourly_limit_records_policy_skip_without_dispatching() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(SerialRecordingDispatcher::new());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(policy_schedule("hourly", ConcurrencyPolicy::Allow, 1))
            .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "hourly").await;
        dispatcher.wait_for(1).await;
        send_now(&mgr, "hourly").await;
        wait_for_history(&mgr, "hourly", 2).await;
        mgr.stop().await;

        assert_eq!(dispatcher.completed.load(Ordering::SeqCst), 1);
        let history = mgr.execution_history("hourly").await;
        assert!(history
            .iter()
            .any(|execution| execution.status == ExecutionStatus::Skipped));
    }

    #[tokio::test]
    async fn hourly_limit_combines_persisted_starts_with_pending_reservations() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let persistence = Arc::new(RecordingPersistence {
            persisted_started: AtomicUsize::new(1),
            ..RecordingPersistence::default()
        });
        let persistence_trait: Arc<dyn SchedulerPersistence> = persistence;
        mgr.set_persistence(persistence_trait).await;
        let dispatcher = Arc::new(BlockingDispatcher {
            calls: AtomicUsize::new(0),
            dropped: Arc::new(AtomicBool::new(false)),
        });
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(policy_schedule("blocker", ConcurrencyPolicy::Allow, 0))
            .await;
        mgr.register(policy_schedule("limited", ConcurrencyPolicy::Queue, 2))
            .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "blocker").await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.calls.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("capacity blocker did not start");
        send_now(&mgr, "limited").await;
        wait_for_history(&mgr, "limited", 1).await;
        send_now(&mgr, "limited").await;
        wait_for_history(&mgr, "limited", 2).await;

        let history = mgr.execution_history("limited").await;
        assert_eq!(
            history
                .iter()
                .filter(|execution| execution.status == ExecutionStatus::Pending)
                .count(),
            1
        );
        assert_eq!(
            history
                .iter()
                .filter(|execution| execution.status == ExecutionStatus::Skipped)
                .count(),
            1
        );
        mgr.stop().await;
    }

    #[tokio::test]
    async fn backfill_reservations_consume_the_rolling_hourly_admission_limit() {
        // Regression: hourly admission used to count queued reservations by
        // *trigger* time. Recovery backfill carries historical trigger times,
        // so every queued occurrence was invisible to the limit and a whole
        // backfill batch bypassed `max_executions_per_hour`.
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let dispatcher = Arc::new(BlockingDispatcher::new());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        let mut schedule = Schedule::new(
            "bf",
            "bf",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "wf",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Backfill),
            concurrency_policy: Some(ConcurrencyPolicy::Queue),
            max_executions_per_hour: 2,
        });
        // Three missed hourly occurrences, all older than the rolling
        // one-hour admission window.
        schedule.last_fire = Some(Utc::now() - TimeDelta::seconds(3 * 3600 + 30));
        mgr.register(schedule).await;

        // Restored work needs an armed scheduler; this test intends it to run.
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;

        // The first occurrence occupies the single execution slot forever;
        // the others must queue or be skipped by the hourly limit.
        wait_for_history(&mgr, "bf", 3).await;
        mgr.stop().await;

        let history = mgr.execution_history("bf").await;
        assert!(
            history
                .iter()
                .any(|execution| execution.status == ExecutionStatus::Skipped),
            "queued backfill reservations must consume the rolling hourly admission limit"
        );
        assert!(
            history
                .iter()
                .filter(|execution| execution.status != ExecutionStatus::Skipped)
                .count()
                <= 2,
            "at most max_executions_per_hour occurrences may start or queue"
        );
    }

    #[tokio::test]
    async fn backfill_bounds_waiting_reservations() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        mgr.set_dispatcher(Arc::new(BlockingDispatcher::new()))
            .await;
        mgr.register(missed_schedule(
            "bounded-backfill",
            300,
            MissedPolicy::Backfill,
        ))
        .await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        wait_for_history(&mgr, "bounded-backfill", 200).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let pending = mgr
            .execution_store()
            .lock()
            .await
            .pending_count("bounded-backfill");
        mgr.stop().await;
        assert!(
            pending <= 256,
            "backfill admitted {pending} waiting executions"
        );
    }

    #[tokio::test]
    async fn stop_reconciles_untracked_pending_reservations_to_cancelled() {
        // `handle_fired_trigger` records its Pending reservation and persists
        // it *before* the dispatch task is spawned and tracked. Aborting the
        // executor inside that persistence window leaves a Pending row no
        // tracked task owns; stop must reconcile it so it cannot consume
        // hourly admission budget forever.
        let mgr = SchedulerManager::with_defaults();
        let persistence = Arc::new(GatedPersistence::new());
        let persistence_trait: Arc<dyn SchedulerPersistence> = persistence.clone();
        mgr.set_persistence(persistence_trait).await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(policy_schedule("interrupted", ConcurrencyPolicy::Allow, 0))
            .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "interrupted").await;
        // The in-memory Pending reservation exists; the executor parks inside
        // record persistence before spawning or registering its dispatch task.
        persistence.wait_for_record().await;

        mgr.stop().await;

        let history = mgr.execution_history("interrupted").await;
        assert_eq!(
            history.len(),
            1,
            "exactly the parked reservation is recorded"
        );
        assert_eq!(
            history[0].status,
            ExecutionStatus::Cancelled,
            "an untracked Pending reservation must be reconciled by stop"
        );
        assert!(history[0]
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("stopped")));
    }

    #[tokio::test]
    async fn skip_if_running_rejects_overlapping_dispatch() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let dropped = Arc::new(AtomicBool::new(false));
        let dispatcher = Arc::new(BlockingDispatcher {
            calls: AtomicUsize::new(0),
            dropped,
        });
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(policy_schedule(
            "skip-running",
            ConcurrencyPolicy::SkipIfRunning,
            0,
        ))
        .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "skip-running").await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.calls.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first dispatch did not start");
        send_now(&mgr, "skip-running").await;
        wait_for_history(&mgr, "skip-running", 2).await;
        mgr.stop().await;

        let history = mgr.execution_history("skip-running").await;
        assert_eq!(
            history
                .iter()
                .filter(|execution| execution.status == ExecutionStatus::Skipped)
                .count(),
            1
        );
    }

    struct ReplaceDispatcher {
        calls: AtomicUsize,
        first_dropped: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for ReplaceDispatcher {
        async fn dispatch(
            &self,
            _workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                let _drop_signal = DropSignal(Arc::clone(&self.first_dropped));
                std::future::pending().await
            } else {
                Ok(DispatchResult {
                    success: true,
                    skipped: false,
                    summary: "replacement completed".to_owned(),
                    output: serde_json::Value::Null,
                    duration_ms: 1,
                    error: None,
                })
            }
        }
    }

    #[tokio::test]
    async fn cancel_previous_reconciles_displaced_execution() {
        let mgr = SchedulerManager::new(SchedulerConfig {
            max_concurrent_executions: 1,
            ..SchedulerConfig::default()
        });
        let first_dropped = Arc::new(AtomicBool::new(false));
        let dispatcher = Arc::new(ReplaceDispatcher {
            calls: AtomicUsize::new(0),
            first_dropped: Arc::clone(&first_dropped),
        });
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(policy_schedule(
            "replace",
            ConcurrencyPolicy::CancelPrevious,
            0,
        ))
        .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "replace").await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.calls.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first dispatch did not start");
        send_now(&mgr, "replace").await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.calls.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement did not run");
        wait_for_history(&mgr, "replace", 2).await;
        mgr.stop().await;

        assert!(first_dropped.load(Ordering::SeqCst));
        let history = mgr.execution_history("replace").await;
        assert!(history
            .iter()
            .any(|execution| execution.status == ExecutionStatus::Cancelled));
        assert!(history
            .iter()
            .any(|execution| execution.status == ExecutionStatus::Completed));
    }

    /// Captures the exact parameter values handed to the workflow.
    #[derive(Default)]
    struct ParamRecordingDispatcher {
        received: AsyncMutex<Vec<serde_json::Value>>,
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for ParamRecordingDispatcher {
        async fn dispatch(
            &self,
            _workflow_id: &str,
            parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            self.received.lock().await.push(parameter_values);
            Ok(DispatchResult {
                success: true,
                skipped: false,
                summary: "ok".to_owned(),
                output: serde_json::Value::Null,
                duration_ms: 1,
                error: None,
            })
        }
    }

    async fn wait_for_params(dispatcher: &ParamRecordingDispatcher, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if dispatcher.received.lock().await.len() >= expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dispatcher did not receive the expected parameters");
    }

    #[tokio::test]
    async fn dispatch_resolves_trigger_context_expressions() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(
            Schedule::new(
                "params",
                "params",
                TriggerConfig::Interval {
                    interval_secs: 3600,
                },
                "wf",
            )
            .with_params(serde_json::json!({
                "static": "keep",
                "fired_at": "{{ trigger.time }}",
                "kind": "{{ trigger.type }}",
                "seq": "{{ execution.sequence }}",
            })),
        )
        .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "params").await;
        wait_for_params(&dispatcher, 1).await;
        mgr.stop().await;

        let received = dispatcher.received.lock().await;
        let params = &received[0];
        assert_eq!(params["static"], "keep");
        assert_eq!(params["kind"], "interval");
        assert_eq!(params["seq"], 1, "first dispatched execution is sequence 1");
        assert!(
            params["fired_at"]
                .as_str()
                .is_some_and(|stamp| stamp.contains('T')),
            "trigger.time must resolve to an RFC3339 timestamp, got {params}"
        );
    }

    #[tokio::test]
    async fn unresolvable_expression_fails_dispatch_visibly() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(
            Schedule::new(
                "bad-params",
                "bad params",
                TriggerConfig::Interval {
                    interval_secs: 3600,
                },
                "wf",
            )
            .with_params(serde_json::json!({
                "x": "{{ bogus.expr }}",
            })),
        )
        .await;
        mgr.start(Duration::from_mins(1)).await;

        send_now(&mgr, "bad-params").await;
        wait_for_history(&mgr, "bad-params", 1).await;
        mgr.stop().await;

        assert!(
            dispatcher.received.lock().await.is_empty(),
            "a workflow must never receive raw template strings"
        );
        let history = mgr.execution_history("bad-params").await;
        assert_eq!(history[0].status, ExecutionStatus::Failed);
        assert!(
            history[0]
                .error_message
                .as_deref()
                .is_some_and(|message| message.contains("unknown parameter expression")),
            "resolution failure must be visible in history: {history:?}"
        );
        // The fire cursor advances so a permanently broken schedule cannot
        // re-fire and fail on every single tick.
        assert!(mgr
            .get_schedule("bad-params")
            .await
            .and_then(|schedule| schedule.last_fire)
            .is_some());
    }

    // -----------------------------------------------------------------------
    // Event trigger tests
    // -----------------------------------------------------------------------

    fn event_schedule(
        id: &str,
        event_type: &str,
        debounce: u64,
        filter: Option<crate::event::EventFilter>,
    ) -> Schedule {
        Schedule::new(
            id,
            id,
            TriggerConfig::Event {
                event_type: event_type.to_owned(),
                debounce_secs: debounce,
                filter,
            },
            "wf",
        )
    }

    fn incoming(
        event_type: &str,
        payload: serde_json::Value,
    ) -> crate::event_bridge::IncomingEvent {
        crate::event_bridge::IncomingEvent {
            cascade_depth: 0,
            event_type: event_type.to_owned(),
            payload: Some(payload),
            timestamp: Utc::now(),
            source_schedule_id: None,
        }
    }

    #[tokio::test]
    async fn event_schedule_fires_on_matching_event() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        let persistence = Arc::new(RecordingPersistence::default());
        let persistence_trait: Arc<dyn SchedulerPersistence> = persistence.clone();
        mgr.set_persistence(persistence_trait).await;
        mgr.register(
            event_schedule("on-crash", "crash.found", 0, None).with_params(serde_json::json!({
                "target": "{{ event.payload.target }}",
                "kind": "{{ trigger.type }}",
            })),
        )
        .await;
        mgr.start(Duration::from_mins(1)).await;

        let matched = mgr
            .emit_event(incoming(
                "crash.found",
                serde_json::json!({"target": "parse_input", "crashes": 2}),
            ))
            .await;
        assert_eq!(matched, vec!["on-crash".to_owned()]);

        wait_for_params(&dispatcher, 1).await;
        mgr.stop().await;

        // The event payload resolved the schedule's parameter expressions.
        let received = dispatcher.received.lock().await;
        assert_eq!(received[0]["target"], "parse_input");
        assert_eq!(received[0]["kind"], "event");
        drop(received);

        // last_fire and execution history are recorded exactly like a cron fire.
        assert!(mgr
            .get_schedule("on-crash")
            .await
            .and_then(|schedule| schedule.last_fire)
            .is_some());
        let history = mgr.execution_history("on-crash").await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, ExecutionStatus::Completed);
        assert!(persistence
            .last_fire_updates
            .lock()
            .await
            .iter()
            .any(|(id, _)| id == "on-crash"));
        assert!(persistence
            .recorded
            .lock()
            .await
            .iter()
            .any(|execution| execution.schedule_id == "on-crash"));
    }

    #[tokio::test]
    async fn non_matching_event_does_not_fire() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(event_schedule("on-crash", "crash.found", 0, None))
            .await;
        mgr.start(Duration::from_mins(1)).await;

        let matched = mgr
            .emit_event(incoming(
                "run.failed",
                serde_json::json!({"target": "parse_input"}),
            ))
            .await;
        assert!(matched.is_empty());

        // Give the executor loop a chance to (wrongly) dispatch, then assert.
        tokio::time::sleep(Duration::from_millis(50)).await;
        mgr.stop().await;
        assert!(dispatcher.received.lock().await.is_empty());
        assert!(mgr.execution_history("on-crash").await.is_empty());
        assert!(mgr
            .get_schedule("on-crash")
            .await
            .and_then(|schedule| schedule.last_fire)
            .is_none());
    }

    #[tokio::test]
    async fn event_filter_is_honored_end_to_end() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(
            event_schedule(
                "on-parse-crash",
                "crash.found",
                0,
                Some(crate::event::EventFilter {
                    field: "payload.target".to_owned(),
                    pattern: "parse_*".to_owned(),
                }),
            )
            .with_params(serde_json::json!({"target": "{{ event.payload.target }}"})),
        )
        .await;
        mgr.start(Duration::from_mins(1)).await;

        let filtered_out = mgr
            .emit_event(incoming(
                "crash.found",
                serde_json::json!({"target": "render_frame"}),
            ))
            .await;
        assert!(filtered_out.is_empty());

        let matched = mgr
            .emit_event(incoming(
                "crash.found",
                serde_json::json!({"target": "parse_input"}),
            ))
            .await;
        assert_eq!(matched, vec!["on-parse-crash".to_owned()]);

        wait_for_params(&dispatcher, 1).await;
        mgr.stop().await;
        let received = dispatcher.received.lock().await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0]["target"], "parse_input");
    }

    #[tokio::test]
    async fn event_debounce_collapses_rapid_events_through_the_manager() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(ParamRecordingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(event_schedule("debounced", "crash.found", 60, None))
            .await;
        mgr.start(Duration::from_mins(1)).await;

        let first = mgr
            .emit_event(incoming("crash.found", serde_json::json!({"target": "t"})))
            .await;
        let second = mgr
            .emit_event(incoming("crash.found", serde_json::json!({"target": "t"})))
            .await;
        assert_eq!(first.len(), 1);
        assert!(
            second.is_empty(),
            "second event inside the window debounces"
        );

        wait_for_params(&dispatcher, 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        mgr.stop().await;
        assert_eq!(dispatcher.received.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn events_emitted_before_start_are_dropped_safely() {
        let mgr = SchedulerManager::with_defaults();
        mgr.register(event_schedule("quiet", "crash.found", 0, None))
            .await;

        // No trigger channel exists until `start`; the event is dropped, not fired.
        let matched = mgr
            .emit_event(incoming("crash.found", serde_json::json!({"target": "t"})))
            .await;
        assert!(matched.is_empty());
        assert_eq!(mgr.execution_count().await, 0);
    }

    /// Persistence double that can park the executor inside
    /// [`SchedulerPersistence::record_execution`].
    struct GatedPersistence {
        /// Signals that `record_execution` was entered.
        record_started: Notify,
        /// One-shot release for the parked `record_execution` call.
        release: Notify,
        gate_open: AtomicBool,
    }

    impl GatedPersistence {
        fn new() -> Self {
            Self {
                record_started: Notify::new(),
                release: Notify::new(),
                gate_open: AtomicBool::new(false),
            }
        }

        /// Let every current and future `record_execution` call complete.
        fn open_gate(&self) {
            self.gate_open.store(true, Ordering::SeqCst);
            self.release.notify_one();
        }

        async fn wait_for_record(&self) {
            tokio::time::timeout(Duration::from_secs(2), self.record_started.notified())
                .await
                .expect("record persistence was not reached");
        }
    }

    #[async_trait::async_trait]
    impl SchedulerPersistence for GatedPersistence {
        async fn record_execution(
            &self,
            _execution: &ScheduleExecution,
        ) -> Result<(), PersistenceError> {
            if !self.gate_open.load(Ordering::SeqCst) {
                self.record_started.notify_one();
                self.release.notified().await;
            }
            Ok(())
        }

        async fn update_execution(
            &self,
            _execution: &ScheduleExecution,
        ) -> Result<(), PersistenceError> {
            Ok(())
        }

        async fn update_schedule(&self, _schedule: &Schedule) -> Result<(), PersistenceError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn emit_event_backpressure_does_not_block_store_reads_or_executor_progress() {
        // Regression: `emit_event` used to hold the schedule-store mutex
        // across every awaited trigger-queue send. With a full queue and two
        // event schedules matching one event, the executor's first action for
        // the next dequeued trigger (`load_unblocked_schedule`) needs that
        // same mutex: send #2 can never obtain a queue slot and the executor
        // can never obtain the store, so the scheduler deadlocks.
        let mgr = Arc::new(SchedulerManager::with_defaults());
        let persistence = Arc::new(GatedPersistence::new());
        let persistence_trait: Arc<dyn SchedulerPersistence> = persistence.clone();
        mgr.set_persistence(persistence_trait).await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(event_schedule("evt-a", "evt", 0, None)).await;
        mgr.register(event_schedule("evt-b", "evt", 0, None)).await;
        mgr.register(policy_schedule("stall", ConcurrencyPolicy::Allow, 0))
            .await;
        mgr.start(Duration::from_mins(1)).await;

        // Park the executor inside record persistence for the first trigger;
        // it holds no store lock there, so the queue fills deterministically.
        send_now(&mgr, "stall").await;
        persistence.wait_for_record().await;
        let queue_capacity = mgr.trigger_sender().unwrap().capacity();
        for _ in 0..queue_capacity {
            send_now(&mgr, "stall").await;
        }

        // Two schedules match, so `emit_event` sends twice into a full queue.
        let emit = mgr.emit_event(incoming("evt", serde_json::json!({"target": "t"})));
        tokio::pin!(emit);
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                std::future::Future::poll(emit.as_mut(), cx).is_pending()
            ))
            .await,
            "event publication must wait for the full queue"
        );
        tokio::time::timeout(Duration::from_secs(1), mgr.get_schedule("stall"))
            .await
            .expect("store reads must not block on event queue backpressure");

        // Resume the executor: it must keep dequeuing while the event sends
        // still wait for queue capacity.
        persistence.open_gate();

        let mut matched = tokio::time::timeout(Duration::from_secs(2), emit)
            .await
            .expect("emit_event must not deadlock against the executor's store reads");
        matched.sort();
        assert_eq!(matched, vec!["evt-a".to_owned(), "evt-b".to_owned()]);

        // The event triggers sit behind a full queue; their history rows only
        // appear once the executor has drained it.
        wait_for_history(&mgr, "evt-a", 1).await;
        wait_for_history(&mgr, "evt-b", 1).await;
        mgr.stop().await;
    }

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct BlockingDispatcher {
        calls: AtomicUsize,
        dropped: Arc<AtomicBool>,
    }

    impl BlockingDispatcher {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                dropped: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    #[async_trait::async_trait]
    impl WorkflowDispatcher for BlockingDispatcher {
        async fn dispatch(
            &self,
            _workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            let _drop_signal = DropSignal(Arc::clone(&self.dropped));
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn stop_cancels_tracked_dispatches_and_reconciles_running_records() {
        let mgr = SchedulerManager::with_defaults();
        let dropped = Arc::new(AtomicBool::new(false));
        let dispatcher = Arc::new(BlockingDispatcher {
            calls: AtomicUsize::new(0),
            dropped: Arc::clone(&dropped),
        });
        let dispatcher_trait: Arc<dyn WorkflowDispatcher> = dispatcher.clone();
        mgr.set_dispatcher(dispatcher_trait).await;
        mgr.register(Schedule::new(
            "blocking",
            "blocking",
            TriggerConfig::Interval { interval_secs: 60 },
            "wf",
        ))
        .await;

        // Restored work needs an armed scheduler; this test intends it to run.
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while dispatcher.calls.load(Ordering::SeqCst) < 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dispatch did not start");
        mgr.stop().await;

        assert!(
            dropped.load(Ordering::SeqCst),
            "dispatch future outlived stop"
        );
        let history = mgr.execution_history("blocking").await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, ExecutionStatus::Cancelled);
        assert!(history[0]
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("stopped")));
    }

    #[tokio::test]
    async fn interrupted_backfill_is_recovered_after_restart() {
        let mgr = SchedulerManager::with_defaults();
        let blocking = Arc::new(BlockingDispatcher::new());
        mgr.set_dispatcher(blocking.clone()).await;
        let mut schedule = Schedule::new(
            "interrupted-backfill",
            "interrupted-backfill",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "interrupted-backfill",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Backfill),
            ..SchedulePolicies::default()
        });
        schedule.last_fire = Some(Utc::now() - TimeDelta::hours(3));
        mgr.register(schedule).await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while blocking.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("backfill did not start");
        let saved =
            serde_json::to_vec(&mgr.get_schedule("interrupted-backfill").await.unwrap()).unwrap();
        mgr.stop().await;

        let mgr = SchedulerManager::with_defaults();
        mgr.register(serde_json::from_slice(&saved).unwrap()).await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        mgr.start(Duration::from_mins(1)).await;
        mgr.arm();
        let recovered = tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.total_calls().await < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        mgr.stop().await;
        assert!(recovered.is_ok(), "interrupted backfill was lost");
    }

    #[tokio::test]
    async fn restarting_manager_requires_a_fresh_arm() {
        let mgr = SchedulerManager::with_defaults();
        let blocking = Arc::new(BlockingDispatcher::new());
        mgr.set_dispatcher(blocking.clone()).await;
        mgr.register(missed_schedule("fresh-arm", 2, MissedPolicy::Backfill))
            .await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while blocking.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recovery did not start");
        mgr.stop().await;
        let dispatcher = Arc::new(CountingDispatcher::default());
        mgr.set_dispatcher(dispatcher.clone()).await;
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let calls_before_arming = dispatcher.total_calls().await;
        mgr.arm();
        let resumed = tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.total_calls().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        mgr.stop().await;
        assert_eq!(
            calls_before_arming, 0,
            "restart reused previous authorization"
        );
        assert!(resumed.is_ok());
    }

    #[tokio::test]
    async fn backfill_does_not_advance_the_cursor_to_dispatch_time() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(BlockingDispatcher::new());
        mgr.set_dispatcher(dispatcher.clone()).await;
        let now = Utc::now();
        let mut schedule = Schedule::new(
            "old-backfill",
            "old-backfill",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "wf",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Backfill),
            ..SchedulePolicies::default()
        });
        schedule.last_fire = Some(now - TimeDelta::minutes(210));
        mgr.register(schedule).await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.calls.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("backfill did not start");
        let cursor = mgr
            .get_schedule("old-backfill")
            .await
            .unwrap()
            .last_fire
            .unwrap();
        mgr.stop().await;
        assert!(
            cursor <= now - TimeDelta::minutes(30),
            "historical recovery advanced to {cursor}"
        );
    }

    struct CancelledRecoveryDispatcher(AtomicUsize);

    #[async_trait::async_trait]
    impl WorkflowDispatcher for CancelledRecoveryDispatcher {
        async fn dispatch(
            &self,
            _: &str,
            _: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                std::future::pending().await
            } else {
                Ok(DispatchResult {
                    success: true,
                    skipped: false,
                    summary: "completed".to_owned(),
                    output: serde_json::Value::Null,
                    duration_ms: 0,
                    error: None,
                })
            }
        }
    }

    #[tokio::test]
    async fn cancelled_backfill_keeps_its_recovery_checkpoint() {
        let mgr = SchedulerManager::with_defaults();
        let dispatcher = Arc::new(CancelledRecoveryDispatcher(AtomicUsize::new(0)));
        mgr.set_dispatcher(dispatcher.clone()).await;
        let mut schedule = Schedule::new(
            "cancelled-backfill",
            "cancelled-backfill",
            TriggerConfig::Interval {
                interval_secs: 3600,
            },
            "wf",
        )
        .with_policies(SchedulePolicies {
            missed_policy: Some(MissedPolicy::Backfill),
            concurrency_policy: Some(ConcurrencyPolicy::CancelPrevious),
            max_executions_per_hour: 0,
        });
        schedule.last_fire = Some(Utc::now() - TimeDelta::hours(1));
        mgr.register(schedule).await;
        mgr.arm();
        mgr.start(Duration::from_mins(1)).await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.0.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("backfill did not start");
        send_now(&mgr, "cancelled-backfill").await;
        tokio::time::timeout(Duration::from_secs(2), async {
            while !mgr
                .execution_history("cancelled-backfill")
                .await
                .iter()
                .any(|execution| execution.status == ExecutionStatus::Cancelled)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recovery was not cancelled");
        tokio::time::sleep(Duration::from_millis(100)).await;
        let checkpoint = mgr
            .get_schedule("cancelled-backfill")
            .await
            .unwrap()
            .recovery_pending;
        mgr.stop().await;
        assert!(
            checkpoint.is_some(),
            "cancelled recovery must remain pending"
        );
        assert_eq!(
            dispatcher.0.load(Ordering::SeqCst),
            1,
            "blocked recovery must not launch a replacement"
        );
    }
}

#[cfg(test)]
mod arming_tests {
    use super::tests::interval_schedule;
    use super::SchedulerManager;
    use crate::arming::ArmSignal;
    use crate::recovery::{RecoveryBatch, RecoveryPlan};
    use chrono::Utc;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tokio::sync::Notify;

    fn plan_with_one_batch() -> RecoveryPlan {
        let schedule = interval_schedule("missed");
        let mut plan = RecoveryPlan::default();
        plan.batches
            .push(RecoveryBatch::single(&schedule, Utc::now()));
        plan
    }

    #[tokio::test]
    async fn restored_work_is_held_until_the_scheduler_is_armed() {
        let (tx, mut rx) = mpsc::channel(16);
        let arm = ArmSignal::default();
        let shutdown = Arc::new(Notify::new());
        let handle = tokio::spawn(SchedulerManager::submit_recovery(
            plan_with_one_batch(),
            tx,
            Arc::clone(&shutdown),
            arm.clone(),
        ));

        // Restarting the process is not consent to resume: nothing fires.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "a missed occurrence fired without the scheduler being armed"
        );

        arm.arm();

        let trigger = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("arming did not release the held recovery")
            .expect("a trigger");
        assert!(trigger.is_recovery);
        handle.await.expect("producer finished");
    }

    #[tokio::test]
    async fn an_already_armed_scheduler_submits_without_waiting() {
        let (tx, mut rx) = mpsc::channel(16);
        let arm = ArmSignal::default();
        arm.arm();
        let shutdown = Arc::new(Notify::new());
        tokio::spawn(SchedulerManager::submit_recovery(
            plan_with_one_batch(),
            tx,
            shutdown,
            arm,
        ));

        assert!(
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("armed recovery did not submit")
                .is_some(),
            "an armed scheduler must submit its restored work"
        );
    }

    #[tokio::test]
    async fn disarming_pauses_recovery_waiting_for_queue_space() {
        let (tx, mut rx) = mpsc::channel(1);
        let observer = tx.clone();
        let arm = ArmSignal::default();
        arm.arm();
        let mut plan = plan_with_one_batch();
        plan.batches.extend(plan_with_one_batch().batches);
        let handle = tokio::spawn(SchedulerManager::submit_recovery(
            plan,
            tx,
            Arc::new(Notify::new()),
            arm.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(2), async {
            while observer.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first recovery trigger was not queued");
        arm.disarm();
        rx.recv().await.expect("first recovery trigger");
        assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());
        arm.arm();
        assert!(tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("rearming did not resume recovery")
            .is_some());
        handle.await.expect("producer finished");
    }

    #[tokio::test]
    async fn shutting_down_while_disarmed_fires_nothing() {
        let (tx, mut rx) = mpsc::channel(16);
        let arm = ArmSignal::default();
        let shutdown = Arc::new(Notify::new());
        let handle = tokio::spawn(SchedulerManager::submit_recovery(
            plan_with_one_batch(),
            tx,
            Arc::clone(&shutdown),
            arm,
        ));

        // Notify repeatedly: the producer may not have reached its wait yet.
        let notifier = tokio::spawn(async move {
            for _ in 0..100 {
                shutdown.notify_waiters();
                tokio::task::yield_now().await;
            }
        });
        handle.await.expect("producer exits on shutdown");
        notifier.abort();

        assert!(
            rx.try_recv().is_err(),
            "work was submitted during shutdown of a disarmed scheduler"
        );
    }

    #[tokio::test]
    async fn a_fresh_manager_is_disarmed() {
        let manager = SchedulerManager::new(crate::config::SchedulerConfig::default());
        assert!(!manager.is_armed());
        manager.arm();
        assert!(manager.is_armed());
        manager.disarm();
        assert!(!manager.is_armed());
    }
}
