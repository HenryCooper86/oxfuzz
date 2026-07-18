//! `SchedulerManager`: top-level entry point that owns the async trigger loop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use chrono::Utc;
use tokio::sync::{Mutex, Notify, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::{ConcurrencyPolicy, MissedPolicy, SchedulerConfig};
use crate::dispatcher::WorkflowDispatcher;
use crate::event_bridge::{EventBridge, IncomingEvent};
use crate::executor::{ExecutionStatus, ExecutionStore, ScheduleExecution, ScheduleExecutor};
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
}

struct TrackedDispatch {
    execution_id: String,
    schedule_id: String,
    handle: JoinHandle<()>,
}

type SerialLocks = Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>;
type DispatchTasks = Arc<StdMutex<Vec<TrackedDispatch>>>;

/// Runtime-owned scheduler state that changes when the trigger loop starts/stops.
struct RuntimeState {
    recovery_handle: Option<JoinHandle<()>>,
    eval_handle: Option<JoinHandle<()>>,
    exec_handle: Option<JoinHandle<()>>,
    shutdown: Arc<Notify>,
    trigger_tx: Option<TriggerSender>,
    starting: bool,
}

impl RuntimeState {
    fn new() -> Self {
        Self {
            recovery_handle: None,
            eval_handle: None,
            exec_handle: None,
            shutdown: Arc::new(Notify::new()),
            trigger_tx: None,
            starting: false,
        }
    }
}

/// The top-level scheduler service.
///
/// Owns the `ScheduleStore`, `ScheduleExecutor`, and runs an async trigger loop
/// that evaluates all active schedules on each tick.
pub struct SchedulerManager {
    store: Arc<Mutex<ScheduleStore>>,
    executor: Arc<Mutex<ScheduleExecutor>>,
    /// Execution history store.
    execution_store: Arc<Mutex<ExecutionStore>>,
    config: SchedulerConfig,
    /// Runtime lifecycle state for the trigger and executor loops.
    runtime: StdMutex<RuntimeState>,
    /// Optional workflow dispatcher injected after construction.
    ///
    /// When `Some`, fired triggers are dispatched through the real orchestrator
    /// instead of the placeholder `ScheduleExecutor`. Injected via
    /// `set_dispatcher()` (same pattern as `AgentRunner` in `ServiceContainer`).
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
    /// Every dispatched workflow task is retained until reaped or stopped.
    dispatch_tasks: DispatchTasks,
}

impl SchedulerManager {
    /// Create a new scheduler manager with the given configuration.
    pub fn new(config: SchedulerConfig) -> Self {
        let execution_slots = Arc::new(Semaphore::new(config.max_concurrent_executions.max(1)));
        Self {
            store: Arc::new(Mutex::new(ScheduleStore::new())),
            executor: Arc::new(Mutex::new(ScheduleExecutor::new())),
            execution_store: Arc::new(Mutex::new(ExecutionStore::with_retention(
                config.history_retention_limit,
            ))),
            config,
            runtime: StdMutex::new(RuntimeState::new()),
            dispatcher: Arc::new(Mutex::new(None)),
            persistence: Arc::new(Mutex::new(None)),
            execution_slots,
            event_bridge: Mutex::new(EventBridge::new()),
            serial_locks: Arc::new(Mutex::new(HashMap::new())),
            dispatch_tasks: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    /// Create a scheduler manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SchedulerConfig::default())
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
            Self::persist_schedule(persistence.as_ref(), schedule).await;
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
            Self::persist_schedule(persistence.as_ref(), schedule).await;
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

    /// Get a single execution record by ID.
    pub async fn get_execution(&self, execution_id: &str) -> Option<ScheduleExecution> {
        let exec_store = self.execution_store.lock().await;
        exec_store.get(execution_id).cloned()
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
    /// The event is matched synchronously against every enabled event-driven
    /// schedule (event type, optional payload filter, debounce); matching
    /// schedules are fired through the same trigger queue and executor loop a
    /// cron fire uses, so `last_fire` and execution history behave identically.
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
        let store = self.store.lock().await;
        let mut bridge = self.event_bridge.lock().await;
        bridge.process_event(&event, &store, &tx).await
    }

    /// Inject the workflow dispatcher used to run real executions.
    ///
    /// Called once after the service container is fully initialised (same
    /// pattern as `ServiceContainer::init_agent_runner`). Until this is
    /// called, fired triggers fall back to the placeholder executor.
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
            runtime.trigger_tx = Some(tx.clone());
            Arc::clone(&runtime.shutdown)
        };

        info!(
            "Starting scheduler with tick interval {:?}, max_concurrent={}",
            tick_interval, self.config.max_concurrent_executions
        );

        // Plan recovery and move every affected cursor before the normal
        // evaluator starts. Skip therefore cannot fire on the immediate first
        // tick, while backfill remains a compact, lazily submitted batch.
        let (recovery_plan, advanced_schedules) = {
            let mut store_guard = self.store.lock().await;
            let recovery_now = Utc::now();
            let plan = recovery::recover_missed(&store_guard, recovery_now);
            let mut advanced = Vec::with_capacity(plan.advances.len());
            for advance in &plan.advances {
                store_guard.update_last_fire(&advance.schedule_id, advance.last_fire);
                if let Some(schedule) = store_guard.get(&advance.schedule_id) {
                    advanced.push(schedule.clone());
                }
            }
            (plan, advanced)
        };

        let persistence_snapshot = self.persistence.lock().await.clone();
        for schedule in &advanced_schedules {
            Self::persist_schedule(persistence_snapshot.as_ref(), schedule).await;
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
        let exec_tasks = Arc::clone(&self.dispatch_tasks);
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
                exec_tasks,
                exec_shutdown,
            )
            .await;
        });

        let recovery_shutdown = shutdown.clone();
        let recovery_tx = tx.clone();
        let recovery_handle = tokio::spawn(async move {
            Self::submit_recovery(recovery_plan, recovery_tx, recovery_shutdown).await;
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
                        let schedules: Vec<Schedule> = store_guard.list_enabled()
                            .into_iter()
                            .cloned()
                            .collect();
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
        runtime.eval_handle = Some(eval_handle);
        runtime.exec_handle = Some(exec_handle);
        runtime.starting = false;
    }

    async fn submit_recovery(
        plan: recovery::RecoveryPlan,
        tx: TriggerSender,
        shutdown: Arc<Notify>,
    ) {
        for batch in plan.batches {
            let mut fired_at = batch.first_fire;
            let mut remaining = batch.count;
            while remaining > 0 {
                let trigger = recovery::trigger_at(&batch, fired_at);
                let sent = tokio::select! {
                    () = shutdown.notified() => false,
                    result = tx.send(trigger) => result.is_ok(),
                };
                if !sent {
                    return;
                }
                remaining -= 1;
                if remaining > 0 {
                    let Some(next) = batch.next_fire(fired_at) else {
                        warn!(schedule_id = %batch.schedule_id, "Cannot advance recovery schedule");
                        return;
                    };
                    fired_at = next;
                }
            }
        }
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
        dispatch_tasks: DispatchTasks,
        shutdown: Arc<Notify>,
    ) {
        loop {
            tokio::select! {
                () = shutdown.notified() => {
                    info!("Executor loop shutting down");
                    break;
                }
                trigger = rx.recv() => {
                    if let Some(fired) = trigger {
                        // Re-read the dispatcher on every trigger so that
                        // late injection (after loop start) takes effect.
                        let current_dispatcher = dispatcher.lock().await.clone();
                        Self::handle_fired_trigger(
                            fired,
                            &store,
                            &executor,
                            &execution_store,
                            current_dispatcher,
                            persistence.lock().await.clone(),
                            &serial_locks,
                            &dispatch_tasks,
                            &execution_slots,
                        ).await;
                    } else {
                        info!("Trigger queue closed, executor stopping");
                        break;
                    }
                }
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
                executions.update(&task.execution_id, |record| {
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
                });
                executions.get(&task.execution_id).cloned()
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
            schedules.update_last_fire(&schedule.id, fired.fired_at.max(now));
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
            schedules.update_last_fire(&schedule.id, fired.fired_at.max(now));
            schedules.get(&schedule.id).cloned()
        };
        if let Some(updated_schedule) = &updated_schedule {
            Self::persist_schedule(persistence, updated_schedule).await;
        }
        Self::persist_record(persistence, &record).await;
    }

    /// Handle a single fired trigger.
    ///
    /// When a `WorkflowDispatcher` is available, creates a `Running` execution
    /// record and spawns an async task to run the real workflow. Updates the
    /// record to `Completed` or `Failed` on completion.
    ///
    /// Falls back to the placeholder `ScheduleExecutor` (instant `Completed`)
    /// when no dispatcher has been injected.
    async fn handle_fired_trigger(
        fired: FiredTrigger,
        store: &Arc<Mutex<ScheduleStore>>,
        executor: &Arc<Mutex<ScheduleExecutor>>,
        execution_store: &Arc<Mutex<ExecutionStore>>,
        dispatcher: Option<Arc<dyn WorkflowDispatcher>>,
        persistence: Option<Arc<dyn SchedulerPersistence>>,
        serial_locks: &SerialLocks,
        dispatch_tasks: &DispatchTasks,
        execution_slots: &Arc<Semaphore>,
    ) {
        let schedule = {
            let store_guard = store.lock().await;
            let Some(schedule) = store_guard.get(&fired.schedule_id).cloned() else {
                warn!(schedule_id = %fired.schedule_id, "Schedule not found, skipping");
                return;
            };
            schedule
        };

        let now = chrono::Utc::now();
        let max_per_hour = schedule.policies.max_executions_per_hour;
        if max_per_hour > 0 {
            let since = now - chrono::Duration::hours(1);
            let (live_started, pending) = {
                let executions = execution_store.lock().await;
                (
                    executions.started_since(&schedule.id, since),
                    executions.pending_since(&schedule.id, since),
                )
            };
            let persisted_started = if let Some(adapter) = persistence.as_ref() {
                match adapter.executions_started_since(&schedule.id, since).await {
                    Ok(count) => usize::try_from(count).unwrap_or(usize::MAX),
                    Err(error) => {
                        warn!(
                            schedule_id = %schedule.id,
                            %error,
                            "Cannot verify hourly schedule limit; skipping trigger"
                        );
                        Self::record_policy_skip(
                            &fired,
                            &schedule,
                            "hourly execution history is unavailable".to_owned(),
                            store,
                            execution_store,
                            persistence.as_ref(),
                        )
                        .await;
                        return;
                    }
                }
            } else {
                0
            };
            let admitted = live_started.max(persisted_started).saturating_add(pending);
            if admitted >= usize::try_from(max_per_hour).unwrap_or(usize::MAX) {
                Self::record_policy_skip(
                    &fired,
                    &schedule,
                    format!("hourly execution limit reached ({max_per_hour})"),
                    store,
                    execution_store,
                    persistence.as_ref(),
                )
                .await;
                return;
            }
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

            let request_summary = serde_json::json!({
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "workflow_id": schedule.workflow_id,
                "trigger": serde_json::to_value(&schedule.trigger).unwrap_or_default(),
                "parameter_values": parameter_values,
                "execution_sequence": sequence,
                "trigger_time": fired.fired_at.to_rfc3339(),
            });

            let pending_record = ScheduleExecution {
                execution_id: execution_id.clone(),
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

            {
                let mut exec_store_guard = execution_store.lock().await;
                exec_store_guard.record(pending_record.clone());
            }

            // Advance monotonically. Recovery pre-advances to the latest due
            // occurrence, so individual historical backfill items must not move
            // the durable cursor backwards while they drain.
            let updated_schedule = {
                let mut store_guard = store.lock().await;
                store_guard.update_last_fire(&schedule.id, fired.fired_at.max(now));
                store_guard.get(&schedule.id).cloned()
            };
            if let Some(updated_schedule) = &updated_schedule {
                Self::persist_schedule(persistence.as_ref(), updated_schedule).await;
            }
            Self::persist_record(persistence.as_ref(), &pending_record).await;

            // Spawn real execution without blocking the trigger loop.
            let workflow_id = schedule.workflow_id.clone();
            let exec_store_clone = Arc::clone(execution_store);
            let exec_id_clone = execution_id.clone();
            let persistence_clone = persistence.clone();
            let execution_slots_clone = Arc::clone(execution_slots);
            let serialize = concurrency_policy == ConcurrencyPolicy::Queue;
            let serial_lock = if serialize {
                let mut locks = serial_locks.lock().await;
                Some(
                    locks
                        .entry(schedule.id.clone())
                        .or_insert_with(|| Arc::new(Mutex::new(())))
                        .clone(),
                )
            } else {
                None
            };

            let handle = tokio::spawn(async move {
                let _serial_guard = match serial_lock {
                    Some(lock) => Some(lock.lock_owned().await),
                    None => None,
                };
                let _execution_permit = execution_slots_clone
                    .acquire_owned()
                    .await
                    .expect("scheduler execution semaphore is never closed");
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
                let dispatch_start = std::time::Instant::now();
                match disp.dispatch(&workflow_id, parameter_values).await {
                    Ok(result) => {
                        let duration_ms =
                            u64::try_from(dispatch_start.elapsed().as_millis()).unwrap_or(0);
                        let mut store = exec_store_clone.lock().await;
                        store.update(&exec_id_clone, |rec| {
                            rec.status = if result.success {
                                ExecutionStatus::Completed
                            } else {
                                ExecutionStatus::Failed
                            };
                            rec.completed_at = Some(chrono::Utc::now());
                            rec.response_summary = serde_json::json!({
                                "status": if result.success { "completed" } else { "failed" },
                                "summary": result.summary,
                                "output": result.output,
                                "duration_ms": duration_ms,
                            });
                            if !result.success {
                                rec.error_message = result.error;
                            }
                        });
                        let updated = store.get(&exec_id_clone).cloned();
                        drop(store);
                        if let Some(updated) = updated {
                            Self::persist_update(persistence_clone.as_ref(), &updated).await;
                        }
                        debug!(execution_id = %exec_id_clone, "Dispatched workflow completed");
                    }
                    Err(e) => {
                        let mut store = exec_store_clone.lock().await;
                        store.update(&exec_id_clone, |rec| {
                            rec.status = ExecutionStatus::Failed;
                            rec.completed_at = Some(chrono::Utc::now());
                            rec.response_summary = serde_json::json!({
                                "status": "failed",
                                "error": e.to_string(),
                            });
                            rec.error_message = Some(e.to_string());
                        });
                        let updated = store.get(&exec_id_clone).cloned();
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
                handle,
            });
        } else {
            // Placeholder path: instant completion via ScheduleExecutor.
            let mut store_guard = store.lock().await;
            let mut exec_guard = executor.lock().await;
            let mut exec_store_guard = execution_store.lock().await;
            let execution_id =
                exec_guard.trigger_execution(&schedule, &mut store_guard, &mut exec_store_guard);
            let persisted = exec_store_guard.get(&execution_id).cloned();
            let updated_schedule = store_guard.get(&schedule.id).cloned();
            debug!(execution_id = %execution_id, "Placeholder execution triggered");
            drop(exec_store_guard);
            drop(exec_guard);
            drop(store_guard);
            if let Some(updated_schedule) = &updated_schedule {
                Self::persist_schedule(persistence.as_ref(), updated_schedule).await;
            }
            if let Some(persisted) = persisted {
                Self::persist_record(persistence.as_ref(), &persisted).await;
            }
        }
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

    /// Stop the scheduler gracefully.
    ///
    /// # Panics
    ///
    /// Panics if the internal scheduler runtime mutex is poisoned.
    pub async fn stop(&self) {
        let (recovery_handle, eval_handle, exec_handle, shutdown) = {
            let mut runtime = self
                .runtime
                .lock()
                .expect("scheduler runtime lock poisoned");
            if runtime.recovery_handle.is_none()
                && runtime.eval_handle.is_none()
                && runtime.exec_handle.is_none()
                && !runtime.starting
            {
                return;
            }

            let shutdown = Arc::clone(&runtime.shutdown);
            let recovery_handle = runtime.recovery_handle.take();
            let eval_handle = runtime.eval_handle.take();
            let exec_handle = runtime.exec_handle.take();
            runtime.trigger_tx = None;
            runtime.starting = false;
            runtime.shutdown = Arc::new(Notify::new());
            (recovery_handle, eval_handle, exec_handle, shutdown)
        };

        info!("Stopping scheduler");

        // Wake producers and loops, then abort them so no new dispatch task can
        // be registered while the tracked set is drained below.
        shutdown.notify_waiters();

        if let Some(handle) = recovery_handle {
            handle.abort();
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

        let tracked: Vec<TrackedDispatch> = {
            let mut tasks = self
                .dispatch_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tasks.drain(..).collect()
        };
        let mut cancelled = Vec::new();
        for task in tracked {
            let was_running = !task.handle.is_finished();
            if was_running {
                task.handle.abort();
                cancelled.push(task.execution_id.clone());
            }
            let _ = task.handle.await;
        }

        let mut reconciled = Vec::new();
        if !cancelled.is_empty() {
            let mut executions = self.execution_store.lock().await;
            for execution_id in cancelled {
                executions.update(&execution_id, |record| {
                    if matches!(
                        record.status,
                        ExecutionStatus::Pending | ExecutionStatus::Running
                    ) {
                        record.status = ExecutionStatus::Cancelled;
                        record.completed_at = Some(Utc::now());
                        record.error_message =
                            Some("scheduler stopped before completion".to_owned());
                        record.response_summary = serde_json::json!({
                            "status": "cancelled",
                            "reason": "scheduler stopped before completion",
                        });
                    }
                });
                if let Some(record) = executions.get(&execution_id) {
                    reconciled.push(record.clone());
                }
            }
        }
        let persistence = self.persistence.lock().await.clone();
        for record in &reconciled {
            Self::persist_update(persistence.as_ref(), record).await;
        }

        info!("Scheduler stopped");
    }

    /// Whether the scheduler is currently running.
    ///
    /// # Panics
    ///
    /// Panics if the internal scheduler runtime mutex is poisoned.
    pub fn is_running(&self) -> bool {
        self.runtime
            .lock()
            .expect("scheduler runtime lock poisoned")
            .eval_handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
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
    use crate::config::{ConcurrencyPolicy, MissedPolicy};
    use crate::dispatcher::{DispatchError, DispatchResult};
    use crate::store::{SchedulePolicies, TriggerConfig};
    use chrono::{DateTime, TimeDelta, Utc};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::{Mutex as AsyncMutex, Notify};

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

    #[tokio::test]
    async fn test_manager_executes_interval_schedule() {
        let mgr = SchedulerManager::with_defaults();

        // Register a schedule with a very short interval.
        let schedule = Schedule::new(
            "fast-interval",
            "Fast Interval",
            TriggerConfig::Interval { interval_secs: 0 }, // fires immediately
            "wf",
        );
        mgr.register(schedule).await;

        // Start with a short tick.
        mgr.start(Duration::from_millis(20)).await;

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
    impl WorkflowDispatcher for AlwaysOkDispatcher {
        async fn dispatch(
            &self,
            workflow_id: &str,
            _parameter_values: serde_json::Value,
        ) -> Result<DispatchResult, DispatchError> {
            Ok(DispatchResult {
                success: true,
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
            TriggerConfig::Interval { interval_secs: 0 },
            "wf",
        ))
        .await;

        mgr.start(Duration::from_millis(20)).await;
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
            event_type: event_type.to_owned(),
            payload: Some(payload),
            timestamp: Utc::now(),
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
}
