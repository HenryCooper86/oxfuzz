//! `SchedulerManager`: top-level entry point that owns the async trigger loop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use chrono::Utc;
use tokio::sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::{ConcurrencyPolicy, MissedPolicy, SchedulerConfig};
use crate::dispatcher::WorkflowDispatcher;
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
}

struct TrackedDispatch {
    execution_id: String,
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
            execution_store: Arc::new(Mutex::new(ExecutionStore::new())),
            config,
            runtime: StdMutex::new(RuntimeState::new()),
            dispatcher: Arc::new(Mutex::new(None)),
            persistence: Arc::new(Mutex::new(None)),
            execution_slots,
            serial_locks: Arc::new(Mutex::new(HashMap::new())),
            dispatch_tasks: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    /// Create a scheduler manager with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SchedulerConfig::default())
    }

    /// Register a schedule.
    pub async fn register(&self, schedule: Schedule) {
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
                    let Some(next) = fired_at.checked_add_signed(batch.interval) else {
                        warn!(schedule_id = %batch.schedule_id, "Recovery timestamp overflow");
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
                        let permit = tokio::select! {
                            () = shutdown.notified() => break,
                            result = Arc::clone(&execution_slots).acquire_owned() => {
                                match result {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                }
                            }
                        };
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
                            permit,
                        ).await;
                    } else {
                        info!("Trigger queue closed, executor stopping");
                        break;
                    }
                }
            }
        }
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
        execution_permit: OwnedSemaphorePermit,
    ) {
        let mut store_guard = store.lock().await;
        let schedule = if let Some(s) = store_guard.get(&fired.schedule_id) {
            s.clone()
        } else {
            warn!(schedule_id = %fired.schedule_id, "Schedule not found, skipping");
            return;
        };

        if let Some(disp) = dispatcher {
            // Real dispatch path: create a Running record, spawn real execution.
            let now = chrono::Utc::now();
            let execution_id = format!("exec-{}-{}", schedule.id, uuid::Uuid::new_v4());

            let request_summary = serde_json::json!({
                "schedule_id": schedule.id,
                "schedule_name": schedule.name,
                "workflow_id": schedule.workflow_id,
                "trigger": serde_json::to_value(&schedule.trigger).unwrap_or_default(),
                "parameter_values": schedule.parameter_values,
                "trigger_time": fired.fired_at.to_rfc3339(),
            });

            let running_record = ScheduleExecution {
                execution_id: execution_id.clone(),
                schedule_id: schedule.id.clone(),
                triggered_at: fired.fired_at,
                started_at: Some(now),
                completed_at: None,
                status: ExecutionStatus::Running,
                workflow_execution_id: None,
                request_summary,
                response_summary: serde_json::json!({}),
                error_message: None,
            };

            {
                let mut exec_store_guard = execution_store.lock().await;
                exec_store_guard.record(running_record.clone());
            }

            // Advance monotonically. Recovery pre-advances to the latest due
            // occurrence, so individual historical backfill items must not move
            // the durable cursor backwards while they drain.
            store_guard.update_last_fire(&schedule.id, fired.fired_at.max(now));
            let updated_schedule = store_guard.get(&schedule.id).cloned();
            drop(store_guard);
            if let Some(updated_schedule) = &updated_schedule {
                Self::persist_schedule(persistence.as_ref(), updated_schedule).await;
            }
            Self::persist_record(persistence.as_ref(), &running_record).await;

            // Spawn real execution without blocking the trigger loop.
            let workflow_id = schedule.workflow_id.clone();
            let parameter_values = schedule.parameter_values.clone();
            let exec_store_clone = Arc::clone(execution_store);
            let exec_id_clone = execution_id.clone();
            let persistence_clone = persistence.clone();
            let serialize = schedule.policies.missed_policy == MissedPolicy::Backfill
                || schedule.policies.concurrency_policy == ConcurrencyPolicy::Queue;
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
                let _execution_permit = execution_permit;
                let _serial_guard = match serial_lock {
                    Some(lock) => Some(lock.lock_owned().await),
                    None => None,
                };
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
                handle,
            });
        } else {
            // Placeholder path: instant completion via ScheduleExecutor.
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
            drop(execution_permit);
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
                    if record.status == ExecutionStatus::Running {
                        record.status = ExecutionStatus::Failed;
                        record.completed_at = Some(Utc::now());
                        record.error_message =
                            Some("scheduler stopped before completion".to_owned());
                        record.response_summary = serde_json::json!({
                            "status": "failed",
                            "error": "scheduler stopped before completion",
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
                    missed_policy: policy,
                    concurrency_policy: ConcurrencyPolicy::default(),
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

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct BlockingDispatcher {
        started: Notify,
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
            self.started.notify_waiters();
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn stop_cancels_tracked_dispatches_and_reconciles_running_records() {
        let mgr = SchedulerManager::with_defaults();
        let dropped = Arc::new(AtomicBool::new(false));
        let dispatcher = Arc::new(BlockingDispatcher {
            started: Notify::new(),
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
        tokio::time::timeout(Duration::from_secs(1), dispatcher.started.notified())
            .await
            .expect("dispatch did not start");
        mgr.stop().await;

        assert!(
            dropped.load(Ordering::SeqCst),
            "dispatch future outlived stop"
        );
        let history = mgr.execution_history("blocking").await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, ExecutionStatus::Failed);
        assert!(history[0]
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("stopped")));
    }
}
