//! Scheduled fuzz campaigns, backed by `hf-scheduler`.
//!
//! A campaign is a persisted [`Schedule`] (cron / interval / one-time trigger)
//! whose `parameter_values` carry [`CampaignParams`] (project/target/engine/
//! duration). [`CampaignScheduler`] installs a dispatcher that runs the campaign
//! headlessly through the [`ServiceContainer`] when a schedule fires, ticks in
//! the background, and persists schedules to JSON so they survive restarts.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
    NewScheduleOccurrence, ScheduleOccurrenceAcknowledgement, ScheduleOccurrenceInspection,
    ScheduleOccurrenceRecord, ScheduleOccurrenceReservation, ScheduleOccurrenceTransition,
    ScheduleOccurrenceTransitionResult, StorageError, Store,
};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use crate::campaign_state::{
    atomic_write_json, read_json_file, CampaignRuntimeState, CampaignStateStore, ConcurrencyGate,
    StateFileError,
};
use crate::container::{PersistenceAvailability, SchedulableTarget, ServiceContainer};
use crate::schedule_retirement::{
    acquire_schedule_path_lease, current_generation, expected_written_generation, retire,
    verify_written_generation, RetirementFaults, RetirementOutcome, RetirementStorage,
    ScheduleGeneration,
};
#[cfg(test)]
use crate::schedule_retirement::{
    process_lock_strong_count, retired_schedule_path, retired_schedule_retirement_path,
    retirement_completion_path, RetiredScheduleRetirementReceipt, RetiredScheduleRetirementState,
    RetirementPauseHook, ScheduleRetirementFailurePoint, ScheduleRetirementPausePoint,
};

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
#[cfg(test)]
struct ScheduleRaceHook {
    paused: tokio::sync::Barrier,
    resumed: tokio::sync::Barrier,
    reached: AtomicBool,
}

#[cfg(test)]
impl ScheduleRaceHook {
    fn new() -> Self {
        Self {
            paused: tokio::sync::Barrier::new(2),
            resumed: tokio::sync::Barrier::new(2),
            reached: AtomicBool::new(false),
        }
    }

    async fn pause(&self) {
        self.reached.store(true, Ordering::SeqCst);
        self.paused.wait().await;
        self.resumed.wait().await;
    }

    async fn wait_until_paused(&self) {
        self.paused.wait().await;
    }

    async fn resume(&self) {
        self.resumed.wait().await;
    }

    fn reached(&self) -> bool {
        self.reached.load(Ordering::SeqCst)
    }
}

struct ScheduleFileStore {
    path: PathBuf,
    // Outermost lock for acknowledgement reconciliation, direct ID mutation,
    // and quarantine establishment. When present, lock order is admission ->
    // path-global lease -> write_lock -> quarantined_schedules. Retirement
    // takes admission then the path lease and keeps that lease through startup
    // snapshot registration; it does not take write_lock.
    mutation_admission: AsyncMutex<()>,
    write_lock: AsyncMutex<()>,
    expected_generation: AsyncMutex<Option<ScheduleGeneration>>,
    quarantined_schedules: AsyncMutex<HashMap<String, Option<Schedule>>>,
    retirement_faults: RetirementFaults,
    #[cfg(test)]
    direct_mutation_hook: Mutex<Option<Arc<ScheduleRaceHook>>>,
    #[cfg(test)]
    direct_mutation_admitted_hook: Mutex<Option<Arc<ScheduleRaceHook>>>,
    #[cfg(test)]
    acknowledgement_cursor_hook: Mutex<Option<Arc<ScheduleRaceHook>>>,
    #[cfg(test)]
    quarantine_hook: Mutex<Option<Arc<ScheduleRaceHook>>>,
    #[cfg(test)]
    post_write_verification_hook: Mutex<Option<Arc<ScheduleRaceHook>>>,
    #[cfg(test)]
    mutation_admission_waiters: AtomicUsize,
}

impl ScheduleFileStore {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            mutation_admission: AsyncMutex::new(()),
            write_lock: AsyncMutex::new(()),
            expected_generation: AsyncMutex::new(None),
            quarantined_schedules: AsyncMutex::new(HashMap::new()),
            retirement_faults: RetirementFaults::default(),
            #[cfg(test)]
            direct_mutation_hook: Mutex::new(None),
            #[cfg(test)]
            direct_mutation_admitted_hook: Mutex::new(None),
            #[cfg(test)]
            acknowledgement_cursor_hook: Mutex::new(None),
            #[cfg(test)]
            quarantine_hook: Mutex::new(None),
            #[cfg(test)]
            post_write_verification_hook: Mutex::new(None),
            #[cfg(test)]
            mutation_admission_waiters: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    async fn retire_engine_schedules(
        &self,
        store: Option<&Store>,
    ) -> Result<Vec<String>, CampaignSchedulerError> {
        self.retire_engine_schedules_with_storage(store.map_or(
            RetirementStorage::NotConfigured,
            RetirementStorage::Available,
        ))
        .await
        .map(|outcome| outcome.retired_ids)
    }

    async fn retire_engine_schedules_with_storage(
        &self,
        storage: RetirementStorage<'_>,
    ) -> Result<RetirementOutcome, CampaignSchedulerError> {
        let _admission = self.mutation_admission.lock().await;
        let outcome = retire(&self.path, storage, &self.retirement_faults).await?;
        *self.expected_generation.lock().await = Some(outcome.generation.clone());
        Ok(outcome)
    }

    #[cfg(test)]
    fn set_retirement_failure_for_test(&self, failure: Option<ScheduleRetirementFailurePoint>) {
        self.retirement_faults.set(failure);
    }

    #[cfg(test)]
    fn set_retirement_pause_for_test(
        &self,
        point: ScheduleRetirementPausePoint,
        hook: Arc<RetirementPauseHook>,
    ) {
        self.retirement_faults.set_pause(point, hook);
    }

    #[cfg(test)]
    async fn replace(&self, schedules: &[Schedule]) -> Result<(), StateFileError> {
        let _lease = acquire_schedule_path_lease(&self.path).await?;
        self.replace_while_leased(schedules).await
    }

    async fn replace_while_leased(&self, schedules: &[Schedule]) -> Result<(), StateFileError> {
        let _guard = self.write_lock.lock().await;
        self.require_expected_generation().await?;
        let mut schedules = schedules.to_vec();
        self.restore_quarantined_schedules(&mut schedules).await;
        let written = expected_written_generation(&self.path, &schedules)?;
        atomic_write_schedules(&self.path, &schedules)?;
        #[cfg(test)]
        self.pause_post_write_verification_for_test().await;
        self.accept_written_generation(written).await
    }

    async fn replace_from_manager(&self, manager: &SchedulerManager) -> Result<(), StateFileError> {
        let _lease = acquire_schedule_path_lease(&self.path).await?;
        let _guard = self.write_lock.lock().await;
        self.require_expected_generation().await?;
        let mut schedules = manager.list_schedules().await;
        self.restore_quarantined_schedules(&mut schedules).await;
        let written = expected_written_generation(&self.path, &schedules)?;
        atomic_write_schedules(&self.path, &schedules)?;
        #[cfg(test)]
        self.pause_post_write_verification_for_test().await;
        self.accept_written_generation(written).await
    }

    async fn upsert(&self, schedule: &Schedule) -> Result<(), StateFileError> {
        let _lease = acquire_schedule_path_lease(&self.path).await?;
        let _guard = self.write_lock.lock().await;
        self.require_expected_generation().await?;
        if self
            .quarantined_schedules
            .lock()
            .await
            .contains_key(&schedule.id)
        {
            return Ok(());
        }
        let mut schedules = load_schedules(&self.path)?;
        schedules.retain(|existing| existing.id != schedule.id);
        schedules.push(schedule.clone());
        let written = expected_written_generation(&self.path, &schedules)?;
        atomic_write_schedules(&self.path, &schedules)?;
        #[cfg(test)]
        self.pause_post_write_verification_for_test().await;
        self.accept_written_generation(written).await
    }

    async fn quarantine(&self, schedule_id: &str) -> Result<(), StateFileError> {
        #[cfg(test)]
        self.pause_quarantine_for_test().await;
        let _admission_guard = self.mutation_admission.lock().await;
        let _lease = acquire_schedule_path_lease(&self.path).await?;
        self.quarantine_while_leased(schedule_id).await
    }

    async fn quarantine_while_leased(&self, schedule_id: &str) -> Result<(), StateFileError> {
        let _guard = self.write_lock.lock().await;
        self.require_expected_generation().await?;
        let mut quarantined = self.quarantined_schedules.lock().await;
        if quarantined.contains_key(schedule_id) {
            return Ok(());
        }
        let original = load_schedules(&self.path)?
            .into_iter()
            .find(|schedule| schedule.id == schedule_id);
        quarantined.insert(schedule_id.to_owned(), original);
        Ok(())
    }

    async fn require_expected_generation(&self) -> Result<(), StateFileError> {
        let current = current_generation(&self.path)?;
        let mut expected = self.expected_generation.lock().await;
        match expected.as_ref() {
            Some(expected) if expected != &current => Err(StateFileError::Conflict {
                path: self.path.clone(),
            }),
            Some(_) => Ok(()),
            None => {
                *expected = Some(current);
                Ok(())
            }
        }
    }

    async fn accept_written_generation(
        &self,
        written: ScheduleGeneration,
    ) -> Result<(), StateFileError> {
        verify_written_generation(&self.path, &written)?;
        *self.expected_generation.lock().await = Some(written);
        Ok(())
    }

    async fn is_quarantined(&self, schedule_id: &str) -> bool {
        self.quarantined_schedules
            .lock()
            .await
            .contains_key(schedule_id)
    }

    #[cfg(test)]
    fn set_direct_mutation_hook(&self, hook: Option<Arc<ScheduleRaceHook>>) {
        *self
            .direct_mutation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    fn set_post_write_verification_hook(&self, hook: Option<Arc<ScheduleRaceHook>>) {
        *self
            .post_write_verification_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    async fn pause_post_write_verification_for_test(&self) {
        let hook = self
            .post_write_verification_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }

    #[cfg(test)]
    fn set_direct_mutation_admitted_hook(&self, hook: Option<Arc<ScheduleRaceHook>>) {
        *self
            .direct_mutation_admitted_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    fn set_acknowledgement_cursor_hook(&self, hook: Option<Arc<ScheduleRaceHook>>) {
        *self
            .acknowledgement_cursor_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    fn set_quarantine_hook(&self, hook: Option<Arc<ScheduleRaceHook>>) {
        *self
            .quarantine_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    async fn pause_direct_mutation_for_test(&self) {
        let hook = self
            .direct_mutation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_direct_mutation_admitted_for_test(&self) {
        let hook = self
            .direct_mutation_admitted_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_acknowledgement_cursor_for_test(&self) {
        let hook = self
            .acknowledgement_cursor_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }

    #[cfg(test)]
    async fn pause_quarantine_for_test(&self) {
        let hook = self
            .quarantine_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }

    #[cfg(test)]
    fn mutation_admission_waiters(&self) -> usize {
        self.mutation_admission_waiters.load(Ordering::SeqCst)
    }

    async fn restore_quarantined_schedules(&self, schedules: &mut Vec<Schedule>) {
        let quarantined = self.quarantined_schedules.lock().await;
        for (schedule_id, original) in quarantined.iter() {
            match original {
                Some(original) => {
                    if let Some(schedule) = schedules
                        .iter_mut()
                        .find(|schedule| schedule.id == *schedule_id)
                    {
                        *schedule = original.clone();
                    } else {
                        schedules.push(original.clone());
                    }
                }
                None => schedules.retain(|schedule| schedule.id != *schedule_id),
            }
        }
    }
}

/// Persists scheduler definitions atomically and execution history to the
/// database when one is configured.
struct CampaignSchedulerPersistence {
    store: Option<Arc<Store>>,
    schedules: Arc<ScheduleFileStore>,
    history_retention_limit: usize,
    manager: Weak<SchedulerManager>,
}

#[derive(Clone, Copy)]
enum OccurrenceJournalFailure {
    Corrupt,
    Unavailable,
}

impl CampaignSchedulerPersistence {
    fn new(
        store: Option<Arc<Store>>,
        schedules: Arc<ScheduleFileStore>,
        history_retention_limit: usize,
        manager: Weak<SchedulerManager>,
    ) -> Self {
        Self {
            store,
            schedules,
            history_retention_limit,
            manager,
        }
    }

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

    async fn quarantine_schedule(&self, schedule_id: &str) -> Result<(), StateFileError> {
        self.schedules.quarantine(schedule_id).await
    }

    async fn quarantine_schedule_while_leased(
        &self,
        schedule_id: &str,
    ) -> Result<(), StateFileError> {
        self.schedules.quarantine_while_leased(schedule_id).await
    }

    async fn schedule_is_quarantined(&self, schedule_id: &str) -> bool {
        self.schedules.is_quarantined(schedule_id).await
    }

    async fn map_storage_result<T>(
        &self,
        result: Result<T, StorageError>,
    ) -> Result<T, PersistenceError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                let failure = match &error {
                    StorageError::InvalidData(_)
                    | StorageError::Serde(_)
                    | StorageError::Timestamp(_)
                    | StorageError::NotFound(_) => OccurrenceJournalFailure::Corrupt,
                    StorageError::Db(_) | StorageError::Migrate(_) => {
                        OccurrenceJournalFailure::Unavailable
                    }
                };
                self.latch_journal_failure(failure).await;
                Err(PersistenceError::new(error.to_string()))
            }
        }
    }

    async fn decode_occurrence(
        &self,
        row: &ScheduleOccurrenceRecord,
    ) -> Result<OneTimeOccurrence, PersistenceError> {
        match row_to_occurrence(row) {
            Ok(occurrence) => Ok(occurrence),
            Err(error) => {
                self.latch_journal_failure(OccurrenceJournalFailure::Corrupt)
                    .await;
                Err(error)
            }
        }
    }

    async fn latch_journal_failure(&self, failure: OccurrenceJournalFailure) {
        let Some(manager) = self.manager.upgrade() else {
            return;
        };
        let (reason, corrupt) = match failure {
            OccurrenceJournalFailure::Corrupt => (JOURNAL_CORRUPT_REASON, true),
            OccurrenceJournalFailure::Unavailable => (JOURNAL_UNAVAILABLE_REASON, false),
        };
        let current = manager.one_time_block_reason().await;
        if current.as_deref() == Some(JOURNAL_CORRUPT_REASON)
            || current.as_deref() == Some(reason)
            || (!corrupt && current.is_some())
        {
            return;
        }
        if corrupt {
            manager.record_corrupt_one_time_journal();
        }
        manager.block_one_time(reason).await;
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
        (None, None) => Err(PersistenceError::new(
            "non-terminal occurrence is missing its execution",
        )),
        (Some(_), None) | (None, Some(_)) => Err(PersistenceError::new(
            "occurrence execution record is incomplete",
        )),
        (Some(actual), Some(_)) if actual != expected_status => Err(PersistenceError::new(
            "occurrence and execution states do not match",
        )),
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
        if self.schedule_is_quarantined(&schedule.id).await {
            return Err(PersistenceError::new(
                "schedule cursor writes are blocked by one-time journal corruption",
            ));
        }
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
        let reservation = self
            .map_storage_result(store.reserve_schedule_occurrence(&new).await)
            .await?;
        match reservation {
            ScheduleOccurrenceReservation::Reserved(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeReservation::Reserved),
            ScheduleOccurrenceReservation::Existing(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeReservation::Existing),
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
        let result = self
            .map_storage_result(store.transition_schedule_occurrence(&request).await)
            .await?;
        match result {
            ScheduleOccurrenceTransitionResult::Applied(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeTransitionResult::Applied),
            ScheduleOccurrenceTransitionResult::Idempotent(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeTransitionResult::Idempotent),
            ScheduleOccurrenceTransitionResult::Conflict(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeTransitionResult::Conflict),
            ScheduleOccurrenceTransitionResult::Missing => Ok(OneTimeTransitionResult::Missing),
        }
    }

    async fn renew_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        lease_expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<bool, PersistenceError> {
        let result = self
            .occurrence_store()?
            .renew_schedule_occurrence_lease(
                occurrence_id,
                owner_id,
                &lease_expires_at.to_rfc3339(),
            )
            .await;
        self.map_storage_result(result).await
    }

    async fn release_one_time_lease(
        &self,
        occurrence_id: &str,
        owner_id: &str,
        released_at: chrono::DateTime<chrono::Utc>,
        recovery_detail: &str,
    ) -> Result<bool, PersistenceError> {
        let result = self
            .occurrence_store()?
            .release_schedule_occurrence_lease(
                occurrence_id,
                owner_id,
                &released_at.to_rfc3339(),
                recovery_detail,
            )
            .await;
        self.map_storage_result(result).await
    }

    async fn load_one_time_occurrences(&self) -> Result<Vec<OneTimeOccurrence>, PersistenceError> {
        let result = self.occurrence_store()?.list_schedule_occurrences().await;
        let rows = self.map_storage_result(result).await?;
        let mut occurrences = Vec::with_capacity(rows.len());
        for row in &rows {
            occurrences.push(self.decode_occurrence(row).await?);
        }
        Ok(occurrences)
    }

    async fn get_one_time_occurrence(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<OneTimeOccurrence>, PersistenceError> {
        let result = self
            .occurrence_store()?
            .schedule_occurrence(occurrence_id)
            .await;
        let row = self.map_storage_result(result).await?;
        match row {
            Some(row) => self.decode_occurrence(&row).await.map(Some),
            None => Ok(None),
        }
    }

    async fn get_one_time_execution(
        &self,
        occurrence_id: &str,
    ) -> Result<Option<ScheduleExecution>, PersistenceError> {
        let result = self
            .occurrence_store()?
            .schedule_occurrence(occurrence_id)
            .await;
        let Some(row) = self.map_storage_result(result).await? else {
            return Ok(None);
        };
        let occurrence = self.decode_occurrence(&row).await?;
        match validate_row_execution(&row, &occurrence) {
            Ok(execution) => Ok(execution),
            Err(error) => {
                self.latch_journal_failure(OccurrenceJournalFailure::Corrupt)
                    .await;
                Err(error)
            }
        }
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
        let result = self
            .occurrence_store()?
            .acknowledge_schedule_occurrence(
                occurrence_id,
                &acknowledged_at.to_rfc3339(),
                recovery_detail,
                &execution.status.to_string(),
                &execution_data_json,
            )
            .await;
        match self.map_storage_result(result).await? {
            ScheduleOccurrenceAcknowledgement::Acknowledged(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeAcknowledgement::Acknowledged),
            ScheduleOccurrenceAcknowledgement::AlreadyCancelled(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeAcknowledgement::AlreadyCancelled),
            ScheduleOccurrenceAcknowledgement::Conflict(row) => self
                .decode_occurrence(&row)
                .await
                .map(OneTimeAcknowledgement::Conflict),
            ScheduleOccurrenceAcknowledgement::Missing => Ok(OneTimeAcknowledgement::Missing),
        }
    }
}

/// How often the scheduler evaluates triggers.
const TICK: Duration = Duration::from_secs(30);
/// Constant `workflow_id` for all fuzz-campaign schedules (the dispatcher reads
/// the campaign from `parameter_values`, not the id).
pub(crate) const CAMPAIGN_KIND: &str = "fuzz-campaign";

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
        // Scheduled campaigns have no request-scoped language, and the UI locale
        // is never persisted to the service, so scheduled reports use the
        // documented English default. Localizing these needs a stored preference
        // -- see the known limitation in the design doc.
        let markdown = match self
            .container
            .generate_report(project, target, crate::report::ReportLanguage::En)
            .await
        {
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
    /// Retired schedule definitions or linked history could not be archived.
    #[error("could not retire legacy schedules [{schedule_ids}]: {reason}")]
    RetiredScheduleArchive {
        schedule_ids: String,
        reason: String,
    },
    /// The durable one-time schedule-retirement receipt is not usable.
    #[error(
        "schedule retirement receipt for [{schedule_ids}] is corrupt or unavailable: {reason}; \
         verify retired_schedules.json and linked database history, then restart"
    )]
    RetiredScheduleReceipt {
        schedule_ids: String,
        reason: String,
    },
    /// Retired schedule input was introduced after one-time retirement completed.
    #[error(
        "fuzzing engine '{engine}' has been retired; choose one of: afl++, honggfuzz, \
         libfuzzer, syzkaller; active retired schedule IDs: {schedule_ids}; remove or replace \
         these schedules in schedules.json, then restart"
    )]
    RetiredScheduleRestore {
        engine: &'static str,
        schedule_ids: String,
    },
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

/// Stable presentation category for one-time recovery failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryPublicErrorCode {
    /// The requested occurrence does not exist.
    NotFound,
    /// The durable occurrence is not eligible for the requested action.
    Conflict,
    /// Required recovery persistence or journal state is unavailable.
    Unavailable,
    /// An unexpected recovery failure occurred.
    Internal,
}

impl RecoveryPublicErrorCode {
    /// Stable wire and CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for RecoveryPublicErrorCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Bounded service-owned error safe for REST, Tauri, and CLI recovery surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RecoveryPublicError {
    /// Stable presentation category.
    pub code: RecoveryPublicErrorCode,
    /// Static message that contains no persistence details or user data.
    pub message: &'static str,
}

impl RecoveryPublicError {
    /// Error returned when the scheduler or its durable recovery state is not
    /// currently available.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            code: RecoveryPublicErrorCode::Unavailable,
            message: "one-time recovery is temporarily unavailable",
        }
    }
}

impl std::fmt::Display for RecoveryPublicError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for RecoveryPublicError {}

impl CampaignSchedulerError {
    /// Convert a detailed internal scheduler failure into the bounded error
    /// contract used only by one-time recovery presentations.
    #[must_use]
    pub fn into_public_recovery_error(self) -> RecoveryPublicError {
        let public = match &self {
            Self::OccurrenceNotFound(_) => RecoveryPublicError {
                code: RecoveryPublicErrorCode::NotFound,
                message: "one-time recovery occurrence was not found",
            },
            Self::OccurrenceConflict(_) => RecoveryPublicError {
                code: RecoveryPublicErrorCode::Conflict,
                message: "one-time recovery occurrence cannot be acknowledged",
            },
            Self::State(_)
            | Self::RetiredScheduleArchive { .. }
            | Self::RetiredScheduleReceipt { .. }
            | Self::History(_)
            | Self::InvalidLastFire { .. }
            | Self::DurabilityUnavailable(_)
            | Self::OccurrenceJournal(_) => RecoveryPublicError::unavailable(),
            Self::Validation(_) | Self::RetiredScheduleRestore { .. } => RecoveryPublicError {
                code: RecoveryPublicErrorCode::Internal,
                message: "one-time recovery request failed",
            },
        };
        tracing::warn!(
            error = %self,
            public_code = %public.code,
            "redacting detailed one-time recovery error for presentation"
        );
        public
    }
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
        // Grab the DB handle (for persisted execution history) before the
        // container is moved into the dispatcher.
        let store = container.store().cloned();
        let schedules = Arc::new(ScheduleFileStore::new(store_path.clone()));
        let retirement_storage = match container.persistence_availability() {
            PersistenceAvailability::Available => store
                .as_deref()
                .map_or(RetirementStorage::Unavailable, RetirementStorage::Available),
            PersistenceAvailability::NotConfigured => RetirementStorage::NotConfigured,
            PersistenceAvailability::Unavailable => RetirementStorage::Unavailable,
        };
        let mut retirement = schedules
            .retire_engine_schedules_with_storage(retirement_storage)
            .await?;
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
        let occurrences = Arc::new(CampaignSchedulerPersistence::new(
            store.clone(),
            Arc::clone(&schedules),
            history_retention_limit,
            Arc::downgrade(&manager),
        ));
        manager
            .set_persistence(Arc::clone(&occurrences) as Arc<dyn SchedulerPersistence>)
            .await;

        let mut loaded = std::mem::take(&mut retirement.schedules);
        let mut restored = false;
        let mut receipt_cursor_restored = false;
        let journal_readable = if let Some(store) = &store {
            match store.inspect_schedule_occurrences().await {
                Ok(inspections) => {
                    let mut receipts = Vec::new();
                    let mut malformed_schedule_ids = Vec::new();
                    for inspection in inspections {
                        match inspection {
                            ScheduleOccurrenceInspection::Valid(row) => {
                                match row_to_occurrence(&row) {
                                    Ok(receipt) => receipts.push(receipt),
                                    Err(_) => {
                                        malformed_schedule_ids.push(Some(row.schedule_id.clone()));
                                    }
                                }
                            }
                            ScheduleOccurrenceInspection::Malformed { schedule_id } => {
                                malformed_schedule_ids.push(schedule_id);
                            }
                        }
                    }

                    let preserve_complete_snapshot =
                        malformed_schedule_ids.iter().any(Option::is_none);
                    let mut quarantine_ids: HashSet<String> =
                        malformed_schedule_ids.into_iter().flatten().collect();
                    quarantine_ids.extend(receipts.iter().filter_map(|receipt| {
                        loaded
                            .iter()
                            .find(|schedule| schedule.id == receipt.schedule_id)
                            .filter(|schedule| {
                                !matches!(schedule.trigger, TriggerConfig::OneTime { .. })
                            })
                            .map(|schedule| schedule.id.clone())
                    }));
                    if preserve_complete_snapshot {
                        quarantine_ids.extend(loaded.iter().map(|schedule| schedule.id.clone()));
                    }
                    if !quarantine_ids.is_empty() || preserve_complete_snapshot {
                        for schedule_id in &quarantine_ids {
                            occurrences
                                .quarantine_schedule_while_leased(schedule_id)
                                .await?;
                        }
                        manager.record_corrupt_one_time_journal();
                        manager.block_one_time(JOURNAL_CORRUPT_REASON).await;
                    }

                    let now = chrono::Utc::now();
                    for schedule in &mut loaded {
                        if !matches!(schedule.trigger, TriggerConfig::OneTime { .. })
                            || occurrences.schedule_is_quarantined(&schedule.id).await
                        {
                            continue;
                        }
                        let receipt = receipts
                            .iter()
                            .find(|receipt| receipt.schedule_id == schedule.id);
                        match receipt {
                            Some(receipt) if receipt.recovery_eligible(now) => {
                                manager.record_expired_one_time_occurrence();
                                let reconciled =
                                    schedule.last_fire.map_or(receipt.triggered_at, |last| {
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
                                        receipt.recovery_detail.clone().unwrap_or_else(|| {
                                            "expired non-terminal occurrence".to_owned()
                                        }),
                                    )
                                    .await;
                            }
                            Some(receipt) => {
                                let reconciled =
                                    schedule.last_fire.map_or(receipt.triggered_at, |last| {
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
                    && !occurrences.schedule_is_quarantined(&schedule.id).await
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
            if let Err(error) = schedules.replace_while_leased(&loaded).await {
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
        drop(retirement);
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
        if self.store.is_some() {
            self.refresh_one_time_receipt_statuses(&schedules).await?;
        }
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
        let occurrences = self.refresh_one_time_receipt_statuses(&schedules).await?;
        let names: std::collections::HashMap<_, _> = schedules
            .iter()
            .map(|schedule| (schedule.id.clone(), schedule.name.clone()))
            .collect();
        let now = chrono::Utc::now();
        let mut recoveries: Vec<_> = occurrences
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

        if let Some(schedule) = self.manager.get_schedule(&occurrence.schedule_id).await {
            self.reject_receipts_attached_to_recurring_schedules(
                std::slice::from_ref(&occurrence),
                std::slice::from_ref(&schedule),
            )
            .await?;
        }
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

    async fn refresh_one_time_receipt_statuses(
        &self,
        schedules: &[Schedule],
    ) -> Result<Vec<OneTimeOccurrence>, CampaignSchedulerError> {
        let occurrences = self
            .occurrences
            .load_one_time_occurrences()
            .await
            .map_err(occurrence_journal_error)?;
        self.reject_receipts_attached_to_recurring_schedules(&occurrences, schedules)
            .await?;

        let now = chrono::Utc::now();
        for occurrence in occurrences
            .iter()
            .filter(|occurrence| occurrence.recovery_eligible(now))
        {
            let belongs_to_one_time = schedules.iter().any(|schedule| {
                schedule.id == occurrence.schedule_id
                    && matches!(schedule.trigger, TriggerConfig::OneTime { .. })
            });
            if belongs_to_one_time
                && !matches!(
                    self.manager
                        .one_time_runtime_status(&occurrence.schedule_id)
                        .await,
                    OneTimeRuntimeStatus::RecoveryRequired { .. }
                )
            {
                self.manager.record_expired_one_time_occurrence();
                self.manager
                    .mark_one_time_recovery_required(
                        &occurrence.schedule_id,
                        occurrence
                            .recovery_detail
                            .clone()
                            .unwrap_or_else(|| "expired non-terminal occurrence".to_owned()),
                    )
                    .await;
            }
        }
        Ok(occurrences)
    }

    async fn reject_receipts_attached_to_recurring_schedules(
        &self,
        occurrences: &[OneTimeOccurrence],
        schedules: &[Schedule],
    ) -> Result<(), CampaignSchedulerError> {
        let mismatched_schedule_ids: HashSet<_> = occurrences
            .iter()
            .filter_map(|occurrence| {
                schedules
                    .iter()
                    .find(|schedule| schedule.id == occurrence.schedule_id)
                    .filter(|schedule| !matches!(schedule.trigger, TriggerConfig::OneTime { .. }))
                    .map(|schedule| schedule.id.clone())
            })
            .collect();
        if mismatched_schedule_ids.is_empty() {
            return Ok(());
        }

        for schedule_id in mismatched_schedule_ids {
            self.occurrences.quarantine_schedule(&schedule_id).await?;
        }
        if self.manager.one_time_block_reason().await.as_deref() != Some(JOURNAL_CORRUPT_REASON) {
            self.manager.record_corrupt_one_time_journal();
            self.manager.block_one_time(JOURNAL_CORRUPT_REASON).await;
        }
        Err(CampaignSchedulerError::OccurrenceJournal(
            "occurrence receipt is not attached to a one-time schedule".to_owned(),
        ))
    }

    async fn finish_one_time_acknowledgement(
        &self,
        occurrence: &OneTimeOccurrence,
    ) -> Result<OneTimeRecoveryView, CampaignSchedulerError> {
        let admission_guard = self.lock_schedule_mutation_admission().await;
        self.manager
            .mark_one_time_consumed(&occurrence.schedule_id)
            .await;
        let current_schedule = self.manager.get_schedule(&occurrence.schedule_id).await;
        #[cfg(test)]
        self.schedules.pause_acknowledgement_cursor_for_test().await;
        if let Some(mut schedule) = current_schedule {
            schedule.last_fire = Some(schedule.last_fire.map_or(occurrence.triggered_at, |last| {
                last.max(occurrence.triggered_at)
            }));
            self.manager.register(schedule).await;
            self.persist().await?;
        }
        drop(admission_guard);
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
            self.probe_one_time_journal_for_creation().await?;
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

    async fn probe_one_time_journal_for_creation(&self) -> Result<(), CampaignSchedulerError> {
        if self.store.is_none() {
            return Err(CampaignSchedulerError::DurabilityUnavailable(
                "SQLite storage is not configured".to_owned(),
            ));
        }
        if let Some(reason) = self.manager.one_time_block_reason().await {
            return Err(CampaignSchedulerError::DurabilityUnavailable(reason));
        }
        if let Err(error) = self.occurrences.load_one_time_occurrences().await {
            tracing::warn!(
                %error,
                "One-time schedule creation journal probe failed"
            );
            let reason = self
                .manager
                .one_time_block_reason()
                .await
                .unwrap_or_else(|| JOURNAL_UNAVAILABLE_REASON.to_owned());
            return Err(CampaignSchedulerError::DurabilityUnavailable(reason));
        }
        Ok(())
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
    /// Returns an occurrence-journal error for a quarantined schedule, or a
    /// state-file error after restoring the in-memory schedule if the
    /// definition file cannot be replaced.
    pub async fn try_remove(&self, id: &str) -> Result<bool, CampaignSchedulerError> {
        #[cfg(test)]
        self.schedules.pause_direct_mutation_for_test().await;
        let _admission_guard = self.admit_schedule_mutation(id).await?;
        #[cfg(test)]
        self.schedules
            .pause_direct_mutation_admitted_for_test()
            .await;
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
    /// Returns an occurrence-journal error for a quarantined schedule, or a
    /// state-file error if the durable definition cannot be replaced.
    pub async fn try_set_enabled(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<bool, CampaignSchedulerError> {
        #[cfg(test)]
        self.schedules.pause_direct_mutation_for_test().await;
        let _admission_guard = self.admit_schedule_mutation(id).await?;
        #[cfg(test)]
        self.schedules
            .pause_direct_mutation_admitted_for_test()
            .await;
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

    async fn admit_schedule_mutation(
        &self,
        schedule_id: &str,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, CampaignSchedulerError> {
        let admission_guard = self.lock_schedule_mutation_admission().await;
        if self.schedules.is_quarantined(schedule_id).await {
            return Err(CampaignSchedulerError::OccurrenceJournal(
                "schedule mutation is blocked by corrupt one-time occurrence evidence".to_owned(),
            ));
        }
        Ok(admission_guard)
    }

    async fn lock_schedule_mutation_admission(&self) -> tokio::sync::MutexGuard<'_, ()> {
        #[cfg(test)]
        self.schedules
            .mutation_admission_waiters
            .fetch_add(1, Ordering::SeqCst);
        let admission_guard = self.schedules.mutation_admission.lock().await;
        #[cfg(test)]
        self.schedules
            .mutation_admission_waiters
            .fetch_sub(1, Ordering::SeqCst);
        admission_guard
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
    expected_written_generation(path, schedules)?;
    atomic_write_json(path, &schedules)
}

/// Load persisted schedules, treating absence as empty and damage as an error.
fn load_schedules(path: &Path) -> Result<Vec<Schedule>, StateFileError> {
    Ok(read_json_file(path)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use hf_scheduler::{
        ExecutionStatus, FiredTrigger, IncomingEvent, OneTimeOccurrenceState, TriggerType,
    };
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
        directory: tempfile::TempDir,
        schedules_path: PathBuf,
        store: Option<Arc<Store>>,
    }

    impl SchedulerFixture {
        fn params(&self) -> CampaignParams {
            CampaignParams {
                project: self.directory.path().display().to_string(),
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
            self.write_due_one_time_with_enabled(id, true);
        }

        fn write_due_one_time_with_enabled(&self, id: &str, enabled: bool) {
            let mut schedule = Schedule::new(
                id,
                id,
                TriggerConfig::OneTime {
                    at: Utc::now() - chrono::Duration::seconds(1),
                },
                CAMPAIGN_KIND,
            )
            .with_params(serde_json::to_value(self.params()).unwrap());
            schedule.enabled = enabled;
            self.push_schedule(schedule);
        }

        fn write_future_one_time(&self, id: &str) {
            self.push_schedule(
                Schedule::new(
                    id,
                    id,
                    TriggerConfig::OneTime {
                        at: Utc::now() + chrono::Duration::hours(1),
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

        fn write_event(&self, id: &str) {
            self.write_event_with_enabled(id, true);
        }

        fn write_event_with_enabled(&self, id: &str, enabled: bool) {
            let mut schedule = Schedule::new(
                id,
                id,
                TriggerConfig::Event {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    debounce_secs: 0,
                    filter: None,
                },
                CAMPAIGN_KIND,
            )
            .with_params(serde_json::to_value(self.params()).unwrap());
            schedule.enabled = enabled;
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
            directory,
        }
    }

    fn scheduler_fixture_without_store() -> SchedulerFixture {
        let directory = tempfile::tempdir().unwrap();
        SchedulerFixture {
            schedules_path: directory.path().join("schedules.json"),
            store: None,
            directory,
        }
    }

    fn retired_campaign(id: &str) -> Schedule {
        Schedule::new(
            id,
            "retired campaign",
            TriggerConfig::Interval { interval_secs: 300 },
            CAMPAIGN_KIND,
        )
        .with_params(serde_json::json!({
            "project": "/project",
            "target": "parse",
            "engine": hf_core::retired_engine::RETIRED_ENGINE_ID,
            "lang": "c",
            "duration_secs": 60
        }))
    }

    fn active_campaign(id: &str) -> Schedule {
        Schedule::new(
            id,
            "active campaign",
            TriggerConfig::Interval { interval_secs: 300 },
            CAMPAIGN_KIND,
        )
        .with_params(serde_json::json!({
            "project": "/project",
            "target": "parse",
            "engine": "libfuzzer",
            "lang": "c",
            "duration_secs": 60
        }))
    }

    fn retired_campaign_with_engine(id: &str, engine: &str) -> Schedule {
        let mut schedule = retired_campaign(id);
        schedule.parameter_values["engine"] = serde_json::Value::String(engine.to_owned());
        schedule
    }

    fn retirement_receipt(fixture: &SchedulerFixture) -> RetiredScheduleRetirementReceipt {
        read_json_file(&retired_schedule_retirement_path(&fixture.schedules_path))
            .unwrap()
            .unwrap()
    }

    fn optional_file_bytes(path: &Path) -> Option<Vec<u8>> {
        match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("could not read {}: {error}", path.display()),
        }
    }

    async fn retired_history_rows(store: &Store) -> Vec<(String, String, String)> {
        sqlx::query_as(
            "SELECT record_kind, record_id, payload_json
             FROM retired_engine_records
             WHERE record_kind IN ('schedule_execution', 'schedule_occurrence')
             ORDER BY record_kind, record_id",
        )
        .fetch_all(store.pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn initial_retirement_without_schedules_persists_completed_receipt_once() {
        let fixture = scheduler_fixture_without_store();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        assert!(repository
            .retire_engine_schedules(None)
            .await
            .unwrap()
            .is_empty());
        let receipt = retirement_receipt(&fixture);
        assert_eq!(receipt.version, 2);
        assert_eq!(receipt.state, RetiredScheduleRetirementState::Completed);
        assert!(!receipt.operation_id.is_empty());
        assert!(!receipt.plan_digest.is_empty());
        let receipt_path = retired_schedule_retirement_path(&fixture.schedules_path);
        let before = std::fs::read(&receipt_path).unwrap();

        assert!(repository
            .retire_engine_schedules(None)
            .await
            .unwrap()
            .is_empty());
        assert_eq!(std::fs::read(receipt_path).unwrap(), before);
    }

    #[tokio::test]
    async fn initial_receipt_failures_leave_state_unchanged_and_retry() {
        for (failure_state, with_retired_schedule) in [
            (RetiredScheduleRetirementState::ArchivePending, true),
            (RetiredScheduleRetirementState::Completed, false),
        ] {
            let fixture = scheduler_fixture_without_store();
            if with_retired_schedule {
                fixture.push_schedule(retired_campaign("schedule-retired"));
            } else {
                fixture.push_schedule(active_campaign("schedule-active"));
            }
            let before = std::fs::read(&fixture.schedules_path).unwrap();
            let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
            repository.set_retirement_failure_for_test(Some(
                ScheduleRetirementFailurePoint::Receipt(failure_state),
            ));

            let error = repository.retire_engine_schedules(None).await.unwrap_err();
            assert!(error.to_string().contains("retirement receipt"));
            assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
            if matches!(
                failure_state,
                RetiredScheduleRetirementState::ArchivePending
            ) {
                assert_eq!(
                    optional_file_bytes(&retired_schedule_path(&fixture.schedules_path)),
                    None
                );
                assert_eq!(
                    optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
                    None
                );
            } else {
                assert!(
                    load_schedules(&retired_schedule_path(&fixture.schedules_path))
                        .unwrap()
                        .is_empty()
                );
                assert_eq!(
                    retirement_receipt(&fixture).state,
                    RetiredScheduleRetirementState::CompletionPending
                );
            }

            repository.retire_engine_schedules(None).await.unwrap();
            assert_eq!(
                retirement_receipt(&fixture).state,
                RetiredScheduleRetirementState::Completed
            );
        }
    }

    #[tokio::test]
    async fn interrupted_receipt_phase_transitions_resume_in_order() {
        for (failure_state, durable_state, active_count, history_count) in [
            (
                RetiredScheduleRetirementState::HistoryPending,
                RetiredScheduleRetirementState::ArchivePending,
                2,
                0,
            ),
            (
                RetiredScheduleRetirementState::ActiveRewritePending,
                RetiredScheduleRetirementState::HistoryPending,
                2,
                2,
            ),
            (
                RetiredScheduleRetirementState::CompletionPending,
                RetiredScheduleRetirementState::ActiveRewritePending,
                1,
                2,
            ),
            (
                RetiredScheduleRetirementState::Completed,
                RetiredScheduleRetirementState::CompletionPending,
                1,
                2,
            ),
        ] {
            let fixture = scheduler_fixture_with_store().await;
            fixture.push_schedule(retired_campaign("schedule-retired"));
            fixture.push_schedule(active_campaign("schedule-active"));
            fixture
                .reserve_receipt(
                    "schedule-retired",
                    "occ-retired",
                    "exec-retired",
                    OneTimeOccurrenceState::Reserved,
                )
                .await;
            let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
            repository.set_retirement_failure_for_test(Some(
                ScheduleRetirementFailurePoint::Receipt(failure_state),
            ));

            repository
                .retire_engine_schedules(fixture.store.as_deref())
                .await
                .unwrap_err();
            assert_eq!(retirement_receipt(&fixture).state, durable_state);
            assert_eq!(
                load_schedules(&fixture.schedules_path).unwrap().len(),
                active_count
            );
            assert_eq!(
                retired_history_rows(fixture.store.as_deref().unwrap())
                    .await
                    .len(),
                history_count
            );

            let restarted = ScheduleFileStore::new(fixture.schedules_path.clone());
            let expected_retired =
                if durable_state == RetiredScheduleRetirementState::CompletionPending {
                    Vec::new()
                } else {
                    vec!["schedule-retired".to_owned()]
                };
            assert_eq!(
                restarted
                    .retire_engine_schedules(fixture.store.as_deref())
                    .await
                    .unwrap(),
                expected_retired
            );
            assert_eq!(
                retirement_receipt(&fixture).state,
                RetiredScheduleRetirementState::Completed
            );
            let active = load_schedules(&fixture.schedules_path).unwrap();
            assert_eq!(active.len(), 1);
            assert_eq!(active[0].id, "schedule-active");
            assert_eq!(
                retired_history_rows(fixture.store.as_deref().unwrap())
                    .await
                    .len(),
                2
            );
        }
    }

    #[tokio::test]
    async fn active_rewrite_failure_keeps_active_file_and_resumes() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.push_schedule(retired_campaign("schedule-retired"));
        fixture.push_schedule(active_campaign("schedule-active"));
        fixture
            .reserve_receipt(
                "schedule-retired",
                "occ-retired",
                "exec-retired",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let before = std::fs::read(&fixture.schedules_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository
            .set_retirement_failure_for_test(Some(ScheduleRetirementFailurePoint::ActiveRewrite));

        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap_err();
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::ActiveRewritePending
        );
        assert_eq!(
            retired_history_rows(fixture.store.as_deref().unwrap())
                .await
                .len(),
            2
        );

        let restarted = ScheduleFileStore::new(fixture.schedules_path.clone());
        restarted
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::Completed
        );
        assert_eq!(load_schedules(&fixture.schedules_path).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn completion_certificate_failure_stays_pending_and_resumes_without_rewrite() {
        let fixture = scheduler_fixture_without_store();
        fixture.push_schedule(retired_campaign("schedule-retired"));
        fixture.push_schedule(active_campaign("schedule-active"));
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.set_retirement_failure_for_test(Some(
            ScheduleRetirementFailurePoint::CompletionCertificate,
        ));

        repository.retire_engine_schedules(None).await.unwrap_err();

        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::CompletionPending
        );
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        assert_eq!(
            optional_file_bytes(&retirement_completion_path(&fixture.schedules_path)),
            None
        );

        repository.retire_engine_schedules(None).await.unwrap();

        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::Completed
        );
        assert!(retirement_completion_path(&fixture.schedules_path).is_file());
    }

    #[tokio::test]
    async fn completed_retirement_rejects_same_and_new_restored_ids_without_mutation() {
        for restored_id in ["schedule-historical", "schedule-new"] {
            let fixture = scheduler_fixture_with_store().await;
            fixture.push_schedule(retired_campaign("schedule-historical"));
            fixture
                .reserve_receipt(
                    "schedule-historical",
                    "occ-historical",
                    "exec-historical",
                    OneTimeOccurrenceState::Reserved,
                )
                .await;
            let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
            repository
                .retire_engine_schedules(fixture.store.as_deref())
                .await
                .unwrap();
            fixture.push_schedule(retired_campaign(restored_id));

            let active_before = std::fs::read(&fixture.schedules_path).unwrap();
            let archive_path = retired_schedule_path(&fixture.schedules_path);
            let archive_before = std::fs::read(&archive_path).unwrap();
            let receipt_path = retired_schedule_retirement_path(&fixture.schedules_path);
            let receipt_before = std::fs::read(&receipt_path).unwrap();
            let completion_path = retirement_completion_path(&fixture.schedules_path);
            let completion_before = std::fs::read(&completion_path).unwrap();
            let store = fixture.store.as_deref().unwrap();
            let history_before = retired_history_rows(store).await;

            let error = fixture
                .start()
                .await
                .err()
                .expect("restore must fail closed");
            assert_eq!(
                error.to_string(),
                format!(
                    "fuzzing engine '{}' has been retired; choose one of: afl++, honggfuzz, \
                     libfuzzer, syzkaller; active retired schedule IDs: {restored_id}; remove or \
                     replace these schedules in schedules.json, then restart",
                    hf_core::retired_engine::RETIRED_ENGINE_ID,
                )
            );
            assert_eq!(
                std::fs::read(&fixture.schedules_path).unwrap(),
                active_before
            );
            assert_eq!(std::fs::read(archive_path).unwrap(), archive_before);
            assert_eq!(std::fs::read(receipt_path).unwrap(), receipt_before);
            assert_eq!(std::fs::read(completion_path).unwrap(), completion_before);
            assert_eq!(retired_history_rows(store).await, history_before);
        }
    }

    #[tokio::test]
    async fn completed_retirement_rejects_alias_case_and_whitespace_ids_sorted() {
        let fixture = scheduler_fixture_with_store().await;
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();
        let short_alias = ["c", "f", "l"].concat();
        let long_alias = ["\tC", "FL", "ITE\n"].concat();
        let canonical_mixed_case = [" Cluster", "Fuzz", "Lite "].concat();
        let unicode_trimmed_alias = ["\u{2003}C", "fL", "iTe\u{3000}"].concat();
        fixture.push_schedule(retired_campaign_with_engine("schedule-z", &short_alias));
        fixture.push_schedule(retired_campaign_with_engine("schedule-a", &long_alias));
        fixture.push_schedule(retired_campaign_with_engine(
            "schedule-m",
            &canonical_mixed_case,
        ));
        fixture.push_schedule(retired_campaign_with_engine(
            "schedule-u",
            &unicode_trimmed_alias,
        ));
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let receipt_path = retired_schedule_retirement_path(&fixture.schedules_path);
        let receipt_before = std::fs::read(&receipt_path).unwrap();
        let store = fixture.store.as_deref().unwrap();
        let history_before = retired_history_rows(store).await;

        let error = fixture
            .start()
            .await
            .err()
            .expect("restore must fail closed");
        assert!(error.to_string().contains(
            "active retired schedule IDs: schedule-a, schedule-m, schedule-u, schedule-z; remove or replace"
        ));
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert!(
            load_schedules(&retired_schedule_path(&fixture.schedules_path))
                .unwrap()
                .is_empty()
        );
        assert_eq!(std::fs::read(receipt_path).unwrap(), receipt_before);
        assert_eq!(retired_history_rows(store).await, history_before);
    }

    #[tokio::test]
    async fn completed_restore_error_bounds_sorted_schedule_ids() {
        let fixture = scheduler_fixture_without_store();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.retire_engine_schedules(None).await.unwrap();
        for index in (0..25).rev() {
            fixture.push_schedule(retired_campaign(&format!("schedule-{index:02}")));
        }
        let error = fixture
            .start()
            .await
            .err()
            .expect("restore must fail closed");
        let message = error.to_string();
        let expected_ids = (0..20)
            .map(|index| format!("schedule-{index:02}"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(message.contains(&format!(
            "active retired schedule IDs: {expected_ids} (+5 more);"
        )));
        assert!(!message.contains("schedule-24"));
    }

    #[tokio::test]
    async fn completed_restore_error_escapes_control_characters_in_ids() {
        let fixture = scheduler_fixture_without_store();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.retire_engine_schedules(None).await.unwrap();
        fixture.push_schedule(retired_campaign("private\n\t\u{1b}id"));

        let error = fixture
            .start()
            .await
            .err()
            .expect("restored retired schedule must fail");
        let message = error.to_string();

        assert!(message.contains(r"private\n\t\u{1b}id"));
        assert!(!message.contains('\n'));
        assert!(!message.contains('\t'));
        assert!(!message.contains('\u{1b}'));
    }

    #[tokio::test]
    async fn corrupt_or_unsupported_retirement_receipt_fails_without_mutation() {
        for receipt_bytes in [
            br#"{"version":1,"state":"future","schedule_ids":[]}"#.as_slice(),
            br#"{"version":2,"state":"completed","schedule_ids":[]}"#.as_slice(),
            br#"{"version":1,"state":"archive_pending","schedule_ids":[]}"#.as_slice(),
        ] {
            let fixture = scheduler_fixture_with_store().await;
            fixture.push_schedule(active_campaign("schedule-active"));
            let receipt_path = retired_schedule_retirement_path(&fixture.schedules_path);
            std::fs::write(&receipt_path, receipt_bytes).unwrap();
            let active_before = std::fs::read(&fixture.schedules_path).unwrap();
            let receipt_before = std::fs::read(&receipt_path).unwrap();
            let store = fixture.store.as_deref().unwrap();
            let history_before = retired_history_rows(store).await;
            let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

            let error = repository
                .retire_engine_schedules(Some(store))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("retirement receipt"));
            assert_eq!(
                std::fs::read(&fixture.schedules_path).unwrap(),
                active_before
            );
            assert_eq!(std::fs::read(&receipt_path).unwrap(), receipt_before);
            assert_eq!(
                optional_file_bytes(&retired_schedule_path(&fixture.schedules_path)),
                None
            );
            assert_eq!(retired_history_rows(store).await, history_before);
        }
    }

    #[tokio::test]
    async fn missing_receipt_with_archive_evidence_fails_closed_without_mutation() {
        let fixture = scheduler_fixture_without_store();
        let retired = retired_campaign("schedule-restored");
        fixture.push_schedule(retired.clone());
        atomic_write_schedules(&retired_schedule_path(&fixture.schedules_path), &[retired])
            .unwrap();
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let archive_before = std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        let error = repository.retire_engine_schedules(None).await.unwrap_err();

        assert!(matches!(
            error,
            CampaignSchedulerError::RetiredScheduleRestore { .. }
        ));
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap(),
            archive_before
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn deleted_completed_receipt_rejects_restored_schedule_without_reopening_retirement() {
        let fixture = scheduler_fixture_without_store();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.retire_engine_schedules(None).await.unwrap();
        std::fs::remove_file(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap();
        fixture.push_schedule(retired_campaign("schedule-restored"));
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let archive_before = std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap();
        let completion_before =
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap();

        let error = repository.retire_engine_schedules(None).await.unwrap_err();

        assert!(matches!(
            error,
            CampaignSchedulerError::RetiredScheduleRestore { .. }
        ));
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap(),
            archive_before
        );
        assert_eq!(
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap(),
            completion_before
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn completed_receipt_rejects_missing_archive_without_recreating_it() {
        let fixture = scheduler_fixture_without_store();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.retire_engine_schedules(None).await.unwrap();
        let receipt_before =
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap();
        let completion_before =
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap();
        std::fs::remove_file(retired_schedule_path(&fixture.schedules_path)).unwrap();

        repository.retire_engine_schedules(None).await.unwrap_err();

        assert_eq!(
            optional_file_bytes(&retired_schedule_path(&fixture.schedules_path)),
            None
        );
        assert_eq!(
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap(),
            receipt_before
        );
        assert_eq!(
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap(),
            completion_before
        );
    }

    #[tokio::test]
    async fn completed_retirement_allows_supported_active_schedule_evolution() {
        let fixture = scheduler_fixture_without_store();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.retire_engine_schedules(None).await.unwrap();
        fixture.push_schedule(active_campaign("schedule-supported-later"));
        let scheduler = fixture.start().await.unwrap();
        scheduler.stop().await;

        let active = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "schedule-supported-later");
    }

    #[tokio::test]
    async fn exact_and_divergent_duplicate_ids_fail_before_any_protocol_mutation() {
        for (location, divergent) in [
            ("active", false),
            ("active", true),
            ("archive", false),
            ("archive", true),
        ] {
            let fixture = scheduler_fixture_without_store();
            let retired = retired_campaign("schedule-duplicate");
            let mut duplicate = retired.clone();
            if divergent {
                duplicate.name = "divergent duplicate".to_owned();
            }
            if location == "active" {
                atomic_write_schedules(&fixture.schedules_path, &[retired.clone(), duplicate])
                    .unwrap();
            } else {
                fixture.push_schedule(retired.clone());
                atomic_write_schedules(
                    &retired_schedule_path(&fixture.schedules_path),
                    &[retired, duplicate],
                )
                .unwrap();
            }
            let active_before = std::fs::read(&fixture.schedules_path).unwrap();
            let archive_path = retired_schedule_path(&fixture.schedules_path);
            let archive_before = optional_file_bytes(&archive_path);
            let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

            let error = repository.retire_engine_schedules(None).await.unwrap_err();

            assert!(error.to_string().contains("duplicate schedule identifiers"));
            assert_eq!(
                std::fs::read(&fixture.schedules_path).unwrap(),
                active_before
            );
            assert_eq!(optional_file_bytes(&archive_path), archive_before);
            assert_eq!(
                optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
                None
            );
            assert_eq!(
                optional_file_bytes(&retirement_completion_path(&fixture.schedules_path)),
                None
            );
        }
    }

    #[tokio::test]
    async fn duplicate_archive_ids_fail_before_any_retirement_mutation() {
        let fixture = scheduler_fixture_without_store();
        let retired = retired_campaign("schedule-duplicate");
        fixture.push_schedule(retired.clone());
        let mut divergent = retired.clone();
        divergent.name = "divergent archived evidence".to_owned();
        atomic_write_schedules(
            &retired_schedule_path(&fixture.schedules_path),
            &[retired, divergent],
        )
        .unwrap();
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let archive_path = retired_schedule_path(&fixture.schedules_path);
        let archive_before = std::fs::read(&archive_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        repository.retire_engine_schedules(None).await.unwrap_err();

        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(std::fs::read(archive_path).unwrap(), archive_before);
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn completion_pending_restore_is_retained_and_rejected() {
        let fixture = scheduler_fixture_without_store();
        fixture.push_schedule(retired_campaign("schedule-completion-restore"));
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.set_retirement_failure_for_test(Some(ScheduleRetirementFailurePoint::Receipt(
            RetiredScheduleRetirementState::Completed,
        )));
        repository.retire_engine_schedules(None).await.unwrap_err();
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::CompletionPending
        );
        fixture.push_schedule(retired_campaign("schedule-completion-restore"));
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();

        let error = repository.retire_engine_schedules(None).await.unwrap_err();

        assert!(matches!(
            error,
            CampaignSchedulerError::RetiredScheduleRestore { .. }
        ));
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
    }

    #[tokio::test]
    async fn completed_evidence_rejects_a_restored_stale_phase_and_active_preimage() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.push_schedule(retired_campaign("schedule-stale"));
        fixture.push_schedule(active_campaign("schedule-supported"));
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.set_retirement_failure_for_test(Some(ScheduleRetirementFailurePoint::Receipt(
            RetiredScheduleRetirementState::ActiveRewritePending,
        )));
        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap_err();
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::HistoryPending
        );
        let stale_receipt =
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap();
        let stale_active = std::fs::read(&fixture.schedules_path).unwrap();
        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();

        std::fs::write(
            retired_schedule_retirement_path(&fixture.schedules_path),
            &stale_receipt,
        )
        .unwrap();
        std::fs::write(&fixture.schedules_path, &stale_active).unwrap();
        let archive_before = std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap();
        let completion_before =
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap();
        let history_before = retired_history_rows(fixture.store.as_deref().unwrap()).await;
        let restarted = ScheduleFileStore::new(fixture.schedules_path.clone());

        let error = restarted
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            CampaignSchedulerError::RetiredScheduleRestore { .. }
        ));
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            stale_active
        );
        assert_eq!(
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap(),
            stale_receipt
        );
        assert_eq!(
            std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap(),
            archive_before
        );
        assert_eq!(
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap(),
            completion_before
        );
        assert_eq!(
            retired_history_rows(fixture.store.as_deref().unwrap()).await,
            history_before
        );
    }

    #[tokio::test]
    async fn completed_evidence_fast_forwards_stale_phase_with_supported_evolution() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.push_schedule(retired_campaign("schedule-stale"));
        fixture.push_schedule(active_campaign("schedule-supported"));
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.set_retirement_failure_for_test(Some(ScheduleRetirementFailurePoint::Receipt(
            RetiredScheduleRetirementState::ActiveRewritePending,
        )));
        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap_err();
        let stale_receipt =
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap();
        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();
        fixture.push_schedule(active_campaign("schedule-later"));
        std::fs::write(
            retired_schedule_retirement_path(&fixture.schedules_path),
            stale_receipt,
        )
        .unwrap();
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let restarted = ScheduleFileStore::new(fixture.schedules_path.clone());

        restarted
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::Completed
        );
    }

    #[tokio::test]
    async fn absent_receipt_and_unavailable_storage_fail_before_any_artifact_write() {
        let fixture = scheduler_fixture_without_store();
        fixture.push_schedule(retired_campaign("schedule-unavailable"));
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        repository
            .retire_engine_schedules_with_storage(RetirementStorage::Unavailable)
            .await
            .err()
            .expect("unavailable storage must reject initialization");

        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_path(&fixture.schedules_path)),
            None
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
        assert_eq!(
            optional_file_bytes(&retirement_completion_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn missing_file_evidence_cannot_reopen_database_proof_while_unavailable() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.push_schedule(retired_campaign("schedule-database-proof"));
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();
        for path in [
            retired_schedule_path(&fixture.schedules_path),
            retired_schedule_retirement_path(&fixture.schedules_path),
            retirement_completion_path(&fixture.schedules_path),
        ] {
            std::fs::remove_file(path).unwrap();
        }
        fixture.push_schedule(retired_campaign("schedule-database-proof"));
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let restarted = ScheduleFileStore::new(fixture.schedules_path.clone());

        restarted
            .retire_engine_schedules_with_storage(RetirementStorage::Unavailable)
            .await
            .err()
            .expect("unavailable storage must not reopen retirement");

        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_path(&fixture.schedules_path)),
            None
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
        assert_eq!(
            optional_file_bytes(&retirement_completion_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn no_database_waiver_fails_closed_after_database_attachment() {
        let fixture = scheduler_fixture_without_store();
        fixture.push_schedule(retired_campaign("schedule-attached"));
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.retire_engine_schedules(None).await.unwrap();
        let store = Store::connect(fixture.directory.path().join("attached.db"))
            .await
            .unwrap();
        store
            .upsert_schedule_execution(
                "execution-attached",
                "schedule-attached",
                "2026-08-11T00:00:00Z",
                "pending",
                "{}",
            )
            .await
            .unwrap();
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let archive_before = std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap();
        let receipt_before =
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap();
        let completion_before =
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap();

        repository
            .retire_engine_schedules(Some(&store))
            .await
            .unwrap_err();

        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap(),
            archive_before
        );
        assert_eq!(
            std::fs::read(retired_schedule_retirement_path(&fixture.schedules_path)).unwrap(),
            receipt_before
        );
        assert_eq!(
            std::fs::read(retirement_completion_path(&fixture.schedules_path)).unwrap(),
            completion_before
        );
        let linked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-attached'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(linked, 1);
    }

    #[tokio::test]
    async fn startup_archives_retired_schedules_and_linked_history_once() {
        let fixture = scheduler_fixture_with_store().await;
        let retired = retired_campaign("schedule-retired");
        fixture.push_schedule(retired.clone());
        let mut active = active_campaign("schedule-active");
        active.enabled = false;
        fixture.push_schedule(active);
        fixture
            .reserve_receipt(
                "schedule-retired",
                "occ-retired",
                "exec-retired",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let scheduler = fixture.start().await.unwrap();
        scheduler.stop().await;
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        let second = repository
            .retire_engine_schedules(fixture.store.as_deref())
            .await
            .unwrap();
        assert!(second.is_empty());

        let active = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "schedule-active");
        let archived = load_schedules(&retired_schedule_path(&fixture.schedules_path)).unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(
            serde_json::to_value(&archived[0]).unwrap(),
            serde_json::to_value(&retired).unwrap(),
        );

        let store = fixture.store.as_ref().unwrap();
        let executions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schedule_executions")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let occurrences: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM schedule_occurrences")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let evidence: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM retired_engine_records
             WHERE record_kind IN ('schedule_execution', 'schedule_occurrence')",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!((executions, occurrences, evidence), (0, 0, 2));
    }

    #[tokio::test]
    async fn retired_schedule_archive_conflict_leaves_active_file_unchanged() {
        let fixture = scheduler_fixture_without_store();
        let active = retired_campaign("schedule-retired");
        fixture.push_schedule(active);
        let mut conflicting = retired_campaign("schedule-retired");
        conflicting.name = "different archived evidence".to_owned();
        atomic_write_schedules(
            &retired_schedule_path(&fixture.schedules_path),
            &[conflicting],
        )
        .unwrap();
        let before = std::fs::read(&fixture.schedules_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        let error = repository.retire_engine_schedules(None).await.unwrap_err();
        assert!(error.to_string().contains("schedule-retired"));
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn retired_schedule_archive_io_failure_leaves_active_file_unchanged() {
        let fixture = scheduler_fixture_without_store();
        fixture.push_schedule(retired_campaign("schedule-retired"));
        let archive_path = retired_schedule_path(&fixture.schedules_path);
        std::fs::create_dir_all(&archive_path).unwrap();
        let before = std::fs::read(&fixture.schedules_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        let error = repository.retire_engine_schedules(None).await.unwrap_err();
        assert!(error.to_string().contains("schedule-retired"));
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
    }

    #[tokio::test]
    async fn retired_schedule_history_failure_leaves_active_file_unchanged() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.push_schedule(retired_campaign("schedule-retired"));
        fixture
            .reserve_receipt(
                "schedule-retired",
                "occ-retired",
                "exec-retired",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let before = std::fs::read(&fixture.schedules_path).unwrap();
        let store = fixture.store.as_ref().unwrap();
        sqlx::query("DROP TABLE retired_engine_records")
            .execute(store.pool())
            .await
            .unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        let error = repository
            .retire_engine_schedules(Some(store.as_ref()))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("schedule-retired"));
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::HistoryPending
        );

        let repair_schema = format!(
            "CREATE TABLE retired_engine_records (
                record_kind TEXT NOT NULL,
                record_id TEXT NOT NULL,
                retired_engine TEXT NOT NULL CHECK (retired_engine = '{}'),
                payload_json TEXT NOT NULL CHECK (json_valid(payload_json)),
                migration_version INTEGER NOT NULL CHECK (migration_version = 24),
                archived_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
                PRIMARY KEY (record_kind, record_id)
            )",
            hf_core::retired_engine::RETIRED_ENGINE_ID,
        );
        sqlx::query(&repair_schema)
            .execute(store.pool())
            .await
            .unwrap();
        sqlx::query(
            "CREATE TRIGGER retired_engine_records_no_update
             BEFORE UPDATE ON retired_engine_records
             BEGIN SELECT RAISE(ABORT, 'retired engine evidence is immutable'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "CREATE TRIGGER retired_engine_records_no_delete
             BEFORE DELETE ON retired_engine_records
             BEGIN SELECT RAISE(ABORT, 'retired engine evidence is immutable'); END",
        )
        .execute(store.pool())
        .await
        .unwrap();

        repository
            .retire_engine_schedules(Some(store.as_ref()))
            .await
            .unwrap();
        assert!(load_schedules(&fixture.schedules_path).unwrap().is_empty());
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::Completed
        );
        assert_eq!(retired_history_rows(store).await.len(), 2);
    }

    #[tokio::test]
    async fn unavailable_bootstrap_storage_writes_nothing_and_recovers() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.push_schedule(retired_campaign("schedule-retired"));
        fixture
            .reserve_receipt(
                "schedule-retired",
                "occ-retired",
                "exec-retired",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let unavailable = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_unavailable_store_for_test();

        let error = CampaignScheduler::try_start(unavailable, fixture.schedules_path.clone(), None)
            .await
            .err()
            .expect("unavailable history storage must fail startup");

        assert!(matches!(
            error,
            CampaignSchedulerError::RetiredScheduleArchive { .. }
        ));
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_retirement_path(&fixture.schedules_path)),
            None
        );
        assert_eq!(
            optional_file_bytes(&retired_schedule_path(&fixture.schedules_path)),
            None
        );
        assert!(retired_history_rows(fixture.store.as_deref().unwrap())
            .await
            .is_empty());

        let scheduler = fixture.start().await.unwrap();
        scheduler.stop().await;
        assert!(load_schedules(&fixture.schedules_path).unwrap().is_empty());
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::Completed
        );
        assert_eq!(
            retired_history_rows(fixture.store.as_deref().unwrap())
                .await
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn in_progress_archive_conflict_rejects_then_recovers_exactly() {
        let fixture = scheduler_fixture_without_store();
        let retired = retired_campaign("schedule-retired");
        fixture.push_schedule(retired.clone());
        let active_before = std::fs::read(&fixture.schedules_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());
        repository.set_retirement_failure_for_test(Some(ScheduleRetirementFailurePoint::Receipt(
            RetiredScheduleRetirementState::HistoryPending,
        )));
        repository.retire_engine_schedules(None).await.unwrap_err();
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::ArchivePending
        );
        let mut divergent = retired.clone();
        divergent.name = "divergent archive".to_owned();
        atomic_write_schedules(
            &retired_schedule_path(&fixture.schedules_path),
            &[divergent],
        )
        .unwrap();
        let archive_before = std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap();

        repository.retire_engine_schedules(None).await.unwrap_err();
        assert_eq!(
            std::fs::read(&fixture.schedules_path).unwrap(),
            active_before
        );
        assert_eq!(
            std::fs::read(retired_schedule_path(&fixture.schedules_path)).unwrap(),
            archive_before
        );
        assert_eq!(
            retirement_receipt(&fixture).state,
            RetiredScheduleRetirementState::ArchivePending
        );

        atomic_write_schedules(&retired_schedule_path(&fixture.schedules_path), &[retired])
            .unwrap();
        repository.retire_engine_schedules(None).await.unwrap();
        assert!(load_schedules(&fixture.schedules_path).unwrap().is_empty());
    }

    #[tokio::test]
    async fn two_instances_serialize_every_retirement_effect_and_preserve_valid_mutation() {
        let pause_points = [
            ScheduleRetirementPausePoint::Receipt(RetiredScheduleRetirementState::ArchivePending),
            ScheduleRetirementPausePoint::ArchiveWrite,
            ScheduleRetirementPausePoint::Receipt(RetiredScheduleRetirementState::HistoryPending),
            ScheduleRetirementPausePoint::HistoryArchive,
            ScheduleRetirementPausePoint::Receipt(
                RetiredScheduleRetirementState::ActiveRewritePending,
            ),
            ScheduleRetirementPausePoint::ActiveRewrite,
            ScheduleRetirementPausePoint::Receipt(
                RetiredScheduleRetirementState::CompletionPending,
            ),
            ScheduleRetirementPausePoint::CompletionCertificate,
            ScheduleRetirementPausePoint::Receipt(RetiredScheduleRetirementState::Completed),
        ];

        for point in pause_points {
            let fixture = scheduler_fixture_without_store();
            fixture.push_schedule(retired_campaign("schedule-retired"));
            let initializer = Arc::new(ScheduleFileStore::new(fixture.schedules_path.clone()));
            let writer = Arc::new(ScheduleFileStore::new(fixture.schedules_path.clone()));
            let hook = Arc::new(RetirementPauseHook::new());
            initializer.set_retirement_pause_for_test(point, Arc::clone(&hook));

            let initializer_task = {
                let initializer = Arc::clone(&initializer);
                tokio::spawn(async move { initializer.retire_engine_schedules(None).await })
            };
            hook.wait_until_paused().await;
            let writer_task = {
                let writer = Arc::clone(&writer);
                tokio::spawn(
                    async move { writer.upsert(&active_campaign("schedule-concurrent")).await },
                )
            };
            tokio::time::timeout(Duration::from_secs(1), async {
                while process_lock_strong_count(&fixture.schedules_path) < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("writer never reached the path-global lease");
            assert!(
                !writer_task.is_finished(),
                "writer crossed retirement boundary {point:?}"
            );

            hook.resume().await;
            initializer_task.await.unwrap().unwrap();
            writer_task.await.unwrap().unwrap();

            let active = load_schedules(&fixture.schedules_path).unwrap();
            assert_eq!(active.len(), 1, "boundary {point:?}");
            assert_eq!(active[0].id, "schedule-concurrent", "boundary {point:?}");
            assert_eq!(
                retirement_receipt(&fixture).state,
                RetiredScheduleRetirementState::Completed,
                "boundary {point:?}"
            );
        }
    }

    #[tokio::test]
    async fn stale_second_instance_replacement_is_rejected_without_overwrite() {
        let fixture = scheduler_fixture_without_store();
        let first = ScheduleFileStore::new(fixture.schedules_path.clone());
        let second = ScheduleFileStore::new(fixture.schedules_path.clone());
        first.retire_engine_schedules(None).await.unwrap();
        second.retire_engine_schedules(None).await.unwrap();
        first
            .upsert(&active_campaign("schedule-preserved"))
            .await
            .unwrap();
        let before = std::fs::read(&fixture.schedules_path).unwrap();

        let error = second
            .replace(&[active_campaign("schedule-stale")])
            .await
            .unwrap_err();

        assert!(matches!(error, StateFileError::Conflict { .. }));
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
    }

    #[tokio::test]
    async fn non_locking_post_write_overwrite_is_detected_and_never_adopted() {
        let fixture = scheduler_fixture_without_store();
        let store = Arc::new(ScheduleFileStore::new(fixture.schedules_path.clone()));
        store
            .replace(&[active_campaign("schedule-initial")])
            .await
            .unwrap();
        let hook = Arc::new(ScheduleRaceHook::new());
        store.set_post_write_verification_hook(Some(Arc::clone(&hook)));
        let writer = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.upsert(&active_campaign("schedule-intended")).await })
        };
        hook.wait_until_paused().await;
        let external = active_campaign("schedule-external");
        atomic_write_schedules(&fixture.schedules_path, std::slice::from_ref(&external)).unwrap();
        hook.resume().await;

        let error = writer
            .await
            .unwrap()
            .expect_err("post-write overwrite must be detected");

        assert!(matches!(error, StateFileError::Conflict { .. }));
        let persisted = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].id, external.id);
        store.set_post_write_verification_hook(None);
        let second = store.upsert(&active_campaign("schedule-second")).await;
        assert!(matches!(second, Err(StateFileError::Conflict { .. })));
    }

    #[tokio::test]
    async fn active_schedules_are_not_rewritten_when_no_retired_engine_exists() {
        let fixture = scheduler_fixture_without_store();
        fixture.push_schedule(active_campaign("schedule-active"));
        let before = std::fs::read(&fixture.schedules_path).unwrap();
        let repository = ScheduleFileStore::new(fixture.schedules_path.clone());

        let retired = repository.retire_engine_schedules(None).await.unwrap();
        assert!(retired.is_empty());
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
    }

    fn due_trigger() -> TriggerConfig {
        TriggerConfig::OneTime {
            at: Utc::now() - chrono::Duration::seconds(1),
        }
    }

    async fn wait_for_execution(scheduler: &CampaignScheduler, schedule_id: &str) {
        wait_for_execution_count(scheduler, schedule_id, 1).await;
    }

    async fn wait_for_execution_count(
        scheduler: &CampaignScheduler,
        schedule_id: &str,
        expected: usize,
    ) {
        for _ in 0..100 {
            if scheduler.manager.execution_history(schedule_id).await.len() >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("schedule {schedule_id} did not dispatch {expected} time(s)");
    }

    async fn wait_for_one_time_block(scheduler: &CampaignScheduler) -> String {
        for _ in 0..100 {
            if let Some(reason) = scheduler.manager.one_time_block_reason().await {
                return reason;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("one-time scheduling was not blocked");
    }

    async fn start_mismatched_recurring(enabled: bool) -> (SchedulerFixture, CampaignScheduler) {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_event_with_enabled("recurring", enabled);
        fixture
            .reserve_expired_receipt(
                "recurring",
                "occ-mismatch",
                "exec-mismatch",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let scheduler = fixture.start().await.unwrap();
        (fixture, scheduler)
    }

    async fn assert_mismatched_recurring_unchanged(
        fixture: &SchedulerFixture,
        scheduler: &CampaignScheduler,
        manager_before: &Schedule,
        file_before: &[u8],
        receipt_before: &ScheduleOccurrenceRecord,
    ) {
        assert!(matches!(
            scheduler.list_one_time_recoveries().await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        assert!(matches!(
            scheduler
                .acknowledge_one_time_recovery("occ-mismatch")
                .await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        assert_eq!(
            serde_json::to_value(scheduler.manager.get_schedule("recurring").await.unwrap())
                .unwrap(),
            serde_json::to_value(manager_before).unwrap()
        );
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), file_before);
        assert_eq!(
            &fixture
                .store
                .as_ref()
                .unwrap()
                .schedule_occurrence("occ-mismatch")
                .await
                .unwrap()
                .unwrap(),
            receipt_before
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum RacedScheduleMutation {
        Remove,
        SetEnabled(bool),
    }

    impl RacedScheduleMutation {
        fn initial_enabled(self) -> bool {
            match self {
                Self::Remove | Self::SetEnabled(false) => true,
                Self::SetEnabled(true) => false,
            }
        }
    }

    async fn apply_raced_schedule_mutation(
        scheduler: Arc<CampaignScheduler>,
        mutation: RacedScheduleMutation,
    ) -> Result<bool, CampaignSchedulerError> {
        match mutation {
            RacedScheduleMutation::Remove => scheduler.try_remove("recurring").await,
            RacedScheduleMutation::SetEnabled(enabled) => {
                scheduler.try_set_enabled("recurring", enabled).await
            }
        }
    }

    async fn start_runtime_mismatch_race(
        mutation: RacedScheduleMutation,
    ) -> (
        SchedulerFixture,
        Arc<CampaignScheduler>,
        Schedule,
        Vec<u8>,
        ScheduleOccurrenceRecord,
    ) {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_event_with_enabled("recurring", mutation.initial_enabled());
        let scheduler = Arc::new(fixture.start().await.unwrap());
        fixture
            .reserve_expired_receipt(
                "recurring",
                "occ-mismatch",
                "exec-mismatch",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let manager_before = scheduler.manager.get_schedule("recurring").await.unwrap();
        let file_before = std::fs::read(&fixture.schedules_path).unwrap();
        let receipt_before = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();
        (
            fixture,
            scheduler,
            manager_before,
            file_before,
            receipt_before,
        )
    }

    async fn assert_quarantine_wins_schedule_mutation_race(mutation: RacedScheduleMutation) {
        let (fixture, scheduler, manager_before, file_before, receipt_before) =
            start_runtime_mismatch_race(mutation).await;
        let hook = Arc::new(ScheduleRaceHook::new());
        scheduler
            .schedules
            .set_direct_mutation_hook(Some(Arc::clone(&hook)));
        let mutation_task = tokio::spawn(apply_raced_schedule_mutation(
            Arc::clone(&scheduler),
            mutation,
        ));

        hook.wait_until_paused().await;
        assert!(matches!(
            scheduler.list_one_time_recoveries().await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        hook.resume().await;
        let mutation_result = mutation_task.await.unwrap();
        scheduler.schedules.set_direct_mutation_hook(None);

        assert!(
            matches!(
                mutation_result,
                Err(CampaignSchedulerError::OccurrenceJournal(_))
            ),
            "quarantine must reject {mutation:?} before manager mutation"
        );
        assert_mismatched_recurring_unchanged(
            &fixture,
            &scheduler,
            &manager_before,
            &file_before,
            &receipt_before,
        )
        .await;
        scheduler.stop().await;
    }

    async fn assert_mutation_wins_schedule_quarantine_race(mutation: RacedScheduleMutation) {
        let (fixture, scheduler, _manager_before, _file_before, receipt_before) =
            start_runtime_mismatch_race(mutation).await;
        let hook = Arc::new(ScheduleRaceHook::new());
        scheduler
            .schedules
            .set_quarantine_hook(Some(Arc::clone(&hook)));
        let refresh_scheduler = Arc::clone(&scheduler);
        let refresh_task =
            tokio::spawn(async move { refresh_scheduler.list_one_time_recoveries().await });

        hook.wait_until_paused().await;
        let mutation_result = apply_raced_schedule_mutation(Arc::clone(&scheduler), mutation).await;
        assert!(
            mutation_result.unwrap(),
            "{mutation:?} must complete before quarantine capture"
        );
        hook.resume().await;
        assert!(matches!(
            refresh_task.await.unwrap(),
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        scheduler.schedules.set_quarantine_hook(None);

        let receipt_after_mutation = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt_after_mutation, receipt_before);
        let durable = load_schedules(&fixture.schedules_path).unwrap();
        match mutation {
            RacedScheduleMutation::Remove => {
                assert!(scheduler.manager.get_schedule("recurring").await.is_none());
                assert!(!durable.iter().any(|schedule| schedule.id == "recurring"));

                let recoveries = scheduler.list_one_time_recoveries().await.unwrap();
                assert_eq!(recoveries.len(), 1);
                assert_eq!(recoveries[0].occurrence_id, "occ-mismatch");
                assert!(!recoveries[0].schedule_exists);
                let acknowledged = scheduler
                    .acknowledge_one_time_recovery("occ-mismatch")
                    .await
                    .unwrap();
                assert_eq!(acknowledged.state, "cancelled");
                assert!(!acknowledged.schedule_exists);
                assert_eq!(
                    fixture
                        .store
                        .as_ref()
                        .unwrap()
                        .schedule_occurrence("occ-mismatch")
                        .await
                        .unwrap()
                        .unwrap()
                        .state,
                    "cancelled"
                );
            }
            RacedScheduleMutation::SetEnabled(enabled) => {
                let manager_schedule = scheduler.manager.get_schedule("recurring").await.unwrap();
                assert_eq!(manager_schedule.enabled, enabled);
                let durable_schedule = durable
                    .iter()
                    .find(|schedule| schedule.id == "recurring")
                    .unwrap();
                assert_eq!(durable_schedule.enabled, enabled);
                assert_eq!(
                    serde_json::to_value(durable_schedule).unwrap(),
                    serde_json::to_value(manager_schedule).unwrap()
                );
                assert!(matches!(
                    scheduler.list_one_time_recoveries().await,
                    Err(CampaignSchedulerError::OccurrenceJournal(_))
                ));
                assert!(matches!(
                    scheduler
                        .acknowledge_one_time_recovery("occ-mismatch")
                        .await,
                    Err(CampaignSchedulerError::OccurrenceJournal(_))
                ));
                assert_eq!(
                    fixture
                        .store
                        .as_ref()
                        .unwrap()
                        .schedule_occurrence("occ-mismatch")
                        .await
                        .unwrap()
                        .unwrap(),
                    receipt_before
                );
            }
        }
        scheduler.stop().await;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RaceContenderPosition {
        HookReached,
        WaitingForAdmission,
    }

    async fn wait_for_hook_or_admission_waiter(
        scheduler: &CampaignScheduler,
        hook: &ScheduleRaceHook,
    ) -> RaceContenderPosition {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if hook.reached() {
                    return RaceContenderPosition::HookReached;
                }
                if scheduler.schedules.mutation_admission_waiters() > 0 {
                    return RaceContenderPosition::WaitingForAdmission;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("race contender did not reach its synchronization point")
    }

    async fn apply_raced_one_time_mutation(
        scheduler: Arc<CampaignScheduler>,
        mutation: RacedScheduleMutation,
    ) -> Result<bool, CampaignSchedulerError> {
        match mutation {
            RacedScheduleMutation::Remove => scheduler.try_remove("once").await,
            RacedScheduleMutation::SetEnabled(enabled) => {
                scheduler.try_set_enabled("once", enabled).await
            }
        }
    }

    async fn start_acknowledgement_mutation_race(
        mutation: RacedScheduleMutation,
    ) -> (SchedulerFixture, Arc<CampaignScheduler>) {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time_with_enabled("once", mutation.initial_enabled());
        fixture
            .reserve_expired_receipt(
                "once",
                "occ-race",
                "exec-race",
                OneTimeOccurrenceState::Running,
            )
            .await;
        let scheduler = Arc::new(fixture.start().await.unwrap());
        (fixture, scheduler)
    }

    async fn assert_acknowledgement_mutation_race_result(
        fixture: &SchedulerFixture,
        scheduler: &CampaignScheduler,
        mutation: RacedScheduleMutation,
        mutation_won: bool,
        mutation_result: Result<bool, CampaignSchedulerError>,
        acknowledged: OneTimeRecoveryView,
    ) {
        assert!(mutation_result.unwrap());
        assert_eq!(acknowledged.state, "cancelled");
        if mutation_won && matches!(mutation, RacedScheduleMutation::Remove) {
            assert!(!acknowledged.schedule_exists);
        }

        let durable = load_schedules(&fixture.schedules_path).unwrap();
        match mutation {
            RacedScheduleMutation::Remove => {
                assert!(scheduler.manager.get_schedule("once").await.is_none());
                assert!(!durable.iter().any(|schedule| schedule.id == "once"));
            }
            RacedScheduleMutation::SetEnabled(enabled) => {
                let current = scheduler.manager.get_schedule("once").await.unwrap();
                let persisted = durable
                    .iter()
                    .find(|schedule| schedule.id == "once")
                    .unwrap();
                assert_eq!(current.enabled, enabled);
                assert_eq!(persisted.enabled, enabled);
                assert_eq!(
                    serde_json::to_value(persisted).unwrap(),
                    serde_json::to_value(current).unwrap()
                );
            }
        }
        assert_eq!(
            fixture
                .store
                .as_ref()
                .unwrap()
                .schedule_occurrence("occ-race")
                .await
                .unwrap()
                .unwrap()
                .state,
            "cancelled"
        );
    }

    async fn assert_acknowledgement_wins_mutation_race(mutation: RacedScheduleMutation) {
        let (fixture, scheduler) = start_acknowledgement_mutation_race(mutation).await;
        let acknowledgement_hook = Arc::new(ScheduleRaceHook::new());
        let mutation_hook = Arc::new(ScheduleRaceHook::new());
        scheduler
            .schedules
            .set_acknowledgement_cursor_hook(Some(Arc::clone(&acknowledgement_hook)));
        scheduler
            .schedules
            .set_direct_mutation_admitted_hook(Some(Arc::clone(&mutation_hook)));

        let acknowledgement_scheduler = Arc::clone(&scheduler);
        let acknowledgement_task = tokio::spawn(async move {
            acknowledgement_scheduler
                .acknowledge_one_time_recovery("occ-race")
                .await
        });
        acknowledgement_hook.wait_until_paused().await;

        let mutation_task = tokio::spawn(apply_raced_one_time_mutation(
            Arc::clone(&scheduler),
            mutation,
        ));
        let contender_position =
            wait_for_hook_or_admission_waiter(&scheduler, &mutation_hook).await;
        if contender_position == RaceContenderPosition::HookReached {
            mutation_hook.wait_until_paused().await;
        }

        acknowledgement_hook.resume().await;
        let acknowledged = acknowledgement_task.await.unwrap().unwrap();
        if contender_position == RaceContenderPosition::WaitingForAdmission {
            mutation_hook.wait_until_paused().await;
        }
        mutation_hook.resume().await;
        let mutation_result = mutation_task.await.unwrap();
        scheduler.schedules.set_acknowledgement_cursor_hook(None);
        scheduler.schedules.set_direct_mutation_admitted_hook(None);

        assert_acknowledgement_mutation_race_result(
            &fixture,
            &scheduler,
            mutation,
            false,
            mutation_result,
            acknowledged,
        )
        .await;
        scheduler.stop().await;
    }

    async fn assert_mutation_wins_acknowledgement_race(mutation: RacedScheduleMutation) {
        let (fixture, scheduler) = start_acknowledgement_mutation_race(mutation).await;
        let acknowledgement_hook = Arc::new(ScheduleRaceHook::new());
        let mutation_hook = Arc::new(ScheduleRaceHook::new());
        scheduler
            .schedules
            .set_acknowledgement_cursor_hook(Some(Arc::clone(&acknowledgement_hook)));
        scheduler
            .schedules
            .set_direct_mutation_admitted_hook(Some(Arc::clone(&mutation_hook)));

        let mutation_task = tokio::spawn(apply_raced_one_time_mutation(
            Arc::clone(&scheduler),
            mutation,
        ));
        mutation_hook.wait_until_paused().await;

        let acknowledgement_scheduler = Arc::clone(&scheduler);
        let acknowledgement_task = tokio::spawn(async move {
            acknowledgement_scheduler
                .acknowledge_one_time_recovery("occ-race")
                .await
        });
        let contender_position =
            wait_for_hook_or_admission_waiter(&scheduler, &acknowledgement_hook).await;
        if contender_position == RaceContenderPosition::HookReached {
            acknowledgement_hook.wait_until_paused().await;
        }

        mutation_hook.resume().await;
        let mutation_result = mutation_task.await.unwrap();
        if contender_position == RaceContenderPosition::WaitingForAdmission {
            acknowledgement_hook.wait_until_paused().await;
        }
        acknowledgement_hook.resume().await;
        let acknowledged = acknowledgement_task.await.unwrap().unwrap();
        scheduler.schedules.set_acknowledgement_cursor_hook(None);
        scheduler.schedules.set_direct_mutation_admitted_hook(None);

        assert_acknowledgement_mutation_race_result(
            &fixture,
            &scheduler,
            mutation,
            true,
            mutation_result,
            acknowledged,
        )
        .await;
        scheduler.stop().await;
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
        let fixture = scheduler_fixture_without_store();
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
    async fn identifiable_malformed_receipt_quarantines_schedule_before_snapshot_writes() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_event("affected-recurring");
        let original = load_schedules(&fixture.schedules_path).unwrap().remove(0);
        let store = fixture.store.as_ref().unwrap();
        sqlx::query(
            "INSERT INTO schedule_occurrences
                (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
             VALUES
                ('occ-malformed', 'affected-recurring', 'exec-malformed',
                 'not-rfc3339', 'completed', 'owner', NULL)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let history_at = Utc::now() - chrono::Duration::minutes(1);
        let history = schedule_execution(
            "history-affected",
            "affected-recurring",
            history_at,
            ExecutionStatus::Completed,
        );
        store
            .upsert_schedule_execution(
                &history.execution_id,
                &history.schedule_id,
                &history.triggered_at.to_rfc3339(),
                &history.status.to_string(),
                &serde_json::to_string(&history).unwrap(),
            )
            .await
            .unwrap();

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            serde_json::to_value(
                load_schedules(&fixture.schedules_path)
                    .unwrap()
                    .iter()
                    .find(|schedule| schedule.id == original.id)
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&original).unwrap()
        );

        assert_eq!(
            scheduler
                .manager
                .emit_event(IncomingEvent {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    payload: None,
                    timestamp: Utc::now(),
                })
                .await,
            vec!["affected-recurring"]
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while scheduler
                .manager
                .execution_history("affected-recurring")
                .await
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("quarantined recurring schedule did not execute in memory");

        let unrelated = scheduler
            .try_create(
                "unrelated",
                &fixture.params(),
                TriggerConfig::Event {
                    event_type: EVENT_CRASH_FOUND.to_owned(),
                    debounce_secs: 0,
                    filter: None,
                },
            )
            .await
            .unwrap();
        let durable = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(
            serde_json::to_value(
                durable
                    .iter()
                    .find(|schedule| schedule.id == original.id)
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert!(durable.iter().any(|schedule| schedule.id == unrelated.id));
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT triggered_at FROM schedule_occurrences WHERE id = 'occ-malformed'",
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
            "not-rfc3339"
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn undecodable_receipt_identity_preserves_the_complete_startup_snapshot() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_event("first-recurring");
        fixture.write_event("second-recurring");
        let originals = load_schedules(&fixture.schedules_path).unwrap();
        let store = fixture.store.as_ref().unwrap();
        sqlx::query(
            "INSERT INTO schedule_occurrences
                (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
             VALUES
                ('occ-undecodable', x'ff', 'exec-undecodable',
                 '2026-07-30T00:00:00Z', 'completed', 'owner', NULL)",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let history_at = Utc::now() - chrono::Duration::minutes(1);
        let history = schedule_execution(
            "history-first",
            "first-recurring",
            history_at,
            ExecutionStatus::Completed,
        );
        store
            .upsert_schedule_execution(
                &history.execution_id,
                &history.schedule_id,
                &history.triggered_at.to_rfc3339(),
                &history.status.to_string(),
                &serde_json::to_string(&history).unwrap(),
            )
            .await
            .unwrap();

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            serde_json::to_value(load_schedules(&fixture.schedules_path).unwrap()).unwrap(),
            serde_json::to_value(&originals).unwrap()
        );
        let fired = scheduler
            .manager
            .emit_event(IncomingEvent {
                event_type: EVENT_RUN_COMPLETED.to_owned(),
                payload: None,
                timestamp: Utc::now(),
            })
            .await;
        assert_eq!(fired, ["first-recurring", "second-recurring"]);
        tokio::time::timeout(Duration::from_secs(2), async {
            while scheduler
                .manager
                .execution_history("first-recurring")
                .await
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("recurring schedule did not execute under global one-time block");

        let unrelated = scheduler
            .try_create(
                "unrelated",
                &fixture.params(),
                TriggerConfig::Event {
                    event_type: EVENT_CRASH_FOUND.to_owned(),
                    debounce_secs: 0,
                    filter: None,
                },
            )
            .await
            .unwrap();
        let durable = load_schedules(&fixture.schedules_path).unwrap();
        for original in &originals {
            assert_eq!(
                serde_json::to_value(
                    durable
                        .iter()
                        .find(|schedule| schedule.id == original.id)
                        .unwrap()
                )
                .unwrap(),
                serde_json::to_value(original).unwrap()
            );
        }
        assert!(durable.iter().any(|schedule| schedule.id == unrelated.id));
        assert_eq!(
            sqlx::query_as::<_, (String, String)>(
                "SELECT typeof(schedule_id), hex(schedule_id)
                 FROM schedule_occurrences WHERE id = 'occ-undecodable'",
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
            ("blob".to_owned(), "FF".to_owned())
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn receipt_attached_to_recurring_schedule_is_quarantined_without_stopping_dispatch() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_event("recurring");
        fixture
            .reserve_expired_receipt(
                "recurring",
                "occ-mismatch",
                "exec-mismatch",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let before = std::fs::read(&fixture.schedules_path).unwrap();

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            scheduler
                .manager
                .emit_event(IncomingEvent {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    payload: None,
                    timestamp: Utc::now(),
                })
                .await,
            vec!["recurring"]
        );
        wait_for_execution(&scheduler, "recurring").await;

        assert!(matches!(
            scheduler
                .acknowledge_one_time_recovery("occ-mismatch")
                .await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        assert!(matches!(
            scheduler.list_one_time_recoveries().await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        let receipt = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "reserved");
        assert_eq!(receipt.execution_status.as_deref(), Some("pending"));
        assert_eq!(std::fs::read(&fixture.schedules_path).unwrap(), before);
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn full_snapshot_preserves_quarantined_schedule_during_unrelated_mutations() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_event("recurring");
        fixture
            .reserve_expired_receipt(
                "recurring",
                "occ-mismatch",
                "exec-mismatch",
                OneTimeOccurrenceState::Reserved,
            )
            .await;
        let original = load_schedules(&fixture.schedules_path).unwrap().remove(0);

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            scheduler
                .manager
                .emit_event(IncomingEvent {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    payload: None,
                    timestamp: Utc::now(),
                })
                .await,
            vec!["recurring"]
        );
        wait_for_execution_count(&scheduler, "recurring", 1).await;
        assert!(scheduler
            .manager
            .get_schedule("recurring")
            .await
            .unwrap()
            .last_fire
            .is_some());

        let created = scheduler
            .try_create(
                "unrelated",
                &fixture.params(),
                TriggerConfig::Interval { interval_secs: 60 },
            )
            .await
            .unwrap();
        let durable = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(
            serde_json::to_value(
                durable
                    .iter()
                    .find(|schedule| schedule.id == "recurring")
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert!(durable.iter().any(|schedule| schedule.id == created.id));

        assert!(scheduler.try_set_enabled(&created.id, false).await.unwrap());
        let durable = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(
            serde_json::to_value(
                durable
                    .iter()
                    .find(|schedule| schedule.id == "recurring")
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert!(
            !durable
                .iter()
                .find(|schedule| schedule.id == created.id)
                .unwrap()
                .enabled
        );

        assert!(scheduler.try_remove(&created.id).await.unwrap());
        let durable = load_schedules(&fixture.schedules_path).unwrap();
        assert_eq!(
            serde_json::to_value(
                durable
                    .iter()
                    .find(|schedule| schedule.id == "recurring")
                    .unwrap()
            )
            .unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert!(!durable.iter().any(|schedule| schedule.id == created.id));

        assert_eq!(
            scheduler
                .manager
                .emit_event(IncomingEvent {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    payload: None,
                    timestamp: Utc::now(),
                })
                .await,
            vec!["recurring"]
        );
        wait_for_execution_count(&scheduler, "recurring", 2).await;
        let receipt = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state, "reserved");
        assert_eq!(receipt.execution_status.as_deref(), Some("pending"));
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn schedule_mutation_quarantine_race_quarantine_wins_remove() {
        assert_quarantine_wins_schedule_mutation_race(RacedScheduleMutation::Remove).await;
    }

    #[tokio::test]
    async fn schedule_mutation_quarantine_race_quarantine_wins_disable() {
        assert_quarantine_wins_schedule_mutation_race(RacedScheduleMutation::SetEnabled(false))
            .await;
    }

    #[tokio::test]
    async fn schedule_mutation_quarantine_race_quarantine_wins_enable() {
        assert_quarantine_wins_schedule_mutation_race(RacedScheduleMutation::SetEnabled(true))
            .await;
    }

    #[tokio::test]
    async fn schedule_mutation_quarantine_race_remove_completes_before_capture() {
        assert_mutation_wins_schedule_quarantine_race(RacedScheduleMutation::Remove).await;
    }

    #[tokio::test]
    async fn schedule_mutation_quarantine_race_disable_completes_before_capture() {
        assert_mutation_wins_schedule_quarantine_race(RacedScheduleMutation::SetEnabled(false))
            .await;
    }

    #[tokio::test]
    async fn schedule_mutation_quarantine_race_enable_completes_before_capture() {
        assert_mutation_wins_schedule_quarantine_race(RacedScheduleMutation::SetEnabled(true))
            .await;
    }

    #[tokio::test]
    async fn acknowledgement_remove_race_acknowledgement_wins() {
        assert_acknowledgement_wins_mutation_race(RacedScheduleMutation::Remove).await;
    }

    #[tokio::test]
    async fn acknowledgement_remove_race_mutation_wins() {
        assert_mutation_wins_acknowledgement_race(RacedScheduleMutation::Remove).await;
    }

    #[tokio::test]
    async fn acknowledgement_disable_race_acknowledgement_wins() {
        assert_acknowledgement_wins_mutation_race(RacedScheduleMutation::SetEnabled(false)).await;
    }

    #[tokio::test]
    async fn acknowledgement_disable_race_mutation_wins() {
        assert_mutation_wins_acknowledgement_race(RacedScheduleMutation::SetEnabled(false)).await;
    }

    #[tokio::test]
    async fn acknowledgement_enable_race_acknowledgement_wins() {
        assert_acknowledgement_wins_mutation_race(RacedScheduleMutation::SetEnabled(true)).await;
    }

    #[tokio::test]
    async fn acknowledgement_enable_race_mutation_wins() {
        assert_mutation_wins_acknowledgement_race(RacedScheduleMutation::SetEnabled(true)).await;
    }

    #[tokio::test]
    async fn quarantined_schedule_direct_remove_is_rejected_before_manager_mutation() {
        let (fixture, scheduler) = start_mismatched_recurring(true).await;
        let file_before = std::fs::read(&fixture.schedules_path).unwrap();
        let manager_before = scheduler.manager.get_schedule("recurring").await.unwrap();
        let receipt_before = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            scheduler.try_remove("recurring").await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        assert_mismatched_recurring_unchanged(
            &fixture,
            &scheduler,
            &manager_before,
            &file_before,
            &receipt_before,
        )
        .await;
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn quarantined_schedule_direct_disable_is_rejected_before_manager_mutation() {
        let (fixture, scheduler) = start_mismatched_recurring(true).await;
        let file_before = std::fs::read(&fixture.schedules_path).unwrap();
        let manager_before = scheduler.manager.get_schedule("recurring").await.unwrap();
        let receipt_before = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            scheduler.try_set_enabled("recurring", false).await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        assert_mismatched_recurring_unchanged(
            &fixture,
            &scheduler,
            &manager_before,
            &file_before,
            &receipt_before,
        )
        .await;
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn quarantined_schedule_direct_enable_is_rejected_before_manager_mutation() {
        let (fixture, scheduler) = start_mismatched_recurring(false).await;
        let file_before = std::fs::read(&fixture.schedules_path).unwrap();
        let manager_before = scheduler.manager.get_schedule("recurring").await.unwrap();
        let receipt_before = fixture
            .store
            .as_ref()
            .unwrap()
            .schedule_occurrence("occ-mismatch")
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(
            scheduler.try_set_enabled("recurring", true).await,
            Err(CampaignSchedulerError::OccurrenceJournal(_))
        ));
        assert_mismatched_recurring_unchanged(
            &fixture,
            &scheduler,
            &manager_before,
            &file_before,
            &receipt_before,
        )
        .await;
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn post_start_journal_failure_blocks_new_one_time_work_but_not_recurring_dispatch() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_future_one_time("once");
        fixture.write_event("recurring");
        let scheduler = fixture.start().await.unwrap();
        fixture.store.as_ref().unwrap().pool().close().await;

        scheduler
            .manager
            .trigger_sender()
            .unwrap()
            .send(FiredTrigger {
                schedule_id: "once".to_owned(),
                fired_at: Utc::now(),
                trigger_type: TriggerType::OneTime,
                is_recovery: false,
                event_payload: None,
            })
            .await
            .unwrap();
        assert_eq!(
            wait_for_one_time_block(&scheduler).await,
            JOURNAL_UNAVAILABLE_REASON
        );
        assert!(matches!(
            scheduler
                .try_create("new once", &fixture.params(), due_trigger())
                .await,
            Err(CampaignSchedulerError::DurabilityUnavailable(_))
        ));

        assert_eq!(
            scheduler
                .manager
                .emit_event(IncomingEvent {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    payload: None,
                    timestamp: Utc::now(),
                })
                .await,
            vec!["recurring"]
        );
        wait_for_execution(&scheduler, "recurring").await;
        assert!(scheduler.manager.is_running());
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn one_time_creation_first_probes_a_post_start_journal_outage() {
        let fixture = scheduler_fixture_with_store().await;
        let scheduler = fixture.start().await.unwrap();
        let file_before = std::fs::read(&fixture.schedules_path).ok();
        let schedule_ids_before: Vec<_> = scheduler
            .list()
            .await
            .into_iter()
            .map(|schedule| schedule.id)
            .collect();
        fixture.store.as_ref().unwrap().pool().close().await;

        assert!(matches!(
            scheduler
                .try_create("new once", &fixture.params(), due_trigger())
                .await,
            Err(CampaignSchedulerError::DurabilityUnavailable(_))
        ));
        assert_eq!(
            scheduler.manager.one_time_block_reason().await.as_deref(),
            Some(JOURNAL_UNAVAILABLE_REASON)
        );
        assert_eq!(
            scheduler
                .list()
                .await
                .into_iter()
                .map(|schedule| schedule.id)
                .collect::<Vec<_>>(),
            schedule_ids_before
        );
        assert_eq!(std::fs::read(&fixture.schedules_path).ok(), file_before);

        let recurring = scheduler
            .try_create(
                "recurring remains live",
                &fixture.params(),
                TriggerConfig::Event {
                    event_type: EVENT_RUN_COMPLETED.to_owned(),
                    debounce_secs: 0,
                    filter: None,
                },
            )
            .await
            .unwrap();
        assert!(scheduler
            .manager
            .get_schedule(&recurring.id)
            .await
            .is_some());
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn foreign_live_receipt_becomes_recovery_required_when_its_lease_expires() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("once");
        fixture
            .reserve_live_receipt("once", "occ-live", "exec-live")
            .await;
        fixture
            .store
            .as_ref()
            .unwrap()
            .renew_schedule_occurrence_lease(
                "occ-live",
                "fixture-owner",
                &(Utc::now() + chrono::Duration::seconds(2)).to_rfc3339(),
            )
            .await
            .unwrap();

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            scheduler.list_views().await.unwrap()[0].durability_status,
            CampaignDurabilityStatus::Consumed
        );
        let mut recoveries = Vec::new();
        for _ in 0..200 {
            recoveries = scheduler.list_one_time_recoveries().await.unwrap();
            if !recoveries.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!recoveries.is_empty(), "live receipt lease did not expire");
        assert_eq!(recoveries[0].occurrence_id, "occ-live");
        assert_eq!(
            scheduler.list_views().await.unwrap()[0].durability_status,
            CampaignDurabilityStatus::RecoveryRequired
        );
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn occurrence_column_decode_failure_is_classified_as_corrupt_journal_data() {
        let fixture = scheduler_fixture_with_store().await;
        fixture.write_due_one_time("once");
        fixture
            .reserve_live_receipt("once", "occ-invalid-type", "exec-invalid-type")
            .await;
        sqlx::query(
            "UPDATE schedule_occurrences SET owner_id = X'80' WHERE id = 'occ-invalid-type'",
        )
        .execute(fixture.store.as_ref().unwrap().pool())
        .await
        .unwrap();

        let scheduler = fixture.start().await.unwrap();
        assert_eq!(
            scheduler.manager.one_time_block_reason().await.as_deref(),
            Some(JOURNAL_CORRUPT_REASON)
        );
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
        let database_path = fixture.directory.path().join("scheduler.db");
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

    #[test]
    fn recovery_public_errors_have_stable_codes_and_redacted_messages() {
        let unavailable = CampaignSchedulerError::State(StateFileError::Io {
            operation: "replace",
            path: PathBuf::from("/PRIVATE_PATH_MARKER/schedules.json"),
            source: std::io::Error::other("OS_PRIVATE_MARKER"),
        })
        .into_public_recovery_error();
        assert_eq!(unavailable.code, RecoveryPublicErrorCode::Unavailable);
        assert_eq!(
            unavailable.message,
            "one-time recovery is temporarily unavailable"
        );
        let serialized = serde_json::to_string(&unavailable).unwrap();
        assert!(!serialized.contains("PRIVATE_PATH_MARKER"));
        assert!(!serialized.contains("OS_PRIVATE_MARKER"));

        for detailed in [
            CampaignSchedulerError::RetiredScheduleArchive {
                schedule_ids: "PRIVATE_ID_MARKER".to_owned(),
                reason: "/PRIVATE_PATH_MARKER/PRIVATE_REASON_MARKER".to_owned(),
            },
            CampaignSchedulerError::RetiredScheduleReceipt {
                schedule_ids: "PRIVATE_ID_MARKER".to_owned(),
                reason: "/PRIVATE_PATH_MARKER/PRIVATE_REASON_MARKER".to_owned(),
            },
            CampaignSchedulerError::RetiredScheduleRestore {
                engine: hf_core::retired_engine::RETIRED_ENGINE_ID,
                schedule_ids: "PRIVATE_ID_MARKER".to_owned(),
            },
        ] {
            let public = detailed.into_public_recovery_error();
            let serialized = serde_json::to_string(&public).unwrap();
            assert!(!serialized.contains("PRIVATE_ID_MARKER"));
            assert!(!serialized.contains("PRIVATE_PATH_MARKER"));
            assert!(!serialized.contains("PRIVATE_REASON_MARKER"));
        }

        assert_eq!(
            CampaignSchedulerError::OccurrenceNotFound("PRIVATE_ID".to_owned())
                .into_public_recovery_error()
                .code,
            RecoveryPublicErrorCode::NotFound
        );
        assert_eq!(
            CampaignSchedulerError::OccurrenceConflict("PRIVATE_STATE".to_owned())
                .into_public_recovery_error()
                .code,
            RecoveryPublicErrorCode::Conflict
        );
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
        let persistence = CampaignSchedulerPersistence::new(None, repository, 100, Weak::new());

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
        let persistence =
            CampaignSchedulerPersistence::new(Some(Arc::clone(&store)), repository, 2, Weak::new());
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
