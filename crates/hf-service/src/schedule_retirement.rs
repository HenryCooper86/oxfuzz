//! Durable one-time retirement protocol for file-backed campaign schedules.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use hf_scheduler::Schedule;
use hf_storage::{
    validate_schedule_retirement_manifest, validate_schedule_retirement_operation_id, Store,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::campaign_state::{atomic_write_json, StateFileError};
use crate::scheduler::CampaignSchedulerError;

const RECEIPT_VERSION: u32 = 2;
const COMPLETION_VERSION: u32 = 1;
const MAX_RECEIPT_SCHEDULES: usize = 4_096;
const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCHEDULE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SCHEDULE_ID_BYTES: usize = 512;
const MAX_ERROR_IDS: usize = 20;
const MAX_ERROR_ID_CHARS: usize = 128;
const MAX_ERROR_DETAIL_CHARS: usize = 1_024;
const SCHEDULE_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const SCHEDULE_LOCK_POLL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy)]
pub(crate) enum RetirementStorage<'a> {
    Available(&'a Store),
    NotConfigured,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetiredScheduleRetirementState {
    ArchivePending,
    HistoryPending,
    ActiveRewritePending,
    CompletionPending,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoryRequirement {
    Database,
    NotConfigured,
    NoRetiredSchedules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HistoryProofPhase {
    BeforeHistory,
    HistoryMayBeCommitted,
    HistoryMustBeCommitted,
}

struct ReconciledAuthorities {
    permanently_retired_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleImage {
    present: bool,
    schedules: Vec<Schedule>,
    canonical_digest: String,
    byte_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduleSnapshot {
    schedule: Schedule,
    canonical_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementPlan {
    retired: Vec<ScheduleSnapshot>,
    active_pre: ScheduleImage,
    active_post: ScheduleImage,
    archive_pre: ScheduleImage,
    archive_post: ScheduleImage,
    history: HistoryRequirement,
}

#[derive(Serialize)]
struct OperationPlanBinding<'a> {
    operation_id: &'a str,
    plan: &'a RetirementPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetiredScheduleRetirementReceipt {
    pub(crate) version: u32,
    pub(crate) state: RetiredScheduleRetirementState,
    pub(crate) operation_id: String,
    pub(crate) plan_digest: String,
    plan: RetirementPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementCompletion {
    version: u32,
    operation_id: String,
    plan_digest: String,
    active_post_digest: String,
    archive_post_digest: String,
    history: HistoryRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScheduleGeneration {
    present: bool,
    byte_digest: String,
}

pub(crate) struct RetirementOutcome {
    pub(crate) schedules: Vec<Schedule>,
    pub(crate) permanently_retired_ids: Vec<String>,
    #[cfg(test)]
    pub(crate) retired_ids: Vec<String>,
    pub(crate) generation: ScheduleGeneration,
    pub(crate) lease: Option<SchedulePathLease>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleRetirementFailurePoint {
    Receipt(RetiredScheduleRetirementState),
    ActiveRewrite,
    CompletionCertificate,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScheduleRetirementPausePoint {
    Receipt(RetiredScheduleRetirementState),
    ArchiveWrite,
    HistoryArchive,
    ActiveRewrite,
    CompletionCertificate,
}

#[cfg(test)]
pub(crate) struct RetirementPauseHook {
    paused: tokio::sync::Barrier,
    resumed: tokio::sync::Barrier,
}

#[cfg(test)]
impl RetirementPauseHook {
    pub(crate) fn new() -> Self {
        Self {
            paused: tokio::sync::Barrier::new(2),
            resumed: tokio::sync::Barrier::new(2),
        }
    }

    async fn pause(&self) {
        self.paused.wait().await;
        self.resumed.wait().await;
    }

    pub(crate) async fn wait_until_paused(&self) {
        self.paused.wait().await;
    }

    pub(crate) async fn resume(&self) {
        self.resumed.wait().await;
    }
}

#[derive(Default)]
pub(crate) struct RetirementFaults {
    failure: Mutex<Option<ScheduleRetirementFailurePoint>>,
    #[cfg(test)]
    pause: Mutex<Option<(ScheduleRetirementPausePoint, Arc<RetirementPauseHook>)>>,
}

impl RetirementFaults {
    #[cfg(test)]
    pub(crate) fn set(&self, failure: Option<ScheduleRetirementFailurePoint>) {
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = failure;
    }

    #[cfg(test)]
    pub(crate) fn set_pause(
        &self,
        point: ScheduleRetirementPausePoint,
        hook: Arc<RetirementPauseHook>,
    ) {
        *self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((point, hook));
    }

    #[cfg(test)]
    async fn pause_at(&self, point: ScheduleRetirementPausePoint) {
        let hook = self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .filter(|(configured, _)| *configured == point)
            .map(|(_, hook)| Arc::clone(hook));
        if let Some(hook) = hook {
            hook.pause().await;
        }
    }

    fn inject(&self, point: ScheduleRetirementFailurePoint) -> Result<(), CampaignSchedulerError> {
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if failure.as_ref() == Some(&point) {
            *failure = None;
            return Err(receipt_error(&[], "injected durable-phase failure"));
        }
        Ok(())
    }

    fn before_receipt(
        &self,
        state: RetiredScheduleRetirementState,
    ) -> Result<(), CampaignSchedulerError> {
        self.inject(ScheduleRetirementFailurePoint::Receipt(state))?;
        Ok(())
    }

    fn before_active_rewrite(&self) -> Result<(), CampaignSchedulerError> {
        self.inject(ScheduleRetirementFailurePoint::ActiveRewrite)?;
        Ok(())
    }

    fn before_completion_certificate(&self) -> Result<(), CampaignSchedulerError> {
        self.inject(ScheduleRetirementFailurePoint::CompletionCertificate)?;
        Ok(())
    }
}

pub(crate) struct SchedulePathLease {
    _process: tokio::sync::OwnedMutexGuard<()>,
    _file: File,
}

static PROCESS_PATH_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<tokio::sync::Mutex<()>>>>> =
    OnceLock::new();

pub(crate) async fn acquire_schedule_path_lease(
    schedules_path: &Path,
) -> Result<SchedulePathLease, StateFileError> {
    acquire_schedule_path_lease_with_timeout(schedules_path, SCHEDULE_LOCK_TIMEOUT).await
}

async fn acquire_schedule_path_lease_with_timeout(
    schedules_path: &Path,
    timeout: Duration,
) -> Result<SchedulePathLease, StateFileError> {
    let lock_path = schedule_lock_path(schedules_path);
    let process_path = absolute_lock_path(&lock_path);
    let deadline = tokio::time::Instant::now() + timeout;
    let process_lock = {
        let mut locks = PROCESS_PATH_LOCKS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&process_path).and_then(Weak::upgrade) {
            lock
        } else {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            locks.insert(process_path, Arc::downgrade(&lock));
            lock
        }
    };
    let process_guard = tokio::time::timeout_at(deadline, process_lock.lock_owned())
        .await
        .map_err(|_| lock_timeout_error(&lock_path))?;

    let parent = lock_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|source| StateFileError::Io {
        operation: "create lock directory for",
        path: lock_path.clone(),
        source,
    })?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| StateFileError::Io {
            operation: "open lock for",
            path: lock_path.clone(),
            source,
        })?;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(lock_timeout_error(&lock_path));
        }
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => break,
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(lock_timeout_error(&lock_path));
                }
                tokio::time::sleep_until(
                    deadline.min(tokio::time::Instant::now() + SCHEDULE_LOCK_POLL),
                )
                .await;
            }
            Err(source) => return Err(classify_lock_error(&lock_path, source)),
        }
    }
    Ok(SchedulePathLease {
        _process: process_guard,
        _file: file,
    })
}

fn absolute_lock_path(lock_path: &Path) -> PathBuf {
    if lock_path.is_absolute() {
        lock_path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(
            |_| lock_path.to_path_buf(),
            |directory| directory.join(lock_path),
        )
    }
}

fn lock_timeout_error(path: &Path) -> StateFileError {
    classify_lock_error(
        path,
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for the schedule advisory lock",
        ),
    )
}

fn classify_lock_error(path: &Path, source: std::io::Error) -> StateFileError {
    StateFileError::Io {
        operation: "lock",
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
pub(crate) fn process_lock_strong_count(schedules_path: &Path) -> usize {
    let path = absolute_lock_path(&schedule_lock_path(schedules_path));
    PROCESS_PATH_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&path)
        .map_or(0, Weak::strong_count)
}

#[cfg(test)]
fn process_lock_registry_contains(schedules_path: &Path) -> bool {
    let path = absolute_lock_path(&schedule_lock_path(schedules_path));
    PROCESS_PATH_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .contains_key(&path)
}

pub(crate) async fn retire(
    schedules_path: &Path,
    storage: RetirementStorage<'_>,
    faults: &RetirementFaults,
) -> Result<RetirementOutcome, CampaignSchedulerError> {
    let lease = acquire_schedule_path_lease(schedules_path).await?;
    let mut outcome = retire_with_lease(schedules_path, storage, faults).await?;
    outcome.lease = Some(lease);
    Ok(outcome)
}

async fn retire_with_lease(
    schedules_path: &Path,
    storage: RetirementStorage<'_>,
    faults: &RetirementFaults,
) -> Result<RetirementOutcome, CampaignSchedulerError> {
    let active = load_image(schedules_path)?;
    validate_unique_ids(&active.schedules, "active schedule file")?;
    validate_schedule_bounds(&active.schedules)?;
    let receipt_path = retired_schedule_retirement_path(schedules_path);
    let loaded_receipt = load_receipt(&receipt_path)?;
    if loaded_receipt.is_none() {
        validate_initial_retired_ids(&active.schedules)?;
    }
    let archive_path = retired_schedule_path(schedules_path);
    let archive = load_image(&archive_path)
        .map_err(|error| archive_error(&retired_ids(&active.schedules), error))?;
    validate_unique_ids(&archive.schedules, "retired schedule archive")?;
    validate_schedule_bounds(&archive.schedules)?;

    let mut receipt = if let Some(receipt) = loaded_receipt {
        validate_receipt(&receipt)?;
        receipt
    } else {
        reject_independent_evidence_without_receipt(
            schedules_path,
            &archive,
            storage,
            &active.schedules,
        )
        .await?;
        let receipt = initial_receipt(&active, &archive, storage)?;
        #[cfg(test)]
        faults
            .pause_at(ScheduleRetirementPausePoint::Receipt(receipt.state))
            .await;
        persist_receipt(&receipt_path, &receipt, faults)?;
        receipt
    };
    #[cfg(test)]
    let already_completed = matches!(receipt.state, RetiredScheduleRetirementState::Completed);

    loop {
        receipt = reload_expected_receipt(&receipt_path, &receipt)?;
        if receipt.state != RetiredScheduleRetirementState::Completed {
            if let Some(outcome) = reconcile_completed_evidence(
                schedules_path,
                storage,
                &receipt_path,
                &receipt,
                faults,
            )
            .await?
            {
                return Ok(outcome);
            }
        }
        let proof_phase = match receipt.state {
            RetiredScheduleRetirementState::ArchivePending => HistoryProofPhase::BeforeHistory,
            RetiredScheduleRetirementState::HistoryPending => {
                HistoryProofPhase::HistoryMayBeCommitted
            }
            RetiredScheduleRetirementState::ActiveRewritePending
            | RetiredScheduleRetirementState::CompletionPending
            | RetiredScheduleRetirementState::Completed => {
                HistoryProofPhase::HistoryMustBeCommitted
            }
        };
        let authorities = reconcile_durable_authorities(storage, &receipt, proof_phase).await?;
        let ids = receipt_ids(&receipt);
        match receipt.state {
            RetiredScheduleRetirementState::ArchivePending => {
                let current_active = load_image(schedules_path)?;
                require_active_preimage_or_restore(&current_active, &receipt)?;
                let current_archive =
                    load_image(&archive_path).map_err(|error| archive_error(&ids, error))?;
                validate_unique_ids(&current_archive.schedules, "retired schedule archive")?;
                if image_matches(&current_archive, &receipt.plan.archive_pre)? {
                    expected_written_generation(
                        &archive_path,
                        &receipt.plan.archive_post.schedules,
                    )
                    .map_err(|error| archive_error(&ids, error))?;
                    #[cfg(test)]
                    faults
                        .pause_at(ScheduleRetirementPausePoint::ArchiveWrite)
                        .await;
                    atomic_write_json(&archive_path, &receipt.plan.archive_post.schedules)
                        .map_err(|error| archive_error(&ids, error))?;
                    let written =
                        load_image(&archive_path).map_err(|error| archive_error(&ids, error))?;
                    require_image(&written, &receipt.plan.archive_post, &ids, "archive write")?;
                } else {
                    require_image(
                        &current_archive,
                        &receipt.plan.archive_post,
                        &ids,
                        "archive compare-and-swap",
                    )?;
                }
                #[cfg(test)]
                faults
                    .pause_at(ScheduleRetirementPausePoint::Receipt(
                        RetiredScheduleRetirementState::HistoryPending,
                    ))
                    .await;
                receipt = transition(
                    &receipt_path,
                    &receipt,
                    RetiredScheduleRetirementState::HistoryPending,
                    faults,
                )?;
            }
            RetiredScheduleRetirementState::HistoryPending => {
                let current_active = load_image(schedules_path)?;
                require_active_preimage_or_restore(&current_active, &receipt)?;
                require_archive_postimage(&archive_path, &receipt)?;
                #[cfg(test)]
                faults
                    .pause_at(ScheduleRetirementPausePoint::HistoryArchive)
                    .await;
                archive_history(storage, &receipt).await?;
                reconcile_durable_authorities(
                    storage,
                    &receipt,
                    HistoryProofPhase::HistoryMustBeCommitted,
                )
                .await?;
                #[cfg(test)]
                faults
                    .pause_at(ScheduleRetirementPausePoint::Receipt(
                        RetiredScheduleRetirementState::ActiveRewritePending,
                    ))
                    .await;
                receipt = transition(
                    &receipt_path,
                    &receipt,
                    RetiredScheduleRetirementState::ActiveRewritePending,
                    faults,
                )?;
            }
            RetiredScheduleRetirementState::ActiveRewritePending => {
                let current_active = load_image(schedules_path)?;
                if !image_matches(&current_active, &receipt.plan.active_pre)?
                    && !image_matches(&current_active, &receipt.plan.active_post)?
                {
                    return Err(active_third_state_error(&current_active.schedules, &ids));
                }
                require_archive_postimage(&archive_path, &receipt)?;
                if image_matches(&current_active, &receipt.plan.active_pre)? {
                    if !image_matches(&receipt.plan.active_pre, &receipt.plan.active_post)? {
                        #[cfg(test)]
                        faults
                            .pause_at(ScheduleRetirementPausePoint::ActiveRewrite)
                            .await;
                        faults.before_active_rewrite()?;
                        expected_written_generation(
                            schedules_path,
                            &receipt.plan.active_post.schedules,
                        )
                        .map_err(|error| archive_error(&ids, error))?;
                        atomic_write_json(schedules_path, &receipt.plan.active_post.schedules)
                            .map_err(|error| archive_error(&ids, error))?;
                    }
                    let written = load_image(schedules_path)?;
                    require_image(&written, &receipt.plan.active_post, &ids, "active rewrite")?;
                }
                #[cfg(test)]
                faults
                    .pause_at(ScheduleRetirementPausePoint::Receipt(
                        RetiredScheduleRetirementState::CompletionPending,
                    ))
                    .await;
                receipt = transition(
                    &receipt_path,
                    &receipt,
                    RetiredScheduleRetirementState::CompletionPending,
                    faults,
                )?;
            }
            RetiredScheduleRetirementState::CompletionPending => {
                let current_active = load_image(schedules_path)?;
                let prohibited = prohibited_active_ids(&current_active.schedules, &ids);
                if !prohibited.is_empty() {
                    return Err(permanently_retired_error(&prohibited));
                }
                require_image(
                    &current_active,
                    &receipt.plan.active_post,
                    &ids,
                    "completion active image",
                )?;
                require_archive_postimage(&archive_path, &receipt)?;
                #[cfg(test)]
                faults
                    .pause_at(ScheduleRetirementPausePoint::CompletionCertificate)
                    .await;
                ensure_completion_certificate(schedules_path, &receipt, faults)?;
                #[cfg(test)]
                faults
                    .pause_at(ScheduleRetirementPausePoint::Receipt(
                        RetiredScheduleRetirementState::Completed,
                    ))
                    .await;
                receipt = transition(
                    &receipt_path,
                    &receipt,
                    RetiredScheduleRetirementState::Completed,
                    faults,
                )?;
            }
            RetiredScheduleRetirementState::Completed => {
                let current_active = load_image(schedules_path)?;
                validate_unique_ids(&current_active.schedules, "active schedule file")?;
                let prohibited = prohibited_active_ids(
                    &current_active.schedules,
                    &authorities.permanently_retired_ids,
                );
                if !prohibited.is_empty() {
                    return Err(permanently_retired_error(&prohibited));
                }
                require_archive_postimage(&archive_path, &receipt)?;
                require_completion_certificate(schedules_path, &receipt)?;
                let generation = current_active.generation();
                return Ok(RetirementOutcome {
                    schedules: current_active.schedules,
                    permanently_retired_ids: authorities.permanently_retired_ids,
                    #[cfg(test)]
                    retired_ids: if already_completed { Vec::new() } else { ids },
                    generation,
                    lease: None,
                });
            }
        }
    }
}

async fn reconcile_completed_evidence(
    schedules_path: &Path,
    storage: RetirementStorage<'_>,
    receipt_path: &Path,
    receipt: &RetiredScheduleRetirementReceipt,
    faults: &RetirementFaults,
) -> Result<Option<RetirementOutcome>, CampaignSchedulerError> {
    let Some(certificate) = load_completion(&retirement_completion_path(schedules_path))? else {
        return Ok(None);
    };
    if !same_json(&certificate, &completion_for(receipt))? {
        return Err(receipt_error(
            &receipt_ids(receipt),
            "completion certificate conflicts with the receipt",
        ));
    }

    let active = load_image(schedules_path)?;
    validate_unique_ids(&active.schedules, "active schedule file")?;
    validate_schedule_bounds(&active.schedules)?;
    let authorities =
        reconcile_durable_authorities(storage, receipt, HistoryProofPhase::HistoryMustBeCommitted)
            .await?;
    let prohibited = prohibited_active_ids(&active.schedules, &authorities.permanently_retired_ids);
    if !prohibited.is_empty() {
        return Err(permanently_retired_error(&prohibited));
    }
    require_archive_postimage(&retired_schedule_path(schedules_path), receipt)?;

    if receipt.state != RetiredScheduleRetirementState::Completed {
        transition(
            receipt_path,
            receipt,
            RetiredScheduleRetirementState::Completed,
            faults,
        )?;
    }
    Ok(Some(RetirementOutcome {
        generation: active.generation(),
        schedules: active.schedules,
        permanently_retired_ids: authorities.permanently_retired_ids,
        #[cfg(test)]
        retired_ids: Vec::new(),
        lease: None,
    }))
}

async fn reject_independent_evidence_without_receipt(
    schedules_path: &Path,
    archive: &ScheduleImage,
    storage: RetirementStorage<'_>,
    active: &[Schedule],
) -> Result<(), CampaignSchedulerError> {
    let ids = retired_ids(active);
    let file_evidence = archive.present || retirement_completion_path(schedules_path).exists();
    let mut permanent_ids = archive
        .schedules
        .iter()
        .map(|schedule| schedule.id.clone())
        .collect::<Vec<_>>();
    let database_evidence = if let RetirementStorage::Available(store) = storage {
        let proof = store
            .schedule_retirement_history_proof()
            .await
            .map_err(|error| archive_error(&ids, error))?;
        if let Some(proof) = proof {
            permanent_ids.extend(proof.schedule_ids);
            true
        } else {
            false
        }
    } else {
        false
    };
    let prohibited = prohibited_active_ids(active, &permanent_ids);
    if (file_evidence || database_evidence) && !prohibited.is_empty() {
        return Err(permanently_retired_error(&prohibited));
    }
    if file_evidence {
        return Err(receipt_error(
            &ids,
            "retirement evidence exists without its receipt",
        ));
    }
    if database_evidence {
        return Err(receipt_error(
            &ids,
            "database retirement evidence exists without its receipt",
        ));
    }
    if matches!(storage, RetirementStorage::Unavailable) {
        return Err(archive_error(
            &ids,
            "linked schedule history storage is unavailable",
        ));
    }
    Ok(())
}

fn initial_receipt(
    active: &ScheduleImage,
    archive: &ScheduleImage,
    storage: RetirementStorage<'_>,
) -> Result<RetiredScheduleRetirementReceipt, CampaignSchedulerError> {
    let retired = retired_campaigns(&active.schedules);
    let retired_id_set = retired
        .iter()
        .map(|schedule| schedule.id.as_str())
        .collect::<HashSet<_>>();
    let active_post_schedules = active
        .schedules
        .iter()
        .filter(|schedule| !retired_id_set.contains(schedule.id.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let active_post = if retired.is_empty() {
        active.clone()
    } else {
        generated_image(active_post_schedules)?
    };
    let mut archive_post_schedules = archive.schedules.clone();
    archive_post_schedules.extend(retired.iter().cloned());
    archive_post_schedules.sort_by(|left, right| left.id.cmp(&right.id));
    let archive_post = generated_image(archive_post_schedules)?;
    let snapshots = retired
        .into_iter()
        .map(|schedule| {
            let canonical_digest = canonical_digest(&schedule)?;
            Ok(ScheduleSnapshot {
                schedule,
                canonical_digest,
            })
        })
        .collect::<Result<Vec<_>, CampaignSchedulerError>>()?;
    let history = match (snapshots.is_empty(), storage) {
        (_, RetirementStorage::NotConfigured) => HistoryRequirement::NotConfigured,
        (true, RetirementStorage::Available(_) | RetirementStorage::Unavailable) => {
            HistoryRequirement::NoRetiredSchedules
        }
        (false, RetirementStorage::Available(_) | RetirementStorage::Unavailable) => {
            HistoryRequirement::Database
        }
    };
    let plan = RetirementPlan {
        retired: snapshots,
        active_pre: active.clone(),
        active_post,
        archive_pre: archive.clone(),
        archive_post,
        history,
    };
    let operation_id = uuid::Uuid::new_v4().to_string();
    let plan_digest = operation_plan_digest(&operation_id, &plan)?;
    Ok(RetiredScheduleRetirementReceipt {
        version: RECEIPT_VERSION,
        state: RetiredScheduleRetirementState::ArchivePending,
        operation_id,
        plan_digest,
        plan,
    })
}

async fn archive_history(
    storage: RetirementStorage<'_>,
    receipt: &RetiredScheduleRetirementReceipt,
) -> Result<(), CampaignSchedulerError> {
    let ids = receipt_ids(receipt);
    if receipt.plan.history != HistoryRequirement::Database {
        return Ok(());
    }
    let RetirementStorage::Available(store) = storage else {
        return Err(receipt_error(
            &ids,
            "database history authority was not reconciled",
        ));
    };
    store
        .archive_schedule_history_for_retired_engine_operation(
            &receipt.operation_id,
            &receipt.plan_digest,
            &ids,
        )
        .await
        .map_err(|error| archive_error(&ids, error))?;
    Ok(())
}

async fn reconcile_durable_authorities(
    storage: RetirementStorage<'_>,
    receipt: &RetiredScheduleRetirementReceipt,
    phase: HistoryProofPhase,
) -> Result<ReconciledAuthorities, CampaignSchedulerError> {
    let ids = receipt_ids(receipt);
    match (receipt.plan.history, storage) {
        (HistoryRequirement::Database, RetirementStorage::Available(store)) => {
            let proof = store
                .schedule_retirement_history_proof()
                .await
                .map_err(|error| archive_error(&ids, error))?;
            match proof {
                None if phase == HistoryProofPhase::HistoryMustBeCommitted => {
                    Err(receipt_error(&ids, "linked history proof is missing"))
                }
                None => Ok(ReconciledAuthorities {
                    permanently_retired_ids: ids,
                }),
                Some(proof) => {
                    let exact = proof.operation_id == receipt.operation_id
                        && proof.plan_digest == receipt.plan_digest
                        && proof.schedule_ids == ids;
                    if !exact {
                        return Err(receipt_error(
                            &ids,
                            "database retirement proof contradicts the receipt",
                        ));
                    }
                    if phase == HistoryProofPhase::BeforeHistory {
                        return Err(receipt_error(
                            &ids,
                            "database retirement proof exists before its receipt phase",
                        ));
                    }
                    if !proof.history_archived {
                        return Err(receipt_error(
                            &ids,
                            "linked history proof has active schedule history",
                        ));
                    }
                    Ok(ReconciledAuthorities {
                        permanently_retired_ids: proof.schedule_ids,
                    })
                }
            }
        }
        (
            HistoryRequirement::Database | HistoryRequirement::NoRetiredSchedules,
            RetirementStorage::Unavailable,
        ) => Err(archive_error(
            &ids,
            "linked schedule history storage is unavailable",
        )),
        (HistoryRequirement::Database, RetirementStorage::NotConfigured) => Err(receipt_error(
            &ids,
            "database-backed history proof is required",
        )),
        (HistoryRequirement::NotConfigured, RetirementStorage::NotConfigured) => {
            Ok(ReconciledAuthorities {
                permanently_retired_ids: ids,
            })
        }
        (HistoryRequirement::NoRetiredSchedules, RetirementStorage::Available(store)) => {
            let proof = store
                .schedule_retirement_history_proof()
                .await
                .map_err(|error| archive_error(&ids, error))?;
            if proof.is_some() {
                Err(receipt_error(
                    &ids,
                    "database retirement proof contradicts an empty receipt",
                ))
            } else {
                Ok(ReconciledAuthorities {
                    permanently_retired_ids: Vec::new(),
                })
            }
        }
        (HistoryRequirement::NotConfigured, RetirementStorage::Available(_)) => Err(receipt_error(
            &ids,
            "database persistence was configured after the history waiver",
        )),
        (HistoryRequirement::NotConfigured, RetirementStorage::Unavailable) => Err(archive_error(
            &ids,
            "database persistence is configured but unavailable after the history waiver",
        )),
        (HistoryRequirement::NoRetiredSchedules, RetirementStorage::NotConfigured) => Err(
            receipt_error(&ids, "configured database authority disappeared"),
        ),
    }
}

fn require_active_preimage_or_restore(
    current: &ScheduleImage,
    receipt: &RetiredScheduleRetirementReceipt,
) -> Result<(), CampaignSchedulerError> {
    if image_matches(current, &receipt.plan.active_pre)? {
        return Ok(());
    }
    Err(active_third_state_error(
        &current.schedules,
        &receipt_ids(receipt),
    ))
}

fn active_third_state_error(current: &[Schedule], ids: &[String]) -> CampaignSchedulerError {
    let prohibited = prohibited_active_ids(current, ids);
    if prohibited.is_empty() {
        receipt_error(ids, "active schedule compare-and-swap failed")
    } else {
        permanently_retired_error(&prohibited)
    }
}

fn require_archive_postimage(
    archive_path: &Path,
    receipt: &RetiredScheduleRetirementReceipt,
) -> Result<(), CampaignSchedulerError> {
    let ids = receipt_ids(receipt);
    let archive = load_image(archive_path).map_err(|error| archive_error(&ids, error))?;
    validate_unique_ids(&archive.schedules, "retired schedule archive")?;
    require_image(&archive, &receipt.plan.archive_post, &ids, "archive proof")
}

fn transition(
    receipt_path: &Path,
    receipt: &RetiredScheduleRetirementReceipt,
    state: RetiredScheduleRetirementState,
    faults: &RetirementFaults,
) -> Result<RetiredScheduleRetirementReceipt, CampaignSchedulerError> {
    let current = load_receipt(receipt_path)?
        .ok_or_else(|| receipt_error(&receipt_ids(receipt), "receipt disappeared"))?;
    if !same_json(&current, receipt)? {
        return Err(receipt_error(
            &receipt_ids(receipt),
            "receipt compare-and-swap failed",
        ));
    }
    let mut next = receipt.clone();
    next.state = state;
    persist_receipt(receipt_path, &next, faults)?;
    Ok(next)
}

fn persist_receipt(
    path: &Path,
    receipt: &RetiredScheduleRetirementReceipt,
    faults: &RetirementFaults,
) -> Result<(), CampaignSchedulerError> {
    validate_receipt(receipt)?;
    let bytes = pretty_bytes(receipt)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(receipt_error(
            &receipt_ids(receipt),
            "receipt state file exceeds size limit",
        ));
    }
    faults.before_receipt(receipt.state)?;
    atomic_write_json(path, receipt)
        .map_err(|error| receipt_error(&receipt_ids(receipt), error))?;
    let written = load_receipt(path)?
        .ok_or_else(|| receipt_error(&receipt_ids(receipt), "receipt write disappeared"))?;
    validate_receipt(&written)?;
    if same_json(&written, receipt)? {
        Ok(())
    } else {
        Err(receipt_error(
            &receipt_ids(receipt),
            "receipt write verification failed",
        ))
    }
}

fn reload_expected_receipt(
    path: &Path,
    expected: &RetiredScheduleRetirementReceipt,
) -> Result<RetiredScheduleRetirementReceipt, CampaignSchedulerError> {
    let current = load_receipt(path)?
        .ok_or_else(|| receipt_error(&receipt_ids(expected), "receipt disappeared"))?;
    validate_receipt(&current)?;
    if current.operation_id != expected.operation_id || current.plan_digest != expected.plan_digest
    {
        return Err(receipt_error(
            &receipt_ids(expected),
            "receipt operation changed during retirement",
        ));
    }
    Ok(current)
}

fn load_receipt(
    path: &Path,
) -> Result<Option<RetiredScheduleRetirementReceipt>, CampaignSchedulerError> {
    let bytes = read_bounded_optional(path, MAX_RECEIPT_BYTES)
        .map_err(|error| receipt_error(&[], error))?;
    bytes
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|error| receipt_error(&[], escaped_detail(error)))
        })
        .transpose()
}

fn validate_receipt(
    receipt: &RetiredScheduleRetirementReceipt,
) -> Result<(), CampaignSchedulerError> {
    let ids = receipt_ids(receipt);
    if receipt.version != RECEIPT_VERSION {
        return Err(receipt_error(&ids, "unsupported receipt version"));
    }
    if validate_schedule_retirement_operation_id(&receipt.operation_id).is_err() {
        return Err(receipt_error(&ids, "invalid operation identifier"));
    }
    for image in [
        &receipt.plan.active_pre,
        &receipt.plan.active_post,
        &receipt.plan.archive_pre,
        &receipt.plan.archive_post,
    ] {
        validate_schedule_bounds(&image.schedules)?;
        validate_unique_ids(&image.schedules, "receipt schedule image")?;
        validate_image(image, &ids)?;
    }
    if receipt.plan.retired.len() > MAX_RECEIPT_SCHEDULES {
        return Err(receipt_error(&ids, "receipt schedule count exceeds limit"));
    }
    let proof_ids = receipt
        .plan
        .retired
        .iter()
        .map(|snapshot| snapshot.schedule.id.clone())
        .collect::<Vec<_>>();
    if !proof_ids.is_empty() && validate_schedule_retirement_manifest(&proof_ids).is_err() {
        return Err(receipt_error(
            &ids,
            "receipt contains an invalid retirement proof identity",
        ));
    }
    for snapshot in &receipt.plan.retired {
        validate_id_bound(&snapshot.schedule.id)?;
        if canonical_digest(&snapshot.schedule)? != snapshot.canonical_digest {
            return Err(receipt_error(
                &ids,
                "retired schedule snapshot digest differs",
            ));
        }
    }
    validate_plan_semantics(&receipt.plan, &ids)?;
    if operation_plan_digest(&receipt.operation_id, &receipt.plan)? != receipt.plan_digest {
        return Err(receipt_error(&ids, "receipt plan digest differs"));
    }
    Ok(())
}

fn validate_plan_semantics(
    plan: &RetirementPlan,
    ids: &[String],
) -> Result<(), CampaignSchedulerError> {
    let classified = retired_campaigns(&plan.active_pre.schedules);
    if classified.len() != plan.retired.len() {
        return Err(receipt_error(
            ids,
            "retired snapshots do not match the classified active preimage",
        ));
    }
    for (schedule, snapshot) in classified.iter().zip(&plan.retired) {
        if !same_json(schedule, &snapshot.schedule)? {
            return Err(receipt_error(
                ids,
                "retired snapshots do not match the classified active preimage",
            ));
        }
    }

    let retired_ids = classified
        .iter()
        .map(|schedule| schedule.id.as_str())
        .collect::<HashSet<_>>();
    let expected_active = if classified.is_empty() {
        plan.active_pre.clone()
    } else {
        generated_image(
            plan.active_pre
                .schedules
                .iter()
                .filter(|schedule| !retired_ids.contains(schedule.id.as_str()))
                .cloned()
                .collect(),
        )?
    };
    if !image_matches(&expected_active, &plan.active_post)? {
        return Err(receipt_error(
            ids,
            "active postimage is not the exact retired-schedule subtraction",
        ));
    }

    let mut archive_schedules = plan.archive_pre.schedules.clone();
    for retired in &classified {
        match archive_schedules
            .iter()
            .find(|existing| existing.id == retired.id)
        {
            Some(existing) if same_json(existing, retired)? => {}
            Some(_) => {
                return Err(receipt_error(
                    ids,
                    "retired archive merge conflicts with existing evidence",
                ));
            }
            None => archive_schedules.push(retired.clone()),
        }
    }
    archive_schedules.sort_by(|left, right| left.id.cmp(&right.id));
    let expected_archive = generated_image(archive_schedules)?;
    if !image_matches(&expected_archive, &plan.archive_post)? {
        return Err(receipt_error(
            ids,
            "archive postimage is not the exact conflict-checked merge",
        ));
    }

    let history_matches = if classified.is_empty() {
        matches!(
            plan.history,
            HistoryRequirement::NoRetiredSchedules | HistoryRequirement::NotConfigured
        )
    } else {
        matches!(
            plan.history,
            HistoryRequirement::Database | HistoryRequirement::NotConfigured
        )
    };
    if !history_matches {
        return Err(receipt_error(
            ids,
            "history requirement is incompatible with the retired schedule set",
        ));
    }
    Ok(())
}

fn validate_image(image: &ScheduleImage, ids: &[String]) -> Result<(), CampaignSchedulerError> {
    if canonical_digest(&image.schedules)? != image.canonical_digest {
        return Err(receipt_error(ids, "schedule image digest differs"));
    }
    if !is_sha256_digest(&image.byte_digest) {
        return Err(receipt_error(ids, "schedule byte digest is invalid"));
    }
    if !image.present && (!image.schedules.is_empty() || image.byte_digest != digest_bytes(&[])) {
        return Err(receipt_error(ids, "absent schedule image contains data"));
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == Sha256::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_completion_certificate(
    schedules_path: &Path,
    receipt: &RetiredScheduleRetirementReceipt,
    faults: &RetirementFaults,
) -> Result<(), CampaignSchedulerError> {
    let path = retirement_completion_path(schedules_path);
    let expected = completion_for(receipt);
    match load_completion(&path)? {
        Some(existing) if same_json(&existing, &expected)? => Ok(()),
        Some(_) => Err(receipt_error(
            &receipt_ids(receipt),
            "completion certificate conflicts with the receipt",
        )),
        None => {
            let bytes = pretty_bytes(&expected)?;
            if bytes.len() as u64 > MAX_RECEIPT_BYTES {
                return Err(receipt_error(
                    &receipt_ids(receipt),
                    "completion certificate exceeds size limit",
                ));
            }
            faults.before_completion_certificate()?;
            atomic_write_json(&path, &expected)
                .map_err(|error| receipt_error(&receipt_ids(receipt), error))?;
            let written = load_completion(&path)?.ok_or_else(|| {
                receipt_error(&receipt_ids(receipt), "completion certificate disappeared")
            })?;
            if same_json(&written, &expected)? {
                Ok(())
            } else {
                Err(receipt_error(
                    &receipt_ids(receipt),
                    "completion certificate write verification failed",
                ))
            }
        }
    }
}

fn require_completion_certificate(
    schedules_path: &Path,
    receipt: &RetiredScheduleRetirementReceipt,
) -> Result<(), CampaignSchedulerError> {
    let expected = completion_for(receipt);
    let existing = load_completion(&retirement_completion_path(schedules_path))?
        .ok_or_else(|| receipt_error(&receipt_ids(receipt), "completion certificate is missing"))?;
    if same_json(&existing, &expected)? {
        Ok(())
    } else {
        Err(receipt_error(
            &receipt_ids(receipt),
            "completion certificate conflicts with the receipt",
        ))
    }
}

fn load_completion(path: &Path) -> Result<Option<RetirementCompletion>, CampaignSchedulerError> {
    let bytes = read_bounded_optional(path, MAX_RECEIPT_BYTES)
        .map_err(|error| receipt_error(&[], error))?;
    bytes
        .map(|bytes| {
            serde_json::from_slice::<RetirementCompletion>(&bytes)
                .map_err(|error| receipt_error(&[], escaped_detail(error)))
        })
        .transpose()
}

fn completion_for(receipt: &RetiredScheduleRetirementReceipt) -> RetirementCompletion {
    RetirementCompletion {
        version: COMPLETION_VERSION,
        operation_id: receipt.operation_id.clone(),
        plan_digest: receipt.plan_digest.clone(),
        active_post_digest: receipt.plan.active_post.byte_digest.clone(),
        archive_post_digest: receipt.plan.archive_post.byte_digest.clone(),
        history: receipt.plan.history,
    }
}

fn read_bounded_optional(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, StateFileError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StateFileError::Io {
                operation: "open",
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StateFileError::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > max_bytes {
        return Err(StateFileError::Io {
            operation: "read bounded",
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "state file exceeds size limit",
            ),
        });
    }
    Ok(Some(bytes))
}

fn load_image(path: &Path) -> Result<ScheduleImage, StateFileError> {
    match read_bounded_optional(path, MAX_SCHEDULE_FILE_BYTES)? {
        Some(bytes) => {
            let schedules = serde_json::from_slice::<Vec<Schedule>>(&bytes).map_err(|source| {
                StateFileError::Decode {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            Ok(ScheduleImage {
                present: true,
                canonical_digest: canonical_digest_state(path, &schedules)?,
                schedules,
                byte_digest: digest_bytes(&bytes),
            })
        }
        None => Ok(ScheduleImage {
            present: false,
            schedules: Vec::new(),
            canonical_digest: canonical_digest_state(path, &Vec::<Schedule>::new())?,
            byte_digest: digest_bytes(&[]),
        }),
    }
}

fn generated_image(schedules: Vec<Schedule>) -> Result<ScheduleImage, CampaignSchedulerError> {
    let bytes = pretty_bytes(&schedules)?;
    Ok(ScheduleImage {
        present: true,
        canonical_digest: canonical_digest(&schedules)?,
        schedules,
        byte_digest: digest_bytes(&bytes),
    })
}

fn pretty_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CampaignSchedulerError> {
    serde_json::to_vec_pretty(value).map_err(|error| receipt_error(&[], escaped_detail(error)))
}

fn canonical_digest<T: Serialize>(value: &T) -> Result<String, CampaignSchedulerError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|error| receipt_error(&[], escaped_detail(error)))
}

fn operation_plan_digest(
    operation_id: &str,
    plan: &RetirementPlan,
) -> Result<String, CampaignSchedulerError> {
    canonical_digest(&OperationPlanBinding { operation_id, plan })
}

fn canonical_digest_state<T: Serialize>(path: &Path, value: &T) -> Result<String, StateFileError> {
    serde_json::to_vec(value)
        .map(|bytes| digest_bytes(&bytes))
        .map_err(|source| StateFileError::Encode {
            path: path.to_path_buf(),
            source,
        })
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn image_matches(
    left: &ScheduleImage,
    right: &ScheduleImage,
) -> Result<bool, CampaignSchedulerError> {
    Ok(left.present == right.present
        && left.byte_digest == right.byte_digest
        && left.canonical_digest == right.canonical_digest
        && same_json(&left.schedules, &right.schedules)?)
}

fn require_image(
    current: &ScheduleImage,
    expected: &ScheduleImage,
    ids: &[String],
    context: &'static str,
) -> Result<(), CampaignSchedulerError> {
    if image_matches(current, expected)? {
        Ok(())
    } else {
        Err(receipt_error(ids, context))
    }
}

fn same_json<T: Serialize>(left: &T, right: &T) -> Result<bool, CampaignSchedulerError> {
    Ok(
        serde_json::to_vec(left).map_err(|error| receipt_error(&[], escaped_detail(error)))?
            == serde_json::to_vec(right)
                .map_err(|error| receipt_error(&[], escaped_detail(error)))?,
    )
}

impl ScheduleImage {
    fn generation(&self) -> ScheduleGeneration {
        ScheduleGeneration {
            present: self.present,
            byte_digest: self.byte_digest.clone(),
        }
    }
}

pub(crate) fn current_generation(path: &Path) -> Result<ScheduleGeneration, StateFileError> {
    load_image(path).map(|image| image.generation())
}

pub(crate) fn expected_written_generation(
    path: &Path,
    schedules: &[Schedule],
) -> Result<ScheduleGeneration, StateFileError> {
    let bytes = serde_json::to_vec_pretty(schedules).map_err(|source| StateFileError::Encode {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() as u64 > MAX_SCHEDULE_FILE_BYTES {
        return Err(StateFileError::Io {
            operation: "serialize bounded",
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "schedule state file exceeds size limit",
            ),
        });
    }
    Ok(ScheduleGeneration {
        present: true,
        byte_digest: digest_bytes(&bytes),
    })
}

pub(crate) fn verify_written_generation(
    path: &Path,
    expected: &ScheduleGeneration,
) -> Result<(), StateFileError> {
    if current_generation(path)? == *expected {
        Ok(())
    } else {
        Err(StateFileError::Conflict {
            path: path.to_path_buf(),
        })
    }
}

fn validate_unique_ids(
    schedules: &[Schedule],
    context: &'static str,
) -> Result<(), CampaignSchedulerError> {
    let mut seen = HashSet::with_capacity(schedules.len());
    if schedules.iter().all(|schedule| seen.insert(&schedule.id)) {
        Ok(())
    } else {
        Err(receipt_error(
            &retired_ids(schedules),
            format!("duplicate schedule identifiers in {context}"),
        ))
    }
}

fn validate_schedule_bounds(schedules: &[Schedule]) -> Result<(), CampaignSchedulerError> {
    if schedules.len() > MAX_RECEIPT_SCHEDULES {
        return Err(receipt_error(&[], "receipt schedule count exceeds limit"));
    }
    for schedule in schedules {
        validate_id_bound(&schedule.id)?;
    }
    Ok(())
}

fn validate_initial_retired_ids(schedules: &[Schedule]) -> Result<(), CampaignSchedulerError> {
    let ids = retired_ids(schedules);
    if ids.is_empty() {
        return Ok(());
    }
    validate_schedule_retirement_manifest(&ids).map_err(|_| {
        archive_error(
            &ids,
            "invalid legacy retired schedule identity; assign a new schedule ID or remove the \
             invalid legacy definition offline, then restart",
        )
    })?;
    Ok(())
}

fn validate_id_bound(id: &str) -> Result<(), CampaignSchedulerError> {
    if id.len() <= MAX_SCHEDULE_ID_BYTES {
        Ok(())
    } else {
        Err(receipt_error(
            &[],
            "receipt schedule identifier exceeds limit",
        ))
    }
}

fn receipt_ids(receipt: &RetiredScheduleRetirementReceipt) -> Vec<String> {
    retired_ids(
        &receipt
            .plan
            .retired
            .iter()
            .map(|snapshot| snapshot.schedule.clone())
            .collect::<Vec<_>>(),
    )
}

fn retired_campaigns(schedules: &[Schedule]) -> Vec<Schedule> {
    schedules
        .iter()
        .filter(|schedule| is_retired_campaign(schedule))
        .cloned()
        .collect()
}

fn retired_ids(schedules: &[Schedule]) -> Vec<String> {
    let mut ids = schedules
        .iter()
        .filter(|schedule| is_retired_campaign(schedule))
        .map(|schedule| schedule.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn prohibited_active_ids(schedules: &[Schedule], permanently_retired: &[String]) -> Vec<String> {
    let permanently_retired = permanently_retired
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut ids = schedules
        .iter()
        .filter(|schedule| {
            is_retired_campaign(schedule) || permanently_retired.contains(schedule.id.as_str())
        })
        .map(|schedule| schedule.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn is_retired_campaign(schedule: &Schedule) -> bool {
    schedule.workflow_id == crate::scheduler::CAMPAIGN_KIND
        && schedule
            .parameter_values
            .get("engine")
            .and_then(serde_json::Value::as_str)
            .is_some_and(hf_core::retired_engine::is_retired_engine_id)
}

pub(crate) fn permanently_retired_error(ids: &[String]) -> CampaignSchedulerError {
    CampaignSchedulerError::RetiredScheduleRestore {
        engine: hf_core::retired_engine::RETIRED_ENGINE_ID,
        schedule_ids: bounded_schedule_ids(ids),
    }
}

fn archive_error(ids: &[String], reason: impl std::fmt::Display) -> CampaignSchedulerError {
    CampaignSchedulerError::RetiredScheduleArchive {
        schedule_ids: bounded_schedule_ids(ids),
        reason: escaped_detail(reason),
    }
}

fn receipt_error(ids: &[String], reason: impl std::fmt::Display) -> CampaignSchedulerError {
    CampaignSchedulerError::RetiredScheduleReceipt {
        schedule_ids: bounded_schedule_ids(ids),
        reason: escaped_detail(reason),
    }
}

fn escaped_detail(detail: impl std::fmt::Display) -> String {
    detail
        .to_string()
        .chars()
        .flat_map(char::escape_default)
        .take(MAX_ERROR_DETAIL_CHARS)
        .collect()
}

pub(crate) fn bounded_schedule_ids(ids: &[String]) -> String {
    if ids.is_empty() {
        return "none".to_owned();
    }
    let mut sorted = ids.to_vec();
    sorted.sort();
    sorted.dedup();
    let omitted = sorted.len().saturating_sub(MAX_ERROR_IDS);
    let mut rendered = sorted
        .iter()
        .take(MAX_ERROR_IDS)
        .map(|id| {
            let mut chars = id.chars();
            let mut bounded = chars
                .by_ref()
                .take(MAX_ERROR_ID_CHARS)
                .flat_map(char::escape_default)
                .collect::<String>();
            if chars.next().is_some() {
                bounded.push_str("...");
            }
            bounded
        })
        .collect::<Vec<_>>()
        .join(", ");
    if omitted > 0 {
        let _ = write!(rendered, " (+{omitted} more)");
    }
    rendered
}

pub(crate) fn retired_schedule_path(schedules_path: &Path) -> PathBuf {
    sibling_path(schedules_path, "retired_schedules.json")
}

pub(crate) fn retired_schedule_retirement_path(schedules_path: &Path) -> PathBuf {
    sibling_path(schedules_path, "retired_schedule_retirement.json")
}

pub(crate) fn retirement_completion_path(schedules_path: &Path) -> PathBuf {
    sibling_path(schedules_path, "retired_schedule_retirement_complete.json")
}

fn schedule_lock_path(schedules_path: &Path) -> PathBuf {
    sibling_path(schedules_path, ".schedules.json.lock")
}

fn sibling_path(path: &Path, name: &str) -> PathBuf {
    path.parent()
        .map_or_else(|| PathBuf::from(name), |parent| parent.join(name))
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use hf_scheduler::TriggerConfig;

    use super::*;

    fn schedule(id: &str) -> Schedule {
        Schedule::new(
            id,
            "retired",
            TriggerConfig::Interval { interval_secs: 60 },
            crate::scheduler::CAMPAIGN_KIND,
        )
        .with_params(serde_json::json!({
            "engine": hf_core::retired_engine::RETIRED_ENGINE_ID
        }))
    }

    fn supported_schedule(id: &str) -> Schedule {
        Schedule::new(
            id,
            "supported",
            TriggerConfig::Interval { interval_secs: 60 },
            crate::scheduler::CAMPAIGN_KIND,
        )
        .with_params(serde_json::json!({ "engine": "libfuzzer" }))
    }

    fn rehash_image(image: &mut ScheduleImage) {
        image.canonical_digest = canonical_digest(&image.schedules).unwrap();
        image.byte_digest = if image.present {
            digest_bytes(&pretty_bytes(&image.schedules).unwrap())
        } else {
            digest_bytes(&[])
        };
    }

    fn rehash_receipt(receipt: &mut RetiredScheduleRetirementReceipt) {
        receipt.plan_digest = operation_plan_digest(&receipt.operation_id, &receipt.plan).unwrap();
    }

    fn test_receipt() -> RetiredScheduleRetirementReceipt {
        let active = generated_image(vec![schedule("schedule-retired")]).unwrap();
        let archive = ScheduleImage {
            present: false,
            schedules: Vec::new(),
            canonical_digest: canonical_digest(&Vec::<Schedule>::new()).unwrap(),
            byte_digest: digest_bytes(&[]),
        };
        initial_receipt(&active, &archive, RetirementStorage::NotConfigured).unwrap()
    }

    #[test]
    fn receipt_validation_bounds_schedule_count_before_using_it() {
        let mut receipt = test_receipt();
        receipt.plan.active_pre.schedules = (0..=MAX_RECEIPT_SCHEDULES)
            .map(|index| schedule(&format!("schedule-{index}")))
            .collect();

        let error = validate_receipt(&receipt).unwrap_err();

        assert!(error.to_string().contains("schedule count exceeds limit"));
    }

    #[test]
    fn receipt_validation_bounds_identifier_length_without_echoing_it() {
        let private_id = "P".repeat(MAX_SCHEDULE_ID_BYTES + 1);
        let mut receipt = test_receipt();
        receipt.plan.active_pre.schedules[0].id = private_id.clone();

        let error = validate_receipt(&receipt).unwrap_err();
        let detail = error.to_string();

        assert!(detail.contains("identifier exceeds limit"));
        assert!(!detail.contains(&private_id));
    }

    #[test]
    fn receipt_validation_rederives_every_semantic_plan_relationship() {
        let active = generated_image(vec![
            schedule("schedule-retired"),
            supported_schedule("schedule-supported"),
        ])
        .unwrap();
        let archive = ScheduleImage {
            present: false,
            schedules: Vec::new(),
            canonical_digest: canonical_digest(&Vec::<Schedule>::new()).unwrap(),
            byte_digest: digest_bytes(&[]),
        };
        let receipt = initial_receipt(&active, &archive, RetirementStorage::NotConfigured).unwrap();

        let mut wrong_retired = receipt.clone();
        wrong_retired.plan.retired[0].schedule = supported_schedule("schedule-supported");
        wrong_retired.plan.retired[0].canonical_digest =
            canonical_digest(&wrong_retired.plan.retired[0].schedule).unwrap();
        rehash_receipt(&mut wrong_retired);

        let mut wrong_active_post = receipt.clone();
        wrong_active_post.plan.active_post.schedules =
            wrong_active_post.plan.active_pre.schedules.clone();
        rehash_image(&mut wrong_active_post.plan.active_post);
        rehash_receipt(&mut wrong_active_post);

        let mut wrong_archive_post = receipt.clone();
        wrong_archive_post.plan.archive_post.schedules.clear();
        rehash_image(&mut wrong_archive_post.plan.archive_post);
        rehash_receipt(&mut wrong_archive_post);

        let mut wrong_history = receipt;
        wrong_history.plan.history = HistoryRequirement::NoRetiredSchedules;
        rehash_receipt(&mut wrong_history);

        for inconsistent in [
            wrong_retired,
            wrong_active_post,
            wrong_archive_post,
            wrong_history,
        ] {
            let error = validate_receipt(&inconsistent).unwrap_err();
            assert!(error.to_string().contains("retirement receipt"));
        }
    }

    #[test]
    fn receipt_is_bounded_before_every_persist() {
        let mut oversized = schedule("schedule-retired");
        oversized.description = "x".repeat(6 * 1024 * 1024);
        let active = generated_image(vec![oversized]).unwrap();
        let archive = ScheduleImage {
            present: false,
            schedules: Vec::new(),
            canonical_digest: canonical_digest(&Vec::<Schedule>::new()).unwrap(),
            byte_digest: digest_bytes(&[]),
        };
        let receipt = initial_receipt(&active, &archive, RetirementStorage::NotConfigured).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt.json");

        let error = persist_receipt(&path, &receipt, &RetirementFaults::default()).unwrap_err();

        assert!(error.to_string().contains("size limit"));
        assert!(!path.exists());
    }

    #[test]
    fn schedule_input_is_bounded_before_json_decode() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("schedules.json");
        std::fs::write(&path, vec![b' '; MAX_RECEIPT_BYTES as usize + 1]).unwrap();

        let error = load_image(&path).unwrap_err();

        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn unreleased_version_one_receipt_fails_closed_explicitly() {
        let mut receipt = test_receipt();
        receipt.version = 1;

        let error = validate_receipt(&receipt).unwrap_err();

        assert!(error.to_string().contains("unsupported receipt version"));
    }

    async fn wait_for_path(path: &Path) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("subprocess did not publish its lock condition");
    }

    #[tokio::test]
    async fn subprocess_lock_holder() {
        let Ok(schedule_path) = std::env::var("OXFUZZ_LOCK_HELPER_SCHEDULE") else {
            return;
        };
        let ready = PathBuf::from(std::env::var("OXFUZZ_LOCK_HELPER_READY").unwrap());
        let release = PathBuf::from(std::env::var("OXFUZZ_LOCK_HELPER_RELEASE").unwrap());
        let _lease = acquire_schedule_path_lease_with_timeout(
            Path::new(&schedule_path),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        std::fs::write(ready, b"ready").unwrap();
        wait_for_path(&release).await;
    }

    fn spawn_lock_holder(
        schedule_path: &Path,
        ready: &Path,
        release: &Path,
    ) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "schedule_retirement::tests::subprocess_lock_holder",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("OXFUZZ_LOCK_HELPER_SCHEDULE", schedule_path)
            .env("OXFUZZ_LOCK_HELPER_READY", ready)
            .env("OXFUZZ_LOCK_HELPER_RELEASE", release)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    }

    #[tokio::test]
    async fn subprocess_advisory_lock_excludes_and_releases_contenders() {
        let directory = tempfile::tempdir().unwrap();
        let schedule_path = directory.path().join("schedules.json");
        let ready = directory.path().join("ready");
        let release = directory.path().join("release");
        let mut child = spawn_lock_holder(&schedule_path, &ready, &release);
        wait_for_path(&ready).await;

        let error =
            acquire_schedule_path_lease_with_timeout(&schedule_path, Duration::from_millis(100))
                .await
                .err()
                .expect("subprocess lock must exclude the contender");
        assert!(matches!(
            error,
            StateFileError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::TimedOut
        ));

        std::fs::write(&release, b"release").unwrap();
        assert!(child.wait().unwrap().success());
        acquire_schedule_path_lease_with_timeout(&schedule_path, Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn subprocess_advisory_lock_releases_after_forced_exit() {
        let directory = tempfile::tempdir().unwrap();
        let schedule_path = directory.path().join("schedules.json");
        let ready = directory.path().join("ready");
        let release = directory.path().join("release");
        let mut child = spawn_lock_holder(&schedule_path, &ready, &release);
        wait_for_path(&ready).await;

        child.kill().unwrap();
        child.wait().unwrap();

        acquire_schedule_path_lease_with_timeout(&schedule_path, Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn cancelled_lock_wait_does_not_leave_a_background_waiter() {
        let directory = tempfile::tempdir().unwrap();
        let schedule_path = directory.path().join("schedules.json");
        let lease = acquire_schedule_path_lease(&schedule_path).await.unwrap();
        let task_path = schedule_path.clone();
        let waiter = tokio::spawn(async move {
            acquire_schedule_path_lease_with_timeout(&task_path, Duration::from_secs(5)).await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while process_lock_strong_count(&schedule_path) < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        waiter.abort();
        let joined = waiter.await;
        assert!(matches!(joined, Err(error) if error.is_cancelled()));
        drop(lease);

        acquire_schedule_path_lease_with_timeout(&schedule_path, Duration::from_secs(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lock_registry_prunes_dead_path_entries() {
        let directory = tempfile::tempdir().unwrap();
        let mut dead_paths = Vec::new();
        for index in 0..8 {
            let path = directory
                .path()
                .join(format!("workspace-{index}"))
                .join("schedules.json");
            drop(acquire_schedule_path_lease(&path).await.unwrap());
            dead_paths.push(path);
        }
        let final_path = directory
            .path()
            .join("workspace-final")
            .join("schedules.json");
        let _lease = acquire_schedule_path_lease(&final_path).await.unwrap();

        assert!(dead_paths
            .iter()
            .all(|path| !process_lock_registry_contains(path)));
        assert!(process_lock_registry_contains(&final_path));
    }

    #[test]
    fn unsupported_advisory_lock_error_is_preserved() {
        let path = Path::new("schedules.json");
        let error = classify_lock_error(
            path,
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "advisory locks are unavailable",
            ),
        );

        assert!(matches!(
            error,
            StateFileError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::Unsupported
        ));
    }
}
