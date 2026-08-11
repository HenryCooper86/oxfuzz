//! Durable one-time retirement protocol for file-backed campaign schedules.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use hf_scheduler::Schedule;
use hf_storage::Store;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::campaign_state::{atomic_write_json, StateFileError};
use crate::scheduler::CampaignSchedulerError;

const RECEIPT_VERSION: u32 = 2;
const COMPLETION_VERSION: u32 = 1;
const MAX_RECEIPT_SCHEDULES: usize = 4_096;
const MAX_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ERROR_IDS: usize = 20;
const MAX_ERROR_ID_CHARS: usize = 128;
const MAX_ERROR_DETAIL_CHARS: usize = 1_024;

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
    let lock_path = schedule_lock_path(schedules_path);
    let process_path = if lock_path.is_absolute() {
        lock_path.clone()
    } else {
        std::env::current_dir().map_or_else(
            |_| lock_path.clone(),
            |directory| directory.join(&lock_path),
        )
    };
    let process_lock = {
        let mut locks = PROCESS_PATH_LOCKS
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lock) = locks.get(&process_path).and_then(Weak::upgrade) {
            lock
        } else {
            let lock = Arc::new(tokio::sync::Mutex::new(()));
            locks.insert(process_path, Arc::downgrade(&lock));
            lock
        }
    };
    let process_guard = process_lock.lock_owned().await;
    let task_path = lock_path.clone();
    let file = tokio::task::spawn_blocking(move || {
        let parent = task_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent).map_err(|source| StateFileError::Io {
            operation: "create lock directory for",
            path: task_path.clone(),
            source,
        })?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&task_path)
            .map_err(|source| StateFileError::Io {
                operation: "open lock for",
                path: task_path.clone(),
                source,
            })?;
        fs2::FileExt::lock_exclusive(&file).map_err(|source| StateFileError::Io {
            operation: "lock",
            path: task_path,
            source,
        })?;
        Ok(file)
    })
    .await
    .map_err(|source| StateFileError::Io {
        operation: "join lock task for",
        path: lock_path,
        source: std::io::Error::other(source.to_string()),
    })??;
    Ok(SchedulePathLease {
        _process: process_guard,
        _file: file,
    })
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
    let archive_path = retired_schedule_path(schedules_path);
    let archive = load_image(&archive_path)
        .map_err(|error| archive_error(&retired_ids(&active.schedules), error))?;
    validate_unique_ids(&archive.schedules, "retired schedule archive")?;
    validate_schedule_bounds(&archive.schedules)?;

    let receipt_path = retired_schedule_retirement_path(schedules_path);
    let mut receipt = if let Some(receipt) = load_receipt(&receipt_path)? {
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
        let ids = receipt_ids(&receipt);
        match receipt.state {
            RetiredScheduleRetirementState::ArchivePending => {
                let current_active = load_image(schedules_path)?;
                require_active_preimage_or_restore(&current_active, &receipt)?;
                let current_archive =
                    load_image(&archive_path).map_err(|error| archive_error(&ids, error))?;
                validate_unique_ids(&current_archive.schedules, "retired schedule archive")?;
                if image_matches(&current_archive, &receipt.plan.archive_pre)? {
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
                require_history_proof(storage, &receipt).await?;
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
                require_history_proof(storage, &receipt).await?;
                if image_matches(&current_active, &receipt.plan.active_pre)? {
                    if !image_matches(&receipt.plan.active_pre, &receipt.plan.active_post)? {
                        #[cfg(test)]
                        faults
                            .pause_at(ScheduleRetirementPausePoint::ActiveRewrite)
                            .await;
                        faults.before_active_rewrite()?;
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
                let restored = retired_campaigns(&current_active.schedules);
                if !restored.is_empty() {
                    return Err(restored_error(&restored));
                }
                require_image(
                    &current_active,
                    &receipt.plan.active_post,
                    &ids,
                    "completion active image",
                )?;
                require_archive_postimage(&archive_path, &receipt)?;
                require_history_proof(storage, &receipt).await?;
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
                let restored = retired_campaigns(&current_active.schedules);
                if !restored.is_empty() {
                    return Err(restored_error(&restored));
                }
                require_archive_postimage(&archive_path, &receipt)?;
                require_history_proof(storage, &receipt).await?;
                require_completion_certificate(schedules_path, &receipt)?;
                let generation = current_active.generation();
                return Ok(RetirementOutcome {
                    schedules: current_active.schedules,
                    #[cfg(test)]
                    retired_ids: if already_completed { Vec::new() } else { ids },
                    generation,
                    lease: None,
                });
            }
        }
    }
}

async fn reject_independent_evidence_without_receipt(
    schedules_path: &Path,
    archive: &ScheduleImage,
    storage: RetirementStorage<'_>,
    active: &[Schedule],
) -> Result<(), CampaignSchedulerError> {
    let ids = retired_ids(active);
    if archive.present || retirement_completion_path(schedules_path).exists() {
        let restored = retired_campaigns(active);
        if !restored.is_empty() {
            return Err(restored_error(&restored));
        }
        return Err(receipt_error(
            &ids,
            "retirement evidence exists without its receipt",
        ));
    }
    if let RetirementStorage::Available(store) = storage {
        let has_proof = store
            .has_schedule_retirement_history_proof()
            .await
            .map_err(|error| archive_error(&ids, error))?;
        if has_proof {
            let restored = retired_campaigns(active);
            if !restored.is_empty() {
                return Err(restored_error(&restored));
            }
            return Err(receipt_error(
                &ids,
                "database retirement evidence exists without its receipt",
            ));
        }
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
    let history = if snapshots.is_empty() {
        HistoryRequirement::NoRetiredSchedules
    } else {
        match storage {
            RetirementStorage::NotConfigured => HistoryRequirement::NotConfigured,
            RetirementStorage::Available(_) | RetirementStorage::Unavailable => {
                HistoryRequirement::Database
            }
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
    match (receipt.plan.history, storage) {
        (HistoryRequirement::Database, RetirementStorage::Available(store)) => {
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
        (HistoryRequirement::Database, RetirementStorage::Unavailable) => Err(archive_error(
            &ids,
            "linked schedule history storage is unavailable",
        )),
        (HistoryRequirement::Database, RetirementStorage::NotConfigured) => Err(receipt_error(
            &ids,
            "database-backed history proof is required",
        )),
        (HistoryRequirement::NotConfigured | HistoryRequirement::NoRetiredSchedules, _) => Ok(()),
    }
}

async fn require_history_proof(
    storage: RetirementStorage<'_>,
    receipt: &RetiredScheduleRetirementReceipt,
) -> Result<(), CampaignSchedulerError> {
    let ids = receipt_ids(receipt);
    match (receipt.plan.history, storage) {
        (HistoryRequirement::Database, RetirementStorage::Available(store)) => {
            if store
                .schedule_retirement_history_proven(
                    &receipt.operation_id,
                    &receipt.plan_digest,
                    &ids,
                )
                .await
                .map_err(|error| archive_error(&ids, error))?
            {
                Ok(())
            } else {
                Err(receipt_error(&ids, "linked history proof is missing"))
            }
        }
        (HistoryRequirement::Database, RetirementStorage::Unavailable) => Err(archive_error(
            &ids,
            "linked schedule history storage is unavailable",
        )),
        (HistoryRequirement::Database, RetirementStorage::NotConfigured) => Err(receipt_error(
            &ids,
            "database-backed history proof is required",
        )),
        (HistoryRequirement::NotConfigured | HistoryRequirement::NoRetiredSchedules, _) => Ok(()),
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
    let restored = retired_campaigns(current);
    if restored.is_empty() {
        receipt_error(ids, "active schedule compare-and-swap failed")
    } else {
        restored_error(&restored)
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
    faults.before_receipt(receipt.state)?;
    atomic_write_json(path, receipt).map_err(|error| receipt_error(&receipt_ids(receipt), error))
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
    let bytes = read_bounded_optional(path).map_err(|error| receipt_error(&[], error))?;
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
    if uuid::Uuid::parse_str(&receipt.operation_id).is_err() {
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
    for snapshot in &receipt.plan.retired {
        validate_id_bound(&snapshot.schedule.id)?;
        if canonical_digest(&snapshot.schedule)? != snapshot.canonical_digest {
            return Err(receipt_error(
                &ids,
                "retired schedule snapshot digest differs",
            ));
        }
    }
    if operation_plan_digest(&receipt.operation_id, &receipt.plan)? != receipt.plan_digest {
        return Err(receipt_error(&ids, "receipt plan digest differs"));
    }
    Ok(())
}

fn validate_image(image: &ScheduleImage, ids: &[String]) -> Result<(), CampaignSchedulerError> {
    if canonical_digest(&image.schedules)? != image.canonical_digest {
        return Err(receipt_error(ids, "schedule image digest differs"));
    }
    if !image.present && (!image.schedules.is_empty() || image.byte_digest != digest_bytes(&[])) {
        return Err(receipt_error(ids, "absent schedule image contains data"));
    }
    if image.present {
        let expected = pretty_bytes(&image.schedules)?;
        if digest_bytes(&expected) != image.byte_digest
            && image.byte_digest.len() != Sha256::output_size() * 2
        {
            return Err(receipt_error(ids, "schedule byte digest is invalid"));
        }
    }
    Ok(())
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
            faults.before_completion_certificate()?;
            atomic_write_json(&path, &expected)
                .map_err(|error| receipt_error(&receipt_ids(receipt), error))
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
    let bytes = read_bounded_optional(path).map_err(|error| receipt_error(&[], error))?;
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

fn read_bounded_optional(path: &Path) -> Result<Option<Vec<u8>>, StateFileError> {
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
    file.take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| StateFileError::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
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
    match std::fs::read(path) {
        Ok(bytes) => {
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
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(ScheduleImage {
            present: false,
            schedules: Vec::new(),
            canonical_digest: canonical_digest_state(path, &Vec::<Schedule>::new())?,
            byte_digest: digest_bytes(&[]),
        }),
        Err(source) => Err(StateFileError::Io {
            operation: "read",
            path: path.to_path_buf(),
            source,
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

fn validate_id_bound(id: &str) -> Result<(), CampaignSchedulerError> {
    if id.chars().count() <= MAX_ERROR_ID_CHARS {
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

fn is_retired_campaign(schedule: &Schedule) -> bool {
    schedule.workflow_id == crate::scheduler::CAMPAIGN_KIND
        && schedule
            .parameter_values
            .get("engine")
            .and_then(serde_json::Value::as_str)
            .is_some_and(hf_core::retired_engine::is_retired_engine_id)
}

fn restored_error(retired: &[Schedule]) -> CampaignSchedulerError {
    CampaignSchedulerError::RetiredScheduleRestore {
        engine: hf_core::retired_engine::RETIRED_ENGINE_ID,
        schedule_ids: bounded_schedule_ids(&retired_ids(retired)),
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
        let private_id = "P".repeat(MAX_ERROR_ID_CHARS + 1);
        let mut receipt = test_receipt();
        receipt.plan.active_pre.schedules[0].id = private_id.clone();

        let error = validate_receipt(&receipt).unwrap_err();
        let detail = error.to_string();

        assert!(detail.contains("identifier exceeds limit"));
        assert!(!detail.contains(&private_id));
    }
}
