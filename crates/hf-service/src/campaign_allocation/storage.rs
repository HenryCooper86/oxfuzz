//! Synced project allocation state and cross-process admission exclusion.
use super::{
    invalid, proposal_digest, AllocationCandidate, AllocationGrant, AllocationProposal,
    AllocationStatus, AllocationView, ClassifiedError, Digest, Sha256, Uuid,
};
use crate::campaign_state::{atomic_write_json, read_json_file};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};

pub(crate) struct AllocationStore {
    directory: PathBuf,
    project: PathBuf,
}

/// In-process per-directory gates for the allocation read-decide-write cycle.
///
/// The advisory `flock` in [`AllocationStore::lock`] only excludes across open
/// file descriptions, so on Linux two `reserve` calls in this process can each
/// hold "the" lock over an interleaved read/write and over-commit the quota.
/// Every mutating operation takes its directory's mutex for the whole
/// read->decide->write section; the `flock` stays as a courtesy lock for other
/// processes. Mirrors the registry pattern of `schedule_retirement`'s
/// `PROCESS_PATH_LOCKS`.
static PROCESS_ALLOCATION_LOCKS: LazyLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Acquire this store's in-process gate, creating it on first use. The guard
/// pins the shared `Arc` so the registry entry outlives the lock scope.
fn process_lock(directory: &Path) -> Arc<Mutex<()>> {
    // The directory may not exist yet (a first `propose` creates it); the
    // canonical identity is therefore the configured absolute path, which is
    // stable for every store over the same root.
    let key = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| directory.to_path_buf(), |cwd| cwd.join(directory))
    };
    let mut locks = PROCESS_ALLOCATION_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks.retain(|_, lock| lock.strong_count() > 0);
    locks.get(&key).and_then(Weak::upgrade).unwrap_or_else(|| {
        let lock = Arc::new(Mutex::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    })
}

impl AllocationStore {
    pub(crate) fn new(root: &Path, project: PathBuf) -> Self {
        let digest = format!(
            "{:x}",
            Sha256::digest(project.as_os_str().as_encoded_bytes())
        );
        Self {
            directory: root.join(digest),
            project,
        }
    }
    pub(super) fn path(&self) -> PathBuf {
        self.directory.join("current.json")
    }
    fn lock(&self) -> Result<File, ClassifiedError> {
        std::fs::create_dir_all(&self.directory).map_err(storage_error)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.directory.join(".lock"))
            .map_err(storage_error)?;
        lock.try_lock().map_err(|error| {
            invalid(format!(
                "project allocation is busy or unavailable: {error}"
            ))
        })?;
        Ok(lock)
    }
    fn read(&self) -> Result<Option<AllocationView>, ClassifiedError> {
        match std::fs::metadata(self.path()) {
            Ok(metadata) if metadata.len() > 16 * 1024 * 1024 => {
                return Err(invalid("allocation state exceeds its size limit"))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(storage_error(error)),
        }
        let view: Option<AllocationView> = read_json_file(&self.path()).map_err(storage_error)?;
        if let Some(view) = &view {
            validate(view, &self.project)?;
        }
        Ok(view)
    }
    pub(crate) fn inspect(&self) -> Result<Option<AllocationView>, ClassifiedError> {
        self.read()
    }
    pub(crate) fn propose(
        &self,
        proposal: AllocationProposal,
    ) -> Result<AllocationView, ClassifiedError> {
        // The in-process gate serializes the whole read->decide->write; the
        // advisory flock below only excludes other processes (VULN-002).
        // The process guard is held (not dropped) until the end of the
        // operation: its lifetime, not a read, is what excludes concurrent
        // writers in this process.
        let gate = process_lock(&self.directory);
        let _process_guard = gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _lock = self.lock()?;
        if let Some(previous) = self.read()? {
            if previous.status != AllocationStatus::Revoked {
                return Err(invalid(
                    "revoke the current allocation before proposing another",
                ));
            }
            atomic_write_json(
                &self
                    .directory
                    .join(format!("{}.json", previous.proposal.id)),
                &previous,
            )
            .map_err(storage_error)?;
        }
        let view = AllocationView {
            digest: proposal_digest(&proposal)?,
            proposal,
            status: AllocationStatus::Draft,
            reviewed_at: None,
            reservations: Vec::new(),
        };
        validate(&view, &self.project)?;
        self.write(&view)?;
        Ok(view)
    }
    pub(crate) fn review(
        &self,
        id: Uuid,
        digest: &str,
        approve: bool,
    ) -> Result<AllocationView, ClassifiedError> {
        // The process guard is held (not dropped) until the end of the
        // operation: its lifetime, not a read, is what excludes concurrent
        // writers in this process.
        let gate = process_lock(&self.directory);
        let _process_guard = gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _lock = self.lock()?;
        let mut view = self
            .read()?
            .ok_or_else(|| invalid("no project allocation exists"))?;
        if view.proposal.id != id || view.digest != digest {
            return Err(invalid(
                "allocation changed; reload and review the exact proposal",
            ));
        }
        if approve && view.status != AllocationStatus::Draft {
            return Err(invalid("only a draft allocation can be approved"));
        }
        view.status = if approve {
            AllocationStatus::Approved
        } else {
            AllocationStatus::Revoked
        };
        view.reviewed_at = Some(chrono::Utc::now().to_rfc3339());
        self.write(&view)?;
        Ok(view)
    }
    pub(crate) fn reserve(
        &self,
        schedule: &str,
        candidates: &[AllocationCandidate],
        requested_secs: u64,
    ) -> Result<Option<AllocationGrant>, ClassifiedError> {
        // The process guard is held (not dropped) until the end of the
        // operation: its lifetime, not a read, is what excludes concurrent
        // writers in this process.
        let gate = process_lock(&self.directory);
        let _process_guard = gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.read()?.is_none() {
            return Ok(None);
        }
        let _lock = self.lock()?;
        let Some(mut view) = self.read()? else {
            return Err(invalid("allocation disappeared during admission"));
        };
        if !cfg!(feature = "campaign-allocation") {
            return Err(invalid(
                "project has an allocation but campaign-allocation is disabled",
            ));
        }
        if view.status != AllocationStatus::Approved {
            return Err(invalid("project allocation is not approved"));
        }
        if schedule.is_empty() || schedule.len() > 1024 || requested_secs == 0 {
            return Err(invalid(
                "allocation reservation needs a schedule and positive duration",
            ));
        }
        let count = view.reservations.len();
        let entries = &view.proposal.entries;
        let entry = (0..entries.len()).map(|offset| &entries[(count + offset) % entries.len()]).find(|entry| {
            candidates.contains(&entry.candidate) && view.reservations.iter().filter(|grant| grant.candidate == entry.candidate).count() < entry.max_runs as usize
        }).ok_or_else(|| invalid("no allocation allowance for this schedule's current promoted harnesses; quota may be exhausted or approval stale"))?;
        let grant = AllocationGrant {
            id: Uuid::new_v4(),
            plan_id: view.proposal.id,
            schedule_id: schedule.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
            candidate: entry.candidate.clone(),
            duration_secs: requested_secs.min(view.proposal.per_run_secs),
        };
        view.reservations.push(grant.clone());
        self.write(&view)?;
        Ok(Some(grant))
    }

    /// The in-process gate for this store's directory, so tests can prove the
    /// mutating operations serialize behind it.
    #[cfg(all(test, feature = "campaign-allocation"))]
    pub(super) fn process_gate_for_test(&self) -> Arc<Mutex<()>> {
        process_lock(&self.directory)
    }
    fn write(&self, view: &AllocationView) -> Result<(), ClassifiedError> {
        atomic_write_json(&self.path(), view).map_err(storage_error)
    }
}
fn storage_error(error: impl std::fmt::Display) -> ClassifiedError {
    ClassifiedError::Storage(format!("allocation state: {error}"))
}
fn validate(view: &AllocationView, project: &Path) -> Result<(), ClassifiedError> {
    let proposal = &view.proposal;
    if proposal.schema_version != 1
        || proposal.project != project.to_string_lossy()
        || proposal.entries.is_empty()
        || proposal.entries.len() > 64
        || proposal.max_runs == 0
        || proposal.max_runs > 10_000
        || proposal.per_run_secs == 0
        || proposal.max_total_secs > 31_536_000
        || proposal.max_total_secs / u64::from(proposal.max_runs) != proposal.per_run_secs
        || proposal.max_total_secs % u64::from(proposal.max_runs) != proposal.unallocated_secs
        || proposal_digest(proposal)? != view.digest
        || view.reservations.len() > proposal.max_runs as usize
        || proposal
            .entries
            .iter()
            .map(|entry| u64::from(entry.max_runs))
            .sum::<u64>()
            != u64::from(proposal.max_runs)
    {
        return Err(invalid(
            "invalid retained allocation proposal or accounting",
        ));
    }
    let mut identities = std::collections::HashSet::new();
    for entry in &proposal.entries {
        if entry.max_runs == 0
            || !identities.insert(entry.candidate.harness_id)
            || entry.evidence.len() > 2
            || !(1..=2).contains(&entry.weight)
            || entry.candidate.source_sha256.len() != 64
            || !entry
                .candidate
                .source_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || view
                .reservations
                .iter()
                .filter(|grant| grant.candidate == entry.candidate)
                .count()
                > entry.max_runs as usize
        {
            return Err(invalid("invalid retained allocation entry"));
        }
    }
    let mut grants = std::collections::HashSet::new();
    if view.reservations.iter().any(|grant| {
        !grants.insert(grant.id)
            || grant.plan_id != proposal.id
            || grant.duration_secs == 0
            || grant.duration_secs > proposal.per_run_secs
            || !proposal
                .entries
                .iter()
                .any(|entry| entry.candidate == grant.candidate)
    }) {
        return Err(invalid("invalid retained allocation reservation"));
    }
    Ok(())
}
