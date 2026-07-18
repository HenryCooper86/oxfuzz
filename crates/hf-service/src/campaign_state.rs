//! Runtime state for portfolio fuzzing campaigns: the rotation cursor, budget
//! consumption, and the global concurrency setting.
//!
//! This is deliberately a JSON sidecar next to `schedules.json`, **not** a
//! database table. Adding a table would trip the storage layer's
//! archive-and-recreate compatibility gate (`hf-storage` migration) and wipe the
//! user's targets/harnesses/runs/crashes on the next launch. State that only the
//! scheduler owns has no business forcing that risk on everything else.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Default cap on how many campaigns fuzz at once. Conservative: fuzzing is
/// CPU/RAM-hungry and each run holds a sandbox.
pub const DEFAULT_MAX_CONCURRENT: usize = 2;

/// How far a portfolio campaign has progressed. Advances only on a real fuzz run
/// (never a skipped fire), so the rotation cursor and the budget stay honest.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignRuntimeState {
    /// Round-robin position over the priority-ordered promoted targets.
    pub cursor: u64,
    /// Completed fuzz runs (drives the max-runs budget and progress display).
    pub runs_done: u32,
    /// Cumulative measured campaign-work seconds (drives max-total-time).
    pub secs_done: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Persisted {
    #[serde(default = "default_max_concurrent")]
    max_concurrent: usize,
    #[serde(default)]
    states: HashMap<String, CampaignRuntimeState>,
}

impl Default for Persisted {
    // Hand-written so an empty store starts at the real default concurrency; a
    // derived `Default` would give 0 (serde defaults only apply on deserialize).
    fn default() -> Self {
        Self {
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            states: HashMap::new(),
        }
    }
}

fn default_max_concurrent() -> usize {
    DEFAULT_MAX_CONCURRENT
}

/// Durable JSON sidecar error. Missing files are handled separately and are not
/// errors; unreadable, corrupt, or unwritable state must be surfaced.
#[derive(Debug, thiserror::Error)]
pub enum StateFileError {
    /// The sidecar could not be read or written.
    #[error("failed to {operation} state file {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The sidecar contained invalid JSON.
    #[error("failed to decode state file {path}: {source}")]
    Decode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// The in-memory value could not be encoded as JSON.
    #[error("failed to encode state file {path}: {source}")]
    Encode {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> StateFileError {
    StateFileError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

/// Read an optional JSON state file while distinguishing absence from damage.
pub(crate) fn read_json_file<T: DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, StateFileError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error("read", path, error)),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| StateFileError::Decode {
            path: path.to_path_buf(),
            source,
        })
}

/// Atomically replace a JSON file after syncing its contents and containing
/// directory. The temporary inode lives beside the destination, so rename is
/// atomic on supported local filesystems.
pub(crate) fn atomic_write_json<T: Serialize>(
    path: &Path,
    value: &T,
) -> Result<(), StateFileError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let body = serde_json::to_vec_pretty(value).map_err(|source| StateFileError::Encode {
        path: path.to_path_buf(),
        source,
    })?;
    std::fs::create_dir_all(parent)
        .map_err(|error| io_error("create directory for", path, error))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".hobot-fuzz-state-")
        .tempfile_in(parent)
        .map_err(|error| io_error("create temporary", path, error))?;
    temporary
        .write_all(&body)
        .map_err(|error| io_error("write temporary", path, error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| io_error("sync temporary", path, error))?;
    temporary
        .persist(path)
        .map_err(|error| io_error("replace", path, error.error))?;
    #[cfg(unix)]
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("sync parent directory for", path, error))?;
    Ok(())
}

/// File-backed store of per-campaign runtime state plus the global concurrency
/// setting. One JSON file, loaded once and written through on every change.
#[derive(Debug)]
pub struct CampaignStateStore {
    path: PathBuf,
    inner: Mutex<Persisted>,
}

impl CampaignStateStore {
    /// Load from `path`. A missing file starts empty; corruption is returned.
    ///
    /// # Errors
    /// Returns a state-file error when an existing sidecar cannot be read or
    /// decoded.
    pub fn try_load(path: PathBuf) -> Result<Self, StateFileError> {
        let inner = read_json_file(&path)?.unwrap_or_default();
        Ok(Self {
            path,
            inner: Mutex::new(inner),
        })
    }

    /// Load from `path`, failing fast if persisted state is damaged.
    ///
    /// Prefer [`Self::try_load`] at boundaries that can return an error.
    ///
    /// # Panics
    /// Panics when an existing state file is unreadable or corrupt.
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        match Self::try_load(path) {
            Ok(store) => store,
            Err(error) => panic!("campaign state cannot be loaded: {error}"),
        }
    }

    /// This campaign's progress, or the zero state if it has never run.
    #[must_use]
    pub fn snapshot(&self, id: &str) -> CampaignRuntimeState {
        self.lock().states.get(id).copied().unwrap_or_default()
    }

    /// Record one successful campaign outcome atomically.
    ///
    /// One campaign fire advances the target cursor once, while `iterations`
    /// charges every completed fuzz iteration and `elapsed` charges measured
    /// wall-clock work. Failed campaign attempts never call this method.
    ///
    /// # Errors
    /// Returns an error without changing in-memory state if persistence fails.
    pub fn record_success(
        &self,
        id: &str,
        iterations: usize,
        elapsed: Duration,
    ) -> Result<CampaignRuntimeState, StateFileError> {
        let mut guard = self.lock();
        let mut candidate = guard.clone();
        let state = candidate.states.entry(id.to_owned()).or_default();
        state.cursor = state.cursor.wrapping_add(1);
        state.runs_done = state
            .runs_done
            .saturating_add(u32::try_from(iterations).unwrap_or(u32::MAX));
        state.secs_done = state.secs_done.saturating_add(elapsed.as_secs());
        let result = *state;
        atomic_write_json(&self.path, &candidate)?;
        *guard = candidate;
        Ok(result)
    }

    /// Advance the target-rotation cursor by one without charging fuzz progress.
    ///
    /// Used on a failed or unrunnable fire (build failure, unparseable engine)
    /// so a target that cannot run yields to the next target on the following
    /// fire instead of pinning the cursor forever and starving the rotation.
    /// Unlike [`Self::record_success`], it leaves `runs_done`/`secs_done` intact
    /// so the budget only ever counts real work.
    ///
    /// # Errors
    /// Returns an error without changing in-memory state if persistence fails.
    pub fn advance_cursor(&self, id: &str) -> Result<CampaignRuntimeState, StateFileError> {
        let mut guard = self.lock();
        let mut candidate = guard.clone();
        let state = candidate.states.entry(id.to_owned()).or_default();
        state.cursor = state.cursor.wrapping_add(1);
        let result = *state;
        atomic_write_json(&self.path, &candidate)?;
        *guard = candidate;
        Ok(result)
    }

    /// Record one completed fuzz run using an explicit second count.
    ///
    /// This compatibility helper fails fast on persistence errors. New campaign
    /// code should call [`Self::record_success`].
    ///
    /// # Panics
    /// Panics when the updated state cannot be persisted.
    pub fn record_run(&self, id: &str, secs: u64) -> CampaignRuntimeState {
        match self.record_success(id, 1, Duration::from_secs(secs)) {
            Ok(state) => state,
            Err(error) => panic!("campaign progress cannot be persisted: {error}"),
        }
    }

    /// Drop a campaign's state transactionally.
    ///
    /// # Errors
    /// Returns an error without changing in-memory state if persistence fails.
    pub fn try_forget(&self, id: &str) -> Result<(), StateFileError> {
        let mut guard = self.lock();
        let mut candidate = guard.clone();
        if candidate.states.remove(id).is_some() {
            atomic_write_json(&self.path, &candidate)?;
            *guard = candidate;
        }
        Ok(())
    }

    /// Drop a campaign's state, failing fast if the change cannot be persisted.
    ///
    /// # Panics
    /// Panics when the updated state cannot be persisted.
    pub fn forget(&self, id: &str) {
        if let Err(error) = self.try_forget(id) {
            panic!("campaign progress cannot be removed: {error}");
        }
    }

    /// The configured concurrency cap (never below 1).
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.lock().max_concurrent.max(1)
    }

    /// Set and transactionally persist the concurrency cap.
    ///
    /// # Errors
    /// Returns an error without changing in-memory state if persistence fails.
    pub fn try_set_max_concurrent(&self, n: usize) -> Result<(), StateFileError> {
        let mut guard = self.lock();
        let mut candidate = guard.clone();
        candidate.max_concurrent = n.max(1);
        atomic_write_json(&self.path, &candidate)?;
        *guard = candidate;
        Ok(())
    }

    /// Set the concurrency cap, failing fast if it cannot be persisted.
    ///
    /// # Panics
    /// Panics when the updated state cannot be persisted.
    pub fn set_max_concurrent(&self, n: usize) {
        if let Err(error) = self.try_set_max_concurrent(n) {
            panic!("campaign concurrency cannot be persisted: {error}");
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Persisted> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A resizable cap on how many campaigns fuzz at once.
///
/// [`Self::try_enter`] returns a permit that frees its slot on drop; `None` means
/// the cap is reached. A blocked fire is **skipped, not queued** -- a short
/// interval over long runs would otherwise pile up unbounded background work.
#[derive(Debug)]
pub struct ConcurrencyGate {
    running: AtomicUsize,
    limit: AtomicUsize,
}

impl ConcurrencyGate {
    /// A gate allowing `limit` concurrent runs (never below 1).
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            running: AtomicUsize::new(0),
            limit: AtomicUsize::new(limit.max(1)),
        }
    }

    /// Resize the cap. Runs already in flight are never interrupted.
    pub fn set_limit(&self, n: usize) {
        self.limit.store(n.max(1), Ordering::SeqCst);
    }

    /// The current cap.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::SeqCst)
    }

    /// How many runs currently hold a permit.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.running.load(Ordering::SeqCst)
    }

    /// Take a slot if one is free. The returned permit frees it on drop.
    pub fn try_enter(self: &Arc<Self>) -> Option<ConcurrencyPermit> {
        loop {
            let cur = self.running.load(Ordering::SeqCst);
            if cur >= self.limit.load(Ordering::SeqCst) {
                return None;
            }
            // CAS so two fires racing for the last slot cannot both win.
            if self
                .running
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(ConcurrencyPermit {
                    gate: Arc::clone(self),
                });
            }
        }
    }
}

/// Holds a concurrency slot for the duration of one campaign run.
#[derive(Debug)]
pub struct ConcurrencyPermit {
    gate: Arc<ConcurrencyGate>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.gate.running.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("campaign_state.json");
        {
            let store = CampaignStateStore::load(path.clone());
            store.record_run("sched-1", 60);
            store.record_run("sched-1", 60);
            store.set_max_concurrent(4);
        }
        // A fresh load sees the persisted state (survives a restart).
        let reloaded = CampaignStateStore::load(path);
        let st = reloaded.snapshot("sched-1");
        assert_eq!(st.runs_done, 2);
        assert_eq!(st.secs_done, 120);
        assert_eq!(st.cursor, 2);
        assert_eq!(reloaded.max_concurrent(), 4);
    }

    #[test]
    fn unknown_campaign_is_the_zero_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = CampaignStateStore::load(dir.path().join("s.json"));
        assert_eq!(store.snapshot("never-run"), CampaignRuntimeState::default());
        // Default concurrency applies before anything is set.
        assert_eq!(store.max_concurrent(), DEFAULT_MAX_CONCURRENT);
    }

    #[test]
    fn forget_resets_a_campaign() {
        let dir = tempfile::tempdir().unwrap();
        let store = CampaignStateStore::load(dir.path().join("s.json"));
        store.record_run("s", 30);
        store.forget("s");
        assert_eq!(store.snapshot("s"), CampaignRuntimeState::default());
    }

    #[test]
    fn concurrency_never_drops_below_one() {
        let dir = tempfile::tempdir().unwrap();
        let store = CampaignStateStore::load(dir.path().join("s.json"));
        store.set_max_concurrent(0);
        assert_eq!(store.max_concurrent(), 1);
    }

    #[test]
    fn gate_admits_up_to_the_limit_then_refuses() {
        let gate = Arc::new(ConcurrencyGate::new(2));
        let a = gate.try_enter().expect("slot 1");
        let b = gate.try_enter().expect("slot 2");
        assert_eq!(gate.in_flight(), 2);
        assert!(gate.try_enter().is_none(), "third must be refused");
        drop(a);
        // Freeing a slot lets the next run in.
        let c = gate.try_enter().expect("slot freed");
        assert_eq!(gate.in_flight(), 2);
        drop(b);
        drop(c);
        assert_eq!(gate.in_flight(), 0);
    }

    #[test]
    fn gate_can_be_resized_up() {
        let gate = Arc::new(ConcurrencyGate::new(1));
        let _a = gate.try_enter().expect("slot 1");
        assert!(gate.try_enter().is_none());
        gate.set_limit(2);
        assert!(gate.try_enter().is_some(), "raising the cap frees a slot");
    }

    #[test]
    fn corrupt_state_is_reported_without_overwriting_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("campaign_state.json");
        std::fs::write(&path, "{not-json").unwrap();

        let error = CampaignStateStore::try_load(path.clone()).expect_err("corruption must fail");

        assert!(error.to_string().contains("decode"));
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{not-json");
    }

    #[test]
    fn failed_persistence_does_not_commit_budget_progress_in_memory() {
        let dir = tempfile::tempdir().unwrap();
        let blocked_parent = dir.path().join("state-dir");
        std::fs::create_dir(&blocked_parent).unwrap();
        let store = CampaignStateStore::try_load(blocked_parent.join("state.json")).unwrap();
        std::fs::remove_dir(&blocked_parent).unwrap();
        std::fs::write(&blocked_parent, "file").unwrap();

        assert!(store
            .record_success("campaign", 3, std::time::Duration::from_secs(17))
            .is_err());
        assert_eq!(store.snapshot("campaign"), CampaignRuntimeState::default());
    }

    #[test]
    fn successful_budget_progress_counts_iterations_and_measured_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = CampaignStateStore::try_load(dir.path().join("state.json")).unwrap();

        let state = store
            .record_success("campaign", 3, std::time::Duration::from_secs(17))
            .unwrap();

        assert_eq!(state.cursor, 1, "one campaign fire advances one target");
        assert_eq!(state.runs_done, 3, "all successful fuzz iterations count");
        assert_eq!(state.secs_done, 17, "charge measured wall-clock work");
    }

    #[test]
    fn advance_cursor_rotates_without_charging_budget() {
        let dir = tempfile::tempdir().unwrap();
        let store = CampaignStateStore::try_load(dir.path().join("state.json")).unwrap();

        // A failing target must yield to the next on the following fire, but a
        // failed fire performs no real fuzz work, so nothing is charged.
        let state = store.advance_cursor("campaign").unwrap();
        assert_eq!(
            state.cursor, 1,
            "a failed fire still rotates to the next target"
        );
        assert_eq!(state.runs_done, 0, "a failed fire charges no iterations");
        assert_eq!(
            state.secs_done, 0,
            "a failed fire charges no wall-clock time"
        );

        // The advance persists across reload.
        let reloaded = CampaignStateStore::try_load(dir.path().join("state.json")).unwrap();
        assert_eq!(reloaded.snapshot("campaign").cursor, 1);
    }
}
