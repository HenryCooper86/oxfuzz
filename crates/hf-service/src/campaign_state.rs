//! Runtime state for portfolio fuzzing campaigns: the rotation cursor, budget
//! consumption, and the global concurrency setting.
//!
//! This is deliberately a JSON sidecar next to `schedules.json`, **not** a
//! database table. Adding a table would trip the storage layer's
//! archive-and-recreate compatibility gate (`hf-storage` migration) and wipe the
//! user's targets/harnesses/runs/crashes on the next launch. State that only the
//! scheduler owns has no business forcing that risk on everything else.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
    /// Cumulative fuzz seconds (drives the max-total-time budget).
    pub secs_done: u64,
}

#[derive(Debug, Serialize, Deserialize)]
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

/// File-backed store of per-campaign runtime state plus the global concurrency
/// setting. One JSON file, loaded once and written through on every change.
#[derive(Debug)]
pub struct CampaignStateStore {
    path: PathBuf,
    inner: Mutex<Persisted>,
}

impl CampaignStateStore {
    /// Load from `path` (best-effort; a missing or corrupt file starts empty).
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        let inner = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str::<Persisted>(&s).ok())
            .unwrap_or_default();
        Self {
            path,
            inner: Mutex::new(inner),
        }
    }

    /// This campaign's progress, or the zero state if it has never run.
    #[must_use]
    pub fn snapshot(&self, id: &str) -> CampaignRuntimeState {
        self.lock().states.get(id).copied().unwrap_or_default()
    }

    /// Record one completed fuzz run: advance the cursor, count the run, add the
    /// seconds. Persists. Returns the new state.
    pub fn record_run(&self, id: &str, secs: u64) -> CampaignRuntimeState {
        let mut guard = self.lock();
        let st = guard.states.entry(id.to_owned()).or_default();
        st.cursor = st.cursor.wrapping_add(1);
        st.runs_done = st.runs_done.saturating_add(1);
        st.secs_done = st.secs_done.saturating_add(secs);
        let out = *st;
        persist(&guard, &self.path);
        out
    }

    /// Drop a campaign's state (on delete), so a recreated campaign starts fresh.
    pub fn forget(&self, id: &str) {
        let mut guard = self.lock();
        if guard.states.remove(id).is_some() {
            persist(&guard, &self.path);
        }
    }

    /// The configured concurrency cap (never below 1).
    #[must_use]
    pub fn max_concurrent(&self) -> usize {
        self.lock().max_concurrent.max(1)
    }

    /// Set (and persist) the concurrency cap.
    pub fn set_max_concurrent(&self, n: usize) {
        let mut guard = self.lock();
        guard.max_concurrent = n.max(1);
        persist(&guard, &self.path);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Persisted> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn persist(state: &Persisted, path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(path, json);
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
}
