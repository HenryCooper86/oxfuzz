//! Run recovery via a persistent run journal, backed by `hf-journal`.
//!
//! `hf-journal`'s [`JournalStore`] models work as *scopes* (Open/Closed/
//! Abandoned) but is in-memory only -- its own docs note a production
//! implementation "would be backed by `SQLite`". A fuzz run can't span an app
//! restart, so a run still `Open` after a restart was interrupted (the app
//! crashed or quit mid-run). [`RunJournal`] supplies the missing durable layer:
//! it mirrors each run as a scope and appends lifecycle events to a write-ahead
//! log, then replays the WAL on startup to surface interrupted runs.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use hf_core::engine::EngineKind;
use hf_journal::storage::{JournalStore, ScopeStatus, ScopeType};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A write-ahead-log line recording a run lifecycle event.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunEvent {
    /// "open", "close", or "dismiss".
    event: String,
    run_id: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    engine: String,
    ts: i64,
}

/// An interrupted run surfaced for recovery.
#[derive(Debug, Clone, Serialize)]
pub struct InterruptedRun {
    pub run_id: String,
    pub project: String,
    pub target: String,
    pub engine: String,
    /// Start time as a Unix timestamp (seconds).
    pub started_at: i64,
}

/// Persistent run journal: scope tracking + a WAL for crash recovery.
pub struct RunJournal {
    store: Mutex<JournalStore>,
    /// Interrupted runs detected at startup (cleared as they are dismissed).
    interrupted: Mutex<Vec<InterruptedRun>>,
    /// WAL path; `None` disables persistence (tests / no data dir).
    wal_path: Option<PathBuf>,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl RunJournal {
    /// A non-persistent journal (no recovery; used where no data dir applies).
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            store: Mutex::new(JournalStore::new()),
            interrupted: Mutex::new(Vec::new()),
            wal_path: None,
        }
    }

    /// Open the journal at `wal_path`, replaying it to detect interrupted runs
    /// (scopes opened but never closed/dismissed). The WAL is then compacted to
    /// just the still-open events so it cannot grow without bound.
    #[must_use]
    pub fn open(wal_path: PathBuf) -> Self {
        let events = read_wal(&wal_path);
        let mut store = JournalStore::new();
        // run_id -> the open event, removed when a matching close/dismiss is seen.
        let mut open: std::collections::HashMap<String, RunEvent> =
            std::collections::HashMap::new();
        for ev in events {
            match ev.event.as_str() {
                "open" => {
                    store.open_scope(&ev.run_id, ScopeType::Pipeline);
                    open.insert(ev.run_id.clone(), ev);
                }
                "close" | "dismiss" => {
                    store.set_scope_status(&ev.run_id, ScopeStatus::Closed);
                    open.remove(&ev.run_id);
                }
                _ => {}
            }
        }
        // Still-open scopes were interrupted.
        let interrupted: Vec<InterruptedRun> = open
            .values()
            .map(|ev| {
                store.set_scope_status(&ev.run_id, ScopeStatus::Abandoned);
                InterruptedRun {
                    run_id: ev.run_id.clone(),
                    project: ev.project.clone(),
                    target: ev.target.clone(),
                    engine: ev.engine.clone(),
                    started_at: ev.ts,
                }
            })
            .collect();
        // Compact: keep only the open events for the runs we still track.
        compact_wal(&wal_path, open.values());
        Self {
            store: Mutex::new(store),
            interrupted: Mutex::new(interrupted),
            wal_path: Some(wal_path),
        }
    }

    /// Interrupted runs awaiting recovery.
    #[must_use]
    pub fn interrupted(&self) -> Vec<InterruptedRun> {
        self.interrupted
            .lock()
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Mark a run as started (opens a scope; appends to the WAL).
    pub fn open_run(&self, run_id: Uuid, project: &Path, target: &str, engine: EngineKind) {
        let id = run_id.to_string();
        if let Ok(mut store) = self.store.lock() {
            store.open_scope(&id, ScopeType::Pipeline);
        }
        self.append(&RunEvent {
            event: "open".to_owned(),
            run_id: id,
            project: project.to_string_lossy().into_owned(),
            target: target.to_owned(),
            engine: format!("{engine:?}"),
            ts: now(),
        });
    }

    /// Mark a run as finished (closes its scope; appends to the WAL).
    pub fn close_run(&self, run_id: Uuid) {
        let id = run_id.to_string();
        if let Ok(mut store) = self.store.lock() {
            store.set_scope_status(&id, ScopeStatus::Closed);
        }
        self.append(&RunEvent {
            event: "close".to_owned(),
            run_id: id,
            project: String::new(),
            target: String::new(),
            engine: String::new(),
            ts: now(),
        });
    }

    /// Dismiss an interrupted run (marks its scope Abandoned; drops it from the
    /// recovery list).
    pub fn dismiss(&self, run_id: &str) {
        if let Ok(mut store) = self.store.lock() {
            store.set_scope_status(run_id, ScopeStatus::Abandoned);
        }
        if let Ok(mut list) = self.interrupted.lock() {
            list.retain(|r| r.run_id != run_id);
        }
        self.append(&RunEvent {
            event: "dismiss".to_owned(),
            run_id: run_id.to_owned(),
            project: String::new(),
            target: String::new(),
            engine: String::new(),
            ts: now(),
        });
    }

    /// Append one event to the WAL (best-effort).
    fn append(&self, ev: &RunEvent) {
        let Some(path) = &self.wal_path else { return };
        let Ok(mut line) = serde_json::to_string(ev) else {
            return;
        };
        line.push('\n');
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(line.as_bytes()) {
                    tracing::warn!("run journal append failed: {e}");
                }
            }
            Err(e) => tracing::warn!("run journal open failed: {e}"),
        }
    }
}

/// Read and parse all WAL lines (best-effort; skips corrupt lines).
fn read_wal(path: &Path) -> Vec<RunEvent> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<RunEvent>(l).ok())
        .collect()
}

/// Rewrite the WAL with only the given (still-open) events.
fn compact_wal<'a>(path: &Path, events: impl Iterator<Item = &'a RunEvent>) {
    let mut body = String::new();
    for ev in events {
        if let Ok(line) = serde_json::to_string(ev) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, body);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_runs_opened_but_not_closed() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");

        // Session 1: two runs start, one finishes.
        let j = RunJournal::open(wal.clone());
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        j.open_run(r1, Path::new("/p"), "t1", EngineKind::LibFuzzer);
        j.open_run(r2, Path::new("/p"), "t2", EngineKind::Honggfuzz);
        j.close_run(r1);
        drop(j); // simulate crash: r2 never closed

        // Session 2: replay -> r2 is interrupted.
        let j2 = RunJournal::open(wal.clone());
        let interrupted = j2.interrupted();
        assert_eq!(interrupted.len(), 1, "expected exactly one interrupted run");
        assert_eq!(interrupted[0].run_id, r2.to_string());
        assert_eq!(interrupted[0].target, "t2");

        // Dismiss it -> gone, and a third session sees nothing.
        j2.dismiss(&r2.to_string());
        assert!(j2.interrupted().is_empty());
        drop(j2);
        let j3 = RunJournal::open(wal);
        assert!(j3.interrupted().is_empty());
    }

    #[test]
    fn in_memory_journal_never_recovers() {
        let j = RunJournal::in_memory();
        j.open_run(Uuid::new_v4(), Path::new("/p"), "t", EngineKind::LibFuzzer);
        assert!(j.interrupted().is_empty());
    }
}
