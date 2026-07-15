//! Run recovery via a persistent run journal, backed by `hf-journal`.
//!
//! `hf-journal`'s [`JournalStore`] models work as *scopes* (Open/Closed/
//! Abandoned) but is in-memory only -- its own docs note a production
//! implementation "would be backed by `SQLite`". A fuzz run can't span an app
//! restart, so a run still `Open` after a restart was interrupted (the app
//! crashed or quit mid-run). [`RunJournal`] supplies the missing durable layer:
//! it mirrors each run as a scope and appends lifecycle events to a write-ahead
//! log, then replays the WAL on startup to surface interrupted runs.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use hf_core::engine::EngineKind;
use hf_journal::storage::{JournalStore, ScopeStatus, ScopeType};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_WAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_WAL_LINE_BYTES: usize = 64 * 1024;
const MAX_WAL_EVENTS: usize = 100_000;

#[derive(Clone, Copy)]
struct WalLimits {
    max_bytes: usize,
    max_line_bytes: usize,
    max_events: usize,
}

impl Default for WalLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_WAL_BYTES,
            max_line_bytes: MAX_WAL_LINE_BYTES,
            max_events: MAX_WAL_EVENTS,
        }
    }
}

struct WalReplay {
    events: Vec<RunEvent>,
    issue: Option<String>,
}

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
    /// Free-form detail for non-lifecycle events (e.g. an auto-revert note).
    #[serde(default)]
    detail: String,
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
    /// Serializes the WAL and matching in-memory lifecycle mutation. Instances
    /// opened on the same path share this lock within the process.
    wal_lock: Arc<Mutex<()>>,
    /// Sticky replay/write failure for callers that need fail-closed startup.
    durability_error: Mutex<Option<String>>,
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
            wal_lock: Arc::new(Mutex::new(())),
            durability_error: Mutex::new(None),
        }
    }

    /// Open the journal at `wal_path`, replaying it to detect interrupted runs
    /// (scopes opened but never closed/dismissed). A fully valid WAL is then
    /// compacted to just the still-open events; a degraded WAL is preserved.
    #[must_use]
    pub fn open(wal_path: PathBuf) -> Self {
        let wal_lock = wal_lock_for_path(&wal_path);
        let _wal_guard = lock_recover(&wal_lock);
        let replay = read_wal(&wal_path);
        let mut store = JournalStore::new();
        // run_id -> the open event, removed when a matching close/dismiss is seen.
        let open = replay_open_events(&replay.events);
        // Still-open scopes were interrupted.
        let interrupted: Vec<InterruptedRun> = open
            .values()
            .map(|ev| {
                store.open_scope(&ev.run_id, ScopeType::Pipeline);
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
        // Compact only a fully valid replay. If even one record is malformed,
        // preserve the original WAL byte-for-byte so ambiguous open-run
        // evidence remains available for recovery and operator inspection.
        let mut durability_error = replay.issue;
        if durability_error.is_none() {
            if let Err(error) = compact_wal(&wal_path, open.values()) {
                durability_error = Some(format!(
                    "run journal compaction durability could not be confirmed: {error}"
                ));
            }
        }
        if let Some(error) = &durability_error {
            tracing::error!(%error, path = %wal_path.display(), "run journal is degraded");
        }
        Self {
            store: Mutex::new(store),
            interrupted: Mutex::new(interrupted),
            wal_path: Some(wal_path),
            wal_lock: Arc::clone(&wal_lock),
            durability_error: Mutex::new(durability_error),
        }
    }

    /// Return the first unresolved replay or write error, if durability has
    /// degraded. Callers that require fail-closed execution must refuse to
    /// start new runs while this returns `Some`.
    #[must_use]
    pub fn durability_error(&self) -> Option<String> {
        lock_recover(&self.durability_error).clone()
    }

    /// Interrupted runs awaiting recovery.
    #[must_use]
    pub fn interrupted(&self) -> Vec<InterruptedRun> {
        lock_recover(&self.interrupted).clone()
    }

    /// Mark a run as started (opens a scope; appends to the WAL).
    pub fn open_run(&self, run_id: Uuid, project: &Path, target: &str, engine: EngineKind) {
        let id = run_id.to_string();
        let event = RunEvent {
            event: "open".to_owned(),
            run_id: id.clone(),
            project: project.to_string_lossy().into_owned(),
            target: target.to_owned(),
            engine: format!("{engine:?}"),
            detail: String::new(),
            ts: now(),
        };
        let _wal_guard = lock_recover(&self.wal_lock);
        if self.append_locked(&event) {
            lock_recover(&self.store).open_scope(&id, ScopeType::Pipeline);
        }
    }

    /// Record a non-lifecycle note against a run (e.g. an auto-revert firing).
    /// Appended to the WAL for the audit trail; ignored by recovery replay
    /// (unknown event strings do not reopen a scope).
    pub fn note(&self, run_id: Uuid, event: &str, detail: &str) {
        let event = RunEvent {
            event: event.to_owned(),
            run_id: run_id.to_string(),
            project: String::new(),
            target: String::new(),
            engine: String::new(),
            detail: detail.to_owned(),
            ts: now(),
        };
        let _wal_guard = lock_recover(&self.wal_lock);
        self.append_locked(&event);
    }

    /// Mark a run as finished (closes its scope; appends to the WAL).
    pub fn close_run(&self, run_id: Uuid) {
        let id = run_id.to_string();
        let event = RunEvent {
            event: "close".to_owned(),
            run_id: id.clone(),
            project: String::new(),
            target: String::new(),
            engine: String::new(),
            detail: String::new(),
            ts: now(),
        };
        let _wal_guard = lock_recover(&self.wal_lock);
        if self.append_locked(&event) {
            lock_recover(&self.store).set_scope_status(&id, ScopeStatus::Closed);
        }
    }

    /// Dismiss an interrupted run (marks its scope Abandoned; drops it from the
    /// recovery list).
    pub fn dismiss(&self, run_id: &str) {
        let event = RunEvent {
            event: "dismiss".to_owned(),
            run_id: run_id.to_owned(),
            project: String::new(),
            target: String::new(),
            engine: String::new(),
            detail: String::new(),
            ts: now(),
        };
        let _wal_guard = lock_recover(&self.wal_lock);
        if self.append_locked(&event) {
            lock_recover(&self.store).set_scope_status(run_id, ScopeStatus::Abandoned);
            lock_recover(&self.interrupted).retain(|run| run.run_id != run_id);
        }
    }

    /// Append while `wal_lock` is held, recording a sticky error on failure.
    fn append_locked(&self, event: &RunEvent) -> bool {
        let Some(path) = &self.wal_path else {
            return true;
        };
        if let Err(error) = append_wal(path, event) {
            let message = format!("run journal append failed: {error}");
            tracing::error!(%error, path = %path.display(), "run journal append failed");
            let mut durability_error = lock_recover(&self.durability_error);
            if durability_error.is_none() {
                *durability_error = Some(message);
            }
            false
        } else {
            true
        }
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn wal_lock_for_path(path: &Path) -> Arc<Mutex<()>> {
    static WAL_LOCKS: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>> = OnceLock::new();

    let locks = WAL_LOCKS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut locks = lock_recover(locks);
    locks.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
    lock
}

fn replay_open_events(events: &[RunEvent]) -> BTreeMap<String, RunEvent> {
    let mut open = BTreeMap::new();
    for event in events {
        match event.event.as_str() {
            "open" => {
                open.insert(event.run_id.clone(), event.clone());
            }
            "close" | "dismiss" => {
                open.remove(&event.run_id);
            }
            _ => {}
        }
    }
    open
}

fn read_wal(path: &Path) -> WalReplay {
    read_wal_with_limits(path, WalLimits::default())
}

/// Read a bounded WAL prefix and retain every valid record in that prefix.
/// Any ambiguity disables compaction so the source bytes remain untouched.
fn read_wal_with_limits(path: &Path, limits: WalLimits) -> WalReplay {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return WalReplay {
                events: Vec::new(),
                issue: None,
            };
        }
        Err(error) => {
            return WalReplay {
                events: Vec::new(),
                issue: Some(format!(
                    "run journal could not be read; raw WAL was not compacted: {error}"
                )),
            };
        }
    };

    let read_limit = limits.max_bytes.saturating_add(1);
    let mut bytes = Vec::new();
    if let Err(error) = file.take(read_limit as u64).read_to_end(&mut bytes) {
        return WalReplay {
            events: Vec::new(),
            issue: Some(format!(
                "run journal read failed; raw WAL was not compacted: {error}"
            )),
        };
    }

    let mut issues = Vec::new();
    if bytes.len() > limits.max_bytes {
        add_issue(
            &mut issues,
            format!("WAL exceeds the {}-byte replay limit", limits.max_bytes),
        );
        bytes.truncate(limits.max_bytes);
    }

    let mut events = Vec::new();
    let mut offset = 0;
    let mut line_number = 0;
    while offset < bytes.len() {
        line_number += 1;
        if line_number > limits.max_events {
            add_issue(
                &mut issues,
                format!("WAL exceeds the {}-event replay limit", limits.max_events),
            );
            break;
        }

        let remaining = &bytes[offset..];
        let newline = remaining.iter().position(|byte| *byte == b'\n');
        let (line, consumed, terminated) = match newline {
            Some(index) => (&remaining[..index], index + 1, true),
            None => (remaining, remaining.len(), false),
        };
        if !terminated {
            add_issue(&mut issues, format!("line {line_number} is unterminated"));
        }
        if line.len() > limits.max_line_bytes {
            add_issue(
                &mut issues,
                format!(
                    "line {line_number} exceeds the {}-byte line limit",
                    limits.max_line_bytes
                ),
            );
        } else if line.is_empty() {
            add_issue(&mut issues, format!("line {line_number} is empty"));
        } else {
            match serde_json::from_slice::<RunEvent>(line) {
                Ok(event) => events.push(event),
                Err(error) => add_issue(
                    &mut issues,
                    format!("line {line_number} is invalid JSON: {error}"),
                ),
            }
        }
        offset = offset.saturating_add(consumed);
    }

    WalReplay {
        events,
        issue: (!issues.is_empty()).then(|| {
            format!(
                "run journal replay degraded ({}); raw WAL was preserved without compaction",
                issues.join("; ")
            )
        }),
    }
}

fn add_issue(issues: &mut Vec<String>, issue: String) {
    const MAX_REPORTED_ISSUES: usize = 4;
    if issues.len() < MAX_REPORTED_ISSUES {
        issues.push(issue);
    }
}

fn serialize_event(event: &RunEvent) -> io::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > MAX_WAL_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("event exceeds the {MAX_WAL_LINE_BYTES}-byte WAL line limit"),
        ));
    }
    Ok(line)
}

fn append_wal(path: &Path, event: &RunEvent) -> io::Result<()> {
    let line = serialize_event(event)?;
    let parent = parent_directory(path);
    std::fs::create_dir_all(parent)?;
    // Reserve one extra byte in case a prior crash left an unterminated tail.
    // Capacity checks may atomically replace the WAL, so open the append handle
    // only after that check completes.
    ensure_append_capacity(path, line.len().saturating_add(1))?;
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    let needs_separator = if file.metadata()?.len() == 0 {
        false
    } else {
        file.seek(SeekFrom::End(-1))?;
        let mut last_byte = [0_u8; 1];
        file.read_exact(&mut last_byte)?;
        last_byte[0] != b'\n'
    };
    if needs_separator {
        file.write_all(b"\n")?;
    }
    file.write_all(&line)?;
    file.sync_all()?;
    sync_parent_directory(parent)
}

fn ensure_append_capacity(path: &Path, append_bytes: usize) -> io::Result<()> {
    let current_bytes = match std::fs::metadata(path) {
        Ok(metadata) => metadata_len(&metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error),
    };
    if current_bytes.saturating_add(append_bytes) <= MAX_WAL_BYTES {
        return Ok(());
    }

    let replay = read_wal(path);
    if let Some(issue) = replay.issue {
        return Err(io::Error::new(io::ErrorKind::InvalidData, issue));
    }
    let open = replay_open_events(&replay.events);
    compact_wal(path, open.values())?;

    let compacted_bytes = match std::fs::metadata(path) {
        Ok(metadata) => metadata_len(&metadata),
        Err(error) => return Err(error),
    };
    if compacted_bytes.saturating_add(append_bytes) > MAX_WAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("open-run evidence exceeds the {MAX_WAL_BYTES}-byte WAL limit"),
        ));
    }
    Ok(())
}

/// Atomically rewrite the WAL with the given events. The caller supplies a
/// deterministic iterator (the service uses `BTreeMap::values`).
fn compact_wal<'a>(path: &Path, events: impl Iterator<Item = &'a RunEvent>) -> io::Result<()> {
    let mut body = Vec::new();
    for event in events {
        let line = serialize_event(event)?;
        if body.len().saturating_add(line.len()) > MAX_WAL_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("open-run evidence exceeds the {MAX_WAL_BYTES}-byte WAL limit"),
            ));
        }
        body.extend_from_slice(&line);
    }

    let parent = parent_directory(path);
    std::fs::create_dir_all(parent)?;
    let temporary = path.with_extension(format!("jsonl.{}.tmp", Uuid::new_v4()));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&body)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        sync_parent_directory(parent)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn metadata_len(metadata: &std::fs::Metadata) -> usize {
    match usize::try_from(metadata.len()) {
        Ok(length) => length,
        Err(_) => usize::MAX,
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn event(event: &str, run_id: &str, target: &str, ts: i64) -> RunEvent {
        RunEvent {
            event: event.to_owned(),
            run_id: run_id.to_owned(),
            project: "/p".to_owned(),
            target: target.to_owned(),
            engine: "LibFuzzer".to_owned(),
            detail: String::new(),
            ts,
        }
    }

    fn json_line(event: &RunEvent) -> String {
        format!("{}\n", serde_json::to_string(event).unwrap())
    }

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

    #[test]
    fn concurrent_appends_are_complete_and_parseable() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let journals = [
            Arc::new(RunJournal::open(wal.clone())),
            Arc::new(RunJournal::open(wal.clone())),
        ];
        let mut threads = Vec::new();

        for worker in 0..4 {
            let journal = Arc::clone(&journals[worker % journals.len()]);
            threads.push(std::thread::spawn(move || {
                for sequence in 0..4 {
                    journal.note(
                        Uuid::new_v4(),
                        "concurrency-test",
                        &format!("worker={worker};sequence={sequence}"),
                    );
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        drop(journals);

        let replay = read_wal(&wal);
        assert!(replay.issue.is_none(), "{:?}", replay.issue);
        assert_eq!(replay.events.len(), 4 * 4);
    }

    #[test]
    fn compaction_orders_open_runs_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let mut body = json_line(&event("open", "run-z", "z", 2));
        body.push_str(&json_line(&event("open", "run-a", "a", 1)));
        std::fs::write(&wal, body).unwrap();

        let journal = RunJournal::open(wal.clone());
        assert!(journal.durability_error().is_none());
        let replay = read_wal(&wal);
        let ids = replay
            .events
            .iter()
            .map(|event| event.run_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(ids, ["run-a", "run-z"]);
    }

    #[test]
    fn corrupt_line_is_reported_and_preserved_without_losing_valid_open_run() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let mut original = json_line(&event("open", "still-open", "target", 1));
        original.push_str("{this is not json}\n");
        std::fs::write(&wal, &original).unwrap();

        let journal = RunJournal::open(wal.clone());

        assert_eq!(journal.interrupted().len(), 1);
        let error = journal.durability_error().expect("corruption must surface");
        assert!(error.contains("line 2"), "unexpected error: {error}");
        assert_eq!(std::fs::read_to_string(&wal).unwrap(), original);
    }

    #[test]
    fn truncated_tail_is_reported_and_wal_is_not_compacted() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let mut original = json_line(&event("open", "valid-open", "target", 1));
        original.push_str(r#"{"event":"open","run_id":"partial"#);
        std::fs::write(&wal, &original).unwrap();

        let journal = RunJournal::open(wal.clone());

        assert_eq!(journal.interrupted()[0].run_id, "valid-open");
        let error = journal.durability_error().expect("truncation must surface");
        assert!(error.contains("unterminated"), "unexpected error: {error}");
        assert_eq!(std::fs::read_to_string(&wal).unwrap(), original);
    }

    #[test]
    fn wal_reader_stops_at_configured_byte_limit() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let original = format!(
            "{}{}",
            json_line(&event("open", "visible", "target", 1)),
            "x".repeat(1_024)
        );
        std::fs::write(&wal, &original).unwrap();

        let replay = read_wal_with_limits(
            &wal,
            WalLimits {
                max_bytes: 512,
                max_line_bytes: 256,
                max_events: 32,
            },
        );

        assert_eq!(replay.events[0].run_id, "visible");
        let issue = replay.issue.expect("oversized WAL must surface");
        assert!(issue.contains("512-byte"), "unexpected issue: {issue}");
        assert_eq!(std::fs::read_to_string(&wal).unwrap(), original);
    }

    #[test]
    fn oversized_event_is_rejected_without_a_partial_record() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let journal = RunJournal::open(wal.clone());

        journal.note(Uuid::new_v4(), "oversized", &"x".repeat(MAX_WAL_LINE_BYTES));

        let error = journal
            .durability_error()
            .expect("oversized event must surface");
        assert!(error.contains("line limit"), "unexpected error: {error}");
        assert!(std::fs::read(&wal).unwrap().is_empty());
    }

    #[test]
    fn append_after_truncated_tail_starts_a_new_replayable_record() {
        let dir = tempfile::tempdir().unwrap();
        let wal = dir.path().join("run_journal.jsonl");
        let mut original = json_line(&event("open", "valid-open", "target", 1));
        original.push_str(r#"{"event":"open","run_id":"partial"#);
        std::fs::write(&wal, original).unwrap();

        let journal = RunJournal::open(wal.clone());
        journal.dismiss("valid-open");
        drop(journal);

        let reopened = RunJournal::open(wal);
        assert!(reopened.interrupted().is_empty());
        assert!(reopened.durability_error().is_some());
    }
}
