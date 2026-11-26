//! Binary-only session history, live progress, and continuation checks.
//!
//! A session's record is the `report.json` it wrote under the project's own
//! `.binary/<sha16>/<session>/` directory, so history is a bounded scan of
//! that directory and never trusts a path a report states. A running session
//! is kept in a per-process registry with its stage, and its progress is the
//! `fuzzer_stats` AFL++ refreshes in the session's output directory.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::binary_issue::read_session_report;
use super::binary_only::{BinaryFuzzOutcome, BinaryInput, BinaryStage, ElfMachine, REPORT_NAME};
use super::project_identity::project_slug;
use super::workspace::prepare_configured_workspace_root;
use super::ServiceContainer;

/// Most binaries and sessions per binary walked, and most sessions listed.
const MAX_BINARIES: usize = 256;
const MAX_SESSIONS_PER_BINARY: usize = 256;
const MAX_LISTED_SESSIONS: usize = 200;
/// Largest `fuzzer_stats` snapshot read for progress.
const MAX_STATS_BYTES: u64 = 64 * 1024;

fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(message.into())
}

/// One session running in this process.
#[derive(Debug, Clone)]
pub(crate) struct ActiveBinarySession {
    project: String,
    binary_name: String,
    root: PathBuf,
    started_at: DateTime<Utc>,
    duration_secs: u64,
    stage: BinaryStage,
}

/// The sessions running in this process, by session id.
pub(crate) type BinarySessionRegistry = Arc<Mutex<HashMap<Uuid, ActiveBinarySession>>>;

/// Removes a session from the registry when it ends, however it ends.
pub(crate) struct ActiveSessionGuard {
    registry: BinarySessionRegistry,
    session: Uuid,
}

impl Drop for ActiveSessionGuard {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.registry.lock() {
            sessions.remove(&self.session);
        }
    }
}

/// Record that `session` reached `stage`.
pub(super) fn set_stage(registry: &BinarySessionRegistry, session: Uuid, stage: BinaryStage) {
    if let Ok(mut sessions) = registry.lock() {
        if let Some(active) = sessions.get_mut(&session) {
            active.stage = stage;
        }
    }
}

/// A running session as the desktop polls it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinaryProgress {
    pub session: Uuid,
    pub binary_name: String,
    pub stage: BinaryStage,
    pub started_at: DateTime<Utc>,
    pub duration_secs: u64,
    pub elapsed_secs: u64,
    pub execs_done: Option<u64>,
    pub execs_per_sec: Option<f64>,
    pub edges_found: Option<u64>,
    pub corpus_count: Option<u64>,
    pub saved_crashes: Option<u64>,
    pub saved_hangs: Option<u64>,
}

/// One earlier session, as the history lists it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinarySessionSummary {
    pub session: Uuid,
    /// The session directory as found on disk, not as the report states it.
    pub workspace: PathBuf,
    pub binary_name: String,
    pub binary_sha256: String,
    pub machine: ElfMachine,
    pub input: BinaryInput,
    pub duration_secs: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub execs_done: Option<u64>,
    pub findings: usize,
    pub distinct_findings: usize,
    pub confirmed: usize,
    pub minimized: usize,
    pub continued_from: Option<Uuid>,
    /// Whether the directory still holds the binary, so the session can be
    /// continued.
    pub can_continue: bool,
}

fn progress_of(id: Uuid, active: &ActiveBinarySession, now: DateTime<Utc>) -> BinaryProgress {
    let stats_path = active.root.join("out").join("default").join("fuzzer_stats");
    // AFL++ writes the file once it is fuzzing; before that, and when it is
    // unreadable or malformed mid-write, the progress has no counters.
    let stats = std::fs::metadata(&stats_path)
        .ok()
        .filter(|metadata| metadata.is_file() && metadata.len() <= MAX_STATS_BYTES)
        .and_then(|_| std::fs::read(&stats_path).ok())
        .and_then(|contents| hf_engine::afl::parse_fuzzer_stats(&contents).ok());
    let elapsed = now
        .signed_duration_since(active.started_at)
        .num_seconds()
        .max(0);
    BinaryProgress {
        session: id,
        binary_name: active.binary_name.clone(),
        stage: active.stage,
        started_at: active.started_at,
        duration_secs: active.duration_secs,
        elapsed_secs: elapsed.unsigned_abs(),
        execs_done: stats.as_ref().and_then(|stats| stats.execs_done),
        execs_per_sec: stats.as_ref().and_then(|stats| stats.execs_per_sec),
        edges_found: stats.as_ref().and_then(|stats| stats.edges_found),
        corpus_count: stats.as_ref().and_then(|stats| stats.corpus_count),
        saved_crashes: stats.as_ref().and_then(|stats| stats.saved_crashes),
        saved_hangs: stats.as_ref().and_then(|stats| stats.saved_hangs),
    }
}

fn summarize(outcome: &BinaryFuzzOutcome, workspace: &Path) -> BinarySessionSummary {
    BinarySessionSummary {
        session: outcome.session,
        workspace: workspace.to_path_buf(),
        binary_name: outcome.binary_name.clone(),
        binary_sha256: outcome.binary_sha256.clone(),
        machine: outcome.machine,
        input: outcome.input,
        duration_secs: outcome.duration_secs,
        started_at: outcome.started_at,
        finished_at: outcome.finished_at,
        execs_done: outcome.execs_done,
        findings: outcome.findings.len(),
        distinct_findings: outcome.distinct_findings,
        confirmed: outcome
            .findings
            .iter()
            .filter(|finding| finding.confirmed)
            .count(),
        minimized: outcome
            .findings
            .iter()
            .filter(|finding| finding.minimized.is_some())
            .count(),
        continued_from: outcome.continued_from,
        can_continue: workspace
            .join("target")
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.is_file()),
    }
}

/// Real subdirectories of `directory` (no symbolic links), in name order,
/// at most `limit`.
fn subdirectories(directory: &Path, limit: usize) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        // A missing directory has no sessions.
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        // An unreadable entry is skipped; the others are still listed.
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .map(|entry| entry.path())
        .collect();
    found.sort();
    found.truncate(limit);
    found
}

/// Every readable session report under `sessions` (a project's `.binary`
/// directory), newest first, with the directory each was found in. A report
/// whose recorded session id differs from its directory is skipped.
fn sessions_in(sessions: &Path) -> Vec<(BinaryFuzzOutcome, PathBuf)> {
    let mut found = Vec::new();
    for binary in subdirectories(sessions, MAX_BINARIES) {
        for session in subdirectories(&binary, MAX_SESSIONS_PER_BINARY) {
            let Some(id) = session
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            // A session that failed before writing its report, or whose
            // report is unreadable, is not listed.
            let Ok(outcome) = read_session_report(sessions, &session.join(REPORT_NAME)) else {
                continue;
            };
            if outcome.session != id {
                continue;
            }
            found.push((outcome, session));
        }
    }
    found.sort_by(|(a, _), (b, _)| b.finished_at.cmp(&a.finished_at));
    found.truncate(MAX_LISTED_SESSIONS);
    found
}

/// Check that `previous` is a session directory of the binary whose digest
/// is `sha256`, before its queue seeds a new session.
pub(super) fn verify_same_binary(previous: &Path, sha256: &str) -> Result<(), ClassifiedError> {
    let is_directory = previous
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_dir());
    if !is_directory {
        return Err(invalid(
            "there is no earlier session of this binary in this project to continue",
        ));
    }
    let report = previous.join(REPORT_NAME);
    if let Some(parent) = previous.parent() {
        if let Ok(outcome) = read_session_report(parent, &report) {
            if outcome.binary_sha256 != sha256 {
                return Err(invalid(
                    "the earlier session fuzzed a different binary; continue a session of this one",
                ));
            }
        }
    }
    Ok(())
}

impl ServiceContainer {
    fn binary_sessions_dir(project: &Path) -> Result<PathBuf, ClassifiedError> {
        Ok(prepare_configured_workspace_root()?
            .join(PathBuf::from(project_slug(project)))
            .join(".binary"))
    }

    pub(super) fn binary_session_registry(&self) -> BinarySessionRegistry {
        Arc::clone(&self.binary_sessions)
    }

    /// Register a starting session; it is removed when the guard drops.
    pub(super) fn track_binary_session(
        &self,
        session: Uuid,
        project: &Path,
        binary_name: String,
        root: &Path,
        duration_secs: u64,
    ) -> ActiveSessionGuard {
        if let Ok(mut sessions) = self.binary_sessions.lock() {
            sessions.insert(
                session,
                ActiveBinarySession {
                    project: project_slug(project),
                    binary_name,
                    root: root.to_path_buf(),
                    started_at: Utc::now(),
                    duration_secs,
                    stage: BinaryStage::Preparing,
                },
            );
        }
        ActiveSessionGuard {
            registry: self.binary_session_registry(),
            session,
        }
    }

    /// The progress of the binary-only session running for `project` in this
    /// process (the most recently started one), or `None` when none runs.
    #[must_use]
    pub fn binary_progress(&self, project: &Path) -> Option<BinaryProgress> {
        let slug = project_slug(project);
        let sessions = self.binary_sessions.lock().ok()?;
        sessions
            .iter()
            .filter(|(_, active)| active.project == slug)
            .max_by_key(|(_, active)| active.started_at)
            .map(|(id, active)| progress_of(*id, active, Utc::now()))
    }

    /// The project's earlier binary-only sessions, newest first.
    ///
    /// # Errors
    /// Returns an error when the workspace root cannot be resolved.
    pub fn binary_sessions(
        &self,
        project: &Path,
    ) -> Result<Vec<BinarySessionSummary>, ClassifiedError> {
        let sessions = Self::binary_sessions_dir(project)?;
        Ok(sessions_in(&sessions)
            .iter()
            .map(|(outcome, workspace)| summarize(outcome, workspace))
            .collect())
    }

    /// One earlier session's report, with its workspace set to the directory
    /// it was found in.
    ///
    /// # Errors
    /// Returns [`ClassifiedError::Validation`] when the project has no such
    /// session.
    pub fn binary_session(
        &self,
        project: &Path,
        session: Uuid,
    ) -> Result<BinaryFuzzOutcome, ClassifiedError> {
        let sessions = Self::binary_sessions_dir(project)?;
        for binary in subdirectories(&sessions, MAX_BINARIES) {
            let directory = binary.join(session.to_string());
            if !directory
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.is_dir())
            {
                continue;
            }
            let mut outcome = read_session_report(&sessions, &directory.join(REPORT_NAME))?;
            if outcome.session != session {
                return Err(invalid("the session report names another session"));
            }
            outcome.workspace = directory;
            return Ok(outcome);
        }
        Err(invalid(format!(
            "this project has no binary-only session {session}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::binary_only::BinaryFinding;

    fn outcome(session: Uuid, finished: i64, findings: Vec<BinaryFinding>) -> BinaryFuzzOutcome {
        BinaryFuzzOutcome {
            session,
            workspace: PathBuf::from("/elsewhere"),
            binary_name: "picinfo".to_owned(),
            binary_sha256: "ab".repeat(32),
            machine: ElfMachine::Aarch64,
            input: BinaryInput::File,
            duration_secs: 60,
            execs_done: Some(1000),
            execs_per_sec: Some(10.0),
            edges_found: Some(5),
            corpus_count: Some(3),
            saved_hangs: Some(0),
            distinct_findings: findings.len(),
            findings,
            findings_omitted: 0,
            started_at: DateTime::from_timestamp(finished - 60, 0),
            finished_at: DateTime::from_timestamp(finished, 0),
            continued_from: None,
            dictionary_tokens: 0,
        }
    }

    fn finding(sha: char, confirmed: bool, minimized: bool) -> BinaryFinding {
        let sha256 = sha.to_string().repeat(64);
        BinaryFinding {
            input: PathBuf::from("findings/x"),
            sha256: sha256.clone(),
            size: 8,
            fuzzer_signal: Some(11),
            replay_signal: confirmed.then_some(11),
            replayed: true,
            confirmed,
            kind: None,
            signature: String::new(),
            summary: String::new(),
            frames: Vec::new(),
            duplicate_of: None,
            minimized: minimized.then(|| crate::container::binary_only::MinimizedInput {
                input: PathBuf::from("minimized/x"),
                sha256,
                size: 4,
            }),
        }
    }

    fn write_session(sessions: &Path, sha16: &str, outcome: &BinaryFuzzOutcome) -> PathBuf {
        let directory = sessions.join(sha16).join(outcome.session.to_string());
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(REPORT_NAME),
            serde_json::to_vec(outcome).unwrap(),
        )
        .unwrap();
        directory
    }

    #[test]
    fn history_lists_sessions_newest_first_from_where_they_are_found() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join(".binary");
        let older = outcome(Uuid::new_v4(), 1_000, vec![finding('a', true, true)]);
        let newer = outcome(
            Uuid::new_v4(),
            2_000,
            vec![finding('b', true, false), finding('c', false, false)],
        );
        let older_dir = write_session(&sessions, "aaaaaaaaaaaaaaaa", &older);
        write_session(&sessions, "bbbbbbbbbbbbbbbb", &newer);
        std::fs::write(older_dir.join("target"), b"\x7fELF").unwrap();

        let listed: Vec<_> = sessions_in(&sessions)
            .iter()
            .map(|(outcome, workspace)| summarize(outcome, workspace))
            .collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].session, newer.session);
        assert_eq!(
            (listed[0].findings, listed[0].confirmed, listed[0].minimized),
            (2, 1, 0)
        );
        assert!(!listed[0].can_continue);
        assert_eq!(listed[1].session, older.session);
        assert_eq!(listed[1].workspace, older_dir);
        assert!(listed[1].can_continue);
    }

    #[test]
    fn history_skips_mismatched_unreadable_and_linked_sessions() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join(".binary");
        let good = outcome(Uuid::new_v4(), 1_000, Vec::new());
        write_session(&sessions, "aaaaaaaaaaaaaaaa", &good);
        // A report whose session id is not its directory's name.
        let liar = outcome(Uuid::new_v4(), 3_000, Vec::new());
        let directory = sessions
            .join("aaaaaaaaaaaaaaaa")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(REPORT_NAME),
            serde_json::to_vec(&liar).unwrap(),
        )
        .unwrap();
        // A directory that is not a session id, and a broken report.
        std::fs::create_dir_all(sessions.join("aaaaaaaaaaaaaaaa").join("not-a-session")).unwrap();
        let broken = sessions
            .join("aaaaaaaaaaaaaaaa")
            .join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&broken).unwrap();
        std::fs::write(broken.join(REPORT_NAME), b"{").unwrap();
        // A session directory reached through a symbolic link.
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            let linked = outcome(Uuid::new_v4(), 4_000, Vec::new());
            let real = write_session(outside.path(), "cccccccccccccccc", &linked);
            std::os::unix::fs::symlink(
                &real,
                sessions
                    .join("aaaaaaaaaaaaaaaa")
                    .join(linked.session.to_string()),
            )
            .unwrap();
        }

        let listed = sessions_in(&sessions);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0.session, good.session);
        assert!(sessions_in(&root.path().join("missing")).is_empty());
    }

    #[test]
    fn a_report_written_before_timestamps_still_reads() {
        let mut value = serde_json::to_value(outcome(Uuid::nil(), 1_000, Vec::new())).unwrap();
        let object = value.as_object_mut().unwrap();
        for field in [
            "started_at",
            "finished_at",
            "continued_from",
            "dictionary_tokens",
        ] {
            object.remove(field);
        }
        let read: BinaryFuzzOutcome = serde_json::from_value(value).unwrap();
        assert!(read.started_at.is_none() && read.finished_at.is_none());
        assert_eq!(read.dictionary_tokens, 0);
    }

    #[test]
    fn progress_reads_the_running_sessions_fuzzer_stats() {
        let root = tempfile::tempdir().unwrap();
        let started = DateTime::from_timestamp(1_000, 0).unwrap();
        let active = ActiveBinarySession {
            project: "demo".to_owned(),
            binary_name: "picinfo".to_owned(),
            root: root.path().to_path_buf(),
            started_at: started,
            duration_secs: 60,
            stage: BinaryStage::Fuzzing,
        };
        let id = Uuid::new_v4();
        let now = DateTime::from_timestamp(1_030, 0).unwrap();
        let before = progress_of(id, &active, now);
        assert_eq!(before.elapsed_secs, 30);
        assert!(before.execs_done.is_none());

        let stats = root.path().join("out/default");
        std::fs::create_dir_all(&stats).unwrap();
        std::fs::write(
            stats.join("fuzzer_stats"),
            "execs_done        : 4200\nexecs_per_sec     : 140.00\nsaved_crashes     : 2\n\
             saved_hangs       : 1\ncorpus_count      : 7\nedges_found       : 31\n",
        )
        .unwrap();
        let during = progress_of(id, &active, now);
        assert_eq!(during.execs_done, Some(4200));
        assert_eq!(during.saved_crashes, Some(2));
        assert_eq!(during.saved_hangs, Some(1));
        assert_eq!(during.corpus_count, Some(7));
        assert_eq!(during.edges_found, Some(31));
        assert_eq!(during.stage, BinaryStage::Fuzzing);
    }

    #[test]
    fn the_registry_tracks_stage_and_forgets_a_finished_session() {
        let registry: BinarySessionRegistry = Arc::default();
        let id = Uuid::new_v4();
        registry.lock().unwrap().insert(
            id,
            ActiveBinarySession {
                project: "demo".to_owned(),
                binary_name: "picinfo".to_owned(),
                root: PathBuf::from("/nowhere"),
                started_at: Utc::now(),
                duration_secs: 60,
                stage: BinaryStage::Preparing,
            },
        );
        set_stage(&registry, id, BinaryStage::Replaying);
        assert_eq!(registry.lock().unwrap()[&id].stage, BinaryStage::Replaying);
        drop(ActiveSessionGuard {
            registry: Arc::clone(&registry),
            session: id,
        });
        assert!(registry.lock().unwrap().is_empty());
    }

    #[test]
    fn only_an_earlier_session_of_the_same_binary_can_be_continued() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("aaaaaaaaaaaaaaaa");
        let earlier = outcome(Uuid::new_v4(), 1_000, Vec::new());
        let directory = write_session(root.path(), "aaaaaaaaaaaaaaaa", &earlier);
        assert!(verify_same_binary(&directory, &"ab".repeat(32)).is_ok());
        assert!(verify_same_binary(&directory, &"cd".repeat(32)).is_err());
        assert!(verify_same_binary(&sessions.join(Uuid::new_v4().to_string()), "ab").is_err());
    }
}
