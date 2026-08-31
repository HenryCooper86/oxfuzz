//! Durable, fail-closed recovery evidence for Semgrep enrichment publication.
//!
//! Each operation owns one bounded JSONL file. A successful publication follows
//! `open -> ready_to_commit -> close`; an unsuccessful operation follows
//! `open -> abort` or `open -> ready_to_commit -> abort`. Only a durable `close`
//! proves publication, and terminal journal files are retained for replay.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use chrono::{DateTime, Utc};
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_LIFECYCLE_RECORDS: usize = 3;
#[cfg(unix)]
const TRANSACTION_LOCK_FILE: &str = ".semgrep-journal.lock";

/// Provenance made durable immediately before atomic database publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemgrepReadyRecord {
    /// Digest of the stable source snapshot.
    pub source_sha256: String,
    /// Digest of the validated raw Semgrep output.
    pub output_sha256: String,
    /// Resolved digest of the sandbox image.
    pub sandbox_image_sha256: String,
    /// Digest of the bundled Semgrep rules tree.
    pub rules_tree_sha256: String,
    /// Version of the fixed Semgrep command contract.
    pub command_schema_version: u32,
}

/// Bounded terminal category for an unsuccessful Semgrep journal lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepAbortKind {
    /// The operation failed before a successful publication close.
    Failed,
    /// The operator cancelled the operation.
    Cancelled,
    /// Startup recovery repaired the interrupted operation.
    Recovered,
}

/// A Semgrep operation whose journal does not contain a durable close record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptedSemgrepOperation {
    /// Service-owned operation identifier.
    pub operation_id: Uuid,
    /// Canonical project root recorded when the operation began.
    pub project_root: PathBuf,
    /// Operation-owned staging directory name.
    pub staging_dir_name: String,
    /// Validated publication provenance, when it became durable before interruption.
    pub ready: Option<SemgrepReadyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum SemgrepJournalEvent {
    Open {
        version: u32,
        operation_id: Uuid,
        project_root: PathBuf,
        staging_dir_name: String,
        timestamp: DateTime<Utc>,
    },
    ReadyToCommit {
        version: u32,
        operation_id: Uuid,
        ready: SemgrepReadyRecord,
        timestamp: DateTime<Utc>,
    },
    Close {
        version: u32,
        operation_id: Uuid,
        timestamp: DateTime<Utc>,
    },
    Abort {
        version: u32,
        operation_id: Uuid,
        terminal_kind: SemgrepAbortKind,
        timestamp: DateTime<Utc>,
    },
}

#[derive(Debug, Clone)]
enum OperationLifecycle {
    Open {
        project_root: PathBuf,
        staging_dir_name: String,
    },
    Ready {
        project_root: PathBuf,
        staging_dir_name: String,
        ready: SemgrepReadyRecord,
    },
    Closed,
    Aborted,
}

#[cfg(test)]
type AppendRaceHook = Arc<dyn Fn(AppendRacePoint) + Send + Sync>;

/// A bounded per-operation journal for Semgrep publication recovery.
pub struct SemgrepJournal {
    persistent: bool,
    directory: Option<PathBuf>,
    directory_handle: Mutex<Option<Arc<File>>>,
    shared_state: Arc<SharedJournalState>,
    memory_events: Mutex<BTreeMap<Uuid, Vec<SemgrepJournalEvent>>>,
    #[cfg(test)]
    race_hook: Mutex<Option<AppendRaceHook>>,
    #[cfg(test)]
    append_failure: Mutex<Option<AppendFailurePoint>>,
}

struct SharedJournalState {
    operation_lock: Mutex<()>,
    durability_error: Mutex<Option<String>>,
}

struct PersistentJournalTransaction {
    directory: Arc<File>,
    lock_file: Option<File>,
    directory_lock: Option<File>,
}

impl PersistentJournalTransaction {
    fn verify_lock_identity(&self) -> io::Result<()> {
        match self.lock_file.as_ref() {
            Some(lock_file) => verify_transaction_lock_path_identity(&self.directory, lock_file),
            None => Err(io::Error::other(
                "Semgrep journal transaction lock was already released",
            )),
        }
    }
}

impl Drop for PersistentJournalTransaction {
    fn drop(&mut self) {
        drop(self.lock_file.take());
        drop(self.directory_lock.take());
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JournalDirectoryAccess {
    Create,
    Existing,
}

impl SemgrepJournal {
    /// Create a non-persistent journal with the same lifecycle validation.
    #[must_use]
    pub fn in_memory() -> Self {
        Self {
            persistent: false,
            directory: None,
            directory_handle: Mutex::new(None),
            shared_state: Arc::new(SharedJournalState {
                operation_lock: Mutex::new(()),
                durability_error: Mutex::new(None),
            }),
            memory_events: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            race_hook: Mutex::new(None),
            #[cfg(test)]
            append_failure: Mutex::new(None),
        }
    }

    /// Retain a normalized persistent journal path without touching its filesystem.
    ///
    /// Filesystem opening, creation, validation, and replay are deferred until
    /// the first read, write, or recovery transaction.
    #[must_use]
    pub fn open(directory: PathBuf) -> Self {
        let normalized = normalize_directory_path(&directory);
        let lock_key = normalized
            .as_ref()
            .cloned()
            .unwrap_or_else(|_| directory.clone());
        let shared_state = journal_state_for_directory(&lock_key);
        let normalized = match normalized {
            Ok(normalized) => Some(normalized),
            Err(error) => {
                let message = format!("Semgrep journal directory is unsafe: {error}");
                let mut sticky = lock_recover(&shared_state.durability_error);
                sticky.get_or_insert(message);
                Some(directory)
            }
        };
        Self {
            persistent: true,
            directory: normalized,
            directory_handle: Mutex::new(None),
            shared_state: Arc::clone(&shared_state),
            memory_events: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            race_hook: Mutex::new(None),
            #[cfg(test)]
            append_failure: Mutex::new(None),
        }
    }

    /// Return the first replay or append error recorded by this journal.
    #[must_use]
    pub fn durability_error(&self) -> Option<String> {
        lock_recover(&self.shared_state.durability_error).clone()
    }

    /// Durably begin an operation.
    pub fn begin(
        &self,
        operation_id: Uuid,
        project_root: &Path,
        staging_dir_name: &str,
    ) -> Result<(), ClassifiedError> {
        if staging_dir_name != operation_id.to_string() {
            return Err(ClassifiedError::Validation(
                "Semgrep staging directory name must equal the operation UUID".to_owned(),
            ));
        }
        let event = SemgrepJournalEvent::Open {
            version: JOURNAL_VERSION,
            operation_id,
            project_root: project_root.to_path_buf(),
            staging_dir_name: staging_dir_name.to_owned(),
            timestamp: Utc::now(),
        };
        let _guard = lock_recover(&self.shared_state.operation_lock);
        let transaction = self.begin_transaction(JournalDirectoryAccess::Create)?;
        serialize_event(&event).map_err(|error| self.record_durability_failure(&error))?;

        if self.persistent {
            let transaction = transaction.ok_or_else(|| self.current_durability_error())?;
            self.create_operation_file(&transaction.directory, operation_id, &event)?;
            self.finish_transaction(&transaction)
        } else {
            let mut events = lock_recover(&self.memory_events);
            if events.contains_key(&operation_id) {
                return Err(invalid_transition(operation_id, "duplicate open"));
            }
            events.insert(operation_id, vec![event]);
            Ok(())
        }
    }

    /// Durably record that validated output is ready for database publication.
    pub fn ready_to_commit(
        &self,
        operation_id: Uuid,
        ready: &SemgrepReadyRecord,
    ) -> Result<(), ClassifiedError> {
        let event = SemgrepJournalEvent::ReadyToCommit {
            version: JOURNAL_VERSION,
            operation_id,
            ready: ready.clone(),
            timestamp: Utc::now(),
        };
        self.append_transition(operation_id, event, |state| {
            matches!(state, OperationLifecycle::Open { .. })
        })
    }

    /// Durably close an operation after its database publication is complete.
    pub fn close(&self, operation_id: Uuid) -> Result<(), ClassifiedError> {
        let event = SemgrepJournalEvent::Close {
            version: JOURNAL_VERSION,
            operation_id,
            timestamp: Utc::now(),
        };
        self.append_transition(operation_id, event, |state| {
            matches!(state, OperationLifecycle::Ready { .. })
        })
    }

    /// Durably terminalize an unsuccessful operation without publication.
    ///
    /// This transition never fabricates ready-to-commit provenance and never
    /// satisfies [`Self::is_closed`].
    pub fn abort(
        &self,
        operation_id: Uuid,
        terminal_kind: SemgrepAbortKind,
    ) -> Result<(), ClassifiedError> {
        let event = SemgrepJournalEvent::Abort {
            version: JOURNAL_VERSION,
            operation_id,
            terminal_kind,
            timestamp: Utc::now(),
        };
        self.append_transition(operation_id, event, |state| {
            matches!(
                state,
                OperationLifecycle::Open { .. } | OperationLifecycle::Ready { .. }
            )
        })
    }

    /// Return whether the operation has its own complete, valid lifecycle.
    pub fn is_closed(&self, operation_id: Uuid) -> Result<bool, ClassifiedError> {
        let _guard = lock_recover(&self.shared_state.operation_lock);
        let transaction = self.begin_transaction(JournalDirectoryAccess::Existing)?;
        if self.persistent && transaction.is_none() {
            return Ok(false);
        }
        let lifecycle = self.read_lifecycle(
            transaction
                .as_ref()
                .map(|transaction| transaction.directory.as_ref()),
            operation_id,
        )?;
        if let Some(transaction) = transaction.as_ref() {
            self.finish_transaction(transaction)?;
        }
        Ok(matches!(lifecycle, Some(OperationLifecycle::Closed)))
    }

    /// Return all valid operations that began but did not durably close.
    pub fn interrupted(&self) -> Result<Vec<InterruptedSemgrepOperation>, ClassifiedError> {
        let _guard = lock_recover(&self.shared_state.operation_lock);
        let transaction = self.begin_transaction(JournalDirectoryAccess::Create)?;
        let lifecycles = if self.persistent {
            let transaction = transaction
                .as_ref()
                .ok_or_else(|| self.current_durability_error())?;
            read_all_journals(&transaction.directory)
                .map_err(|error| self.record_durability_failure(&error))
                .and_then(|lifecycles| {
                    self.finish_transaction(transaction)?;
                    Ok(lifecycles)
                })?
        } else {
            lock_recover(&self.memory_events)
                .iter()
                .map(|(operation_id, events)| {
                    replay_events(*operation_id, events).map(|state| (*operation_id, state))
                })
                .collect::<io::Result<BTreeMap<_, _>>>()
                .map_err(|error| self.record_durability_failure(&error))?
        };

        Ok(lifecycles
            .into_iter()
            .filter_map(|(operation_id, lifecycle)| match lifecycle {
                OperationLifecycle::Open {
                    project_root,
                    staging_dir_name,
                } => Some(InterruptedSemgrepOperation {
                    operation_id,
                    project_root,
                    staging_dir_name,
                    ready: None,
                }),
                OperationLifecycle::Ready {
                    project_root,
                    staging_dir_name,
                    ready,
                } => Some(InterruptedSemgrepOperation {
                    operation_id,
                    project_root,
                    staging_dir_name,
                    ready: Some(ready),
                }),
                OperationLifecycle::Closed | OperationLifecycle::Aborted => None,
            })
            .collect())
    }

    fn append_transition(
        &self,
        operation_id: Uuid,
        event: SemgrepJournalEvent,
        allowed: impl FnOnce(&OperationLifecycle) -> bool,
    ) -> Result<(), ClassifiedError> {
        let _guard = lock_recover(&self.shared_state.operation_lock);
        let transaction = self.begin_transaction(JournalDirectoryAccess::Create)?;
        serialize_event(&event).map_err(|error| self.record_durability_failure(&error))?;

        if self.persistent {
            let transaction = transaction.ok_or_else(|| self.current_durability_error())?;
            let mut file = open_operation_file(
                &transaction.directory,
                operation_id,
                OperationOpenMode::ReadAppend,
            )
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    invalid_transition(operation_id, "operation was not opened")
                } else {
                    self.record_durability_failure(&error)
                }
            })?;
            let events = read_events_from_file(&mut file, operation_id)
                .map_err(|error| self.record_durability_failure(&error))?;
            let state = replay_events(operation_id, &events)
                .map_err(|error| self.record_durability_failure(&error))?;
            if !allowed(&state) {
                return Err(invalid_transition(
                    operation_id,
                    "event is out of lifecycle order",
                ));
            }
            self.append_to_file(&transaction.directory, &mut file, operation_id, &event)?;
            self.finish_transaction(&transaction)
        } else {
            let mut events = lock_recover(&self.memory_events);
            let Some(existing) = events.get_mut(&operation_id) else {
                return Err(invalid_transition(operation_id, "operation was not opened"));
            };
            let state = replay_events(operation_id, existing)
                .map_err(|error| self.record_durability_failure(&error))?;
            if !allowed(&state) {
                return Err(invalid_transition(
                    operation_id,
                    "event is out of lifecycle order",
                ));
            }
            existing.push(event);
            Ok(())
        }
    }

    fn create_operation_file(
        &self,
        directory: &File,
        operation_id: Uuid,
        event: &SemgrepJournalEvent,
    ) -> Result<(), ClassifiedError> {
        let mut file = open_operation_file(directory, operation_id, OperationOpenMode::Create)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    invalid_transition(operation_id, "duplicate open")
                } else {
                    self.record_durability_failure(&error)
                }
            })?;
        self.append_to_file(directory, &mut file, operation_id, event)
    }

    fn append_to_file(
        &self,
        directory: &File,
        file: &mut File,
        operation_id: Uuid,
        event: &SemgrepJournalEvent,
    ) -> Result<(), ClassifiedError> {
        let line =
            serialize_event(event).map_err(|error| self.record_durability_failure(&error))?;
        let length = file
            .metadata()
            .map_err(|error| self.record_durability_failure(&error))?
            .len();
        let length = usize::try_from(length).unwrap_or(usize::MAX);
        if length.saturating_add(line.len()) > MAX_JOURNAL_BYTES {
            return Err(self.record_durability_failure(&io::Error::new(
                io::ErrorKind::InvalidData,
                format!("journal exceeds the {MAX_JOURNAL_BYTES}-byte limit"),
            )));
        }
        #[cfg(test)]
        self.run_test_race_hook(AppendRacePoint::BeforeIdentityCheck);
        verify_operation_path_identity(directory, operation_id, file)
            .map_err(|error| self.record_durability_failure(&error))?;
        #[cfg(test)]
        self.inject_test_append_failure(AppendFailurePoint::BeforeWrite)?;
        append_and_sync(file, &line)
            .and_then(|()| {
                #[cfg(test)]
                self.inject_test_append_failure(AppendFailurePoint::AfterFileSync)
                    .map_err(|error| io::Error::other(error.to_string()))?;
                #[cfg(test)]
                self.run_test_race_hook(AppendRacePoint::AfterFileSync);
                verify_operation_path_identity(directory, operation_id, file)
            })
            .and_then(|()| directory.sync_all())
            .map_err(|error| self.record_durability_failure(&error))
    }

    fn read_lifecycle(
        &self,
        directory: Option<&File>,
        operation_id: Uuid,
    ) -> Result<Option<OperationLifecycle>, ClassifiedError> {
        if self.persistent {
            let Some(directory) = directory else {
                return Ok(None);
            };
            let mut file =
                match open_operation_file(directory, operation_id, OperationOpenMode::Read) {
                    Ok(file) => file,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(self.record_durability_failure(&error)),
                };
            let events = read_events_from_file(&mut file, operation_id)
                .map_err(|error| self.record_durability_failure(&error))?;
            replay_events(operation_id, &events)
                .map(Some)
                .map_err(|error| self.record_durability_failure(&error))
        } else {
            let events = lock_recover(&self.memory_events);
            events
                .get(&operation_id)
                .map(|events| replay_events(operation_id, events))
                .transpose()
                .map_err(|error| self.record_durability_failure(&error))
        }
    }

    fn directory_handle(
        &self,
        access: JournalDirectoryAccess,
    ) -> Result<Option<Arc<File>>, ClassifiedError> {
        self.ensure_healthy()?;
        if !self.persistent {
            return Ok(None);
        }
        let mut retained = lock_recover(&self.directory_handle);
        if let Some(handle) = retained.as_ref() {
            return Ok(Some(Arc::clone(handle)));
        }
        let directory = self
            .directory
            .as_deref()
            .ok_or_else(|| self.current_durability_error())?;
        let resolved_directory = canonicalize_existing_ancestor(directory)
            .map_err(|error| self.record_durability_failure(&error))?;
        let opened = match access {
            JournalDirectoryAccess::Create => {
                open_or_create_directory_nofollow(&resolved_directory)
            }
            JournalDirectoryAccess::Existing => {
                open_existing_directory_nofollow(&resolved_directory)
            }
        };
        let handle = match opened {
            Ok(handle) => Arc::new(handle),
            Err(error)
                if access == JournalDirectoryAccess::Existing
                    && error.kind() == io::ErrorKind::NotFound =>
            {
                return Ok(None);
            }
            Err(error) => return Err(self.record_durability_failure(&error)),
        };
        *retained = Some(Arc::clone(&handle));
        Ok(Some(handle))
    }

    fn ensure_healthy(&self) -> Result<(), ClassifiedError> {
        if self.durability_error().is_some() {
            Err(self.current_durability_error())
        } else {
            Ok(())
        }
    }

    fn begin_transaction(
        &self,
        access: JournalDirectoryAccess,
    ) -> Result<Option<PersistentJournalTransaction>, ClassifiedError> {
        self.ensure_healthy()?;
        if self.persistent {
            let Some(directory) = self.directory_handle(access)? else {
                return Ok(None);
            };
            let directory_lock = open_and_lock_journal_directory(&directory)
                .map_err(|error| self.record_durability_failure(&error))?;
            let lock_file = open_and_lock_transaction_file(&directory)
                .map_err(|error| self.record_durability_failure(&error))?;
            validate_all_journals(&directory)
                .map_err(|error| self.record_durability_failure(&error))?;
            Ok(Some(PersistentJournalTransaction {
                directory,
                lock_file: Some(lock_file),
                directory_lock: Some(directory_lock),
            }))
        } else {
            Ok(None)
        }
    }

    fn finish_transaction(
        &self,
        transaction: &PersistentJournalTransaction,
    ) -> Result<(), ClassifiedError> {
        transaction
            .verify_lock_identity()
            .map_err(|error| self.record_durability_failure(&error))
    }

    fn current_durability_error(&self) -> ClassifiedError {
        ClassifiedError::Storage(
            self.durability_error()
                .unwrap_or_else(|| "Semgrep journal is unavailable".to_owned()),
        )
    }

    fn record_durability_failure(&self, error: &io::Error) -> ClassifiedError {
        let directory = self
            .directory
            .as_deref()
            .map_or_else(|| "<memory>".to_owned(), |path| path.display().to_string());
        let message = format!("Semgrep journal durability failed in {directory}: {error}");
        let mut durability_error = lock_recover(&self.shared_state.durability_error);
        let sticky = durability_error.get_or_insert(message).clone();
        ClassifiedError::Storage(sticky)
    }

    #[cfg(all(test, unix))]
    fn install_test_race_hook(&self, hook: impl Fn(AppendRacePoint) + Send + Sync + 'static) {
        *lock_recover(&self.race_hook) = Some(Arc::new(hook));
    }

    #[cfg(all(test, unix))]
    pub(crate) fn install_test_append_failure(&self, point: AppendFailurePoint) {
        *lock_recover(&self.append_failure) = Some(point);
    }

    #[cfg(test)]
    fn inject_test_append_failure(&self, point: AppendFailurePoint) -> Result<(), ClassifiedError> {
        let mut failure = lock_recover(&self.append_failure);
        if failure.as_ref() == Some(&point) {
            *failure = None;
            return Err(
                self.record_durability_failure(&io::Error::other("injected append failure"))
            );
        }
        Ok(())
    }

    #[cfg(test)]
    fn run_test_race_hook(&self, point: AppendRacePoint) {
        let hook = lock_recover(&self.race_hook).clone();
        if let Some(hook) = hook {
            hook(point);
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppendRacePoint {
    BeforeIdentityCheck,
    AfterFileSync,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppendFailurePoint {
    BeforeWrite,
    AfterFileSync,
}

fn invalid_transition(operation_id: Uuid, detail: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!(
        "invalid Semgrep journal transition for {operation_id}: {detail}"
    ))
}

fn serialize_event(event: &SemgrepJournalEvent) -> io::Result<Vec<u8>> {
    let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
    line.push(b'\n');
    if line.len() > MAX_LINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("event exceeds the {MAX_LINE_BYTES}-byte line limit"),
        ));
    }
    Ok(line)
}

trait DurableWrite: Write {
    fn sync_all(&mut self) -> io::Result<()>;
}

impl DurableWrite for File {
    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

fn append_and_sync(writer: &mut impl DurableWrite, line: &[u8]) -> io::Result<()> {
    writer.write_all(line)?;
    writer.flush()?;
    writer.sync_all()
}

fn replay_events(
    expected_operation_id: Uuid,
    events: &[SemgrepJournalEvent],
) -> io::Result<OperationLifecycle> {
    if events.is_empty() || events.len() > MAX_LIFECYCLE_RECORDS {
        return Err(invalid_data("journal must contain one to three records"));
    }

    let (project_root, staging_dir_name) = match &events[0] {
        SemgrepJournalEvent::Open {
            version,
            operation_id,
            project_root,
            staging_dir_name,
            ..
        } => {
            validate_event_identity(*version, *operation_id, expected_operation_id)?;
            if staging_dir_name != &expected_operation_id.to_string() {
                return Err(invalid_data(
                    "open record staging directory does not equal operation UUID",
                ));
            }
            (project_root.clone(), staging_dir_name.clone())
        }
        _ => return Err(invalid_data("first journal record is not open")),
    };

    match events {
        [_] => Ok(OperationLifecycle::Open {
            project_root,
            staging_dir_name,
        }),
        [_, SemgrepJournalEvent::ReadyToCommit {
            version,
            operation_id,
            ready,
            ..
        }] => {
            validate_event_identity(*version, *operation_id, expected_operation_id)?;
            Ok(OperationLifecycle::Ready {
                project_root,
                staging_dir_name,
                ready: ready.clone(),
            })
        }
        [_, SemgrepJournalEvent::ReadyToCommit {
            version: ready_version,
            operation_id: ready_operation_id,
            ..
        }, SemgrepJournalEvent::Close {
            version: close_version,
            operation_id: close_operation_id,
            ..
        }] => {
            validate_event_identity(*ready_version, *ready_operation_id, expected_operation_id)?;
            validate_event_identity(*close_version, *close_operation_id, expected_operation_id)?;
            Ok(OperationLifecycle::Closed)
        }
        [_, SemgrepJournalEvent::Abort {
            version,
            operation_id,
            ..
        }] => {
            validate_event_identity(*version, *operation_id, expected_operation_id)?;
            Ok(OperationLifecycle::Aborted)
        }
        [_, SemgrepJournalEvent::ReadyToCommit {
            version: ready_version,
            operation_id: ready_operation_id,
            ..
        }, SemgrepJournalEvent::Abort {
            version: abort_version,
            operation_id: abort_operation_id,
            ..
        }] => {
            validate_event_identity(*ready_version, *ready_operation_id, expected_operation_id)?;
            validate_event_identity(*abort_version, *abort_operation_id, expected_operation_id)?;
            Ok(OperationLifecycle::Aborted)
        }
        _ => Err(invalid_data(
            "journal records do not follow open, optional ready_to_commit, and close or abort",
        )),
    }
}

fn validate_event_identity(
    version: u32,
    operation_id: Uuid,
    expected_operation_id: Uuid,
) -> io::Result<()> {
    if version != JOURNAL_VERSION {
        return Err(invalid_data(format!(
            "unsupported journal version {version}"
        )));
    }
    if operation_id != expected_operation_id {
        return Err(invalid_data(
            "record operation ID does not match journal filename",
        ));
    }
    Ok(())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn read_events_from_file(
    file: &mut File,
    operation_id: Uuid,
) -> io::Result<Vec<SemgrepJournalEvent>> {
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(invalid_data("journal entry is not a regular file"));
    }
    let file_size = usize::try_from(before.len()).unwrap_or(usize::MAX);
    if file_size > MAX_JOURNAL_BYTES {
        return Err(invalid_data(format!(
            "journal exceeds the {MAX_JOURNAL_BYTES}-byte limit"
        )));
    }

    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(file_size);
    file.take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if !same_file_snapshot(&before, &after) || bytes.len() != file_size {
        return Err(invalid_data("journal changed while it was read"));
    }
    if bytes.is_empty() {
        return Err(invalid_data("journal is empty"));
    }
    if !bytes.ends_with(b"\n") {
        return Err(invalid_data("journal has a truncated final record"));
    }

    let mut events = Vec::new();
    for (line_index, line) in bytes[..bytes.len() - 1]
        .split(|byte| *byte == b'\n')
        .enumerate()
    {
        if line.is_empty() {
            return Err(invalid_data(format!(
                "journal line {} is empty",
                line_index + 1
            )));
        }
        if line.len().saturating_add(1) > MAX_LINE_BYTES {
            return Err(invalid_data(format!(
                "journal line {} exceeds the {MAX_LINE_BYTES}-byte limit",
                line_index + 1
            )));
        }
        if events.len() == MAX_LIFECYCLE_RECORDS {
            return Err(invalid_data(format!(
                "journal exceeds the {MAX_LIFECYCLE_RECORDS}-record limit"
            )));
        }
        let event = serde_json::from_slice(line).map_err(|error| {
            invalid_data(format!(
                "journal line {} is invalid: {error}",
                line_index + 1
            ))
        })?;
        events.push(event);
    }
    replay_events(operation_id, &events)?;
    Ok(events)
}

#[cfg(unix)]
fn same_file_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn validate_all_journals(directory: &File) -> io::Result<()> {
    read_all_journals(directory).map(|_| ())
}

#[cfg(unix)]
fn read_all_journals(directory: &File) -> io::Result<BTreeMap<Uuid, OperationLifecycle>> {
    let mut journals = BTreeMap::new();
    let entries = rustix::fs::Dir::read_from(directory)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." || name == TRANSACTION_LOCK_FILE.as_bytes() {
            continue;
        }
        let name = std::str::from_utf8(name)
            .map_err(|_| invalid_data("journal filename is not valid UTF-8"))?;
        if Path::new(name).extension() != Some(std::ffi::OsStr::new("jsonl")) {
            return Err(invalid_data(format!(
                "unexpected Semgrep journal directory entry {name}"
            )));
        }
        let id_text = name
            .strip_suffix(".jsonl")
            .ok_or_else(|| invalid_data("journal filename has an invalid suffix"))?;
        let operation_id = Uuid::parse_str(id_text)
            .map_err(|_| invalid_data(format!("invalid operation journal filename {name}")))?;
        if name != operation_file_name(operation_id) {
            return Err(invalid_data(format!(
                "operation journal filename is not canonical: {name}"
            )));
        }
        let mut file = open_operation_file(directory, operation_id, OperationOpenMode::Read)?;
        let events = read_events_from_file(&mut file, operation_id)?;
        let lifecycle = replay_events(operation_id, &events)?;
        journals.insert(operation_id, lifecycle);
    }
    Ok(journals)
}

#[cfg(not(unix))]
fn read_all_journals(_directory: &File) -> io::Result<BTreeMap<Uuid, OperationLifecycle>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative filesystem access",
    ))
}

#[derive(Clone, Copy)]
enum OperationOpenMode {
    Create,
    Read,
    ReadAppend,
}

#[cfg(unix)]
fn open_operation_file(
    directory: &File,
    operation_id: Uuid,
    mode: OperationOpenMode,
) -> io::Result<File> {
    use rustix::fs::{openat, Mode, OFlags};

    let flags = match mode {
        OperationOpenMode::Create => {
            OFlags::WRONLY
                | OFlags::APPEND
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
        }
        OperationOpenMode::Read => OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        OperationOpenMode::ReadAppend => {
            OFlags::RDWR | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC
        }
    };
    let descriptor = openat(
        directory,
        operation_file_name(operation_id),
        flags,
        Mode::RUSR | Mode::WUSR,
    )?;
    let file = File::from(descriptor);
    if !file.metadata()?.file_type().is_file() {
        return Err(invalid_data("journal entry is not a regular file"));
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_operation_file(
    _directory: &File,
    _operation_id: Uuid,
    _mode: OperationOpenMode,
) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative filesystem access",
    ))
}

#[cfg(unix)]
fn operation_file_name(operation_id: Uuid) -> String {
    format!("{operation_id}.jsonl")
}

#[cfg(unix)]
fn open_and_lock_journal_directory(directory: &File) -> io::Result<File> {
    use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags};

    let descriptor = openat(
        directory,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let lock = File::from(descriptor);
    verify_same_directory(directory, &lock)?;
    flock(&lock, FlockOperation::LockExclusive)?;
    verify_same_directory(directory, &lock)?;
    Ok(lock)
}

#[cfg(unix)]
fn verify_same_directory(expected: &File, actual: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let expected = expected.metadata()?;
    let actual = actual.metadata()?;
    if !expected.is_dir()
        || !actual.is_dir()
        || expected.dev() != actual.dev()
        || expected.ino() != actual.ino()
    {
        return Err(invalid_data(
            "journal directory lock does not name the opened journal directory",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn open_and_lock_journal_directory(_directory: &File) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative directory locks",
    ))
}

#[cfg(unix)]
fn open_and_lock_transaction_file(directory: &File) -> io::Result<File> {
    use rustix::fs::{fchmod, flock, openat, FlockOperation, Mode, OFlags};

    let existing_flags = OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let (descriptor, created) = match openat(
        directory,
        TRANSACTION_LOCK_FILE,
        existing_flags,
        Mode::empty(),
    ) {
        Ok(descriptor) => (descriptor, false),
        Err(rustix::io::Errno::NOENT) => {
            let create_flags = existing_flags | OFlags::CREATE | OFlags::EXCL;
            match openat(
                directory,
                TRANSACTION_LOCK_FILE,
                create_flags,
                Mode::RUSR | Mode::WUSR,
            ) {
                Ok(descriptor) => (descriptor, true),
                Err(rustix::io::Errno::EXIST) => (
                    openat(
                        directory,
                        TRANSACTION_LOCK_FILE,
                        existing_flags,
                        Mode::empty(),
                    )?,
                    false,
                ),
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    };
    let file = File::from(descriptor);
    #[cfg(test)]
    pause_after_transaction_lock_creation(created);
    verify_transaction_lock_path_identity(directory, &file)?;
    flock(&file, FlockOperation::LockExclusive)?;
    verify_transaction_lock_path_identity(directory, &file)?;
    fchmod(&file, Mode::RUSR | Mode::WUSR)?;
    file.sync_all()?;
    if created {
        directory.sync_all()?;
    }
    Ok(file)
}

#[cfg(all(test, unix))]
fn pause_after_transaction_lock_creation(created: bool) {
    if !created || std::env::var("HF_SEMGREP_JOURNAL_PAUSE_AFTER_LOCK_CREATE").as_deref() != Ok("1")
    {
        return;
    }
    println!("ready");
    std::io::stdout().flush().expect("lock creator signal");
    let mut release = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut release)
        .expect("lock creator release");
}

#[cfg(not(unix))]
fn open_and_lock_transaction_file(_directory: &File) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative advisory locks",
    ))
}

#[cfg(not(unix))]
fn verify_transaction_lock_path_identity(_directory: &File, _file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative filesystem identity checks",
    ))
}

/// Widen a `stat` link count to `u64`. `st_nlink` is `u64` on `x86_64` Linux
/// but `u32` on `aarch64` Linux and `u16` on macOS; the generic boundary
/// keeps the conversion portable without a per-arch cast.
#[cfg(unix)]
fn nlink_to_u64(count: impl Into<u64>) -> u64 {
    count.into()
}

#[cfg(unix)]
fn verify_transaction_lock_path_identity(directory: &File, file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{statat, AtFlags, FileType};

    let descriptor = file.metadata()?;
    let path = statat(directory, TRANSACTION_LOCK_FILE, AtFlags::SYMLINK_NOFOLLOW)?;
    let descriptor_is_linked_regular = descriptor.file_type().is_file() && descriptor.nlink() == 1;
    let path_is_linked_regular =
        FileType::from_raw_mode(path.st_mode) == FileType::RegularFile && path.st_nlink == 1;
    if !descriptor_is_linked_regular
        || !path_is_linked_regular
        || descriptor.dev() != path.st_dev as u64
        || descriptor.ino() != path.st_ino as u64
        || descriptor.nlink() != nlink_to_u64(path.st_nlink)
    {
        return Err(invalid_data(
            "transaction lock pathname no longer names the opened regular file",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_operation_path_identity(
    directory: &File,
    operation_id: Uuid,
    file: &File,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    use rustix::fs::{statat, AtFlags, FileType};

    let descriptor = file.metadata()?;
    let path = statat(
        directory,
        operation_file_name(operation_id),
        AtFlags::SYMLINK_NOFOLLOW,
    )?;
    let descriptor_is_linked_regular = descriptor.file_type().is_file() && descriptor.nlink() == 1;
    let path_is_linked_regular =
        FileType::from_raw_mode(path.st_mode) == FileType::RegularFile && path.st_nlink == 1;
    if !descriptor_is_linked_regular
        || !path_is_linked_regular
        || descriptor.dev() != path.st_dev as u64
        || descriptor.ino() != path.st_ino as u64
        || descriptor.nlink() != nlink_to_u64(path.st_nlink)
    {
        return Err(invalid_data(
            "journal pathname no longer names the opened regular file",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_operation_path_identity(
    _directory: &File,
    _operation_id: Uuid,
    _file: &File,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative filesystem identity checks",
    ))
}

fn normalize_directory_path(directory: &Path) -> io::Result<PathBuf> {
    if directory.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "journal directory path is empty",
        ));
    }
    let candidate = if directory.is_absolute() {
        directory.to_path_buf()
    } else {
        std::env::current_dir()?.join(directory)
    };
    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "journal directory contains a parent traversal",
                ));
            }
        }
    }
    Ok(normalized)
}

fn canonicalize_existing_ancestor(path: &Path) -> io::Result<PathBuf> {
    let mut cursor = path;
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("journal directory is a symlink: {}", cursor.display()),
                    ));
                }
                if !metadata.is_dir() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "journal path component is not a directory: {}",
                            cursor.display()
                        ),
                    ));
                }
                let mut canonical = std::fs::canonicalize(cursor)?;
                for component in missing.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name = cursor.file_name().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "journal path has no existing ancestor",
                    )
                })?;
                missing.push(name.to_os_string());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "journal path has no existing ancestor",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(unix)]
fn open_or_create_directory_nofollow(directory: &Path) -> io::Result<File> {
    use rustix::fs::{mkdirat, open, openat, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = File::from(open(Path::new("/"), flags, Mode::empty())?);
    for component in directory.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let next = match openat(&current, name, flags, Mode::empty()) {
            Ok(next) => next,
            Err(rustix::io::Errno::NOENT) => {
                mkdirat(&current, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)?;
                current.sync_all()?;
                openat(&current, name, flags, Mode::empty())?
            }
            Err(error) => return Err(error.into()),
        };
        current = File::from(next);
    }
    Ok(current)
}

#[cfg(unix)]
fn open_existing_directory_nofollow(directory: &Path) -> io::Result<File> {
    use rustix::fs::{open, openat, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut current = File::from(open(Path::new("/"), flags, Mode::empty())?);
    for component in directory.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        current = File::from(openat(&current, name, flags, Mode::empty())?);
    }
    Ok(current)
}

#[cfg(not(unix))]
fn open_or_create_directory_nofollow(_directory: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative filesystem access",
    ))
}

#[cfg(not(unix))]
fn open_existing_directory_nofollow(_directory: &Path) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Semgrep journals require descriptor-relative filesystem access",
    ))
}

fn journal_state_for_directory(directory: &Path) -> Arc<SharedJournalState> {
    static JOURNAL_STATES: OnceLock<Mutex<HashMap<PathBuf, Weak<SharedJournalState>>>> =
        OnceLock::new();

    let states = JOURNAL_STATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut states = lock_recover(states);
    states.retain(|_, state| state.strong_count() > 0);
    if let Some(state) = states.get(directory).and_then(Weak::upgrade) {
        return state;
    }
    let state = Arc::new(SharedJournalState {
        operation_lock: Mutex::new(()),
        durability_error: Mutex::new(None),
    });
    states.insert(directory.to_path_buf(), Arc::downgrade(&state));
    state
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        append_and_sync, AppendFailurePoint, AppendRacePoint, DurableWrite, SemgrepAbortKind,
        SemgrepJournal, SemgrepReadyRecord,
    };
    use hf_core::error::ClassifiedError;
    use std::io::{self, Write};
    #[cfg(unix)]
    use std::io::{BufRead, BufReader, Read};
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::process::{Child, ChildStdout, Command, ExitStatus, Stdio};
    #[cfg(unix)]
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    #[cfg(unix)]
    const PROCESS_CHILD_ENV: &str = "HF_SEMGREP_JOURNAL_CHILD";
    #[cfg(unix)]
    const PROCESS_DIRECTORY_ENV: &str = "HF_SEMGREP_JOURNAL_DIRECTORY";
    #[cfg(unix)]
    const PROCESS_OPERATION_ENV: &str = "HF_SEMGREP_JOURNAL_OPERATION";

    fn ready_record() -> SemgrepReadyRecord {
        SemgrepReadyRecord {
            source_sha256: "source".to_owned(),
            output_sha256: "output".to_owned(),
            sandbox_image_sha256: "sandbox".to_owned(),
            rules_tree_sha256: "rules".to_owned(),
            command_schema_version: 1,
        }
    }

    fn begin(journal: &SemgrepJournal, operation_id: Uuid) {
        journal
            .begin(
                operation_id,
                Path::new("/project"),
                &operation_id.to_string(),
            )
            .unwrap();
    }

    fn close(journal: &SemgrepJournal, operation_id: Uuid) {
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();
        journal.close(operation_id).unwrap();
    }

    #[cfg(unix)]
    struct JournalChild {
        child: Child,
        stdout: BufReader<ChildStdout>,
    }

    #[cfg(unix)]
    fn spawn_journal_child(
        test_name: &str,
        role: &str,
        directory: &Path,
        operation_id: Uuid,
    ) -> JournalChild {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("semgrep_recovery::tests::{test_name}"))
            .arg("--nocapture")
            .env(PROCESS_CHILD_ENV, role)
            .env(PROCESS_DIRECTORY_ENV, directory)
            .env(PROCESS_OPERATION_ENV, operation_id.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        journal_child_from_spawned(child)
    }

    #[cfg(unix)]
    fn spawn_restrictive_lock_creator(directory: &Path, operation_id: Uuid) -> JournalChild {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg(
                "umask 777; exec \"$0\" --exact \
                 semgrep_recovery::tests::journal_restrictive_create_child --nocapture",
            )
            .arg(std::env::current_exe().unwrap())
            .env(PROCESS_CHILD_ENV, "create")
            .env(PROCESS_DIRECTORY_ENV, directory)
            .env(PROCESS_OPERATION_ENV, operation_id.to_string())
            .env("HF_SEMGREP_JOURNAL_PAUSE_AFTER_LOCK_CREATE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        journal_child_from_spawned(child)
    }

    #[cfg(unix)]
    fn journal_child_from_spawned(mut child: Child) -> JournalChild {
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut signal = String::new();
            if stdout.read_line(&mut signal).unwrap() == 0 {
                let mut stderr = String::new();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                let status = child.wait().unwrap();
                panic!("journal child exited before signalling: status={status}; stderr={stderr}");
            }
            if signal.trim() == "ready" {
                break;
            }
        }
        JournalChild { child, stdout }
    }

    #[cfg(unix)]
    fn wait_for_early_exit(child: &mut Child) -> Option<ExitStatus> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    fn release_and_wait(mut child: JournalChild) -> ExitStatus {
        child.child.stdin.take().unwrap().write_all(b"x").unwrap();
        let mut remaining_stdout = String::new();
        child.stdout.read_to_string(&mut remaining_stdout).unwrap();
        let output = child.child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "paused journal child failed\nstdout:\n{remaining_stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.status
    }

    #[cfg(unix)]
    fn wait_for_child(mut child: JournalChild) -> ExitStatus {
        let mut remaining_stdout = String::new();
        child.stdout.read_to_string(&mut remaining_stdout).unwrap();
        let output = child.child.wait_with_output().unwrap();
        if !output.status.success() {
            eprintln!(
                "journal child failed\nstdout:\n{remaining_stdout}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        output.status
    }

    #[cfg(unix)]
    fn child_journal() -> (SemgrepJournal, Uuid) {
        let directory = PathBuf::from(std::env::var(PROCESS_DIRECTORY_ENV).unwrap());
        let operation_id = Uuid::parse_str(&std::env::var(PROCESS_OPERATION_ENV).unwrap()).unwrap();
        (SemgrepJournal::open(directory), operation_id)
    }

    #[cfg(unix)]
    fn signal_child_ready() {
        println!("ready");
        std::io::stdout().flush().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn process_close_and_abort_serialize_to_one_terminal_outcome() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let actual_parent = root.path().join("actual");
        let directory = actual_parent.join("journal");
        std::fs::create_dir_all(&directory).unwrap();
        let alias_parent = root.path().join("alias");
        symlink(&actual_parent, &alias_parent).unwrap();
        let alias = alias_parent.join("journal");
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.clone());
        begin(&journal, operation_id);
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();

        let close_child = spawn_journal_child(
            "journal_paused_close_child",
            "close",
            &directory,
            operation_id,
        );
        let mut abort_child =
            spawn_journal_child("journal_abort_child", "abort", &alias, operation_id);
        assert!(
            wait_for_early_exit(&mut abort_child.child).is_none(),
            "abort completed while close owned the journal transaction"
        );

        let close_status = release_and_wait(close_child);
        let abort_status = wait_for_child(abort_child);
        assert!(close_status.success());

        let reopened = SemgrepJournal::open(directory);
        assert!(reopened.is_closed(operation_id).unwrap());
        assert!(reopened.interrupted().unwrap().is_empty());
        assert!(abort_status.success());
    }

    #[cfg(unix)]
    #[test]
    fn process_replay_waits_for_a_complete_append_transaction() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, operation_id);
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();

        let close_child = spawn_journal_child(
            "journal_paused_close_child",
            "close",
            directory.path(),
            operation_id,
        );
        let mut replay_child = spawn_journal_child(
            "journal_replay_child",
            "replay",
            directory.path(),
            operation_id,
        );
        assert!(
            wait_for_early_exit(&mut replay_child.child).is_none(),
            "replay completed while append owned the journal transaction"
        );

        assert!(release_and_wait(close_child).success());
        assert!(wait_for_child(replay_child).success());
    }

    #[cfg(unix)]
    #[test]
    fn process_first_creators_converge_under_restrictive_umask() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let creator = spawn_restrictive_lock_creator(directory.path(), operation_id);
        let mut contender = spawn_journal_child(
            "journal_first_create_contender_child",
            "create_contender",
            directory.path(),
            operation_id,
        );
        assert!(
            wait_for_early_exit(&mut contender.child).is_none(),
            "contender degraded instead of waiting for first-create convergence"
        );

        assert!(release_and_wait(creator).success());
        assert!(wait_for_child(contender).success());
        assert!(SemgrepJournal::open(directory.path().to_path_buf())
            .interrupted()
            .unwrap()
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn process_lock_replacement_cannot_bypass_active_transaction() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, operation_id);
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();

        let close_child = spawn_journal_child(
            "journal_replaced_close_child",
            "replaced_close",
            directory.path(),
            operation_id,
        );
        let lock_path = directory.path().join(".semgrep-journal.lock");
        std::fs::remove_file(&lock_path).unwrap();
        std::fs::write(&lock_path, b"replacement").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut replay_child = spawn_journal_child(
            "journal_replay_child",
            "replay",
            directory.path(),
            operation_id,
        );
        assert!(
            wait_for_early_exit(&mut replay_child.child).is_none(),
            "replacement lock let replay bypass the active transaction"
        );

        assert!(release_and_wait(close_child).success());
        assert!(wait_for_child(replay_child).success());
    }

    #[cfg(unix)]
    #[test]
    fn journal_paused_close_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("close") {
            return;
        }
        let (journal, operation_id) = child_journal();
        journal.install_test_race_hook(|point| {
            if point == AppendRacePoint::BeforeIdentityCheck {
                signal_child_ready();
                let mut release = [0_u8; 1];
                std::io::stdin().read_exact(&mut release).unwrap();
            }
        });
        journal.close(operation_id).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn journal_replaced_close_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("replaced_close") {
            return;
        }
        let (journal, operation_id) = child_journal();
        journal.install_test_race_hook(|point| {
            if point == AppendRacePoint::BeforeIdentityCheck {
                signal_child_ready();
                let mut release = [0_u8; 1];
                std::io::stdin().read_exact(&mut release).unwrap();
            }
        });
        assert!(journal.close(operation_id).is_err());
        assert!(journal.durability_error().is_some());
    }

    #[cfg(unix)]
    #[test]
    fn journal_restrictive_create_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("create") {
            return;
        }
        let (journal, _) = child_journal();
        assert!(journal.interrupted().unwrap().is_empty());
        assert!(journal.durability_error().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn journal_first_create_contender_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("create_contender") {
            return;
        }
        let (journal, _) = child_journal();
        signal_child_ready();
        assert!(journal.interrupted().unwrap().is_empty());
        assert!(journal.durability_error().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn journal_abort_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("abort") {
            return;
        }
        let (journal, operation_id) = child_journal();
        signal_child_ready();
        assert!(
            journal
                .abort(operation_id, SemgrepAbortKind::Failed)
                .is_err(),
            "abort must reject the lifecycle closed by the competing process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn journal_replay_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("replay") {
            return;
        }
        let (journal, operation_id) = child_journal();
        signal_child_ready();
        assert!(journal.interrupted().unwrap().is_empty());
        assert!(journal.is_closed(operation_id).unwrap());
    }

    fn event_line(event: &str, version: u32, operation_id: Uuid) -> String {
        let mut value = serde_json::json!({
            "event": event,
            "version": version,
            "operation_id": operation_id,
            "timestamp": "2026-07-28T00:00:00Z"
        });
        if event == "open" {
            value["project_root"] = serde_json::json!("/project");
            value["staging_dir_name"] = serde_json::json!(operation_id.to_string());
        }
        format!("{}\n", serde_json::to_string(&value).unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_is_a_fixed_owner_read_write_file() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());

        assert!(journal.interrupted().unwrap().is_empty());

        let metadata =
            std::fs::symlink_metadata(directory.path().join(".semgrep-journal.lock")).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_permissions_ignore_restrictive_umask() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let output = Command::new("/bin/sh")
            .arg("-c")
            .arg(
                "umask 777; exec \"$0\" --exact \
                 semgrep_recovery::tests::journal_restrictive_umask_child --nocapture",
            )
            .arg(std::env::current_exe().unwrap())
            .env(PROCESS_CHILD_ENV, "umask")
            .env(PROCESS_DIRECTORY_ENV, directory.path())
            .env(PROCESS_OPERATION_ENV, Uuid::new_v4().to_string())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "restrictive-umask child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let metadata =
            std::fs::symlink_metadata(directory.path().join(".semgrep-journal.lock")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn journal_restrictive_umask_child() {
        if std::env::var(PROCESS_CHILD_ENV).as_deref() != Ok("umask") {
            return;
        }

        let (journal, _) = child_journal();
        assert!(journal.interrupted().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("lock-target");
        std::fs::write(&target, b"unchanged").unwrap();
        symlink(&target, directory.path().join(".semgrep-journal.lock")).unwrap();

        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(journal.interrupted().is_err());
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn transaction_lock_hard_link_is_rejected_before_metadata_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("owner-file");
        std::fs::write(&target, b"unchanged").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).unwrap();
        std::fs::hard_link(&target, directory.path().join(".semgrep-journal.lock")).unwrap();
        let before_mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;

        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        let result = journal.interrupted();

        let after_mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(after_mode, before_mode);
        assert_eq!(std::fs::read(target).unwrap(), b"unchanged");
        assert!(result.is_err());
    }

    #[test]
    fn transaction_lock_is_the_only_non_journal_entry_allowed() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("unexpected"), b"data").unwrap();

        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(journal.interrupted().is_err());
    }

    #[test]
    fn closed_operation_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());

        begin(&journal, operation_id);
        close(&journal, operation_id);
        drop(journal);

        assert!(SemgrepJournal::open(directory.path().to_path_buf())
            .is_closed(operation_id)
            .unwrap());
    }

    #[test]
    fn begin_only_and_ready_without_close_are_interrupted() {
        let directory = tempfile::tempdir().unwrap();
        let open_id = Uuid::new_v4();
        let ready_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, open_id);
        begin(&journal, ready_id);
        journal.ready_to_commit(ready_id, &ready_record()).unwrap();
        drop(journal);

        let interrupted = SemgrepJournal::open(directory.path().to_path_buf())
            .interrupted()
            .unwrap();
        assert_eq!(interrupted.len(), 2);
        let open = interrupted
            .iter()
            .find(|operation| operation.operation_id == open_id)
            .unwrap();
        assert_eq!(open.project_root, PathBuf::from("/project"));
        assert_eq!(open.staging_dir_name, open_id.to_string());
        assert!(open.ready.is_none());
        let ready = interrupted
            .iter()
            .find(|operation| operation.operation_id == ready_id)
            .unwrap();
        assert_eq!(ready.ready.as_ref(), Some(&ready_record()));
    }

    #[test]
    fn open_and_ready_operations_abort_as_terminal_non_publications() {
        let directory = tempfile::tempdir().unwrap();
        let open_id = Uuid::new_v4();
        let ready_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, open_id);
        begin(&journal, ready_id);
        journal.ready_to_commit(ready_id, &ready_record()).unwrap();

        journal.abort(open_id, SemgrepAbortKind::Failed).unwrap();
        journal
            .abort(ready_id, SemgrepAbortKind::Cancelled)
            .unwrap();
        drop(journal);

        let reopened = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(reopened.interrupted().unwrap().is_empty());
        for operation_id in [open_id, ready_id] {
            assert!(!reopened.is_closed(operation_id).unwrap());
            assert!(reopened
                .ready_to_commit(operation_id, &ready_record())
                .is_err());
            assert!(reopened.close(operation_id).is_err());
            assert!(reopened
                .abort(operation_id, SemgrepAbortKind::Recovered)
                .is_err());
        }
    }

    #[test]
    fn abort_rejects_unbounded_terminal_categories_at_the_type_boundary() {
        assert_eq!(
            serde_json::to_string(&SemgrepAbortKind::Recovered).unwrap(),
            "\"recovered\""
        );
        assert!(serde_json::from_str::<SemgrepAbortKind>("\"other\"").is_err());
    }

    #[test]
    fn close_error_before_write_replays_ready_for_compensation() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, operation_id);
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();
        journal.install_test_append_failure(AppendFailurePoint::BeforeWrite);

        assert!(journal.close(operation_id).is_err());
        drop(journal);

        let interrupted = SemgrepJournal::open(directory.path().to_path_buf())
            .interrupted()
            .unwrap();
        assert_eq!(interrupted.len(), 1);
        assert_eq!(interrupted[0].operation_id, operation_id);
        assert_eq!(interrupted[0].ready.as_ref(), Some(&ready_record()));
    }

    #[test]
    fn close_error_after_file_sync_replays_successful_close() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, operation_id);
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();
        journal.install_test_append_failure(AppendFailurePoint::AfterFileSync);

        assert!(journal.close(operation_id).is_err());
        drop(journal);

        let reopened = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(reopened.is_closed(operation_id).unwrap());
        assert!(reopened.interrupted().unwrap().is_empty());
    }

    #[test]
    fn illegal_lifecycle_transitions_fail_without_appending() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());

        assert!(journal.close(operation_id).is_err());
        assert!(journal
            .ready_to_commit(operation_id, &ready_record())
            .is_err());
        begin(&journal, operation_id);
        assert!(journal
            .begin(
                operation_id,
                Path::new("/project"),
                &operation_id.to_string()
            )
            .is_err());
        journal
            .ready_to_commit(operation_id, &ready_record())
            .unwrap();
        assert!(journal
            .ready_to_commit(operation_id, &ready_record())
            .is_err());
        journal.close(operation_id).unwrap();
        assert!(journal
            .ready_to_commit(operation_id, &ready_record())
            .is_err());
        assert!(journal.close(operation_id).is_err());

        let lines = std::fs::read_to_string(directory.path().join(format!("{operation_id}.jsonl")))
            .unwrap();
        assert_eq!(lines.lines().count(), 3);
        assert!(journal.durability_error().is_none());
    }

    #[test]
    fn staging_directory_name_must_equal_operation_uuid() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());

        assert!(journal
            .begin(operation_id, Path::new("/project"), "different")
            .is_err());
        assert!(!directory
            .path()
            .join(format!("{operation_id}.jsonl"))
            .exists());
    }

    #[test]
    fn each_operation_uses_its_uuid_jsonl_file() {
        let directory = tempfile::tempdir().unwrap();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, first);
        begin(&journal, second);

        let mut names = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        let mut expected = vec![
            std::ffi::OsString::from(super::TRANSACTION_LOCK_FILE),
            std::ffi::OsString::from(format!("{first}.jsonl")),
            std::ffi::OsString::from(format!("{second}.jsonl")),
        ];
        expected.sort();
        assert_eq!(names, expected);
    }

    #[test]
    fn malformed_record_sets_a_sticky_durability_error() {
        assert_corruption_is_sticky(b"{not-json}\n");
    }

    #[test]
    fn oversized_record_sets_a_sticky_durability_error() {
        assert_corruption_is_sticky(&vec![b'x'; 64 * 1024 + 1]);
    }

    #[test]
    fn unknown_version_sets_a_sticky_durability_error() {
        let operation_id = Uuid::new_v4();
        assert_named_corruption_is_sticky(
            operation_id,
            event_line("open", 2, operation_id).as_bytes(),
        );
    }

    #[test]
    fn truncated_record_sets_a_sticky_durability_error() {
        let operation_id = Uuid::new_v4();
        let truncated = event_line("open", 1, operation_id)
            .trim_end_matches('\n')
            .as_bytes()
            .to_vec();
        assert_named_corruption_is_sticky(operation_id, &truncated);
    }

    fn assert_corruption_is_sticky(bytes: &[u8]) {
        assert_named_corruption_is_sticky(Uuid::new_v4(), bytes);
    }

    fn assert_named_corruption_is_sticky(operation_id: Uuid, bytes: &[u8]) {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(
            directory.path().join(format!("{operation_id}.jsonl")),
            bytes,
        )
        .unwrap();

        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(
            journal.durability_error().is_none(),
            "construction must defer replay"
        );
        assert!(journal.interrupted().is_err());
        let first = journal.durability_error().expect("corruption must surface");
        assert!(!first.is_empty());
        assert!(journal.interrupted().is_err());
        assert_eq!(journal.durability_error().as_deref(), Some(first.as_str()));
        assert!(journal
            .begin(Uuid::new_v4(), Path::new("/project"), "invalid")
            .is_err());
        assert_eq!(journal.durability_error().as_deref(), Some(first.as_str()));
    }

    #[test]
    fn corrupt_operation_prevents_another_from_appearing_safely_closed() {
        let directory = tempfile::tempdir().unwrap();
        let closed_id = Uuid::new_v4();
        let corrupt_id = Uuid::new_v4();
        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&journal, closed_id);
        close(&journal, closed_id);
        drop(journal);
        std::fs::write(
            directory.path().join(format!("{corrupt_id}.jsonl")),
            b"{broken}\n",
        )
        .unwrap();

        let reopened = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(reopened.is_closed(closed_id).is_err());
        assert!(reopened.durability_error().is_some());
    }

    #[test]
    fn open_instances_share_corruption_health_and_revalidate_before_reads() {
        let directory = tempfile::tempdir().unwrap();
        let closed_id = Uuid::new_v4();
        let interrupted_id = Uuid::new_v4();
        let first = SemgrepJournal::open(directory.path().to_path_buf());
        let second = SemgrepJournal::open(directory.path().to_path_buf());
        begin(&first, closed_id);
        close(&first, closed_id);
        begin(&first, interrupted_id);

        let corrupt_id = Uuid::new_v4();
        std::fs::write(
            directory.path().join(format!("{corrupt_id}.jsonl")),
            b"{broken}\n",
        )
        .unwrap();

        let observed_error = second.is_closed(closed_id).unwrap_err();
        let sticky = second
            .durability_error()
            .expect("the observing instance must become degraded");
        assert!(matches!(
            observed_error,
            ClassifiedError::Storage(ref message) if message == &sticky
        ));
        assert_eq!(first.durability_error().as_deref(), Some(sticky.as_str()));
        let new_id = Uuid::new_v4();
        let begin_error = first
            .begin(new_id, Path::new("/project"), &new_id.to_string())
            .unwrap_err();
        let ready_error = first
            .ready_to_commit(interrupted_id, &ready_record())
            .unwrap_err();
        let close_error = first.close(interrupted_id).unwrap_err();
        for error in [begin_error, ready_error, close_error] {
            assert!(matches!(
                error,
                ClassifiedError::Storage(ref message) if message == &sticky
            ));
        }
        assert_eq!(first.durability_error().as_deref(), Some(sticky.as_str()));
    }

    #[cfg(unix)]
    #[test]
    fn operation_file_symlink_is_never_followed() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        std::fs::write(&target, b"unchanged").unwrap();
        let operation_id = Uuid::new_v4();
        symlink(
            &target,
            directory.path().join(format!("{operation_id}.jsonl")),
        )
        .unwrap();

        let journal = SemgrepJournal::open(directory.path().to_path_buf());
        assert!(journal
            .begin(
                operation_id,
                Path::new("/project"),
                &operation_id.to_string()
            )
            .is_err());
        assert!(journal.durability_error().is_some());
        assert_eq!(std::fs::read(&target).unwrap(), b"unchanged");
    }

    #[cfg(unix)]
    #[test]
    fn journal_directory_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let parent = tempfile::tempdir().unwrap();
        let actual = parent.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        let link = parent.path().join("journal");
        symlink(&actual, &link).unwrap();

        let journal = SemgrepJournal::open(link);
        let operation_id = Uuid::new_v4();
        assert!(journal
            .begin(
                operation_id,
                Path::new("/project"),
                &operation_id.to_string()
            )
            .is_err());
        assert!(journal.durability_error().is_some());
        assert!(std::fs::read_dir(actual).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[derive(Clone, Copy)]
    enum PathRace {
        Unlink,
        ReplaceRegular,
        ReplaceSymlink,
    }

    #[cfg(unix)]
    fn install_path_race(
        journal: &SemgrepJournal,
        operation_path: PathBuf,
        point: AppendRacePoint,
        race: PathRace,
    ) {
        use std::os::unix::fs::symlink;

        journal.install_test_race_hook(move |actual| {
            if actual != point {
                return;
            }
            std::fs::remove_file(&operation_path).unwrap();
            match race {
                PathRace::Unlink => {}
                PathRace::ReplaceRegular => {
                    std::fs::write(&operation_path, b"replacement\n").unwrap();
                }
                PathRace::ReplaceSymlink => {
                    let target = operation_path.with_extension("target");
                    std::fs::write(&target, b"target").unwrap();
                    symlink(target, &operation_path).unwrap();
                }
            }
        });
    }

    #[cfg(unix)]
    #[test]
    fn create_rejects_unlink_regular_and_symlink_replacement_races() {
        let cases = [
            (PathRace::Unlink, AppendRacePoint::BeforeIdentityCheck),
            (PathRace::ReplaceRegular, AppendRacePoint::AfterFileSync),
            (PathRace::ReplaceSymlink, AppendRacePoint::AfterFileSync),
        ];
        for (race, point) in cases {
            let directory = tempfile::tempdir().unwrap();
            let operation_id = Uuid::new_v4();
            let journal = SemgrepJournal::open(directory.path().to_path_buf());
            install_path_race(
                &journal,
                directory.path().join(format!("{operation_id}.jsonl")),
                point,
                race,
            );

            assert!(journal
                .begin(
                    operation_id,
                    Path::new("/project"),
                    &operation_id.to_string(),
                )
                .is_err());
            assert!(journal.durability_error().is_some());
        }
    }

    #[cfg(unix)]
    #[test]
    fn append_rejects_unlink_regular_and_symlink_replacement_races() {
        let cases = [
            (PathRace::Unlink, AppendRacePoint::AfterFileSync),
            (
                PathRace::ReplaceRegular,
                AppendRacePoint::BeforeIdentityCheck,
            ),
            (
                PathRace::ReplaceSymlink,
                AppendRacePoint::BeforeIdentityCheck,
            ),
        ];
        for (race, point) in cases {
            let directory = tempfile::tempdir().unwrap();
            let operation_id = Uuid::new_v4();
            let journal = SemgrepJournal::open(directory.path().to_path_buf());
            begin(&journal, operation_id);
            install_path_race(
                &journal,
                directory.path().join(format!("{operation_id}.jsonl")),
                point,
                race,
            );

            assert!(journal
                .ready_to_commit(operation_id, &ready_record())
                .is_err());
            assert!(journal.durability_error().is_some());
        }
    }

    #[test]
    fn journals_opened_for_the_same_directory_share_transition_serialization() {
        let directory = tempfile::tempdir().unwrap();
        let operation_id = Uuid::new_v4();
        let first = SemgrepJournal::open(directory.path().to_path_buf());
        let second = SemgrepJournal::open(directory.path().to_path_buf());

        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                first.begin(
                    operation_id,
                    Path::new("/project"),
                    &operation_id.to_string(),
                )
            });
            let right = scope.spawn(|| {
                second.begin(
                    operation_id,
                    Path::new("/project"),
                    &operation_id.to_string(),
                )
            });
            (left.join().unwrap(), right.join().unwrap())
        });

        assert_ne!(left.is_ok(), right.is_ok());
        assert!(SemgrepJournal::open(directory.path().to_path_buf())
            .interrupted()
            .unwrap()
            .iter()
            .any(|operation| operation.operation_id == operation_id));
    }

    #[test]
    fn in_memory_journal_enforces_the_same_lifecycle() {
        let journal = SemgrepJournal::in_memory();
        let operation_id = Uuid::new_v4();
        begin(&journal, operation_id);
        assert_eq!(journal.interrupted().unwrap().len(), 1);
        close(&journal, operation_id);
        assert!(journal.is_closed(operation_id).unwrap());
        assert!(journal.interrupted().unwrap().is_empty());
    }

    #[derive(Default)]
    struct RecordingWriter {
        calls: Vec<&'static str>,
        fail_sync: bool,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls.push("write");
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.calls.push("flush");
            Ok(())
        }
    }

    impl DurableWrite for RecordingWriter {
        fn sync_all(&mut self) -> io::Result<()> {
            self.calls.push("sync_all");
            if self.fail_sync {
                Err(io::Error::other("injected sync failure"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn append_flushes_and_syncs_before_reporting_success() {
        let mut writer = RecordingWriter::default();

        append_and_sync(&mut writer, b"record\n").unwrap();

        assert_eq!(writer.calls, ["write", "flush", "sync_all"]);
    }

    #[test]
    fn append_does_not_report_success_when_sync_fails() {
        let mut writer = RecordingWriter {
            fail_sync: true,
            ..RecordingWriter::default()
        };

        assert!(append_and_sync(&mut writer, b"record\n").is_err());
        assert_eq!(writer.calls, ["write", "flush", "sync_all"]);
    }
}
