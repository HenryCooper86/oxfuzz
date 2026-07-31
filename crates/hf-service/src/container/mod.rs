//! Central dependency container -- shared by all presentation layers.
//!
//! Mirrors the `y-service::ServiceContainer` pattern: the GUI, CLI, and
//! web API all construct one container and call service methods through it.
//! This keeps business logic out of presentation crates (AGENTS.md 2.9) and
//! ensures every build / fuzz run goes through `hf-runtime` sandboxing
//! (AGENTS.md 2.12).

mod chat;
mod corpus;
mod coverage_cache;
mod crash_inputs;
mod discovery;
mod guards;
mod harness;
mod harness_workspace;
mod history;
mod lifecycle;
mod output_budget;
mod policy;
mod project_identity;
mod run;
mod staging;
mod system;
mod triage;
mod workspace;

pub use guards::AgentTurnGuard;
pub use harness_workspace::{copy_project_sources, generate_target_seeds};
pub use workspace::{
    initialize_workspace_root, project_workspace_dir, workspace_dir, workspace_root,
};

use std::fmt::Write;
use std::fs::File;
#[cfg(feature = "semgrep-enrichment")]
use std::fs::TryLockError;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use coverage_cache::{coverage_signature, export_cache};
use crash_inputs::{
    bucket_by_cluster, casrep_input_path, collect_casreps, collect_crash_inputs,
    collect_legacy_crash_inputs, deterministic_crash_id, is_regular_file, stage_crash_inputs,
};
use guards::{
    close_run_journal, ensure_run_journal_durable, ActiveRunGuard, PersistedRunGuard,
    ProviderHealthTask,
};
use harness_workspace::{
    build_workspace_dictionary, container_input_path, dict_llm_cache, harness_binary_name,
    read_current_harness_id, read_current_harness_source, read_dictionary_source_excerpt,
    sanitize_target, write_current_harness_id, write_current_harness_source,
};
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessDraft, HarnessStatus};
use hf_core::provider::ProviderPool;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetCandidate, TargetLanguage};
use hf_guardrails::{Action, Decision, Guardrails};
use hf_runtime::{RuntimeConfig, SANDBOX_IMAGE};
use hf_storage::{AutoRevertEvent, GuardrailDecisionRecord, RunKind, RunRecord, RunStatus, Store};
use output_budget::{monitor_run_output, run_artifacts_within_budget};
use policy::GUARDRAIL_DECISION_RETENTION;
use project_identity::{
    canonical_project_root, defectdojo_project_name, project_slug, select_target_candidate,
    stored_project_matches,
};
use staging::{
    qualification_evidence, resolve_run_sandbox_image, retain_run_context, run_binary_path,
    run_context_digests, run_output_dir, run_sandbox_options, run_source_path, sha256_file,
    stage_run_artifacts, verify_run_artifacts, verify_staged_qualification, ReplayProvenance,
    RunArtifacts,
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use workspace::{
    clear_managed_workspace_root, prepare_configured_workspace_root,
    prepare_managed_workspace_root_with_adoption, resolve_workspace_directory, run_output_relative,
    workspace_lock_error, workspace_lock_file, workspace_operation_gate,
};

const SMOKE_FUZZ_SECS: u64 = 60;
const COVERAGE_PRUNE_OPERATION_SECS: u64 = 600;
const COVERAGE_PRUNE_COMMAND_SECS: u64 = 10;
const CORPUS_MINIMIZE_SECS: u64 = 300;
/// Bound on the stored policy reason; denial reasons embed action labels that
/// can carry long parameters (e.g. a shell command).
const MAX_GUARDAIL_DETAIL_CHARS: usize = 256;
pub(crate) const WORKSPACE_CLEANUP_BUSY_MESSAGE: &str =
    "workspace cannot be cleared while another workspace operation is active";
pub(crate) const EXACT_DOCKER_IMAGE_REV_PREFIX: &str = "docker-image-id-sha256:";

pub(crate) struct WorkspaceOperationLease {
    _process_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    _system_guard: File,
}

pub(crate) struct WorkspaceCleanupLease {
    _process_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
    _system_guard: File,
}

#[cfg(feature = "semgrep-enrichment")]
pub(crate) struct SemgrepProjectLease {
    _system_guard: File,
}

fn fuzzing_policy_error(error: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!("invalid fuzzing settings: {error}"))
}

fn require_fuzzing_harness_engine(
    engine: EngineKind,
    language: TargetLanguage,
) -> Result<(), ClassifiedError> {
    crate::config::resolve_harness_engine(Some(engine), language)
        .map(|_| ())
        .map_err(|error| fuzzing_policy_error(&error))
}

fn resolve_fuzzing_run(
    engine: EngineKind,
    duration_secs: u64,
) -> Result<crate::config::ResolvedFuzzingRun, ClassifiedError> {
    crate::config::resolve_fuzzing_run(Some(engine), Some(duration_secs))
        .map_err(|error| fuzzing_policy_error(&error))
}

/// Internal pipeline steps (smoke qualification, coverage pruning, corpus
/// minimization) run fixed implementation budgets, not operator-requested
/// campaigns, so they clamp to the configured ceiling instead of failing.
fn resolve_internal_run(
    engine: EngineKind,
    internal_budget_secs: u64,
) -> Result<crate::config::ResolvedFuzzingRun, ClassifiedError> {
    crate::config::resolve_internal_fuzzing_run(engine, internal_budget_secs)
        .map_err(|error| fuzzing_policy_error(&error))
}

/// Runs that reached a terminal state may own crash artifacts. Failed and
/// cancelled campaigns can produce valid partial evidence before stopping.
fn run_has_crash_evidence(status: RunStatus) -> bool {
    matches!(
        status,
        RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
    )
}

#[cfg(feature = "semgrep-enrichment")]
pub(crate) fn acquire_semgrep_project_lease(
    canonical_project: &Path,
) -> Result<SemgrepProjectLease, ClassifiedError> {
    use sha2::{Digest as _, Sha256};

    let lock_dir = crate::init::user_app_dir().join("locks");
    std::fs::create_dir_all(&lock_dir).map_err(|error| {
        ClassifiedError::Internal(format!(
            "create Semgrep project lease directory {}: {error}",
            lock_dir.display()
        ))
    })?;
    let digest = Sha256::digest(canonical_project.as_os_str().as_encoded_bytes());
    let lock_path = lock_dir.join(format!("semgrep-project-{digest:x}.lock"));
    let system_guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| {
            ClassifiedError::Internal(format!(
                "open Semgrep project lease {}: {error}",
                lock_path.display()
            ))
        })?;
    system_guard.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => {
            ClassifiedError::Validation("Semgrep enrichment: busy".to_owned())
        }
        TryLockError::Error(error) => {
            ClassifiedError::Internal(format!("acquire Semgrep project lease: {error}"))
        }
    })?;
    Ok(SemgrepProjectLease {
        _system_guard: system_guard,
    })
}

/// Initialize an explicit workspace root for a service-owned subsystem after
/// that subsystem has completed all policy preflight checks.
#[cfg(feature = "automotive-scapy")]
pub(crate) fn initialize_workspace_root_at(root: &Path) -> Result<PathBuf, ClassifiedError> {
    prepare_managed_workspace_root_with_adoption(root, false)
}

/// Create or resolve a service-owned directory below `workspace` without
/// following symlinks left by an earlier untrusted sandbox execution.
pub(crate) fn ensure_workspace_directory(
    workspace: &Path,
    relative: &Path,
) -> Result<PathBuf, ClassifiedError> {
    let workspace_metadata = std::fs::symlink_metadata(workspace).map_err(|e| {
        ClassifiedError::Validation(format!(
            "inspect workspace directory {}: {e}",
            workspace.display()
        ))
    })?;
    if !workspace_metadata.file_type().is_dir() {
        return Err(ClassifiedError::Validation(format!(
            "workspace is not a regular directory: {}",
            workspace.display()
        )));
    }
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || !relative
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
    {
        return Err(ClassifiedError::Validation(format!(
            "workspace directory path is unsafe: {}",
            relative.display()
        )));
    }

    let root = std::fs::canonicalize(workspace).map_err(|e| {
        ClassifiedError::Validation(format!("resolve workspace {}: {e}", workspace.display()))
    })?;
    let mut current = root.clone();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            unreachable!("relative path was validated above")
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(ClassifiedError::Validation(format!(
                    "workspace directory is not a regular directory: {}",
                    current.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir(&current).map_err(|e| {
                    ClassifiedError::Internal(format!(
                        "create workspace directory {}: {e}",
                        current.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect workspace directory {}: {error}",
                    current.display()
                )));
            }
        }
    }
    let resolved = std::fs::canonicalize(&current).map_err(|e| {
        ClassifiedError::Validation(format!(
            "resolve workspace directory {}: {e}",
            current.display()
        ))
    })?;
    if !resolved.starts_with(&root) {
        return Err(ClassifiedError::Validation(format!(
            "workspace directory escaped {}: {}",
            root.display(),
            resolved.display()
        )));
    }
    Ok(resolved)
}

async fn merge_run_discoveries(
    engine: EngineKind,
    artifacts: &RunArtifacts,
    retained_corpus: &Path,
) -> Result<hf_core::corpus::Corpus, ClassifiedError> {
    let run_corpus = artifacts.corpus_host.clone();
    let run_output = artifacts.output_host.clone();
    let retained_corpus = retained_corpus.to_path_buf();
    let (corpus, _) = tokio::task::spawn_blocking(move || {
        if matches!(engine, EngineKind::AflPlusPlus | EngineKind::Honggfuzz) {
            hf_corpus::grow(&run_corpus, &run_output)?;
        }
        hf_corpus::merge_snapshot(&retained_corpus, &run_corpus)
    })
    .await
    .map_err(|error| ClassifiedError::Internal(format!("join corpus merge task: {error}")))??;
    Ok(corpus)
}

struct TerminalRunMetrics {
    edges: u64,
    execs: f64,
    crashes: u64,
}

fn retained_coverage_samples(
    series: &std::sync::Mutex<Vec<(f64, u64, f64)>>,
) -> Vec<CoverageSample> {
    let raw = series
        .lock()
        .map(|samples| samples.clone())
        .unwrap_or_default();
    downsample(&raw, 150)
        .into_iter()
        .map(|(t, edges, execs)| CoverageSample { t, edges, execs })
        .collect()
}

async fn persist_terminal_run_evidence(
    store: &Store,
    run_id: Uuid,
    metrics: &TerminalRunMetrics,
    series: &std::sync::Mutex<Vec<(f64, u64, f64)>>,
) -> Result<(), ClassifiedError> {
    store
        .set_run_stats(run_id, metrics.edges, metrics.execs, metrics.crashes)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
    let samples = retained_coverage_samples(series);
    if !samples.is_empty() {
        let json = serde_json::to_string(&samples).map_err(|error| {
            ClassifiedError::Internal(format!("serialize run samples: {error}"))
        })?;
        store
            .set_run_samples(run_id, &json)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
    }
    Ok(())
}

async fn terminal_run_metrics(
    engine: EngineKind,
    artifacts: &RunArtifacts,
    result: &hf_engine::runner::RunResult,
) -> Result<TerminalRunMetrics, ClassifiedError> {
    let mut edges = 0_u64;
    let mut execs = 0.0_f64;
    let mut finding_reported = false;
    for progress in &result.progress {
        match progress {
            FuzzProgress::EdgesCovered(value) => edges = edges.max(*value),
            FuzzProgress::ExecsPerSec(value) => execs = execs.max(*value),
            FuzzProgress::CrashesFound(count) => finding_reported |= *count > 0,
            FuzzProgress::LogLine(_) | FuzzProgress::Done => {}
        }
    }

    let mut terminal_afl_crashes = 0_u64;
    if engine == EngineKind::AflPlusPlus {
        let output = artifacts.output_host.clone();
        if let Some(stats) = tokio::task::spawn_blocking(move || {
            hf_engine::afl::read_fuzzer_stats(&output)
                .map_err(|error| ClassifiedError::Validation(error.to_string()))
        })
        .await
        .map_err(|error| {
            ClassifiedError::Internal(format!("join AFL++ statistics task: {error}"))
        })?? {
            if let Some(value) = stats.edges_found {
                edges = edges.max(value);
            }
            if let Some(value) = stats.execs_per_sec {
                execs = execs.max(value);
            }
            terminal_afl_crashes = stats.saved_crashes.unwrap_or(0);
        }
    }
    // Recursive crash-artifact walk over a possibly large output tree: run it on
    // the blocking pool, like the AFL stats read above, rather than stalling a
    // tokio worker (and progress streaming) on synchronous filesystem I/O.
    let crash_out = artifacts.output_host.clone();
    let artifact_crashes =
        tokio::task::spawn_blocking(move || collect_crash_inputs(engine, &crash_out).len() as u64)
            .await
            .map_err(|error| {
                ClassifiedError::Internal(format!("join crash-artifact scan task: {error}"))
            })?;
    Ok(TerminalRunMetrics {
        edges,
        execs,
        crashes: artifact_crashes
            .max(u64::from(finding_reported))
            .max(terminal_afl_crashes),
    })
}

/// Resolve a per-project directory beneath an explicit managed workspace root.
#[must_use]
#[cfg(feature = "automotive-scapy")]
pub(crate) fn project_workspace_dir_at(root: &Path, project: &Path) -> PathBuf {
    root.join(project_slug(project))
}

/// Whether the in-container qemu for a syzkaller run can use KVM hardware
/// acceleration. Requires a Linux host with `/dev/kvm`, and that the sandbox
/// arch matches the host arch (KVM cannot accelerate a foreign architecture).
/// On macOS/Windows the Docker VM does not expose nested KVM, so this is always
/// false and qemu falls back to slow TCG emulation.
fn syz_kvm_usable(platform: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        hf_runtime::norm_platform(platform) == hf_runtime::host_platform()
            && Path::new("/dev/kvm").exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = platform;
        false
    }
}

/// Build the sandbox image from the repo's Dockerfile for a given platform.
///
/// # Errors
/// Returns `ClassifiedError::Internal` if the `docker build` command fails.
pub fn build_sandbox_image(root: &Path, platform: &str) -> Result<(), ClassifiedError> {
    let status = std::process::Command::new(hf_runtime::docker_bin())
        .current_dir(root)
        .args([
            "build",
            "--platform",
            platform,
            "-t",
            SANDBOX_IMAGE,
            "-f",
            "docker/sandbox/Dockerfile",
            ".",
        ])
        .status()
        .map_err(|e| ClassifiedError::Internal(format!("docker build: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(ClassifiedError::Internal("docker build failed".to_owned()))
    }
}

/// Walk up from the current dir and the executable path looking for the repo
/// root (the directory that contains `docker/sandbox/Dockerfile`).
pub fn repo_root() -> Option<PathBuf> {
    let mut starts: Vec<PathBuf> = Vec::new();
    if let Ok(dir) = std::env::current_dir() {
        starts.push(dir);
    }
    if let Ok(exe) = std::env::current_exe() {
        starts.push(exe);
    }
    for start in starts {
        let mut cur: Option<&Path> = Some(start.as_path());
        while let Some(p) = cur {
            if p.join("Cargo.toml").is_file() && p.join("config").is_dir() {
                return Some(p.to_path_buf());
            }
            cur = p.parent();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ServiceContainer
// ---------------------------------------------------------------------------

/// All wired application services, constructed from a runtime + optional
/// provider pool.
///
/// The container is `Clone` (it wraps `Arc`) so Tauri commands can capture
/// it by value.
#[derive(Clone)]
pub struct ServiceContainer {
    runtime: Arc<dyn RuntimeAdapter>,
    /// The LLM provider pool, held in a shared swappable cell so it can be
    /// reloaded from config at runtime ([`Self::reload_providers`]) and the new
    /// pool is seen by every clone of this container (and thus every consumer)
    /// without a restart.
    provider_pool: Arc<std::sync::RwLock<Option<Arc<dyn ProviderPool>>>>,
    store: Option<Arc<Store>>,
    session_manager: Option<Arc<hf_session::SessionManager>>,
    checkpoint_manager: Option<Arc<hf_session::ChatCheckpointManager>>,
    guardrails: Guardrails,
    diagnostics: Arc<crate::diagnostics::DiagnosticsRecorder>,
    run_journal: Arc<crate::recovery::RunJournal>,
    #[cfg(feature = "semgrep-enrichment")]
    pub(crate) semgrep: Arc<crate::semgrep::SemgrepCoordinator>,
    /// Cancellation tokens for in-flight fuzz runs, keyed by run id. A run
    /// registers its token on start and removes it on completion;
    /// [`Self::cancel_run`] fires the token to stop the run cooperatively.
    active_runs: Arc<std::sync::Mutex<std::collections::HashMap<Uuid, CancellationToken>>>,
    /// Labels of agent turns currently executing, so the Observability panel can
    /// show live agent activity instead of always "No active agent instances".
    /// A turn registers via [`Self::track_agent`] and is removed when the
    /// returned guard drops. Shared across clones of this container.
    active_agents: Arc<std::sync::Mutex<Vec<String>>>,
    /// Per-session locks serializing every chat read-modify-write operation.
    /// Turns, rollback, branching, and deletion share this lock so transcript,
    /// metadata, and checkpoint mutations cannot interleave. Different
    /// sessions still run concurrently. Shared across clones.
    session_turn_locks: Arc<
        std::sync::Mutex<
            std::collections::HashMap<hf_core::types::SessionId, Arc<tokio::sync::Mutex<()>>>,
        >,
    >,
    /// Late-bound link to the campaign scheduler, shared across clones of this
    /// container so any operation in this process (scheduled or interactive)
    /// can emit scheduler events (crash found, run terminated). Set by
    /// `CampaignScheduler::try_start` via [`Self::bind_scheduler_events`].
    scheduler_events:
        Arc<std::sync::Mutex<Option<std::sync::Weak<hf_scheduler::SchedulerManager>>>>,
    /// Keeps the periodic provider health-check task alive; when the last
    /// clone of the container drops, the guard cancels and aborts the loop.
    /// `None` for containers built via [`Self::new`] (tests, stubs).
    _health_task: Option<Arc<ProviderHealthTask>>,
}

/// Truncate a policy reason to the audit column's bound, on a char boundary.
fn bounded_guardrail_detail(reason: &str) -> String {
    reason.chars().take(MAX_GUARDAIL_DETAIL_CHARS).collect()
}

/// Build the per-model cost table (`model -> (per-1k-in, per-1k-out)`) from the
/// configured providers, for LLM cost diagnostics.
fn build_cost_map() -> std::collections::HashMap<String, (f64, f64)> {
    crate::config::get_providers()
        .into_iter()
        .map(|p| (p.model, (p.cost_per_1k_input, p.cost_per_1k_output)))
        .collect()
}

/// Build the `hf-session` managers over a database store: the [`SessionManager`]
/// (`SQLite` session tree + `JSONL` display/context transcripts) and a
/// [`ChatCheckpointManager`] sharing the same stores for turn-level rollback
/// (checkpoints are persisted in `SQLite` so undo survives restarts).
///
/// [`SessionManager`]: hf_session::SessionManager
/// [`ChatCheckpointManager`]: hf_session::ChatCheckpointManager
fn build_session_managers(
    store: &Arc<Store>,
) -> (
    Arc<hf_session::SessionManager>,
    Arc<hf_session::ChatCheckpointManager>,
) {
    use hf_core::session::{
        ChatCheckpointStore, DisplayTranscriptStore, SessionStore, TranscriptStore,
    };

    let base = crate::init::user_app_dir().join("transcripts");
    let session_store: Arc<dyn SessionStore> =
        Arc::new(hf_storage::SqliteSessionStore::new(store.pool().clone()));
    let transcript: Arc<dyn TranscriptStore> =
        Arc::new(hf_storage::JsonlTranscriptStore::new(base.join("context")));
    let display: Arc<dyn DisplayTranscriptStore> = Arc::new(
        hf_storage::JsonlDisplayTranscriptStore::new(base.join("display")),
    );
    // Persist checkpoints in the DB so turn-level rollback survives a restart
    // (the in-memory store lost them on exit, silently no-op'ing rollback).
    let checkpoint_store: Arc<dyn ChatCheckpointStore> = Arc::new(
        hf_storage::SqliteChatCheckpointStore::new(store.pool().clone()),
    );

    let manager = Arc::new(hf_session::SessionManager::new(
        Arc::clone(&session_store),
        Arc::clone(&transcript),
        Arc::clone(&display),
        crate::config::effective_session_config(),
    ));
    let checkpoints = Arc::new(hf_session::ChatCheckpointManager::new(
        transcript,
        display,
        checkpoint_store,
        session_store,
    ));
    (manager, checkpoints)
}

fn chat_storage_error(context: &str, error: impl std::fmt::Display) -> ClassifiedError {
    ClassifiedError::Storage(format!("{context}: {error}"))
}

impl ServiceContainer {

    async fn create_chat_checkpoint_unlocked(
        &self,
        session: &hf_core::types::SessionId,
        message_count_before: u32,
    ) -> Result<(), ClassifiedError> {
        let manager = self.chat_checkpoint_manager()?;
        let turn = manager
            .current_turn(session)
            .await
            .map_err(|error| chat_storage_error("read current chat turn", error))?
            .saturating_add(1);
        manager
            .create_checkpoint(
                session,
                turn,
                message_count_before,
                Uuid::new_v4().to_string(),
            )
            .await
            .map_err(|error| chat_storage_error("create chat checkpoint", error))?;
        Ok(())
    }

    pub(crate) async fn persist_chat_turn_unlocked(
        &self,
        session: &hf_core::types::SessionId,
        messages: &[hf_core::types::Message],
    ) -> Result<(), ClassifiedError> {
        let sessions = self.chat_session_manager()?;
        let checkpoints = self.chat_checkpoint_manager()?;
        let snapshot = sessions
            .snapshot_transcripts(session)
            .await
            .map_err(|error| chat_storage_error("snapshot chat transcript", error))?;
        let message_count_before = snapshot.context_count();
        let turn = checkpoints
            .current_turn(session)
            .await
            .map_err(|error| chat_storage_error("read current chat turn", error))?
            .saturating_add(1);

        sessions
            .append_messages(session, messages)
            .await
            .map_err(|error| chat_storage_error("append chat turn", error))?;
        if let Err(error) = checkpoints
            .create_checkpoint(
                session,
                turn,
                u32::try_from(message_count_before).unwrap_or(u32::MAX),
                Uuid::new_v4().to_string(),
            )
            .await
        {
            let compensation = sessions
                .restore_transcript_snapshot(session, &snapshot)
                .await;
            let detail = match compensation {
                Ok(()) => format!(
                    "create chat checkpoint failed and transcript was rolled back: {error}"
                ),
                Err(rollback) => format!(
                    "create chat checkpoint failed: {error}; transcript compensation failed: {rollback}"
                ),
            };
            return Err(ClassifiedError::Storage(detail));
        }
        Ok(())
    }

    async fn validate_chat_session(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<(), ClassifiedError> {
        let node = self
            .chat_session_manager()?
            .get_session(session)
            .await
            .map_err(|_| {
                ClassifiedError::Validation("unknown or invalid chat session".to_owned())
            })?;
        if node.state != hf_core::session::SessionState::Active {
            return Err(ClassifiedError::Validation(
                "chat session is not active".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn chat_session_guard(
        &self,
        session: &hf_core::types::SessionId,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, ClassifiedError> {
        // Validate before adding an entry to the lock map so arbitrary ids do
        // not retain mutexes. Validate again after acquisition to close the
        // race with a deletion that was already waiting on the same lock.
        self.validate_chat_session(session).await?;
        let guard = self.session_turn_lock(session).lock_owned().await;
        self.validate_chat_session(session).await?;
        Ok(guard)
    }

    fn chat_session_manager(&self) -> Result<&Arc<hf_session::SessionManager>, ClassifiedError> {
        self.session_manager.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("chat persistence is not configured".to_owned())
        })
    }

    fn chat_checkpoint_manager(
        &self,
    ) -> Result<&Arc<hf_session::ChatCheckpointManager>, ClassifiedError> {
        self.checkpoint_manager.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("chat checkpoints are not configured".to_owned())
        })
    }

    async fn ensure_run_is_not_qualification(
        &self,
        store: &Store,
        run_id: Uuid,
    ) -> Result<(), ClassifiedError> {
        let referenced = store
            .list_all_harnesses()
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .any(|harness| {
                harness.smoke_run.as_ref().and_then(|smoke| smoke.run_id) == Some(run_id)
            });
        if referenced {
            return Err(ClassifiedError::Validation(format!(
                "run {run_id} is retained harness qualification evidence"
            )));
        }
        Ok(())
    }

    async fn run_evidence_root(
        &self,
        store: &Store,
        run: &RunRecord,
    ) -> Result<Option<PathBuf>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let Some(recorded) = run.evidence_dir.as_deref() else {
            return Ok(None);
        };
        let expected = run_output_relative(run.id);
        if Path::new(recorded) != expected {
            return Err(ClassifiedError::Validation(format!(
                "run {} has invalid evidence directory '{}'",
                run.id, recorded
            )));
        }
        let harness_id = run
            .config
            .as_ref()
            .map(|config| config.harness_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run {} has evidence but no harness attribution",
                    run.id
                ))
            })?;
        let harness = store.get_harness(harness_id).await?.ok_or_else(|| {
            ClassifiedError::Validation(format!("run {} evidence has no harness record", run.id))
        })?;
        let target = store
            .list_all_targets()
            .await?
            .into_iter()
            .find(|target| target.id == harness.target_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run {} evidence has no target record", run.id))
            })?;
        let workspace = workspace_dir(Path::new(&run.project_root), &target.symbol);
        let relative_root = PathBuf::from("runs").join(run.id.to_string());
        let candidate = workspace.join(&relative_root);
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                resolve_workspace_directory(&workspace, &relative_root).map(Some)
            }
            Ok(_) => Err(ClassifiedError::Validation(format!(
                "run {} evidence root is not a regular directory: {}",
                run.id,
                candidate.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(ClassifiedError::Validation(format!(
                "inspect run {} evidence root: {error}",
                run.id
            ))),
        }
    }

    /// The target a persisted run exercised, resolved through its harness
    /// (`run.config.harness_id -> harness.target_id`). `None` if unrecorded.
    async fn run_target_id(
        &self,
        store: &Store,
        run: &RunRecord,
    ) -> Result<Option<Uuid>, ClassifiedError> {
        let Some(harness_id) = run.config.as_ref().map(|c| c.harness_id) else {
            return Ok(None);
        };
        Ok(store
            .get_harness(harness_id)
            .await?
            .map(|harness| harness.target_id))
    }

    /// The effective auto-revert policy for a project: its stored per-project
    /// override when one is set, otherwise the global policy from config.
    async fn effective_auto_revert_policy(
        &self,
        project: &Path,
    ) -> Result<crate::config::AutoRevertPolicy, ClassifiedError> {
        if let Some(store) = self.store.as_ref() {
            let key = project.to_string_lossy().to_string();
            if let Some(o) = store.project_auto_revert(&key).await? {
                return Ok(crate::config::AutoRevertPolicy {
                    enabled: o.enabled,
                    threshold_pct: o.threshold_pct,
                    notify_only: o.notify_only,
                });
            }
        }
        Ok(crate::config::auto_revert_policy())
    }

    /// Evaluate the auto-revert policy for a just-finished run and, if it
    /// triggered, restore the most recent comparable (last-good) harness revision.
    ///
    /// The policy fires only when it is enabled and this run's harness revision
    /// differs from a comparable finished run for the same target *and* this
    /// run's peak edge coverage dropped by at least the configured percentage
    /// versus a prior run with the same target, engine, budget, resources,
    /// sanitizer, corpus location, environment, and engine arguments. The
    /// restore reuses [`Self::revert_harness_from_run`], so exact-artifact
    /// activation is HITL-gated exactly like a manual revert -- a denied approval
    /// simply leaves the harness unchanged. Returns the outcome only when the
    /// revert applied.
    async fn maybe_auto_revert(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        this_edges: u64,
        this_rev: Option<&str>,
    ) -> Option<AutoRevertOutcome> {
        let policy = match self.effective_auto_revert_policy(project).await {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not read its effective policy");
                return None;
            }
        };
        if !policy.enabled {
            return None;
        }
        let store = self.store.as_ref()?;
        // Without a recorded revision we cannot attribute a change to a harness.
        let this_rev = this_rev.filter(|r| !r.is_empty())?;
        // The most recent comparable finished run for this same target, before
        // this one, that recorded edge coverage and a harness revision.
        let key = project.to_string_lossy().to_string();
        let mut runs = match store.list_runs(Some(&key)).await {
            Ok(runs) => runs,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not read comparable runs");
                return None;
            }
        };
        runs.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        let this_run = runs.iter().find(|r| r.id == this_run_id).cloned()?;
        let this_config = this_run.config.as_ref()?;
        if this_run.status != RunStatus::Done || this_run.kind != RunKind::Campaign {
            return None;
        }
        let this_context = this_run
            .context_rev
            .as_deref()
            .filter(|value| !value.is_empty())?;
        // Resolve the target through the run's persisted harness rather than
        // re-discovering it as C. This keeps C++, Rust, and future language runs
        // eligible for the same rollback policy.
        let target_id = match self.run_target_id(store, &this_run).await {
            Ok(Some(target_id)) => target_id,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not resolve the current run target");
                return None;
            }
        };
        let mut prev = None;
        for r in runs {
            if r.id == this_run_id
                || r.status != RunStatus::Done
                || r.kind != RunKind::Campaign
                || r.edges.is_none()
                || r.harness_rev.is_none()
                || r.harness_rev.as_deref() == Some(this_rev)
                || r.context_rev.as_deref() != Some(this_context)
            {
                continue;
            }
            if r.started_at >= this_run.started_at {
                continue;
            }
            let Some(previous_config) = r.config.as_ref() else {
                continue;
            };
            if !auto_revert_baseline_compatible(previous_config, this_config) {
                continue;
            }
            let candidate_target = match self.run_target_id(store, &r).await {
                Ok(candidate_target) => candidate_target,
                Err(error) => {
                    tracing::warn!(%error, "auto-revert could not resolve a baseline run target");
                    return None;
                }
            };
            if candidate_target == Some(target_id) {
                prev = Some(r);
                break;
            }
        }
        let prev = prev?;
        let prev_rev = prev.harness_rev.clone().unwrap_or_default();
        let prev_edges = prev.edges.unwrap_or(0);
        let drop_pct = auto_revert_decision(
            &prev_rev,
            this_rev,
            prev_edges,
            this_edges,
            policy.threshold_pct,
        )?;

        let prev_id = prev.id.to_string();
        let outcome = |reverted: bool| AutoRevertOutcome {
            reverted_to_run: prev_id.clone(),
            from_rev: this_rev.to_owned(),
            to_rev: prev_rev.clone(),
            previous_edges: prev_edges,
            regressed_edges: this_edges,
            drop_pct,
            reverted,
        };

        // Notify-only: report the regression (journal + surfaced outcome) but do
        // not touch the harness. This is the safe default for headless/scheduled
        // campaigns, which run permissively and would otherwise mutate unattended.
        if policy.notify_only {
            let detail = format!(
                "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev}; comparable last-good {prev_rev} is run {prev_id} (notify-only, not restored)"
            );
            tracing::warn!("auto-revert (notify-only): {detail}");
            self.run_journal
                .note(this_run_id, "auto-revert-notify", &detail);
            let out = outcome(false);
            self.persist_auto_revert_event(project, target, this_run_id, &out)
                .await;
            return Some(out);
        }

        // Regression confirmed: restore the comparable baseline's harness. The
        // recompile is HITL-gated inside `harness_compile`; if approval is denied
        // the active canonical revision and binary remain unchanged.
        match self.revert_harness_from_run(&prev_id).await {
            Ok(_) => {
                let detail = format!(
                    "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev} -> restored comparable baseline {prev_rev} from run {prev_id}"
                );
                tracing::warn!("auto-revert: {detail}");
                self.run_journal.note(this_run_id, "auto-revert", &detail);
                let out = outcome(true);
                self.persist_auto_revert_event(project, target, this_run_id, &out)
                    .await;
                Some(out)
            }
            Err(e) => {
                tracing::warn!("auto-revert declined or failed: {e}");
                None
            }
        }
    }

    /// Persist an auto-revert firing to the durable audit trail (best-effort).
    async fn persist_auto_revert_event(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        out: &AutoRevertOutcome,
    ) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let ev = AutoRevertEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            project_root: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            run_id: this_run_id.to_string(),
            from_rev: out.from_rev.clone(),
            to_rev: out.to_rev.clone(),
            previous_edges: out.previous_edges,
            regressed_edges: out.regressed_edges,
            drop_pct: out.drop_pct,
            reverted: out.reverted,
        };
        if let Err(e) = store.record_auto_revert_event(&ev).await {
            tracing::warn!("failed to record auto-revert event: {e}");
        }
    }

    // -- Guardrail decision audit --------------------------------------------

    /// Authorize `action`, appending the decision to the durable policy audit
    /// trail. Every authorizing service entry point goes through here so the
    /// record is uniform: the policy outcome, and the approval-gate outcome
    /// when the gate was consulted.
    ///
    /// Recording is best-effort (AGENTS.md 2.5): a storage failure is logged
    /// and never changes the authorization outcome, which stays exactly what
    /// [`Guardrails::authorize`] returns.
    pub(crate) async fn authorize_recorded(
        &self,
        action: Action,
        origin: &'static str,
        project: Option<&Path>,
    ) -> Result<(), hf_guardrails::GuardrailError> {
        let action_kind = action.kind();
        let risk_tier = action.risk();
        let policy_decision = self.guardrails.policy().evaluate(&action);
        let outcome = self.guardrails.authorize(action).await;
        let (decision, detail) = match (&policy_decision, &outcome) {
            (Decision::RequireApproval { reason, .. }, Ok(())) => {
                ("approved", Some(reason.clone()))
            }
            (Decision::RequireApproval { .. }, Err(error)) => {
                ("denied_by_operator", Some(error.to_string()))
            }
            (Decision::Deny { reason }, _) => ("denied", Some(reason.clone())),
            (Decision::Allow, Ok(())) => ("allowed", None),
            (Decision::Allow, Err(error)) => ("denied", Some(error.to_string())),
        };
        self.record_guardrail_decision(GuardrailDecisionRecord {
            id: Uuid::new_v4().to_string(),
            decided_at: Utc::now(),
            action: action_kind.to_owned(),
            risk_tier: risk_tier.as_str().to_owned(),
            decision: decision.to_owned(),
            origin: origin.to_owned(),
            project: project.map(|path| path.to_string_lossy().into_owned()),
            detail: detail.map(|detail| bounded_guardrail_detail(&detail)),
        })
        .await;
        outcome
    }

    /// Persist one guardrail decision, then prune the trail to its retention
    /// window. Failures are logged, never propagated: the audit write must not
    /// change the operation's outcome.
    async fn record_guardrail_decision(&self, record: GuardrailDecisionRecord) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        if let Err(error) = store.record_guardrail_decision(&record).await {
            tracing::warn!(%error, "failed to record guardrail decision");
            return;
        }
        if let Err(error) = store
            .prune_guardrail_decisions(GUARDRAIL_DECISION_RETENTION)
            .await
        {
            tracing::warn!(%error, "failed to prune guardrail decisions");
        }
    }

    /// Build a human-reviewable issue draft for a crash, targeting the fuzzed
    /// project's configured GitHub/GitLab repository.
    ///
    /// Non-publishing: it returns a title, Markdown body, labels, the provider,
    /// and a prefilled new-issue URL. Use [`Self::file_issue`] to actually file it.
    pub async fn issue_export(
        &self,
        project: &Path,
        crash_id: &str,
    ) -> Result<crate::workbench::IssueExport, ClassifiedError> {
        crate::workbench::issue_export(self.store.as_deref(), project, crash_id).await
    }

    /// Whether a usable issue-tracker integration is configured (provider + repo).
    #[must_use]
    pub fn issue_tracker_configured(&self) -> bool {
        crate::issue_tracker::is_configured()
    }

    /// File a crash as an issue via the configured provider's API.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the tracker is unconfigured, lacks a token,
    /// the crash is unknown, or the API rejects the request.
    pub async fn file_issue(
        &self,
        crash_id: &str,
    ) -> Result<crate::issue_tracker::CreatedIssue, ClassifiedError> {
        crate::workbench::file_issue(self.store.as_deref(), crash_id).await
    }

    /// Verify the issue-tracker URL + token without filing anything.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, tokenless, or the API rejects it.
    pub async fn issue_tracker_test_connection(&self) -> Result<(), ClassifiedError> {
        let cfg = crate::issue_tracker::load_config()?;
        let token = crate::issue_tracker::resolve_token(&cfg)?;
        let client = crate::issue_tracker::IssueTrackerClient::from_config(&cfg, &token)?;
        client.test_connection().await
    }

    /// Saved editable report drafts for the internal workbench.
    pub fn list_report_drafts(
        &self,
    ) -> Result<Vec<crate::report_store::ReportDraft>, ClassifiedError> {
        crate::report_store::list_report_drafts()
    }

    /// Save or update one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid input and storage errors for failed
    /// filesystem writes.
    pub fn save_report_draft(
        &self,
        id: Option<String>,
        title: &str,
        project: &str,
        target: Option<&str>,
        status: &str,
        content: &str,
    ) -> Result<crate::report_store::ReportDraft, ClassifiedError> {
        crate::report_store::save_report_draft(id, title, project, target, status, content)
    }

    /// Delete one editable report draft.
    ///
    /// # Errors
    /// Returns validation errors for invalid ids and storage errors for failed
    /// filesystem deletion.
    pub fn delete_report_draft(&self, id: &str) -> Result<(), ClassifiedError> {
        crate::report_store::delete_report_draft(id)
    }

    /// Late-bind the campaign scheduler so service operations emit scheduler
    /// events (crash found, run terminated) into its event bridge. Called by
    /// `CampaignScheduler::try_start`; the slot is shared across clones of
    /// this container, so one bind covers every surface built from it.
    pub(crate) fn bind_scheduler_events(&self, manager: &Arc<hf_scheduler::SchedulerManager>) {
        if let Ok(mut slot) = self.scheduler_events.lock() {
            *slot = Some(Arc::downgrade(manager));
        }
    }

    /// Emit a scheduler event through the bound campaign scheduler, if any.
    ///
    /// Best-effort by design: a container without a scheduler (one-shot CLI
    /// invocations) or a stopped scheduler simply drops the event, and neither
    /// case may fail the operation that produced it.
    async fn emit_scheduler_event(&self, event_type: &str, payload: serde_json::Value) {
        let manager = self
            .scheduler_events
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().and_then(std::sync::Weak::upgrade));
        if let Some(manager) = manager {
            manager
                .emit_event(hf_scheduler::IncomingEvent {
                    event_type: event_type.to_owned(),
                    payload: Some(payload),
                    timestamp: Utc::now(),
                })
                .await;
        }
    }

    /// Runtime adapter used by service-owned optional subsystems.
    #[must_use]
    #[cfg(any(feature = "automotive-scapy", feature = "semgrep-enrichment"))]
    pub(crate) fn runtime_adapter(&self) -> &Arc<dyn RuntimeAdapter> {
        &self.runtime
    }

    #[cfg(feature = "semgrep-enrichment")]
    pub(crate) fn semgrep_runtime(&self) -> &Arc<dyn RuntimeAdapter> {
        self.runtime_adapter()
    }

    /// A snapshot of the agent turns currently executing.
    fn active_agent_pool(&self) -> AgentPoolSnapshot {
        let labels = self
            .active_agents
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default();
        let instances: Vec<AgentInstanceSnapshot> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| AgentInstanceSnapshot {
                instance_id: format!("turn-{i}"),
                agent_name: label.clone(),
                state: "running".to_owned(),
                elapsed_ms: 0,
                iterations: 0,
                tokens_used: 0,
            })
            .collect();
        AgentPoolSnapshot {
            active_instances: instances.len(),
            available_slots: 0,
            total_instances: instances.len(),
            instances,
        }
    }

    /// Enter a workspace-backed service operation. Both guards are `Send`, so
    /// callers may retain the lease across sandbox, storage, and provider awaits.
    pub(crate) async fn acquire_workspace_operation(
        &self,
    ) -> Result<WorkspaceOperationLease, ClassifiedError> {
        let root = workspace_root();
        self.acquire_workspace_operation_at(&root).await
    }

    pub(crate) async fn acquire_workspace_operation_at(
        &self,
        root: &Path,
    ) -> Result<WorkspaceOperationLease, ClassifiedError> {
        let (root, gate) = workspace_operation_gate(root)?;
        let process_guard = gate.read_owned().await;
        let system_guard = workspace_lock_file(&root)?;
        system_guard
            .try_lock_shared()
            .map_err(|error| workspace_lock_error(error, false))?;
        Ok(WorkspaceOperationLease {
            _process_guard: process_guard,
            _system_guard: system_guard,
        })
    }

    /// Enter a synchronous workspace read without racing whole-root cleanup.
    fn try_acquire_workspace_operation_now() -> Result<WorkspaceOperationLease, ClassifiedError> {
        let root = workspace_root();
        let (root, gate) = workspace_operation_gate(&root)?;
        let process_guard = gate.try_read_owned().map_err(|_| {
            ClassifiedError::Validation(
                "workspace operation cannot start while workspace cleanup is active".to_owned(),
            )
        })?;
        let system_guard = workspace_lock_file(&root)?;
        system_guard
            .try_lock_shared()
            .map_err(|error| workspace_lock_error(error, false))?;
        Ok(WorkspaceOperationLease {
            _process_guard: process_guard,
            _system_guard: system_guard,
        })
    }

    /// Take the whole-workspace cleanup lease without blocking a runtime thread.
    /// Cleanup is an explicit user action, so an overlapping operation is
    /// rejected and can be retried after that operation finishes.
    pub(crate) fn try_acquire_workspace_cleanup(
        root: &Path,
    ) -> Result<WorkspaceCleanupLease, ClassifiedError> {
        let (root, gate) = workspace_operation_gate(root)?;
        let process_guard = gate
            .try_write_owned()
            .map_err(|_| ClassifiedError::Validation(WORKSPACE_CLEANUP_BUSY_MESSAGE.to_owned()))?;
        let system_guard = workspace_lock_file(&root)?;
        system_guard
            .try_lock()
            .map_err(|error| workspace_lock_error(error, true))?;
        Ok(WorkspaceCleanupLease {
            _process_guard: process_guard,
            _system_guard: system_guard,
        })
    }

    #[cfg(test)]
    pub(crate) fn semgrep_test_workspace_cleanup_lease(
        root: &Path,
    ) -> Result<WorkspaceCleanupLease, ClassifiedError> {
        Self::try_acquire_workspace_cleanup(root)
    }

    #[cfg(test)]
    fn clear_workspace_at(&self, root: &Path) -> Result<(), ClassifiedError> {
        self.clear_workspace_at_with_adoption(root, false)
    }

    fn clear_workspace_at_with_adoption(
        &self,
        root: &Path,
        adopt_legacy_default: bool,
    ) -> Result<(), ClassifiedError> {
        let _workspace_cleanup = Self::try_acquire_workspace_cleanup(root)?;
        let active_runs = self
            .active_runs
            .lock()
            .map_err(|_| ClassifiedError::Internal("active-run registry is poisoned".into()))?;
        if !active_runs.is_empty() {
            return Err(ClassifiedError::Validation(
                "workspace cannot be cleared while an active fuzz run exists".to_owned(),
            ));
        }
        match std::fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(ClassifiedError::Validation(format!(
                    "inspect workspace root {}: {error}",
                    root.display()
                )));
            }
        }
        prepare_managed_workspace_root_with_adoption(root, adopt_legacy_default)?;
        clear_managed_workspace_root(root)
    }

    // -- Discovery --------------------------------------------------------

    // -- Harness ----------------------------------------------------------

    /// Resolve a target symbol to its discovered candidate id.
    ///
    /// Unknown symbols are rejected rather than being attached to the nil UUID.
    /// Shared by harness compilation and triage so persisted records key off the
    /// same canonical project and target identity.
    async fn resolve_target_id(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError> {
        let project = canonical_project_root(project)?;
        if let Some(store) = &self.store {
            let targets = store.list_all_targets().await?;
            let project_targets: Vec<TargetCandidate> = targets
                .into_iter()
                .filter(|candidate| {
                    stored_project_matches(&candidate.project_root, &project)
                        && candidate.language == lang
                })
                .collect();
            if let Some(candidate) = select_target_candidate(&project_targets, target)? {
                return Ok(candidate.id);
            }
        }
        let inventory = self.discover(&project, lang).await?;
        select_target_candidate(&inventory.candidates, target)?
            .map(|c| c.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))
    }

    /// Resolve a target without assuming that it is C. Persisted discovery is
    /// authoritative; only missing projects are scanned across supported
    /// languages. This prevents run, triage, and corpus records for Rust/C++
    /// targets from being silently attached to the nil UUID.
    async fn resolve_target_id_any_language(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Uuid, ClassifiedError> {
        self.resolve_target_candidate_any_language(project, target)
            .await?
            .map(|candidate| candidate.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))
    }

    async fn resolve_target_candidate_any_language(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Option<TargetCandidate>, ClassifiedError> {
        let project = canonical_project_root(project)?;
        if let Some(store) = &self.store {
            let targets = store.list_all_targets().await?;
            let project_targets: Vec<TargetCandidate> = targets
                .into_iter()
                .filter(|candidate| stored_project_matches(&candidate.project_root, &project))
                .collect();
            if let Some(candidate) = select_target_candidate(&project_targets, target)? {
                return Ok(Some(candidate.clone()));
            }
        }
        for language in [
            TargetLanguage::C,
            TargetLanguage::Cpp,
            TargetLanguage::Rust,
            TargetLanguage::Go,
            TargetLanguage::Python,
        ] {
            match self.discover(&project, language).await {
                Ok(inventory) => {
                    if let Some(candidate) = select_target_candidate(&inventory.candidates, target)?
                    {
                        return Ok(Some(candidate.clone()));
                    }
                }
                Err(ClassifiedError::Validation(message))
                    if message.contains("not yet supported by the scanner") => {}
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    /// Resolve the persisted record for the binary/source revision currently
    /// active in a target workspace. The explicit id marker is authoritative;
    /// source matching keeps pre-marker workspaces upgrade-compatible.
    async fn active_harness(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let workspace = workspace_dir(project, target);
        let source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "no active harness source for '{target}'; compile the harness first"
            ))
        })?;

        if let Some(id) = read_current_harness_id(&workspace) {
            let harness = store
                .get_harness(id)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?
                .ok_or_else(|| {
                    ClassifiedError::Validation(format!(
                        "active harness record {id} is missing; compile '{target}' again"
                    ))
                })?;
            if harness.engine != engine || harness.source != source {
                return Err(ClassifiedError::Validation(format!(
                    "active harness metadata for '{target}' does not match its binary/source; compile it again"
                )));
            }
            return Ok(harness);
        }

        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let harnesses = store
            .list_harnesses(target_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        harnesses
            .into_iter()
            .filter(|harness| harness.engine == engine && harness.source == source)
            .max_by_key(|harness| match harness.status {
                HarnessStatus::Promoted => 4,
                HarnessStatus::SmokePassed => 3,
                HarnessStatus::Compiled => 2,
                HarnessStatus::Draft => 1,
                HarnessStatus::Failed => 0,
            })
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "no persisted qualification record matches the active {engine:?} harness for '{target}'; compile it again"
                ))
            })
    }

    /// Verify that the active source/executable and the persisted smoke run all
    /// describe the same immutable qualification evidence.
    async fn verify_harness_qualification(
        &self,
        project: &Path,
        target: &str,
        harness: &Harness,
    ) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let (qualification_run_id, expected_source, expected_binary) =
            qualification_evidence(harness)?;
        let workspace = workspace_dir(project, target);
        let source_path = workspace.join("harness.source");
        let binary_path = workspace.join(harness_binary_name(target));
        if !is_regular_file(&source_path) || !is_regular_file(&binary_path) {
            return Err(ClassifiedError::Validation(
                "qualified harness artifacts are missing or are not regular files; compile and smoke again"
                    .to_owned(),
            ));
        }
        if sha256_file(&source_path)? != expected_source {
            return Err(ClassifiedError::Validation(
                "active harness source digest does not match smoke qualification".to_owned(),
            ));
        }
        if sha256_file(&binary_path)? != expected_binary {
            return Err(ClassifiedError::Validation(
                "active harness binary digest does not match smoke qualification".to_owned(),
            ));
        }

        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let run = store
            .get_run(qualification_run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(
                    "smoke qualification run is missing; run smoke qualification again".to_owned(),
                )
            })?;
        let same_harness = run
            .config
            .as_ref()
            .is_some_and(|config| config.harness_id == harness.id);
        if run.status != RunStatus::Done
            || !same_harness
            || run.harness_rev.as_deref() != Some(expected_source)
            || run.binary_rev.as_deref() != Some(expected_binary)
        {
            return Err(ClassifiedError::Validation(
                "smoke qualification evidence does not match the active harness digests".to_owned(),
            ));
        }
        let recorded_source = store
            .run_harness_source(qualification_run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        if recorded_source.as_deref() != Some(harness.source.as_str()) {
            return Err(ClassifiedError::Validation(
                "smoke qualification source evidence does not match the active harness".to_owned(),
            ));
        }
        Ok(())
    }

    /// Reconcile one target's persisted corpus with its exact on-disk state.
    async fn persist_corpus(
        &self,
        target_id: Uuid,
        corpus: &hf_core::corpus::Corpus,
    ) -> Result<(), ClassifiedError> {
        let Some(store) = &self.store else {
            return Ok(());
        };
        store
            .replace_corpus_entries(target_id, &corpus.entries)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))
    }

    /// Draft the harness source for a candidate: LLM-authored when a provider is
    /// configured, otherwise the heuristic template. Never fails -- an LLM error
    /// degrades to the heuristic draft so generation can proceed.
    async fn draft_harness_source(
        &self,
        project: &Path,
        candidate: &TargetCandidate,
        engine: EngineKind,
    ) -> String {
        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            let related = crate::knowledge::harness_related_context(project, candidate);
            match hf_harness::draft_with_context(candidate, engine, &related, Box::new(provider))
                .await
            {
                Ok(draft) => return draft.source,
                Err(e) => tracing::warn!(
                    "LLM harness draft for '{}' failed ({e}); using heuristic draft",
                    candidate.symbol
                ),
            }
        }
        heuristic_draft(candidate, engine).source
    }

    /// Compile `initial_source` in the sandbox, and on a compile failure feed the
    /// diagnostics back to the LLM for up to `max_repairs` corrective passes.
    /// Shared by harness generation and coverage-guided refinement.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Harness` if the harness still fails to build
    /// after `max_repairs` attempts, or an infrastructure error from the sandbox.
    async fn compile_source_with_repair(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        lang: TargetLanguage,
        workspace: &Path,
        initial_source: String,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let target = &candidate.symbol;
        let mut source = initial_source;
        let mut repairs_used = 0usize;
        let mut last_diagnostics = String::new();

        loop {
            let mut build_cmd =
                hf_harness::build_command(engine, lang, &harness_binary_name(target));
            build_cmd.output = PathBuf::from(harness_binary_name(target));
            let harness = Harness {
                id: Uuid::new_v4(),
                target_id: candidate.id,
                engine,
                source: source.clone(),
                language: lang,
                build_cmd,
                sanitizer: Sanitizer::Address,
                status: HarnessStatus::Draft,
                smoke_run: None,
            };
            match hf_harness::try_compile(harness, self.runtime.as_ref(), workspace).await? {
                hf_harness::CompileResult::Ok(compiled) => {
                    if let Some(store) = &self.store {
                        store
                            .upsert_harness(&compiled)
                            .await
                            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
                    }
                    write_current_harness_source(workspace, &compiled.source)?;
                    // Point `harness.active` at the freshly-compiled harness, as
                    // `harness_compile` does. Without this, a repair/refine that
                    // rewrites the source leaves the marker on the previous id, so
                    // `active_harness` later reads a stale id whose source no
                    // longer matches and hard-errors ("compile it again") even
                    // though the refined harness built cleanly.
                    write_current_harness_id(workspace, compiled.id)?;
                    let binary_name = compiled
                        .build_cmd
                        .output
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(target)
                        .to_string();
                    return Ok(HarnessGenOutcome {
                        status: compiled.status,
                        binary_name,
                        workspace: workspace.to_path_buf(),
                        repairs_used,
                    });
                }
                hf_harness::CompileResult::Failed(failure) => {
                    last_diagnostics = failure.diagnostics();
                    if repairs_used >= max_repairs {
                        break;
                    }
                    let Some(pool) = self.provider_pool() else {
                        // No LLM to repair with; the first failure is terminal.
                        break;
                    };
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "harness_repair");
                    match hf_harness::repair(
                        candidate,
                        engine,
                        &source,
                        &last_diagnostics,
                        Box::new(provider),
                    )
                    .await
                    {
                        Ok(draft) => {
                            source = draft.source;
                            repairs_used += 1;
                        }
                        Err(e) => {
                            tracing::warn!("harness repair for '{target}' failed: {e}");
                            break;
                        }
                    }
                }
            }
        }

        let diag: String = last_diagnostics.chars().take(600).collect();
        Err(ClassifiedError::Harness(format!(
            "harness for '{target}' failed to build after {repairs_used} repair attempt(s): {diag}"
        )))
    }

    /// Draft a targeted refined harness in response to a coverage plateau, as a
    /// proposal only. Returns `None` (no proposal) when refinement is not
    /// applicable: no LLM provider, no uncovered frontier (non-C target or full
    /// coverage), or the compile action is not already policy-allowed (so we
    /// never block a headless campaign on an approval prompt, nor compile
    /// without an Allow decision). The refined harness stays `Compiled`; the
    /// existing promotion gate keeps it from being auto-run.
    async fn propose_refine_on_plateau(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Option<RefineProposal> {
        self.provider_pool()?;
        if !matches!(
            self.guardrails.policy().evaluate(&Action::CompileHarness),
            Decision::Allow
        ) {
            return None;
        }
        // Populate the frontier cache once; `harness_refine` reuses it (same
        // signature) rather than re-running the expensive coverage pipeline.
        let frontier_locations = self.coverage_uncovered(project, target).await.len();
        if frontier_locations == 0 {
            return None;
        }
        // Two corrective passes is enough for a targeted re-draft; keep it small
        // so a plateau does not turn into a long repair loop.
        match self.harness_refine(project, target, engine, lang, 2).await {
            Ok(outcome) => Some(RefineProposal {
                frontier_locations,
                compiled: outcome.status == HarnessStatus::Compiled,
                note: format!(
                    "coverage plateaued; proposed a refined harness for {frontier_locations} \
                     uncovered location(s), left Compiled for human review"
                ),
            }),
            Err(error) => {
                tracing::warn!(%error, "coverage-plateau refine proposal failed");
                Some(RefineProposal {
                    frontier_locations,
                    compiled: false,
                    note: format!("coverage plateaued; refine proposal failed: {error}"),
                })
            }
        }
    }

    // -- Seeds ------------------------------------------------------------

    // -- Run --------------------------------------------------------------

    /// Run a fuzzer to termination and notify event-driven schedules about the
    /// outcome: `run.completed` on success (cancellation included), `run.failed`
    /// when a started run terminates with a failure. Errors before the run
    /// becomes durable are rejections, not run failures, and emit nothing.
    async fn run_fuzzer_with_started(
        &self,
        project: &Path,
        target: &str,
        resolved: crate::config::ResolvedFuzzingRun,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
        on_started: &(dyn Fn(Uuid) + Send + Sync),
        replay: Option<ReplayProvenance>,
    ) -> Result<RunSummary, ClassifiedError> {
        let engine = resolved.engine;
        // Capture the run id once the run is durable so a failure event can
        // name it.
        let started_run = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = std::sync::Arc::clone(&started_run);
        let tracked_started = move |run_id: Uuid| {
            if let Ok(mut slot) = captured.lock() {
                *slot = Some(run_id);
            }
            on_started(run_id);
        };
        let result = self
            .run_fuzzer_with_started_inner(
                project,
                target,
                resolved,
                on_progress,
                &tracked_started,
                replay,
            )
            .await;
        match &result {
            Ok(summary) => {
                self.emit_scheduler_event(
                    crate::scheduler::EVENT_RUN_COMPLETED,
                    serde_json::json!({
                        "project": project.display().to_string(),
                        "target": target,
                        "run_id": summary.run_id.to_string(),
                        "engine": engine.as_str(),
                        "edges": summary.edges,
                        "execs": summary.execs,
                        "crashes": summary.crashes,
                        "termination": summary.termination,
                    }),
                )
                .await;
            }
            Err(error) => {
                let run_id = started_run.lock().ok().and_then(|slot| *slot);
                if let Some(run_id) = run_id {
                    self.emit_scheduler_event(
                        crate::scheduler::EVENT_RUN_FAILED,
                        serde_json::json!({
                            "project": project.display().to_string(),
                            "target": target,
                            "run_id": run_id.to_string(),
                            "engine": engine.as_str(),
                            "error": error.to_string(),
                        }),
                    )
                    .await;
                }
            }
        }
        result
    }

    async fn run_fuzzer_with_started_inner(
        &self,
        project: &Path,
        target: &str,
        resolved: crate::config::ResolvedFuzzingRun,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
        on_started: &(dyn Fn(Uuid) + Send + Sync),
        replay: Option<ReplayProvenance>,
    ) -> Result<RunSummary, ClassifiedError> {
        const MAX_RAW_COVERAGE_SAMPLES: usize = 10_000;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();

        let engine = resolved.engine;
        let duration_secs = resolved.duration_secs;

        let qualified = self.active_harness(project, target, engine).await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(format!(
                "active harness '{target}' is {:?}; run smoke qualification and explicitly promote it before starting a full campaign",
                qualified.status
            )));
        }
        self.verify_harness_qualification(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: format!("{engine:?}"),
                duration_secs,
            },
            "run_fuzzer",
            Some(project),
        )
        .await?;
        ensure_run_journal_durable(&self.run_journal)?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = ensure_workspace_directory(&workspace, Path::new("corpus"))?;

        let bin = harness_binary_name(target);
        let binary = workspace.join(&bin);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{bin}' not found -- compile the harness first."
            )));
        }

        // Build a dictionary from the target sources (statically extracted, then
        // LLM-augmented) and point the engine at it -- one of the cheapest
        // coverage multipliers; absent literals just yield no flag.
        let extra_args = self
            .build_run_dictionary_args(project, target, &workspace, engine)
            .await;

        let mut run_cfg = FuzzRunConfig {
            // Link the run to the target's compiled harness so the target-scoped
            // workbench dashboard can attribute it. A throwaway id here would
            // leave every run unattributable (dashboard shows zero runs).
            harness_id: qualified.id,
            engine,
            duration: Some(std::time::Duration::from_secs(duration_secs)),
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            seed_corpus: Some(corpus_dir.clone()),
            sanitizer: hf_core::target::Sanitizer::Address,
            env: Vec::new(),
            extra_args,
            seed: None,
            replay_of: None,
        };
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("fuzz runs require the persistent service store".to_owned())
        })?;
        let mut run_record = RunRecord::new(
            project.to_string_lossy().to_string(),
            engine,
            None,
            Utc::now(),
        );
        // Every run pins its RNG seed in the persisted config. A replay
        // re-executes with the original run's seed and links back to it; a
        // fresh run derives its seed deterministically from its own id, so
        // every run is reproducible by default.
        match replay {
            Some(provenance) => {
                run_cfg.seed = Some(provenance.seed);
                run_cfg.replay_of = Some(provenance.original_run_id);
            }
            None => run_cfg.seed = Some(hf_engine::seed::derive_run_seed(run_record.id)),
        }
        run_record.config = Some(run_cfg.clone());
        let sandbox_image = resolve_run_sandbox_image(self.runtime.as_ref()).await?;
        let context = run_context_digests(&workspace, sandbox_image.sha256())?;
        retain_run_context(&mut run_record, context);
        let artifacts = stage_run_artifacts(&workspace, run_record.id, &qualified.source, &binary)?;
        if let Err(error) = verify_staged_qualification(&qualified, &artifacts) {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(error);
        }
        if let Err(error) = verify_run_artifacts(&artifacts) {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(error);
        }
        let sandbox = run_sandbox_options(&artifacts, Some(sandbox_image.reference().to_owned()));
        run_record.status = RunStatus::Running;
        run_record.harness_rev = Some(artifacts.source_sha256.clone());
        run_record.binary_rev = Some(artifacts.binary_sha256.clone());
        run_record.evidence_dir = Some(artifacts.output_relative.to_string_lossy().into_owned());
        let run_id = run_record.id;
        if let Err(error) = store.insert_run(&run_record).await {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        self.run_journal.open_run(run_id, project, target, engine);
        if let Err(error) = ensure_run_journal_durable(&self.run_journal) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            return Err(error);
        }
        let mut persisted_run = PersistedRunGuard::new(
            Arc::clone(store),
            Some(Arc::clone(&self.run_journal)),
            run_id,
        );
        if let Err(error) = store
            .set_run_harness_source(run_record.id, &qualified.source)
            .await
        {
            let failure_recorded = store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            if failure_recorded.is_ok() {
                self.run_journal.close_run(run_id);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }

        // Register a cancellation token so `cancel_run(run_id)` can stop this
        // run cooperatively. `ActiveRunGuard` removes it again when this scope
        // ends -- crucially, even if the `run_fuzzer` future is dropped/aborted
        // (e.g. wrapped in a `timeout`) rather than returning normally. A plain
        // post-await removal would leak the entry on abort, leaving a phantom
        // run that `active_run_ids` reports and `cancel_run` can never clear.
        let cancel = CancellationToken::new();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };
        // The run is durable and cancellable at this point. Non-blocking
        // presentation transports may now return the exact UUID; no engine
        // process has been launched yet.
        on_started(run_id);

        let runner = hf_engine::runner::EngineRunner::new();
        // Watch edge readings for stagnation while forwarding every event.
        let feedback = CoverageFeedback::new(
            run_id,
            crate::config::coverage_stagnation_policy(),
            on_progress,
        );
        // Accumulate an intra-run coverage/throughput time series live, so the
        // run's coverage curve can be charted later. Each fuzzer stats line emits
        // an EdgesCovered then an ExecsPerSec event; pair them and stamp the
        // elapsed time.
        let series: std::sync::Arc<std::sync::Mutex<Vec<(f64, u64, f64)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_edges = std::sync::atomic::AtomicU64::new(0);
        let run_started = std::time::Instant::now();
        let series_w = std::sync::Arc::clone(&series);
        let watched = |p: FuzzProgress| {
            use std::sync::atomic::Ordering::Relaxed;
            match &p {
                FuzzProgress::EdgesCovered(v) => {
                    feedback.on_edges(*v);
                    last_edges.store(*v, Relaxed);
                }
                FuzzProgress::ExecsPerSec(v) => {
                    let t = run_started.elapsed().as_secs_f64();
                    let e = last_edges.load(Relaxed);
                    if let Ok(mut s) = series_w.lock() {
                        if s.len() < MAX_RAW_COVERAGE_SAMPLES {
                            s.push((t, e, *v));
                        } else if let Some(last) = s.last_mut() {
                            *last = (t, e, *v);
                        }
                    }
                }
                _ => {}
            }
            on_progress(p);
        };
        let output_monitor_stop = CancellationToken::new();
        let output_budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_monitor = tokio::spawn(monitor_run_output(
            artifacts.output_host.clone(),
            artifacts.corpus_host.clone(),
            64 * 1024 * 1024,
            cancel.clone(),
            output_monitor_stop.clone(),
            Arc::clone(&output_budget_exceeded),
        ));
        // Stream progress live: `on_progress` fires for each output line and
        // stat as the fuzzer runs, not post-hoc.
        let run_result = runner
            .run_streaming_opts(
                engine,
                &run_cfg,
                &artifacts.binary_container,
                &artifacts.corpus_container,
                &artifacts.output_container,
                self.runtime.as_ref(),
                &workspace,
                &sandbox,
                &cancel,
                &watched,
            )
            .await;
        output_monitor_stop.cancel();
        let _ = output_monitor.await;
        if !run_artifacts_within_budget(&artifacts, 64 * 1024 * 1024).await {
            output_budget_exceeded.store(true, std::sync::atomic::Ordering::Release);
        }
        if output_budget_exceeded.load(std::sync::atomic::Ordering::Acquire) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
            self.run_journal.close_run(run_id);
            return Err(ClassifiedError::Sandbox(
                "fuzz run corpus/output exceeded its retained-evidence budget".to_owned(),
            ));
        }
        let result = match run_result {
            Ok(result) => result,
            Err(error) => {
                let status_update = store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await;
                status_update.map_err(|e| ClassifiedError::Storage(e.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        let was_cancelled = result.termination == hf_core::runtime::CommandTermination::Cancelled;

        // Keep the retained corpus immutable throughout execution. Engines
        // write only to this run's disposable snapshot/output; after the
        // sandbox exits, bounded corpus APIs preflight those discoveries and
        // atomically merge unique inputs into the live corpus.
        let retained = match merge_run_discoveries(engine, &artifacts, &corpus_dir).await {
            Ok(corpus) => corpus,
            Err(error) => {
                store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await
                    .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        // persist_corpus derives the target from the explicit `qualified.target_id`
        // argument and `retained.entries`, never `retained.target_id`, so no
        // identity copy is needed here.
        if let Err(error) = self.persist_corpus(qualified.target_id, &retained).await {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            self.run_journal.close_run(run_id);
            return Err(error);
        }

        // Summarize from the parsed events. Live streaming already forwarded
        // them to `on_progress`, so do not re-emit here.
        let metrics = match terminal_run_metrics(engine, &artifacts, &result).await {
            Ok(metrics) => metrics,
            Err(error) => {
                store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await
                    .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        if let Err(error) =
            persist_terminal_run_evidence(store, run_record.id, &metrics, &series).await
        {
            let _ = store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            self.run_journal.close_run(run_id);
            return Err(error);
        }
        let TerminalRunMetrics {
            edges,
            execs,
            crashes,
        } = metrics;
        // A run becomes terminal only after its summary evidence is durable.
        // This prevents a `Done` record whose stats or coverage curve were lost.
        let status = if was_cancelled {
            RunStatus::Cancelled
        } else {
            RunStatus::Done
        };
        let status_update = store
            .set_run_status(run_record.id, status, Some(Utc::now()))
            .await;
        status_update.map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        if let Err(error) = close_run_journal(&self.run_journal, run_id) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            persisted_run.disarm();
            return Err(error);
        }
        persisted_run.disarm();
        // Auto-revert policy: if this run's harness revision regressed coverage
        // past the threshold versus the latest comparable run for this target,
        // restore that last-good revision (HITL-gated recompile). Skipped for
        // cancelled runs, whose truncated coverage is not a fair comparison.
        let auto_revert = if was_cancelled {
            None
        } else {
            self.maybe_auto_revert(
                project,
                target,
                run_id,
                edges,
                run_record.harness_rev.as_deref(),
            )
            .await
        };
        Ok(RunSummary {
            run_id,
            edges,
            execs,
            crashes,
            termination: result.termination,
            stagnation: feedback.proposal(),
            auto_revert,
        })
    }

    // -- Triage -----------------------------------------------------------

    async fn triage_run_record(
        &self,
        project: &Path,
        target: &str,
        run: RunRecord,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        const TRIAGE_BUDGET: std::time::Duration = std::time::Duration::from_mins(5);

        tokio::time::timeout(
            TRIAGE_BUDGET,
            self.triage_run_record_inner(project, target, run),
        )
        .await
        .map_err(|_| {
            ClassifiedError::Sandbox(format!(
                "triage exceeded its {} second end-to-end budget",
                TRIAGE_BUDGET.as_secs()
            ))
        })?
    }

    async fn triage_run_record_inner(
        &self,
        project: &Path,
        target: &str,
        run: RunRecord,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        /// Cap on LLM bug-report drafts per triage pass: a run may surface many
        /// distinct bugs, and one report each would fan out into hundreds of LLM
        /// calls. Crashes beyond the cap are still ingested and persisted, just
        /// without a drafted report.
        const MAX_BUG_REPORT_DRAFTS: usize = 20;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        self.authorize_recorded(Action::Triage, "triage_run", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let run_id = run.id;
        let engine = run.engine;
        let out_dir = run_output_dir(&workspace, &run)?;
        let run_binary = run_binary_path(&workspace, &run, target)?;
        let source_context = if run.harness_rev.is_some() {
            let source = run_source_path(&workspace, &run)?;
            std::fs::read_to_string(&source).ok()
        } else {
            None
        };

        // Prefer CASR: it reproduces each crash, classifies exploitability and
        // severity, and clusters/deduplicates -- all in the sandbox. Fall back to
        // the built-in reproduce/classify/dedup path when CASR is unavailable (no
        // harness binary, native runtime without casr, or the tool errored). The
        // captured sanitizer traces (`logs`) feed bug-report drafting; CASR-path
        // crashes carry their summary instead.
        let (mut deduped, mut logs): (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ) = match self
            .run_casr_triage(&workspace, &out_dir, &run_binary, engine, run_id, target_id)
            .await?
        {
            Some(crashes) if !crashes.is_empty() => (crashes, std::collections::HashMap::new()),
            _ => {
                self.legacy_triage(&out_dir, &workspace, &run_binary, engine, run_id, target_id)
                    .await?
            }
        };

        // Give each crash a deterministic id so persisting is idempotent: a
        // second triage of the same run replaces these rows instead of adding
        // duplicates (the report lists every persisted crash for the run).
        for crash in &mut deduped {
            crash.id = deterministic_crash_id(run_id, &crash.stack_signature, &crash.input_path);
        }

        // Persist the completed classification NOW, before the optional (and
        // slower) minimization and LLM bug-report phases. Those phases run under
        // the same end-to-end triage budget; without this early write, a run
        // with many crashes or a slow provider would time out mid-enrichment and
        // discard all classification, and because ids are deterministic the
        // re-run would time out identically -- triage could never persist. The
        // final upsert below re-writes the same rows with the enriched fields.
        if let Some(store) = &self.store {
            store
                .upsert_crashes(&deduped)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        }

        // Native minimizers execute against the immutable run-owned harness and
        // original crash input. Legacy records without binary digest evidence
        // remain triageable but cannot claim a verified minimized artifact.
        if run.binary_rev.is_some() {
            self.minimize_triaged_crashes(
                &workspace,
                run_id,
                engine,
                &run_binary,
                &mut deduped,
                &mut logs,
            )
            .await;
        }

        // Draft an LLM bug report for each unique crash when a provider is
        // configured, using the captured sanitizer trace (capped, see above).
        if let Some(pool) = self.provider_pool() {
            let unique = deduped.len();
            for crash in deduped.iter_mut().take(MAX_BUG_REPORT_DRAFTS) {
                let bridge = LlmProviderBridge::new(Arc::clone(&pool))
                    .with_diagnostics(Arc::clone(&self.diagnostics), "triage_report");
                let log = logs
                    .get(&crash.input_path)
                    .filter(|l| !l.trim().is_empty())
                    .cloned()
                    .unwrap_or_else(|| crash.summary.clone());
                // Augment the report prompt with related project context when
                // this project has been indexed; empty on any failure, which
                // renders the un-augmented prompt.
                let related =
                    crate::knowledge::triage_related_context(project, target, &crash.summary);
                let related_section = hf_prompt::render_related_context_section(&related);
                match hf_crash::draft_report_with_context(
                    crash,
                    &log,
                    source_context.as_deref(),
                    if related_section.is_empty() {
                        None
                    } else {
                        Some(related_section.as_str())
                    },
                    Box::new(bridge),
                )
                .await
                {
                    Ok(report) => crash.bug_report = Some(report),
                    Err(e) => tracing::warn!("bug report drafting failed for {}: {e}", crash.id),
                }
            }
            if unique > MAX_BUG_REPORT_DRAFTS {
                tracing::info!(
                    "capped bug-report drafting at {MAX_BUG_REPORT_DRAFTS} of {unique} unique crashes"
                );
            }
        }

        // Re-check immutable evidence after untrusted triage execution before
        // persisting any derived classification.
        let _ = run_binary_path(&workspace, &run, target)?;
        if run.harness_rev.is_some() {
            let _ = run_source_path(&workspace, &run)?;
        }
        if let Some(store) = &self.store {
            store
                .upsert_crashes(&deduped)
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        }
        // Triage completed with classified crashes: fire event-driven
        // schedules listening for `crash.found`.
        if !deduped.is_empty() {
            self.emit_scheduler_event(
                crate::scheduler::EVENT_CRASH_FOUND,
                serde_json::json!({
                    "project": project.display().to_string(),
                    "target": target,
                    "run_id": run_id.to_string(),
                    "crashes": deduped.len(),
                }),
            )
            .await;
        }
        Ok(deduped)
    }

    async fn minimize_triaged_crashes(
        &self,
        workspace: &Path,
        run_id: Uuid,
        engine: EngineKind,
        binary: &Path,
        crashes: &mut [hf_core::crash::Crash],
        logs: &mut std::collections::HashMap<PathBuf, String>,
    ) {
        use crate::crash_minimization::{prepare, PreparedMinimization, MAX_CRASH_MINIMIZATIONS};
        let Ok(_workspace_operation) = self.acquire_workspace_operation().await else {
            tracing::warn!("crash minimization skipped because the workspace is unavailable");
            return;
        };

        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 120,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        for crash in crashes.iter_mut().take(MAX_CRASH_MINIMIZATIONS) {
            let original = crash.input_path.clone();
            let prepared = match prepare(workspace, run_id, engine, binary, &original, crash.id) {
                Ok(prepared) => prepared,
                Err(error) => {
                    tracing::warn!(
                        crash_id = %crash.id,
                        "crash minimization staging failed: {error}"
                    );
                    continue;
                }
            };
            let minimized = match prepared {
                PreparedMinimization::Unsupported => break,
                PreparedMinimization::Complete(path) => Some(path),
                PreparedMinimization::Run(run) => {
                    let result = self
                        .runtime
                        .run_command_opts(&run.command, workspace, &limits, &run.sandbox)
                        .await;
                    match result {
                        Ok(result)
                            if result.termination
                                == hf_core::runtime::CommandTermination::Completed
                                && result.exit_code == 0 =>
                        {
                            match run.publish() {
                                Ok(path) => Some(path),
                                Err(error) => {
                                    tracing::warn!(
                                        crash_id = %crash.id,
                                        "crash minimizer output was rejected: {error}"
                                    );
                                    None
                                }
                            }
                        }
                        Ok(result) => {
                            tracing::warn!(
                                crash_id = %crash.id,
                                termination = ?result.termination,
                                exit_code = result.exit_code,
                                "crash minimizer did not complete successfully"
                            );
                            None
                        }
                        Err(error) => {
                            tracing::warn!(
                                crash_id = %crash.id,
                                "crash minimizer failed: {error}"
                            );
                            None
                        }
                    }
                }
            };
            if let Some(path) = minimized {
                if let Some(log) = logs.get(&original).cloned() {
                    logs.insert(path.clone(), log);
                }
                crash.input_path = path;
                crash.minimized = true;
            }
        }
    }

    /// Fetch the raw `llvm-cov export` JSON for a target, cached per target by
    /// the corpus+harness signature. The covered-set, summary, and frontier
    /// accessors all parse from this one cached export, so the expensive (~180s)
    /// coverage pipeline runs at most once per signature rather than once per
    /// accessor. `None` when no C harness was built or the pipeline did not
    /// complete cleanly (a transient failure is not cached, so it retries).
    async fn coverage_export_json_cached(&self, project: &Path, target: &str) -> Option<String> {
        let _workspace_operation = self.acquire_workspace_operation().await.ok()?;
        let workspace = workspace_dir(project, target);
        if !workspace.join("harness.c").exists() {
            return None;
        }
        let cache_key = format!("{}::{target}", project.display());
        let signature = coverage_signature(&workspace);
        if let Some((cached_sig, cached)) = export_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&cache_key).cloned())
        {
            if cached_sig == signature {
                return Some(cached);
            }
        }
        let json = self.run_coverage_export(&workspace).await?;
        if let Ok(mut map) = export_cache().lock() {
            map.insert(cache_key, (signature, json.clone()));
        }
        Some(json)
    }

    /// Run the C source-coverage pipeline (build with instrumentation -> replay
    /// the corpus -> `llvm-cov export`) in the sandbox for an already-resolved
    /// `workspace`, returning the raw export JSON. `None` when the pipeline does
    /// not complete cleanly (so the caller does not cache a transient failure).
    /// The caller holds the workspace-operation guard and has verified a harness
    /// exists. Prefer [`Self::coverage_export_json_cached`], which adds the
    /// guard, harness check, and per-signature cache.
    async fn run_coverage_export(&self, workspace: &Path) -> Option<String> {
        let pipeline = "clang -g -O1 -fsanitize=fuzzer -fprofile-instr-generate \
             -fcoverage-mapping *.c -o fuzz_cov 2>/dev/null \
             && LLVM_PROFILE_FILE=cov.profraw ./fuzz_cov -runs=0 corpus 2>/dev/null; \
             llvm-profdata merge -sparse cov.profraw -o cov.profdata 2>/dev/null \
             && llvm-cov export ./fuzz_cov -instr-profile=cov.profdata 2>/dev/null";
        let cmd = vec!["sh".to_owned(), "-c".to_owned(), pipeline.to_owned()];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 180,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        match self.runtime.run_command(&cmd, workspace, &limits).await {
            Ok(result)
                if result.termination == hf_core::runtime::CommandTermination::Completed
                    && result.exit_code == 0 =>
            {
                Some(result.stdout)
            }
            Ok(result) => {
                tracing::warn!(
                    termination = ?result.termination,
                    exit_code = result.exit_code,
                    "coverage collection did not complete cleanly; not caching so it retries"
                );
                None
            }
            Err(e) => {
                tracing::warn!("coverage collection failed: {e}");
                None
            }
        }
    }

    /// Build the engine dictionary flags for a run: extract the static
    /// dictionary from the target sources, augment it with LLM-proposed tokens,
    /// and return the engine-specific `-dict`/`-x`/`-w` args (empty when no
    /// dictionary was built).
    async fn build_run_dictionary_args(
        &self,
        project: &Path,
        target: &str,
        workspace: &Path,
        engine: EngineKind,
    ) -> Vec<String> {
        let dict_name = "fuzzer.dict";
        let Some(dict_path) = build_workspace_dictionary(workspace, dict_name) else {
            return Vec::new();
        };
        // Best-effort, provider-gated, cached per source version; a failure
        // leaves the static dictionary in place.
        self.augment_dictionary_llm(project, target, workspace, &dict_path)
            .await;
        hf_engine::dict::dict_run_args(engine, &format!("/work/{dict_name}"))
    }

    /// Merge LLM-proposed dictionary tokens into the static dictionary at
    /// `dict_path`: format keywords / magic sequences the lexical scan may miss.
    /// No-op without a provider or source. The LLM tokens are cached per target
    /// by the static dictionary's hash, so a repeated run on unchanged sources
    /// makes no LLM call; failures leave the static dictionary intact.
    async fn augment_dictionary_llm(
        &self,
        project: &Path,
        target: &str,
        workspace: &Path,
        dict_path: &Path,
    ) {
        use hf_core::provider::{ChatRequest, LlmProvider as _};
        use hf_core::types::Message;
        use std::hash::{Hash as _, Hasher as _};

        let Some(pool) = self.provider_pool() else {
            return;
        };
        let Ok(static_text) = std::fs::read_to_string(dict_path) else {
            return;
        };
        let mut tokens = hf_engine::dict::parse_dict(&static_text);
        let key = format!("{}::{target}", project.display());
        let signature = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            static_text.hash(&mut hasher);
            hasher.finish()
        };
        let cached = dict_llm_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&key).cloned())
            .filter(|(cached_sig, _)| *cached_sig == signature);
        let llm_tokens = if let Some((_, cached_tokens)) = cached {
            cached_tokens
        } else {
            let excerpt = read_dictionary_source_excerpt(workspace, 8192);
            if excerpt.trim().is_empty() {
                return;
            }
            let prompt = hf_prompt::render_dictionary_prompt(target, &excerpt);
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "dict_gen");
            let req = ChatRequest::from_messages(vec![Message::user(prompt)]);
            let fresh = match provider.chat_completion(&req).await {
                Ok(resp) => hf_engine::dict::parse_dict(resp.text()),
                Err(e) => {
                    tracing::warn!("LLM dictionary generation for '{target}' failed: {e}");
                    return;
                }
            };
            if let Ok(mut map) = dict_llm_cache().lock() {
                map.insert(key, (signature, fresh.clone()));
            }
            fresh
        };
        if llm_tokens.is_empty() {
            return;
        }
        let mut seen: std::collections::HashSet<Vec<u8>> = tokens.iter().cloned().collect();
        let mut added = 0usize;
        for token in llm_tokens {
            if seen.insert(token.clone()) {
                tokens.push(token);
                added += 1;
            }
        }
        if added == 0 {
            return;
        }
        if let Err(e) = std::fs::write(dict_path, hf_engine::dict::render_dict(&tokens)) {
            tracing::warn!("failed to write augmented dictionary: {e}");
        } else {
            tracing::info!("merged {added} LLM-proposed dictionary token(s) for '{target}'");
        }
    }

    /// Assemble a self-contained reproduction bundle for `crash` into `dest`:
    /// the current harness source, the crash input bytes, and a `REPRODUCE.md`
    /// manifest carrying the exact build and run steps. A maintainer can then
    /// reproduce the finding with only the target toolchain -- no `oxfuzz`
    /// install (VISION reproducibility). Returns the bundle directory.
    ///
    /// # Errors
    /// Returns a validation error if the harness or crash input is missing (or
    /// the input is not a regular file -- symlinks are refused, never followed),
    /// or an internal error if the bundle cannot be written.
    pub async fn export_repro_bundle(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        crash: &hf_core::crash::Crash,
        dest: &Path,
    ) -> Result<PathBuf, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let workspace = workspace_dir(&project_root, target);
        let harness_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!("no harness source for '{target}' to bundle"))
        })?;
        // Copy the crash input by value; refuse a symlinked input rather than
        // following it out of the workspace into an unrelated file.
        if !is_regular_file(&crash.input_path) {
            return Err(ClassifiedError::Validation(format!(
                "crash input {} is missing or not a regular file",
                crash.input_path.display()
            )));
        }
        let input = std::fs::read(&crash.input_path).map_err(|e| {
            ClassifiedError::Validation(format!(
                "read crash input {}: {e}",
                crash.input_path.display()
            ))
        })?;
        let harness_filename = lang.harness_filename().to_owned();
        let build = hf_harness::build_command(engine, lang, "fuzz_bin");
        let build_command = format!(
            "{} {} {} -o {}",
            build.compiler,
            build.args.join(" "),
            harness_filename,
            build.output.display()
        );
        let manifest = crate::repro::ReproManifest {
            project: project_root.to_string_lossy().into_owned(),
            target: target.to_owned(),
            language: format!("{lang:?}"),
            engine: engine.as_str().to_owned(),
            // Harnesses build with ASan by default (see `build_command`).
            sanitizer: "address".to_owned(),
            build_command,
            harness_filename,
            input_filename: "crash_input".to_owned(),
            binary_name: "fuzz_bin".to_owned(),
            crash_kind: format!("{:?}", crash.kind),
            crash_summary: crash.summary.clone(),
            stack_signature: crash.stack_signature.clone(),
            minimized: crash.minimized,
        };
        crate::repro::write_repro_bundle(dest, &manifest, &harness_source, &input)
            .map_err(|e| ClassifiedError::Internal(format!("write repro bundle: {e}")))
    }

    /// Export a reproduction bundle for a crash from the target's most recent
    /// run. Selects the crash whose id starts with `crash_id` when given, else
    /// the first crash of the run. Returns the bundle directory.
    ///
    /// # Errors
    /// Returns a validation error when the latest run has no crashes, no crash
    /// matches `crash_id`, or the harness/input cannot be read; an internal
    /// error when the bundle cannot be written.
    pub async fn export_repro_bundle_for_latest(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        crash_id: Option<&str>,
        dest: &Path,
    ) -> Result<PathBuf, ClassifiedError> {
        let crashes = self.crashes_for_latest_run(project, Some(target)).await?;
        let crash = match crash_id {
            Some(id) => crashes
                .iter()
                .find(|crash| crash.id.to_string().starts_with(id))
                .ok_or_else(|| {
                    ClassifiedError::Validation(format!(
                        "no crash matching id '{id}' in the latest run for '{target}'"
                    ))
                })?,
            None => crashes.first().ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "the latest run for '{target}' has no crashes to bundle"
                ))
            })?,
        };
        self.export_repro_bundle(project, target, engine, lang, crash, dest)
            .await
    }

    /// Persisted crashes for the most recent matching run (empty without a
    /// store or matching runs). `target = None` selects project-wide history.
    async fn crashes_for_latest_run(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        let Some(store) = &self.store else {
            return Ok(Vec::new());
        };
        let run = self.latest_run_record(project, target).await?;
        Ok(match run {
            // Guard against any pre-existing duplicate rows (e.g. crashes
            // persisted before the deterministic-id fix): collapse by signature.
            Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await?),
            None => Vec::new(),
        })
    }

    /// Export the latest run's crashes as a SARIF 2.1.0 document (string),
    /// for `GitHub` code scanning / security dashboards. Empty `results` when
    /// there are no crashes.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected serialization failure.
    pub async fn export_sarif(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let crashes = self.crashes_for_latest_run(project, Some(target)).await?;
        let sarif =
            crate::sarif::crashes_to_sarif(&crashes, env!("CARGO_PKG_VERSION"), &project_root);
        serde_json::to_string_pretty(&sarif)
            .map_err(|e| ClassifiedError::Internal(format!("serialize sarif: {e}")))
    }

    /// Whether a usable `DefectDojo` config is present (for the settings UI to show
    /// a configured / not-configured state without attempting a push).
    #[must_use]
    pub fn defectdojo_configured(&self) -> bool {
        crate::defectdojo::is_configured()
    }

    /// The configured `DefectDojo` base URL (no trailing slash), or `None` when it
    /// is unconfigured / still the placeholder. Lets presentation layers open the
    /// web UI without hard-coding or re-reading the config themselves.
    #[must_use]
    pub fn defectdojo_url(&self) -> Option<String> {
        crate::defectdojo::load_config()
            .ok()
            .map(|c| c.url.trim_end_matches('/').to_owned())
    }

    /// Verify the configured `DefectDojo` URL + token by calling its API.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, the token is missing, or the
    /// server is unreachable / rejects auth.
    pub async fn defectdojo_test_connection(&self) -> Result<(), ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        client.test_connection().await
    }

    /// Push the latest run's triaged crashes to `DefectDojo` as findings.
    ///
    /// Reuses `crashes_for_latest_run` and the shared CWE/severity
    /// mapping so the `DefectDojo` push and the SARIF export never disagree. The
    /// product defaults to the project's directory name and the test to the
    /// target, so repeat pushes land in the same `DefectDojo` test and dedup.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if unconfigured, there are no crashes to push,
    /// or the `DefectDojo` request fails.
    pub async fn push_to_defectdojo(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<crate::defectdojo::PushOutcome, ClassifiedError> {
        let cfg = crate::defectdojo::load_config()?;
        let token = crate::defectdojo::resolve_token(&cfg)?;
        let crashes = self.crashes_for_latest_run(project, target).await?;
        if crashes.is_empty() {
            return Err(ClassifiedError::Validation(
                "no triaged crashes to push to DefectDojo".to_owned(),
            ));
        }
        let findings = crate::defectdojo::crashes_to_generic(&crashes);
        let client = crate::defectdojo::DefectDojoClient::from_config(&cfg, &token)?;
        let product_name = cfg
            .product_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| defectdojo_project_name(project));
        let engagement_name = cfg
            .engagement_name
            .clone()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "Fuzzing".to_owned());
        let test_title =
            Some(target.map_or_else(|| "oxfuzz".to_owned(), |t| format!("oxfuzz: {t}")));
        let import = crate::defectdojo::ImportTarget {
            product_name,
            product_type_name: cfg.resolved_product_type(),
            engagement_name,
            test_title,
            reimport: cfg.reimport,
            auto_create: cfg.auto_create,
            // This push carries only the latest run's crashes, not the target's
            // complete crash history, so it must not close still-open findings a
            // shorter/non-deterministic run happened not to rediscover.
            close_old_findings: false,
        };
        client.import(&import, &findings).await
    }

    /// Compose a detailed Markdown campaign report for a target.
    ///
    /// Aggregates the discovered target, the most recent run, its triaged
    /// crashes (with CASR severity + LLM bug reports), line/region coverage, and
    /// corpus composition into one self-contained document. Missing persistence
    /// or tooling is represented honestly as unavailable data.
    ///
    /// # Errors
    /// Returns `ClassifiedError` only on an unexpected internal failure.
    pub async fn generate_report(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<String, ClassifiedError> {
        use crate::report::{render_markdown, ReportData};

        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();

        // Resolve the target candidate (best-effort) and its id.
        let candidate = self
            .resolve_target_candidate_any_language(project, target)
            .await?;
        let target_id = candidate.as_ref().map_or_else(Uuid::nil, |c| c.id);

        // Latest run + its crashes from the store, when persistence is wired.
        let (run, crashes) = if let Some(store) = &self.store {
            let run = self.latest_run_record(project, Some(target)).await?;
            let crashes = match &run {
                // Collapse any pre-existing duplicate rows by signature so the
                // report never lists the same crash twice.
                Some(r) => hf_crash::dedup(store.list_crashes_by_run(r.id).await?),
                None => Vec::new(),
            };
            (run, crashes)
        } else {
            (None, Vec::new())
        };

        // Live coverage (best-effort) and corpus composition.
        let coverage = self.coverage_summary(project, target).await;
        let covered_functions = self.coverage_functions(project, target).await.len();
        let corpus = self
            .collect_corpus_stats(project, target, target_id)
            .await?;

        let data = ReportData {
            generated_at: Utc::now().to_rfc3339(),
            project: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            tool_version: env!("CARGO_PKG_VERSION").to_owned(),
            candidate,
            run,
            crashes,
            coverage,
            covered_functions,
            corpus,
        };

        // The deterministic fact-sheet is always correct and carries the graphs;
        // it is the no-provider fallback AND the grounded input for the LLM.
        let facts = render_markdown(&data);

        // When a provider is configured, have the LLM compose a professional
        // narrative grounded in those facts. On any failure, fall back to the
        // deterministic fact-sheet so a report is always produced.
        if let Some(pool) = self.provider_pool() {
            match self.compose_ai_report(&pool, &facts, &data).await {
                Ok(report) => return Ok(report),
                Err(e) => tracing::warn!("AI report composition failed, using fact-sheet: {e}"),
            }
        }
        Ok(facts)
    }

    /// Document formats this host can export a report to (see
    /// [`crate::report_export::available_formats`]).
    #[must_use]
    pub fn report_formats(&self) -> Vec<String> {
        crate::report_export::available_formats()
    }

    /// Compose the report for `target` and write it to `out_path` in `format`.
    /// Markdown and HTML always work; PDF/DOCX require pandoc (and, for PDF, a
    /// PDF engine).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if composition, format parsing, or the export
    /// (IO / external tool) fails.
    pub async fn export_report(
        &self,
        project: &Path,
        target: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        let markdown = self.generate_report(project, target).await?;
        let title = format!("oxfuzz report — {target}");
        crate::report_export::write_report(&markdown, &title, fmt, out_path)
    }

    /// Write already-composed report `markdown` (e.g. a saved draft) to
    /// `out_path` in `format`, without recomposing it.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on unknown format or export failure.
    pub fn export_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let fmt = crate::report_export::ReportFormat::parse(format).ok_or_else(|| {
            ClassifiedError::Validation(format!("unknown report format: {format}"))
        })?;
        crate::report_export::write_report(markdown, title, fmt, out_path)
    }

    /// Compose the narrative report with the LLM, grounded in the fact-sheet.
    async fn compose_ai_report(
        &self,
        pool: &Arc<dyn ProviderPool>,
        facts: &str,
        data: &crate::report::ReportData,
    ) -> Result<String, ClassifiedError> {
        use hf_core::provider::{ChatRequest, RouteRequest};
        use hf_core::types::Message;

        let messages = vec![
            Message::system(crate::report::report_system_prompt()),
            Message::user(crate::report::report_user_prompt(facts, data)),
        ];
        let req = ChatRequest::from_messages(messages);
        let resp = pool
            .chat_completion(
                &req,
                &RouteRequest::with_tags(&["reasoning", "code", "general"]),
            )
            .await?;
        self.diagnostics
            .record("report", &resp.model, &resp.usage)
            .await;
        let text = resp.text().trim();
        if text.is_empty() {
            return Err(ClassifiedError::Provider(
                "empty report from provider".to_owned(),
            ));
        }
        // Guarantee the campaign graphs survive even if the model dropped them.
        Ok(crate::report::ensure_graphs(text, data))
    }

    /// Summarize corpus composition for the report, preferring the persisted
    /// entries (richer source tags) and falling back to the workspace listing.
    async fn collect_corpus_stats(
        &self,
        project: &Path,
        target: &str,
        target_id: Uuid,
    ) -> Result<crate::report::CorpusStats, ClassifiedError> {
        use hf_core::corpus::CorpusSource;
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let entries = match &self.store {
            Some(store) if target_id != Uuid::nil() => store.list_corpus_entries(target_id).await?,
            _ => Vec::new(),
        };
        let entries = if entries.is_empty() {
            // No persisted entries: read the live corpus directory.
            let workspace = workspace_dir(project, target);
            hf_corpus::list(&workspace.join("corpus"))?.entries
        } else {
            entries
        };

        let mut stats = crate::report::CorpusStats::default();
        for e in &entries {
            stats.count += 1;
            stats.total_bytes += e.size;
            match e.source {
                CorpusSource::Seed => stats.seeds += 1,
                CorpusSource::Fuzzer => stats.from_fuzzer += 1,
                CorpusSource::Minimized => stats.minimized += 1,
                CorpusSource::Manual => {}
            }
        }
        Ok(stats)
    }

    /// Replay a single crash input through the compiled harness in the sandbox
    /// and return the combined stdout+stderr (the sanitizer trace). A forced
    /// stop or runtime failure is inconclusive and returns `None`.
    async fn reproduce_crash(
        &self,
        workspace: &Path,
        binary_host: &Path,
        input_host_path: &Path,
    ) -> Option<String> {
        let _workspace_operation = self.acquire_workspace_operation().await.ok()?;
        if !binary_host.is_file() {
            return None;
        }
        let binary = container_input_path(workspace, binary_host);
        let container_input = container_input_path(workspace, input_host_path);
        let cmd = vec![binary, container_input];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 30,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        match self
            .runtime
            .run_command_opts(&cmd, workspace, &limits, &sandbox)
            .await
        {
            // A crashing input exits non-zero; the trace is the useful output.
            Ok(result) if result.termination == hf_core::runtime::CommandTermination::Completed => {
                Some(format!("{}\n{}", result.stdout, result.stderr))
            }
            Ok(result) => {
                tracing::warn!(termination = ?result.termination, "crash reproduction did not complete");
                None
            }
            Err(e) => {
                tracing::warn!("crash reproduction failed: {e}");
                None
            }
        }
    }

    /// Most recent terminal persisted run in a project, optionally restricted to one
    /// target through `run.config.harness_id -> harness.target_id`.
    async fn latest_run_record(
        &self,
        project: &Path,
        target: Option<&str>,
    ) -> Result<Option<RunRecord>, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let runs = store
            .list_runs(None)
            .await?
            .into_iter()
            .filter(|run| stored_project_matches(Path::new(&run.project_root), project))
            .collect::<Vec<_>>();
        let Some(target) = target else {
            return Ok(runs
                .into_iter()
                .find(|run| run_has_crash_evidence(run.status)));
        };
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        if target_id.is_nil() {
            return Ok(None);
        }
        for run in runs {
            if !run_has_crash_evidence(run.status) {
                continue;
            }
            if self.run_target_id(store, &run).await? == Some(target_id) {
                return Ok(Some(run));
            }
        }
        Ok(None)
    }

    /// Run CASR over the crash dir in the sandbox, returning one `Crash` per
    /// unique (clustered) report with its severity/analysis. Returns `None` when
    /// CASR is unavailable or produced nothing, so the caller can fall back.
    async fn run_casr_triage(
        &self,
        workspace: &Path,
        out_dir: &Path,
        binary_host: &Path,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<Option<Vec<hf_core::crash::Crash>>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        if !binary_host.is_file() {
            return Ok(None);
        }
        let binary = container_input_path(workspace, binary_host);
        if !out_dir.exists() {
            return Ok(None);
        }
        // CASR's input expectation differs by driver: `casr-afl` walks the AFL
        // output tree (out/<instance>/crashes/...), while `casr-libfuzzer` wants
        // a flat directory of crash inputs. For non-AFL engines we stage only
        // real crash inputs into a clean dir, since engines like honggfuzz mix
        // coverage maps and logs into `out` that CASR would otherwise replay.
        let crash_dir = if engine == EngineKind::AflPlusPlus {
            container_input_path(workspace, out_dir)
        } else {
            let staging = workspace
                .join("runs")
                .join(run_id.to_string())
                .join("triage")
                .join("casr_in");
            let _ = std::fs::remove_dir_all(&staging);
            if stage_crash_inputs(engine, out_dir, &staging) == 0 {
                return Ok(None);
            }
            container_input_path(workspace, &staging)
        };
        // Fresh CASR output directory each pass.
        let casr_host = workspace
            .join("runs")
            .join(run_id.to_string())
            .join("triage")
            .join("casr_out");
        let _ = std::fs::remove_dir_all(&casr_host);
        std::fs::create_dir_all(&casr_host).map_err(|error| {
            ClassifiedError::Internal(format!(
                "create CASR output directory {}: {error}",
                casr_host.display()
            ))
        })?;
        let casr_container = container_input_path(workspace, &casr_host);
        let cmd = hf_crash::casr_command(engine, &binary, &crash_dir, &casr_container, 30);
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 240,
            env: std::collections::HashMap::new(),
            ptrace: true,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            extra_mounts: vec![hf_core::runtime::SandboxMount::writable(
                casr_host.clone(),
                casr_container.clone(),
            )],
            ..hf_core::runtime::SandboxOptions::default()
        };
        match self
            .runtime
            .run_command_opts(&cmd, workspace, &limits, &sandbox)
            .await
        {
            Ok(r) if r.termination != hf_core::runtime::CommandTermination::Completed => {
                return Err(ClassifiedError::Sandbox(format!(
                    "CASR triage was force-stopped: {:?}",
                    r.termination
                )));
            }
            Ok(r) if r.exit_code != 0 => {
                tracing::warn!(
                    "casr exited {}: {}",
                    r.exit_code,
                    r.stderr.lines().last().unwrap_or_default()
                );
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("casr run failed, falling back to built-in triage: {e}");
                return Ok(None);
            }
        }
        let reports = collect_casreps(&casr_host);
        if reports.is_empty() {
            tracing::info!("casr produced no reports; falling back to built-in triage");
            return Ok(None);
        }
        // The actual crash inputs, including AFL++'s nested
        // out/<instance>/crashes/ layout, so each casrep resolves to a real file.
        let crash_inputs = collect_crash_inputs(engine, out_dir);
        let mut crashes = reports
            .into_iter()
            .map(|(path, casr)| {
                let input_path = casrep_input_path(out_dir, &path, &crash_inputs);
                let signature = if casr.crashline.is_empty() {
                    casr.stack.first().cloned().unwrap_or_default()
                } else {
                    casr.crashline.clone()
                };
                let summary = if casr.severity_short.is_empty() {
                    casr.crashline.clone()
                } else {
                    format!("{} at {}", casr.severity_short, casr.crashline)
                };
                hf_core::crash::Crash {
                    id: Uuid::new_v4(),
                    run_id,
                    target_id,
                    input_path,
                    stack_signature: signature,
                    kind: hf_crash::kind_from_short(&casr.severity_short),
                    summary,
                    minimized: false,
                    bug_report: None,
                    casr: Some(casr),
                }
            })
            .collect::<Vec<_>>();
        // Bucket by CASR cluster: keep one representative per cluster (clusters
        // are CASR's own "same bug" grouping, stronger than our stack signature).
        // Crashes CASR did not cluster (cluster=None) all pass through.
        crashes = bucket_by_cluster(crashes);
        tracing::info!("casr triaged {} unique crash(es)", crashes.len());
        Ok(Some(crashes))
    }

    /// Built-in triage fallback: replay crashes in the sandbox until the set of
    /// distinct stack signatures saturates, classify, and dedup. Returns the
    /// deduped crashes plus captured sanitizer traces for bug-report drafting.
    async fn legacy_triage(
        &self,
        out_dir: &Path,
        workspace: &Path,
        binary_host: &Path,
        engine: EngineKind,
        run_id: Uuid,
        target_id: Uuid,
    ) -> Result<
        (
            Vec<hf_core::crash::Crash>,
            std::collections::HashMap<PathBuf, String>,
        ),
        ClassifiedError,
    > {
        /// Hard cap on sandbox crash replays per triage pass.
        const MAX_REPRODUCE: usize = 300;
        /// Stop reproducing after this many consecutive crashes with no new
        /// stack signature (the distinct-bug set has saturated).
        const SIGNATURE_STAGNATION: usize = 40;

        let ingested = hf_crash::ingest_for_engine(out_dir, engine, run_id, target_id)?;
        if ingested.is_truncated() {
            tracing::warn!(
                run_id = %run_id,
                artifact_limit_reached = ingested.artifact_limit_reached,
                report_limit_reached = ingested.report_limit_reached,
                "triage crash ingestion reached a safety limit"
            );
        }
        let crashes = ingested.crashes;
        let total_ingested = crashes.len();
        let mut logs: std::collections::HashMap<PathBuf, String> = std::collections::HashMap::new();
        let mut reproduced: Vec<hf_core::crash::Crash> = Vec::new();
        let mut seen_signatures: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        let mut since_new_signature = 0usize;
        for mut crash in crashes {
            if reproduced.len() >= MAX_REPRODUCE || since_new_signature >= SIGNATURE_STAGNATION {
                break;
            }
            let log = self
                .reproduce_crash(workspace, binary_host, &crash.input_path)
                .await;
            if log.as_deref().is_none_or(|value| value.trim().is_empty()) {
                since_new_signature += 1;
            } else if let Some(log) = log.as_deref() {
                let (kind, sig, summary) = hf_crash::classify(log);
                crash.kind = kind;
                crash.summary = summary;
                if seen_signatures.insert(sig.clone()) {
                    since_new_signature = 0;
                } else {
                    since_new_signature += 1;
                }
                crash.stack_signature = sig;
            }
            if let Some(log) = log {
                logs.insert(crash.input_path.clone(), log);
            }
            reproduced.push(crash);
        }
        if reproduced.len() < total_ingested {
            tracing::info!(
                "reproduced {} of {total_ingested} crash inputs ({} distinct signatures) before saturating",
                reproduced.len(),
                seen_signatures.len()
            );
        }
        Ok((hf_crash::dedup(reproduced), logs))
    }

    // -- Corpus -----------------------------------------------------------

    async fn corpus_absorb_run_record(
        &self,
        project: &Path,
        target: &str,
        run: Option<RunRecord>,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_absorb_crashes", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // Prefer the deduplicated crash set triage persisted for the latest run;
        // fall back to whatever crash inputs are staged under the run output.
        let mut inputs: Vec<PathBuf> = Vec::new();
        if let Some(store) = &self.store {
            if let Some(run) = &run {
                let crashes = store.list_crashes_by_run(run.id).await?;
                inputs.extend(crashes.into_iter().map(|c| c.input_path));
            }
        }
        if inputs.is_empty() {
            let out_dir = match run.as_ref() {
                Some(run) => run_output_dir(&workspace, run)?,
                None => workspace.join("out"),
            };
            inputs = run.as_ref().map_or_else(
                || collect_legacy_crash_inputs(&out_dir),
                |run| collect_crash_inputs(run.engine, &out_dir),
            );
        }

        let (mut corpus, added) = hf_corpus::absorb(&corpus_dir, &inputs)?;
        if self.store.is_some() {
            let target_id = self.resolve_target_id_any_language(project, target).await?;
            corpus.target_id = target_id;
            self.persist_corpus(target_id, &corpus).await?;
        }
        Ok(added)
    }

}

// ---------------------------------------------------------------------------
// Environment-driven construction
// ---------------------------------------------------------------------------

/// Build the sandbox runtime from the environment: a Docker runtime when the
/// daemon is reachable (and `HF_USE_DOCKER` is not disabled), else the stub.
#[must_use]
pub fn runtime_from_env() -> Arc<dyn RuntimeAdapter> {
    let use_docker = std::env::var("HF_USE_DOCKER").map_or(true, |v| v != "0" && v != "false");
    if use_docker && hf_runtime::docker_daemon_ready() {
        let cfg = RuntimeConfig::default();
        Arc::new(hf_runtime::docker::DockerRuntime::new(
            cfg,
            &workspace_root(),
        ))
    } else {
        Arc::new(hf_runtime::StubRuntime)
    }
}

/// Build an LLM provider pool from `HF_PROVIDER_*` env vars, or `None` when no
/// API key is configured.
#[must_use]
pub fn provider_pool_from_env() -> Option<Arc<dyn ProviderPool>> {
    let api_key = std::env::var("HF_PROVIDER_API_KEY")
        .ok()
        .filter(|k| !k.is_empty())?;
    let model = std::env::var("HF_PROVIDER_MODEL").unwrap_or_else(|_| "gpt-4o".to_owned());
    let base_url = std::env::var("HF_PROVIDER_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_owned());
    // Build a single-provider pool through the TOML schema so every
    // ProviderConfig field receives its serde default without an unwieldy
    // struct literal. Values are escaped as TOML basic strings via the `toml`
    // serializer so a `"`, `\`, or newline in the API key/model/base URL cannot
    // produce malformed TOML that silently parses to `None` and disables the LLM.
    let quote = |value: &str| toml::Value::String(value.to_owned()).to_string();
    let toml_str = format!(
        "[[providers]]
\
         id = \"env\"
\
         provider_type = \"openai-compat\"
\
         model = {model_q}
\
         api_key = {api_key_q}
\
         base_url = {base_url_q}
\
         tags = [\"general\", \"reasoning\", \"code\"]
",
        model_q = quote(&model),
        api_key_q = quote(&api_key),
        base_url_q = quote(&base_url),
    );
    let cfg: hf_provider::ProviderPoolConfig = toml::from_str(&toml_str).ok()?;
    hf_provider::ProviderPoolImpl::from_config(&cfg)
        .ok()
        .map(|p| Arc::new(p) as Arc<dyn ProviderPool>)
}

/// Build an LLM provider pool from `config/providers.toml` (the file the GUI
/// Settings -> Providers tab writes). Returns `None` if the file is missing,
/// unparsable, or has no enabled provider.
#[must_use]
pub fn provider_pool_from_config() -> Option<Arc<dyn ProviderPool>> {
    let path = crate::init::config_dir().join("providers.toml");
    let text = std::fs::read_to_string(&path).ok()?;
    let cfg: hf_provider::ProviderPoolConfig = match toml::from_str(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            // A typo'd providers.toml previously disabled the LLM silently,
            // indistinguishable from "no config". Surface the parse error.
            tracing::warn!("failed to parse {}: {e}", path.display());
            return None;
        }
    };
    if !cfg.providers.iter().any(|p| p.enabled) {
        return None;
    }
    match hf_provider::ProviderPoolImpl::from_config(&cfg) {
        Ok(pool) => Some(Arc::new(pool) as Arc<dyn ProviderPool>),
        Err(e) => {
            tracing::warn!("failed to build provider pool from config: {e}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Outcome types
// ---------------------------------------------------------------------------

/// The result of a harness compile.
#[derive(Debug, Clone)]
pub struct CompileOutcome {
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
}

/// Outcome of an end-to-end harness generation with automatic repair: the
/// compiled harness plus how many repair attempts it took to get there.
#[derive(Debug, Clone)]
pub struct HarnessGenOutcome {
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
    /// Number of LLM repair passes applied before the harness compiled (0 when
    /// the first draft built cleanly).
    pub repairs_used: usize,
}

/// A generated seed entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SeedEntry {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

/// The result of a corpus minimization pass: entry counts before and after.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct MinimizeOutcome {
    pub before: usize,
    pub after: usize,
}

/// Outcome of an autonomous end-to-end campaign
/// ([`ServiceContainer::run_campaign`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CampaignOutcome {
    /// The target the campaign fuzzed (chosen automatically when not supplied).
    pub target: String,
    /// Status of the promoted harness revision used by the campaign.
    pub harness_status: HarnessStatus,
    /// Unique crashes surfaced by the final triage.
    pub crashes: usize,
    /// Peak edge coverage observed across the campaign's runs.
    pub edges: u64,
    /// How many run -> triage iterations the campaign performed.
    pub iterations: usize,
    /// How many iterations triggered the auto-revert policy (a harness revision
    /// regressed coverage past the threshold). Counts both applied reverts and
    /// notify-only detections, so headless history surfaces self-healing.
    pub auto_reverts: usize,
    /// Why the final campaign iteration stopped.
    pub termination: hf_core::runtime::CommandTermination,
    /// When the campaign plateaued on coverage without finding a crash, the
    /// result of the automatic targeted-refinement *proposal*. The refined
    /// harness is left `Compiled` (never promoted or auto-run), preserving the
    /// human promotion gate. `None` when no plateau was detected or refinement
    /// was not attempted (no provider, non-C target, or the compile action
    /// requires approval).
    #[serde(default)]
    pub refine: Option<RefineProposal>,
}

/// Outcome of an automatic coverage-plateau refinement proposal (HITL-safe:
/// the refined harness is only compiled, never promoted or executed).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RefineProposal {
    /// Uncovered frontier locations that drove the refinement.
    pub frontier_locations: usize,
    /// Whether a refined harness compiled successfully (still only `Compiled`,
    /// awaiting human review and promotion).
    pub compiled: bool,
    /// A short human-readable note for the run log.
    pub note: String,
}

/// Outcome of replaying one stored crash input against the current harness.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RegressionResult {
    /// Persisted crash id (empty if the input came from the output dir).
    pub crash_id: String,
    /// The crash input that was replayed.
    pub input: String,
    /// True if the input still triggers a crash (a regression / unfixed bug).
    pub still_crashes: bool,
    /// Whether the sandbox replay completed and the result is conclusive.
    pub verified: bool,
    /// A short trace/summary line from the replay.
    pub summary: String,
}

/// Per-provider health + usage for the Observability panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderSnapshot {
    pub id: String,
    pub model: String,
    pub tags: Vec<String>,
    pub is_frozen: bool,
    pub active_requests: usize,
    pub max_concurrency: usize,
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub estimated_cost_usd: f64,
}

/// A single agent turn currently executing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AgentInstanceSnapshot {
    pub instance_id: String,
    pub agent_name: String,
    pub state: String,
    pub elapsed_ms: u64,
    pub iterations: u32,
    pub tokens_used: u64,
}

/// Agent pool state. `available_slots` is the number of registered definitions;
/// `active_instances` and `instances` describe live per-turn executions.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct AgentPoolSnapshot {
    pub active_instances: usize,
    pub available_slots: usize,
    pub total_instances: usize,
    pub instances: Vec<AgentInstanceSnapshot>,
}

/// Runtime/state counters for the Observability panel's Memory section.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct MemorySnapshot {
    pub pending_runs: usize,
    pub interrupted_runs: usize,
    pub llm_calls: u64,
    pub targets: usize,
    pub crashes: usize,
}

/// A live snapshot of system state for the Observability panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SystemSnapshot {
    pub providers: Vec<ProviderSnapshot>,
    pub agents: AgentPoolSnapshot,
    pub memory: MemorySnapshot,
}

/// A cheap snapshot of a target's on-disk artifacts, for the Info panel.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct ArtifactSummary {
    /// Whether the compiled harness binary (`fuzz_<target>`) exists.
    pub harness_built: bool,
    /// Number of corpus inputs on disk.
    pub corpus_count: usize,
    /// Number of crash inputs staged in the run output directory.
    pub crash_count: usize,
}

/// One point on a run's intra-run coverage/throughput curve.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageSample {
    /// Seconds elapsed since the run started.
    pub t: f64,
    /// Edge coverage at that moment.
    pub edges: u64,
    /// Executions/second at that moment.
    pub execs: f64,
}

/// Reduce a time series to at most `cap` points by uniform stride, always
/// keeping the last sample so the curve reaches its true end.
fn downsample(series: &[(f64, u64, f64)], cap: usize) -> Vec<(f64, u64, f64)> {
    if series.len() <= cap || cap == 0 {
        return series.to_vec();
    }
    let stride = series.len().div_ceil(cap);
    let mut out: Vec<(f64, u64, f64)> = series.iter().step_by(stride).copied().collect();
    if let Some(last) = series.last() {
        if out.last() != Some(last) {
            out.push(*last);
        }
    }
    out
}

/// The auto-revert decision, isolated from the async plumbing so its rules are
/// unit-testable. Returns `Some(drop_pct)` when the policy should restore the
/// previous harness: the revision changed (`prev_rev != this_rev`), there is a
/// non-zero baseline, coverage dropped, and the drop meets the threshold.
/// Returns `None` otherwise.
fn auto_revert_decision(
    prev_rev: &str,
    this_rev: &str,
    prev_edges: u64,
    this_edges: u64,
    threshold_pct: f64,
) -> Option<f64> {
    // Only a genuine revision change can be a revision regression; an unchanged
    // harness covering fewer edges is run-to-run noise.
    if prev_rev == this_rev {
        return None;
    }
    // No baseline, or coverage held/improved -> nothing to revert.
    if prev_edges == 0 || this_edges >= prev_edges {
        return None;
    }
    let drop_pct = (prev_edges - this_edges) as f64 / prev_edges as f64 * 100.0;
    (drop_pct >= threshold_pct).then_some(drop_pct)
}

/// Whether two run configurations produce coverage measurements that are safe
/// to compare for an automatic harness rollback.
///
/// The harness id is intentionally ignored because a revision change is the
/// subject of the comparison. Engine, budget, sanitizer, corpus location,
/// environment, engine arguments, and the separately persisted comparison
/// context must match; otherwise a lower edge count can be caused by the
/// experimental setup rather than the new harness.
fn auto_revert_baseline_compatible(previous: &FuzzRunConfig, current: &FuzzRunConfig) -> bool {
    previous.engine == current.engine
        && previous.duration == current.duration
        && previous.max_mem_mb == current.max_mem_mb
        && previous.max_cpus == current.max_cpus
        && previous.seed_corpus == current.seed_corpus
        && previous.sanitizer == current.sanitizer
        && previous.env == current.env
        && previous.extra_args == current.extra_args
}

/// Stable opaque key for grouping comparable coverage experiments in
/// presentation layers. The harness id is excluded so revision A/B results for
/// the same target and execution context share a key.
fn auto_revert_comparison_key(
    target_id: Uuid,
    config: &FuzzRunConfig,
    context_rev: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let context = serde_json::json!({
        "target_id": target_id,
        "engine": config.engine,
        "duration": config.duration,
        "max_mem_mb": config.max_mem_mb,
        "max_cpus": config.max_cpus,
        "seed_corpus": config.seed_corpus,
        "sanitizer": config.sanitizer,
        "env": config.env,
        "extra_args": config.extra_args,
        "context_rev": context_rev,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&context).unwrap_or_default());
    format!("{:x}", hasher.finalize())[..16].to_owned()
}

/// A target a scheduled campaign can legally run (see
/// [`ServiceContainer::schedulable_targets`]): it has a promoted harness, and
/// the engine and language are the harness's own, not a guess.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SchedulableTarget {
    pub target: String,
    /// Canonical engine id, e.g. `libfuzzer`.
    pub engine: String,
    /// Canonical language id, e.g. `c`.
    pub language: String,
    /// Discovery fit score (0..1). Portfolio campaigns rotate highest-first, so
    /// the most promising targets get fuzzed sooner and more often.
    pub fit_score: f64,
}

/// One run in the persisted run history (see [`ServiceContainer::run_history`]).
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunHistoryItem {
    pub id: String,
    pub project_root: String,
    /// Target symbol resolved through the run's persisted harness.
    pub target: Option<String>,
    /// Opaque grouping key shared only by directly comparable successful runs.
    pub comparison_key: Option<String>,
    pub engine: String,
    pub status: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub duration_secs: Option<i64>,
    pub crashes: usize,
    /// Peak edge coverage, once the run finished (None for older/pending runs).
    pub edges: Option<u64>,
    /// Peak executions/second, once the run finished.
    pub execs: Option<f64>,
    /// Full SHA-256 of the approved harness source the run used.
    pub harness_rev: Option<String>,
    /// Full SHA-256 of the staged executable the run used.
    pub binary_rev: Option<String>,
    /// Workspace-relative run output directory.
    pub evidence_dir: Option<String>,
}

/// Public lifecycle states used by non-blocking run-control transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunLifecycleStatus {
    /// The durable row exists but execution has not started.
    Pending,
    /// The sandboxed engine is active and may be cancelled cooperatively.
    Running,
    /// Execution completed and terminal evidence is durable.
    Done,
    /// Execution failed and the durable row has been repaired.
    Failed,
    /// The user requested cooperative cancellation.
    Cancelled,
}

impl RunLifecycleStatus {
    /// Stable lowercase transport representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Done => "done",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

impl From<RunStatus> for RunLifecycleStatus {
    fn from(status: RunStatus) -> Self {
        match status {
            RunStatus::Pending => Self::Pending,
            RunStatus::Running => Self::Running,
            RunStatus::Done => Self::Done,
            RunStatus::Failed => Self::Failed,
            RunStatus::Cancelled => Self::Cancelled,
        }
    }
}

/// Durable status snapshot for one service-owned run UUID.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunControlStatus {
    /// Service-owned run UUID.
    pub run_id: Uuid,
    /// Durable lifecycle state.
    pub status: RunLifecycleStatus,
    /// Whether a cooperative cancellation token is currently registered.
    pub active: bool,
    /// RFC3339 reservation time.
    pub started_at: String,
    /// RFC3339 terminal time, when complete.
    pub ended_at: Option<String>,
}

/// Domain outcome of a cooperative cancellation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunCancelOutcome {
    /// The active run's token was signalled.
    Accepted,
    /// No durable run exists for the requested UUID.
    NotFound,
    /// The run exists but is terminal or no longer active.
    Inactive,
}

/// A fuzz run summary.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummary {
    /// Persisted run that owns this summary and its evidence.
    pub run_id: Uuid,
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
    /// Authoritative reason the sandboxed engine stopped.
    pub termination: hf_core::runtime::CommandTermination,
    /// The highest coverage-stagnation proposal tier surfaced during the run
    /// (improve mutation inputs / regenerate the harness / stop the target),
    /// or `None` if coverage kept progressing. Lets a presentation layer offer
    /// an iterate-next affordance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stagnation: Option<hf_coverage::StagnationProposal>,
    /// Set when the auto-revert policy fired: this run's harness regressed
    /// coverage past the configured threshold, so an earlier (last-good)
    /// revision was restored and recompiled. Lets a presentation layer surface
    /// the automatic action. `None` when the policy is off or did not trigger.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_revert: Option<AutoRevertOutcome>,
}

/// The outcome of the auto-revert policy firing for a finished run: its harness
/// revision changed and coverage dropped past the threshold, so the previous
/// run's (last-good) harness was restored and recompiled.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AutoRevertOutcome {
    /// The id of the earlier run whose harness was (or would be) restored.
    pub reverted_to_run: String,
    /// The regressed run's harness revision (the one that was replaced).
    pub from_rev: String,
    /// The restored run's harness revision.
    pub to_rev: String,
    /// Peak edge coverage of the restored (previous) run.
    pub previous_edges: u64,
    /// Peak edge coverage of the regressed run.
    pub regressed_edges: u64,
    /// The percent coverage drop that triggered the revert.
    pub drop_pct: f64,
    /// `true` when the harness was actually restored and recompiled; `false`
    /// when the policy is in notify-only mode and only reported the regression.
    pub reverted: bool,
}

/// The resolved auto-revert policy for a project, plus whether a per-project
/// override is in effect (vs inheriting the global default).
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct EffectiveAutoRevert {
    /// Whether the policy is armed for this project.
    pub enabled: bool,
    /// The coverage-drop threshold (percent) that triggers a revert.
    pub threshold_pct: f64,
    /// Report the regression without restoring the harness.
    pub notify_only: bool,
    /// `true` when a per-project override applies; `false` when inheriting global.
    pub overridden: bool,
}

/// Inputs for a syzkaller kernel-fuzzing campaign.
#[derive(Debug, Clone, Default)]
pub struct SyzkallerRunOpts {
    /// Project label (for logging only).
    pub project: String,
    /// Target architecture (e.g. `"amd64"`); defaults to the host platform.
    pub arch: Option<String>,
    /// Campaign duration in seconds.
    pub duration_secs: u64,
    /// Path to a KCOV kernel image (bzImage). Required without `manager_cfg`;
    /// otherwise overrides the config's `vm.kernel` path.
    pub kernel_image: Option<String>,
    /// Path to a rootfs disk image. Required without `manager_cfg`; otherwise
    /// overrides the config's `image` path. The selected file is copied before
    /// qemu receives a writable view.
    pub disk_image: Option<String>,
    /// Optional SSH private key for the VM; overrides the config's `sshkey`.
    pub ssh_key: Option<String>,
    /// Path to an existing `syz-manager` config. The service parses and
    /// rewrites managed paths rather than mounting this file or its parent.
    pub manager_cfg: Option<String>,
    /// Number of fuzzing VMs (default 2); overrides a supplied config when set
    /// and is clamped to the service maximum of four.
    pub vm_count: Option<u32>,
}

/// Result of a syzkaller campaign.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SyzkallerSummary {
    pub edges: u64,
    pub execs: f64,
    pub crashes: u64,
    pub exit_code: Option<i32>,
    /// Authoritative reason the sandbox stopped.
    pub termination: Option<hf_core::runtime::CommandTermination>,
}

/// Build the syzkaller manager argv without a shell interpolation boundary.
///
/// Keeping the staged config path as one argv element makes its bytes data
/// rather than executable syntax. The inner timeout ends the campaign at its
/// requested budget with a graceful `TERM`, then `--kill-after` force-kills a
/// syz-manager that ignores it -- both before the sandbox teardown backstop, so
/// a hung manager cannot trip the outer Docker deadline and discard the summary.
fn syzkaller_manager_command(
    manager_cfg: &str,
    duration_secs: u64,
    kill_after_secs: u64,
) -> Vec<String> {
    vec![
        "timeout".to_owned(),
        "--signal=TERM".to_owned(),
        format!("--kill-after={kill_after_secs}"),
        duration_secs.to_string(),
        "syz-manager".to_owned(),
        format!("-config={manager_cfg}"),
    ]
}

// ---------------------------------------------------------------------------
// LLM provider bridge: wraps a ProviderPool as a single LlmProvider
// ---------------------------------------------------------------------------

struct LlmProviderBridge {
    pool: Arc<dyn ProviderPool>,
    meta: hf_core::provider::ProviderMetadata,
    /// When set, each completion is recorded as a cost/trace diagnostic under
    /// the given operation label.
    diag: Option<(Arc<crate::diagnostics::DiagnosticsRecorder>, String)>,
    /// Task-tiered routing: soft-preferred provider tags derived from the task
    /// label. Empty (no preference) unless a task tier is set.
    route: hf_core::provider::RouteRequest,
}

/// Map a task label to soft-preferred provider tags so, in a tagged deployment,
/// authoring/triage work routes to a `reasoning`-tagged model and mechanical
/// work to a `fast` one. Untagged deployments are unaffected (the preference is
/// soft -- see [`RouteRequest::preferred_tags`]).
fn preferred_tags_for_task(task: &str) -> Vec<String> {
    let task = task.to_ascii_lowercase();
    if task.contains("harness")
        || task.contains("refine")
        || task.contains("triage")
        || task.contains("report")
        || task.contains("chat")
    {
        vec!["reasoning".to_owned()]
    } else if task.contains("seed") || task.contains("rank") {
        vec!["fast".to_owned()]
    } else {
        Vec::new()
    }
}

impl LlmProviderBridge {
    fn new(pool: Arc<dyn ProviderPool>) -> Self {
        use hf_core::provider::{
            ProviderCapability, ProviderMetadata, ProviderType, ToolCallingMode,
        };
        let meta = ProviderMetadata {
            id: hf_core::types::ProviderId::from_string("pool-bridge"),
            provider_type: ProviderType::Custom,
            model: String::new(),
            tags: Vec::new(),
            capabilities: vec![ProviderCapability::Text],
            max_concurrency: 1,
            context_window: 128_000,
            cost_per_1k_input: 0.0,
            cost_per_1k_output: 0.0,
            tool_calling_mode: ToolCallingMode::PromptBased,
        };
        Self {
            pool,
            meta,
            diag: None,
            route: hf_core::provider::RouteRequest::default(),
        }
    }

    /// Record completions through this bridge as diagnostics under `op`, and
    /// derive task-tiered routing from the same label.
    fn with_diagnostics(
        mut self,
        recorder: Arc<crate::diagnostics::DiagnosticsRecorder>,
        op: &str,
    ) -> Self {
        self.route = hf_core::provider::RouteRequest::preferring_tags(preferred_tags_for_task(op));
        self.diag = Some((recorder, op.to_owned()));
        self
    }
}

#[async_trait::async_trait]
impl hf_core::provider::LlmProvider for LlmProviderBridge {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let response = self.pool.chat_completion(request, &self.route).await?;
        if let Some((recorder, op)) = &self.diag {
            recorder.record(op, &response.model, &response.usage).await;
        }
        Ok(response)
    }

    async fn chat_completion_stream(
        &self,
        request: &hf_core::provider::ChatRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        self.pool.chat_completion_stream(request, &self.route).await
    }

    fn metadata(&self) -> &hf_core::provider::ProviderMetadata {
        &self.meta
    }
}

// ---------------------------------------------------------------------------
// Heuristic harness draft (no-LLM fallback)
// ---------------------------------------------------------------------------

/// Generate a heuristic harness draft when no LLM provider is configured.
fn heuristic_draft(candidate: &TargetCandidate, engine: EngineKind) -> HarnessDraft {
    let includes = generate_includes(candidate);
    let forward_decl = generate_forward_decl(&candidate.symbol, candidate.signature.as_deref());
    let body = generate_harness_body(&candidate.symbol, candidate.signature.as_deref());
    let source = format!(
        r"// Auto-generated harness for {symbol}
// Engine: {engine}
// Target: {file}:{line}
#include <stdint.h>
#include <stddef.h>
{includes}
{forward_decl}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    // Target signature: {sig}
{body}
    return 0;
}}
",
        symbol = candidate.symbol,
        engine = engine_label(engine),
        file = candidate.location.file.display(),
        line = candidate.location.line,
        includes = includes,
        forward_decl = forward_decl,
        sig = candidate.signature.as_deref().unwrap_or("(unknown)"),
        body = body,
    );
    HarnessDraft {
        target_id: candidate.id,
        engine,
        source,
        rationale: String::new(),
        build_cmd: hf_harness::build_command(
            engine,
            candidate.language,
            &harness_binary_name(&candidate.symbol),
        ),
    }
}

fn engine_label(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::LibFuzzer => "libFuzzer",
        EngineKind::AflPlusPlus => "AFL++",
        EngineKind::Honggfuzz => "honggfuzz",
        EngineKind::ClusterFuzzLite => "ClusterFuzzLite",
        EngineKind::Syzkaller => "syzkaller",
    }
}

/// Build the `#include` line for a target's header.
fn generate_includes(candidate: &TargetCandidate) -> String {
    let file = &candidate.location.file;
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("target");
    format!("#include \"{stem}.h\"")
}

/// Build a forward declaration for the target function so the harness
/// compiles even when the header does not export the symbol.
///
/// Uses the signature captured by the scanner (the declarator portion of the
/// function definition).  We prepend the return type that the scanner strips
/// out (best-effort: assume `int` when unknown) and terminate with `;`.
fn generate_forward_decl(symbol: &str, signature: Option<&str>) -> String {
    let Some(sig) = signature else {
        return format!("int {symbol}();");
    };
    // The scanner stores the declarator, e.g. "parse_value_inner(const char
    // *buf, size_t len, value_t *out, int *err)".  Use it verbatim and append
    // `;` to form a prototype.  When the return type is not visible we
    // declare it as `int` (C default) so the compiler has a prototype.
    let trimmed = sig.trim();
    if trimmed.is_empty() {
        return format!("int {symbol}();");
    }
    // If the declarator already has a return type prefix, keep it; otherwise
    // assume int.
    let has_return_type = trimmed.split_whitespace().next().is_some_and(|first_word| {
        // If the first token contains the function name (starts with the
        // symbol or has no space before the opening paren) there is no
        // explicit return type in the declarator.
        !first_word.starts_with(symbol) && first_word != symbol
    });
    if has_return_type {
        format!("{trimmed};")
    } else {
        format!("int {trimmed};")
    }
}

/// Build the body of `LLVMFuzzerTestOneInput` for a target.
fn generate_harness_body(symbol: &str, signature: Option<&str>) -> String {
    let fallback = format!("    {symbol}((const char *)data, size);");
    let Some(sig) = signature else {
        return fallback;
    };
    let (Some(open), Some(close)) = (sig.find('('), sig.rfind(')')) else {
        return fallback;
    };
    // Guard against a malformed declarator where the first `(` is at or after the
    // last `)` (e.g. an oddly-parsed `foo)(...` signature): `open + 1 > close`
    // would make the slice below panic on a start-past-end range.
    if open >= close {
        return fallback;
    }
    let params_str = &sig[open + 1..close];
    let params: Vec<&str> = params_str
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty() && *p != "void")
        .collect();
    if params.is_empty() {
        return fallback;
    }

    let mut decls: Vec<String> = Vec::new();
    let mut args: Vec<String> = Vec::new();
    let mut buffer_used = false;

    for (i, param) in params.iter().enumerate() {
        let star_count = param.matches('*').count();
        let is_char_like =
            param.contains("char") || param.contains("uint8") || param.contains("void");
        if star_count == 1 && is_char_like && !buffer_used {
            args.push("(const char *)data".to_string());
            buffer_used = true;
        } else if star_count >= 1 {
            let base = param[..param.find('*').unwrap_or(param.len())]
                .trim()
                .trim_start_matches("const ")
                .trim();
            let base = if base.is_empty() { "char" } else { base };
            decls.push(format!("    {base} _arg{i} = {{0}};"));
            args.push(format!("&_arg{i}"));
        } else {
            args.push("size".to_string());
        }
    }

    let mut body = String::new();
    for d in &decls {
        body.push_str(d);
        body.push('\n');
    }
    let _ = write!(body, "    {symbol}({});", args.join(", "));
    body
}

/// Coverage-guided feedback for a live fuzz run.
///
/// Feeds each streamed edge reading into a [`hf_coverage::CoverageTracker`]
/// and, while coverage stays flat, surfaces an escalating
/// [`StagnationProposal`](hf_coverage::StagnationProposal) to the user: a live
/// log line each time the proposal escalates a tier (improve the mutation
/// inputs -> regenerate the harness -> stop the target), and the highest
/// tier reached on the final [`RunSummary`]. This realizes the coverage
/// feedback loop from `docs/design/corpus-coverage-design.md` §4: we detect
/// stagnation and *propose* iterating rather than regenerating a harness
/// autonomously, which would bypass the human-in-the-loop review that harness
/// execution requires (AGENTS.md §2.12).
struct CoverageFeedback<'a> {
    /// The run the streamed edge readings are measured for.
    run_id: Uuid,
    tracker: std::sync::Mutex<hf_coverage::CoverageTracker>,
    /// Latched proposal: the highest tier surfaced so far, so each tier is
    /// proposed at most once.
    proposal: std::sync::Mutex<Option<hf_coverage::StagnationProposal>>,
    policy: hf_coverage::StagnationPolicy,
    emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
}

impl<'a> CoverageFeedback<'a> {
    fn new(
        run_id: Uuid,
        policy: hf_coverage::StagnationPolicy,
        emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Self {
        Self {
            run_id,
            tracker: std::sync::Mutex::new(hf_coverage::CoverageTracker::new()),
            proposal: std::sync::Mutex::new(None),
            policy,
            emit,
        }
    }

    /// Record a cumulative edge count from a stat pulse and, whenever the
    /// stagnation proposal escalates to a tier not yet surfaced, emit and
    /// latch it.
    fn on_edges(&self, edges: u64) {
        let Ok(mut tracker) = self.tracker.lock() else {
            return;
        };
        tracker.update(&hf_core::coverage::CoverageReport {
            run_id: self.run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        });
        let Some(proposal) = hf_coverage::propose_action(&tracker, &self.policy) else {
            return;
        };
        let Ok(mut slot) = self.proposal.lock() else {
            return;
        };
        // Only a tier not yet surfaced is announced.
        if slot.as_ref() == Some(&proposal) {
            return;
        }
        (self.emit)(FuzzProgress::LogLine(format!(
            "[coverage] no new edges for {}s -- {}",
            tracker.stagnation_secs(),
            describe_proposal(&proposal),
        )));
        *slot = Some(proposal);
    }

    /// The highest proposal tier surfaced during the run, if any.
    fn proposal(&self) -> Option<hf_coverage::StagnationProposal> {
        self.proposal.lock().ok().and_then(|p| p.clone())
    }
}

/// A short, user-facing description of a stagnation proposal for the run log.
fn describe_proposal(proposal: &hf_coverage::StagnationProposal) -> &'static str {
    match proposal {
        hf_coverage::StagnationProposal::NewHarness => {
            "consider regenerating the harness to reach new code paths"
        }
        hf_coverage::StagnationProposal::CustomMutator => {
            "consider adding seeds, a dictionary, or a custom mutator"
        }
        hf_coverage::StagnationProposal::Stop => "consider stopping this target",
    }
}

#[cfg(test)]
mod coverage_feedback_tests {
    use super::{CoverageFeedback, FuzzProgress};
    use hf_coverage::{StagnationPolicy, StagnationProposal};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    fn policy(threshold_secs: u64) -> StagnationPolicy {
        StagnationPolicy {
            threshold_secs,
            new_harness_windows: 2,
            stop_windows: 3,
        }
    }

    fn log_line_count(emitted: &Mutex<Vec<FuzzProgress>>) -> usize {
        emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|p| matches!(p, FuzzProgress::LogLine(_)))
            .count()
    }

    /// An instant `secs` in the past, for deterministic stagnation aging.
    fn backdated(secs: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn proposes_once_when_edges_plateau() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        // threshold 0: the first flat pulse after the initial reading is stagnant.
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        fb.on_edges(100); // first reading -- never stagnant (needs >1 update)
        assert_eq!(fb.proposal(), None);
        fb.on_edges(100); // flat -> stagnant -> propose the first tier
        fb.on_edges(100); // still flat, same tier -> must NOT propose again (latched)

        assert_eq!(fb.proposal(), Some(StagnationProposal::CustomMutator));
        assert_eq!(
            log_line_count(&emitted),
            1,
            "the proposal must be surfaced exactly once"
        );
    }

    #[test]
    fn escalates_the_proposal_as_stagnation_drags_on() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(100), &emit);
        let report = |edges| hf_core::coverage::CoverageReport {
            run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        };

        // Coverage last progressed 150s ago: one full 100s stagnation window.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(100), backdated(150));
        fb.on_edges(100);
        assert_eq!(fb.proposal(), Some(StagnationProposal::CustomMutator));

        // 250s flat: the second window escalates to a new-harness proposal.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(101), backdated(250));
        fb.on_edges(101);
        assert_eq!(fb.proposal(), Some(StagnationProposal::NewHarness));

        // 350s flat: the third window recommends stopping the target.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(102), backdated(350));
        fb.on_edges(102);
        fb.on_edges(102); // same tier again -> not re-surfaced
        assert_eq!(fb.proposal(), Some(StagnationProposal::Stop));

        assert_eq!(
            log_line_count(&emitted),
            3,
            "each escalation tier must be surfaced exactly once"
        );
    }

    #[test]
    fn no_proposal_on_a_single_reading() {
        let emit = |_p: FuzzProgress| {};
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn threshold_gates_the_proposal() {
        let emit = |_p: FuzzProgress| {};
        // A high threshold is not reached in the test's wall-clock window, so a
        // flat plateau does not (yet) propose.
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(3600), &emit);
        fb.on_edges(100);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn coverage_report_carries_the_run_id() {
        // The report fed to the tracker must name the run the coverage was
        // measured for, not the nil UUID.
        let emit = |_p: FuzzProgress| {};
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(0), &emit);
        fb.on_edges(100);
        assert_eq!(fb.tracker.lock().unwrap().run_id(), run_id);
    }
}

#[cfg(test)]
mod workspace_tests {
    use super::output_budget::{output_budget_status, OutputBudget};

    #[test]
    fn run_output_budget_rejects_oversized_or_excessive_evidence() {
        let output = tempfile::tempdir().unwrap();
        std::fs::write(output.path().join("one"), b"1234").unwrap();
        let within = |max_bytes, max_entries, max_file_bytes| {
            output_budget_status(output.path(), max_bytes, max_entries, max_file_bytes)
                == OutputBudget::Within
        };
        assert!(within(4, 1, 4));
        assert!(!within(3, 1, 4));
        assert!(!within(4, 1, 3));
        std::fs::write(output.path().join("two"), b"x").unwrap();
        assert!(!within(10, 1, 10));
    }

    #[test]
    fn output_budget_status_distinguishes_overflow_from_transient_scan_error() {
        let output = tempfile::tempdir().unwrap();
        std::fs::write(output.path().join("one"), b"1234").unwrap();
        // Clean, within limits.
        assert_eq!(
            output_budget_status(output.path(), 4, 1, 4),
            OutputBudget::Within
        );
        // Definite overflow (byte budget exceeded).
        assert_eq!(
            output_budget_status(output.path(), 3, 1, 4),
            OutputBudget::Exceeded
        );
        // A root that does not exist is a transient/indeterminate scan result,
        // NOT an overflow -- the live monitor must not treat this as a reason to
        // kill the run.
        let missing = output.path().join("gone");
        assert_eq!(
            output_budget_status(&missing, 10, 10, 10),
            OutputBudget::Indeterminate
        );
    }
}

#[cfg(test)]
mod syzkaller_command_tests {
    use super::syzkaller_manager_command;

    #[test]
    fn manager_config_path_is_a_literal_argument_not_shell_source() {
        let path = "/tmp/manager;touch /work/pwn.cfg";
        let command = syzkaller_manager_command(path, 90, 30);

        assert_eq!(
            command,
            vec![
                "timeout",
                "--signal=TERM",
                "--kill-after=30",
                "90",
                "syz-manager",
                "-config=/tmp/manager;touch /work/pwn.cfg",
            ]
        );
        assert!(!command.iter().any(|arg| arg == "bash" || arg == "-c"));
    }
}

#[cfg(test)]
mod downsample_tests {
    use super::downsample;

    #[test]
    fn keeps_short_series_intact() {
        let s = vec![(0.0, 1, 10.0), (1.0, 2, 20.0)];
        assert_eq!(downsample(&s, 10).len(), 2);
    }

    #[test]
    fn caps_and_keeps_last() {
        let s: Vec<(f64, u64, f64)> = (0..100).map(|i| (f64::from(i), i as u64, 0.0)).collect();
        let out = downsample(&s, 10);
        assert!(out.len() <= 11, "capped near the target, got {}", out.len());
        assert_eq!(out.last().unwrap().1, 99, "always keeps the final sample");
    }
}

#[cfg(test)]
mod auto_revert_tests {
    use super::{
        auto_revert_baseline_compatible, auto_revert_comparison_key, auto_revert_decision,
    };
    use hf_core::engine::{EngineKind, FuzzRunConfig};
    use hf_core::target::Sanitizer;
    use std::path::PathBuf;
    use std::time::Duration;
    use uuid::Uuid;

    fn config(engine: EngineKind, duration_secs: u64) -> FuzzRunConfig {
        FuzzRunConfig {
            harness_id: Uuid::new_v4(),
            engine,
            duration: Some(Duration::from_secs(duration_secs)),
            max_mem_mb: 2048,
            max_cpus: 1,
            seed_corpus: Some(PathBuf::from("/work/corpus")),
            sanitizer: Sanitizer::Address,
            env: vec![("MODE".to_owned(), "strict".to_owned())],
            extra_args: vec!["-dict=/work/parser.dict".to_owned()],
            seed: None,
            replay_of: None,
        }
    }

    #[test]
    fn baseline_requires_matching_engine_budget_and_execution_context() {
        let current = config(EngineKind::LibFuzzer, 60);
        let mut baseline = current.clone();
        baseline.harness_id = Uuid::new_v4();
        assert!(auto_revert_baseline_compatible(&baseline, &current));

        baseline.engine = EngineKind::AflPlusPlus;
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.duration = Some(Duration::from_hours(1));
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.max_cpus = 4;
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.sanitizer = Sanitizer::Undefined;
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.env.clear();
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
        baseline = current.clone();
        baseline.extra_args.clear();
        assert!(!auto_revert_baseline_compatible(&baseline, &current));
    }

    #[test]
    fn comparison_key_groups_only_the_same_target_and_run_context() {
        let target = Uuid::new_v4();
        let current = config(EngineKind::LibFuzzer, 60);
        let mut other_revision = current.clone();
        other_revision.harness_id = Uuid::new_v4();
        assert_eq!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(target, &other_revision, "context-a")
        );

        assert_ne!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(Uuid::new_v4(), &current, "context-a")
        );
        other_revision.duration = Some(Duration::from_mins(10));
        assert_ne!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(target, &other_revision, "context-a")
        );
        assert_ne!(
            auto_revert_comparison_key(target, &current, "context-a"),
            auto_revert_comparison_key(target, &current, "context-b")
        );
    }

    #[test]
    fn fires_when_changed_harness_drops_coverage_past_threshold() {
        // 1000 -> 700 edges is a 30% drop with a changed revision.
        let drop = auto_revert_decision("old", "new", 1000, 700, 20.0);
        assert!(matches!(drop, Some(p) if (p - 30.0).abs() < f64::EPSILON));
    }

    #[test]
    fn does_not_fire_when_harness_unchanged() {
        // Same revision: a coverage dip is noise, not a revision regression.
        assert!(auto_revert_decision("same", "same", 1000, 100, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_below_threshold() {
        // 1000 -> 900 is only a 10% drop; threshold is 20%.
        assert!(auto_revert_decision("old", "new", 1000, 900, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_when_coverage_held_or_improved() {
        assert!(auto_revert_decision("old", "new", 1000, 1000, 20.0).is_none());
        assert!(auto_revert_decision("old", "new", 1000, 1200, 20.0).is_none());
    }

    #[test]
    fn does_not_fire_without_a_baseline() {
        assert!(auto_revert_decision("old", "new", 0, 0, 20.0).is_none());
    }

    #[test]
    fn fires_exactly_at_threshold() {
        let drop = auto_revert_decision("old", "new", 100, 80, 20.0);
        assert!(matches!(drop, Some(p) if (p - 20.0).abs() < f64::EPSILON));
    }
}
