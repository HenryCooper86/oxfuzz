//! Central dependency container -- shared by all presentation layers.
//!
//! Mirrors the `y-service::ServiceContainer` pattern: the GUI, CLI, and
//! web API all construct one container and call service methods through it.
//! This keeps business logic out of presentation crates (AGENTS.md 2.9) and
//! ensures every build / fuzz run goes through `hf-runtime` sandboxing
//! (AGENTS.md 2.12).

#[cfg(feature = "build-context")]
pub(crate) mod build_context;
#[cfg(feature = "campaign-health")]
mod campaign_health;
#[cfg(feature = "campaign-trust")]
mod campaign_trust;
mod chat;
#[cfg(feature = "concolic-enrichment")]
mod concolic;
mod corpus;
mod coverage_cache;
mod crash_inputs;
mod discovery;
mod export;
mod guards;
mod harness;
#[cfg(feature = "harness-work-order")]
mod harness_work_order;
#[cfg(feature = "harness-work-order")]
pub use harness_work_order::HarnessWorkOrderExportRequest;
mod harness_workspace;
mod history;
mod lifecycle;
mod output_budget;
mod policy;
mod project_identity;
mod run;
#[cfg(feature = "run-closeout")]
mod run_closeout;
mod staging;
mod system;
mod triage;
#[cfg(feature = "unreached-surface")]
mod unreached_surface;
mod workspace;

#[cfg(feature = "native-analysis")]
pub use discovery::AnalyzedInventory;
pub use guards::AgentTurnGuard;
pub use harness_workspace::{copy_project_sources, generate_target_seeds};
pub(crate) use workspace::ensure_workspace_directory;
pub use workspace::{
    initialize_workspace_root, project_workspace_dir, workspace_dir, workspace_root,
};

use std::fmt::Write;
use std::fs::File;
#[cfg(feature = "semgrep-enrichment")]
use std::fs::TryLockError;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use crash_inputs::{collect_crash_inputs, is_regular_file};
use guards::ProviderHealthTask;
use harness_workspace::{
    harness_binary_name, read_current_harness_id, read_current_harness_source, sanitize_target,
};
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessDraft, HarnessStatus};
use hf_core::provider::ProviderPool;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{TargetCandidate, TargetLanguage};
use hf_guardrails::{Action, Decision, Guardrails};
use hf_runtime::{RuntimeConfig, SANDBOX_IMAGE};
use hf_storage::{GuardrailDecisionRecord, RunRecord, RunStatus, Store};
#[cfg(feature = "build-doctor")]
pub(crate) use project_identity::canonical_project_root;
#[cfg(not(feature = "build-doctor"))]
use project_identity::canonical_project_root;
use project_identity::{project_slug, select_target_candidate, stored_project_matches};
#[cfg(feature = "patch-to-proof")]
pub(crate) use staging::run_context_source_digest;
use staging::{qualification_evidence, sha256_file, RunArtifacts};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
#[cfg(feature = "build-doctor")]
pub(crate) use workspace::build_doctor_staging_dir;
use workspace::{
    clear_managed_workspace_root, prepare_configured_workspace_root,
    prepare_managed_workspace_root_with_adoption, target_revision_gate, target_revision_lock_file,
    workspace_lock_error, workspace_lock_file, workspace_operation_gate,
};

const SMOKE_FUZZ_SECS: u64 = 60;
const COVERAGE_PRUNE_OPERATION_SECS: u64 = 600;
const COVERAGE_PRUNE_COMMAND_SECS: u64 = 10;
const CORPUS_MINIMIZE_SECS: u64 = 300;
/// Bound on the stored policy reason; denial reasons embed action labels that
/// can carry long parameters (e.g. a shell command).
const MAX_GUARDAIL_DETAIL_CHARS: usize = 256;
/// Newest decisions retained in the audit trail; recording prunes beyond this
/// window on write (mirrors schedule-execution history retention).
const GUARDRAIL_DECISION_RETENTION: usize = 1000;
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

/// Exclusive ownership of one target's active harness revision. The lock order
/// is workspace-operation first, then target-revision, so root cleanup cannot
/// deadlock against compile, review, smoke, promotion, or revert.
pub(crate) struct TargetRevisionLease {
    _process_guard: tokio::sync::OwnedMutexGuard<()>,
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
    let status = hf_runtime::scrubbed_command(hf_runtime::docker_bin())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistenceAvailability {
    NotConfigured,
    Available,
    Unavailable,
}

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
    persistence_availability: PersistenceAvailability,
    #[cfg(feature = "harness-work-order")]
    work_order_recovery_ready: bool,
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
                    // Names the schedule this operation is running for, when it
                    // is running for one, so the bridge does not re-fire it with
                    // its own event.
                    source_schedule_id: crate::scheduler::dispatching_schedule(),
                })
                .await;
        }
    }

    /// Runtime adapter used by service-owned optional subsystems.
    #[must_use]
    #[cfg(any(
        feature = "automotive-scapy",
        feature = "build-doctor",
        feature = "semgrep-enrichment",
        feature = "patch-to-proof"
    ))]
    pub(crate) fn runtime_adapter(&self) -> &Arc<dyn RuntimeAdapter> {
        &self.runtime
    }

    #[cfg(feature = "semgrep-enrichment")]
    pub(crate) fn semgrep_runtime(&self) -> &Arc<dyn RuntimeAdapter> {
        self.runtime_adapter()
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

    /// Take the per-target revision lease after acquiring the outer workspace
    /// operation lease. This serializes all mutations and exact checks for one
    /// active harness across service containers and processes.
    pub(crate) async fn acquire_target_revision(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<TargetRevisionLease, ClassifiedError> {
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace).map_err(|error| {
            ClassifiedError::Internal(format!(
                "create harness revision workspace {}: {error}",
                workspace.display()
            ))
        })?;
        let (workspace, gate) = target_revision_gate(&workspace)?;
        let process_guard = gate.lock_owned().await;
        let system_guard = target_revision_lock_file(&workspace)?;
        system_guard
            .try_lock()
            .map_err(|error| workspace_lock_error(error, true))?;
        Ok(TargetRevisionLease {
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

    #[cfg(all(test, feature = "semgrep-enrichment"))]
    pub(crate) fn semgrep_test_workspace_cleanup_lease(
        root: &Path,
    ) -> Result<WorkspaceCleanupLease, ClassifiedError> {
        Self::try_acquire_workspace_cleanup(root)
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
        let _target_revision = self.acquire_target_revision(project, target).await?;
        self.active_harness_locked(project, target, engine).await
    }

    /// Resolve the active harness while the caller retains the workspace
    /// operation lease for its complete qualification operation.
    async fn active_harness_locked(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
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

    /// Verify qualification while the caller holds workspace-operation followed
    /// by target-revision leases. Keeping this lock order avoids recursive
    /// read guards in promotion and protects the checked artifacts through the
    /// persistence decision.
    async fn verify_harness_qualification_locked(
        &self,
        project: &Path,
        target: &str,
        harness: &Harness,
    ) -> Result<(), ClassifiedError> {
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

    // -- Seeds ------------------------------------------------------------

    // -- Run --------------------------------------------------------------

    // -- Triage -----------------------------------------------------------

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

    // -- Corpus -----------------------------------------------------------
}

// ---------------------------------------------------------------------------
// Environment-driven construction
// ---------------------------------------------------------------------------

/// Build the sandbox runtime from the environment: a Docker runtime when the
/// daemon is reachable (and `HF_USE_DOCKER` is not disabled), else the stub.
#[must_use]
pub fn runtime_from_env() -> Arc<dyn RuntimeAdapter> {
    if docker_runtime_enabled() && hf_runtime::docker_daemon_ready() {
        let cfg = RuntimeConfig::default();
        Arc::new(hf_runtime::docker::DockerRuntime::new(
            cfg,
            &workspace_root(),
        ))
    } else {
        Arc::new(hf_runtime::StubRuntime)
    }
}

/// Whether production construction is configured to use the Docker runtime.
/// Readiness diagnostics use this same decision so they cannot report a
/// sandbox that the service has explicitly disabled.
pub(crate) fn docker_runtime_enabled() -> bool {
    docker_runtime_enabled_from(std::env::var("HF_USE_DOCKER").ok().as_deref())
}

pub(crate) fn docker_runtime_enabled_from(value: Option<&str>) -> bool {
    !matches!(value, Some("0" | "false"))
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
    /// Persisted identity of the compiled harness revision.
    pub harness_id: Uuid,
    pub status: HarnessStatus,
    pub binary_name: String,
    pub workspace: PathBuf,
    /// Non-blocking harness lint findings for the compiled source. Blocking
    /// findings never produce an outcome: they fail the compile instead.
    pub lint: Vec<hf_harness::LintFinding>,
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
    /// Non-blocking harness lint findings for the source that compiled.
    pub lint: Vec<hf_harness::LintFinding>,
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
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
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

/// Whether an operation may, must, or must not use an LLM.
///
/// Kept in the service rather than in a CLI flag because it decides which
/// generator runs, which is business logic (AGENTS.md 2.9). It exists because
/// picking the generator from whether a key happens to be exported is not a
/// decision anyone made: the model and the template produce materially
/// different harnesses, and a caller who wanted one should not silently receive
/// the other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiPolicy {
    /// Use the LLM when one is configured and reachable; fall back otherwise.
    #[default]
    Auto,
    /// The LLM must answer. No provider, or a failed call, is an error rather
    /// than a silent downgrade to a different generator.
    Require,
    /// Never call the LLM, even when one is configured -- for a reproducible
    /// run, an offline one, or a target the template already handles.
    Off,
}

/// Inputs for a syzkaller kernel-fuzzing campaign.
#[derive(Debug, Clone, Default)]
pub struct SyzkallerRunOpts {
    /// Project the campaign belongs to. Canonicalized and used as the run's
    /// `project_root`, so a kernel campaign appears in run history and reaches
    /// triage the same way a userspace run does.
    pub project: PathBuf,
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

/// The workspace target name for a kernel campaign.
///
/// A kernel campaign has no discovered symbol to key on, so the kernel image
/// names the target. Campaigns against one kernel then share a workspace and
/// their crashes group together, while a different kernel is a different
/// target -- which is what an operator comparing two kernels expects.
#[must_use]
pub fn syzkaller_target_label(opts: &SyzkallerRunOpts) -> String {
    let stem = opts
        .kernel_image
        .as_deref()
        .or(opts.manager_cfg.as_deref())
        .map(Path::new)
        .and_then(Path::file_stem)
        .and_then(|stem| stem.to_str())
        .unwrap_or("kernel");
    format!("kernel-{stem}")
}

/// The synthetic target id a kernel campaign's crashes are attributed to.
///
/// Derived rather than discovered: there is no `targets` row for a kernel, and
/// inventing a fresh id per run would scatter one kernel's crashes across every
/// campaign. Same construction as the deterministic crash id, so the value is
/// stable for a `(project, kernel)` pair.
#[must_use]
pub fn syzkaller_target_id(project: &Path, label: &str) -> uuid::Uuid {
    let name = format!("syzkaller|{}|{label}", project.to_string_lossy());
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, name.as_bytes())
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
    /// The persisted run, when a campaign actually launched. `None` when the
    /// call returned setup guidance instead of fuzzing, which is not a run and
    /// must not appear in history. Triage takes this id.
    pub run_id: Option<uuid::Uuid>,
    /// Canonical project the run was recorded against; empty when no campaign
    /// launched.
    pub project_root: PathBuf,
    /// Workspace target name the kernel evidence lives under; empty when no
    /// campaign launched.
    pub target: String,
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
/// soft -- see [`hf_core::provider::RouteRequest::preferred_tags`]).
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
    // libFuzzer's `main` has C linkage, so a C++ harness must not let the
    // entry point be name-mangled: without this every C++ target fails to link
    // with `undefined reference to LLVMFuzzerTestOneInput`, whatever its
    // signature.
    let linkage = if candidate.language == TargetLanguage::Cpp {
        "extern \"C\" "
    } else {
        ""
    };
    let source = format!(
        r"// Auto-generated harness for {symbol}
// Engine: {engine}
// Target: {file}:{line}
#include <stdint.h>
#include <stddef.h>
{includes}
{forward_decl}

{linkage}int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
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
        linkage = linkage,
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
        generator: hf_core::harness::DraftGenerator::Heuristic,
    }
}

fn engine_label(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::LibFuzzer => "libFuzzer",
        EngineKind::AflPlusPlus => "AFL++",
        EngineKind::Honggfuzz => "honggfuzz",
        EngineKind::Syzkaller => "syzkaller",
    }
}

/// Build the `#include` line for a target's header.
fn generate_includes(candidate: &TargetCandidate) -> String {
    header_include_for(&candidate.location.file)
}

/// The `#include` line for a target's own header, when the target has one.
///
/// Emitted only if the header actually exists beside the source. Guessing
/// `<stem>.h` unconditionally made the harness fail to compile with
/// `fatal error: 'frame.h' file not found` for every target whose declarations
/// do not live in a same-named header -- a single-file `.cc`, a header named
/// after the module rather than the file, a project using one aggregate header.
///
/// Nothing is lost when it is absent: [`generate_forward_decl`] already
/// declares the target, which is why it exists.
fn header_include_for(source: &std::path::Path) -> String {
    let Some(stem) = source.file_stem().and_then(|s| s.to_str()) else {
        return String::new();
    };
    for extension in ["h", "hpp", "hh", "hxx"] {
        let header = source.with_file_name(format!("{stem}.{extension}"));
        if header.is_file() {
            return format!("#include \"{stem}.{extension}\"");
        }
    }
    String::new()
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
/// The declared pointer type of a parameter, for casting the fuzzer buffer to
/// it: `const uint8_t *data` -> `const uint8_t *`.
///
/// Recovers the type by dropping the parameter name, so the cast follows the
/// target rather than a guess. Falls back to `const char *` only when nothing
/// resembling a type survives, which is the same guess the caller's `fallback`
/// makes when the signature cannot be read at all.
fn pointer_cast_type(param: &str) -> String {
    let Some(star) = param.rfind('*') else {
        return "const char *".to_owned();
    };
    let base = param[..star].trim();
    if base.is_empty() {
        return "const char *".to_owned();
    }
    // Everything after the last `*` is the parameter name (or nothing, for an
    // unnamed parameter); the type is what precedes it.
    format!("{base} *")
}

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
            // Cast to the parameter's own declared type. Hardcoding
            // `const char *` here is an incompatible-pointer warning in C (it
            // still links, which is why it went unnoticed) and a hard error in
            // C++, where harnesses build with `clang++` -- so a C++ target
            // taking `const uint8_t *`, the commonest fuzzing signature there
            // is, would not compile at all on this no-LLM path.
            args.push(format!("({})data", pointer_cast_type(param)));
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
mod heuristic_harness_tests {
    use super::generate_harness_body;

    /// The buffer is cast to the parameter's own type, not to one hardcoded
    /// type.
    ///
    /// `const uint8_t *` is the commonest fuzzing signature there is. Casting
    /// it to `const char *` is an incompatible-pointer warning in C -- which is
    /// why this went unnoticed, since it still links -- and a hard compile
    /// error in C++, where harnesses build with `clang++`. That made every C++
    /// target with a byte-buffer parameter fail to build on the no-LLM path.
    #[test]
    fn the_buffer_cast_matches_the_declared_parameter_type() {
        for (signature, expected) in [
            (
                "parse_frame(const uint8_t *data, size_t len)",
                "parse_frame((const uint8_t *)data, size);",
            ),
            (
                "parse_text(const char *buf, size_t len)",
                "parse_text((const char *)data, size);",
            ),
            (
                "parse_blob(void *p, size_t len)",
                "parse_blob((void *)data, size);",
            ),
            (
                "parse_u(unsigned char *b, size_t n)",
                "parse_u((unsigned char *)data, size);",
            ),
        ] {
            let symbol = signature.split('(').next().unwrap();
            let body = generate_harness_body(symbol, Some(signature));
            assert!(
                body.contains(expected),
                "for {signature}\n  expected: {expected}\n  got: {body}"
            );
        }
    }

    /// A C++ harness gives its entry point C linkage.
    ///
    /// libFuzzer's `main` has C linkage, so without `extern "C"` the mangled
    /// `LLVMFuzzerTestOneInput` is invisible to it and every C++ target fails
    /// to link, whatever its signature.
    #[test]
    fn a_cpp_harness_entry_point_is_not_name_mangled() {
        let cpp = super::heuristic_draft(
            &candidate(hf_core::target::TargetLanguage::Cpp),
            hf_core::engine::EngineKind::LibFuzzer,
        );
        assert!(
            cpp.source
                .contains("extern \"C\" int LLVMFuzzerTestOneInput"),
            "C++ entry point must have C linkage: {}",
            cpp.source
        );

        let c = super::heuristic_draft(
            &candidate(hf_core::target::TargetLanguage::C),
            hf_core::engine::EngineKind::LibFuzzer,
        );
        assert!(
            c.source.contains("int LLVMFuzzerTestOneInput") && !c.source.contains("extern \"C\""),
            "a C harness needs no linkage specifier: {}",
            c.source
        );
    }

    fn candidate(language: hf_core::target::TargetLanguage) -> hf_core::target::TargetCandidate {
        hf_core::target::TargetCandidate {
            id: uuid::Uuid::new_v4(),
            project_root: std::path::PathBuf::from("/p"),
            language,
            symbol: "parse_frame".to_owned(),
            kind: hf_core::target::TargetKind::Parser,
            location: hf_core::target::SourceLocation {
                file: std::path::PathBuf::from("/p/frame.cc"),
                line: 1,
                col: 1,
                end_line: Some(5),
                end_col: Some(2),
            },
            signature: Some("parse_frame(const uint8_t *data, size_t len)".to_owned()),
            input_surface: hf_core::target::InputSurface::Bytes,
            complexity: 1,
            fit_score: 0.9,
            sanitizers: vec![hf_core::target::Sanitizer::Address],
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        }
    }

    /// A header is included only when it exists.
    ///
    /// Guessing `<stem>.h` from the source filename made the harness fail with
    /// `fatal error: '<stem>.h' file not found` for any target whose
    /// declarations are not in a same-named header. The forward declaration
    /// already declares the target, so an absent header costs nothing.
    #[test]
    fn a_header_is_included_only_when_it_exists() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("frame.cc");
        std::fs::write(&source, "int f(void){return 0;}").unwrap();
        assert_eq!(
            super::header_include_for(&source),
            "",
            "no header on disk means no include"
        );

        std::fs::write(dir.path().join("frame.h"), "int f(void);").unwrap();
        assert_eq!(super::header_include_for(&source), "#include \"frame.h\"");

        // A C++ project may name it `.hpp`.
        let other = dir.path().join("codec.cc");
        std::fs::write(&other, "int g(void){return 0;}").unwrap();
        std::fs::write(dir.path().join("codec.hpp"), "int g(void);").unwrap();
        assert_eq!(super::header_include_for(&other), "#include \"codec.hpp\"");
    }

    /// With no signature to read, the old behaviour stands: a `const char *`
    /// cast is the only defensible guess.
    #[test]
    fn an_unreadable_signature_still_falls_back() {
        assert!(generate_harness_body("f", None).contains("f((const char *)data, size);"));
        assert!(generate_harness_body("f", Some("garbage")).contains("(const char *)data"));
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
