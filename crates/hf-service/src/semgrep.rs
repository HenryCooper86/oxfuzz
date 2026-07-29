//! Service-owned Semgrep admission, sandbox lifecycle, and source snapshots.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandTermination, ResourceLimits, SandboxMount, SandboxNetworkMode, SandboxOptions,
};
use hf_core::target::{TargetCandidate, TargetInventory, TargetLanguage};
use hf_guardrails::Action;
use hf_runtime::SANDBOX_IMAGE;
use hf_storage::{
    SemgrepFindingRecord, SemgrepFindingSeverity, SemgrepPublication, SemgrepRunRecord,
    SemgrepRunStatus, SemgrepTargetScoreRecord,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

use crate::container::{acquire_semgrep_project_lease, SemgrepProjectLease};

/// Pinned Semgrep Community Edition version in the sandbox image.
pub const SEMGREP_VERSION: &str = "1.169.0";
/// Pinned `0xdea/semgrep-rules` revision bundled in the sandbox image.
pub const RULES_COMMIT: &str = "4d66ecf30bfb1809a984085f2c86a8c3915bfc71";
/// Version of the fixed Semgrep sandbox command contract.
pub const COMMAND_SCHEMA_VERSION: u32 = 1;

const SEMGREP_COMMAND: &str = "/usr/local/bin/oxfuzz-semgrep-scan";
const SEMGREP_OUTPUT_FILE: &str = "semgrep.json";
const MAX_SEMGREP_OUTPUT_BYTES: u64 = 67_108_864;
const OUTPUT_TRUNCATION_MARKER: &str = "[output truncated]";
const LINE_TRUNCATION_MARKER: &str = "[line truncated]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StartupRecoveryOutcome {
    Recovered,
    Deferred,
}

/// Current lifecycle phase of one explicit Semgrep enrichment operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepOperationState {
    /// The bounded source snapshot is being prepared.
    Staging,
    /// The fixed Semgrep wrapper is running in the sandbox.
    Scanning,
    /// Scanner output is ready for validation and mapping.
    Validating,
    /// The normalized result is being published.
    Persisting,
    /// The complete overlay was published.
    Done,
    /// The operation failed atomically.
    Failed,
    /// The operator cancelled the operation.
    Cancelled,
}

/// Staleness state of the selected Semgrep score overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepOverlayState {
    /// No completed Semgrep publication was selected.
    None,
    /// The selected publication is current and its scores are applied.
    Current,
    /// Eligible source no longer matches the scanned source revision.
    StaleSource,
    /// Candidate identity or immutable base scores no longer match.
    StaleBase,
    /// Successful publication cannot be proven by the recovery journal.
    IncompleteJournal,
}

/// One candidate with immutable base and separately exposed Semgrep scoring.
#[derive(Debug, Clone, Serialize)]
pub struct SemgrepTargetView {
    /// Original candidate. Its `fit_score` remains the immutable base score.
    #[serde(flatten)]
    pub candidate: TargetCandidate,
    /// Immutable discovery or LLM-ranked base score.
    pub base_score: f64,
    /// Capped Semgrep score contribution.
    pub semgrep_boost: f64,
    /// Base plus current capped Semgrep contribution.
    pub effective_score: f64,
    /// Number of distinct matched rules contributing to the boost.
    pub semgrep_matched_rule_count: u32,
}

/// Presentation-safe normalized Semgrep finding.
#[derive(Debug, Clone, Serialize)]
pub struct SemgrepFindingView {
    /// Service-owned deterministic finding fingerprint.
    pub fingerprint: String,
    /// Bounded Semgrep rule identifier.
    pub rule_id: String,
    /// Canonical lower-case advisory severity.
    pub severity: String,
    /// Bounded normalized advisory message.
    pub message: String,
    /// Project-relative source path.
    pub relative_file: PathBuf,
    /// One-based start line.
    pub start_line: u32,
    /// One-based start column.
    pub start_col: u32,
    /// One-based end line.
    pub end_line: u32,
    /// One-based end column.
    pub end_col: u32,
    /// Unambiguously matched target, when one exists.
    pub matched_target_id: Option<Uuid>,
    /// Nominal advisory severity weight.
    pub nominal_weight: f64,
}

/// Effective target inventory with optional Semgrep publication evidence.
#[derive(Debug, Clone, Serialize)]
pub struct SemgrepInventoryView {
    /// Canonical project root.
    pub project_root: PathBuf,
    /// Inventory language.
    pub language: TargetLanguage,
    /// Selected Semgrep operation, when one exists.
    pub scan_id: Option<Uuid>,
    /// Selected scan source revision, when one exists.
    pub source_sha256: Option<String>,
    /// Whether the selected overlay is current or stale.
    pub overlay_state: SemgrepOverlayState,
    /// Deterministically ordered candidate views.
    pub candidates: Vec<SemgrepTargetView>,
    /// Normalized findings retained for the selected publication.
    pub findings: Vec<SemgrepFindingView>,
    /// Read-only scanner call graph.
    pub call_graph: HashMap<String, Vec<String>>,
}

/// Presentation-safe status for one service-owned Semgrep operation.
#[derive(Debug, Clone, Serialize)]
pub struct SemgrepOperationView {
    /// Service-owned operation identifier.
    pub operation_id: Uuid,
    /// Canonical project root.
    pub project_root: String,
    /// Canonical language identifier.
    pub language: String,
    /// Current lifecycle phase.
    pub state: SemgrepOperationState,
    /// Whether the operation retains its process-local admission reservation.
    pub active: bool,
    /// RFC 3339 admission time.
    pub started_at: String,
    /// RFC 3339 terminal time.
    pub ended_at: Option<String>,
    /// Stable bounded terminal failure code.
    pub failure_code: Option<String>,
    /// Bounded redacted terminal failure message.
    pub failure_message: Option<String>,
    /// Exact historical inventory result for a successfully completed UUID.
    pub result: Option<SemgrepInventoryView>,
}

/// Result of requesting cooperative cancellation for an operation UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepCancelOutcome {
    /// The active operation's cancellation token was signalled.
    Accepted,
    /// The operation exists but no longer owns an active cancellation token.
    Inactive,
    /// The UUID is not owned by this service store.
    NotFound,
}

/// Shared process-local Semgrep admission and recovery state.
pub(crate) struct SemgrepCoordinator {
    active: Mutex<HashMap<PathBuf, ActiveSemgrepOperation>>,
    journal: Arc<crate::semgrep_recovery::SemgrepJournal>,
    recovery_error: Mutex<Option<String>>,
    #[cfg(test)]
    completion_pause: Mutex<Option<CompletionPause>>,
    #[cfg(test)]
    cleanup_failure: Mutex<bool>,
}

enum ActiveSemgrepOperation {
    Cancellable {
        operation_id: Uuid,
        cancellation: CancellationToken,
    },
    Finalizing {
        operation_id: Uuid,
    },
}

impl ActiveSemgrepOperation {
    fn operation_id(&self) -> Uuid {
        match self {
            Self::Cancellable { operation_id, .. } | Self::Finalizing { operation_id } => {
                *operation_id
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionPausePoint {
    AfterOwnershipBeforeDurableWrite,
    AfterStagingInsertBeforeBegin,
    AfterBegin,
    BeforeClaim,
    AfterClaim,
    AfterPublicationFailure,
    AfterPublicationBeforeCleanup,
    BeforeClose,
    AfterCloseBeforeLeaseRelease,
    AfterStatusParentLoad,
}

#[cfg(test)]
#[derive(Clone)]
struct CompletionPause {
    point: CompletionPausePoint,
    reached: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl SemgrepCoordinator {
    pub(crate) fn in_memory() -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            journal: Arc::new(crate::semgrep_recovery::SemgrepJournal::in_memory()),
            recovery_error: Mutex::new(None),
            #[cfg(test)]
            completion_pause: Mutex::new(None),
            #[cfg(test)]
            cleanup_failure: Mutex::new(false),
        }
    }

    pub(crate) fn persistent(directory: PathBuf) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            journal: Arc::new(crate::semgrep_recovery::SemgrepJournal::open(directory)),
            recovery_error: Mutex::new(None),
            #[cfg(test)]
            completion_pause: Mutex::new(None),
            #[cfg(test)]
            cleanup_failure: Mutex::new(false),
        }
    }

    fn reserve(
        &self,
        project: &Path,
        operation_id: Uuid,
        cancellation: CancellationToken,
    ) -> Result<(), ClassifiedError> {
        let mut active = self.active.lock().map_err(|_| {
            ClassifiedError::Internal("Semgrep operation registry is unavailable".to_owned())
        })?;
        if active.contains_key(project) {
            return Err(semgrep_validation("busy"));
        }
        active.insert(
            project.to_path_buf(),
            ActiveSemgrepOperation::Cancellable {
                operation_id,
                cancellation,
            },
        );
        Ok(())
    }

    fn ensure_recovery_healthy(&self) -> Result<(), ClassifiedError> {
        let degraded = self.journal.durability_error().is_some()
            || self
                .recovery_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some();
        if degraded {
            return Err(ClassifiedError::Storage(
                "Semgrep recovery is degraded".to_owned(),
            ));
        }
        Ok(())
    }

    pub(crate) fn mark_recovery_degraded(&self, error: impl std::fmt::Display) {
        let mut recovery_error = self
            .recovery_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        recovery_error.get_or_insert_with(|| bounded_bytes(&error.to_string(), 1_024));
    }

    pub(crate) async fn recover_interrupted(
        &self,
        store: &hf_storage::Store,
        managed_workspace: &Path,
    ) -> Result<(), ClassifiedError> {
        let interrupted = self.journal.interrupted().inspect_err(|error| {
            self.mark_recovery_degraded(error);
        })?;
        for operation in interrupted {
            if let Err(error) = self.recover_one(store, managed_workspace, &operation).await {
                self.mark_recovery_degraded(&error);
                return Err(error);
            }
        }
        let active_runs = store.active_semgrep_runs().await.inspect_err(|error| {
            self.mark_recovery_degraded(error);
        })?;
        for run in active_runs {
            if let Err(error) = self
                .recover_active_without_journal(store, managed_workspace, run.id)
                .await
            {
                self.mark_recovery_degraded(&error);
                return Err(error);
            }
        }
        Ok(())
    }

    async fn recover_one(
        &self,
        store: &hf_storage::Store,
        managed_workspace: &Path,
        operation: &crate::semgrep_recovery::InterruptedSemgrepOperation,
    ) -> Result<(), ClassifiedError> {
        if operation.staging_dir_name != operation.operation_id.to_string() {
            return Err(ClassifiedError::Storage(
                "Semgrep recovery identity does not match its operation".to_owned(),
            ));
        }
        let Some(run) = store.semgrep_run(operation.operation_id).await? else {
            let operation_root = managed_workspace
                .join("semgrep")
                .join(operation.operation_id.to_string());
            cleanup_operation_root_in(managed_workspace, &operation_root)?;
            self.journal.abort(
                operation.operation_id,
                crate::semgrep_recovery::SemgrepAbortKind::Recovered,
            )?;
            return Ok(());
        };
        if !canonical_stored_project(Path::new(&run.project_root), &operation.project_root) {
            return Err(ClassifiedError::Storage(
                "Semgrep recovery identity does not match its operation".to_owned(),
            ));
        }
        match run.status {
            SemgrepRunStatus::Staging
            | SemgrepRunStatus::Scanning
            | SemgrepRunStatus::Validating
            | SemgrepRunStatus::Persisting => {
                store
                    .fail_semgrep_run(
                        operation.operation_id,
                        SemgrepRunStatus::Failed,
                        "recovered",
                        "Interrupted Semgrep operation was repaired at startup",
                        Utc::now(),
                    )
                    .await?;
            }
            SemgrepRunStatus::Done => {
                store
                    .compensate_semgrep_publication(
                        operation.operation_id,
                        "recovered",
                        "Unclosed Semgrep publication was repaired at startup",
                        Utc::now(),
                    )
                    .await?;
            }
            SemgrepRunStatus::Failed | SemgrepRunStatus::Cancelled => {
                let publication = store
                    .semgrep_publication(operation.operation_id)
                    .await?
                    .ok_or_else(|| {
                        ClassifiedError::Storage(
                            "Semgrep terminal operation disappeared during recovery".to_owned(),
                        )
                    })?;
                if !publication.findings.is_empty() || !publication.scores.is_empty() {
                    return Err(ClassifiedError::Storage(
                        "Semgrep terminal operation retained publication children".to_owned(),
                    ));
                }
            }
        }
        let operation_root = managed_workspace
            .join("semgrep")
            .join(operation.operation_id.to_string());
        cleanup_operation_root_in(managed_workspace, &operation_root)?;
        self.journal.abort(
            operation.operation_id,
            crate::semgrep_recovery::SemgrepAbortKind::Recovered,
        )?;
        Ok(())
    }

    async fn recover_active_without_journal(
        &self,
        store: &hf_storage::Store,
        managed_workspace: &Path,
        operation_id: Uuid,
    ) -> Result<(), ClassifiedError> {
        let operation_root = managed_workspace
            .join("semgrep")
            .join(operation_id.to_string());
        cleanup_operation_root_in(managed_workspace, &operation_root)?;
        store
            .fail_semgrep_run(
                operation_id,
                SemgrepRunStatus::Failed,
                "recovered_missing_journal",
                "Semgrep operation without recovery journal was repaired at startup",
                Utc::now(),
            )
            .await?;
        Ok(())
    }

    fn release(&self, project: &Path, operation_id: Uuid) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .get(project)
            .is_some_and(|operation| operation.operation_id() == operation_id)
        {
            active.remove(project);
        }
    }

    fn is_active(&self, operation_id: Uuid) -> bool {
        self.active.lock().ok().is_some_and(|active| {
            active
                .values()
                .any(|operation| operation.operation_id() == operation_id)
        })
    }

    #[cfg(test)]
    fn active_operation_for_project(&self, project: &Path) -> Option<Uuid> {
        self.active.lock().ok().and_then(|active| {
            active
                .get(project)
                .map(ActiveSemgrepOperation::operation_id)
        })
    }

    fn cancel(&self, operation_id: Uuid) -> Result<bool, ClassifiedError> {
        let active = self.active.lock().map_err(|_| {
            ClassifiedError::Internal("Semgrep operation registry is unavailable".to_owned())
        })?;
        let Some(operation) = active
            .values()
            .find(|operation| operation.operation_id() == operation_id)
        else {
            return Ok(false);
        };
        match operation {
            ActiveSemgrepOperation::Cancellable { cancellation, .. } => {
                cancellation.cancel();
                Ok(true)
            }
            ActiveSemgrepOperation::Finalizing { .. } => Ok(false),
        }
    }

    fn claim_completion(&self, project: &Path, operation_id: Uuid) -> bool {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(operation) = active.get_mut(project) else {
            return false;
        };
        match operation {
            ActiveSemgrepOperation::Cancellable {
                operation_id: active_id,
                cancellation,
            } if *active_id == operation_id => {
                let cancelled = cancellation.is_cancelled();
                *operation = ActiveSemgrepOperation::Finalizing { operation_id };
                cancelled
            }
            ActiveSemgrepOperation::Cancellable { .. }
            | ActiveSemgrepOperation::Finalizing { .. } => false,
        }
    }

    #[cfg(test)]
    async fn pause_completion(&self, point: CompletionPausePoint) {
        let pause = self
            .completion_pause
            .lock()
            .ok()
            .and_then(|pause| pause.clone())
            .filter(|pause| pause.point == point);
        if let Some(pause) = pause {
            pause.reached.notify_one();
            pause.release.notified().await;
        }
    }

    #[cfg(test)]
    fn install_completion_pause(
        &self,
        point: CompletionPausePoint,
    ) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        if let Ok(mut pause) = self.completion_pause.lock() {
            *pause = Some(CompletionPause {
                point,
                reached: Arc::clone(&reached),
                release: Arc::clone(&release),
            });
        }
        (reached, release)
    }

    #[cfg(test)]
    fn install_test_cleanup_failure(&self) {
        *self
            .cleanup_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
    }

    #[cfg(test)]
    fn take_test_cleanup_failure(&self) -> bool {
        let mut failure = self
            .cleanup_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *failure)
    }
}

pub(crate) async fn recover_semgrep_at_bootstrap(
    store: &hf_storage::Store,
    semgrep: &SemgrepCoordinator,
    workspace: &Path,
) -> Result<StartupRecoveryOutcome, ClassifiedError> {
    let _workspace_lease = match crate::ServiceContainer::try_acquire_workspace_cleanup(workspace) {
        Ok(lease) => lease,
        Err(ClassifiedError::Validation(message))
            if message == crate::container::WORKSPACE_CLEANUP_BUSY_MESSAGE =>
        {
            semgrep.mark_recovery_degraded(
                "Semgrep recovery was deferred while another workspace operation is active",
            );
            return Ok(StartupRecoveryOutcome::Deferred);
        }
        Err(error) => {
            semgrep.mark_recovery_degraded(&error);
            return Err(error);
        }
    };
    semgrep.recover_interrupted(store, workspace).await?;
    Ok(StartupRecoveryOutcome::Recovered)
}

struct ActiveSemgrepGuard {
    coordinator: Arc<SemgrepCoordinator>,
    project: PathBuf,
    operation_id: Uuid,
}

impl Drop for ActiveSemgrepGuard {
    fn drop(&mut self) {
        self.coordinator.release(&self.project, self.operation_id);
    }
}

impl crate::ServiceContainer {
    #[cfg(test)]
    pub(crate) async fn semgrep_test_publish_inventory(
        &self,
        inventory: &TargetInventory,
        boost_by_target: HashMap<Uuid, f64>,
    ) -> Result<Uuid, ClassifiedError> {
        let store = self.store().cloned().ok_or_else(|| {
            ClassifiedError::Validation("Semgrep test publication requires a store".to_owned())
        })?;
        let language = inventory
            .candidates
            .first()
            .map(|candidate| candidate.language)
            .ok_or_else(|| semgrep_validation("inventory_missing"))?;
        let operation_id = Uuid::new_v4();
        let source_sha256 = digest_live_sources(&inventory.project_root, language)?;
        let started_at = Utc::now();
        let run = SemgrepRunRecord {
            id: operation_id,
            project_root: inventory.project_root.to_string_lossy().into_owned(),
            language: language.as_str().to_owned(),
            source_sha256: None,
            sandbox_image: SANDBOX_IMAGE.to_owned(),
            sandbox_image_sha256: "1".repeat(64),
            semgrep_version: SEMGREP_VERSION.to_owned(),
            rules_commit: RULES_COMMIT.to_owned(),
            rules_tree_sha256: rules_tree_sha256().to_owned(),
            command_schema_version: COMMAND_SCHEMA_VERSION,
            status: SemgrepRunStatus::Staging,
            started_at,
            ended_at: None,
            output_sha256: None,
            finding_count: None,
            matched_candidate_count: None,
            duration_ms: None,
            failure_code: None,
            failure_message: None,
        };
        store.insert_semgrep_run(&run).await?;
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Staging,
                SemgrepRunStatus::Scanning,
                Some(&source_sha256),
            )
            .await?;
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Scanning,
                SemgrepRunStatus::Validating,
                None,
            )
            .await?;
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Validating,
                SemgrepRunStatus::Persisting,
                None,
            )
            .await?;
        self.semgrep.journal.begin(
            operation_id,
            &inventory.project_root,
            &operation_id.to_string(),
        )?;
        let output_sha256 = "3".repeat(64);
        self.semgrep.journal.ready_to_commit(
            operation_id,
            &crate::semgrep_recovery::SemgrepReadyRecord {
                source_sha256: source_sha256.clone(),
                output_sha256: output_sha256.clone(),
                sandbox_image_sha256: "1".repeat(64),
                rules_tree_sha256: rules_tree_sha256().to_owned(),
                command_schema_version: COMMAND_SCHEMA_VERSION,
            },
        )?;
        let scores = inventory
            .candidates
            .iter()
            .map(|candidate| {
                let boost = boost_by_target.get(&candidate.id).copied().unwrap_or(0.0);
                SemgrepTargetScoreRecord {
                    scan_id: operation_id,
                    target_id: candidate.id,
                    base_score: candidate.fit_score,
                    boost,
                    effective_score: (candidate.fit_score + boost).min(1.0),
                    matched_rule_count: u32::from(boost > 0.0),
                }
            })
            .collect::<Vec<_>>();
        let matched_candidate_count = u32::try_from(
            scores
                .iter()
                .filter(|score| score.matched_rule_count > 0)
                .count(),
        )
        .map_err(|_| ClassifiedError::Storage("Semgrep test count overflowed".to_owned()))?;
        let publication = SemgrepPublication {
            run: SemgrepRunRecord {
                source_sha256: Some(source_sha256),
                status: SemgrepRunStatus::Done,
                ended_at: Some(Utc::now()),
                output_sha256: Some(output_sha256),
                finding_count: Some(0),
                matched_candidate_count: Some(matched_candidate_count),
                duration_ms: Some(1),
                ..run
            },
            findings: Vec::new(),
            scores,
        };
        store.publish_semgrep_run(&publication).await?;
        self.semgrep.journal.close(operation_id)?;
        Ok(operation_id)
    }

    /// Admit and start one explicit Semgrep enrichment without awaiting it.
    ///
    /// # Errors
    /// Returns a classified admission or durable staging/journal error.
    pub async fn start_semgrep_enrichment(
        &self,
        project: PathBuf,
        language: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError> {
        if !matches!(language, TargetLanguage::C | TargetLanguage::Cpp) {
            return Err(semgrep_validation("unsupported_language"));
        }

        let canonical_project = canonical_semgrep_project(&project)?;
        let store = self.store().cloned().ok_or_else(|| {
            ClassifiedError::Validation(
                "Semgrep enrichment requires the persistent service store".to_owned(),
            )
        })?;
        require_persisted_inventory(&store, &canonical_project, language).await?;

        self.authorize_recorded(
            Action::AnalyzeSource {
                analyzer: "semgrep".to_owned(),
            },
            "semgrep_enrichment",
            Some(&canonical_project),
        )
        .await?;

        let resolved_image = self
            .semgrep_runtime()
            .resolve_image_reference(SANDBOX_IMAGE)
            .await
            .map_err(|_| semgrep_sandbox("sandbox_unavailable"))?
            .ok_or_else(|| semgrep_sandbox("sandbox_unavailable"))?;

        let service = self.clone();
        let image_reference = resolved_image.reference().to_owned();
        let image_sha256 = resolved_image.sha256().to_owned();
        let (admission_sender, admission_receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let outcome = service
                .admit_semgrep_enrichment(
                    store,
                    canonical_project,
                    language,
                    image_reference,
                    image_sha256,
                )
                .await;
            let _ = admission_sender.send(outcome);
        });
        admission_receiver.await.map_err(|_| {
            ClassifiedError::Internal("Semgrep admission task stopped unexpectedly".to_owned())
        })?
    }

    async fn admit_semgrep_enrichment(
        &self,
        store: Arc<hf_storage::Store>,
        canonical_project: PathBuf,
        language: TargetLanguage,
        image_reference: String,
        image_sha256: String,
    ) -> Result<Uuid, ClassifiedError> {
        let workspace_lease = self.acquire_workspace_operation().await?;
        let project_lease = acquire_semgrep_project_lease(&canonical_project)?;
        self.semgrep.ensure_recovery_healthy()?;

        let operation_id = Uuid::new_v4();
        let cancellation = CancellationToken::new();
        self.semgrep
            .reserve(&canonical_project, operation_id, cancellation.clone())?;
        let active_guard = ActiveSemgrepGuard {
            coordinator: Arc::clone(&self.semgrep),
            project: canonical_project.clone(),
            operation_id,
        };
        #[cfg(test)]
        self.semgrep
            .pause_completion(CompletionPausePoint::AfterOwnershipBeforeDurableWrite)
            .await;

        let started_at = Utc::now();
        let run = SemgrepRunRecord {
            id: operation_id,
            project_root: canonical_project.to_string_lossy().into_owned(),
            language: language.as_str().to_owned(),
            source_sha256: None,
            sandbox_image: SANDBOX_IMAGE.to_owned(),
            sandbox_image_sha256: image_sha256.clone(),
            semgrep_version: SEMGREP_VERSION.to_owned(),
            rules_commit: RULES_COMMIT.to_owned(),
            rules_tree_sha256: rules_tree_sha256().to_owned(),
            command_schema_version: COMMAND_SCHEMA_VERSION,
            status: SemgrepRunStatus::Staging,
            started_at,
            ended_at: None,
            output_sha256: None,
            finding_count: None,
            matched_candidate_count: None,
            duration_ms: None,
            failure_code: None,
            failure_message: None,
        };
        if let Err(error) = insert_semgrep_run_with_retry(&store, &run).await {
            if error.to_string().contains("UNIQUE constraint failed") {
                return Err(semgrep_validation("busy"));
            }
            return Err(ClassifiedError::Storage(
                "Semgrep staging record could not be created".to_owned(),
            ));
        }
        #[cfg(test)]
        self.semgrep
            .pause_completion(CompletionPausePoint::AfterStagingInsertBeforeBegin)
            .await;

        if self
            .semgrep
            .journal
            .begin(operation_id, &canonical_project, &operation_id.to_string())
            .is_err()
        {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "journal_failed",
                "Semgrep recovery journal could not begin",
                None,
            )
            .await;
            return Err(ClassifiedError::Storage(
                "Semgrep recovery journal could not begin".to_owned(),
            ));
        }

        let service = self.clone();
        let project_digest = sha256_bytes(canonical_project.as_os_str().as_encoded_bytes());
        let language_name = language.as_str();
        let span = tracing::info_span!(
            "semgrep_enrichment",
            operation_id = %operation_id,
            project_identity_sha256 = %project_digest,
            language = language_name,
            source_sha256 = tracing::field::Empty,
            sandbox_image_sha256 = image_sha256,
            rules_tree_sha256 = rules_tree_sha256(),
            command_schema_version = COMMAND_SCHEMA_VERSION,
        );
        let operation_span = span.clone();
        tokio::spawn(
            async move {
                service
                    .run_semgrep_scan(
                        operation_id,
                        canonical_project,
                        language,
                        image_reference,
                        cancellation,
                        operation_span,
                        workspace_lease,
                        project_lease,
                        active_guard,
                    )
                    .await;
            }
            .instrument(span),
        );

        Ok(operation_id)
    }

    /// Read one service-owned Semgrep operation by UUID.
    ///
    /// # Errors
    /// Returns a storage error when the persisted operation cannot be loaded.
    pub async fn semgrep_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<SemgrepOperationView>, ClassifiedError> {
        let Some(store) = self.store() else {
            return Ok(None);
        };
        let Some(run) = store.semgrep_run(operation_id).await? else {
            return Ok(None);
        };
        #[cfg(test)]
        self.semgrep
            .pause_completion(CompletionPausePoint::AfterStatusParentLoad)
            .await;
        let mut state = operation_state(run.status);
        let result = if run.status != SemgrepRunStatus::Done {
            None
        } else if !matches!(self.semgrep.journal.is_closed(operation_id), Ok(true)) {
            state = SemgrepOperationState::Persisting;
            None
        } else if let Ok(result) = self.semgrep_result(operation_id).await {
            result
        } else {
            tracing::warn!(
                operation_id = %operation_id,
                failure_code = "semgrep_result_unavailable",
                "Semgrep result reconstruction was unavailable"
            );
            None
        };
        Ok(Some(SemgrepOperationView {
            operation_id: run.id,
            project_root: run.project_root,
            language: run.language,
            state,
            active: self.semgrep.is_active(operation_id),
            started_at: run.started_at.to_rfc3339(),
            ended_at: run.ended_at.map(|value| value.to_rfc3339()),
            failure_code: run.failure_code,
            failure_message: run.failure_message,
            result,
        }))
    }

    /// Build effective ranking from the latest completed publication only.
    ///
    /// This read never starts Semgrep and leaves candidate base scores
    /// immutable.
    pub async fn effective_inventory(
        &self,
        inventory: TargetInventory,
        language: TargetLanguage,
    ) -> Result<SemgrepInventoryView, ClassifiedError> {
        if !matches!(language, TargetLanguage::C | TargetLanguage::Cpp) {
            return Ok(base_inventory_view(inventory, language));
        }
        let publication = match self.store() {
            Some(store) => {
                store
                    .latest_semgrep_publication(
                        &inventory.project_root.to_string_lossy(),
                        language.as_str(),
                    )
                    .await?
            }
            None => None,
        };
        Ok(self.inventory_with_publication(inventory, language, publication, true))
    }

    /// Read the exact historical result for one completed operation UUID.
    ///
    /// This never substitutes a newer publication.
    pub async fn semgrep_result(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<SemgrepInventoryView>, ClassifiedError> {
        let Some(store) = self.store() else {
            return Ok(None);
        };
        let Some(publication) = store.semgrep_publication(operation_id).await? else {
            return Ok(None);
        };
        if publication.run.status != SemgrepRunStatus::Done {
            return Ok(None);
        }
        let language = publication
            .run
            .language
            .parse::<TargetLanguage>()
            .map_err(|_| semgrep_validation("unsupported_language"))?;
        let project = PathBuf::from(&publication.run.project_root);
        let mut inventory = load_current_inventory(store, &project, language, false).await?;
        let persisted_ids = inventory
            .candidates
            .iter()
            .map(|candidate| candidate.id)
            .collect::<BTreeSet<_>>();
        let scanner_ids_verified =
            hf_discovery::discover(&project, language)
                .await
                .is_ok_and(|scanned| {
                    let scanned_ids = scanned
                        .candidates
                        .iter()
                        .map(|candidate| candidate.id)
                        .collect::<BTreeSet<_>>();
                    if persisted_ids == scanned_ids {
                        inventory.call_graph = scanned.call_graph;
                        true
                    } else {
                        false
                    }
                });
        Ok(Some(self.inventory_with_publication(
            inventory,
            language,
            Some(publication),
            scanner_ids_verified,
        )))
    }

    fn inventory_with_publication(
        &self,
        inventory: TargetInventory,
        language: TargetLanguage,
        publication: Option<SemgrepPublication>,
        scanner_ids_verified: bool,
    ) -> SemgrepInventoryView {
        let Some(publication) = publication else {
            return base_inventory_view(inventory, language);
        };
        let mut view = base_inventory_view(inventory, language);
        view.scan_id = Some(publication.run.id);
        view.source_sha256
            .clone_from(&publication.run.source_sha256);
        view.findings = publication
            .findings
            .iter()
            .map(semgrep_finding_view)
            .collect();

        let journal_closed = self
            .semgrep
            .journal
            .is_closed(publication.run.id)
            .unwrap_or(false);
        if !journal_closed {
            view.overlay_state = SemgrepOverlayState::IncompleteJournal;
            return view;
        }
        let live_source = digest_live_sources(&view.project_root, language);
        if live_source.as_ref().ok() != publication.run.source_sha256.as_ref() {
            view.overlay_state = SemgrepOverlayState::StaleSource;
            return view;
        }
        if !scanner_ids_verified {
            view.overlay_state = SemgrepOverlayState::StaleBase;
            return view;
        }

        let candidate_ids = view
            .candidates
            .iter()
            .map(|candidate| candidate.candidate.id)
            .collect::<BTreeSet<_>>();
        let score_ids = publication
            .scores
            .iter()
            .map(|score| score.target_id)
            .collect::<BTreeSet<_>>();
        let base_by_id = view
            .candidates
            .iter()
            .map(|candidate| (candidate.candidate.id, candidate.base_score))
            .collect::<HashMap<_, _>>();
        if publication.scores.len() != view.candidates.len()
            || score_ids != candidate_ids
            || publication.scores.iter().any(|score| {
                base_by_id
                    .get(&score.target_id)
                    .is_none_or(|base| base.to_bits() != score.base_score.to_bits())
            })
        {
            view.overlay_state = SemgrepOverlayState::StaleBase;
            return view;
        }

        let scores = publication
            .scores
            .iter()
            .map(|score| (score.target_id, score))
            .collect::<HashMap<_, _>>();
        for target in &mut view.candidates {
            if let Some(score) = scores.get(&target.candidate.id) {
                target.semgrep_boost = score.boost;
                target.effective_score = score.effective_score;
                target.semgrep_matched_rule_count = score.matched_rule_count;
            }
        }
        view.overlay_state = SemgrepOverlayState::Current;
        sort_semgrep_targets(&mut view.candidates);
        view
    }

    /// Request cooperative cancellation for one service-owned operation UUID.
    ///
    /// # Errors
    /// Returns a storage error when operation ownership cannot be checked.
    pub async fn request_semgrep_cancel(
        &self,
        operation_id: Uuid,
    ) -> Result<SemgrepCancelOutcome, ClassifiedError> {
        let Some(store) = self.store() else {
            return Ok(SemgrepCancelOutcome::NotFound);
        };
        if store.semgrep_run(operation_id).await?.is_none() {
            return Ok(SemgrepCancelOutcome::NotFound);
        }
        if !self.semgrep.cancel(operation_id)? {
            return Ok(SemgrepCancelOutcome::Inactive);
        }
        Ok(SemgrepCancelOutcome::Accepted)
    }

    #[cfg(not(test))]
    fn claim_semgrep_completion(
        &self,
        canonical_project: &Path,
        operation_id: Uuid,
    ) -> std::future::Ready<bool> {
        std::future::ready(
            self.semgrep
                .claim_completion(canonical_project, operation_id),
        )
    }

    #[cfg(test)]
    async fn claim_semgrep_completion(&self, canonical_project: &Path, operation_id: Uuid) -> bool {
        self.semgrep
            .pause_completion(CompletionPausePoint::BeforeClaim)
            .await;
        let cancelled = self
            .semgrep
            .claim_completion(canonical_project, operation_id);
        self.semgrep
            .pause_completion(CompletionPausePoint::AfterClaim)
            .await;
        cancelled
    }

    async fn finish_semgrep_failure(
        &self,
        store: &hf_storage::Store,
        canonical_project: &Path,
        operation_id: Uuid,
        mut status: SemgrepRunStatus,
        mut code: &str,
        mut message: &str,
        operation_root: Option<&Path>,
    ) {
        if self
            .claim_semgrep_completion(canonical_project, operation_id)
            .await
        {
            status = SemgrepRunStatus::Cancelled;
            code = "cancelled";
            message = "Semgrep enrichment was cancelled";
        }
        fail_semgrep_operation(
            store,
            &self.semgrep,
            operation_id,
            status,
            code,
            message,
            operation_root,
        )
        .await;
    }

    async fn run_semgrep_scan(
        &self,
        operation_id: Uuid,
        canonical_project: PathBuf,
        language: TargetLanguage,
        image_reference: String,
        cancellation: CancellationToken,
        operation_span: tracing::Span,
        workspace_lease: crate::container::WorkspaceOperationLease,
        project_lease: SemgrepProjectLease,
        active_guard: ActiveSemgrepGuard,
    ) {
        let _workspace_lease = workspace_lease;
        let _project_lease = project_lease;
        let _active = active_guard;
        let Some(store) = self.store().cloned() else {
            return;
        };
        if cancellation.is_cancelled() {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Cancelled,
                "cancelled",
                "Semgrep enrichment was cancelled",
                None,
            )
            .await;
            return;
        }
        let Ok(inventory) =
            load_current_inventory(&store, &canonical_project, language, true).await
        else {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "inventory_missing",
                "Semgrep persisted inventory could not be loaded",
                None,
            )
            .await;
            return;
        };

        let staging_started = std::time::Instant::now();
        let Ok(snapshot) = stage_source_snapshot(&canonical_project, language, operation_id) else {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "snapshot_invalid",
                "Semgrep source snapshot could not be staged",
                None,
            )
            .await;
            return;
        };
        operation_span.record("source_sha256", snapshot.source_sha256.as_str());
        tracing::info!(
            stage = "staging",
            duration_ms = elapsed_millis(staging_started),
            file_count = snapshot.file_count,
            total_bytes = snapshot.total_bytes,
            "Semgrep stage complete"
        );
        #[cfg(test)]
        self.semgrep
            .pause_completion(CompletionPausePoint::AfterBegin)
            .await;
        if cancellation.is_cancelled() {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Cancelled,
                "cancelled",
                "Semgrep enrichment was cancelled",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        if set_semgrep_phase_with_retry(
            &store,
            operation_id,
            SemgrepRunStatus::Staging,
            SemgrepRunStatus::Scanning,
            Some(&snapshot.source_sha256),
        )
        .await
        .is_err()
        {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep scanning phase could not be recorded",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }

        let limits = ResourceLimits {
            max_mem_mb: 4_096,
            max_cpus: 2,
            max_duration_secs: 600,
            env: HashMap::new(),
            ptrace: false,
        };
        let options = SandboxOptions {
            extra_mounts: vec![
                SandboxMount::read_only(snapshot.source_dir.clone(), "/work/source"),
                SandboxMount::writable(snapshot.output_dir.clone(), "/work/output"),
            ],
            image: Some(image_reference),
            platform: None,
            network_mode: SandboxNetworkMode::None,
            workdir: None,
            relax_hardening: false,
            capabilities: Vec::new(),
            stdin: None,
            devices: Vec::new(),
            workspace_read_only: true,
            max_file_size_bytes: Some(MAX_SEMGREP_OUTPUT_BYTES),
            max_pids: Some(128),
        };
        let execution_started = std::time::Instant::now();
        let command = [SEMGREP_COMMAND.to_owned()];
        let result = self
            .semgrep_runtime()
            .run_command_streaming_opts(
                &command,
                &snapshot.operation_root,
                &limits,
                &options,
                &cancellation,
                &|_| {},
            )
            .await;
        tracing::info!(
            stage = "execution",
            duration_ms = elapsed_millis(execution_started),
            "Semgrep sandbox execution complete"
        );

        let Ok(result) = result else {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "sandbox_unavailable",
                "Semgrep sandbox execution failed",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        };
        match result.termination {
            CommandTermination::Cancelled => {
                tracing::info!(stage = "cancellation", count = 1_u64, "Semgrep cancelled");
                self.finish_semgrep_failure(
                    &store,
                    &canonical_project,
                    operation_id,
                    SemgrepRunStatus::Cancelled,
                    "cancelled",
                    "Semgrep enrichment was cancelled",
                    Some(&snapshot.operation_root),
                )
                .await;
                return;
            }
            CommandTermination::TimedOut => {
                tracing::info!(stage = "timeout", count = 1_u64, "Semgrep timed out");
                self.finish_semgrep_failure(
                    &store,
                    &canonical_project,
                    operation_id,
                    SemgrepRunStatus::Failed,
                    "timeout",
                    "Semgrep sandbox execution timed out",
                    Some(&snapshot.operation_root),
                )
                .await;
                return;
            }
            CommandTermination::Completed => {}
        }
        if cancellation.is_cancelled() {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Cancelled,
                "cancelled",
                "Semgrep enrichment was cancelled",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        if result.exit_code != 0 {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "tool_exit",
                "Semgrep wrapper returned a non-zero exit status",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        if captured_output_was_truncated(&result.stdout)
            || captured_output_was_truncated(&result.stderr)
        {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "output_invalid",
                "Semgrep captured output was truncated",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        let output_bytes = match read_semgrep_output(&snapshot.output_dir) {
            Ok(bytes) => bytes,
            Err(failure) => {
                self.finish_semgrep_failure(
                    &store,
                    &canonical_project,
                    operation_id,
                    SemgrepRunStatus::Failed,
                    failure.code,
                    failure.message,
                    Some(&snapshot.operation_root),
                )
                .await;
                return;
            }
        };
        if self
            .claim_semgrep_completion(&canonical_project, operation_id)
            .await
        {
            fail_semgrep_operation(
                &store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Cancelled,
                "cancelled",
                "Semgrep enrichment was cancelled",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        if set_semgrep_phase_with_retry(
            &store,
            operation_id,
            SemgrepRunStatus::Scanning,
            SemgrepRunStatus::Validating,
            None,
        )
        .await
        .is_err()
        {
            fail_semgrep_operation(
                &store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep validation phase could not be recorded",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        self.complete_semgrep_publication(
            &store,
            operation_id,
            &canonical_project,
            language,
            &inventory,
            &snapshot,
            &output_bytes,
        )
        .await;
    }

    async fn complete_semgrep_publication(
        &self,
        store: &hf_storage::Store,
        operation_id: Uuid,
        canonical_project: &Path,
        language: TargetLanguage,
        inventory: &TargetInventory,
        snapshot: &SourceSnapshot,
        output_bytes: &[u8],
    ) {
        let output_sha256 = sha256_bytes(output_bytes);
        let Ok(findings) =
            hf_discovery::semgrep::parse_findings(output_bytes, &snapshot.relative_paths)
        else {
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "output_invalid",
                "Semgrep output failed strict validation",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        };
        let Ok(analysis) = hf_discovery::semgrep::map_and_score(inventory, findings) else {
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "mapping_failed",
                "Semgrep findings could not be mapped to the persisted inventory",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        };
        if !matches!(
            digest_live_sources(canonical_project, language),
            Ok(digest) if digest == snapshot.source_sha256
        ) {
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "source_changed",
                "Eligible source changed before Semgrep publication",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        if set_semgrep_phase_with_retry(
            store,
            operation_id,
            SemgrepRunStatus::Validating,
            SemgrepRunStatus::Persisting,
            None,
        )
        .await
        .is_err()
        {
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep persisting phase could not be recorded",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }

        let ready = crate::semgrep_recovery::SemgrepReadyRecord {
            source_sha256: snapshot.source_sha256.clone(),
            output_sha256: output_sha256.clone(),
            sandbox_image_sha256: if let Ok(Some(run)) = store.semgrep_run(operation_id).await {
                run.sandbox_image_sha256
            } else {
                self.semgrep
                    .mark_recovery_degraded("Semgrep provenance could not be reloaded");
                return;
            },
            rules_tree_sha256: rules_tree_sha256().to_owned(),
            command_schema_version: COMMAND_SCHEMA_VERSION,
        };
        if let Err(error) = self.semgrep.journal.ready_to_commit(operation_id, &ready) {
            self.semgrep.mark_recovery_degraded(&error);
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "journal_failed",
                "Semgrep recovery journal could not record validated provenance",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }

        let Ok(publication) =
            build_semgrep_publication(store, operation_id, analysis, output_sha256).await
        else {
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep publication records could not be built",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        };
        if store.publish_semgrep_run(&publication).await.is_err() {
            #[cfg(test)]
            self.semgrep
                .pause_completion(CompletionPausePoint::AfterPublicationFailure)
                .await;
            fail_semgrep_operation(
                store,
                &self.semgrep,
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep publication transaction failed",
                Some(&snapshot.operation_root),
            )
            .await;
            return;
        }
        #[cfg(test)]
        self.semgrep
            .pause_completion(CompletionPausePoint::AfterPublicationBeforeCleanup)
            .await;
        #[cfg(test)]
        let cleanup_result = if self.semgrep.take_test_cleanup_failure() {
            Err(snapshot_validation("injected Semgrep cleanup failure"))
        } else {
            cleanup_operation_root(&snapshot.operation_root)
        };
        #[cfg(not(test))]
        let cleanup_result = cleanup_operation_root(&snapshot.operation_root);
        if let Err(cleanup_error) = cleanup_result {
            self.semgrep.mark_recovery_degraded(&cleanup_error);
            if store
                .compensate_semgrep_publication(
                    operation_id,
                    "cleanup_failed",
                    "Semgrep staged artifacts could not be removed safely",
                    Utc::now(),
                )
                .await
                .is_err()
            {
                self.semgrep
                    .mark_recovery_degraded("Semgrep cleanup compensation failed");
            }
            tracing::error!(
                operation_id = %operation_id,
                failure_code = "cleanup_failed",
                "Semgrep publication cleanup failed and recovery is degraded"
            );
            return;
        }
        #[cfg(test)]
        self.semgrep
            .pause_completion(CompletionPausePoint::BeforeClose)
            .await;
        let close_result = self.semgrep.journal.close(operation_id);
        #[cfg(test)]
        if close_result.is_ok() {
            self.semgrep
                .pause_completion(CompletionPausePoint::AfterCloseBeforeLeaseRelease)
                .await;
        }
        if let Err(error) = close_result {
            self.semgrep.mark_recovery_degraded(error);
        }
    }
}

struct OutputFailure {
    code: &'static str,
    message: &'static str,
}

async fn build_semgrep_publication(
    store: &hf_storage::Store,
    operation_id: Uuid,
    analysis: hf_discovery::semgrep::SemgrepAnalysis,
    output_sha256: String,
) -> Result<SemgrepPublication, ClassifiedError> {
    let mut run = store
        .semgrep_run(operation_id)
        .await?
        .ok_or_else(|| ClassifiedError::Storage("Semgrep operation disappeared".to_owned()))?;
    let ended_at = Utc::now();
    let duration_ms = ended_at
        .signed_duration_since(run.started_at)
        .num_milliseconds()
        .max(0)
        .try_into()
        .map_err(|_| ClassifiedError::Storage("Semgrep duration overflowed".to_owned()))?;
    let finding_count = u32::try_from(analysis.findings.len())
        .map_err(|_| ClassifiedError::Storage("Semgrep finding count overflowed".to_owned()))?;
    run.status = SemgrepRunStatus::Done;
    run.ended_at = Some(ended_at);
    run.output_sha256 = Some(output_sha256);
    run.finding_count = Some(finding_count);
    run.matched_candidate_count = Some(analysis.matched_candidate_count);
    run.duration_ms = Some(duration_ms);
    run.failure_code = None;
    run.failure_message = None;

    let findings = analysis
        .findings
        .into_iter()
        .map(|finding| SemgrepFindingRecord {
            scan_id: operation_id,
            fingerprint: finding.fingerprint,
            rule_id: finding.rule_id,
            severity: match finding.severity {
                hf_discovery::semgrep::SemgrepSeverity::Error => SemgrepFindingSeverity::Error,
                hf_discovery::semgrep::SemgrepSeverity::Warning => SemgrepFindingSeverity::Warning,
                hf_discovery::semgrep::SemgrepSeverity::Info => SemgrepFindingSeverity::Info,
            },
            message: finding.message,
            relative_file: finding.relative_path.to_string_lossy().into_owned(),
            start_line: finding.range.start_line,
            start_col: finding.range.start_col,
            end_line: finding.range.end_line,
            end_col: finding.range.end_col,
            target_id: finding.matched_target_id,
            nominal_weight: finding.nominal_weight,
        })
        .collect();
    let scores = analysis
        .scores
        .into_iter()
        .map(|score| SemgrepTargetScoreRecord {
            scan_id: operation_id,
            target_id: score.target_id,
            base_score: score.base_score,
            boost: score.boost,
            effective_score: score.effective_score,
            matched_rule_count: score.matched_rule_count,
        })
        .collect();
    Ok(SemgrepPublication {
        run,
        findings,
        scores,
    })
}

async fn require_persisted_inventory(
    store: &hf_storage::Store,
    canonical_project: &Path,
    language: TargetLanguage,
) -> Result<(), ClassifiedError> {
    let inventory = load_current_inventory(store, canonical_project, language, true).await?;
    if inventory.candidates.iter().any(|candidate| {
        candidate.location.end_line.is_none() || candidate.location.end_col.is_none()
    }) {
        return Err(semgrep_validation("inventory_span_incomplete"));
    }
    Ok(())
}

async fn load_current_inventory(
    store: &hf_storage::Store,
    canonical_project: &Path,
    language: TargetLanguage,
    require_nonempty: bool,
) -> Result<TargetInventory, ClassifiedError> {
    let candidates = store
        .list_all_targets()
        .await?
        .into_iter()
        .filter(|candidate| {
            candidate.language == language
                && canonical_stored_project(&candidate.project_root, canonical_project)
        })
        .collect::<Vec<_>>();
    if require_nonempty && candidates.is_empty() {
        return Err(semgrep_validation("inventory_missing"));
    }
    Ok(TargetInventory {
        project_root: canonical_project.to_path_buf(),
        candidates,
        call_graph: HashMap::new(),
    })
}

fn canonical_stored_project(stored: &Path, canonical: &Path) -> bool {
    stored == canonical || std::fs::canonicalize(stored).is_ok_and(|resolved| resolved == canonical)
}

fn canonical_semgrep_project(project: &Path) -> Result<PathBuf, ClassifiedError> {
    let canonical =
        std::fs::canonicalize(project).map_err(|_| semgrep_validation("project_invalid"))?;
    let metadata =
        std::fs::symlink_metadata(&canonical).map_err(|_| semgrep_validation("project_invalid"))?;
    if !metadata.file_type().is_dir() {
        return Err(semgrep_validation("project_invalid"));
    }
    Ok(canonical)
}

fn operation_state(status: SemgrepRunStatus) -> SemgrepOperationState {
    match status {
        SemgrepRunStatus::Staging => SemgrepOperationState::Staging,
        SemgrepRunStatus::Scanning => SemgrepOperationState::Scanning,
        SemgrepRunStatus::Validating => SemgrepOperationState::Validating,
        SemgrepRunStatus::Persisting => SemgrepOperationState::Persisting,
        SemgrepRunStatus::Done => SemgrepOperationState::Done,
        SemgrepRunStatus::Failed => SemgrepOperationState::Failed,
        SemgrepRunStatus::Cancelled => SemgrepOperationState::Cancelled,
    }
}

fn base_inventory_view(
    inventory: TargetInventory,
    language: TargetLanguage,
) -> SemgrepInventoryView {
    let mut candidates = inventory
        .candidates
        .into_iter()
        .map(|candidate| {
            let base_score = candidate.fit_score;
            SemgrepTargetView {
                candidate,
                base_score,
                semgrep_boost: 0.0,
                effective_score: base_score,
                semgrep_matched_rule_count: 0,
            }
        })
        .collect::<Vec<_>>();
    sort_semgrep_targets(&mut candidates);
    SemgrepInventoryView {
        project_root: inventory.project_root,
        language,
        scan_id: None,
        source_sha256: None,
        overlay_state: SemgrepOverlayState::None,
        candidates,
        findings: Vec::new(),
        call_graph: inventory.call_graph,
    }
}

fn sort_semgrep_targets(candidates: &mut [SemgrepTargetView]) {
    candidates.sort_by(|left, right| {
        right
            .effective_score
            .total_cmp(&left.effective_score)
            .then_with(|| right.base_score.total_cmp(&left.base_score))
            .then_with(|| {
                left.candidate
                    .relative_file()
                    .cmp(&right.candidate.relative_file())
            })
            .then_with(|| left.candidate.symbol.cmp(&right.candidate.symbol))
            .then_with(|| left.candidate.id.cmp(&right.candidate.id))
    });
}

fn semgrep_finding_view(finding: &SemgrepFindingRecord) -> SemgrepFindingView {
    SemgrepFindingView {
        fingerprint: finding.fingerprint.clone(),
        rule_id: finding.rule_id.clone(),
        severity: match finding.severity {
            SemgrepFindingSeverity::Error => "error",
            SemgrepFindingSeverity::Warning => "warning",
            SemgrepFindingSeverity::Info => "info",
        }
        .to_owned(),
        message: finding.message.clone(),
        relative_file: PathBuf::from(&finding.relative_file),
        start_line: finding.start_line,
        start_col: finding.start_col,
        end_line: finding.end_line,
        end_col: finding.end_col,
        matched_target_id: finding.target_id,
        nominal_weight: finding.nominal_weight,
    }
}

fn rules_tree_sha256() -> &'static str {
    include_str!("../../../third_party/semgrep-rules/RULES_SHA256").trim()
}

fn captured_output_was_truncated(output: &str) -> bool {
    output.contains(OUTPUT_TRUNCATION_MARKER) || output.contains(LINE_TRUNCATION_MARKER)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn elapsed_millis(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn semgrep_validation(code: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!("Semgrep enrichment: {}", bounded_bytes(code, 64)))
}

fn semgrep_sandbox(code: &str) -> ClassifiedError {
    ClassifiedError::Sandbox(format!("Semgrep enrichment: {}", bounded_bytes(code, 64)))
}

fn bounded_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

async fn fail_semgrep_operation(
    store: &hf_storage::Store,
    coordinator: &SemgrepCoordinator,
    operation_id: Uuid,
    status: SemgrepRunStatus,
    code: &str,
    message: &str,
    operation_root: Option<&Path>,
) {
    let code = bounded_bytes(code, 64);
    let message = bounded_bytes(message, 1_024);
    let mut persisted = false;
    for attempt in 0..20_u32 {
        match store
            .fail_semgrep_run(operation_id, status, &code, &message, Utc::now())
            .await
        {
            Ok(()) => {
                persisted = true;
                break;
            }
            Err(error) if storage_is_busy(&error) && attempt < 19 => {
                tokio::time::sleep(std::time::Duration::from_millis(
                    5_u64.saturating_mul(u64::from(attempt + 1)),
                ))
                .await;
            }
            Err(_) => break,
        }
    }
    if !persisted {
        coordinator.mark_recovery_degraded("Semgrep terminal state could not be persisted");
        tracing::error!(
            operation_id = %operation_id,
            failure_code = "persistence_failed",
            "Semgrep terminal state could not be persisted"
        );
        return;
    }

    let owned_operation_root = match operation_root {
        Some(path) => path.to_path_buf(),
        None => match crate::container::initialize_workspace_root() {
            Ok(workspace) => workspace.join("semgrep").join(operation_id.to_string()),
            Err(error) => {
                coordinator.mark_recovery_degraded(error);
                return;
            }
        },
    };
    if let Err(error) = cleanup_operation_root(&owned_operation_root) {
        coordinator.mark_recovery_degraded(error);
        return;
    }
    let abort_kind = match status {
        SemgrepRunStatus::Cancelled => crate::semgrep_recovery::SemgrepAbortKind::Cancelled,
        _ => crate::semgrep_recovery::SemgrepAbortKind::Failed,
    };
    if let Err(error) = coordinator.journal.abort(operation_id, abort_kind) {
        coordinator.mark_recovery_degraded(error);
    }
}

async fn set_semgrep_phase_with_retry(
    store: &hf_storage::Store,
    operation_id: Uuid,
    expected: SemgrepRunStatus,
    next: SemgrepRunStatus,
    source_sha256: Option<&str>,
) -> Result<(), hf_storage::StorageError> {
    for attempt in 0..20_u32 {
        match store
            .set_semgrep_phase(operation_id, expected, next, source_sha256)
            .await
        {
            Ok(()) => return Ok(()),
            Err(error) if storage_is_busy(&error) && attempt < 19 => {
                tokio::time::sleep(std::time::Duration::from_millis(
                    5_u64.saturating_mul(u64::from(attempt + 1)),
                ))
                .await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(hf_storage::StorageError::InvalidData(
        "Semgrep phase retry budget exhausted".to_owned(),
    ))
}

async fn insert_semgrep_run_with_retry(
    store: &hf_storage::Store,
    run: &SemgrepRunRecord,
) -> Result<(), hf_storage::StorageError> {
    for attempt in 0..20_u32 {
        match store.insert_semgrep_run(run).await {
            Ok(()) => return Ok(()),
            Err(error) if storage_is_busy(&error) && attempt < 19 => {
                tokio::time::sleep(std::time::Duration::from_millis(
                    5_u64.saturating_mul(u64::from(attempt + 1)),
                ))
                .await;
            }
            Err(error) => return Err(error),
        }
    }
    Err(hf_storage::StorageError::InvalidData(
        "Semgrep staging retry budget exhausted".to_owned(),
    ))
}

fn storage_is_busy(error: &hf_storage::StorageError) -> bool {
    let message = error.to_string();
    message.contains("database is locked") || message.contains("database table is locked")
}

#[cfg(unix)]
fn read_semgrep_output(output_dir: &Path) -> Result<Vec<u8>, OutputFailure> {
    use rustix::fs::{openat, Mode, OFlags};

    let directory =
        open_directory_path_nofollow(output_dir, "Semgrep output directory").map_err(|_| {
            OutputFailure {
                code: "output_invalid",
                message: "Semgrep output directory is invalid",
            }
        })?;
    let descriptor = match openat(
        &directory,
        SEMGREP_OUTPUT_FILE,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => {
            return Err(OutputFailure {
                code: "output_missing",
                message: "Semgrep output file is missing",
            });
        }
        Err(_) => {
            return Err(OutputFailure {
                code: "output_invalid",
                message: "Semgrep output file is not a regular owned file",
            });
        }
    };
    read_bounded_output(File::from(descriptor))
}

#[cfg(not(unix))]
fn read_semgrep_output(_output_dir: &Path) -> Result<Vec<u8>, OutputFailure> {
    Err(OutputFailure {
        code: "output_invalid",
        message: "Semgrep output requires descriptor-safe filesystem access",
    })
}

fn read_bounded_output(mut file: File) -> Result<Vec<u8>, OutputFailure> {
    let metadata = file.metadata().map_err(|_| OutputFailure {
        code: "output_invalid",
        message: "Semgrep output metadata is unavailable",
    })?;
    if !metadata.file_type().is_file() {
        return Err(OutputFailure {
            code: "output_invalid",
            message: "Semgrep output is not a regular file",
        });
    }
    if metadata.len() > MAX_SEMGREP_OUTPUT_BYTES {
        return Err(OutputFailure {
            code: "output_too_large",
            message: "Semgrep output exceeds the fixed 64 MiB limit",
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    Read::by_ref(&mut file)
        .take(MAX_SEMGREP_OUTPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| OutputFailure {
            code: "output_invalid",
            message: "Semgrep output could not be read",
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SEMGREP_OUTPUT_BYTES {
        return Err(OutputFailure {
            code: "output_too_large",
            message: "Semgrep output exceeds the fixed 64 MiB limit",
        });
    }
    let after = file.metadata().map_err(|_| OutputFailure {
        code: "output_invalid",
        message: "Semgrep output metadata changed while reading",
    })?;
    if after.len() != metadata.len() {
        return Err(OutputFailure {
            code: "output_invalid",
            message: "Semgrep output changed while reading",
        });
    }
    Ok(bytes)
}

/// A service-owned immutable source tree prepared for one Semgrep operation.
#[derive(Debug)]
pub struct SourceSnapshot {
    /// Exact `<managed-workspace>/semgrep/<operation-uuid>` ownership root.
    pub operation_root: PathBuf,
    /// Read-only container input tree populated with normalized relative paths.
    pub source_dir: PathBuf,
    /// Operation-owned writable container output directory.
    pub output_dir: PathBuf,
    /// Sorted staged project-relative source manifest.
    pub relative_paths: BTreeSet<PathBuf>,
    /// Stable ordered path-and-content SHA-256 revision.
    pub source_sha256: String,
    /// Number of regular source files in the complete snapshot.
    pub file_count: usize,
    /// Aggregate source bytes in the complete snapshot.
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug)]
struct SnapshotLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_relative_path_bytes: usize,
}

const SNAPSHOT_LIMITS: SnapshotLimits = SnapshotLimits {
    max_files: 25_000,
    max_file_bytes: 2 * 1024 * 1024,
    max_total_bytes: 512 * 1024 * 1024,
    max_relative_path_bytes: 4_096,
};

/// Stage the canonical C/C++ discovery source set below the managed workspace.
///
/// # Errors
/// Returns an error if the project or any source is unsafe, unstable, or over
/// the fixed bounds, or if an operation-owned directory cannot be created.
pub fn stage_source_snapshot(
    canonical_project: &Path,
    language: TargetLanguage,
    operation_id: Uuid,
) -> Result<SourceSnapshot, ClassifiedError> {
    let workspace = crate::container::initialize_workspace_root()?;
    stage_source_snapshot_at_with_limits(
        canonical_project,
        language,
        operation_id,
        &workspace,
        SNAPSHOT_LIMITS,
    )
}

/// Digest the live canonical C/C++ discovery source set without staging it.
///
/// # Errors
/// Returns an error if the source set is unsupported, unsafe, unstable, or
/// exceeds the same fixed limits used for staging.
pub fn digest_live_sources(
    canonical_project: &Path,
    language: TargetLanguage,
) -> Result<String, ClassifiedError> {
    digest_live_sources_with_limits(canonical_project, language, SNAPSHOT_LIMITS)
}

/// Remove one validated Semgrep operation directory below the managed workspace.
///
/// # Errors
/// Returns an error if the managed path is absent, symlinked, ambiguous, or
/// does not have the exact `<workspace>/semgrep/<uuid>` ownership shape.
pub fn cleanup_operation_root(operation_root: &Path) -> Result<(), ClassifiedError> {
    let workspace = crate::container::initialize_workspace_root()?;
    cleanup_operation_root_in(&workspace, operation_root)
}

fn stage_source_snapshot_at_with_limits(
    canonical_project: &Path,
    language: TargetLanguage,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
) -> Result<SourceSnapshot, ClassifiedError> {
    let selected = hf_discovery::discoverable_source_files(canonical_project, language)?;
    stage_selected_paths_at_with_limits(
        canonical_project,
        selected,
        operation_id,
        managed_workspace,
        limits,
    )
}

fn stage_selected_paths_at_with_limits(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
) -> Result<SourceSnapshot, ClassifiedError> {
    stage_selected_paths_at_with_hooks(
        canonical_project,
        relative_paths,
        operation_id,
        managed_workspace,
        limits,
        |_| {},
        || {},
    )
}

#[cfg(test)]
fn stage_selected_paths_at_with_hook<F>(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
    after_read: F,
) -> Result<SourceSnapshot, ClassifiedError>
where
    F: FnOnce(),
{
    stage_selected_paths_at_with_hooks(
        canonical_project,
        relative_paths,
        operation_id,
        managed_workspace,
        limits,
        |_| {},
        after_read,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageMutationPoint {
    SemgrepRoot,
    OperationRoot,
    SourceRoot,
    DestinationParent,
}

#[cfg(test)]
fn stage_selected_paths_at_with_stage_hook<H>(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
    stage_hook: H,
) -> Result<SourceSnapshot, ClassifiedError>
where
    H: FnMut(StageMutationPoint),
{
    stage_selected_paths_at_with_hooks(
        canonical_project,
        relative_paths,
        operation_id,
        managed_workspace,
        limits,
        stage_hook,
        || {},
    )
}

fn stage_selected_paths_at_with_hooks<H, F>(
    canonical_project: &Path,
    relative_paths: Vec<PathBuf>,
    operation_id: Uuid,
    managed_workspace: &Path,
    limits: SnapshotLimits,
    mut stage_hook: H,
    after_read: F,
) -> Result<SourceSnapshot, ClassifiedError>
where
    H: FnMut(StageMutationPoint),
    F: FnOnce(),
{
    validate_canonical_directory(canonical_project, "project root")?;
    if relative_paths.len() > limits.max_files {
        return Err(snapshot_validation(format!(
            "snapshot file count exceeds {}",
            limits.max_files
        )));
    }

    let mut selected = BTreeMap::new();
    for relative in relative_paths {
        let normalized = normalized_relative_path_bytes(&relative)?;
        if normalized.len() > limits.max_relative_path_bytes {
            return Err(snapshot_validation(format!(
                "snapshot relative path exceeds {} bytes",
                limits.max_relative_path_bytes
            )));
        }
        if selected.insert(normalized, relative).is_some() {
            return Err(snapshot_validation(
                "snapshot source set contains a duplicate relative path",
            ));
        }
    }

    let workspace = validate_canonical_directory(managed_workspace, "managed workspace")?;
    let workspace_descriptor = open_directory_path_nofollow(&workspace, "managed workspace")?;
    verify_directory_path_identity(&workspace, &workspace_descriptor, "managed workspace")?;
    let semgrep_root = workspace.join("semgrep");
    let semgrep_descriptor = open_or_create_directory_at(&workspace_descriptor, "semgrep", true)?;
    stage_hook(StageMutationPoint::SemgrepRoot);
    verify_directory_path_identity(&workspace, &workspace_descriptor, "managed workspace")?;
    verify_directory_path_identity(&semgrep_root, &semgrep_descriptor, "Semgrep workspace")?;
    let operation_root = semgrep_root.join(operation_id.to_string());
    let source_dir = operation_root.join("source");
    let output_dir = operation_root.join("output");
    let operation_descriptor = create_new_directory_at(
        &semgrep_descriptor,
        operation_id.to_string().as_str(),
        "Semgrep operation directory",
    )?;

    let staged = (|| {
        stage_hook(StageMutationPoint::OperationRoot);
        verify_staging_directory_chain(
            &workspace,
            &workspace_descriptor,
            &semgrep_root,
            &semgrep_descriptor,
            &operation_root,
            &operation_descriptor,
        )?;
        let source_descriptor =
            create_new_directory_at(&operation_descriptor, "source", "snapshot source directory")?;
        stage_hook(StageMutationPoint::SourceRoot);
        verify_staging_directory_chain(
            &workspace,
            &workspace_descriptor,
            &semgrep_root,
            &semgrep_descriptor,
            &operation_root,
            &operation_descriptor,
        )?;
        verify_directory_path_identity(&source_dir, &source_descriptor, "snapshot source")?;
        let output_descriptor =
            create_new_directory_at(&operation_descriptor, "output", "snapshot output directory")?;
        verify_directory_path_identity(&output_dir, &output_descriptor, "snapshot output")?;
        let mut hasher = Sha256::new();
        let mut total_bytes = 0_u64;
        let mut after_read = Some(after_read);
        let mut manifest = BTreeSet::new();

        for (normalized_path, relative) in selected {
            let remaining = limits
                .max_total_bytes
                .checked_sub(total_bytes)
                .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
            let allowance = limits.max_file_bytes.min(remaining);
            let bytes = if let Some(hook) = after_read.take() {
                read_stable_source(canonical_project, &relative, allowance, hook)?
            } else {
                read_stable_source(canonical_project, &relative, allowance, || {})?
            };
            let file_bytes = u64::try_from(bytes.len())
                .map_err(|_| snapshot_validation("snapshot file length cannot be represented"))?;
            total_bytes = total_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
            let (parent_descriptor, parent_path, leaf) =
                open_or_create_destination_parent(&source_descriptor, &source_dir, &relative)?;
            stage_hook(StageMutationPoint::DestinationParent);
            verify_staging_directory_chain(
                &workspace,
                &workspace_descriptor,
                &semgrep_root,
                &semgrep_descriptor,
                &operation_root,
                &operation_descriptor,
            )?;
            verify_directory_path_identity(&source_dir, &source_descriptor, "snapshot source")?;
            verify_directory_path_identity(
                &parent_path,
                &parent_descriptor,
                "snapshot destination parent",
            )?;
            write_new_owned_file_at(&parent_descriptor, &leaf, &bytes)?;
            verify_directory_path_identity(
                &parent_path,
                &parent_descriptor,
                "snapshot destination parent",
            )?;
            hash_path_and_bytes(&mut hasher, &normalized_path, &bytes);
            manifest.insert(relative);
        }
        verify_directory_path_identity(&source_dir, &source_descriptor, "snapshot source")?;
        verify_directory_path_identity(&output_dir, &output_descriptor, "snapshot output")?;

        Ok(SourceSnapshot {
            operation_root: operation_root.clone(),
            source_dir,
            output_dir,
            file_count: manifest.len(),
            total_bytes,
            relative_paths: manifest,
            source_sha256: hex::encode(hasher.finalize()),
        })
    })();

    match staged {
        Ok(snapshot) => Ok(snapshot),
        Err(error) => match cleanup_operation_root_in(&workspace, &operation_root) {
            Ok(()) => Err(error),
            Err(cleanup) => Err(append_error_context(
                error,
                &format!("snapshot cleanup failed: {cleanup}"),
            )),
        },
    }
}

fn digest_live_sources_with_limits(
    canonical_project: &Path,
    language: TargetLanguage,
    limits: SnapshotLimits,
) -> Result<String, ClassifiedError> {
    digest_live_sources_with_limits_and_read_hook(canonical_project, language, limits, |_| {})
}

fn digest_live_sources_with_limits_and_read_hook<H>(
    canonical_project: &Path,
    language: TargetLanguage,
    limits: SnapshotLimits,
    mut before_read: H,
) -> Result<String, ClassifiedError>
where
    H: FnMut(&Path),
{
    validate_canonical_directory(canonical_project, "project root")?;
    let relative_paths = hf_discovery::discoverable_source_files(canonical_project, language)?;
    if relative_paths.len() > limits.max_files {
        return Err(snapshot_validation(format!(
            "snapshot file count exceeds {}",
            limits.max_files
        )));
    }

    let mut sources = Vec::with_capacity(relative_paths.len());
    let mut total_bytes = 0_u64;
    for relative in relative_paths {
        let normalized = normalized_relative_path_bytes(&relative)?;
        if normalized.len() > limits.max_relative_path_bytes {
            return Err(snapshot_validation(format!(
                "snapshot relative path exceeds {} bytes",
                limits.max_relative_path_bytes
            )));
        }
        let remaining = limits
            .max_total_bytes
            .checked_sub(total_bytes)
            .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
        let allowance = limits.max_file_bytes.min(remaining);
        let bytes = read_stable_source_with_hooks(
            canonical_project,
            &relative,
            allowance,
            || before_read(&relative),
            || {},
        )?;
        let file_bytes = u64::try_from(bytes.len())
            .map_err(|_| snapshot_validation("snapshot file length cannot be represented"))?;
        total_bytes = total_bytes
            .checked_add(file_bytes)
            .ok_or_else(|| snapshot_validation("snapshot aggregate byte count overflowed"))?;
        sources.push((relative, bytes));
    }
    digest_ordered_sources(sources)
}

fn digest_ordered_sources(sources: Vec<(PathBuf, Vec<u8>)>) -> Result<String, ClassifiedError> {
    let mut ordered = BTreeMap::new();
    for (path, bytes) in sources {
        let normalized = normalized_relative_path_bytes(&path)?;
        if ordered.insert(normalized, bytes).is_some() {
            return Err(snapshot_validation(
                "snapshot digest input contains a duplicate path",
            ));
        }
    }
    let mut hasher = Sha256::new();
    for (path, bytes) in ordered {
        hash_path_and_bytes(&mut hasher, &path, &bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_path_and_bytes(hasher: &mut Sha256, path: &[u8], bytes: &[u8]) {
    hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(path);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn normalized_relative_path_bytes(path: &Path) -> Result<Vec<u8>, ClassifiedError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(snapshot_validation("snapshot relative path is unsafe"));
    }
    let mut normalized = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(snapshot_validation("snapshot relative path is unsafe"));
        };
        let name = name
            .to_str()
            .ok_or_else(|| snapshot_validation("snapshot relative path is not UTF-8"))?;
        if name.is_empty() {
            return Err(snapshot_validation("snapshot relative path is unsafe"));
        }
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(name.as_bytes());
    }
    if normalized.is_empty() {
        return Err(snapshot_validation("snapshot relative path is unsafe"));
    }
    Ok(normalized)
}

fn validate_canonical_directory(path: &Path, label: &str) -> Result<PathBuf, ClassifiedError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        snapshot_validation(format!("inspect {label} {}: {error}", path.display()))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(snapshot_validation(format!(
            "{label} is not a regular directory: {}",
            path.display()
        )));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        snapshot_validation(format!("resolve {label} {}: {error}", path.display()))
    })?;
    if canonical != path {
        return Err(snapshot_validation(format!(
            "{label} is not canonical: {}",
            path.display()
        )));
    }
    Ok(canonical)
}

#[cfg(unix)]
fn open_directory_path_nofollow(path: &Path, label: &str) -> Result<File, ClassifiedError> {
    use rustix::fs::{open, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = open(path, flags, Mode::empty())
        .map_err(|error| snapshot_validation(format!("open {label} without links: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_directory_path_nofollow(_path: &Path, _label: &str) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn open_or_create_directory_at(
    parent: &File,
    name: &str,
    allow_existing: bool,
) -> Result<File, ClassifiedError> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match openat(parent, name, flags, Mode::empty()) {
        Ok(descriptor) if allow_existing => Ok(File::from(descriptor)),
        Ok(_) => Err(snapshot_validation(
            "snapshot directory already exists unexpectedly",
        )),
        Err(rustix::io::Errno::NOENT) => {
            match mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) if allow_existing => {}
                Err(error) => {
                    return Err(snapshot_validation(format!(
                        "create snapshot directory: {error}"
                    )));
                }
            }
            let descriptor = openat(parent, name, flags, Mode::empty()).map_err(|error| {
                snapshot_validation(format!("open created snapshot directory: {error}"))
            })?;
            Ok(File::from(descriptor))
        }
        Err(error) => Err(snapshot_validation(format!(
            "open snapshot directory without links: {error}"
        ))),
    }
}

#[cfg(not(unix))]
fn open_or_create_directory_at(
    _parent: &File,
    _name: &str,
    _allow_existing: bool,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn create_new_directory_at(
    parent: &File,
    name: &str,
    label: &str,
) -> Result<File, ClassifiedError> {
    use rustix::fs::{mkdirat, openat, Mode, OFlags};

    mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR)
        .map_err(|error| snapshot_validation(format!("create {label}: {error}")))?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = openat(parent, name, flags, Mode::empty())
        .map_err(|error| snapshot_validation(format!("open created {label}: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn create_new_directory_at(
    _parent: &File,
    _name: &str,
    _label: &str,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

fn open_or_create_destination_parent(
    source_descriptor: &File,
    source_path: &Path,
    relative_file: &Path,
) -> Result<(File, PathBuf, std::ffi::OsString), ClassifiedError> {
    let mut components: Vec<_> = relative_file
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(snapshot_validation("snapshot relative path is unsafe")),
        })
        .collect::<Result<_, _>>()?;
    let leaf = components
        .pop()
        .ok_or_else(|| snapshot_validation("snapshot relative path is empty"))?;
    let mut current = source_descriptor.try_clone().map_err(|error| {
        snapshot_validation(format!("retain snapshot source directory: {error}"))
    })?;
    let mut current_path = source_path.to_path_buf();
    for component in components {
        current = open_or_create_directory_at(
            &current,
            component
                .to_str()
                .ok_or_else(|| snapshot_validation("snapshot relative path is not UTF-8"))?,
            true,
        )?;
        current_path.push(component);
    }
    Ok((current, current_path, leaf))
}

#[cfg(unix)]
fn write_new_owned_file_at(
    parent: &File,
    name: &std::ffi::OsStr,
    bytes: &[u8],
) -> Result<(), ClassifiedError> {
    use rustix::fs::{openat, Mode, OFlags};

    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let descriptor = openat(parent, name, flags, Mode::RUSR | Mode::WUSR)
        .map_err(|error| snapshot_validation(format!("create staged source: {error}")))?;
    let mut file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|error| snapshot_validation(format!("inspect staged source: {error}")))?
        .file_type()
        .is_file()
    {
        return Err(snapshot_validation("staged source is not a regular file"));
    }
    file.write_all(bytes)
        .map_err(|error| snapshot_validation(format!("write staged source: {error}")))?;
    file.sync_all()
        .map_err(|error| snapshot_validation(format!("sync staged source: {error}")))
}

#[cfg(not(unix))]
fn write_new_owned_file_at(
    _parent: &File,
    _name: &std::ffi::OsStr,
    _bytes: &[u8],
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires descriptor-relative filesystem access".to_owned(),
    ))
}

fn verify_staging_directory_chain(
    workspace_path: &Path,
    workspace: &File,
    semgrep_path: &Path,
    semgrep: &File,
    operation_path: &Path,
    operation: &File,
) -> Result<(), ClassifiedError> {
    verify_directory_path_identity(workspace_path, workspace, "managed workspace")?;
    verify_directory_path_identity(semgrep_path, semgrep, "Semgrep workspace")?;
    verify_directory_path_identity(operation_path, operation, "Semgrep operation")
}

#[cfg(unix)]
fn verify_directory_path_identity(
    path: &Path,
    descriptor: &File,
    label: &str,
) -> Result<(), ClassifiedError> {
    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| snapshot_validation(format!("inspect {label} path: {error}")))?;
    let descriptor_metadata = descriptor
        .metadata()
        .map_err(|error| snapshot_validation(format!("inspect open {label}: {error}")))?;
    if !same_directory_identity(&path_metadata, &descriptor_metadata) {
        return Err(snapshot_validation(format!(
            "{label} pathname changed during staging"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_directory_path_identity(
    _path: &Path,
    _descriptor: &File,
    _label: &str,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep staging requires filesystem identity checks".to_owned(),
    ))
}

fn read_stable_source<F>(
    canonical_project: &Path,
    relative: &Path,
    maximum: u64,
    after_read: F,
) -> Result<Vec<u8>, ClassifiedError>
where
    F: FnOnce(),
{
    read_stable_source_with_hooks(canonical_project, relative, maximum, || {}, after_read)
}

fn read_stable_source_with_hooks<B, A>(
    canonical_project: &Path,
    relative: &Path,
    maximum: u64,
    before_allocate: B,
    after_read: A,
) -> Result<Vec<u8>, ClassifiedError>
where
    B: FnOnce(),
    A: FnOnce(),
{
    let _ = normalized_relative_path_bytes(relative)?;
    let mut file = open_source_beneath(canonical_project, relative)?;
    let before = file.metadata().map_err(|error| {
        snapshot_validation(format!(
            "inspect open snapshot source {}: {error}",
            relative.display()
        ))
    })?;
    if !before.file_type().is_file() || before.len() > maximum {
        return Err(snapshot_validation(format!(
            "snapshot source must be a regular file no larger than {maximum} bytes"
        )));
    }
    before_allocate();
    let capacity = usize::try_from(before.len())
        .map_err(|_| snapshot_validation("snapshot source length cannot be allocated"))?;
    let read_limit = maximum
        .checked_add(1)
        .ok_or_else(|| snapshot_validation("snapshot read bound overflowed"))?;
    let mut bytes = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            snapshot_validation(format!(
                "read snapshot source {}: {error}",
                relative.display()
            ))
        })?;
    let observed = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if observed > maximum {
        return Err(snapshot_validation(format!(
            "snapshot source exceeds {maximum} bytes"
        )));
    }
    after_read();
    let after = file.metadata().map_err(|error| {
        snapshot_validation(format!(
            "reinspect open snapshot source {}: {error}",
            relative.display()
        ))
    })?;
    if before.len() != observed || !stable_file_metadata(&before, &after) {
        return Err(snapshot_validation(
            "snapshot source changed while it was read",
        ));
    }
    verify_open_source_path_identity(canonical_project, relative, &after)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_source_beneath(canonical_project: &Path, relative: &Path) -> Result<File, ClassifiedError> {
    use rustix::fs::{open, openat, Mode, OFlags};

    let components: Vec<_> = relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            _ => Err(snapshot_validation("snapshot relative path is unsafe")),
        })
        .collect::<Result<_, _>>()?;
    let (leaf, parents) = components
        .split_last()
        .ok_or_else(|| snapshot_validation("snapshot relative path is empty"))?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory = File::from(
        open(canonical_project, directory_flags, Mode::empty()).map_err(|error| {
            snapshot_validation(format!("open canonical project directory: {error}"))
        })?,
    );
    for component in parents {
        directory = File::from(
            openat(&directory, *component, directory_flags, Mode::empty()).map_err(|error| {
                snapshot_validation(format!("open snapshot source parent: {error}"))
            })?,
        );
    }
    let descriptor = openat(
        &directory,
        *leaf,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| snapshot_validation(format!("open snapshot source: {error}")))?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_source_beneath(
    _canonical_project: &Path,
    _relative: &Path,
) -> Result<File, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep snapshots require descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn stable_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.file_type().is_file()
        && right.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn stable_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.file_type().is_file()
        && right.file_type().is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn verify_open_source_path_identity(
    canonical_project: &Path,
    relative: &Path,
    opened: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    use std::os::unix::fs::MetadataExt;

    let path = canonical_project.join(relative);
    let current = std::fs::symlink_metadata(&path).map_err(|error| {
        snapshot_validation(format!(
            "reinspect snapshot source path {}: {error}",
            relative.display()
        ))
    })?;
    if !current.file_type().is_file()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || !stable_file_metadata(opened, &current)
    {
        return Err(snapshot_validation(
            "snapshot source path changed while it was read",
        ));
    }
    let resolved = std::fs::canonicalize(&path).map_err(|error| {
        snapshot_validation(format!(
            "resolve snapshot source path {}: {error}",
            relative.display()
        ))
    })?;
    if resolved != path || !resolved.starts_with(canonical_project) {
        return Err(snapshot_validation(
            "snapshot source escaped its canonical project",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_open_source_path_identity(
    _canonical_project: &Path,
    _relative: &Path,
    _opened: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep snapshots require filesystem identity checks".to_owned(),
    ))
}

fn cleanup_operation_root_in(
    managed_workspace: &Path,
    operation_root: &Path,
) -> Result<(), ClassifiedError> {
    cleanup_operation_root_in_with_hooks(managed_workspace, operation_root, || {}, || {}, || {})
}

#[cfg(test)]
fn cleanup_operation_root_in_with_hook<F>(
    managed_workspace: &Path,
    operation_root: &Path,
    before_remove: F,
) -> Result<(), ClassifiedError>
where
    F: FnOnce(),
{
    cleanup_operation_root_in_with_hooks(
        managed_workspace,
        operation_root,
        || {},
        || {},
        before_remove,
    )
}

fn cleanup_operation_root_in_with_hooks<B, F, R>(
    managed_workspace: &Path,
    operation_root: &Path,
    before_semgrep_open: B,
    before_final_workspace_identity: F,
    before_remove: R,
) -> Result<(), ClassifiedError>
where
    B: FnOnce(),
    F: FnOnce(),
    R: FnOnce(),
{
    let workspace_path = validate_canonical_directory(managed_workspace, "managed workspace")?;
    let workspace = open_directory_path_nofollow(&workspace_path, "canonical managed workspace")?;
    verify_directory_path_identity(&workspace_path, &workspace, "managed workspace")?;
    let semgrep_root = workspace_path.join("semgrep");
    let operation_name = operation_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| snapshot_validation("Semgrep operation path has no UTF-8 UUID"))?;
    let operation_id = Uuid::parse_str(operation_name)
        .map_err(|_| snapshot_validation("Semgrep operation path is not UUID-owned"))?;
    let expected = semgrep_root.join(operation_id.to_string());
    if operation_root != expected {
        return Err(snapshot_validation(
            "Semgrep cleanup target is not the exact owned operation directory",
        ));
    }
    before_semgrep_open();
    let Some(semgrep) = open_optional_directory_at(&workspace, "semgrep", "Semgrep workspace")?
    else {
        before_final_workspace_identity();
        verify_directory_path_identity(&workspace_path, &workspace, "managed workspace")?;
        return match open_optional_directory_at(&workspace, "semgrep", "Semgrep workspace")? {
            None => Ok(()),
            Some(_) => Err(snapshot_validation(
                "Semgrep workspace appeared while proving its absence",
            )),
        };
    };
    verify_directory_path_identity(&workspace_path, &workspace, "managed workspace")?;
    verify_directory_path_identity(&semgrep_root, &semgrep, "Semgrep workspace")?;

    let Some(operation) =
        open_optional_directory_at(&semgrep, operation_name, "Semgrep operation directory")?
    else {
        before_final_workspace_identity();
        verify_directory_path_identity(&workspace_path, &workspace, "managed workspace")?;
        verify_directory_path_identity(&semgrep_root, &semgrep, "Semgrep workspace")?;
        return match open_optional_directory_at(
            &semgrep,
            operation_name,
            "Semgrep operation directory",
        )? {
            None => Ok(()),
            Some(_) => Err(snapshot_validation(
                "Semgrep operation appeared while proving its absence",
            )),
        };
    };
    verify_directory_path_identity(operation_root, &operation, "Semgrep operation")?;

    before_remove();
    remove_owned_operation_nofollow(&semgrep, operation_name, &operation)?;
    before_final_workspace_identity();
    verify_directory_path_identity(&workspace_path, &workspace, "managed workspace")?;
    verify_directory_path_identity(&semgrep_root, &semgrep, "Semgrep workspace")
}

#[cfg(unix)]
fn open_optional_directory_at(
    parent: &File,
    name: &str,
    label: &str,
) -> Result<Option<File>, ClassifiedError> {
    use rustix::fs::{openat, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    match openat(parent, name, flags, Mode::empty()) {
        Ok(descriptor) => Ok(Some(File::from(descriptor))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(snapshot_validation(format!(
            "open {label} without links: {error}"
        ))),
    }
}

#[cfg(not(unix))]
fn open_optional_directory_at(
    _parent: &File,
    _name: &str,
    _label: &str,
) -> Result<Option<File>, ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep cleanup requires descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn remove_owned_operation_nofollow(
    semgrep: &File,
    operation_name: &str,
    operation: &File,
) -> Result<(), ClassifiedError> {
    use rustix::fs::{openat, unlinkat, AtFlags, Mode, OFlags};

    let open_operation = operation.metadata().map_err(|error| {
        snapshot_validation(format!(
            "reinspect open Semgrep operation directory: {error}"
        ))
    })?;
    remove_open_directory_contents(operation)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let current = File::from(
        openat(semgrep, operation_name, flags, Mode::empty()).map_err(|error| {
            snapshot_validation(format!(
                "reopen Semgrep operation directory before removal: {error}"
            ))
        })?,
    );
    let current_metadata = current.metadata().map_err(|error| {
        snapshot_validation(format!(
            "inspect reopened Semgrep operation directory: {error}"
        ))
    })?;
    if !same_directory_identity(&open_operation, &current_metadata) {
        return Err(snapshot_validation(
            "Semgrep operation pathname changed during cleanup",
        ));
    }
    unlinkat(semgrep, operation_name, AtFlags::REMOVEDIR)
        .map_err(|error| {
            snapshot_validation(format!("remove owned Semgrep operation directory: {error}"))
        })
        .and_then(|()| {
            semgrep.sync_all().map_err(|error| {
                snapshot_validation(format!("sync Semgrep workspace after cleanup: {error}"))
            })
        })
}

#[cfg(not(unix))]
fn remove_owned_operation_nofollow(
    _semgrep: &File,
    _operation_name: &str,
    _operation: &File,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep cleanup requires descriptor-relative filesystem access".to_owned(),
    ))
}

#[cfg(unix)]
fn remove_open_directory_contents(directory: &File) -> Result<(), ClassifiedError> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    use rustix::fs::{openat, unlinkat, AtFlags, Mode, OFlags};

    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)
        .map_err(|error| snapshot_validation(format!("read Semgrep cleanup directory: {error}")))?
    {
        let entry = entry.map_err(|error| {
            snapshot_validation(format!("read Semgrep cleanup directory entry: {error}"))
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes != b"." && bytes != b".." {
            names.push(OsString::from_vec(bytes.to_vec()));
        }
    }

    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    for name in names {
        match openat(directory, &name, directory_flags, Mode::empty()) {
            Ok(child) => {
                let child = File::from(child);
                remove_open_directory_contents(&child)?;
                unlinkat(directory, &name, AtFlags::REMOVEDIR).map_err(|error| {
                    snapshot_validation(format!(
                        "remove owned Semgrep cleanup subdirectory: {error}"
                    ))
                })?;
            }
            Err(rustix::io::Errno::NOTDIR | rustix::io::Errno::LOOP) => {
                unlinkat(directory, &name, AtFlags::empty()).map_err(|error| {
                    snapshot_validation(format!("remove owned Semgrep cleanup file: {error}"))
                })?;
            }
            Err(error) => {
                return Err(snapshot_validation(format!(
                    "open Semgrep cleanup entry without links: {error}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_directory_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.file_type().is_dir()
        && right.file_type().is_dir()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
}

fn snapshot_validation(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(format!("Semgrep snapshot: {}", message.into()))
}

fn append_error_context(error: ClassifiedError, context: &str) -> ClassifiedError {
    let append = |message: String| format!("{message}; {context}");
    match error {
        ClassifiedError::Provider(message) => ClassifiedError::Provider(append(message)),
        ClassifiedError::Sandbox(message) => ClassifiedError::Sandbox(append(message)),
        ClassifiedError::Engine(message) => ClassifiedError::Engine(append(message)),
        ClassifiedError::Harness(message) => ClassifiedError::Harness(append(message)),
        ClassifiedError::Storage(message) => ClassifiedError::Storage(append(message)),
        ClassifiedError::Validation(message) => ClassifiedError::Validation(append(message)),
        ClassifiedError::Internal(message) => ClassifiedError::Internal(append(message)),
        ClassifiedError::Timeout => ClassifiedError::Timeout,
    }
}

#[cfg(test)]
macro_rules! assert_f64_eq {
    ($left:expr, $right:expr) => {
        assert_eq!($left.to_bits(), f64::to_bits($right));
    };
}

#[cfg(test)]
mod effective_inventory_tests {
    use std::path::{Path, PathBuf};

    use chrono::Utc;
    use hf_core::target::{
        InputSurface, SourceLocation, TargetCandidate, TargetInventory, TargetKind, TargetLanguage,
    };
    use hf_storage::{
        SemgrepFindingRecord, SemgrepFindingSeverity, SemgrepPublication, SemgrepRunRecord,
        SemgrepRunStatus, SemgrepTargetScoreRecord,
    };
    use uuid::Uuid;

    use super::{
        digest_live_sources, sort_semgrep_targets, SemgrepOverlayState, SemgrepTargetView,
        COMMAND_SCHEMA_VERSION, RULES_COMMIT, SEMGREP_VERSION,
    };
    use crate::ServiceContainer;

    fn candidate(project: &Path, id: Uuid, symbol: &str, base_score: f64) -> TargetCandidate {
        TargetCandidate {
            id,
            project_root: project.to_path_buf(),
            language: TargetLanguage::C,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: project.join("parser.c"),
                line: 1,
                col: 1,
                end_line: Some(1),
                end_col: Some(80),
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: base_score,
            sanitizers: Vec::new(),
            rationale: "persisted".to_owned(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        }
    }

    fn inventory(project: &Path, candidate: TargetCandidate) -> TargetInventory {
        TargetInventory {
            project_root: project.to_path_buf(),
            candidates: vec![candidate],
            call_graph: std::collections::HashMap::new(),
        }
    }

    fn publication(
        project: &Path,
        target_id: Uuid,
        source_sha256: String,
        base_score: f64,
    ) -> SemgrepPublication {
        let scan_id = Uuid::new_v4();
        SemgrepPublication {
            run: SemgrepRunRecord {
                id: scan_id,
                project_root: project.to_string_lossy().into_owned(),
                language: "c".to_owned(),
                source_sha256: Some(source_sha256),
                sandbox_image: "image".to_owned(),
                sandbox_image_sha256: "1".repeat(64),
                semgrep_version: SEMGREP_VERSION.to_owned(),
                rules_commit: RULES_COMMIT.to_owned(),
                rules_tree_sha256: "2".repeat(64),
                command_schema_version: COMMAND_SCHEMA_VERSION,
                status: SemgrepRunStatus::Done,
                started_at: Utc::now(),
                ended_at: Some(Utc::now()),
                output_sha256: Some("3".repeat(64)),
                finding_count: Some(2),
                matched_candidate_count: Some(1),
                duration_ms: Some(1),
                failure_code: None,
                failure_message: None,
            },
            findings: vec![
                SemgrepFindingRecord {
                    scan_id,
                    fingerprint: "4".repeat(64),
                    rule_id: "matched.rule".to_owned(),
                    severity: SemgrepFindingSeverity::Warning,
                    message: "matched signal".to_owned(),
                    relative_file: "parser.c".to_owned(),
                    start_line: 1,
                    start_col: 1,
                    end_line: 1,
                    end_col: 4,
                    target_id: Some(target_id),
                    nominal_weight: 0.05,
                },
                SemgrepFindingRecord {
                    scan_id,
                    fingerprint: "5".repeat(64),
                    rule_id: "unmatched.rule".to_owned(),
                    severity: SemgrepFindingSeverity::Info,
                    message: "unmatched signal".to_owned(),
                    relative_file: "parser.c".to_owned(),
                    start_line: 1,
                    start_col: 6,
                    end_line: 1,
                    end_col: 9,
                    target_id: None,
                    nominal_weight: 0.01,
                },
            ],
            scores: vec![SemgrepTargetScoreRecord {
                scan_id,
                target_id,
                base_score,
                boost: 0.05,
                effective_score: base_score + 0.05,
                matched_rule_count: 1,
            }],
        }
    }

    fn close_publication_journal(service: &ServiceContainer, publication: &SemgrepPublication) {
        let scan_id = publication.run.id;
        service
            .semgrep
            .journal
            .begin(
                scan_id,
                Path::new(&publication.run.project_root),
                &scan_id.to_string(),
            )
            .unwrap();
        service
            .semgrep
            .journal
            .ready_to_commit(
                scan_id,
                &crate::semgrep_recovery::SemgrepReadyRecord {
                    source_sha256: publication.run.source_sha256.clone().unwrap(),
                    output_sha256: publication.run.output_sha256.clone().unwrap(),
                    sandbox_image_sha256: publication.run.sandbox_image_sha256.clone(),
                    rules_tree_sha256: publication.run.rules_tree_sha256.clone(),
                    command_schema_version: COMMAND_SCHEMA_VERSION,
                },
            )
            .unwrap();
        service.semgrep.journal.close(scan_id).unwrap();
    }

    #[test]
    fn current_and_stale_views_keep_base_immutable_and_findings_queryable() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("parser.c"),
            b"int parse(const char *p) { return p[0]; }\n",
        )
        .unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let target_id = Uuid::new_v4();
        let base_candidate = candidate(&project, target_id, "parse", 0.5);
        let publication = publication(
            &project,
            target_id,
            digest_live_sources(&project, TargetLanguage::C).unwrap(),
            0.5,
        );
        let service = ServiceContainer::stubbed();
        close_publication_journal(&service, &publication);

        let current = service.inventory_with_publication(
            inventory(&project, base_candidate.clone()),
            TargetLanguage::C,
            Some(publication.clone()),
            true,
        );
        assert_eq!(current.overlay_state, SemgrepOverlayState::Current);
        assert_f64_eq!(current.candidates[0].candidate.fit_score, 0.5);
        assert_f64_eq!(current.candidates[0].base_score, 0.5);
        assert_f64_eq!(current.candidates[0].semgrep_boost, 0.05);
        assert_f64_eq!(current.candidates[0].effective_score, 0.55);
        assert_eq!(current.findings.len(), 2);
        assert!(current
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));

        let unverified = service.inventory_with_publication(
            inventory(&project, base_candidate.clone()),
            TargetLanguage::C,
            Some(publication.clone()),
            false,
        );
        assert_eq!(unverified.overlay_state, SemgrepOverlayState::StaleBase);
        assert_f64_eq!(unverified.candidates[0].effective_score, 0.5);
        assert_eq!(unverified.findings.len(), 2);
        assert!(unverified
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));

        let mut reranked = base_candidate;
        reranked.fit_score = 0.7;
        let stale_base = service.inventory_with_publication(
            inventory(&project, reranked),
            TargetLanguage::C,
            Some(publication.clone()),
            true,
        );
        assert_eq!(stale_base.overlay_state, SemgrepOverlayState::StaleBase);
        assert_f64_eq!(stale_base.candidates[0].effective_score, 0.7);
        assert_f64_eq!(stale_base.candidates[0].semgrep_boost, 0.0);
        assert_eq!(stale_base.findings.len(), 2);
        assert!(stale_base
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));

        std::fs::write(
            project.join("parser.c"),
            b"int changed(void) { return 0; }\n",
        )
        .unwrap();
        let stale_source = service.inventory_with_publication(
            inventory(&project, candidate(&project, target_id, "parse", 0.5)),
            TargetLanguage::C,
            Some(publication),
            true,
        );
        assert_eq!(stale_source.overlay_state, SemgrepOverlayState::StaleSource);
        assert_f64_eq!(stale_source.candidates[0].effective_score, 0.5);
        assert_eq!(stale_source.findings.len(), 2);
        assert!(stale_source
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));
    }

    #[test]
    fn missing_or_open_journal_is_incomplete_and_base_only() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("parser.c"),
            b"int parse(char *p) { return *p; }\n",
        )
        .unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let target_id = Uuid::new_v4();
        let candidate = candidate(&project, target_id, "parse", 0.4);
        let publication = publication(
            &project,
            target_id,
            digest_live_sources(&project, TargetLanguage::C).unwrap(),
            0.4,
        );
        let service = ServiceContainer::stubbed();

        let view = service.inventory_with_publication(
            inventory(&project, candidate),
            TargetLanguage::C,
            Some(publication),
            true,
        );
        assert_eq!(view.overlay_state, SemgrepOverlayState::IncompleteJournal);
        assert_f64_eq!(view.candidates[0].effective_score, 0.4);
        assert_eq!(view.findings.len(), 2);
        assert!(view
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));
    }

    #[test]
    fn score_count_and_target_id_mismatches_are_stale_base() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("parser.c"),
            b"int parse(char *p) { return *p; }\n",
        )
        .unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let target_id = Uuid::new_v4();
        let base_candidate = candidate(&project, target_id, "parse", 0.4);
        let publication = publication(
            &project,
            target_id,
            digest_live_sources(&project, TargetLanguage::C).unwrap(),
            0.4,
        );
        let service = ServiceContainer::stubbed();
        close_publication_journal(&service, &publication);

        let mut count_mismatch = publication.clone();
        count_mismatch.scores.clear();
        let count_view = service.inventory_with_publication(
            inventory(&project, base_candidate.clone()),
            TargetLanguage::C,
            Some(count_mismatch),
            true,
        );
        assert_eq!(count_view.overlay_state, SemgrepOverlayState::StaleBase);
        assert_f64_eq!(count_view.candidates[0].semgrep_boost, 0.0);

        let mut id_mismatch = publication;
        id_mismatch.scores[0].target_id = Uuid::new_v4();
        let id_view = service.inventory_with_publication(
            inventory(&project, base_candidate),
            TargetLanguage::C,
            Some(id_mismatch),
            true,
        );
        assert_eq!(id_view.overlay_state, SemgrepOverlayState::StaleBase);
        assert_f64_eq!(id_view.candidates[0].semgrep_boost, 0.0);
    }

    fn ordered_view(
        project: &Path,
        id: u128,
        symbol: &str,
        relative_file: &str,
        base_score: f64,
        effective_score: f64,
    ) -> SemgrepTargetView {
        let mut candidate = candidate(project, Uuid::from_u128(id), symbol, base_score);
        candidate.location.file = project.join(relative_file);
        SemgrepTargetView {
            candidate,
            base_score,
            semgrep_boost: effective_score - base_score,
            effective_score,
            semgrep_matched_rule_count: 1,
        }
    }

    #[test]
    fn total_order_uses_every_approved_key_in_sequence() {
        let project = PathBuf::from("/project");
        let mut views = vec![
            ordered_view(&project, 3, "omega", "c.c", 0.6, 0.8),
            ordered_view(&project, 1, "zeta", "b.c", 0.6, 0.8),
            ordered_view(&project, 8, "base_wins", "z.c", 0.7, 0.8),
            ordered_view(&project, 9, "effective_wins", "z.c", 0.1, 0.9),
            ordered_view(&project, 7, "z_file_wins", "a.c", 0.6, 0.8),
            ordered_view(&project, 6, "alpha", "b.c", 0.6, 0.8),
            ordered_view(&project, 2, "omega", "c.c", 0.6, 0.8),
        ];

        sort_semgrep_targets(&mut views);

        let ids = views
            .iter()
            .map(|view| view.candidate.id.as_u128())
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![9, 8, 7, 6, 1, 2, 3]);
    }
}

#[cfg(test)]
mod publication_tests {
    use hf_discovery::semgrep::{SemgrepAnalysis, SemgrepTargetScore};
    use hf_storage::{SemgrepRunRecord, SemgrepRunStatus, Store};
    use uuid::Uuid;

    use super::build_semgrep_publication;

    #[test]
    fn recovery_health_error_redacts_private_cause() {
        let coordinator = super::SemgrepCoordinator::in_memory();
        coordinator.mark_recovery_degraded("/private/secret/workspace/semgrep");

        let error = coordinator
            .ensure_recovery_healthy()
            .unwrap_err()
            .to_string();

        assert!(error.contains("Semgrep recovery is degraded"));
        assert!(!error.contains("/private/secret/workspace"));
        assert!(!error.contains("semgrep-journal"));
    }

    #[tokio::test]
    async fn publication_builder_uses_checked_terminal_aggregates() {
        let root = tempfile::tempdir().unwrap();
        let store = Store::connect(root.path().join("publication.db"))
            .await
            .unwrap();
        let operation_id = Uuid::new_v4();
        let started_at = chrono::Utc::now();
        let run = SemgrepRunRecord {
            id: operation_id,
            project_root: root.path().to_string_lossy().into_owned(),
            language: "c".to_owned(),
            source_sha256: None,
            sandbox_image: "image".to_owned(),
            sandbox_image_sha256: "1".repeat(64),
            semgrep_version: super::SEMGREP_VERSION.to_owned(),
            rules_commit: super::RULES_COMMIT.to_owned(),
            rules_tree_sha256: "2".repeat(64),
            command_schema_version: super::COMMAND_SCHEMA_VERSION,
            status: SemgrepRunStatus::Staging,
            started_at,
            ended_at: None,
            output_sha256: None,
            finding_count: None,
            matched_candidate_count: None,
            duration_ms: None,
            failure_code: None,
            failure_message: None,
        };
        store.insert_semgrep_run(&run).await.unwrap();
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Staging,
                SemgrepRunStatus::Scanning,
                Some(&"3".repeat(64)),
            )
            .await
            .unwrap();
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Scanning,
                SemgrepRunStatus::Validating,
                None,
            )
            .await
            .unwrap();
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Validating,
                SemgrepRunStatus::Persisting,
                None,
            )
            .await
            .unwrap();
        let target_id = Uuid::new_v4();
        let publication = build_semgrep_publication(
            &store,
            operation_id,
            SemgrepAnalysis {
                findings: Vec::new(),
                scores: vec![SemgrepTargetScore {
                    target_id,
                    base_score: 0.4,
                    boost: 0.0,
                    effective_score: 0.4,
                    matched_rule_count: 0,
                }],
                matched_candidate_count: 0,
            },
            "4".repeat(64),
        )
        .await
        .unwrap();

        assert_eq!(publication.run.status, SemgrepRunStatus::Done);
        assert_eq!(publication.run.finding_count, Some(0));
        assert_eq!(publication.run.matched_candidate_count, Some(0));
        assert_eq!(publication.scores[0].scan_id, operation_id);
        assert!(publication.run.duration_ms.is_some());
    }

    fn staging_run(operation_id: Uuid, project: &std::path::Path) -> SemgrepRunRecord {
        SemgrepRunRecord {
            id: operation_id,
            project_root: project.to_string_lossy().into_owned(),
            language: "c".to_owned(),
            source_sha256: None,
            sandbox_image: "image".to_owned(),
            sandbox_image_sha256: "1".repeat(64),
            semgrep_version: super::SEMGREP_VERSION.to_owned(),
            rules_commit: super::RULES_COMMIT.to_owned(),
            rules_tree_sha256: "2".repeat(64),
            command_schema_version: super::COMMAND_SCHEMA_VERSION,
            status: SemgrepRunStatus::Staging,
            started_at: chrono::Utc::now(),
            ended_at: None,
            output_sha256: None,
            finding_count: None,
            matched_candidate_count: None,
            duration_ms: None,
            failure_code: None,
            failure_message: None,
        }
    }

    async fn advance_to(store: &Store, operation_id: Uuid, status: SemgrepRunStatus) {
        if status == SemgrepRunStatus::Staging {
            return;
        }
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Staging,
                SemgrepRunStatus::Scanning,
                Some(&"3".repeat(64)),
            )
            .await
            .unwrap();
        if status == SemgrepRunStatus::Scanning {
            return;
        }
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Scanning,
                SemgrepRunStatus::Validating,
                None,
            )
            .await
            .unwrap();
        if status == SemgrepRunStatus::Validating {
            return;
        }
        store
            .set_semgrep_phase(
                operation_id,
                SemgrepRunStatus::Validating,
                SemgrepRunStatus::Persisting,
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn recovery_repairs_every_interrupted_phase_and_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(root.path()).unwrap();
        let store = Store::connect(workspace.join("recovery.db")).await.unwrap();
        let coordinator = super::SemgrepCoordinator::persistent(workspace.join("journal"));
        let mut expected_terminal = Vec::new();

        for status in [
            SemgrepRunStatus::Staging,
            SemgrepRunStatus::Scanning,
            SemgrepRunStatus::Validating,
            SemgrepRunStatus::Persisting,
        ] {
            let operation_id = Uuid::new_v4();
            expected_terminal.push((operation_id, SemgrepRunStatus::Failed));
            let project = workspace.join(format!("project-{operation_id}"));
            std::fs::create_dir(&project).unwrap();
            store
                .insert_semgrep_run(&staging_run(operation_id, &project))
                .await
                .unwrap();
            advance_to(&store, operation_id, status).await;
            coordinator
                .journal
                .begin(operation_id, &project, &operation_id.to_string())
                .unwrap();
            let operation_root = workspace.join("semgrep").join(operation_id.to_string());
            std::fs::create_dir_all(&operation_root).unwrap();
            std::fs::write(operation_root.join("owned"), b"data").unwrap();
        }

        let done_id = Uuid::new_v4();
        expected_terminal.push((done_id, SemgrepRunStatus::Failed));
        let project = workspace.join(format!("project-{done_id}"));
        std::fs::create_dir(&project).unwrap();
        store
            .insert_semgrep_run(&staging_run(done_id, &project))
            .await
            .unwrap();
        advance_to(&store, done_id, SemgrepRunStatus::Persisting).await;
        coordinator
            .journal
            .begin(done_id, &project, &done_id.to_string())
            .unwrap();
        let ready = crate::semgrep_recovery::SemgrepReadyRecord {
            source_sha256: "3".repeat(64),
            output_sha256: "4".repeat(64),
            sandbox_image_sha256: "1".repeat(64),
            rules_tree_sha256: "2".repeat(64),
            command_schema_version: super::COMMAND_SCHEMA_VERSION,
        };
        coordinator
            .journal
            .ready_to_commit(done_id, &ready)
            .unwrap();
        let publication = build_semgrep_publication(
            &store,
            done_id,
            SemgrepAnalysis {
                findings: Vec::new(),
                scores: Vec::new(),
                matched_candidate_count: 0,
            },
            ready.output_sha256.clone(),
        )
        .await
        .unwrap();
        store.publish_semgrep_run(&publication).await.unwrap();
        std::fs::create_dir_all(workspace.join("semgrep").join(done_id.to_string())).unwrap();

        for status in [SemgrepRunStatus::Failed, SemgrepRunStatus::Cancelled] {
            let operation_id = Uuid::new_v4();
            expected_terminal.push((operation_id, status));
            let project = workspace.join(format!("project-{operation_id}"));
            std::fs::create_dir(&project).unwrap();
            store
                .insert_semgrep_run(&staging_run(operation_id, &project))
                .await
                .unwrap();
            coordinator
                .journal
                .begin(operation_id, &project, &operation_id.to_string())
                .unwrap();
            store
                .fail_semgrep_run(
                    operation_id,
                    status,
                    "interrupted_abort",
                    "terminal database state preceded abort",
                    chrono::Utc::now(),
                )
                .await
                .unwrap();
            let publication = store
                .semgrep_publication(operation_id)
                .await
                .unwrap()
                .unwrap();
            assert!(publication.findings.is_empty());
            assert!(publication.scores.is_empty());
            std::fs::create_dir_all(workspace.join("semgrep").join(operation_id.to_string()))
                .unwrap();
        }

        let closed_id = Uuid::new_v4();
        let closed_project = workspace.join(format!("project-{closed_id}"));
        std::fs::create_dir(&closed_project).unwrap();
        store
            .insert_semgrep_run(&staging_run(closed_id, &closed_project))
            .await
            .unwrap();
        advance_to(&store, closed_id, SemgrepRunStatus::Persisting).await;
        coordinator
            .journal
            .begin(closed_id, &closed_project, &closed_id.to_string())
            .unwrap();
        coordinator
            .journal
            .ready_to_commit(closed_id, &ready)
            .unwrap();
        let closed_publication = build_semgrep_publication(
            &store,
            closed_id,
            SemgrepAnalysis {
                findings: Vec::new(),
                scores: Vec::new(),
                matched_candidate_count: 0,
            },
            ready.output_sha256.clone(),
        )
        .await
        .unwrap();
        store
            .publish_semgrep_run(&closed_publication)
            .await
            .unwrap();
        coordinator.journal.close(closed_id).unwrap();

        let sibling_id = Uuid::new_v4();
        let sibling = workspace.join("semgrep").join(sibling_id.to_string());
        std::fs::create_dir_all(&sibling).unwrap();
        std::fs::write(sibling.join("must-survive"), b"sibling").unwrap();

        drop(coordinator);
        let coordinator = super::SemgrepCoordinator::persistent(workspace.join("journal"));
        coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .unwrap();
        coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .unwrap();

        assert!(coordinator.journal.interrupted().unwrap().is_empty());
        for (operation_id, expected_status) in expected_terminal {
            let run = store.semgrep_run(operation_id).await.unwrap().unwrap();
            assert_eq!(run.status, expected_status);
            let publication = store
                .semgrep_publication(operation_id)
                .await
                .unwrap()
                .unwrap();
            assert!(publication.findings.is_empty());
            assert!(publication.scores.is_empty());
            assert!(!workspace
                .join("semgrep")
                .join(operation_id.to_string())
                .exists());
            assert!(!coordinator.journal.is_closed(operation_id).unwrap());
        }
        assert_eq!(
            store.semgrep_run(closed_id).await.unwrap().unwrap().status,
            SemgrepRunStatus::Done,
            "replayed Closed+Done must preserve the successful publication"
        );
        assert_eq!(
            std::fs::read(sibling.join("must-survive")).unwrap(),
            b"sibling",
            "recovery removed another operation UUID directory"
        );
    }

    #[tokio::test]
    async fn recovery_repairs_active_staging_row_without_journal_evidence() {
        let root = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(root.path()).unwrap();
        let project = workspace.join("project");
        std::fs::create_dir(&project).unwrap();
        let store = Store::connect(workspace.join("recovery.db")).await.unwrap();
        let journal_dir = workspace.join("journal");
        let coordinator = super::SemgrepCoordinator::persistent(journal_dir.clone());
        let operation_id = Uuid::new_v4();
        store
            .insert_semgrep_run(&staging_run(operation_id, &project))
            .await
            .unwrap();
        let operation_root = workspace.join("semgrep").join(operation_id.to_string());
        std::fs::create_dir_all(&operation_root).unwrap();
        std::fs::write(operation_root.join("owned"), b"partial snapshot").unwrap();

        coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .unwrap();
        coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .unwrap();

        let run = store.semgrep_run(operation_id).await.unwrap().unwrap();
        assert_eq!(run.status, SemgrepRunStatus::Failed);
        assert_eq!(run.failure_code.as_deref(), Some("recovered_missing_journal"));
        assert!(store
            .semgrep_publication(operation_id)
            .await
            .unwrap()
            .is_some_and(|publication| {
                publication.findings.is_empty() && publication.scores.is_empty()
            }));
        assert!(!operation_root.exists());
        assert!(
            !journal_dir.join(format!("{operation_id}.jsonl")).exists(),
            "recovery must not fabricate a journal lifecycle for an unbegun operation"
        );
    }

    #[tokio::test]
    async fn recovery_aborts_interrupted_journal_without_database_parent() {
        let root = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(root.path()).unwrap();
        let project = workspace.join("deleted-project");
        let store = Store::connect(workspace.join("recovery.db")).await.unwrap();
        let coordinator = super::SemgrepCoordinator::persistent(workspace.join("journal"));
        let operation_id = Uuid::new_v4();
        coordinator
            .journal
            .begin(operation_id, &project, &operation_id.to_string())
            .unwrap();
        let operation_root = workspace.join("semgrep").join(operation_id.to_string());
        std::fs::create_dir_all(&operation_root).unwrap();
        std::fs::write(operation_root.join("owned"), b"partial snapshot").unwrap();

        coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .unwrap();
        coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .unwrap();

        assert!(!operation_root.exists());
        assert!(coordinator.journal.interrupted().unwrap().is_empty());
        assert!(!coordinator.journal.is_closed(operation_id).unwrap());
    }

    #[tokio::test]
    async fn active_row_decode_failure_degrades_recovery() {
        let root = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(root.path()).unwrap();
        let project = workspace.join("project");
        let store = Store::connect(workspace.join("recovery.db")).await.unwrap();
        let coordinator = super::SemgrepCoordinator::persistent(workspace.join("journal"));
        let operation_id = Uuid::new_v4();
        store
            .insert_semgrep_run(&staging_run(operation_id, &project))
            .await
            .unwrap();
        sqlx::query("UPDATE semgrep_enrichment_runs SET sandbox_image = '' WHERE id = ?1")
            .bind(operation_id.to_string())
            .execute(store.pool())
            .await
            .unwrap();

        assert!(coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .is_err());
        assert!(coordinator.ensure_recovery_healthy().is_err());
    }

    #[tokio::test]
    async fn recovery_rejects_terminal_rows_with_publication_children() {
        let root = tempfile::tempdir().unwrap();
        let workspace = std::fs::canonicalize(root.path()).unwrap();
        let project = workspace.join("project");
        std::fs::create_dir(&project).unwrap();
        let store = Store::connect(workspace.join("corrupt-terminal.db"))
            .await
            .unwrap();
        let coordinator = super::SemgrepCoordinator::persistent(workspace.join("journal"));
        let operation_id = Uuid::new_v4();
        store
            .insert_semgrep_run(&staging_run(operation_id, &project))
            .await
            .unwrap();
        coordinator
            .journal
            .begin(operation_id, &project, &operation_id.to_string())
            .unwrap();
        store
            .fail_semgrep_run(
                operation_id,
                SemgrepRunStatus::Failed,
                "failed",
                "failed before abort",
                chrono::Utc::now(),
            )
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO semgrep_findings
             (scan_id, fingerprint, rule_id, severity, message, relative_file,
              start_line, start_col, end_line, end_col, target_id, nominal_weight)
             VALUES (?1, ?2, 'rule', 'warning', 'signal', 'parser.c',
                     1, 1, 1, 2, NULL, 0.05)",
        )
        .bind(operation_id.to_string())
        .bind("5".repeat(64))
        .execute(store.pool())
        .await
        .unwrap();
        let operation_root = workspace.join("semgrep").join(operation_id.to_string());
        std::fs::create_dir_all(&operation_root).unwrap();

        assert!(coordinator
            .recover_interrupted(&store, &workspace)
            .await
            .is_err());
        assert!(operation_root.exists());
        assert_eq!(coordinator.journal.interrupted().unwrap().len(), 1);
    }
}

#[cfg(test)]
mod snapshot_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use hf_core::error::ClassifiedError;
    use hf_core::target::TargetLanguage;
    use uuid::Uuid;

    use super::{
        cleanup_operation_root_in, digest_live_sources_with_limits,
        digest_live_sources_with_limits_and_read_hook, digest_ordered_sources,
        stage_selected_paths_at_with_limits, stage_selected_paths_at_with_stage_hook,
        stage_source_snapshot_at_with_limits, SnapshotLimits, StageMutationPoint,
        COMMAND_SCHEMA_VERSION, RULES_COMMIT, SEMGREP_VERSION, SNAPSHOT_LIMITS,
    };

    fn write(root: &Path, relative: &str, bytes: &[u8]) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn tiny_limits() -> SnapshotLimits {
        SnapshotLimits {
            max_files: 8,
            max_file_bytes: 64,
            max_total_bytes: 256,
            max_relative_path_bytes: 64,
        }
    }

    #[test]
    fn pinned_snapshot_contract_values_are_exact() {
        assert_eq!(SEMGREP_VERSION, "1.169.0");
        assert_eq!(RULES_COMMIT, "4d66ecf30bfb1809a984085f2c86a8c3915bfc71");
        assert_eq!(COMMAND_SCHEMA_VERSION, 1);
        assert_eq!(SNAPSHOT_LIMITS.max_files, 25_000);
        assert_eq!(SNAPSHOT_LIMITS.max_file_bytes, 2 * 1024 * 1024);
        assert_eq!(SNAPSHOT_LIMITS.max_total_bytes, 512 * 1024 * 1024);
        assert_eq!(SNAPSHOT_LIMITS.max_relative_path_bytes, 4_096);
    }

    #[test]
    fn snapshot_uses_discovery_source_set_and_preserves_relative_paths() {
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        write(
            project.path(),
            ".gitignore",
            b"build/\nfuzz_workspace/\nvendor/\n",
        );
        write(
            project.path(),
            "src/parser.c",
            b"int parse(const char *s) { return s[0]; }\n",
        );
        write(
            project.path(),
            "include/parser.h",
            b"int parse(const char *s);\n",
        );
        write(
            project.path(),
            "src/not_cpp.cpp",
            b"int cpp_only(int x) { return x; }\n",
        );
        write(
            project.path(),
            ".git/hidden.c",
            b"int hidden(int x) { return x; }\n",
        );
        write(
            project.path(),
            "build/generated.c",
            b"int built(int x) { return x; }\n",
        );
        write(
            project.path(),
            "fuzz_workspace/runtime.c",
            b"int runtime(int x) { return x; }\n",
        );
        write(
            project.path(),
            "vendor/third_party.c",
            b"int vendored(int x) { return x; }\n",
        );

        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let selected =
            hf_discovery::discoverable_source_files(&canonical, TargetLanguage::C).unwrap();
        assert_eq!(
            selected,
            vec![
                PathBuf::from("include/parser.h"),
                PathBuf::from("src/parser.c")
            ]
        );

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let snapshot = stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .unwrap();
        assert_eq!(
            snapshot.relative_paths,
            selected.into_iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            std::fs::read(snapshot.source_dir.join("src/parser.c")).unwrap(),
            b"int parse(const char *s) { return s[0]; }\n"
        );
        assert!(snapshot.output_dir.is_dir());
        assert_eq!(snapshot.file_count, 2);
        assert_eq!(snapshot.total_bytes, 68);
        cleanup_operation_root_in(&canonical_workspace, &snapshot.operation_root).unwrap();
    }

    #[test]
    fn digest_is_stable_by_sorted_path_and_changes_with_path_or_bytes() {
        let first = vec![
            (PathBuf::from("z.c"), b"z".to_vec()),
            (PathBuf::from("a.c"), b"a".to_vec()),
        ];
        let reversed = vec![
            (PathBuf::from("a.c"), b"a".to_vec()),
            (PathBuf::from("z.c"), b"z".to_vec()),
        ];
        let path_changed = vec![
            (PathBuf::from("b.c"), b"a".to_vec()),
            (PathBuf::from("z.c"), b"z".to_vec()),
        ];
        let bytes_changed = vec![
            (PathBuf::from("a.c"), b"A".to_vec()),
            (PathBuf::from("z.c"), b"z".to_vec()),
        ];
        let baseline = digest_ordered_sources(first).unwrap();
        assert_eq!(baseline, digest_ordered_sources(reversed).unwrap());
        assert_ne!(baseline, digest_ordered_sources(path_changed).unwrap());
        assert_ne!(baseline, digest_ordered_sources(bytes_changed).unwrap());
    }

    #[test]
    fn live_digest_matches_staged_digest_without_creating_artifacts() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "b.c", b"bbb");
        write(project.path(), "a.h", b"aaa");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let snapshot = stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .unwrap();
        let entries_before = std::fs::read_dir(workspace.path()).unwrap().count();
        let digest =
            digest_live_sources_with_limits(&canonical, TargetLanguage::C, tiny_limits()).unwrap();
        assert_eq!(digest, snapshot.source_sha256);
        assert_eq!(
            std::fs::read_dir(workspace.path()).unwrap().count(),
            entries_before
        );
        cleanup_operation_root_in(&canonical_workspace, &snapshot.operation_root).unwrap();
    }

    #[test]
    fn injected_limits_reject_one_over_each_bound() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "a.c", b"aaa");
        write(project.path(), "b.h", b"bbb");
        let canonical = std::fs::canonicalize(project.path()).unwrap();

        let cases = [
            SnapshotLimits {
                max_files: 1,
                ..tiny_limits()
            },
            SnapshotLimits {
                max_file_bytes: 2,
                ..tiny_limits()
            },
            SnapshotLimits {
                max_total_bytes: 5,
                ..tiny_limits()
            },
            SnapshotLimits {
                max_relative_path_bytes: 2,
                ..tiny_limits()
            },
        ];
        for limits in cases {
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            let error = stage_source_snapshot_at_with_limits(
                &canonical,
                TargetLanguage::C,
                Uuid::new_v4(),
                &canonical_workspace,
                limits,
            )
            .unwrap_err();
            assert!(error.to_string().contains("snapshot"), "{error}");
            assert!(
                !workspace.path().join("semgrep").exists()
                    || std::fs::read_dir(workspace.path().join("semgrep"))
                        .unwrap()
                        .next()
                        .is_none(),
                "failed staging left an operation directory"
            );
        }
    }

    #[test]
    fn unsafe_selected_paths_and_outside_files_fail_closed() {
        let project = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(project.path(), "safe.c", b"safe");
        write(outside.path(), "outside.c", b"outside");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let absolute = outside.path().join("outside.c");
        let unsafe_paths = [
            vec![PathBuf::from("../outside.c")],
            vec![absolute],
            vec![PathBuf::from(".")],
        ];
        for paths in unsafe_paths {
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            assert!(stage_selected_paths_at_with_limits(
                &canonical,
                paths,
                Uuid::new_v4(),
                &canonical_workspace,
                tiny_limits(),
            )
            .is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_special_file_and_identity_replacement_fail_closed() {
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let project = tempfile::tempdir().unwrap();
        write(project.path(), "real.c", b"real");
        symlink(project.path().join("real.c"), project.path().join("link.c")).unwrap();
        let listener = UnixListener::bind(project.path().join("socket.c")).unwrap();
        let canonical = std::fs::canonicalize(project.path()).unwrap();

        for relative in ["link.c", "socket.c"] {
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            assert!(stage_selected_paths_at_with_limits(
                &canonical,
                vec![PathBuf::from(relative)],
                Uuid::new_v4(),
                &canonical_workspace,
                tiny_limits(),
            )
            .is_err());
        }

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let original = canonical.join("real.c");
        let moved = canonical.join("moved.c");
        assert!(super::stage_selected_paths_at_with_hook(
            &canonical,
            vec![PathBuf::from("real.c")],
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
            || {
                std::fs::rename(&original, &moved).unwrap();
                std::fs::write(&original, b"real").unwrap();
            },
        )
        .is_err());

        write(project.path(), "mutable.c", b"same");
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let mutable = canonical.join("mutable.c");
        assert!(super::stage_selected_paths_at_with_hook(
            &canonical,
            vec![PathBuf::from("mutable.c")],
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
            || std::fs::write(&mutable, b"changed").unwrap(),
        )
        .is_err());

        let outside_parent = tempfile::tempdir().unwrap();
        write(outside_parent.path(), "outside.c", b"outside");
        symlink(outside_parent.path(), canonical.join("linked-parent")).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        assert!(stage_selected_paths_at_with_limits(
            &canonical,
            vec![PathBuf::from("linked-parent/outside.c")],
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .is_err());
        drop(listener);
    }

    #[test]
    fn staging_never_overwrites_an_existing_operation_directory() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "input.c", b"input");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation_id = Uuid::new_v4();
        let operation = canonical_workspace
            .join("semgrep")
            .join(operation_id.to_string());
        std::fs::create_dir_all(&operation).unwrap();
        write(&operation, "owner-marker", b"existing");

        assert!(stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            operation_id,
            &canonical_workspace,
            tiny_limits(),
        )
        .is_err());
        assert_eq!(
            std::fs::read(operation.join("owner-marker")).unwrap(),
            b"existing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_directories_and_files_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let project = tempfile::tempdir().unwrap();
        write(project.path(), "src/input.c", b"input");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let snapshot = stage_source_snapshot_at_with_limits(
            &canonical,
            TargetLanguage::C,
            Uuid::new_v4(),
            &canonical_workspace,
            tiny_limits(),
        )
        .unwrap();

        for directory in [
            &snapshot.operation_root,
            &snapshot.source_dir,
            &snapshot.output_dir,
            &snapshot.source_dir.join("src"),
        ] {
            let mode = std::fs::metadata(directory).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "unexpected mode for {}", directory.display());
        }
        let mode = std::fs::metadata(snapshot.source_dir.join("src/input.c"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        cleanup_operation_root_in(&canonical_workspace, &snapshot.operation_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn staging_rejects_swapped_owned_directory_paths_without_touching_external_trees() {
        use std::os::unix::fs::symlink;

        for point in [
            StageMutationPoint::SemgrepRoot,
            StageMutationPoint::OperationRoot,
            StageMutationPoint::SourceRoot,
            StageMutationPoint::DestinationParent,
        ] {
            let project = tempfile::tempdir().unwrap();
            write(project.path(), "nested/input.c", b"input");
            let canonical = std::fs::canonicalize(project.path()).unwrap();
            let workspace = tempfile::tempdir().unwrap();
            let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
            let outside = tempfile::tempdir().unwrap();
            write(outside.path(), "must-survive", b"external");
            let operation_id = Uuid::new_v4();
            let semgrep = canonical_workspace.join("semgrep");
            let operation = semgrep.join(operation_id.to_string());
            let source = operation.join("source");
            let nested = source.join("nested");
            let mut swapped = false;

            let result = stage_selected_paths_at_with_stage_hook(
                &canonical,
                vec![PathBuf::from("nested/input.c")],
                operation_id,
                &canonical_workspace,
                tiny_limits(),
                |observed| {
                    if observed != point || swapped {
                        return;
                    }
                    swapped = true;
                    let (target, held) = match point {
                        StageMutationPoint::SemgrepRoot => {
                            (semgrep.clone(), canonical_workspace.join("semgrep-held"))
                        }
                        StageMutationPoint::OperationRoot => (
                            operation.clone(),
                            semgrep.join(format!("{operation_id}-held")),
                        ),
                        StageMutationPoint::SourceRoot => {
                            (source.clone(), operation.join("source-held"))
                        }
                        StageMutationPoint::DestinationParent => {
                            (nested.clone(), source.join("nested-held"))
                        }
                    };
                    std::fs::rename(&target, held).unwrap();
                    symlink(outside.path(), target).unwrap();
                },
            );

            assert!(swapped, "test did not reach {point:?}");
            assert!(result.is_err(), "{point:?} swap must fail closed");
            assert_eq!(
                std::fs::read(outside.path().join("must-survive")).unwrap(),
                b"external"
            );
            let external_entries = std::fs::read_dir(outside.path()).unwrap().count();
            assert_eq!(
                external_entries, 1,
                "{point:?} staging wrote through a replacement pathname"
            );
        }
    }

    #[test]
    fn aggregate_limit_rejects_before_allocating_or_reading_the_next_file() {
        let project = tempfile::tempdir().unwrap();
        write(project.path(), "a.c", b"aaaa");
        write(project.path(), "b.c", b"bbbb");
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let mut read_paths = Vec::new();
        let limits = SnapshotLimits {
            max_total_bytes: 4,
            ..tiny_limits()
        };

        let result = digest_live_sources_with_limits_and_read_hook(
            &canonical,
            TargetLanguage::C,
            limits,
            |path| read_paths.push(path.to_path_buf()),
        );

        assert!(result.is_err());
        assert_eq!(
            read_paths,
            vec![PathBuf::from("a.c")],
            "the second file reached the allocation/read boundary"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_without_a_writer_fails_promptly_and_cleans_the_operation() {
        use std::time::{Duration, Instant};

        let project = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(project.path().join("blocked.c"))
            .status()
            .unwrap()
            .success());
        let canonical = std::fs::canonicalize(project.path()).unwrap();
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation_id = Uuid::new_v4();

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("semgrep::snapshot_tests::fifo_stage_child")
            .env("OXFUZZ_FIFO_TEST_PROJECT", &canonical)
            .env("OXFUZZ_FIFO_TEST_WORKSPACE", &canonical_workspace)
            .env("OXFUZZ_FIFO_TEST_OPERATION", operation_id.to_string())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.is_some_and(|status| status.success()),
            "opening a FIFO without O_NONBLOCK did not fail promptly"
        );
        assert!(
            !canonical_workspace.join("semgrep").exists()
                || std::fs::read_dir(canonical_workspace.join("semgrep"))
                    .unwrap()
                    .next()
                    .is_none(),
            "FIFO failure left an operation directory"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_stage_child() {
        let Ok(project) = std::env::var("OXFUZZ_FIFO_TEST_PROJECT") else {
            return;
        };
        let workspace = PathBuf::from(std::env::var("OXFUZZ_FIFO_TEST_WORKSPACE").unwrap());
        let operation_id =
            Uuid::parse_str(&std::env::var("OXFUZZ_FIFO_TEST_OPERATION").unwrap()).unwrap();
        let result = stage_selected_paths_at_with_limits(
            Path::new(&project),
            vec![PathBuf::from("blocked.c")],
            operation_id,
            &workspace,
            tiny_limits(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn cleanup_removes_only_owned_operation_directory() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let semgrep = canonical_workspace.join("semgrep");
        std::fs::create_dir(&semgrep).unwrap();
        let operation_id = Uuid::new_v4();
        let sibling_id = Uuid::new_v4();
        let operation = semgrep.join(operation_id.to_string());
        let sibling = semgrep.join(sibling_id.to_string());
        std::fs::create_dir(&operation).unwrap();
        std::fs::create_dir(&sibling).unwrap();
        write(&operation, "source/input.c", b"data");

        cleanup_operation_root_in(&canonical_workspace, &operation).unwrap();
        assert!(!operation.exists());
        assert!(sibling.is_dir());
        assert!(
            cleanup_operation_root_in(&canonical_workspace, &canonical_workspace).is_err(),
            "the managed root itself is not an operation"
        );
        assert!(
            cleanup_operation_root_in(&canonical_workspace, &sibling.join("nested")).is_err(),
            "nested or absent targets are ambiguous"
        );
    }

    #[test]
    fn cleanup_treats_absent_semgrep_parent_and_uuid_child_as_idempotent() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation = canonical_workspace
            .join("semgrep")
            .join(Uuid::new_v4().to_string());

        cleanup_operation_root_in(&canonical_workspace, &operation).unwrap();

        std::fs::create_dir(canonical_workspace.join("semgrep")).unwrap();
        cleanup_operation_root_in(&canonical_workspace, &operation).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_workspace_replacement_while_proving_semgrep_absent() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let canonical_workspace = std::fs::canonicalize(&workspace).unwrap();
        let operation_id = Uuid::new_v4();
        let operation = canonical_workspace
            .join("semgrep")
            .join(operation_id.to_string());
        let held_workspace = root.path().join("workspace-held");

        let result = super::cleanup_operation_root_in_with_hooks(
            &canonical_workspace,
            &operation,
            || {
                std::fs::rename(&canonical_workspace, &held_workspace).unwrap();
                std::fs::create_dir_all(&operation).unwrap();
                write(&operation, "must-survive", b"replacement");
            },
            || {},
            || {},
        );

        assert!(matches!(result, Err(ClassifiedError::Validation(_))));
        assert_eq!(
            std::fs::read(operation.join("must-survive")).unwrap(),
            b"replacement"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_semgrep_parent_recreation_while_proving_absence() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation = canonical_workspace
            .join("semgrep")
            .join(Uuid::new_v4().to_string());

        let result = super::cleanup_operation_root_in_with_hooks(
            &canonical_workspace,
            &operation,
            || {},
            || {
                std::fs::create_dir_all(&operation).unwrap();
                write(&operation, "must-survive", b"recreated");
            },
            || {},
        );

        assert!(matches!(result, Err(ClassifiedError::Validation(_))));
        assert_eq!(
            std::fs::read(operation.join("must-survive")).unwrap(),
            b"recreated"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_exact_child_recreation_while_proving_absence() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        std::fs::create_dir(canonical_workspace.join("semgrep")).unwrap();
        let operation = canonical_workspace
            .join("semgrep")
            .join(Uuid::new_v4().to_string());

        let result = super::cleanup_operation_root_in_with_hooks(
            &canonical_workspace,
            &operation,
            || {},
            || {
                std::fs::create_dir(&operation).unwrap();
                write(&operation, "must-survive", b"recreated-child");
            },
            || {},
        );

        assert!(matches!(result, Err(ClassifiedError::Validation(_))));
        assert_eq!(
            std::fs::read(operation.join("must-survive")).unwrap(),
            b"recreated-child"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_accepts_descriptor_proven_missing_semgrep_parent() {
        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let operation = canonical_workspace
            .join("semgrep")
            .join(Uuid::new_v4().to_string());

        cleanup_operation_root_in(&canonical_workspace, &operation).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_symlinked_ancestors_and_targets() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), canonical_workspace.join("semgrep")).unwrap();
        assert!(cleanup_operation_root_in(
            &canonical_workspace,
            &canonical_workspace
                .join("semgrep")
                .join(Uuid::new_v4().to_string())
        )
        .is_err());

        std::fs::remove_file(canonical_workspace.join("semgrep")).unwrap();
        std::fs::create_dir(canonical_workspace.join("semgrep")).unwrap();
        let target = canonical_workspace
            .join("semgrep")
            .join(Uuid::new_v4().to_string());
        symlink(outside.path(), &target).unwrap();
        assert!(cleanup_operation_root_in(&canonical_workspace, &target).is_err());
        assert!(outside.path().is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_rejects_an_ancestor_replaced_after_validation() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let canonical_workspace = std::fs::canonicalize(workspace.path()).unwrap();
        let semgrep = canonical_workspace.join("semgrep");
        std::fs::create_dir(&semgrep).unwrap();
        let operation_id = Uuid::new_v4();
        let operation = semgrep.join(operation_id.to_string());
        std::fs::create_dir(&operation).unwrap();
        write(&operation, "source/original.c", b"original");

        let outside = tempfile::tempdir().unwrap();
        let external_operation = outside.path().join(operation_id.to_string());
        std::fs::create_dir(&external_operation).unwrap();
        write(&external_operation, "must-survive", b"external");
        let held_semgrep = canonical_workspace.join("semgrep-held");

        let result =
            super::cleanup_operation_root_in_with_hook(&canonical_workspace, &operation, || {
                std::fs::rename(&semgrep, &held_semgrep).unwrap();
                symlink(outside.path(), &semgrep).unwrap();
            });
        assert!(result.is_err(), "an ancestor swap must fail closed");
        assert_eq!(
            std::fs::read(external_operation.join("must-survive")).unwrap(),
            b"external",
            "cleanup followed a replacement ancestor outside the managed workspace"
        );
    }
}

#[cfg(all(test, unix))]
mod process_lease_tests {
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdout, Command, Output, Stdio};
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use chrono::Utc;
    use hf_core::error::ClassifiedError;
    use hf_core::runtime::{
        CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
        SandboxOptions,
    };
    use hf_core::target::TargetLanguage;
    use hf_storage::{SemgrepRunStatus, Store};
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::{
        recover_semgrep_at_bootstrap, CompletionPausePoint, SemgrepCoordinator,
        StartupRecoveryOutcome,
    };
    use crate::ServiceContainer;

    const CHILD_ENV: &str = "OXFUZZ_SEMGREP_PROCESS_CHILD";
    const DB_ENV: &str = "OXFUZZ_SEMGREP_PROCESS_DB";
    const JOURNAL_ENV: &str = "OXFUZZ_SEMGREP_PROCESS_JOURNAL";
    const PROJECT_ENV: &str = "OXFUZZ_SEMGREP_PROCESS_PROJECT";
    const PAUSE_ENV: &str = "OXFUZZ_SEMGREP_PROCESS_PAUSE";
    const READY_PREFIX: &str = "OXFUZZ_SEMGREP_READY:";
    const IMAGE_ID: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[derive(Clone, Copy)]
    enum ProcessPause {
        AfterOwnershipBeforeDurableWrite,
        AfterBegin,
        BeforeClose,
        AfterCloseBeforeLeaseRelease,
    }

    impl ProcessPause {
        fn as_env(self) -> &'static str {
            match self {
                Self::AfterOwnershipBeforeDurableWrite => "after_ownership_before_durable_write",
                Self::AfterBegin => "after_begin",
                Self::BeforeClose => "before_close",
                Self::AfterCloseBeforeLeaseRelease => "after_close_before_lease_release",
            }
        }

        fn completion_point(self) -> CompletionPausePoint {
            match self {
                Self::AfterOwnershipBeforeDurableWrite => {
                    CompletionPausePoint::AfterOwnershipBeforeDurableWrite
                }
                Self::AfterBegin => CompletionPausePoint::AfterBegin,
                Self::BeforeClose => CompletionPausePoint::BeforeClose,
                Self::AfterCloseBeforeLeaseRelease => {
                    CompletionPausePoint::AfterCloseBeforeLeaseRelease
                }
            }
        }

        fn admission_is_pending(self) -> bool {
            matches!(self, Self::AfterOwnershipBeforeDurableWrite)
        }
    }

    struct ProcessFixture {
        _root: tempfile::TempDir,
        db: PathBuf,
        home: PathBuf,
        journal: PathBuf,
        project: PathBuf,
        workspace: PathBuf,
    }

    impl ProcessFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let project = root.path().join("project");
            std::fs::create_dir(&project).unwrap();
            std::fs::write(
                project.join("parser.c"),
                b"int parse(const char *input) { return input[0]; }\n",
            )
            .unwrap();
            Self {
                db: root.path().join("shared.db"),
                home: root.path().join("home"),
                journal: root.path().join("semgrep-journal"),
                project: std::fs::canonicalize(project).unwrap(),
                workspace: root.path().join("workspace"),
                _root: root,
            }
        }

        fn child_command(&self, test_name: &str) -> Command {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg(test_name)
                .arg("--nocapture")
                .env(CHILD_ENV, "1")
                .env(DB_ENV, &self.db)
                .env(JOURNAL_ENV, &self.journal)
                .env(PROJECT_ENV, &self.project)
                .env("HF_DB_PATH", &self.db)
                .env("HF_WORKSPACE_DIR", &self.workspace)
                .env("HF_CONFIG_DIR", self.home.join("config"))
                .env("HF_GUARDRAILS", "permissive")
                .env("HOME", &self.home)
                .env_remove("XDG_DATA_HOME");
            command
        }
    }

    struct AdmittedChild {
        child: Child,
        stdout: BufReader<ChildStdout>,
        operation_id: Uuid,
    }

    struct RecordingRuntime;

    #[async_trait]
    impl RuntimeAdapter for RecordingRuntime {
        async fn run_command(
            &self,
            _cmd: &[String],
            _cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            panic!("Semgrep must use the typed streaming sandbox profile")
        }

        async fn resolve_image_reference(
            &self,
            image: &str,
        ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
            assert_eq!(image, hf_runtime::SANDBOX_IMAGE);
            ImmutableImageReference::from_sha256_id(IMAGE_ID).map(Some)
        }

        async fn run_command_streaming_opts(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
            options: &SandboxOptions,
            _cancel: &CancellationToken,
            _on_line: &hf_core::runtime::LineSink<'_>,
        ) -> Result<CommandResult, ClassifiedError> {
            let output = options
                .extra_mounts
                .iter()
                .find(|mount| mount.container_path == "/work/output")
                .unwrap()
                .host_path
                .join("semgrep.json");
            std::fs::write(
                output,
                br#"{
                    "version":"1.169.0",
                    "results":[{
                        "check_id":"cpp.lang.security.signal",
                        "path":"parser.c",
                        "start":{"line":1,"col":1},
                        "end":{"line":1,"col":4},
                        "extra":{"message":"advisory signal","severity":"WARNING"}
                    }],
                    "errors":[],
                    "paths":{"scanned":["parser.c"],"skipped":[]}
                }"#,
            )
            .unwrap();
            Ok(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            })
        }

        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            panic!("Semgrep staging is service-owned")
        }

        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            panic!("Semgrep output acquisition is service-owned")
        }
    }

    fn child_path(name: &str) -> String {
        format!("semgrep::process_lease_tests::{name}")
    }

    fn child_value(name: &str) -> PathBuf {
        PathBuf::from(std::env::var(name).unwrap())
    }

    async fn child_service() -> (ServiceContainer, Arc<Store>) {
        let store = Arc::new(Store::connect(child_value(DB_ENV)).await.unwrap());
        let mut service =
            ServiceContainer::new(Arc::new(RecordingRuntime), None).with_store(Arc::clone(&store));
        service.semgrep = Arc::new(SemgrepCoordinator::persistent(child_value(JOURNAL_ENV)));
        (service, store)
    }

    async fn persist_child_inventory(store: &Store, project: &Path) {
        let inventory = hf_discovery::discover(project, TargetLanguage::C)
            .await
            .unwrap();
        store.save_inventory(&inventory, Utc::now()).await.unwrap();
    }

    fn spawn_admitted_child(fixture: &ProcessFixture, pause: ProcessPause) -> AdmittedChild {
        let mut child = fixture
            .child_command(&child_path("admitted_worker_child"))
            .env(PAUSE_ENV, pause.as_env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let operation_id = loop {
            let mut line = String::new();
            if stdout.read_line(&mut line).unwrap() == 0 {
                let mut stderr = String::new();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                let status = child.wait().unwrap();
                panic!(
                    "admitted child exited before signalling readiness: \
                     status={status}; stderr={stderr}"
                );
            }
            if let Some(value) = line.trim().strip_prefix(READY_PREFIX) {
                break Uuid::parse_str(value).unwrap();
            }
        };
        AdmittedChild {
            child,
            stdout,
            operation_id,
        }
    }

    fn child_output(fixture: &ProcessFixture, name: &str) -> Output {
        fixture
            .child_command(&child_path(name))
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn assert_child_success(output: &Output, role: &str) {
        assert!(
            output.status.success(),
            "{role} child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn release_and_wait(mut admitted: AdmittedChild) {
        admitted
            .child
            .stdin
            .take()
            .unwrap()
            .write_all(b"release\n")
            .unwrap();
        let mut remaining_stdout = String::new();
        admitted
            .stdout
            .read_to_string(&mut remaining_stdout)
            .unwrap();
        let output = admitted.child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "admitted child failed\nstdout:\n{remaining_stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    async fn assert_live_ownership(pause: ProcessPause) {
        let fixture = ProcessFixture::new();
        let admitted = spawn_admitted_child(&fixture, pause);
        let operation_id = admitted.operation_id;
        let store = Store::connect(&fixture.db).await.unwrap();
        let journal = crate::semgrep_recovery::SemgrepJournal::open(fixture.journal.clone());
        let operation_root = fixture
            .workspace
            .join("semgrep")
            .join(operation_id.to_string());

        let recovery = child_output(&fixture, "recovery_child");
        assert_child_success(&recovery, "recovery");
        let contender = child_output(&fixture, "same_project_start_child");
        assert_child_success(&contender, "same-project admission");

        let run = store.semgrep_run(operation_id).await.unwrap().unwrap();
        match pause {
            ProcessPause::AfterBegin => {
                assert_eq!(run.status, SemgrepRunStatus::Staging);
                assert!(operation_root.exists());
            }
            ProcessPause::BeforeClose => {
                assert_eq!(run.status, SemgrepRunStatus::Done);
                assert!(!journal.is_closed(operation_id).unwrap());
            }
            ProcessPause::AfterOwnershipBeforeDurableWrite
            | ProcessPause::AfterCloseBeforeLeaseRelease => {
                panic!("unsupported live-ownership pause")
            }
        }
        assert_eq!(journal.interrupted().unwrap().len(), 1);

        release_and_wait(admitted);
    }

    async fn assert_project_ownership_boundary(pause: ProcessPause) {
        let fixture = ProcessFixture::new();
        let admitted = spawn_admitted_child(&fixture, pause);
        let operation_id = admitted.operation_id;
        let store = Store::connect(&fixture.db).await.unwrap();
        let journal = crate::semgrep_recovery::SemgrepJournal::open(fixture.journal.clone());

        match pause {
            ProcessPause::AfterOwnershipBeforeDurableWrite => {
                assert!(store.semgrep_run(operation_id).await.unwrap().is_none());
                let run_count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM semgrep_enrichment_runs")
                        .fetch_one(store.pool())
                        .await
                        .unwrap();
                assert_eq!(run_count, 0);
            }
            ProcessPause::AfterCloseBeforeLeaseRelease => {
                assert_eq!(
                    store
                        .semgrep_run(operation_id)
                        .await
                        .unwrap()
                        .unwrap()
                        .status,
                    SemgrepRunStatus::Done
                );
                assert!(journal.is_closed(operation_id).unwrap());
            }
            ProcessPause::AfterBegin | ProcessPause::BeforeClose => {
                panic!("unsupported ownership-boundary pause")
            }
        }

        let contender = child_output(&fixture, "same_project_start_child");
        assert_child_success(&contender, "same-project admission");
        release_and_wait(admitted);

        let successor = child_output(&fixture, "same_project_start_succeeds_child");
        assert_child_success(&successor, "same-project successor");
    }

    #[tokio::test]
    async fn admitted_child_blocks_recovery_and_same_project_start_after_begin() {
        assert_live_ownership(ProcessPause::AfterBegin).await;
    }

    #[tokio::test]
    async fn admitted_child_blocks_recovery_and_same_project_start_before_close() {
        assert_live_ownership(ProcessPause::BeforeClose).await;
    }

    #[tokio::test]
    async fn admitted_child_blocks_same_project_start_before_durable_write() {
        assert_project_ownership_boundary(ProcessPause::AfterOwnershipBeforeDurableWrite).await;
    }

    #[tokio::test]
    async fn admitted_child_blocks_same_project_start_after_close_until_lease_release() {
        assert_project_ownership_boundary(ProcessPause::AfterCloseBeforeLeaseRelease).await;
    }

    #[tokio::test]
    async fn admitted_worker_child() {
        if std::env::var(CHILD_ENV).as_deref() != Ok("1") {
            return;
        }
        let workspace = crate::initialize_workspace_root().unwrap();
        assert_eq!(
            workspace,
            std::fs::canonicalize(child_value("HF_WORKSPACE_DIR")).unwrap()
        );
        let project = child_value(PROJECT_ENV);
        let (service, store) = child_service().await;
        persist_child_inventory(&store, &project).await;
        let pause = match std::env::var(PAUSE_ENV).unwrap().as_str() {
            "after_ownership_before_durable_write" => {
                ProcessPause::AfterOwnershipBeforeDurableWrite
            }
            "after_begin" => ProcessPause::AfterBegin,
            "before_close" => ProcessPause::BeforeClose,
            "after_close_before_lease_release" => ProcessPause::AfterCloseBeforeLeaseRelease,
            other => panic!("unknown process pause {other}"),
        };
        let (reached, release) = service
            .semgrep
            .install_completion_pause(pause.completion_point());
        let start_service = service.clone();
        let start_project = project.clone();
        let mut start = Some(tokio::spawn(async move {
            start_service
                .start_semgrep_enrichment(start_project, TargetLanguage::C)
                .await
        }));
        if tokio::time::timeout(Duration::from_secs(10), reached.notified())
            .await
            .is_err()
        {
            let rows = sqlx::query_as::<_, (String, String)>(
                "SELECT id, status FROM semgrep_enrichment_runs ORDER BY started_at",
            )
            .fetch_all(store.pool())
            .await
            .unwrap();
            panic!(
                "admitted worker must reach the requested pause: rows={rows:?}; \
                 journal_error={:?}; recovery_health={:?}; interrupted={:?}",
                service.semgrep.journal.durability_error(),
                service.semgrep.ensure_recovery_healthy(),
                service.semgrep.journal.interrupted()
            );
        }
        let operation_id = if pause.admission_is_pending() {
            service
                .semgrep
                .active_operation_for_project(&project)
                .expect("owned admission must reserve the canonical project")
        } else {
            start
                .take()
                .unwrap()
                .await
                .unwrap()
                .expect("admission must return an operation")
        };

        println!("{READY_PREFIX}{operation_id}");
        std::io::stdout().flush().unwrap();
        let mut release_signal = [0_u8; 1];
        std::io::stdin().read_exact(&mut release_signal).unwrap();
        release.notify_one();
        if let Some(start) = start {
            assert_eq!(start.await.unwrap().unwrap(), operation_id);
        }

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let run = store.semgrep_run(operation_id).await.unwrap().unwrap();
                if run.status == SemgrepRunStatus::Done
                    && service.semgrep.journal.is_closed(operation_id).unwrap()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("admitted worker must finish successfully after release");
    }

    #[tokio::test]
    async fn recovery_child() {
        if std::env::var(CHILD_ENV).as_deref() != Ok("1") {
            return;
        }
        let store = Store::connect(child_value(DB_ENV)).await.unwrap();
        let semgrep = SemgrepCoordinator::persistent(child_value(JOURNAL_ENV));
        let workspace = std::fs::canonicalize(child_value("HF_WORKSPACE_DIR")).unwrap();
        let outcome = recover_semgrep_at_bootstrap(&store, &semgrep, &workspace)
            .await
            .unwrap();
        assert_eq!(outcome, StartupRecoveryOutcome::Deferred);
        assert!(semgrep.ensure_recovery_healthy().is_err());
    }

    #[tokio::test]
    async fn same_project_start_child() {
        if std::env::var(CHILD_ENV).as_deref() != Ok("1") {
            return;
        }
        let project = child_value(PROJECT_ENV);
        let (service, _) = child_service().await;
        let error = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("busy"), "{error}");
    }

    #[tokio::test]
    async fn same_project_start_succeeds_child() {
        if std::env::var(CHILD_ENV).as_deref() != Ok("1") {
            return;
        }
        let project = child_value(PROJECT_ENV);
        let (service, store) = child_service().await;
        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if store
                    .semgrep_run(operation_id)
                    .await
                    .unwrap()
                    .is_some_and(|run| run.status == SemgrepRunStatus::Done)
                    && service.semgrep.journal.is_closed(operation_id).unwrap()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("successor operation must finish and close");
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use async_trait::async_trait;
    use chrono::Utc;
    use hf_core::error::ClassifiedError;
    use hf_core::runtime::{
        CommandResult, CommandTermination, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
        SandboxOptions,
    };
    use hf_core::target::{
        InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetInventory, TargetKind,
        TargetLanguage,
    };
    use hf_storage::{SemgrepRunStatus, Store};
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};
    use uuid::Uuid;

    use super::{
        recover_semgrep_at_bootstrap, CompletionPausePoint, SemgrepCancelOutcome,
        SemgrepCoordinator, SemgrepOperationState, SemgrepOverlayState,
    };
    use crate::semgrep_recovery::AppendFailurePoint;
    use crate::ServiceContainer;

    const IMAGE_ID: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    pub(super) fn lifecycle_test_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[derive(Clone)]
    struct CaptureSubscriber {
        next_id: Arc<std::sync::atomic::AtomicU64>,
        text: Arc<Mutex<String>>,
    }

    impl CaptureSubscriber {
        fn new(text: Arc<Mutex<String>>) -> Self {
            Self {
                next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
                text,
            }
        }
    }

    struct CaptureVisitor<'a> {
        text: &'a Arc<Mutex<String>>,
    }

    impl Visit for CaptureVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;

            let mut text = self.text.lock().unwrap();
            let _ = write!(text, "{}={value:?};", field.name());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            use std::fmt::Write as _;

            let mut text = self.text.lock().unwrap();
            let _ = write!(text, "{}={value};", field.name());
        }

        fn record_u64(&mut self, field: &Field, value: u64) {
            use std::fmt::Write as _;

            let mut text = self.text.lock().unwrap();
            let _ = write!(text, "{}={value};", field.name());
        }
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, attributes: &Attributes<'_>) -> Id {
            attributes.record(&mut CaptureVisitor { text: &self.text });
            Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed))
        }

        fn record(&self, _span: &Id, values: &Record<'_>) {
            values.record(&mut CaptureVisitor { text: &self.text });
        }

        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

        fn event(&self, event: &Event<'_>) {
            event.record(&mut CaptureVisitor { text: &self.text });
        }

        fn enter(&self, _span: &Id) {}

        fn exit(&self, _span: &Id) {}
    }

    #[derive(Clone, Copy)]
    pub(super) enum RuntimeBehavior {
        Block,
        Completed(i32),
        CompletedWithUnmatchedFinding,
        TimedOut,
        MissingOutput,
        OversizedOutput,
        SymlinkOutput,
        TruncatedCapture,
    }

    #[derive(Debug, Clone)]
    struct RuntimeCall {
        command: Vec<String>,
        cwd: PathBuf,
        limits: ResourceLimits,
        options: SandboxOptions,
    }

    pub(super) struct RecordingRuntime {
        image: bool,
        behavior: RuntimeBehavior,
        calls: Mutex<Vec<RuntimeCall>>,
        started: Notify,
        release: Notify,
        cancellation_observed: AtomicBool,
    }

    impl RecordingRuntime {
        pub(super) fn new(behavior: RuntimeBehavior) -> Self {
            Self {
                image: true,
                behavior,
                calls: Mutex::new(Vec::new()),
                started: Notify::new(),
                release: Notify::new(),
                cancellation_observed: AtomicBool::new(false),
            }
        }

        fn without_image() -> Self {
            Self {
                image: false,
                ..Self::new(RuntimeBehavior::Completed(0))
            }
        }

        fn calls(&self) -> Vec<RuntimeCall> {
            self.calls.lock().unwrap().clone()
        }

        async fn wait_started(&self) {
            tokio::time::timeout(Duration::from_secs(5), self.started.notified())
                .await
                .expect("runtime must start");
        }

        fn output_dir(options: &SandboxOptions) -> PathBuf {
            options
                .extra_mounts
                .iter()
                .find(|mount| mount.container_path == "/work/output")
                .expect("output mount")
                .host_path
                .clone()
        }

        fn write_output(&self, options: &SandboxOptions) {
            let output = Self::output_dir(options).join("semgrep.json");
            match self.behavior {
                RuntimeBehavior::MissingOutput => {}
                RuntimeBehavior::OversizedOutput => {
                    let file = std::fs::File::create(output).unwrap();
                    file.set_len(67_108_865).unwrap();
                }
                RuntimeBehavior::SymlinkOutput => {
                    #[cfg(unix)]
                    {
                        std::os::unix::fs::symlink("/dev/null", output).unwrap();
                    }
                    #[cfg(not(unix))]
                    std::fs::write(output, b"{}").unwrap();
                }
                RuntimeBehavior::CompletedWithUnmatchedFinding => std::fs::write(
                    output,
                    br#"{
                        "version":"1.169.0",
                        "results":[{
                            "check_id":"cpp.lang.security.signal",
                            "path":"parser.c",
                            "start":{"line":1,"col":1},
                            "end":{"line":1,"col":4},
                            "extra":{"message":"matched advisory signal","severity":"WARNING"}
                        },{
                            "check_id":"cpp.lang.security.file-signal",
                            "path":"parser.c",
                            "start":{"line":2,"col":1},
                            "end":{"line":2,"col":4},
                            "extra":{"message":"unmatched advisory signal","severity":"INFO"}
                        }],
                        "errors":[],
                        "paths":{"scanned":["parser.c"],"skipped":[]}
                    }"#,
                )
                .unwrap(),
                _ => std::fs::write(
                    output,
                    br#"{
                        "version":"1.169.0",
                        "results":[{
                            "check_id":"cpp.lang.security.signal",
                            "path":"parser.c",
                            "start":{"line":1,"col":1},
                            "end":{"line":1,"col":4},
                            "extra":{"message":"advisory signal","severity":"WARNING"}
                        }],
                        "errors":[],
                        "paths":{"scanned":["parser.c"],"skipped":[]}
                    }"#,
                )
                .unwrap(),
            }
        }
    }

    #[async_trait]
    impl RuntimeAdapter for RecordingRuntime {
        async fn run_command(
            &self,
            _cmd: &[String],
            _cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            panic!("Semgrep must use the typed streaming sandbox profile")
        }

        async fn resolve_image_reference(
            &self,
            image: &str,
        ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
            assert_eq!(image, hf_runtime::SANDBOX_IMAGE);
            self.image
                .then(|| ImmutableImageReference::from_sha256_id(IMAGE_ID))
                .transpose()
        }

        async fn run_command_streaming_opts(
            &self,
            cmd: &[String],
            cwd: &Path,
            limits: &ResourceLimits,
            options: &SandboxOptions,
            cancel: &CancellationToken,
            _on_line: &hf_core::runtime::LineSink<'_>,
        ) -> Result<CommandResult, ClassifiedError> {
            self.calls.lock().unwrap().push(RuntimeCall {
                command: cmd.to_vec(),
                cwd: cwd.to_path_buf(),
                limits: limits.clone(),
                options: options.clone(),
            });
            self.started.notify_waiters();
            let termination = match self.behavior {
                RuntimeBehavior::Block => {
                    tokio::select! {
                        () = cancel.cancelled() => {
                            self.cancellation_observed.store(true, Ordering::Release);
                            CommandTermination::Cancelled
                        }
                        () = self.release.notified() => {
                            self.write_output(options);
                            CommandTermination::Completed
                        }
                    }
                }
                RuntimeBehavior::TimedOut => CommandTermination::TimedOut,
                _ => {
                    self.write_output(options);
                    CommandTermination::Completed
                }
            };
            let exit_code = match self.behavior {
                RuntimeBehavior::Completed(code) => code,
                _ => 0,
            };
            let stdout = if matches!(self.behavior, RuntimeBehavior::TruncatedCapture) {
                "\n[output truncated]\n".to_owned()
            } else {
                String::new()
            };
            Ok(CommandResult {
                exit_code,
                stdout,
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination,
            })
        }

        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            panic!("Semgrep staging is service-owned")
        }

        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            panic!("Semgrep output acquisition is service-owned")
        }
    }

    pub(super) fn project_fixture(root: &Path, name: &str) -> PathBuf {
        let project = root.join(name);
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("parser.c"),
            b"int parse(const char *input) { return input[0]; }\n",
        )
        .unwrap();
        std::fs::canonicalize(project).unwrap()
    }

    fn inventory(project: &Path, complete_span: bool) -> TargetInventory {
        TargetInventory {
            project_root: project.to_path_buf(),
            candidates: vec![TargetCandidate {
                id: Uuid::new_v4(),
                project_root: project.to_path_buf(),
                language: TargetLanguage::C,
                symbol: "parse".to_owned(),
                kind: TargetKind::Parser,
                location: SourceLocation {
                    file: project.join("parser.c"),
                    line: 1,
                    col: 1,
                    end_line: complete_span.then_some(1),
                    end_col: complete_span.then_some(50),
                },
                signature: Some("int parse(const char *)".to_owned()),
                input_surface: InputSurface::Bytes,
                complexity: 1,
                fit_score: 0.5,
                sanitizers: vec![Sanitizer::Address],
                rationale: "fixture".to_owned(),
                reachable_functions: Vec::new(),
                accumulated_complexity: 1,
            }],
            call_graph: std::collections::HashMap::new(),
        }
    }

    pub(super) async fn persistent_service(
        root: &Path,
        runtime: Arc<RecordingRuntime>,
    ) -> (ServiceContainer, Arc<Store>) {
        let store = Arc::new(
            Store::connect(root.join(format!("{}.db", Uuid::new_v4())))
                .await
                .unwrap(),
        );
        (
            ServiceContainer::new(runtime, None).with_store(Arc::clone(&store)),
            store,
        )
    }

    pub(super) async fn save_inventory(store: &Store, project: &Path, complete_span: bool) {
        let inventory = if complete_span {
            let mut inventory = hf_discovery::discover(project, TargetLanguage::C)
                .await
                .unwrap();
            for candidate in &mut inventory.candidates {
                candidate.fit_score = 0.5;
                candidate.rationale = "fixture".to_owned();
            }
            inventory
        } else {
            inventory(project, false)
        };
        store.save_inventory(&inventory, Utc::now()).await.unwrap();
    }

    pub(super) async fn wait_for_state(
        service: &ServiceContainer,
        id: Uuid,
        expected: SemgrepOperationState,
    ) {
        let waited = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let view = service
                    .semgrep_operation(id)
                    .await
                    .unwrap()
                    .expect("operation");
                if view.state == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(
            waited.is_ok(),
            "operation must reach {expected:?}, current view: {:?}",
            service.semgrep_operation(id).await.unwrap()
        );
    }

    pub(super) async fn wait_for_pause(reached: &Notify) {
        tokio::time::timeout(Duration::from_secs(5), reached.notified())
            .await
            .expect("worker must reach the completion pause");
    }

    async fn wait_for_recovery_degraded(service: &ServiceContainer) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while service.semgrep.ensure_recovery_healthy().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker must mark Semgrep recovery degraded");
    }

    async fn wait_for_worker_exit(service: &ServiceContainer) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while Arc::strong_count(&service.semgrep) != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Semgrep worker must release the coordinator");
    }

    #[tokio::test]
    async fn persistent_coordinator_construction_does_not_touch_the_journal_filesystem() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let missing_journal = root.path().join("missing-journal");

        let missing = SemgrepCoordinator::persistent(missing_journal.clone());
        assert!(
            !missing_journal.exists(),
            "construction must not create the journal directory"
        );
        assert!(missing.journal.durability_error().is_none());

        let corrupt_journal = root.path().join("corrupt-journal");
        std::fs::create_dir(&corrupt_journal).unwrap();
        let corrupt_id = Uuid::new_v4();
        std::fs::write(
            corrupt_journal.join(format!("{corrupt_id}.jsonl")),
            b"{broken}\n",
        )
        .unwrap();
        let corrupt = SemgrepCoordinator::persistent(corrupt_journal);
        assert!(
            corrupt.journal.durability_error().is_none(),
            "construction must not replay operation journals"
        );

        let store = Store::connect(root.path().join("recovery.db"))
            .await
            .unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let workspace = std::fs::canonicalize(workspace).unwrap();
        assert!(
            recover_semgrep_at_bootstrap(&store, &corrupt, &workspace)
                .await
                .is_err(),
            "the first recovery replay must surface corruption"
        );
        assert!(corrupt.journal.durability_error().is_some());
    }

    #[tokio::test]
    async fn cancelled_start_caller_does_not_orphan_durable_admission() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterStagingInsertBeforeBegin);

        let caller_service = service.clone();
        let caller_project = project.clone();
        let caller = tokio::spawn(async move {
            caller_service
                .start_semgrep_enrichment(caller_project, TargetLanguage::C)
                .await
        });
        wait_for_pause(&reached).await;
        let operation_id = sqlx::query_scalar::<_, String>(
            "SELECT id FROM semgrep_enrichment_runs WHERE project_root = ?1",
        )
        .bind(project.to_string_lossy().as_ref())
        .fetch_one(store.pool())
        .await
        .unwrap()
        .parse::<Uuid>()
        .unwrap();

        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        release.notify_one();

        let run = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let run = store.semgrep_run(operation_id).await.unwrap().unwrap();
                let is_terminal = matches!(
                    run.status,
                    SemgrepRunStatus::Done | SemgrepRunStatus::Failed | SemgrepRunStatus::Cancelled
                );
                let is_durably_closed = run.status != SemgrepRunStatus::Done
                    || service.semgrep.journal.is_closed(operation_id).unwrap();
                if is_terminal && is_durably_closed {
                    break run;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let run = match run {
            Ok(run) => run,
            Err(error) => {
                let current = store.semgrep_run(operation_id).await.unwrap();
                panic!(
                    "owned admission must reach a terminal state after caller cancellation: \
                     {error}; current={current:?}; active={}; journal_error={:?}; \
                     recovery_health={:?}; interrupted={:?}",
                    service.semgrep.is_active(operation_id),
                    service.semgrep.journal.durability_error(),
                    service.semgrep.ensure_recovery_healthy(),
                    service.semgrep.journal.interrupted()
                );
            }
        };
        assert!(!service.semgrep.is_active(operation_id));
        if run.status == SemgrepRunStatus::Done {
            assert!(service.semgrep.journal.is_closed(operation_id).unwrap());
        }
        assert!(service.semgrep.journal.interrupted().unwrap().is_empty());
    }

    #[tokio::test]
    async fn operation_status_survives_concurrent_compensation() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (close_reached, close_release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::BeforeClose);
        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&close_reached).await;
        assert_eq!(
            store
                .semgrep_run(operation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SemgrepRunStatus::Done
        );

        let (status_reached, status_release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterStatusParentLoad);
        let reader = {
            let service = service.clone();
            tokio::spawn(async move { service.semgrep_operation(operation_id).await })
        };
        wait_for_pause(&status_reached).await;
        store
            .compensate_semgrep_publication(
                operation_id,
                "recovered",
                "Concurrent compensation fixture",
                Utc::now(),
            )
            .await
            .unwrap();
        status_release.notify_one();

        let first = reader.await.unwrap().unwrap().unwrap();
        assert_eq!(first.state, SemgrepOperationState::Persisting);
        assert!(first.result.is_none());
        status_release.notify_one();
        let second = service
            .semgrep_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.state, SemgrepOperationState::Failed);
        assert!(second.result.is_none());

        close_release.notify_one();
        wait_for_worker_exit(&service).await;
    }

    #[tokio::test]
    async fn admission_rejects_before_runtime_spawn() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");

        let no_store_runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let no_store = ServiceContainer::new(no_store_runtime.clone(), None);
        let error = no_store
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("store"));
        assert!(no_store_runtime.calls().is_empty());

        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        let error = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::Rust)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("unsupported_language"));
        assert!(runtime.calls().is_empty());

        let error = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("inventory_missing"));
        assert!(runtime.calls().is_empty());

        save_inventory(&store, &project, false).await;
        let error = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("inventory_span_incomplete"));
        assert!(runtime.calls().is_empty());

        let absent = Arc::new(RecordingRuntime::without_image());
        let (service, store) = persistent_service(root.path(), absent.clone()).await;
        save_inventory(&store, &project, true).await;
        let error = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("sandbox_unavailable"));
        assert!(absent.calls().is_empty());
    }

    #[tokio::test]
    async fn start_is_async_and_runtime_contract_is_fixed() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;

        let operation_id = tokio::time::timeout(
            Duration::from_secs(2),
            service.start_semgrep_enrichment(project.clone(), TargetLanguage::C),
        )
        .await
        .expect("start must not await runtime")
        .unwrap();
        runtime.wait_started().await;

        let call = runtime.calls().into_iter().next().unwrap();
        assert_eq!(
            call.command,
            ["/usr/local/bin/oxfuzz-semgrep-scan".to_owned()]
        );
        assert_eq!(call.limits.max_mem_mb, 4_096);
        assert_eq!(call.limits.max_cpus, 2);
        assert_eq!(call.limits.max_duration_secs, 600);
        assert!(call.limits.env.is_empty());
        assert!(!call.limits.ptrace);
        assert_eq!(call.options.image.as_deref(), Some(IMAGE_ID));
        assert_eq!(
            call.options.network_mode,
            hf_core::runtime::SandboxNetworkMode::None
        );
        assert!(!call.options.relax_hardening);
        assert!(call.options.capabilities.is_empty());
        assert!(call.options.devices.is_empty());
        assert!(call.options.stdin.is_none());
        assert!(call.options.workspace_read_only);
        assert_eq!(call.options.max_file_size_bytes, Some(67_108_864));
        assert_eq!(call.options.max_pids, Some(128));
        assert!(call.cwd.starts_with(crate::workspace_root()));
        assert!(call
            .options
            .extra_mounts
            .iter()
            .any(|mount| { mount.container_path == "/work/source" && mount.read_only }));
        assert!(call
            .options
            .extra_mounts
            .iter()
            .any(|mount| { mount.container_path == "/work/output" && !mount.read_only }));

        let view = service
            .semgrep_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(view.operation_id, operation_id);
        assert_eq!(view.project_root, project.to_string_lossy());
        assert_eq!(view.language, "c");
        assert!(view.active);
        assert_eq!(
            service.request_semgrep_cancel(operation_id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        wait_for_state(&service, operation_id, SemgrepOperationState::Cancelled).await;
        assert!(runtime.cancellation_observed.load(Ordering::Acquire));
        assert_eq!(
            store
                .semgrep_run(operation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SemgrepRunStatus::Cancelled
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            service
                .semgrep_operation(operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            SemgrepOperationState::Cancelled,
            "cooperative cancellation must never be rewritten to failed"
        );
    }

    #[tokio::test]
    async fn admission_waits_for_workspace_lease_before_durable_writes() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        let workspace = crate::initialize_workspace_root().unwrap();
        let cleanup_lease =
            ServiceContainer::semgrep_test_workspace_cleanup_lease(&workspace).unwrap();
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterBegin);

        let pending_service = service.clone();
        let pending_project = project.clone();
        let start = tokio::spawn(async move {
            pending_service
                .start_semgrep_enrichment(pending_project, TargetLanguage::C)
                .await
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!start.is_finished());
        let run_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM semgrep_enrichment_runs WHERE project_root = ?1",
        )
        .bind(project.to_string_lossy().as_ref())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(run_count, 0);
        assert!(service.semgrep.journal.interrupted().unwrap().is_empty());
        assert!(runtime.calls().is_empty());

        drop(cleanup_lease);
        let id = tokio::time::timeout(Duration::from_secs(5), start)
            .await
            .expect("admission must continue after workspace cleanup releases")
            .unwrap()
            .unwrap();
        wait_for_pause(&reached).await;
        let run = store.semgrep_run(id).await.unwrap().unwrap();
        assert_eq!(run.status, SemgrepRunStatus::Staging);
        assert_eq!(run.project_root, project.to_string_lossy());
        assert_eq!(run.sandbox_image_sha256, &IMAGE_ID["sha256:".len()..]);
        assert_eq!(run.rules_tree_sha256, super::rules_tree_sha256());
        assert!(!run.rules_tree_sha256.contains('\n'));
        assert!(service.semgrep.is_active(id));
        let interrupted = service.semgrep.journal.interrupted().unwrap();
        assert!(interrupted.iter().any(|entry| {
            entry.operation_id == id
                && entry.project_root == project
                && entry.staging_dir_name == id.to_string()
                && entry.ready.is_none()
        }));
        assert!(runtime.calls().is_empty());

        assert_eq!(
            service.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        release.notify_one();
        wait_for_state(&service, id, SemgrepOperationState::Cancelled).await;
    }

    #[tokio::test]
    async fn same_canonical_project_is_busy_but_different_projects_run() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let first = project_fixture(root.path(), "first");
        let second = project_fixture(root.path(), "second");
        let alias = first.join("..").join("first");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &first, true).await;
        save_inventory(&store, &second, true).await;

        let first_id = service
            .start_semgrep_enrichment(first, TargetLanguage::C)
            .await
            .unwrap();
        let error = service
            .start_semgrep_enrichment(alias, TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ClassifiedError::Validation(message) if message == "Semgrep enrichment: busy"
        ));
        let second_id = service
            .start_semgrep_enrichment(second, TargetLanguage::C)
            .await
            .unwrap();

        assert_eq!(
            service.request_semgrep_cancel(first_id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        assert_eq!(
            service.request_semgrep_cancel(second_id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        wait_for_state(&service, first_id, SemgrepOperationState::Cancelled).await;
        wait_for_state(&service, second_id, SemgrepOperationState::Cancelled).await;
    }

    #[tokio::test]
    async fn database_reservation_agrees_across_service_containers() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let store = Arc::new(Store::connect(root.path().join("shared.db")).await.unwrap());
        save_inventory(&store, &project, true).await;
        let first_runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let second_runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let first =
            ServiceContainer::new(first_runtime.clone(), None).with_store(Arc::clone(&store));
        let second =
            ServiceContainer::new(second_runtime.clone(), None).with_store(Arc::clone(&store));

        let id = first
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        let error = second
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            ClassifiedError::Validation(message) if message == "Semgrep enrichment: busy"
        ));
        assert!(second_runtime.calls().is_empty());

        assert_eq!(
            first.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        wait_for_state(&first, id, SemgrepOperationState::Cancelled).await;
    }

    #[tokio::test]
    async fn workspace_cleanup_is_excluded_for_the_runtime_lifetime() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        runtime.wait_started().await;

        assert!(
            ServiceContainer::semgrep_test_workspace_cleanup_lease(&crate::workspace_root())
                .is_err(),
            "workspace cleanup must remain excluded while the sandbox is active"
        );
        assert_eq!(
            service.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        wait_for_state(&service, id, SemgrepOperationState::Cancelled).await;
    }

    #[tokio::test]
    async fn clear_knowledge_rejects_an_active_semgrep_operation() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterBegin);
        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        let error = service.clear_knowledge().await.unwrap_err();

        assert!(matches!(
            error,
            ClassifiedError::Validation(message)
                if message == crate::container::WORKSPACE_CLEANUP_BUSY_MESSAGE
        ));
        assert!(store.semgrep_run(operation_id).await.unwrap().is_some());
        assert_eq!(service.semgrep.journal.interrupted().unwrap().len(), 1);
        assert_eq!(
            service.request_semgrep_cancel(operation_id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        release.notify_one();
        wait_for_state(
            &service,
            operation_id,
            SemgrepOperationState::Cancelled,
        )
        .await;
    }

    #[tokio::test]
    async fn delete_project_rejects_its_active_semgrep_operation() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let project_alias = project.join("..").join("project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterBegin);
        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        let error = service.delete_project(&project_alias).await.unwrap_err();

        assert!(matches!(
            error,
            ClassifiedError::Validation(message) if message == "Semgrep enrichment: busy"
        ));
        assert!(store.semgrep_run(operation_id).await.unwrap().is_some());
        assert_eq!(service.semgrep.journal.interrupted().unwrap().len(), 1);
        assert_eq!(
            service.request_semgrep_cancel(operation_id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        release.notify_one();
        wait_for_state(
            &service,
            operation_id,
            SemgrepOperationState::Cancelled,
        )
        .await;
    }

    #[tokio::test]
    async fn terminal_runtime_and_output_failures_are_atomic() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let cases = [
            (RuntimeBehavior::TimedOut, "timeout"),
            (RuntimeBehavior::Completed(7), "tool_exit"),
            (RuntimeBehavior::MissingOutput, "output_missing"),
            (RuntimeBehavior::OversizedOutput, "output_too_large"),
            (RuntimeBehavior::TruncatedCapture, "output_invalid"),
        ];
        for (behavior, code) in cases {
            let root = tempfile::tempdir().unwrap();
            let project = project_fixture(root.path(), "project");
            let runtime = Arc::new(RecordingRuntime::new(behavior));
            let (service, store) = persistent_service(root.path(), runtime.clone()).await;
            save_inventory(&store, &project, true).await;

            let id = service
                .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
                .await
                .unwrap();
            wait_for_state(&service, id, SemgrepOperationState::Failed).await;
            let view = service.semgrep_operation(id).await.unwrap().unwrap();
            assert_eq!(view.failure_code.as_deref(), Some(code));
            assert!(!view.active);
            assert!(view.failure_code.as_ref().unwrap().len() <= 64);
            assert!(view.failure_message.as_ref().unwrap().len() <= 1_024);
            let message = view.failure_message.as_ref().unwrap();
            assert!(!message.contains(&project.to_string_lossy().into_owned()));
            assert!(!message.contains("input[0]"));
            assert!(
                !runtime.calls().first().unwrap().cwd.exists(),
                "failed operations must clean their owned staging directory"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tracing_contains_only_bounded_identity_and_provenance() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "absolute-secret-project-marker");
        std::fs::write(
            project.join("secret.c"),
            b"int source_secret_marker(void) { return 1; }\n",
        )
        .unwrap();
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(7)));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        let captured = Arc::new(Mutex::new(String::new()));
        let subscriber = CaptureSubscriber::new(Arc::clone(&captured));
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Failed).await;
        let trace = captured.lock().unwrap().clone();

        assert!(
            trace.contains(&id.to_string()),
            "operation UUID missing from trace: {trace}"
        );
        assert!(trace.contains("project_identity_sha256="));
        assert!(trace.contains("source_sha256="));
        assert!(trace.contains("sandbox_image_sha256="));
        assert!(trace.contains("rules_tree_sha256="));
        assert!(trace.contains("command_schema_version=1"));
        assert!(!trace.contains(&project.to_string_lossy().into_owned()));
        assert!(!trace.contains("absolute-secret-project-marker"));
        assert!(!trace.contains("source_secret_marker"));
        assert!(!trace.contains("{\"results\""));
        assert!(!trace.contains("finding_message"));
    }

    #[tokio::test]
    async fn accepted_cancel_before_success_claim_finishes_cancelled() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::BeforeClaim);

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;
        assert_eq!(
            service.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Accepted
        );
        release.notify_one();

        wait_for_state(&service, id, SemgrepOperationState::Cancelled).await;
    }

    #[tokio::test]
    async fn source_mutation_after_completion_claim_fails_before_ready() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterClaim);

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;
        std::fs::write(
            project.join("parser.c"),
            b"int parse(const char *input) { return input[1]; }\n",
        )
        .unwrap();
        release.notify_one();

        wait_for_state(&service, id, SemgrepOperationState::Failed).await;
        let run = store.semgrep_publication(id).await.unwrap().unwrap();
        assert_eq!(run.run.failure_code.as_deref(), Some("source_changed"));
        assert!(run.findings.is_empty());
        assert!(run.scores.is_empty());
        assert!(!service.semgrep.journal.is_closed(id).unwrap());
        assert!(service.semgrep.journal.interrupted().unwrap().is_empty());
    }

    #[tokio::test]
    async fn publication_transaction_rolls_back_before_separate_failure_cleanup() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        sqlx::query(
            "CREATE TRIGGER reject_semgrep_score
             BEFORE INSERT ON semgrep_target_scores
             BEGIN
               SELECT RAISE(ABORT, 'injected publication failure');
             END",
        )
        .execute(store.pool())
        .await
        .unwrap();
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterPublicationFailure);

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        let rolled_back = store.semgrep_publication(id).await.unwrap().unwrap();
        assert_eq!(rolled_back.run.status, SemgrepRunStatus::Persisting);
        assert!(rolled_back.findings.is_empty());
        assert!(rolled_back.scores.is_empty());
        let interrupted = service.semgrep.journal.interrupted().unwrap();
        assert_eq!(interrupted.len(), 1);
        assert!(
            interrupted[0].ready.is_some(),
            "ready provenance must precede the attempted transaction"
        );
        let operation_root = runtime.calls()[0].cwd.clone();
        assert!(operation_root.exists());

        release.notify_one();
        wait_for_state(&service, id, SemgrepOperationState::Failed).await;

        let failed = store.semgrep_publication(id).await.unwrap().unwrap();
        assert_eq!(
            failed.run.failure_code.as_deref(),
            Some("persistence_failed")
        );
        assert!(failed.findings.is_empty());
        assert!(failed.scores.is_empty());
        assert!(!operation_root.exists());
        assert!(service.semgrep.journal.interrupted().unwrap().is_empty());
        assert!(!service.semgrep.journal.is_closed(id).unwrap());
    }

    #[tokio::test]
    async fn cleanup_failure_compensates_publication_and_reads_base_only() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), Arc::clone(&runtime)).await;
        save_inventory(&store, &project, true).await;
        service.semgrep.install_test_cleanup_failure();

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Failed).await;

        let publication = store.semgrep_publication(id).await.unwrap().unwrap();
        assert_eq!(
            publication.run.failure_code.as_deref(),
            Some("cleanup_failed")
        );
        assert!(publication.findings.is_empty());
        assert!(publication.scores.is_empty());
        assert_eq!(service.semgrep.journal.interrupted().unwrap().len(), 1);
        assert!(service.semgrep.ensure_recovery_healthy().is_err());
        let effective = service
            .effective_inventory(
                hf_discovery::discover(&project, TargetLanguage::C)
                    .await
                    .unwrap(),
                TargetLanguage::C,
            )
            .await
            .unwrap();
        assert_eq!(effective.overlay_state, SemgrepOverlayState::None);
        assert_f64_eq!(effective.candidates[0].semgrep_boost, 0.0);
        assert!(service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap_err()
            .to_string()
            .contains("recovery is degraded"));
        let operation_root = runtime.calls()[0].cwd.clone();
        service
            .semgrep
            .recover_interrupted(&store, &crate::workspace_root())
            .await
            .unwrap();
        assert!(!operation_root.exists());
        assert!(service.semgrep.journal.interrupted().unwrap().is_empty());
    }

    #[tokio::test]
    async fn compensation_failure_keeps_ready_publication_fail_closed() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        sqlx::query(
            "CREATE TRIGGER reject_cleanup_compensation
             BEFORE UPDATE ON semgrep_enrichment_runs
             WHEN NEW.failure_code = 'cleanup_failed'
             BEGIN
               SELECT RAISE(ABORT, 'injected compensation failure');
             END",
        )
        .execute(store.pool())
        .await
        .unwrap();
        service.semgrep.install_test_cleanup_failure();

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_recovery_degraded(&service).await;
        wait_for_worker_exit(&service).await;

        let publication = store.semgrep_publication(id).await.unwrap().unwrap();
        assert_eq!(publication.run.status, SemgrepRunStatus::Done);
        assert_eq!(publication.findings.len(), 1);
        assert_eq!(publication.scores.len(), 1);
        assert_eq!(service.semgrep.journal.interrupted().unwrap().len(), 1);
        let exact = service.semgrep_result(id).await.unwrap().unwrap();
        assert_eq!(exact.overlay_state, SemgrepOverlayState::IncompleteJournal);
        assert_f64_eq!(exact.candidates[0].semgrep_boost, 0.0);
        assert!(service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap_err()
            .to_string()
            .contains("recovery is degraded"));
        sqlx::query("DROP TRIGGER reject_cleanup_compensation")
            .execute(store.pool())
            .await
            .unwrap();
        let operation_root = runtime.calls()[0].cwd.clone();
        service
            .semgrep
            .recover_interrupted(&store, &crate::workspace_root())
            .await
            .unwrap();
        assert!(!operation_root.exists());
        assert!(service.semgrep.journal.interrupted().unwrap().is_empty());
    }

    #[tokio::test]
    async fn close_append_errors_are_incomplete_until_restart_replay() {
        let _test_guard = lifecycle_test_lock().lock().await;
        for (failure, closed_after_restart) in [
            (AppendFailurePoint::BeforeWrite, false),
            (AppendFailurePoint::AfterFileSync, true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let project = project_fixture(root.path(), "project");
            let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
            let (mut service, store) = persistent_service(root.path(), runtime.clone()).await;
            let journal_dir = root.path().join("semgrep-journal");
            service.semgrep = Arc::new(super::SemgrepCoordinator::persistent(journal_dir.clone()));
            save_inventory(&store, &project, true).await;
            let (reached, release) = service
                .semgrep
                .install_completion_pause(CompletionPausePoint::BeforeClose);

            let id = service
                .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
                .await
                .unwrap();
            wait_for_pause(&reached).await;
            let operation_root = runtime.calls()[0].cwd.clone();
            assert!(
                !operation_root.exists(),
                "owned staging must be durably cleaned before close"
            );
            service.semgrep.journal.install_test_append_failure(failure);
            release.notify_one();
            wait_for_recovery_degraded(&service).await;
            wait_for_worker_exit(&service).await;

            let same_process = service.semgrep_result(id).await.unwrap().unwrap();
            assert_eq!(
                same_process.overlay_state,
                SemgrepOverlayState::IncompleteJournal
            );
            assert_f64_eq!(same_process.candidates[0].semgrep_boost, 0.0);
            assert!(service
                .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
                .await
                .unwrap_err()
                .to_string()
                .contains("recovery is degraded"));

            drop(service);
            let coordinator = Arc::new(super::SemgrepCoordinator::persistent(journal_dir.clone()));
            coordinator
                .recover_interrupted(&store, &crate::workspace_root())
                .await
                .unwrap();
            let run = store.semgrep_run(id).await.unwrap().unwrap();
            assert_eq!(
                run.status,
                if closed_after_restart {
                    SemgrepRunStatus::Done
                } else {
                    SemgrepRunStatus::Failed
                }
            );
            assert_eq!(
                coordinator.journal.is_closed(id).unwrap(),
                closed_after_restart
            );
            assert!(coordinator.journal.interrupted().unwrap().is_empty());

            let mut restarted = ServiceContainer::new(
                Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0))),
                None,
            )
            .with_store(Arc::clone(&store));
            restarted.semgrep = coordinator;
            if closed_after_restart {
                let exact = restarted.semgrep_result(id).await.unwrap().unwrap();
                assert_eq!(exact.overlay_state, SemgrepOverlayState::Current);
                assert_f64_eq!(exact.candidates[0].semgrep_boost, 0.05);
            } else {
                assert!(restarted.semgrep_result(id).await.unwrap().is_none());
                let repaired = store.semgrep_publication(id).await.unwrap().unwrap();
                assert!(repaired.findings.is_empty());
                assert!(repaired.scores.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn exact_result_uses_persisted_llm_base_score() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        let mut persisted = hf_discovery::discover(&project, TargetLanguage::C)
            .await
            .unwrap();
        persisted.candidates[0].fit_score = 0.83;
        persisted.candidates[0].rationale = "LLM-ranked".to_owned();
        store.save_inventory(&persisted, Utc::now()).await.unwrap();

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Done).await;
        let result = service.semgrep_result(id).await.unwrap().unwrap();
        assert_eq!(result.overlay_state, super::SemgrepOverlayState::Current);
        assert_f64_eq!(result.candidates[0].base_score, 0.83);
        assert_f64_eq!(result.candidates[0].semgrep_boost, 0.05);
        assert_f64_eq!(result.candidates[0].effective_score, 0.88);
        assert_f64_eq!(result.candidates[0].candidate.fit_score, 0.83);
    }

    #[tokio::test]
    async fn exact_result_with_deleted_inventory_is_findings_preserving_stale_base() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(
            RuntimeBehavior::CompletedWithUnmatchedFinding,
        ));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Done).await;
        sqlx::query("DELETE FROM targets WHERE project_root = ?1")
            .bind(project.to_string_lossy().as_ref())
            .execute(store.pool())
            .await
            .unwrap();

        let exact = service.semgrep_result(id).await.unwrap().unwrap();
        assert_eq!(exact.overlay_state, SemgrepOverlayState::StaleBase);
        assert!(exact.candidates.is_empty());
        assert_eq!(exact.findings.len(), 2);
        assert!(exact
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_some()));
        assert!(exact
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));

        let parent = service.semgrep_operation(id).await.unwrap().unwrap();
        assert_eq!(parent.state, SemgrepOperationState::Done);
    }

    #[tokio::test]
    async fn exact_result_with_reclassified_inventory_is_findings_preserving_stale_base() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(
            RuntimeBehavior::CompletedWithUnmatchedFinding,
        ));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Done).await;
        let candidates = store
            .list_targets(project.to_string_lossy().as_ref())
            .await
            .unwrap();
        assert!(!candidates.is_empty());
        for mut candidate in candidates {
            candidate.language = TargetLanguage::Cpp;
            store.upsert_target(&candidate, Utc::now()).await.unwrap();
        }

        let exact = service.semgrep_result(id).await.unwrap().unwrap();
        assert_eq!(exact.overlay_state, SemgrepOverlayState::StaleBase);
        assert!(exact.candidates.is_empty());
        assert_eq!(exact.findings.len(), 2);
        assert!(exact
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_some()));
        assert!(exact
            .findings
            .iter()
            .any(|finding| finding.matched_target_id.is_none()));

        let parent = service.semgrep_operation(id).await.unwrap().unwrap();
        assert_eq!(parent.state, SemgrepOperationState::Done);
    }

    #[tokio::test]
    async fn operation_status_survives_result_reconstruction_failure() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(
            RuntimeBehavior::CompletedWithUnmatchedFinding,
        ));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Done).await;
        sqlx::query("ALTER TABLE targets RENAME TO targets_unavailable")
            .execute(store.pool())
            .await
            .unwrap();

        let parent = service.semgrep_operation(id).await.unwrap().unwrap();
        assert_eq!(parent.state, SemgrepOperationState::Done);
        assert!(parent.result.is_none());
    }

    #[tokio::test]
    async fn exact_results_are_isolated_and_rescans_do_not_compound() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;

        let first = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        runtime.wait_started().await;
        runtime.release.notify_one();
        wait_for_state(&service, first, SemgrepOperationState::Done).await;

        let second = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        runtime.wait_started().await;
        runtime.release.notify_one();
        wait_for_state(&service, second, SemgrepOperationState::Done).await;
        sqlx::query(
            "UPDATE semgrep_findings
             SET message = 'second scan signal'
             WHERE scan_id = ?1",
        )
        .bind(second.to_string())
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "UPDATE semgrep_target_scores
             SET boost = 0.10, effective_score = 0.60
             WHERE scan_id = ?1",
        )
        .bind(second.to_string())
        .execute(store.pool())
        .await
        .unwrap();

        let first_result = service.semgrep_result(first).await.unwrap().unwrap();
        let second_result = service.semgrep_result(second).await.unwrap().unwrap();
        assert_eq!(first_result.scan_id, Some(first));
        assert_eq!(second_result.scan_id, Some(second));
        assert_f64_eq!(first_result.candidates[0].effective_score, 0.55);
        assert_f64_eq!(second_result.candidates[0].effective_score, 0.60);
        assert_f64_eq!(first_result.candidates[0].base_score, 0.5);
        assert_f64_eq!(second_result.candidates[0].base_score, 0.5);
        assert_eq!(first_result.findings[0].message, "advisory signal");
        assert_eq!(second_result.findings[0].message, "second scan signal");
    }

    #[tokio::test]
    async fn failed_new_scan_does_not_replace_latest_success() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let success_runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (mut service, store) = persistent_service(root.path(), success_runtime.clone()).await;
        let journal_dir = root.path().join("semgrep-journal");
        service.semgrep = Arc::new(super::SemgrepCoordinator::persistent(journal_dir.clone()));
        save_inventory(&store, &project, true).await;

        let successful = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        success_runtime.wait_started().await;
        success_runtime.release.notify_one();
        wait_for_state(&service, successful, SemgrepOperationState::Done).await;

        let failure_runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(7)));
        let mut failing_service =
            ServiceContainer::new(failure_runtime, None).with_store(Arc::clone(&store));
        failing_service.semgrep = Arc::new(super::SemgrepCoordinator::persistent(journal_dir));
        let failed = failing_service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&failing_service, failed, SemgrepOperationState::Failed).await;
        assert_eq!(
            store.semgrep_run(failed).await.unwrap().unwrap().status,
            SemgrepRunStatus::Failed
        );

        let scanned = hf_discovery::discover(&project, TargetLanguage::C)
            .await
            .unwrap();
        let current = failing_service
            .effective_inventory(
                TargetInventory {
                    project_root: project.clone(),
                    candidates: store
                        .list_targets(&project.to_string_lossy())
                        .await
                        .unwrap(),
                    call_graph: scanned.call_graph,
                },
                TargetLanguage::C,
            )
            .await
            .unwrap();
        assert_eq!(current.scan_id, Some(successful));
        assert_eq!(current.overlay_state, super::SemgrepOverlayState::Current);
        assert_f64_eq!(current.candidates[0].effective_score, 0.55);
    }

    #[tokio::test]
    async fn inactive_cancel_after_failure_claim_preserves_tool_failure() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(7)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterClaim);

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;
        assert_eq!(
            service.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Inactive
        );
        release.notify_one();

        wait_for_state(&service, id, SemgrepOperationState::Failed).await;
        assert_eq!(
            service
                .semgrep_operation(id)
                .await
                .unwrap()
                .unwrap()
                .failure_code
                .as_deref(),
            Some("tool_exit")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_output_is_rejected() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::SymlinkOutput));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Failed).await;
        assert_eq!(
            service
                .semgrep_operation(id)
                .await
                .unwrap()
                .unwrap()
                .failure_code
                .as_deref(),
            Some("output_invalid")
        );
    }

    #[tokio::test]
    async fn valid_output_publishes_atomically_and_uuids_are_service_owned() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;

        let unknown = Uuid::new_v4();
        assert!(service.semgrep_operation(unknown).await.unwrap().is_none());
        assert_eq!(
            service.request_semgrep_cancel(unknown).await.unwrap(),
            SemgrepCancelOutcome::NotFound
        );

        let id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_state(&service, id, SemgrepOperationState::Done).await;
        let view = service.semgrep_operation(id).await.unwrap().unwrap();
        assert!(!view.active);
        let result = view.result.unwrap();
        assert_eq!(result.overlay_state, super::SemgrepOverlayState::Current);
        assert_eq!(result.scan_id, Some(id));
        assert_f64_eq!(result.candidates[0].base_score, 0.5);
        assert_f64_eq!(result.candidates[0].candidate.fit_score, 0.5);
        assert_eq!(
            service.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Inactive
        );
        let publication = store.semgrep_publication(id).await.unwrap().unwrap();
        assert_eq!(publication.findings.len(), 1);
        assert_eq!(publication.scores.len(), 1);
        assert_f64_eq!(publication.scores[0].base_score, 0.5);
        assert_f64_eq!(publication.scores[0].boost, 0.05);
        assert_f64_eq!(publication.scores[0].effective_score, 0.55);
        assert!(service.semgrep.journal.is_closed(id).unwrap());
        assert!(
            !runtime.calls().first().unwrap().cwd.exists(),
            "success must clean staging before the successful close"
        );
    }
}

#[cfg(test)]
mod terminal_visibility_tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use hf_core::target::TargetLanguage;
    use hf_storage::SemgrepRunStatus;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use super::lifecycle_tests::{
        lifecycle_test_lock, persistent_service, project_fixture, save_inventory, wait_for_pause,
        wait_for_state, RecordingRuntime, RuntimeBehavior,
    };
    use super::{
        ActiveSemgrepGuard, ActiveSemgrepOperation, CompletionPausePoint, SemgrepCancelOutcome,
        SemgrepCoordinator, SemgrepOperationState,
    };

    #[test]
    fn finalizing_registry_claim_blocks_same_project_reservation() {
        let coordinator = Arc::new(SemgrepCoordinator::in_memory());
        let project = PathBuf::from("project");
        let operation_id = Uuid::new_v4();
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        coordinator
            .reserve(&project, operation_id, cancellation)
            .unwrap();
        let guard = ActiveSemgrepGuard {
            coordinator: Arc::clone(&coordinator),
            project: project.clone(),
            operation_id,
        };

        assert!(coordinator.claim_completion(&project, operation_id));
        {
            let active = coordinator.active.lock().unwrap();
            assert!(matches!(
                active.get(&project),
                Some(ActiveSemgrepOperation::Finalizing {
                    operation_id: active_id
                }) if *active_id == operation_id
            ));
        }
        let successor_id = Uuid::new_v4();
        let error = coordinator
            .reserve(&project, successor_id, CancellationToken::new())
            .unwrap_err();
        assert!(error.to_string().contains("busy"));
        assert_eq!(
            coordinator.active_operation_for_project(&project),
            Some(operation_id)
        );

        drop(guard);
        assert!(!coordinator.is_active(operation_id));
        coordinator
            .reserve(&project, successor_id, CancellationToken::new())
            .unwrap();
        assert_eq!(
            coordinator.active_operation_for_project(&project),
            Some(successor_id)
        );
        coordinator.release(&project, successor_id);
    }

    #[test]
    fn finalizing_registry_ignores_mismatched_claims_and_releases() {
        let coordinator = Arc::new(SemgrepCoordinator::in_memory());
        let project = PathBuf::from("project");
        let operation_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        coordinator
            .reserve(&project, operation_id, CancellationToken::new())
            .unwrap();
        let matching_guard = ActiveSemgrepGuard {
            coordinator: Arc::clone(&coordinator),
            project: project.clone(),
            operation_id,
        };

        assert!(!coordinator.claim_completion(&project, other_id));
        {
            let active = coordinator.active.lock().unwrap();
            assert!(matches!(
                active.get(&project),
                Some(ActiveSemgrepOperation::Cancellable {
                    operation_id: active_id,
                    ..
                }) if *active_id == operation_id
            ));
        }
        assert!(!coordinator.claim_completion(&project, operation_id));
        assert!(!coordinator.claim_completion(&project, operation_id));
        assert!(!coordinator.claim_completion(&project, other_id));
        coordinator.release(&project, other_id);
        {
            let mismatched_guard = ActiveSemgrepGuard {
                coordinator: Arc::clone(&coordinator),
                project: project.clone(),
                operation_id: other_id,
            };
            drop(mismatched_guard);
        }
        {
            let active = coordinator.active.lock().unwrap();
            assert!(matches!(
                active.get(&project),
                Some(ActiveSemgrepOperation::Finalizing {
                    operation_id: active_id
                }) if *active_id == operation_id
            ));
        }

        drop(matching_guard);
        assert_eq!(coordinator.active_operation_for_project(&project), None);
    }

    #[tokio::test]
    async fn done_database_row_is_reported_persisting_until_close() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::BeforeClose);

        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        assert_eq!(
            store
                .semgrep_run(operation_id)
                .await
                .unwrap()
                .unwrap()
                .status,
            SemgrepRunStatus::Done
        );
        assert!(!service.semgrep.journal.is_closed(operation_id).unwrap());
        assert_eq!(
            service
                .semgrep_operation(operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            SemgrepOperationState::Persisting
        );

        release.notify_one();
        wait_for_state(&service, operation_id, SemgrepOperationState::Done).await;
    }

    #[tokio::test]
    async fn same_project_start_is_busy_until_close() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::BeforeClose);

        let operation_id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        let error = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("busy"));

        release.notify_one();
        wait_for_state(&service, operation_id, SemgrepOperationState::Done).await;
    }

    #[tokio::test]
    async fn finalizing_operation_is_inactive_for_cancel_but_active_for_status() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::BeforeClose);

        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        let view = service
            .semgrep_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(view.state, SemgrepOperationState::Persisting);
        assert!(view.active);
        assert_eq!(
            service.request_semgrep_cancel(operation_id).await.unwrap(),
            SemgrepCancelOutcome::Inactive
        );

        release.notify_one();
        wait_for_state(&service, operation_id, SemgrepOperationState::Done).await;
    }

    #[tokio::test]
    async fn externally_observed_done_never_regresses_to_failed() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Completed(0)));
        let (service, store) = persistent_service(root.path(), runtime).await;
        save_inventory(&store, &project, true).await;
        let (reached, release) = service
            .semgrep
            .install_completion_pause(CompletionPausePoint::AfterPublicationBeforeCleanup);

        let operation_id = service
            .start_semgrep_enrichment(project, TargetLanguage::C)
            .await
            .unwrap();
        wait_for_pause(&reached).await;

        let before_cleanup = service
            .semgrep_operation(operation_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before_cleanup.state, SemgrepOperationState::Persisting);
        assert!(before_cleanup.active);
        service.semgrep.install_test_cleanup_failure();
        release.notify_one();
        wait_for_state(&service, operation_id, SemgrepOperationState::Failed).await;
        let after_cleanup = service
            .semgrep_operation(operation_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            [before_cleanup.state, after_cleanup.state],
            [
                SemgrepOperationState::Persisting,
                SemgrepOperationState::Failed
            ]
        );
    }
}
