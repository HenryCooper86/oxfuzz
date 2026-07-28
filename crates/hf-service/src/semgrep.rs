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
use hf_core::target::TargetLanguage;
use hf_guardrails::Action;
use hf_runtime::SANDBOX_IMAGE;
use hf_storage::{SemgrepRunRecord, SemgrepRunStatus};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use uuid::Uuid;

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
    /// Whether cooperative cancellation is currently registered.
    pub active: bool,
    /// RFC 3339 admission time.
    pub started_at: String,
    /// RFC 3339 terminal time.
    pub ended_at: Option<String>,
    /// Stable bounded terminal failure code.
    pub failure_code: Option<String>,
    /// Bounded redacted terminal failure message.
    pub failure_message: Option<String>,
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
    active: Mutex<HashMap<PathBuf, (Uuid, CancellationToken)>>,
    journal: Arc<crate::semgrep_recovery::SemgrepJournal>,
    #[cfg(test)]
    completion_pause: Mutex<Option<CompletionPause>>,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompletionPausePoint {
    BeforeClaim,
    AfterClaim,
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
            #[cfg(test)]
            completion_pause: Mutex::new(None),
        }
    }

    pub(crate) fn persistent(directory: PathBuf) -> Self {
        Self {
            active: Mutex::new(HashMap::new()),
            journal: Arc::new(crate::semgrep_recovery::SemgrepJournal::open(directory)),
            #[cfg(test)]
            completion_pause: Mutex::new(None),
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
        active.insert(project.to_path_buf(), (operation_id, cancellation));
        Ok(())
    }

    fn release(&self, project: &Path, operation_id: Uuid) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active
            .get(project)
            .is_some_and(|(active_id, _)| *active_id == operation_id)
        {
            active.remove(project);
        }
    }

    fn active_token(&self, operation_id: Uuid) -> Option<CancellationToken> {
        self.active.lock().ok().and_then(|active| {
            active
                .values()
                .find(|(active_id, _)| *active_id == operation_id)
                .map(|(_, token)| token.clone())
        })
    }

    fn is_active(&self, operation_id: Uuid) -> bool {
        self.active_token(operation_id).is_some()
    }

    fn cancel(&self, operation_id: Uuid) -> Result<bool, ClassifiedError> {
        let active = self.active.lock().map_err(|_| {
            ClassifiedError::Internal("Semgrep operation registry is unavailable".to_owned())
        })?;
        let Some((_, token)) = active
            .values()
            .find(|(active_id, _)| *active_id == operation_id)
        else {
            return Ok(false);
        };
        token.cancel();
        Ok(true)
    }

    fn claim_completion(&self, project: &Path, operation_id: Uuid) -> bool {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cancelled = active
            .get(project)
            .filter(|(active_id, _)| *active_id == operation_id)
            .is_some_and(|(_, token)| token.is_cancelled());
        if active
            .get(project)
            .is_some_and(|(active_id, _)| *active_id == operation_id)
        {
            active.remove(project);
        }
        cancelled
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
    /// Admit and start one explicit Semgrep enrichment without awaiting it.
    ///
    /// # Errors
    /// Returns a classified admission error before spawning work, or a durable
    /// staging/journal error after reserving the operation.
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

        let operation_id = Uuid::new_v4();
        let cancellation = CancellationToken::new();
        self.semgrep
            .reserve(&canonical_project, operation_id, cancellation.clone())?;

        let started_at = Utc::now();
        let run = SemgrepRunRecord {
            id: operation_id,
            project_root: canonical_project.to_string_lossy().into_owned(),
            language: language.as_str().to_owned(),
            source_sha256: None,
            sandbox_image: SANDBOX_IMAGE.to_owned(),
            sandbox_image_sha256: resolved_image.sha256().to_owned(),
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
            self.semgrep.release(&canonical_project, operation_id);
            if error.to_string().contains("UNIQUE constraint failed") {
                return Err(semgrep_validation("busy"));
            }
            return Err(ClassifiedError::Storage(
                "Semgrep staging record could not be created".to_owned(),
            ));
        }

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
            self.semgrep.release(&canonical_project, operation_id);
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
            sandbox_image_sha256 = resolved_image.sha256(),
            rules_tree_sha256 = rules_tree_sha256(),
            command_schema_version = COMMAND_SCHEMA_VERSION,
        );
        let image_reference = resolved_image.reference().to_owned();
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
        Ok(Some(SemgrepOperationView {
            operation_id: run.id,
            project_root: run.project_root,
            language: run.language,
            state: operation_state(run.status),
            active: self.semgrep.is_active(operation_id),
            started_at: run.started_at.to_rfc3339(),
            ended_at: run.ended_at.map(|value| value.to_rfc3339()),
            failure_code: run.failure_code,
            failure_message: run.failure_message,
        }))
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
        fail_semgrep_operation(store, operation_id, status, code, message, operation_root).await;
    }

    async fn run_semgrep_scan(
        &self,
        operation_id: Uuid,
        canonical_project: PathBuf,
        language: TargetLanguage,
        image_reference: String,
        cancellation: CancellationToken,
        operation_span: tracing::Span,
    ) {
        let _active = ActiveSemgrepGuard {
            coordinator: Arc::clone(&self.semgrep),
            project: canonical_project.clone(),
            operation_id,
        };
        let Some(store) = self.store().cloned() else {
            return;
        };
        let Ok(_workspace_lease) = self.acquire_workspace_operation().await else {
            self.finish_semgrep_failure(
                &store,
                &canonical_project,
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep workspace lease could not be acquired",
                None,
            )
            .await;
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
        if let Err(failure) = read_semgrep_output(&snapshot.output_dir) {
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
        if self
            .claim_semgrep_completion(&canonical_project, operation_id)
            .await
        {
            fail_semgrep_operation(
                &store,
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
                operation_id,
                SemgrepRunStatus::Failed,
                "persistence_failed",
                "Semgrep validation phase could not be recorded",
                Some(&snapshot.operation_root),
            )
            .await;
        }
    }
}

struct OutputFailure {
    code: &'static str,
    message: &'static str,
}

async fn require_persisted_inventory(
    store: &hf_storage::Store,
    canonical_project: &Path,
    language: TargetLanguage,
) -> Result<(), ClassifiedError> {
    let targets = store.list_all_targets().await?;
    let candidates = targets
        .iter()
        .filter(|candidate| {
            candidate.language == language
                && canonical_stored_project(&candidate.project_root, canonical_project)
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(semgrep_validation("inventory_missing"));
    }
    if candidates.iter().any(|candidate| {
        candidate.location.end_line.is_none() || candidate.location.end_col.is_none()
    }) {
        return Err(semgrep_validation("inventory_span_incomplete"));
    }
    Ok(())
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
    operation_id: Uuid,
    mut status: SemgrepRunStatus,
    mut code: &str,
    mut message: &str,
    operation_root: Option<&Path>,
) {
    if let Some(operation_root) = operation_root {
        if cleanup_operation_root(operation_root).is_err() {
            status = SemgrepRunStatus::Failed;
            code = "cleanup_failed";
            message = "Semgrep staged artifacts could not be removed safely";
        }
    }
    let code = bounded_bytes(code, 64);
    let message = bounded_bytes(message, 1_024);
    for attempt in 0..20_u32 {
        match store
            .fail_semgrep_run(operation_id, status, &code, &message, Utc::now())
            .await
        {
            Ok(()) => return,
            Err(error) if storage_is_busy(&error) && attempt < 19 => {
                tokio::time::sleep(std::time::Duration::from_millis(
                    5_u64.saturating_mul(u64::from(attempt + 1)),
                ))
                .await;
            }
            Err(_) => break,
        }
    }
    tracing::error!(
        operation_id = %operation_id,
        failure_code = "persistence_failed",
        "Semgrep terminal state could not be persisted"
    );
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
    cleanup_operation_root_in_with_hook(managed_workspace, operation_root, || {})
}

fn cleanup_operation_root_in_with_hook<F>(
    managed_workspace: &Path,
    operation_root: &Path,
    before_remove: F,
) -> Result<(), ClassifiedError>
where
    F: FnOnce(),
{
    let workspace = validate_canonical_directory(managed_workspace, "managed workspace")?;
    let semgrep_root = workspace.join("semgrep");
    let semgrep_metadata = std::fs::symlink_metadata(&semgrep_root).map_err(|error| {
        snapshot_validation(format!(
            "inspect Semgrep workspace {}: {error}",
            semgrep_root.display()
        ))
    })?;
    if !semgrep_metadata.file_type().is_dir() {
        return Err(snapshot_validation(
            "Semgrep workspace is not a regular directory",
        ));
    }
    let resolved_semgrep = std::fs::canonicalize(&semgrep_root).map_err(|error| {
        snapshot_validation(format!(
            "resolve Semgrep workspace {}: {error}",
            semgrep_root.display()
        ))
    })?;
    if resolved_semgrep != semgrep_root {
        return Err(snapshot_validation(
            "Semgrep workspace has an ambiguous ancestor",
        ));
    }
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
    let metadata = std::fs::symlink_metadata(operation_root).map_err(|error| {
        snapshot_validation(format!(
            "inspect Semgrep operation directory {}: {error}",
            operation_root.display()
        ))
    })?;
    if !metadata.file_type().is_dir() {
        return Err(snapshot_validation(
            "Semgrep cleanup target is not a regular directory",
        ));
    }
    let resolved = std::fs::canonicalize(operation_root).map_err(|error| {
        snapshot_validation(format!(
            "resolve Semgrep operation directory {}: {error}",
            operation_root.display()
        ))
    })?;
    if resolved != expected || !resolved.starts_with(&semgrep_root) {
        return Err(snapshot_validation(
            "Semgrep cleanup target escaped its owned workspace",
        ));
    }
    before_remove();
    remove_owned_operation_nofollow(&semgrep_root, operation_name, &semgrep_metadata, &metadata)
}

#[cfg(unix)]
fn remove_owned_operation_nofollow(
    semgrep_root: &Path,
    operation_name: &str,
    expected_semgrep: &std::fs::Metadata,
    expected_operation: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    use rustix::fs::{open, openat, unlinkat, AtFlags, Mode, OFlags};

    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let semgrep = File::from(open(semgrep_root, flags, Mode::empty()).map_err(|error| {
        snapshot_validation(format!("open Semgrep workspace without links: {error}"))
    })?);
    let open_semgrep = semgrep.metadata().map_err(|error| {
        snapshot_validation(format!("reinspect open Semgrep workspace: {error}"))
    })?;
    if !same_directory_identity(expected_semgrep, &open_semgrep) {
        return Err(snapshot_validation(
            "Semgrep workspace changed before cleanup",
        ));
    }
    let operation = File::from(
        openat(&semgrep, operation_name, flags, Mode::empty()).map_err(|error| {
            snapshot_validation(format!(
                "open Semgrep operation directory without links: {error}"
            ))
        })?,
    );
    let open_operation = operation.metadata().map_err(|error| {
        snapshot_validation(format!(
            "reinspect open Semgrep operation directory: {error}"
        ))
    })?;
    if !same_directory_identity(expected_operation, &open_operation) {
        return Err(snapshot_validation(
            "Semgrep operation directory changed before cleanup",
        ));
    }
    remove_open_directory_contents(&operation)?;
    let current = File::from(
        openat(&semgrep, operation_name, flags, Mode::empty()).map_err(|error| {
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
    unlinkat(&semgrep, operation_name, AtFlags::REMOVEDIR).map_err(|error| {
        snapshot_validation(format!("remove owned Semgrep operation directory: {error}"))
    })
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

#[cfg(not(unix))]
fn remove_owned_operation_nofollow(
    _semgrep_root: &Path,
    _operation_name: &str,
    _expected_semgrep: &std::fs::Metadata,
    _expected_operation: &std::fs::Metadata,
) -> Result<(), ClassifiedError> {
    Err(ClassifiedError::Sandbox(
        "Semgrep cleanup requires descriptor-relative filesystem access".to_owned(),
    ))
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
mod snapshot_tests {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

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

    use super::{CompletionPausePoint, SemgrepCancelOutcome, SemgrepOperationState};
    use crate::ServiceContainer;

    const IMAGE_ID: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn lifecycle_test_lock() -> &'static tokio::sync::Mutex<()> {
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
    enum RuntimeBehavior {
        Block,
        Completed(i32),
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

    struct RecordingRuntime {
        image: bool,
        behavior: RuntimeBehavior,
        calls: Mutex<Vec<RuntimeCall>>,
        started: Notify,
        release: Notify,
        cancellation_observed: AtomicBool,
    }

    impl RecordingRuntime {
        fn new(behavior: RuntimeBehavior) -> Self {
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
                _ => std::fs::write(output, b"{\"results\":[]}").unwrap(),
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

    fn project_fixture(root: &Path, name: &str) -> PathBuf {
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

    async fn persistent_service(
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

    async fn save_inventory(store: &Store, project: &Path, complete_span: bool) {
        store
            .save_inventory(&inventory(project, complete_span), Utc::now())
            .await
            .unwrap();
    }

    async fn wait_for_state(service: &ServiceContainer, id: Uuid, expected: SemgrepOperationState) {
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

    async fn wait_for_pause(reached: &Notify) {
        tokio::time::timeout(Duration::from_secs(5), reached.notified())
            .await
            .expect("worker must reach the completion pause");
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
    async fn admission_persists_staging_and_open_journal_before_background_work() {
        let _test_guard = lifecycle_test_lock().lock().await;
        let root = tempfile::tempdir().unwrap();
        let project = project_fixture(root.path(), "project");
        let runtime = Arc::new(RecordingRuntime::new(RuntimeBehavior::Block));
        let (service, store) = persistent_service(root.path(), runtime.clone()).await;
        save_inventory(&store, &project, true).await;
        let workspace = crate::initialize_workspace_root().unwrap();
        let cleanup_lease =
            ServiceContainer::semgrep_test_workspace_cleanup_lease(&workspace).unwrap();

        let id = service
            .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
            .await
            .unwrap();
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
        drop(cleanup_lease);
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
        assert!(error.to_string().contains("busy"));
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
        assert!(error.to_string().contains("busy"));
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
        let (service, store) = persistent_service(root.path(), runtime).await;
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
        let (service, store) = persistent_service(root.path(), runtime).await;
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
    async fn valid_output_advances_only_to_validating_and_uuids_are_service_owned() {
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
        wait_for_state(&service, id, SemgrepOperationState::Validating).await;
        let view = service.semgrep_operation(id).await.unwrap().unwrap();
        assert!(!view.active);
        assert_eq!(
            service.request_semgrep_cancel(id).await.unwrap(),
            SemgrepCancelOutcome::Inactive
        );
        let operation_root = runtime.calls().first().unwrap().cwd.clone();
        super::cleanup_operation_root(&operation_root).unwrap();
    }
}
