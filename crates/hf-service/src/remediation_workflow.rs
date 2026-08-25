//! Service-owned Patch-to-Proof sandbox verification workflow.
//!
//! Turns an approved remediation draft into durable, sandbox-verified terminal
//! evidence. [`ServiceContainer::start_remediation_verification`] claims the
//! approved operation and spawns the background workflow, which revalidates the
//! immutable binding on disk, runs the five required verification stages
//! through the [`RuntimeAdapter`] sandbox, assembles a
//! [`SandboxVerificationEvidence`], derives the terminal status, and persists
//! it. No patch, build, or replay ever runs on the host or before approval.
//!
//! See `docs/design/patch-to-proof-design.md`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::Sanitizer;
use hf_crash::remediation::{
    RemediationBinding, RemediationHandoff, RemediationStatus, RemediationVerificationSpec,
    SandboxVerificationEvidence, VerificationStageEvidence, VerificationStageStatus,
    REMEDIATION_SCHEMA_VERSION,
};
use hf_storage::{
    RemediationOperationCompletion, RemediationOperationRecord, RemediationOperationStage,
    RemediationOperationStatus, Store,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::container::ServiceContainer;
use crate::evidence::CampaignEvidencePricing;
use crate::remediation::RemediationDraftParts;

/// Request to create a durable, unverified remediation draft for an operator
/// to review before any sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationDraftRequest {
    pub run_id: Uuid,
    pub finding_id: Uuid,
    pub patch: String,
    pub follow_up_fuzz_seconds: u64,
    pub pricing: CampaignEvidencePricing,
}

/// Request to start the sandbox verification workflow for a previously approved
/// remediation operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationStartRequest {
    pub operation_id: Uuid,
}

/// Status snapshot for a draft or approval step.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationDraftView {
    pub operation_id: Uuid,
    pub status: RemediationOperationStatus,
}

/// Status snapshot for an approval step.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationApprovalView {
    pub operation_id: Uuid,
    pub status: RemediationOperationStatus,
}

/// Read-only view of one durable remediation operation, including the immutable
/// binding and any terminal sandbox evidence.
#[derive(Debug, Clone, Serialize)]
pub struct RemediationOperationView {
    pub operation_id: Uuid,
    pub run_id: Uuid,
    pub finding_id: Uuid,
    pub status: RemediationOperationStatus,
    pub current_stage: RemediationOperationStage,
    pub binding: RemediationBinding,
    pub verification: Option<SandboxVerificationEvidence>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
}

impl ServiceContainer {
    /// Create a durable, visibly unverified remediation draft for operator
    /// review. Performs no patch application, build, or replay: the binding is
    /// assembled from durable campaign evidence and persisted in the `draft`
    /// state.
    ///
    /// # Errors
    /// Returns a classified error when persistent storage is unavailable, the
    /// finding/run evidence is incomplete, the patch is invalid, or the
    /// durable record cannot be inserted.
    pub async fn create_remediation_operation(
        &self,
        req: RemediationDraftRequest,
    ) -> Result<RemediationDraftView, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("remediation operations require persistent storage".to_owned())
        })?;
        let parts: RemediationDraftParts = self
            .prepare_remediation_draft(
                req.run_id,
                req.finding_id,
                &req.patch,
                req.pricing,
                req.follow_up_fuzz_seconds,
            )
            .await?;
        let operation_id = Uuid::new_v4();
        let now = chrono::Utc::now();
        let binding_json = serde_json::to_string(&parts.handoff.binding).map_err(|error| {
            ClassifiedError::Internal(format!("serialize remediation binding: {error}"))
        })?;
        let record = RemediationOperationRecord {
            id: operation_id,
            run_id: req.run_id,
            finding_id: req.finding_id,
            project_root: parts.project_root.clone(),
            target: parts.target.clone(),
            status: RemediationOperationStatus::Draft,
            current_stage: RemediationOperationStage::Review,
            binding_json,
            approval_json: None,
            verification_json: None,
            artifact_dir: format!("remediation/{operation_id}"),
            created_at: now,
            updated_at: now,
            ended_at: None,
            failure_code: None,
            failure_message: None,
        };
        store
            .insert_remediation_operation(&record)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(RemediationDraftView {
            operation_id,
            status: RemediationOperationStatus::Draft,
        })
    }

    /// Record immutable, exact-scope human approval for a draft. The approval
    /// binds the operator to the persisted binding digest and performs no
    /// execution.
    ///
    /// # Errors
    /// Returns a classified error when the operation is missing, not a draft,
    /// or the durable approval cannot be persisted.
    pub async fn approve_remediation_operation(
        &self,
        operation_id: Uuid,
        operator: &str,
    ) -> Result<RemediationApprovalView, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("remediation operations require persistent storage".to_owned())
        })?;
        let now = chrono::Utc::now();
        let record = store
            .remediation_operation(operation_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "remediation operation {operation_id} not found"
                ))
            })?;
        let binding_sha256 = sha256_bytes(record.binding_json.as_bytes());
        let approval = serde_json::json!({
            "approval_id": Uuid::new_v4(),
            "operator": operator,
            "approved_at": now.to_rfc3339(),
            "binding_sha256": binding_sha256,
        });
        let approval_json = serde_json::to_string(&approval)
            .map_err(|error| ClassifiedError::Internal(format!("serialize approval: {error}")))?;
        store
            .approve_remediation_operation(operation_id, &approval_json, now)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        Ok(RemediationApprovalView {
            operation_id,
            status: RemediationOperationStatus::Approved,
        })
    }

    /// Start the sandbox verification workflow for a previously approved
    /// remediation operation. Claims the operation atomically (requiring the
    /// `approved` state) and spawns the background workflow; a draft yields an
    /// error containing `"approved"`.
    ///
    /// # Errors
    /// Returns a classified error when persistent storage is unavailable or the
    /// operation is not in the `approved` state.
    pub async fn start_remediation_verification(
        &self,
        req: RemediationStartRequest,
    ) -> Result<(), ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("remediation operations require persistent storage".to_owned())
        })?;
        store
            .claim_remediation_operation(req.operation_id, chrono::Utc::now())
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let container = self.clone();
        let operation_id = req.operation_id;
        tokio::spawn(async move {
            if let Err(error) = container.run_remediation_workflow(operation_id).await {
                tracing::error!(
                    %error,
                    operation_id = %operation_id,
                    "remediation verification workflow failed"
                );
            }
        });
        Ok(())
    }

    /// Load one remediation operation as a read-only view. A `verified` row is
    /// revalidated from its immutable binding and terminal evidence on every
    /// read; a mismatch fails closed to `inconclusive` rather than trusting a
    /// stale verified claim.
    ///
    /// # Errors
    /// Returns a classified error when persistent storage is unavailable, the
    /// operation is missing, or its persisted binding or evidence is malformed.
    pub async fn remediation_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<RemediationOperationView, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("remediation operations require persistent storage".to_owned())
        })?;
        let record = store
            .remediation_operation(operation_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "remediation operation {operation_id} not found"
                ))
            })?;
        let binding: RemediationBinding =
            serde_json::from_str(&record.binding_json).map_err(|error| {
                ClassifiedError::Internal(format!("decode remediation binding: {error}"))
            })?;
        let verification = record
            .verification_json
            .as_deref()
            .map(serde_json::from_str::<SandboxVerificationEvidence>)
            .transpose()
            .map_err(|error| {
                ClassifiedError::Internal(format!("decode remediation evidence: {error}"))
            })?;
        let mut status = record.status;
        if status == RemediationOperationStatus::Verified {
            status = revalidate_verified(&binding, verification.as_ref());
        }
        Ok(RemediationOperationView {
            operation_id,
            run_id: record.run_id,
            finding_id: record.finding_id,
            status,
            current_stage: record.current_stage,
            binding,
            verification,
            failure_code: record.failure_code,
            failure_message: record.failure_message,
        })
    }

    /// Build the Finding Proof Card for a single finding and, when a terminal
    /// Patch-to-Proof remediation is retained for it, override the
    /// `fix_verification` claim with the sandbox-verified determination. A
    /// `verified` row is revalidated from its immutable binding + terminal
    /// evidence before it is trusted (fail-closed to inconclusive).
    pub async fn finding_proof_card_for_crash(
        &self,
        crash_id: Uuid,
    ) -> Result<crate::finding_proof::FindingProofCard, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("finding proof card requires persistent storage".to_owned())
        })?;
        let crash = store
            .get_crash(crash_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("finding {crash_id} not found")))?;
        let mut card = crate::finding_proof::finding_proof_card(&crash);
        if let Ok(Some(record)) = store.latest_remediation_for_finding(crash_id).await {
            card = crate::finding_proof::enrich_fix_verification(card, Some(&record));
        }
        Ok(card)
    }

    /// Run the full five-stage sandbox verification workflow for one claimed
    /// operation and persist the terminal result. The workflow always leaves the
    /// operation in a terminal state: an unexpected error fails closed to
    /// `inconclusive` so a claimed `running` row is never orphaned.
    async fn run_remediation_workflow(&self, operation_id: Uuid) -> Result<(), ClassifiedError> {
        match self.run_remediation_workflow_inner(operation_id).await {
            Ok(()) => Ok(()),
            Err(error) => {
                tracing::error!(
                    %error,
                    operation_id = %operation_id,
                    "remediation verification workflow failed; failing closed to inconclusive"
                );
                if let Some(store) = self.store().cloned() {
                    let message: String = error.to_string().chars().take(4_096).collect();
                    let _ = finish_operation(
                        &store,
                        operation_id,
                        RemediationOperationStatus::Inconclusive,
                        None,
                        Some("workflow_failed"),
                        Some(&message),
                    )
                    .await;
                }
                Err(error)
            }
        }
    }
    async fn run_remediation_workflow_inner(
        &self,
        operation_id: Uuid,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store()
            .ok_or_else(|| {
                ClassifiedError::Storage(
                    "remediation verification requires persistent storage".to_owned(),
                )
            })?
            .clone();
        // Hold the workspace operation lease for the whole workflow: the sandbox
        // stages build and replay under the target workspace, and a concurrent
        // whole-root cleanup must not delete that tree mid-verification.
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let context = load_verification_context(&store, operation_id).await?;

        // Pre-flight: stage the patched build tree and revalidate every
        // immutable binding digest. Any mismatch fails closed before a single
        // sandbox command runs.
        if let Err(error) = stage_build_tree(&context).await {
            return self
                .finish_inconclusive(
                    &store,
                    operation_id,
                    None,
                    Some("preflight_validation_failed"),
                    Some(&error.to_string()),
                )
                .await;
        }

        let evidence = self
            .run_verification_stages(&store, operation_id, &context)
            .await;

        let mut handoff = RemediationHandoff::draft(context.binding.clone())
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        let derived = match handoff.record_verification(evidence.clone()) {
            Ok(()) => handoff.status,
            Err(error) => {
                tracing::error!(%error, "remediation evidence validation failed");
                return self
                    .finish_inconclusive(
                        &store,
                        operation_id,
                        None,
                        Some("evidence_validation_failed"),
                        Some(&error.to_string()),
                    )
                    .await;
            }
        };
        let verification_json = serde_json::to_string(&evidence).map_err(|error| {
            ClassifiedError::Internal(format!("serialize remediation evidence: {error}"))
        })?;
        finish_operation(
            &store,
            operation_id,
            map_status(derived),
            Some(&verification_json),
            None,
            None,
        )
        .await
    }

    /// Run the five required sandbox stages in order and assemble their
    /// evidence.
    ///
    /// A stage that does not pass halts the run: every later stage is recorded
    /// as `skipped` rather than executed, so an unproven step can never be
    /// mistaken for a clean one.
    async fn run_verification_stages(
        &self,
        store: &Store,
        operation_id: Uuid,
        context: &VerificationContext,
    ) -> SandboxVerificationEvidence {
        let runtime = self.runtime_adapter().clone();
        let opts = sandbox_options(&context.binding);
        let mut patched_binary_sha256: Option<String> = None;

        // Stage 1: the finding must reproduce against the unpatched binary
        // before a patch can be credited with fixing it.
        let original_replay = stage_original_replay(&runtime, context, &opts).await;
        self.advance_after(
            store,
            operation_id,
            &original_replay,
            RemediationOperationStage::OriginalReplay,
            RemediationOperationStage::PatchBuild,
        )
        .await;

        // Stage 2: apply the approved patch in the staged tree and compile the
        // approved harness against the patched sources.
        let patch_build = if passed_stage(&original_replay) {
            let (stage, digest) = stage_patch_build(&runtime, context, &opts).await;
            patched_binary_sha256 = digest;
            stage
        } else {
            skipped("skipped_upstream")
        };
        self.advance_after(
            store,
            operation_id,
            &patch_build,
            RemediationOperationStage::PatchBuild,
            RemediationOperationStage::PatchedReplay,
        )
        .await;

        // Stage 3: the same reproducer must no longer crash the patched binary.
        let patched_replay = if passed_stage(&patch_build) {
            stage_patched_replay(&runtime, context, &opts).await
        } else {
            skipped("skipped_upstream")
        };
        self.advance_after(
            store,
            operation_id,
            &patched_replay,
            RemediationOperationStage::PatchedReplay,
            RemediationOperationStage::Regression,
        )
        .await;

        // Stage 4: the retained corpus must not crash the patched binary.
        let regression = if passed_stage(&patched_replay) {
            stage_regression(&runtime, context, &opts).await
        } else {
            skipped("skipped_upstream")
        };
        self.advance_after(
            store,
            operation_id,
            &regression,
            RemediationOperationStage::Regression,
            RemediationOperationStage::FollowUp,
        )
        .await;

        // Stage 5: a bounded fuzzing pass against the patched binary must not
        // find a new crash.
        let follow_up_fuzz = if passed_stage(&regression) {
            stage_follow_up_fuzz(&runtime, context, &opts).await
        } else {
            skipped("skipped_upstream")
        };

        let binding = &context.binding;
        SandboxVerificationEvidence {
            verification_id: Uuid::new_v4(),
            source_revision_sha256: binding.source_revision_sha256.clone(),
            patch_sha256: binding.patch_sha256.clone(),
            reproducer_sha256: binding.reproducer_sha256.clone(),
            harness_sha256: binding.harness_sha256.clone(),
            original_binary_sha256: binding.original_binary_sha256.clone(),
            patched_binary_sha256,
            sandbox_image_sha256: binding.sandbox_image_sha256.clone(),
            regression_corpus_sha256: binding.regression_corpus_sha256.clone(),
            verification_spec_sha256: binding.verification_spec_sha256.clone(),
            original_replay,
            patch_build,
            patched_replay,
            regression,
            follow_up_fuzz,
        }
    }

    /// Record progress to the next stage, but only while the run is still
    /// advancing. A halted run keeps the stage where it stopped.
    async fn advance_after(
        &self,
        store: &Store,
        operation_id: Uuid,
        stage: &VerificationStageEvidence,
        from: RemediationOperationStage,
        to: RemediationOperationStage,
    ) {
        if passed_stage(stage) {
            self.advance_best_effort(store, operation_id, from, to)
                .await;
        }
    }

    async fn advance_best_effort(
        &self,
        store: &Store,
        operation_id: Uuid,
        expected: RemediationOperationStage,
        next: RemediationOperationStage,
    ) {
        if let Err(error) = store
            .advance_remediation_stage(operation_id, expected, next, chrono::Utc::now())
            .await
        {
            tracing::warn!(
                %error,
                operation_id = %operation_id,
                "remediation stage advance failed"
            );
        }
    }

    async fn finish_inconclusive(
        &self,
        store: &Store,
        operation_id: Uuid,
        verification_json: Option<&str>,
        failure_code: Option<&str>,
        failure_message: Option<&str>,
    ) -> Result<(), ClassifiedError> {
        finish_operation(
            store,
            operation_id,
            RemediationOperationStatus::Inconclusive,
            verification_json,
            failure_code,
            failure_message,
        )
        .await
    }
}

async fn finish_operation(
    store: &Store,
    operation_id: Uuid,
    status: RemediationOperationStatus,
    verification_json: Option<&str>,
    failure_code: Option<&str>,
    failure_message: Option<&str>,
) -> Result<(), ClassifiedError> {
    store
        .finish_remediation_operation(
            operation_id,
            &RemediationOperationCompletion {
                status,
                verification_json,
                failure_code,
                failure_message,
                completed_at: chrono::Utc::now(),
            },
        )
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))
}

/// Revalidate a `verified` claim from its immutable binding and terminal
/// evidence. Returns `Verified` only when the claim still holds; otherwise
/// fails closed to `Inconclusive`.
fn revalidate_verified(
    binding: &RemediationBinding,
    verification: Option<&SandboxVerificationEvidence>,
) -> RemediationOperationStatus {
    let Some(evidence) = verification else {
        tracing::error!("verified remediation has no terminal evidence; downgrading");
        return RemediationOperationStatus::Inconclusive;
    };
    let handoff = RemediationHandoff {
        schema_version: REMEDIATION_SCHEMA_VERSION,
        binding: binding.clone(),
        status: RemediationStatus::Verified,
        verification: Some(evidence.clone()),
    };
    if handoff.verify_claim().is_ok() {
        RemediationOperationStatus::Verified
    } else {
        tracing::error!(
            "verified remediation evidence failed revalidation; downgrading to inconclusive"
        );
        RemediationOperationStatus::Inconclusive
    }
}

fn map_status(status: RemediationStatus) -> RemediationOperationStatus {
    match status {
        RemediationStatus::Verified => RemediationOperationStatus::Verified,
        RemediationStatus::Rejected => RemediationOperationStatus::Rejected,
        RemediationStatus::Inconclusive | RemediationStatus::Draft => {
            RemediationOperationStatus::Inconclusive
        }
    }
}

enum ReplayOutcome {
    Crashed,
    Clean,
    Inconclusive,
}

fn replay_outcome(result: &CommandResult) -> ReplayOutcome {
    match result.termination {
        CommandTermination::Completed if result.exit_code != 0 => ReplayOutcome::Crashed,
        CommandTermination::Completed => ReplayOutcome::Clean,
        CommandTermination::TimedOut | CommandTermination::Cancelled => ReplayOutcome::Inconclusive,
    }
}

fn passed(detail: &str, cases: usize) -> VerificationStageEvidence {
    VerificationStageEvidence {
        status: VerificationStageStatus::Passed,
        detail_code: detail.to_owned(),
        cases,
        failures: 0,
        findings: 0,
    }
}

fn failed(detail: &str, cases: usize, failures: usize) -> VerificationStageEvidence {
    VerificationStageEvidence {
        status: VerificationStageStatus::Failed,
        detail_code: detail.to_owned(),
        cases,
        failures,
        findings: failures,
    }
}

fn inconclusive(detail: &str, cases: usize) -> VerificationStageEvidence {
    VerificationStageEvidence {
        status: VerificationStageStatus::Inconclusive,
        detail_code: detail.to_owned(),
        cases,
        failures: 0,
        findings: 0,
    }
}

fn skipped(detail: &str) -> VerificationStageEvidence {
    VerificationStageEvidence {
        status: VerificationStageStatus::Skipped,
        detail_code: detail.to_owned(),
        cases: 0,
        failures: 0,
        findings: 0,
    }
}

fn sandbox_options(binding: &RemediationBinding) -> SandboxOptions {
    SandboxOptions {
        image: Some(format!("sha256:{}", binding.sandbox_image_sha256)),
        ..SandboxOptions::default()
    }
}

fn resource_limits(spec: &RemediationVerificationSpec, timeout_secs: u64) -> ResourceLimits {
    ResourceLimits {
        max_mem_mb: spec.max_mem_mb,
        max_cpus: spec.max_cpus,
        max_duration_secs: timeout_secs,
        env: HashMap::new(),
        ptrace: false,
    }
}

fn sanitizer_flag(sanitizer: Sanitizer) -> &'static str {
    match sanitizer {
        Sanitizer::None => "",
        Sanitizer::Address => "address",
        Sanitizer::Undefined => "undefined",
        Sanitizer::Memory => "memory",
        Sanitizer::Thread => "thread",
    }
}

/// Render the in-container compile command for the approved harness against the
/// staged (patched) sources. The harness source is staged as `harness.c`; every
/// other staged C/C++ source file is compiled in alongside it so the harness
/// links the patched target it exercises.
fn compile_command(harness: &Harness, build_dir: &Path) -> String {
    let mut sources = vec!["harness.c".to_owned()];
    let mut entries: Vec<_> = match std::fs::read_dir(build_dir) {
        Ok(iterator) => iterator.flatten().collect(),
        Err(_) => Vec::new(),
    };
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("harness.") {
            continue;
        }
        let path = entry.path();
        let extension = path.extension().and_then(|value| value.to_str());
        if matches!(extension, Some("c" | "cc" | "cpp" | "cxx")) {
            sources.push(name);
        }
    }
    let flag = sanitizer_flag(harness.sanitizer);
    let fsanitize = if flag.is_empty() {
        "-fsanitize=fuzzer".to_owned()
    } else {
        format!("-fsanitize=fuzzer,{flag}")
    };
    let mut command = format!("{} {fsanitize}", harness.build_cmd.compiler);
    for flag in &harness.build_cmd.extra_flags {
        command.push(' ');
        command.push_str(flag);
    }
    command.push_str(" -o ");
    command.push_str(&harness.build_cmd.output.to_string_lossy());
    for source in &sources {
        command.push(' ');
        command.push_str(source);
    }
    command
}

fn list_corpus(dir: &Path, max: usize) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(iterator) => iterator
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|file_type| file_type.is_file()))
            .map(|entry| entry.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    entries.sort();
    entries.truncate(max);
    entries
}

fn sha256_file(path: &Path) -> Result<String, ClassifiedError> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).map_err(|error| {
        ClassifiedError::Validation(format!("read {}: {error}", path.display()))
    })?;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut chunk).map_err(|error| {
            ClassifiedError::Validation(format!("hash {}: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        digest.update(&chunk[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Render a path losslessly for an opaque sandbox command argument. Paths are
/// passed through to the runtime verbatim; the runtime is responsible for any
/// container-relative translation when it mounts the workspace.
fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Everything resolved from durable state before the first sandbox command.
struct VerificationContext {
    binding: RemediationBinding,
    harness: Harness,
    project_root: PathBuf,
    run_root: PathBuf,
    original_binary: PathBuf,
    reproducer: PathBuf,
    corpus_dir: PathBuf,
    build_dir: PathBuf,
    follow_up_dir: PathBuf,
}

impl VerificationContext {
    /// Path the patched harness is compiled to.
    fn patched_binary(&self) -> PathBuf {
        self.build_dir.join(&self.harness.build_cmd.output)
    }
}

/// A stage that did not pass halts the run.
fn passed_stage(stage: &VerificationStageEvidence) -> bool {
    stage.status == VerificationStageStatus::Passed
}

/// Resolve the operation's immutable binding and every retained artifact path
/// it names. Missing durable state is an error, not an assumption.
async fn load_verification_context(
    store: &Store,
    operation_id: Uuid,
) -> Result<VerificationContext, ClassifiedError> {
    let record = store
        .remediation_operation(operation_id)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        .ok_or_else(|| {
            ClassifiedError::Validation(format!("remediation operation {operation_id} not found"))
        })?;
    let binding: RemediationBinding =
        serde_json::from_str(&record.binding_json).map_err(|error| {
            ClassifiedError::Internal(format!("decode remediation binding: {error}"))
        })?;
    let run = store
        .get_run(record.run_id)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        .ok_or_else(|| {
            ClassifiedError::Validation(format!("run {} was not found", record.run_id))
        })?;
    let config = run.config.as_ref().ok_or_else(|| {
        ClassifiedError::Validation("run has no retained configuration".to_owned())
    })?;
    let harness = store
        .get_harness(config.harness_id)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        .ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "harness {} referenced by run was not found",
                config.harness_id
            ))
        })?;
    let crash = store
        .list_crashes_by_run(record.run_id)
        .await
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        .into_iter()
        .find(|crash| crash.id == record.finding_id)
        .ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "finding {} was not found for run {}",
                record.finding_id, record.run_id
            ))
        })?;

    let project_root = PathBuf::from(&record.project_root);
    let target_workspace = crate::container::workspace_dir(&project_root, &record.target);
    let run_root = target_workspace
        .join("runs")
        .join(record.run_id.to_string());
    let artifact_root = target_workspace.join(&record.artifact_dir);
    Ok(VerificationContext {
        binding,
        harness,
        original_binary: run_root.join("input").join("harness"),
        reproducer: crash.input_path,
        corpus_dir: run_root.join("corpus"),
        build_dir: artifact_root.join("build"),
        follow_up_dir: artifact_root.join("follow_up"),
        run_root,
        project_root,
    })
}

/// Stage the patched build tree: copy the current sources into the
/// operation-owned directory, prove every immutable binding digest still
/// matches, and write the approved harness source and patch for the build
/// stage. Any mismatch fails closed before a single sandbox command runs.
async fn stage_build_tree(context: &VerificationContext) -> Result<(), ClassifiedError> {
    let build_dir = context.build_dir.clone();
    let project_root = context.project_root.clone();
    let sandbox_digest = context.binding.sandbox_image_sha256.clone();
    let expected_source = context.binding.source_revision_sha256.clone();
    let harness_source = context.harness.source.clone();
    let harness_sha = context.binding.harness_sha256.clone();
    let patch = context.binding.patch.clone();
    let original_binary = context.original_binary.clone();
    let reproducer = context.reproducer.clone();
    let expected_binary = context.binding.original_binary_sha256.clone();
    let expected_reproducer = context.binding.reproducer_sha256.clone();
    tokio::task::spawn_blocking(move || -> Result<(), ClassifiedError> {
        std::fs::create_dir_all(&build_dir).map_err(|error| {
            ClassifiedError::Storage(format!("create remediation build directory: {error}"))
        })?;
        crate::container::copy_project_sources(&project_root, &build_dir);
        let source_digest =
            crate::container::run_context_source_digest(&build_dir, &sandbox_digest)?;
        if source_digest != expected_source {
            return Err(ClassifiedError::Validation(format!(
                "remediation pre-flight: staged source revision {source_digest} does not match the run's retained source revision {expected_source}"
            )));
        }
        if sha256_bytes(harness_source.as_bytes()) != harness_sha {
            return Err(ClassifiedError::Validation(
                "remediation pre-flight: harness source digest does not match the binding"
                    .to_owned(),
            ));
        }
        if sha256_file(&original_binary)? != expected_binary {
            return Err(ClassifiedError::Validation(
                "remediation pre-flight: original binary digest does not match the binding"
                    .to_owned(),
            ));
        }
        if sha256_file(&reproducer)? != expected_reproducer {
            return Err(ClassifiedError::Validation(
                "remediation pre-flight: reproducer digest does not match the binding".to_owned(),
            ));
        }
        std::fs::write(build_dir.join("harness.c"), harness_source)
            .map_err(|error| ClassifiedError::Storage(format!("stage harness source: {error}")))?;
        std::fs::write(build_dir.join("PATCH.diff"), patch).map_err(|error| {
            ClassifiedError::Storage(format!("stage remediation patch: {error}"))
        })?;
        Ok(())
    })
    .await
    .map_err(|error| ClassifiedError::Internal(format!("join pre-flight task: {error}")))?
}

/// Stage 1: replay the retained reproducer against the original binary. The
/// finding must still reproduce, otherwise there is nothing to prove fixed.
async fn stage_original_replay(
    runtime: &Arc<dyn RuntimeAdapter>,
    context: &VerificationContext,
    opts: &SandboxOptions,
) -> VerificationStageEvidence {
    let spec = &context.binding.verification_spec;
    match runtime
        .as_ref()
        .run_command_opts(
            &[
                path_string(&context.original_binary),
                path_string(&context.reproducer),
            ],
            &context.run_root,
            &resource_limits(spec, spec.replay_timeout_secs),
            opts,
        )
        .await
    {
        Ok(result) => match replay_outcome(&result) {
            ReplayOutcome::Crashed => passed("original_reproduced", 1),
            ReplayOutcome::Clean => inconclusive("original_not_reproduced", 1),
            ReplayOutcome::Inconclusive => inconclusive("original_replay_timeout", 1),
        },
        Err(error) => {
            tracing::warn!(%error, "original replay command failed");
            inconclusive("original_replay_runtime_error", 1)
        }
    }
}

/// Stage 2: apply the approved patch to the staged tree and compile the
/// approved harness against it. Returns the stage evidence and, on success,
/// the patched binary's digest -- which is only knowable after this build.
async fn stage_patch_build(
    runtime: &Arc<dyn RuntimeAdapter>,
    context: &VerificationContext,
    opts: &SandboxOptions,
) -> (VerificationStageEvidence, Option<String>) {
    let spec = &context.binding.verification_spec;
    let patch_cmd = [
        "patch".to_owned(),
        "-p1".to_owned(),
        "-i".to_owned(),
        "PATCH.diff".to_owned(),
    ];
    let patch_ok = matches!(
        runtime
            .as_ref()
            .run_command_opts(
                &patch_cmd,
                &context.build_dir,
                &resource_limits(spec, spec.replay_timeout_secs),
                opts,
            )
            .await,
        Ok(result) if result.termination == CommandTermination::Completed && result.exit_code == 0
    );
    if patch_ok {
        let build_cmd = [
            "bash".to_owned(),
            "-c".to_owned(),
            compile_command(&context.harness, &context.build_dir),
        ];
        let build_ok = matches!(
            runtime
                .as_ref()
                .run_command_opts(
                    &build_cmd,
                    &context.build_dir,
                    &resource_limits(spec, spec.replay_timeout_secs * 2 + 30),
                    opts,
                )
                .await,
            Ok(result) if result.termination == CommandTermination::Completed && result.exit_code == 0
        );
        if build_ok {
            let patched_path = context.patched_binary();
            match tokio::task::spawn_blocking(move || sha256_file(&patched_path)).await {
                Ok(Ok(digest)) => (passed("patch_built", 1), Some(digest)),
                Ok(Err(error)) => {
                    tracing::warn!(%error, "patched binary digest failed");
                    (inconclusive("patched_binary_unreadable", 1), None)
                }
                Err(error) => {
                    tracing::warn!(%error, "patched binary digest task failed");
                    (inconclusive("patched_binary_unreadable", 1), None)
                }
            }
        } else {
            (failed("build_failed", 1, 1), None)
        }
    } else {
        (failed("patch_failed", 1, 1), None)
    }
}

/// Stage 3: the same reproducer must no longer crash the patched binary.
async fn stage_patched_replay(
    runtime: &Arc<dyn RuntimeAdapter>,
    context: &VerificationContext,
    opts: &SandboxOptions,
) -> VerificationStageEvidence {
    let spec = &context.binding.verification_spec;
    match runtime
        .as_ref()
        .run_command_opts(
            &[
                path_string(&context.patched_binary()),
                path_string(&context.reproducer),
            ],
            &context.build_dir,
            &resource_limits(spec, spec.replay_timeout_secs),
            opts,
        )
        .await
    {
        Ok(result) => match replay_outcome(&result) {
            ReplayOutcome::Crashed => failed("patched_replay_crashed", 1, 1),
            ReplayOutcome::Clean => passed("patched_replay_clean", 1),
            ReplayOutcome::Inconclusive => inconclusive("patched_replay_timeout", 1),
        },
        Err(error) => {
            tracing::warn!(%error, "patched replay command failed");
            inconclusive("patched_replay_runtime_error", 1)
        }
    }
}

/// Stage 4: a bounded, deterministic ordering of the retained corpus must
/// replay cleanly against the patched binary. An empty corpus proves nothing.
async fn stage_regression(
    runtime: &Arc<dyn RuntimeAdapter>,
    context: &VerificationContext,
    opts: &SandboxOptions,
) -> VerificationStageEvidence {
    let spec = &context.binding.verification_spec;
    let entries = list_corpus(&context.corpus_dir, spec.max_regression_cases);
    if entries.is_empty() {
        return inconclusive("regression_empty", 0);
    }
    let patched_binary = context.patched_binary();
    let mut crashes = 0usize;
    let mut inconclusive_run = false;
    for entry in &entries {
        match runtime
            .as_ref()
            .run_command_opts(
                &[path_string(&patched_binary), path_string(entry)],
                &context.build_dir,
                &resource_limits(spec, spec.replay_timeout_secs),
                opts,
            )
            .await
        {
            Ok(result) => match replay_outcome(&result) {
                ReplayOutcome::Crashed => crashes += 1,
                ReplayOutcome::Clean => {}
                ReplayOutcome::Inconclusive => inconclusive_run = true,
            },
            Err(_) => inconclusive_run = true,
        }
    }
    let cases = entries.len();
    if inconclusive_run {
        inconclusive("regression_inconclusive", cases)
    } else if crashes > 0 {
        failed("regression_crashed", cases, crashes)
    } else {
        passed("regression_clean", cases)
    }
}

/// Stage 5: bounded follow-up fuzzing against the patched binary must not find
/// a new crash. Missing completion is inconclusive, never a pass.
async fn stage_follow_up_fuzz(
    runtime: &Arc<dyn RuntimeAdapter>,
    context: &VerificationContext,
    opts: &SandboxOptions,
) -> VerificationStageEvidence {
    let spec = &context.binding.verification_spec;
    let _ = std::fs::create_dir_all(&context.follow_up_dir);
    let cmd = vec![
        path_string(&context.patched_binary()),
        format!("-max_total_time={}", spec.follow_up_fuzz_seconds),
        format!("-seed={}", spec.seed),
        path_string(&context.corpus_dir),
    ];
    match runtime
        .as_ref()
        .run_command_opts(
            &cmd,
            &context.follow_up_dir,
            &resource_limits(spec, spec.follow_up_fuzz_seconds + 5),
            opts,
        )
        .await
    {
        Ok(result) => match replay_outcome(&result) {
            ReplayOutcome::Crashed => failed("follow_up_crashed", 1, 1),
            ReplayOutcome::Clean => passed("follow_up_clean", 1),
            ReplayOutcome::Inconclusive => inconclusive("follow_up_inconclusive", 1),
        },
        Err(error) => {
            tracing::warn!(%error, "follow-up fuzz command failed");
            inconclusive("follow_up_runtime_error", 1)
        }
    }
}
