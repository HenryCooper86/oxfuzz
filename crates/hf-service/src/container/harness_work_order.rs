//! Durable provider-free Harness Work Order export and retrieval.

use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

use chrono::Utc;
use hf_core::{
    build::BuildContext,
    engine::EngineKind,
    error::ClassifiedError,
    harness::{Harness, HarnessStatus},
    runtime::{classify_fixed_sandbox_include_path, FixedSandboxIncludePath},
    target::{TargetCandidate, TargetLanguage},
};
use hf_storage::{
    HarnessWorkOrderAttemptCompletion, HarnessWorkOrderAttemptRecord, HarnessWorkOrderAttemptStage,
    HarnessWorkOrderAttemptStatus, HarnessWorkOrderRecord, HarnessWorkOrderSubmissionInsertError,
    HarnessWorkOrderSubmissionRecord, StorageError, Store,
};
use sha2::Digest;

use crate::{
    container::{
        project_identity::{canonical_project_root, select_target_candidate},
        require_fuzzing_harness_engine, ServiceContainer,
    },
    harness_work_order::{
        build_work_order, verify_work_order, HarnessWorkOrder, HarnessWorkOrderAttempt,
        HarnessWorkOrderAttemptResult, HarnessWorkOrderError, HarnessWorkOrderErrorCode,
        HarnessWorkOrderPayload, HarnessWorkOrderRanking, HarnessWorkOrderSubmission,
        ImportHarnessWorkOrderSubmissionRequest, WorkOrderCompileContext, WorkOrderSeedReference,
        WorkOrderSourceEvidence, WorkOrderStep, WorkOrderSubmissionOrigin, WorkOrderTargetEvidence,
        MAX_WORK_ORDER_SEEDS, MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES,
        MAX_WORK_ORDER_SOURCE_EXCERPT_LINES,
    },
};

const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROVENANCE_LABEL_BYTES: usize = 128;
const MAX_PROVENANCE_RESPONSE_ID_BYTES: usize = 256;
const MAX_ATTEMPT_FAILURE_CODE_BYTES: usize = 128;
const MAX_ATTEMPT_FAILURE_MESSAGE_BYTES: usize = 4_096;

/// Provider-free request for one durable authoring packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessWorkOrderExportRequest {
    pub project: PathBuf,
    pub target: String,
    pub language: TargetLanguage,
    pub engine: EngineKind,
}

impl ServiceContainer {
    fn work_order_store(&self) -> Result<&Store, HarnessWorkOrderError> {
        if !self.work_order_recovery_ready {
            return Err(HarnessWorkOrderError::storage(
                "harness work order recovery is incomplete",
            ));
        }
        self.store()
            .map(AsRef::as_ref)
            .ok_or_else(|| HarnessWorkOrderError::storage("durable work order storage is required"))
    }

    /// Export retained target evidence as an immutable durable work order.
    pub async fn export_harness_work_order(
        &self,
        request: HarnessWorkOrderExportRequest,
    ) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let project = canonical_project_root(&request.project).map_err(service_validation)?;
        require_fuzzing_harness_engine(request.engine, request.language)
            .map_err(service_validation)?;
        let project_text = project.to_str().ok_or_else(|| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidProjectPath,
                "project path is not UTF-8",
            )
        })?;
        let retained = store
            .list_targets(project_text)
            .await
            .map_err(storage_error)?;
        let candidates = retained
            .into_iter()
            .filter(|candidate| candidate.language == request.language)
            .collect::<Vec<_>>();
        let candidate = select_target_candidate(&candidates, &request.target)
            .map_err(service_validation)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::WorkOrderNotFound,
                    "retained target was not found for this project and language",
                )
            })?;

        let build_context = self
            .resolve_build_context(&project)
            .map_err(service_validation)?
            .unwrap_or_else(empty_build_context);
        let relative_source =
            project_relative_regular_file(&project, &candidate.location.file, MAX_SOURCE_BYTES)?;
        let payload = HarnessWorkOrderPayload {
            target: WorkOrderTargetEvidence {
                symbol: candidate.symbol.clone(),
                signature: candidate.signature.clone(),
                language: candidate.language,
                relative_source: relative_source.to_str().map(str::to_owned).ok_or_else(|| {
                    HarnessWorkOrderError::validation(
                        HarnessWorkOrderErrorCode::InvalidProjectPath,
                        "candidate source path is not UTF-8",
                    )
                })?,
                line: candidate.location.line,
                rationale: candidate.rationale.clone(),
            },
            engine: request.engine,
            source: source_evidence(&project, candidate)?,
            compile_context: normalized_build_context(&project, build_context)?,
            compile_context_sha256: String::new(),
            harness_rules: crate::harness_work_order::work_order_rules(candidate.language),
            seeds: seed_references(store, candidate.id).await?,
            validation_steps: vec![
                WorkOrderStep::Import,
                WorkOrderStep::Qualify,
                WorkOrderStep::Rank,
                WorkOrderStep::Promote,
                WorkOrderStep::RunCampaign { duration_secs: 300 },
                WorkOrderStep::Coverage,
            ],
        };
        let packet = build_work_order(payload)?;
        let packet_json = serde_json::to_string(&packet).map_err(serialization_error)?;

        if let Some(existing) = store
            .harness_work_order(&packet.id)
            .await
            .map_err(storage_error)?
        {
            return retained_packet(&existing, Some((&project, candidate.id)));
        }
        let record = HarnessWorkOrderRecord {
            id: packet.id.clone(),
            target_id: candidate.id,
            project_root: project_text.to_owned(),
            schema_version: packet.schema_version,
            packet_json,
            created_at: Utc::now(),
        };
        if let Ok(persisted) = store.insert_harness_work_order(&record).await {
            retained_packet(&persisted, Some((&project, candidate.id)))
        } else {
            let existing = store
                .harness_work_order(&packet.id)
                .await
                .map_err(storage_error)?
                .ok_or_else(|| HarnessWorkOrderError::storage("persist work order"))?;
            retained_packet(&existing, Some((&project, candidate.id)))
        }
    }

    /// Read and verify one immutable durable packet.
    pub async fn harness_work_order_by_id(
        &self,
        id: &str,
    ) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let record = store
            .harness_work_order(id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::WorkOrderNotFound,
                    "work order was not found",
                )
            })?;
        retained_packet(&record, None)
    }

    /// List verified durable packets, optionally scoped to a canonical project.
    pub async fn list_harness_work_orders(
        &self,
        project: Option<&Path>,
    ) -> Result<Vec<HarnessWorkOrder>, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let canonical = project
            .map(canonical_project_root)
            .transpose()
            .map_err(service_validation)?;
        let project_text = canonical
            .as_deref()
            .map(|path| {
                path.to_str().ok_or_else(|| {
                    HarnessWorkOrderError::validation(
                        HarnessWorkOrderErrorCode::InvalidProjectPath,
                        "project path is not UTF-8",
                    )
                })
            })
            .transpose()?;
        store
            .list_harness_work_orders(project_text)
            .await
            .map_err(storage_error)?
            .into_iter()
            .map(|record| retained_packet(&record, None))
            .collect()
    }

    /// Import one externally authored immutable harness submission.
    pub async fn import_harness_work_order_submission(
        &self,
        request: ImportHarnessWorkOrderSubmissionRequest,
    ) -> Result<HarnessWorkOrderSubmission, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let work_order = load_verified_work_order(store, &request.work_order_id).await?;
        validate_submission_source(&request.source)?;
        let origin = normalized_submission_origin(request.origin)?;
        let origin_json = canonical_origin_json(&origin)?;
        let lint =
            hf_harness::lint_harness_source(&request.source, work_order.payload.target.language);
        let lint_json = serde_json::to_string(&lint).map_err(serialization_error)?;
        let record = HarnessWorkOrderSubmissionRecord {
            id: uuid::Uuid::new_v4(),
            work_order_id: request.work_order_id,
            source_sha256: hex::encode(sha2::Sha256::digest(request.source.as_bytes())),
            source: request.source,
            origin_json,
            parent_submission_id: request.parent_submission_id,
            lint_json,
            submitted_at: Utc::now(),
        };
        let persisted = store
            .insert_harness_work_order_submission(&record)
            .await
            .map_err(submission_insertion_error)?;
        retained_submission(&persisted)
    }

    /// Read one immutable submission after verifying its durable work order.
    pub async fn harness_work_order_submission(
        &self,
        id: uuid::Uuid,
    ) -> Result<HarnessWorkOrderSubmission, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let record = store
            .harness_work_order_submission(id)
            .await
            .map_err(durable_submission_storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::SubmissionNotFound,
                    "work order submission was not found",
                )
            })?;
        load_verified_work_order(store, &record.work_order_id).await?;
        retained_submission(&record)
    }

    /// List immutable submissions for one verified durable work order.
    pub async fn list_harness_work_order_submissions(
        &self,
        work_order_id: &str,
    ) -> Result<Vec<HarnessWorkOrderSubmission>, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        load_verified_work_order(store, work_order_id).await?;
        store
            .list_harness_work_order_submissions(work_order_id)
            .await
            .map_err(durable_submission_storage_error)?
            .iter()
            .map(retained_submission)
            .collect()
    }

    /// Qualify one immutable submission through compile, review, and smoke.
    #[tracing::instrument(skip(self), fields(%submission_id))]
    pub async fn qualify_harness_work_order_submission(
        &self,
        submission_id: uuid::Uuid,
    ) -> Result<HarnessWorkOrderAttempt, HarnessWorkOrderError> {
        let preflight = self.qualification_preflight(submission_id).await?;
        let store = self.work_order_store()?;
        let started_at = Utc::now();
        let attempt = HarnessWorkOrderAttemptRecord {
            id: uuid::Uuid::new_v4(),
            submission_id,
            status: HarnessWorkOrderAttemptStatus::Running,
            current_stage: HarnessWorkOrderAttemptStage::Compile,
            harness_id: None,
            smoke_run_id: None,
            result_json: None,
            failure_code: None,
            failure_message: None,
            started_at,
            updated_at: started_at,
            ended_at: None,
        };
        let attempt = store
            .insert_harness_work_order_attempt(&attempt)
            .await
            .map_err(storage_error)?;
        let mut result = HarnessWorkOrderAttemptResult {
            compiled: false,
            smoke_verdict: None,
            repair_depth: preflight.repair_depth,
            source_sha256: None,
            binary_sha256: None,
            execs_per_sec: None,
            crashes: None,
        };
        let payload = &preflight.work_order.payload;
        let target_selector = format!(
            "{}::{}",
            payload.target.relative_source, payload.target.symbol
        );

        let compiled = match self
            .harness_compile(
                preflight.submission.source,
                &preflight.project,
                payload.engine,
                &target_selector,
                payload.target.language,
            )
            .await
        {
            Ok(compiled) => compiled,
            Err(error) => {
                return complete_failed_attempt(
                    store,
                    &attempt,
                    HarnessWorkOrderAttemptStage::Compile,
                    HarnessWorkOrderAttemptStatus::CompileFailed,
                    None,
                    None,
                    &result,
                    &error,
                )
                .await;
            }
        };
        result.compiled = true;
        store
            .transition_harness_work_order_attempt(
                attempt.id,
                HarnessWorkOrderAttemptStage::Compile,
                HarnessWorkOrderAttemptStage::Review,
                Some(compiled.harness_id),
                Utc::now(),
            )
            .await
            .map_err(storage_error)?;

        let review = match self
            .harness_review_exact_detailed(
                &preflight.project,
                &target_selector,
                payload.engine,
                payload.target.language,
                compiled.harness_id,
            )
            .await
        {
            Ok(review) => review,
            Err(failure) => {
                if let Some(evidence) = failure.evidence {
                    result.source_sha256 = Some(evidence.source_sha256);
                    result.binary_sha256 = Some(evidence.binary_sha256);
                }
                return complete_failed_attempt(
                    store,
                    &attempt,
                    HarnessWorkOrderAttemptStage::Review,
                    HarnessWorkOrderAttemptStatus::ReviewFailed,
                    Some(compiled.harness_id),
                    None,
                    &result,
                    &failure.error,
                )
                .await;
            }
        };
        result.source_sha256 = Some(review.source_sha256.clone());
        result.binary_sha256 = Some(review.binary_sha256.clone());
        store
            .transition_harness_work_order_attempt(
                attempt.id,
                HarnessWorkOrderAttemptStage::Review,
                HarnessWorkOrderAttemptStage::Smoke,
                Some(compiled.harness_id),
                Utc::now(),
            )
            .await
            .map_err(storage_error)?;

        let smoke = match self
            .harness_smoke_exact_detailed(
                &preflight.project,
                &target_selector,
                payload.engine,
                payload.target.language,
                compiled.harness_id,
            )
            .await
        {
            Ok(smoke) => smoke,
            Err(failure) => {
                return complete_failed_attempt(
                    store,
                    &attempt,
                    HarnessWorkOrderAttemptStage::Smoke,
                    HarnessWorkOrderAttemptStatus::SmokeFailed,
                    Some(compiled.harness_id),
                    failure.smoke_run_id,
                    &result,
                    &failure.error,
                )
                .await;
            }
        };
        let Some(smoke_run_id) = smoke.summary.run_id else {
            let error = ClassifiedError::Internal(
                "successful smoke qualification omitted its durable run id".to_owned(),
            );
            return complete_failed_attempt(
                store,
                &attempt,
                HarnessWorkOrderAttemptStage::Smoke,
                HarnessWorkOrderAttemptStatus::SmokeFailed,
                Some(compiled.harness_id),
                None,
                &result,
                &error,
            )
            .await;
        };
        result.smoke_verdict = Some(smoke.verdict.level);
        result.execs_per_sec = Some(smoke.summary.execs_per_sec);
        result.crashes = Some(smoke.summary.crashes);
        let result_json = serde_json::to_string(&result).map_err(serialization_error)?;
        let completed = store
            .complete_harness_work_order_attempt(
                attempt.id,
                HarnessWorkOrderAttemptCompletion {
                    expected_stage: HarnessWorkOrderAttemptStage::Smoke,
                    status: HarnessWorkOrderAttemptStatus::SmokePassed,
                    harness_id: Some(compiled.harness_id),
                    smoke_run_id: Some(smoke_run_id),
                    result_json: Some(&result_json),
                    failure_code: None,
                    failure_message: None,
                    completed_at: Utc::now(),
                },
            )
            .await
            .map_err(storage_error)?;
        retained_attempt(&completed)
    }

    /// Read one durable qualification attempt.
    #[tracing::instrument(skip(self), fields(%attempt_id))]
    pub async fn harness_work_order_attempt(
        &self,
        attempt_id: uuid::Uuid,
    ) -> Result<HarnessWorkOrderAttempt, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let record = store
            .harness_work_order_attempt(attempt_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::AttemptNotFound,
                    "work order qualification attempt was not found",
                )
            })?;
        retained_attempt(&record)
    }

    /// List durable qualification attempts for one immutable submission.
    #[tracing::instrument(skip(self), fields(%submission_id))]
    pub async fn list_harness_work_order_attempts(
        &self,
        submission_id: uuid::Uuid,
    ) -> Result<Vec<HarnessWorkOrderAttempt>, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        if store
            .harness_work_order_submission(submission_id)
            .await
            .map_err(durable_submission_storage_error)?
            .is_none()
        {
            return Err(HarnessWorkOrderError::not_found(
                HarnessWorkOrderErrorCode::SubmissionNotFound,
                "work order submission was not found",
            ));
        }
        store
            .list_harness_work_order_attempts(submission_id)
            .await
            .map_err(storage_error)?
            .iter()
            .map(retained_attempt)
            .collect()
    }

    /// Rank retained qualification attempts without dispatching or reading active artifacts.
    #[tracing::instrument(skip(self, attempt_ids), fields(attempt_count = attempt_ids.len()))]
    pub async fn rank_harness_work_order_attempts(
        &self,
        attempt_ids: &[uuid::Uuid],
    ) -> Result<HarnessWorkOrderRanking, HarnessWorkOrderError> {
        validate_ranking_request(attempt_ids)?;
        let store = self.work_order_store()?;
        let mut attempts = Vec::with_capacity(attempt_ids.len());
        for attempt_id in attempt_ids {
            let record = store
                .harness_work_order_attempt(*attempt_id)
                .await
                .map_err(storage_error)?
                .ok_or_else(attempt_not_found)?;
            let attempt = retained_attempt(&record)?;
            let submission_record = store
                .harness_work_order_submission(attempt.submission_id)
                .await
                .map_err(durable_submission_storage_error)?
                .ok_or_else(|| {
                    HarnessWorkOrderError::validation(
                        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                        "ranked attempt submission is missing",
                    )
                })?;
            let submission = retained_submission(&submission_record)?;
            load_verified_work_order(store, &submission.work_order_id).await?;
            let repair_depth = submission_repair_depth(store, &submission).await?;
            if attempt
                .result
                .as_ref()
                .is_some_and(|result| result.repair_depth != repair_depth)
            {
                return Err(invalid_attempt_evidence());
            }
            attempts.push(RankedAttempt::new(
                &attempt,
                submission.submitted_at,
                repair_depth,
            ));
        }
        attempts.sort_by(RankedAttempt::compare);
        let winner_attempt_id = attempts
            .iter()
            .find(|attempt| attempt.compiled)
            .map(|attempt| attempt.id);
        Ok(HarnessWorkOrderRanking {
            attempt_ids: attempts.into_iter().map(|attempt| attempt.id).collect(),
            winner_attempt_id,
        })
    }

    /// Promote the exact clean smoke revision retained by one terminal attempt.
    #[tracing::instrument(skip(self), fields(%attempt_id))]
    pub async fn promote_harness_work_order_attempt(
        &self,
        attempt_id: uuid::Uuid,
    ) -> Result<Harness, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let record = store
            .harness_work_order_attempt(attempt_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(attempt_not_found)?;
        let attempt = retained_attempt(&record).map_err(|_| attempt_not_smoke_passed())?;
        let evidence = PromotionEvidence::from_attempt(&attempt)?;
        let submission_record = store
            .harness_work_order_submission(attempt.submission_id)
            .await
            .map_err(durable_submission_storage_error)?
            .ok_or_else(attempt_not_smoke_passed)?;
        let submission =
            retained_submission(&submission_record).map_err(|_| attempt_not_smoke_passed())?;
        let repair_depth = submission_repair_depth(store, &submission)
            .await
            .map_err(|error| {
                if error.kind == crate::harness_work_order::HarnessWorkOrderErrorKind::Storage {
                    error
                } else {
                    attempt_not_smoke_passed()
                }
            })?;
        if repair_depth != evidence.repair_depth {
            return Err(attempt_not_smoke_passed());
        }
        let work_order_record = store
            .harness_work_order(&submission.work_order_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(attempt_not_smoke_passed)?;
        let work_order =
            retained_packet(&work_order_record, None).map_err(|_| attempt_not_smoke_passed())?;
        let harness = store
            .get_harness(evidence.harness_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(attempt_not_smoke_passed)?;
        validate_retained_promotion_harness(&harness, &evidence)?;
        let target = format!(
            "{}::{}",
            work_order.payload.target.relative_source, work_order.payload.target.symbol
        );
        self.harness_promote_exact(
            Path::new(&work_order_record.project_root),
            &target,
            work_order.payload.engine,
            evidence.harness_id,
            &evidence.source_sha256,
            &evidence.binary_sha256,
        )
        .await
        .map_err(|error| exact_promotion_error(&error))
    }

    async fn qualification_preflight(
        &self,
        submission_id: uuid::Uuid,
    ) -> Result<QualificationPreflight, HarnessWorkOrderError> {
        let store = self.work_order_store()?;
        let submission_record = store
            .harness_work_order_submission(submission_id)
            .await
            .map_err(durable_submission_storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::SubmissionNotFound,
                    "work order submission was not found",
                )
            })?;
        let submission = retained_submission(&submission_record)?;
        let work_order_record = store
            .harness_work_order(&submission.work_order_id)
            .await
            .map_err(storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::not_found(
                    HarnessWorkOrderErrorCode::WorkOrderNotFound,
                    "work order was not found",
                )
            })?;
        let work_order = retained_packet(&work_order_record, None)?;
        let project = canonical_project_root(Path::new(&work_order_record.project_root))
            .map_err(|_| stale_work_order())?;
        if project.to_string_lossy() != work_order_record.project_root {
            return Err(stale_work_order());
        }
        let candidate = store
            .list_targets(&work_order_record.project_root)
            .await
            .map_err(storage_error)?
            .into_iter()
            .find(|candidate| candidate.id == work_order_record.target_id)
            .ok_or_else(stale_work_order)?;
        if candidate.symbol != work_order.payload.target.symbol
            || candidate.language != work_order.payload.target.language
            || candidate.signature != work_order.payload.target.signature
            || candidate.location.line != work_order.payload.target.line
            || candidate.rationale != work_order.payload.target.rationale
        {
            return Err(stale_work_order());
        }
        let relative_source =
            project_relative_regular_file(&project, &candidate.location.file, MAX_SOURCE_BYTES)
                .map_err(|_| stale_work_order())?;
        if relative_source.to_string_lossy() != work_order.payload.target.relative_source {
            return Err(stale_work_order());
        }
        if source_evidence(&project, &candidate)
            .map_err(|_| stale_work_order())?
            .sha256
            != work_order.payload.source.sha256
        {
            return Err(stale_work_order());
        }
        let build_context = self
            .resolve_build_context(&project)
            .map_err(|_| stale_work_order())?
            .unwrap_or_else(empty_build_context);
        let mut current_payload = work_order.payload.clone();
        current_payload.compile_context =
            normalized_build_context(&project, build_context).map_err(|_| stale_work_order())?;
        let current = build_work_order(current_payload).map_err(|_| stale_work_order())?;
        if current.payload.compile_context_sha256 != work_order.payload.compile_context_sha256 {
            return Err(stale_work_order());
        }
        let lint =
            hf_harness::lint_harness_source(&submission.source, work_order.payload.target.language);
        if lint != submission.lint {
            return Err(HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable submission lint does not match its source",
            ));
        }
        if hf_harness::has_blocking_finding(&lint) {
            return Err(HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::SubmissionHasBlockingLint,
                "submission has blocking harness lint findings",
            ));
        }
        let repair_depth = submission_repair_depth(store, &submission).await?;
        Ok(QualificationPreflight {
            project,
            work_order,
            submission,
            repair_depth,
        })
    }
}

struct QualificationPreflight {
    project: PathBuf,
    work_order: HarnessWorkOrder,
    submission: HarnessWorkOrderSubmission,
    repair_depth: u32,
}

async fn submission_repair_depth(
    store: &Store,
    submission: &HarnessWorkOrderSubmission,
) -> Result<u32, HarnessWorkOrderError> {
    let mut depth = 0_u32;
    let mut parent_id = submission.parent_submission_id;
    while let Some(id) = parent_id {
        let parent_record = store
            .harness_work_order_submission(id)
            .await
            .map_err(durable_submission_storage_error)?
            .ok_or_else(|| {
                HarnessWorkOrderError::validation(
                    HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                    "durable submission ancestry is incomplete",
                )
            })?;
        let parent = retained_submission(&parent_record)?;
        if parent.work_order_id != submission.work_order_id {
            return Err(HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable submission ancestry crosses work orders",
            ));
        }
        depth = depth.checked_add(1).ok_or_else(|| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable submission ancestry is too deep",
            )
        })?;
        if depth >= hf_storage::MAX_WORK_ORDER_SUBMISSIONS {
            return Err(HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable submission ancestry is too deep",
            ));
        }
        parent_id = parent.parent_submission_id;
    }
    Ok(depth)
}

struct RankedAttempt {
    id: uuid::Uuid,
    compiled: bool,
    verdict: u8,
    repair_depth: u32,
    execs_per_sec: f64,
    submitted_at: chrono::DateTime<Utc>,
}

impl RankedAttempt {
    fn new(
        attempt: &HarnessWorkOrderAttempt,
        submitted_at: chrono::DateTime<Utc>,
        repair_depth: u32,
    ) -> Self {
        let result = attempt.result.as_ref();
        Self {
            id: attempt.id,
            compiled: result.is_some_and(|result| result.compiled),
            verdict: match result.and_then(|result| result.smoke_verdict) {
                Some(crate::VerdictLevel::Pass) => 0,
                Some(crate::VerdictLevel::Suspect) => 1,
                Some(crate::VerdictLevel::Fail) => 2,
                None => 3,
            },
            repair_depth,
            execs_per_sec: result
                .and_then(|result| result.execs_per_sec)
                .unwrap_or(0.0),
            submitted_at,
        }
    }

    fn compare(left: &Self, right: &Self) -> std::cmp::Ordering {
        right
            .compiled
            .cmp(&left.compiled)
            .then_with(|| left.verdict.cmp(&right.verdict))
            .then_with(|| left.repair_depth.cmp(&right.repair_depth))
            .then_with(|| right.execs_per_sec.total_cmp(&left.execs_per_sec))
            .then_with(|| left.submitted_at.cmp(&right.submitted_at))
            .then_with(|| left.id.cmp(&right.id))
    }
}

struct PromotionEvidence {
    harness_id: uuid::Uuid,
    smoke_run_id: uuid::Uuid,
    repair_depth: u32,
    source_sha256: String,
    binary_sha256: String,
}

impl PromotionEvidence {
    fn from_attempt(attempt: &HarnessWorkOrderAttempt) -> Result<Self, HarnessWorkOrderError> {
        let result = attempt
            .result
            .as_ref()
            .ok_or_else(attempt_not_smoke_passed)?;
        if attempt.status != HarnessWorkOrderAttemptStatus::SmokePassed
            || attempt.current_stage != HarnessWorkOrderAttemptStage::Complete
            || result.smoke_verdict == Some(crate::VerdictLevel::Fail)
        {
            return Err(attempt_not_smoke_passed());
        }
        Ok(Self {
            harness_id: attempt.harness_id.ok_or_else(attempt_not_smoke_passed)?,
            smoke_run_id: attempt.smoke_run_id.ok_or_else(attempt_not_smoke_passed)?,
            repair_depth: result.repair_depth,
            source_sha256: result
                .source_sha256
                .clone()
                .ok_or_else(attempt_not_smoke_passed)?,
            binary_sha256: result
                .binary_sha256
                .clone()
                .ok_or_else(attempt_not_smoke_passed)?,
        })
    }
}

fn validate_ranking_request(attempt_ids: &[uuid::Uuid]) -> Result<(), HarnessWorkOrderError> {
    if attempt_ids.len() > hf_storage::MAX_WORK_ORDER_RANK_ATTEMPTS {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::RankingLimitExceeded,
            format!(
                "ranking accepts at most {} attempts",
                hf_storage::MAX_WORK_ORDER_RANK_ATTEMPTS
            ),
        ));
    }
    if attempt_ids.is_empty()
        || attempt_ids.iter().copied().collect::<HashSet<_>>().len() != attempt_ids.len()
    {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidTransition,
            "ranking requires one or more unique attempt identifiers",
        ));
    }
    Ok(())
}

fn validate_retained_promotion_harness(
    harness: &Harness,
    evidence: &PromotionEvidence,
) -> Result<(), HarnessWorkOrderError> {
    let smoke = harness
        .smoke_run
        .as_ref()
        .ok_or_else(attempt_not_smoke_passed)?;
    if !matches!(
        harness.status,
        HarnessStatus::SmokePassed | HarnessStatus::Promoted
    ) || !smoke.passed
        || smoke.crashes != 0
        || smoke.run_id != Some(evidence.smoke_run_id)
    {
        return Err(attempt_not_smoke_passed());
    }
    if smoke.source_sha256.as_deref() != Some(evidence.source_sha256.as_str())
        || smoke.binary_sha256.as_deref() != Some(evidence.binary_sha256.as_str())
        || hex::encode(sha2::Sha256::digest(harness.source.as_bytes())) != evidence.source_sha256
    {
        return Err(attempt_not_active());
    }
    Ok(())
}

fn attempt_not_found() -> HarnessWorkOrderError {
    HarnessWorkOrderError::not_found(
        HarnessWorkOrderErrorCode::AttemptNotFound,
        "work order qualification attempt was not found",
    )
}

fn attempt_not_smoke_passed() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::AttemptNotSmokePassed,
        "promotion requires complete clean-smoke evidence for the exact attempt",
    )
}

fn exact_promotion_error(error: &ClassifiedError) -> HarnessWorkOrderError {
    if matches!(error, ClassifiedError::Storage(_)) {
        return HarnessWorkOrderError::storage("persist exact harness promotion");
    }
    attempt_not_active()
}

fn attempt_not_active() -> HarnessWorkOrderError {
    HarnessWorkOrderError::conflict(
        HarnessWorkOrderErrorCode::AttemptNotActive,
        "attempt harness id or qualified artifacts are no longer active",
    )
}

async fn complete_failed_attempt(
    store: &Store,
    attempt: &HarnessWorkOrderAttemptRecord,
    expected_stage: HarnessWorkOrderAttemptStage,
    status: HarnessWorkOrderAttemptStatus,
    harness_id: Option<uuid::Uuid>,
    smoke_run_id: Option<uuid::Uuid>,
    result: &HarnessWorkOrderAttemptResult,
    error: &ClassifiedError,
) -> Result<HarnessWorkOrderAttempt, HarnessWorkOrderError> {
    if matches!(error, ClassifiedError::Storage(_)) {
        return Err(HarnessWorkOrderError::storage(
            "harness qualification persistence failed",
        ));
    }
    let result_json = serde_json::to_string(result).map_err(serialization_error)?;
    let (failure_code, failure_message) = bounded_attempt_failure(error);
    let completed = store
        .complete_harness_work_order_attempt(
            attempt.id,
            HarnessWorkOrderAttemptCompletion {
                expected_stage,
                status,
                harness_id,
                smoke_run_id,
                result_json: Some(&result_json),
                failure_code: Some(&failure_code),
                failure_message: Some(&failure_message),
                completed_at: Utc::now(),
            },
        )
        .await
        .map_err(storage_error)?;
    retained_attempt(&completed)
}

fn retained_attempt(
    record: &HarnessWorkOrderAttemptRecord,
) -> Result<HarnessWorkOrderAttempt, HarnessWorkOrderError> {
    let result = record
        .result_json
        .as_deref()
        .map(serde_json::from_str::<HarnessWorkOrderAttemptResult>)
        .transpose()
        .map_err(|_| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable qualification result is malformed",
            )
        })?;
    if let (Some(raw), Some(parsed)) = (record.result_json.as_deref(), result.as_ref()) {
        if serde_json::to_string(parsed).map_err(serialization_error)? != raw {
            return Err(invalid_attempt_evidence());
        }
    }
    if !valid_attempt_semantics(record, result.as_ref()) {
        return Err(invalid_attempt_evidence());
    }
    Ok(HarnessWorkOrderAttempt {
        id: record.id,
        submission_id: record.submission_id,
        status: record.status,
        current_stage: record.current_stage,
        harness_id: record.harness_id,
        smoke_run_id: record.smoke_run_id,
        result,
        failure_code: record.failure_code.clone(),
        failure_message: record.failure_message.clone(),
        started_at: record.started_at,
        updated_at: record.updated_at,
        ended_at: record.ended_at,
    })
}

fn invalid_attempt_evidence() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
        "durable qualification attempt contains contradictory evidence",
    )
}

fn valid_attempt_semantics(
    record: &HarnessWorkOrderAttemptRecord,
    result: Option<&HarnessWorkOrderAttemptResult>,
) -> bool {
    if record.id.is_nil()
        || record.submission_id.is_nil()
        || record.harness_id.is_some_and(|id| id.is_nil())
        || record.smoke_run_id.is_some_and(|id| id.is_nil())
        || record.updated_at < record.started_at
        || !valid_result_values(result)
    {
        return false;
    }

    match record.status {
        HarnessWorkOrderAttemptStatus::Running => {
            record.current_stage != HarnessWorkOrderAttemptStage::Complete
                && record.ended_at.is_none()
                && record.smoke_run_id.is_none()
                && record.result_json.is_none()
                && no_failure(record)
                && match record.current_stage {
                    HarnessWorkOrderAttemptStage::Compile => record.harness_id.is_none(),
                    HarnessWorkOrderAttemptStage::Review | HarnessWorkOrderAttemptStage::Smoke => {
                        record.harness_id.is_some()
                    }
                    HarnessWorkOrderAttemptStage::Complete => false,
                }
        }
        status => {
            if record.current_stage != HarnessWorkOrderAttemptStage::Complete
                || record.ended_at != Some(record.updated_at)
            {
                return false;
            }
            match status {
                HarnessWorkOrderAttemptStatus::CompileFailed => {
                    record.harness_id.is_none()
                        && record.smoke_run_id.is_none()
                        && valid_failure(record)
                        && result.is_some_and(valid_compile_failure_result)
                }
                HarnessWorkOrderAttemptStatus::ReviewFailed => {
                    record.harness_id.is_some()
                        && record.smoke_run_id.is_none()
                        && valid_failure(record)
                        && result.is_some_and(valid_review_failure_result)
                }
                HarnessWorkOrderAttemptStatus::SmokeFailed => {
                    record.harness_id.is_some()
                        && valid_failure(record)
                        && result.is_some_and(valid_smoke_failure_result)
                }
                HarnessWorkOrderAttemptStatus::SmokePassed => {
                    record.harness_id.is_some()
                        && record.smoke_run_id.is_some()
                        && no_failure(record)
                        && result.is_some_and(valid_smoke_passed_result)
                }
                HarnessWorkOrderAttemptStatus::Interrupted => {
                    record.smoke_run_id.is_none()
                        && record.result_json.is_none()
                        && record.failure_code.as_deref() == Some("attempt_interrupted")
                        && record
                            .failure_message
                            .as_deref()
                            .is_some_and(valid_failure_message)
                }
                HarnessWorkOrderAttemptStatus::Running => false,
            }
        }
    }
}

fn valid_result_values(result: Option<&HarnessWorkOrderAttemptResult>) -> bool {
    result.is_none_or(|result| {
        result.repair_depth < hf_storage::MAX_WORK_ORDER_SUBMISSIONS
            && result.source_sha256.as_deref().is_none_or(valid_sha256)
            && result.binary_sha256.as_deref().is_none_or(valid_sha256)
            && result
                .execs_per_sec
                .is_none_or(|value| value.is_finite() && value >= 0.0)
    })
}

fn valid_compile_failure_result(result: &HarnessWorkOrderAttemptResult) -> bool {
    !result.compiled && no_digest_evidence(result) && no_smoke_evidence(result)
}

fn valid_review_failure_result(result: &HarnessWorkOrderAttemptResult) -> bool {
    result.compiled
        && no_smoke_evidence(result)
        && (result.binary_sha256.is_none() || result.source_sha256.is_some())
}

fn valid_smoke_failure_result(result: &HarnessWorkOrderAttemptResult) -> bool {
    result.compiled
        && result.source_sha256.is_some()
        && result.binary_sha256.is_some()
        && no_smoke_evidence(result)
}

fn valid_smoke_passed_result(result: &HarnessWorkOrderAttemptResult) -> bool {
    let (Some(verdict), Some(execs_per_sec), Some(crashes)) =
        (result.smoke_verdict, result.execs_per_sec, result.crashes)
    else {
        return false;
    };
    let metrics_match_verdict = match verdict {
        crate::VerdictLevel::Pass => {
            crashes == 0 && execs_per_sec >= crate::verification::MIN_MEANINGFUL_EXECS_PER_SEC
        }
        crate::VerdictLevel::Suspect => {
            crashes == 0
                && execs_per_sec > 0.0
                && execs_per_sec < crate::verification::MIN_MEANINGFUL_EXECS_PER_SEC
        }
        crate::VerdictLevel::Fail => crashes > 0,
    };
    result.compiled
        && result.source_sha256.is_some()
        && result.binary_sha256.is_some()
        && metrics_match_verdict
}

fn no_digest_evidence(result: &HarnessWorkOrderAttemptResult) -> bool {
    result.source_sha256.is_none() && result.binary_sha256.is_none()
}

fn no_smoke_evidence(result: &HarnessWorkOrderAttemptResult) -> bool {
    result.smoke_verdict.is_none() && result.execs_per_sec.is_none() && result.crashes.is_none()
}

fn no_failure(record: &HarnessWorkOrderAttemptRecord) -> bool {
    record.failure_code.is_none() && record.failure_message.is_none()
}

fn valid_failure(record: &HarnessWorkOrderAttemptRecord) -> bool {
    record.failure_code.as_deref().is_some_and(|code| {
        matches!(
            code,
            "provider" | "sandbox" | "engine" | "harness" | "validation" | "timeout" | "internal"
        )
    }) && record
        .failure_message
        .as_deref()
        .is_some_and(valid_failure_message)
}

fn valid_failure_message(message: &str) -> bool {
    !message.is_empty()
        && message.len() <= MAX_ATTEMPT_FAILURE_MESSAGE_BYTES
        && !message.chars().any(char::is_control)
        && sanitize_failure_message(message) == message
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn stale_work_order() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::StaleWorkOrder,
        "retained work order evidence no longer matches the project",
    )
}

fn bounded_attempt_failure(error: &ClassifiedError) -> (String, String) {
    let code = match error {
        ClassifiedError::Provider(_) => "provider",
        ClassifiedError::Sandbox(_) => "sandbox",
        ClassifiedError::Engine(_) => "engine",
        ClassifiedError::Harness(_) => "harness",
        ClassifiedError::Storage(_) => "storage",
        ClassifiedError::Validation(_) => "validation",
        ClassifiedError::Timeout => "timeout",
        ClassifiedError::Internal(_) => "internal",
    };
    let message = sanitize_failure_message(&error.to_string());
    let message = bounded_utf8(&message, MAX_ATTEMPT_FAILURE_MESSAGE_BYTES)
        .trim_end()
        .to_owned();
    let message = if message.is_empty() {
        format!("{code} failure")
    } else {
        message
    };
    (bounded_utf8(code, MAX_ATTEMPT_FAILURE_CODE_BYTES), message)
}

fn sanitize_failure_message(message: &str) -> String {
    let mut redact_next = false;
    message
        .split_whitespace()
        .map(|token| {
            if redact_next {
                redact_next = false;
                return "<redacted>".to_owned();
            }
            let normalized = normalized_failure_token(token);
            if normalized.eq_ignore_ascii_case("bearer") {
                redact_next = true;
                return "Bearer".to_owned();
            }
            if secret_key(normalized) {
                redact_next = true;
                return token.to_owned();
            }
            if let Some(redacted) = redact_secret_assignment(token, &mut redact_next) {
                return redacted;
            }
            if secret_value(normalized) {
                return "<redacted>".to_owned();
            }
            redact_absolute_path(token).unwrap_or_else(|| token.to_owned())
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalized_failure_token(token: &str) -> &str {
    token.trim_matches(|character: char| {
        matches!(
            character,
            '(' | ')' | '[' | ']' | '{' | '}' | '\'' | '"' | ',' | ';' | ':'
        )
    })
}

fn secret_key(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "password" | "secret" | "token" | "api_key" | "api-key" | "apikey"
    )
}

fn secret_value(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.starts_with("sk-")
        || lowercase.starts_with("ghp_")
        || lowercase.starts_with("github_pat_")
        || lowercase.starts_with("xoxb-")
        || lowercase.starts_with("xoxp-")
        || lowercase.starts_with("xoxa-")
        || lowercase.starts_with("hf_")
        || (lowercase.starts_with("akia") && lowercase.len() > 8)
}

fn redact_secret_assignment(token: &str, redact_next: &mut bool) -> Option<String> {
    for (index, character) in token.char_indices() {
        if !matches!(character, '=' | ':') {
            continue;
        }
        let key = normalized_failure_token(&token[..index]);
        if !secret_key(key) && !key.eq_ignore_ascii_case("authorization") {
            continue;
        }
        let value = &token[index + character.len_utf8()..];
        if value.eq_ignore_ascii_case("bearer") || (value.is_empty() && secret_key(key)) {
            *redact_next = true;
        }
        return Some(format!("{}<redacted>", &token[..=index]));
    }
    None
}

fn redact_absolute_path(token: &str) -> Option<String> {
    let bytes = token.as_bytes();
    for index in 0..bytes.len() {
        let starts_after_non_word =
            index == 0 || (!bytes[index - 1].is_ascii_alphanumeric() && bytes[index - 1] != b'_');
        let unix = bytes[index] == b'/';
        let windows = bytes.get(index..index + 3).is_some_and(|part| {
            part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
        });
        if starts_after_non_word && (unix || windows) {
            return Some(format!("{}<redacted-path>", &token[..index]));
        }
    }
    None
}

fn bounded_utf8(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut end = maximum_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

async fn load_verified_work_order(
    store: &hf_storage::Store,
    id: &str,
) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
    let record = store
        .harness_work_order(id)
        .await
        .map_err(storage_error)?
        .ok_or_else(|| {
            HarnessWorkOrderError::not_found(
                HarnessWorkOrderErrorCode::WorkOrderNotFound,
                "work order was not found",
            )
        })?;
    retained_packet(&record, None)
}

fn validate_submission_source(source: &str) -> Result<(), HarnessWorkOrderError> {
    if source.is_empty() {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceEmpty,
            "submission source must not be empty",
        ));
    }
    if source.len() > MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceTooLarge,
            "submission source exceeds the maximum size",
        ));
    }
    Ok(())
}

fn normalized_submission_origin(
    origin: WorkOrderSubmissionOrigin,
) -> Result<WorkOrderSubmissionOrigin, HarnessWorkOrderError> {
    match origin {
        WorkOrderSubmissionOrigin::Human => Ok(WorkOrderSubmissionOrigin::Human),
        WorkOrderSubmissionOrigin::ExternalTool {
            tool,
            model,
            response_id,
        } => Ok(WorkOrderSubmissionOrigin::ExternalTool {
            tool: normalized_provenance_label(&tool, MAX_PROVENANCE_LABEL_BYTES)?,
            model: model
                .as_deref()
                .map(|value| normalized_provenance_label(value, MAX_PROVENANCE_LABEL_BYTES))
                .transpose()?,
            response_id: response_id
                .as_deref()
                .map(|value| normalized_provenance_label(value, MAX_PROVENANCE_RESPONSE_ID_BYTES))
                .transpose()?,
        }),
    }
}

fn normalized_provenance_label(
    value: &str,
    maximum_bytes: usize,
) -> Result<String, HarnessWorkOrderError> {
    if value.chars().any(char::is_control) {
        return Err(invalid_provenance());
    }
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > maximum_bytes {
        return Err(invalid_provenance());
    }
    Ok(trimmed.to_owned())
}

fn canonical_origin_json(
    origin: &WorkOrderSubmissionOrigin,
) -> Result<String, HarnessWorkOrderError> {
    serde_json::to_string(origin).map_err(serialization_error)
}

fn retained_submission(
    record: &HarnessWorkOrderSubmissionRecord,
) -> Result<HarnessWorkOrderSubmission, HarnessWorkOrderError> {
    validate_submission_source(&record.source)?;
    let source_sha256 = hex::encode(sha2::Sha256::digest(record.source.as_bytes()));
    if record.source_sha256 != source_sha256 {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable submission source digest does not match its source",
        ));
    }
    let origin = serde_json::from_str(&record.origin_json).map_err(|_| invalid_durable_origin())?;
    let origin = normalized_submission_origin(origin).map_err(|_| invalid_durable_origin())?;
    if canonical_origin_json(&origin)? != record.origin_json {
        return Err(invalid_durable_origin());
    }
    let lint =
        serde_json::from_str::<Vec<hf_harness::LintFinding>>(&record.lint_json).map_err(|_| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable submission lint is malformed",
            )
        })?;
    if serde_json::to_string(&lint).map_err(serialization_error)? != record.lint_json {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable submission lint is not canonical",
        ));
    }
    Ok(HarnessWorkOrderSubmission {
        id: record.id,
        work_order_id: record.work_order_id.clone(),
        source: record.source.clone(),
        source_sha256: record.source_sha256.clone(),
        origin,
        parent_submission_id: record.parent_submission_id,
        lint,
        submitted_at: record.submitted_at,
    })
}

fn invalid_provenance() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidProvenance,
        "submission provenance is invalid",
    )
}

fn invalid_durable_origin() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
        "durable submission origin is malformed",
    )
}

fn submission_insertion_error(
    error: HarnessWorkOrderSubmissionInsertError,
) -> HarnessWorkOrderError {
    match error {
        HarnessWorkOrderSubmissionInsertError::MissingWorkOrder => {
            HarnessWorkOrderError::not_found(
                HarnessWorkOrderErrorCode::WorkOrderNotFound,
                "work order was not found",
            )
        }
        HarnessWorkOrderSubmissionInsertError::MissingParent => HarnessWorkOrderError::not_found(
            HarnessWorkOrderErrorCode::ParentNotFound,
            "submission parent was not found",
        ),
        HarnessWorkOrderSubmissionInsertError::ParentWorkOrderMismatch => {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::ParentWorkOrderMismatch,
                "submission parent belongs to a different work order",
            )
        }
        HarnessWorkOrderSubmissionInsertError::SubmissionLimitReached => {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::SubmissionLimitReached,
                "work order submission limit reached",
            )
        }
        HarnessWorkOrderSubmissionInsertError::Storage(error) => storage_error(error),
    }
}

fn durable_submission_storage_error(error: StorageError) -> HarnessWorkOrderError {
    match error {
        StorageError::Timestamp(message) | StorageError::InvalidData(message) => {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                format!("durable submission data is malformed: {message}"),
            )
        }
        error => storage_error(error),
    }
}

fn empty_build_context() -> BuildContext {
    BuildContext {
        include_dirs: Vec::new(),
        defines: Vec::new(),
        std_flag: None,
        extra_flags: Vec::new(),
        entry_count: 0,
        dropped: Vec::new(),
    }
}

async fn seed_references(
    store: &hf_storage::Store,
    target_id: uuid::Uuid,
) -> Result<Vec<WorkOrderSeedReference>, HarnessWorkOrderError> {
    let mut seeds = store
        .list_corpus_entries(target_id)
        .await
        .map_err(storage_error)?
        .into_iter()
        .map(|entry| WorkOrderSeedReference {
            sha256: entry.sha256,
            size: entry.size,
        })
        .collect::<Vec<_>>();
    seeds.sort_unstable();
    seeds.dedup();
    seeds.truncate(MAX_WORK_ORDER_SEEDS);
    Ok(seeds)
}

fn retained_packet(
    record: &HarnessWorkOrderRecord,
    expected: Option<(&Path, uuid::Uuid)>,
) -> Result<HarnessWorkOrder, HarnessWorkOrderError> {
    if let Some((project, target_id)) = expected {
        if record.target_id != target_id || record.project_root != project.to_string_lossy() {
            return Err(HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
                "durable work order identity conflicts with retained target evidence",
            ));
        }
    }
    let packet = serde_json::from_str::<HarnessWorkOrder>(&record.packet_json).map_err(|_| {
        HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable work order packet is malformed",
        )
    })?;
    if serde_json::to_string(&packet).map_err(serialization_error)? != record.packet_json {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable work order packet is not canonical",
        ));
    }
    if packet.id != record.id || packet.schema_version != record.schema_version {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
            "durable work order metadata does not match its packet",
        ));
    }
    verify_work_order(&packet)?;
    Ok(packet)
}

fn project_relative_regular_file(
    project: &Path,
    candidate: &Path,
    max_bytes: u64,
) -> Result<PathBuf, HarnessWorkOrderError> {
    let relative = if candidate.is_absolute() {
        candidate
            .strip_prefix(project)
            .map_err(|_| invalid_project_path())?
    } else {
        candidate
    };
    if relative.components().next().is_none()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(invalid_project_path());
    }
    let file = open_regular_file_beneath(project, relative)?;
    let metadata = file.metadata().map_err(|_| invalid_project_path())?;
    if !metadata.file_type().is_file() {
        return Err(invalid_project_path());
    }
    if metadata.len() > max_bytes {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceTooLarge,
            "candidate source exceeds the maximum size",
        ));
    }
    Ok(relative.to_path_buf())
}

fn source_evidence(
    project: &Path,
    target: &TargetCandidate,
) -> Result<WorkOrderSourceEvidence, HarnessWorkOrderError> {
    let relative = project_relative_regular_file(project, &target.location.file, MAX_SOURCE_BYTES)?;
    let mut file = open_regular_file_beneath(project, &relative)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            HarnessWorkOrderError::validation(
                HarnessWorkOrderErrorCode::InvalidProjectPath,
                "candidate source cannot be read",
            )
        })?;
    if bytes.len() > MAX_SOURCE_BYTES as usize {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::SourceTooLarge,
            "candidate source exceeds the maximum size",
        ));
    }
    let text = String::from_utf8(bytes).map_err(|_| {
        HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "candidate source is not UTF-8",
        )
    })?;
    let lines = text.lines().collect::<Vec<_>>();
    let start = usize::try_from(target.location.line.saturating_sub(1)).unwrap_or(usize::MAX);
    if start >= lines.len() {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "retained target line is outside its source file",
        ));
    }
    let (excerpt, excerpt_truncated) = bounded_excerpt(&lines[start..]);
    Ok(WorkOrderSourceEvidence {
        excerpt,
        excerpt_truncated,
        sha256: hex::encode(sha2::Sha256::digest(text.as_bytes())),
    })
}

fn bounded_excerpt(lines: &[&str]) -> (String, bool) {
    let mut excerpt = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index == MAX_WORK_ORDER_SOURCE_EXCERPT_LINES {
            return (excerpt, true);
        }
        let separator = usize::from(index > 0);
        let available = MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES.saturating_sub(excerpt.len());
        if separator + line.len() > available {
            if line.is_empty() {
                return (excerpt, true);
            }
            let line_bytes = available.saturating_sub(separator);
            let prefix_len = utf8_prefix_len(line, line_bytes);
            if prefix_len == 0 {
                return (excerpt, true);
            }
            if separator == 1 {
                excerpt.push('\n');
            }
            excerpt.push_str(&line[..prefix_len]);
            return (excerpt, true);
        }
        if separator == 1 {
            excerpt.push('\n');
        }
        excerpt.push_str(line);
    }
    (excerpt, false)
}

fn utf8_prefix_len(value: &str, max_bytes: usize) -> usize {
    value
        .char_indices()
        .take_while(|(index, character)| index + character.len_utf8() <= max_bytes)
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0)
}

fn normalized_build_context(
    project: &Path,
    context: BuildContext,
) -> Result<WorkOrderCompileContext, HarnessWorkOrderError> {
    let include_dirs = context
        .include_dirs
        .iter()
        .map(|path| normalized_include_path(project, path))
        .collect::<Result<Vec<_>, _>>()?;
    let defines = context
        .defines
        .iter()
        .map(|define| portable_define(define))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkOrderCompileContext {
        include_dirs,
        defines,
        std_flag: context.std_flag,
        extra_flags: context.extra_flags,
        compile_units: context.entry_count,
        dropped_flags: dropped_flag_categories(&context.dropped),
    })
}

fn normalized_include_path(project: &Path, path: &Path) -> Result<String, HarnessWorkOrderError> {
    match path.to_str().map(classify_fixed_sandbox_include_path) {
        Some(FixedSandboxIncludePath::Canonical) => {
            return path
                .to_str()
                .map(str::to_owned)
                .ok_or_else(invalid_project_path);
        }
        Some(FixedSandboxIncludePath::Invalid) => return Err(invalid_project_path()),
        Some(FixedSandboxIncludePath::Outside) | None => {}
    }
    let relative = if path.is_absolute() {
        path.strip_prefix(project)
            .map_err(|_| invalid_project_path())?
    } else {
        path
    };
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
    {
        return Err(invalid_project_path());
    }
    if relative.as_os_str().is_empty() {
        return Ok(".".to_owned());
    }
    relative
        .to_str()
        .map(str::to_owned)
        .ok_or_else(invalid_project_path)
}

fn portable_define(define: &str) -> Result<String, HarnessWorkOrderError> {
    let value = define.strip_prefix("-D").unwrap_or(define);
    if value
        .split_once('=')
        .is_some_and(|(_, value)| is_absolute_path(value))
    {
        return Err(HarnessWorkOrderError::validation(
            HarnessWorkOrderErrorCode::InvalidProjectPath,
            "compile definition contains an absolute path",
        ));
    }
    Ok(value.to_owned())
}

fn is_absolute_path(value: &str) -> bool {
    let value = value.trim_matches(['\'', '"']);
    let windows_drive = value.len() >= 3
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.as_bytes()[1] == b':'
        && matches!(value.as_bytes()[2], b'/' | b'\\');
    Path::new(value).is_absolute() || value.starts_with('\\') || windows_drive
}

fn dropped_flag_categories(dropped: &[String]) -> Vec<String> {
    let mut categories = dropped
        .iter()
        .map(|flag| {
            if flag.starts_with("-I")
                || flag.starts_with("-isystem")
                || flag.starts_with("-include")
                || flag.starts_with('/')
                || flag.contains('\\')
            {
                "path_bearing_flag"
            } else {
                "unsupported_flag"
            }
            .to_owned()
        })
        .collect::<Vec<_>>();
    categories.sort_unstable();
    categories.dedup();
    categories
}

fn invalid_project_path() -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidProjectPath,
        "path must name a regular file beneath the project root",
    )
}

fn service_validation(_error: crate::ClassifiedError) -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
        "work order request or retained evidence is invalid",
    )
}

fn storage_error(_error: hf_storage::StorageError) -> HarnessWorkOrderError {
    HarnessWorkOrderError::storage("durable work order storage is unavailable")
}

fn serialization_error(_error: serde_json::Error) -> HarnessWorkOrderError {
    HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest,
        "work order packet cannot be serialized",
    )
}

#[cfg(unix)]
fn open_regular_file_beneath(
    project: &Path,
    relative: &Path,
) -> Result<File, HarnessWorkOrderError> {
    use rustix::fs::{open, openat, Mode, OFlags};
    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(invalid_project_path()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (leaf, parents) = components.split_last().ok_or_else(invalid_project_path)?;
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let root = open(project, directory_flags, Mode::empty()).map_err(|_| invalid_project_path())?;
    let mut directory = File::from(root);
    for parent in parents {
        directory = File::from(
            openat(&directory, *parent, directory_flags, Mode::empty())
                .map_err(|_| invalid_project_path())?,
        );
    }
    Ok(File::from(
        openat(
            &directory,
            *leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| invalid_project_path())?,
    ))
}

#[cfg(not(unix))]
fn open_regular_file_beneath(
    _project: &Path,
    _relative: &Path,
) -> Result<File, HarnessWorkOrderError> {
    Err(HarnessWorkOrderError::validation(
        HarnessWorkOrderErrorCode::InvalidProjectPath,
        "descriptor-confined project reads are unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::bounded_excerpt;
    use crate::harness_work_order::{
        MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES, MAX_WORK_ORDER_SOURCE_EXCERPT_LINES,
    };

    #[test]
    fn bounded_excerpt_honors_byte_and_line_limits_on_utf8_edges() {
        let exact = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);
        assert_eq!(bounded_excerpt(&[&exact]), (exact, false));

        let first = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);
        let (next_line, truncated) = bounded_excerpt(&[&first, "next"]);
        assert_eq!(next_line.len(), MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES);
        assert!(!next_line.ends_with('\n'));
        assert!(truncated);

        let prefix = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES - 4);
        let (multibyte, truncated) = bounded_excerpt(&[&prefix, "éé"]);
        assert_eq!(multibyte.len(), MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES - 1);
        assert!(multibyte.ends_with("\né"));
        assert!(truncated);

        let lines = std::iter::repeat_n("line", MAX_WORK_ORDER_SOURCE_EXCERPT_LINES + 1)
            .collect::<Vec<_>>();
        let (line_limited, truncated) = bounded_excerpt(&lines);
        assert_eq!(
            line_limited.lines().count(),
            MAX_WORK_ORDER_SOURCE_EXCERPT_LINES
        );
        assert!(truncated);
    }

    #[test]
    fn bounded_excerpt_preserves_leading_empty_lines_without_separator_only_truncation() {
        assert_eq!(
            bounded_excerpt(&["", "first"]),
            ("\nfirst".to_owned(), false)
        );

        let prefix = "x".repeat(MAX_WORK_ORDER_SOURCE_EXCERPT_BYTES - 2);
        let (excerpt, truncated) = bounded_excerpt(&[&prefix, "é"]);
        assert_eq!(excerpt, prefix);
        assert!(truncated);
    }

    #[test]
    fn normalized_include_rejects_invalid_fixed_paths_under_work_root() {
        assert!(super::normalized_include_path(
            std::path::Path::new("/work"),
            std::path::Path::new("//work/include")
        )
        .is_err());
    }
}
