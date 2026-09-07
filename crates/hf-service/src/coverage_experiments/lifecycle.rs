//! Service policy over frozen campaign evidence; Store owns atomic lifecycle changes.
use super::{
    ensure_owner, valid_text, validate_coverage_experiment_project,
    CancelCoverageExperimentRequest, CompleteCoverageExperimentRequest,
    CoverageExperimentBuildComparison, CoverageExperimentCursor, CoverageExperimentError,
    CoverageExperimentErrorCode, CoverageExperimentInputChange, CoverageExperimentKind,
    CoverageExperimentLimitation, CoverageExperimentOwner, CoverageExperimentPage,
    CoverageExperimentScope, CoverageExperimentStatus, CoverageExperimentTargetEntry,
    CoverageExperimentTargetEntryReason, CoverageExperimentView, CreateCoverageExperimentRequest,
    ListCoverageExperimentsRequest, ServiceContainer, StorageError, Store, Utc, Uuid,
};
use hf_storage::{CoverageExperimentRecord, CoverageExperimentRunEvidenceV1, RunKind, RunStatus};
use CoverageExperimentErrorCode as C;

impl ServiceContainer {
    /// Persist reviewed intent and baseline evidence without dispatching any work.
    #[tracing::instrument(skip_all)]
    pub async fn create_coverage_experiment(
        &self,
        request: CreateCoverageExperimentRequest,
    ) -> Result<CoverageExperimentView, CoverageExperimentError> {
        let store = self.experiment_store()?;
        if !valid_text(&request.goal_function, 1024, false)
            || !valid_text(&request.hypothesis, 4096, true)
            || !(1..=604_800).contains(&request.duration_secs)
        {
            return Err(CoverageExperimentError::new(C::InvalidRequest));
        }
        let project = validate_coverage_experiment_project(&request.project)?;
        let baseline = eligible_snapshot(store, request.baseline_run_id, true).await?;
        ensure_owner(
            &CoverageExperimentOwner {
                project_root: baseline.project_root.clone().into(),
                target_id: baseline.target_id,
            },
            &project,
            request.target_id,
        )?;
        let policy = crate::config::effective_fuzzing_settings()
            .map_err(|_| CoverageExperimentError::field(C::InvalidRequest, "fuzzing_policy"))?;
        let resolved = policy
            .resolve(Some(baseline.engine), Some(request.duration_secs))
            .map_err(|_| CoverageExperimentError::field(C::InvalidRequest, "fuzzing_policy"))?;
        if resolved.duration_secs != request.duration_secs
            || baseline.duration_secs != request.duration_secs
        {
            return Err(CoverageExperimentError::field(
                C::DifferentRunSettings,
                "duration_secs",
            ));
        }
        let now = Utc::now();
        if baseline.ended_at > now {
            return Err(CoverageExperimentError::new(C::InvalidChronology));
        }
        let record = CoverageExperimentRecord {
            id: Uuid::new_v4(),
            schema_version: 1,
            project_root: baseline.project_root.clone(),
            target_id: baseline.target_id,
            target_symbol: baseline.target_symbol.clone(),
            baseline_run_id: baseline.run_id,
            kind: request.kind,
            goal_function: request.goal_function,
            hypothesis: request.hypothesis,
            duration_secs: request.duration_secs,
            baseline,
            status: CoverageExperimentStatus::Prepared,
            result: None,
            cancellation_reason: None,
            created_at: now,
            updated_at: now,
            ended_at: None,
        };
        store.insert_coverage_experiment(&record).await?;
        Ok(record.into())
    }
    /// Read immutable retained evidence after verifying the selected owner.
    #[tracing::instrument(skip_all)]
    pub async fn coverage_experiment(
        &self,
        id: Uuid,
        scope: CoverageExperimentScope,
    ) -> Result<CoverageExperimentView, CoverageExperimentError> {
        self.validate_coverage_experiment_scope(id, scope, None)
            .await?;
        Ok(self
            .experiment_store()?
            .coverage_experiment(id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(C::NotFound))?
            .into())
    }
    /// List retained attempts without applying current execution policy.
    #[tracing::instrument(skip_all)]
    pub async fn list_coverage_experiments(
        &self,
        request: ListCoverageExperimentsRequest,
    ) -> Result<CoverageExperimentPage, CoverageExperimentError> {
        let store = self.experiment_store()?;
        if !(1..=100).contains(&request.limit) {
            return Err(CoverageExperimentError::field(C::InvalidRequest, "limit"));
        }
        let project = validate_coverage_experiment_project(&request.project)?;
        if let Some(cursor) = request.before {
            let retained = store
                .coverage_experiment(cursor.id)
                .await?
                .ok_or_else(|| CoverageExperimentError::field(C::InvalidRequest, "before"))?;
            if std::path::Path::new(&retained.project_root) != project
                || request.target_id.is_some_and(|id| id != retained.target_id)
                || retained.created_at != cursor.created_at
            {
                return Err(CoverageExperimentError::field(C::InvalidRequest, "before"));
            }
        }
        let page = store
            .list_coverage_experiments(
                project
                    .to_str()
                    .ok_or_else(|| CoverageExperimentError::new(C::InvalidProjectPath))?,
                request.target_id,
                request.limit,
                request
                    .before
                    .map(|cursor| hf_storage::CoverageExperimentCursor {
                        created_at: cursor.created_at,
                        id: cursor.id,
                    }),
            )
            .await?;
        Ok(CoverageExperimentPage {
            schema_version: 1,
            items: page.items.into_iter().map(Into::into).collect(),
            next_cursor: page.next_cursor.map(|cursor| CoverageExperimentCursor {
                created_at: cursor.created_at,
                id: cursor.id,
            }),
        })
    }
}
async fn eligible_snapshot(
    store: &Store,
    id: Uuid,
    baseline: bool,
) -> Result<CoverageExperimentRunEvidenceV1, CoverageExperimentError> {
    let run = store
        .get_run(id)
        .await?
        .ok_or_else(|| CoverageExperimentError::new(C::NotFound))?;
    if run.kind != RunKind::Campaign
        || !matches!(
            run.status,
            RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
        )
    {
        return Err(CoverageExperimentError::new(if baseline {
            C::InvalidBaseline
        } else {
            C::InvalidResult
        }));
    }
    Ok(store.coverage_experiment_run_evidence(id).await?)
}

impl ServiceContainer {
    /// Attach one compatible terminal campaign, or return the original exact terminal retry.
    #[tracing::instrument(skip_all)]
    pub async fn complete_coverage_experiment(
        &self,
        id: Uuid,
        request: CompleteCoverageExperimentRequest,
    ) -> Result<CoverageExperimentView, CoverageExperimentError> {
        self.validate_coverage_experiment_scope(id, request.scope.clone(), None)
            .await?;
        let store = self.experiment_store()?;
        let record = store
            .coverage_experiment(id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(C::NotFound))?;
        if record.status != CoverageExperimentStatus::Prepared {
            if record.status == CoverageExperimentStatus::Completed
                && record
                    .result
                    .as_ref()
                    .is_some_and(|result| result.run.run_id == request.result_run_id)
            {
                return Ok(record.into());
            }
            return Err(StorageError::CoverageExperimentConflict { id }.into());
        }
        self.validate_coverage_experiment_scope(id, request.scope, Some(request.result_run_id))
            .await?;
        let run = eligible_snapshot(store, request.result_run_id, false).await?;
        let now = Utc::now();
        if now < record.created_at
            || run.run_id == record.baseline_run_id
            || run.started_at <= record.created_at
            || run.ended_at > now
        {
            return Err(CoverageExperimentError::new(C::InvalidChronology));
        }
        compare_setup(record.kind, &record.baseline, &run)?;
        let input_change =
            CoverageExperimentInputChange::from_snapshots(record.kind, &record.baseline, &run);
        let result = hf_storage::CoverageExperimentResultEvidenceV1 {
            schema_version: 1,
            build_comparison: CoverageExperimentBuildComparison::from_snapshots(
                &record.baseline,
                &run,
            ),
            edge_comparison: hf_storage::CoverageExperimentEdgeComparison::from_snapshots(
                &record.baseline,
                &run,
            )?,
            limitations: limitations(&record.baseline, &run, input_change),
            target_entry: CoverageExperimentTargetEntry::Unavailable {
                reason_code: CoverageExperimentTargetEntryReason::NoExactRunScopedFunctionCoverage,
            },
            input_change,
            run,
        };
        Ok(store
            .complete_coverage_experiment(id, &result, now)
            .await?
            .into())
    }
    /// Cancel only this idle investigation; no campaign is stopped.
    #[tracing::instrument(skip_all)]
    pub async fn cancel_coverage_experiment(
        &self,
        id: Uuid,
        request: CancelCoverageExperimentRequest,
    ) -> Result<CoverageExperimentView, CoverageExperimentError> {
        self.validate_coverage_experiment_scope(id, request.scope, None)
            .await?;
        if !valid_text(&request.reason, 4096, true) {
            return Err(CoverageExperimentError::field(C::InvalidRequest, "reason"));
        }
        let store = self.experiment_store()?;
        let record = store
            .coverage_experiment(id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(C::NotFound))?;
        if record.status != CoverageExperimentStatus::Prepared {
            if record.status == CoverageExperimentStatus::Cancelled
                && record.cancellation_reason.as_deref() == Some(request.reason.as_str())
            {
                return Ok(record.into());
            }
            return Err(StorageError::CoverageExperimentConflict { id }.into());
        }
        Ok(store
            .cancel_coverage_experiment(id, &request.reason, Utc::now())
            .await?
            .into())
    }
}
fn compare_setup(
    kind: CoverageExperimentKind,
    baseline: &CoverageExperimentRunEvidenceV1,
    result: &CoverageExperimentRunEvidenceV1,
) -> Result<(), CoverageExperimentError> {
    for (equal, code, field) in [
        (
            baseline.project_root == result.project_root,
            C::DifferentProject,
            "project_root",
        ),
        (
            baseline.target_id == result.target_id,
            C::DifferentTarget,
            "target_id",
        ),
        (
            baseline.engine == result.engine,
            C::DifferentEngine,
            "engine",
        ),
        (
            baseline.source_rev == result.source_rev,
            C::DifferentSource,
            "source_rev",
        ),
        (
            baseline.sandbox_rev == result.sandbox_rev,
            C::DifferentSandbox,
            "sandbox_rev",
        ),
        (
            baseline.sanitizer == result.sanitizer,
            C::DifferentRunSettings,
            "sanitizer",
        ),
        (
            baseline.duration_secs == result.duration_secs,
            C::DifferentRunSettings,
            "duration_secs",
        ),
        (
            baseline.max_mem_mb == result.max_mem_mb,
            C::DifferentRunSettings,
            "max_mem_mb",
        ),
        (
            baseline.max_cpus == result.max_cpus,
            C::DifferentRunSettings,
            "max_cpus",
        ),
        (
            baseline.engine_env == result.engine_env,
            C::DifferentRunSettings,
            "engine_env",
        ),
        (
            baseline.engine_args == result.engine_args,
            C::DifferentRunSettings,
            "engine_args",
        ),
        (
            baseline.seed == result.seed,
            C::DifferentRunSettings,
            "seed",
        ),
    ] {
        if !equal {
            return Err(CoverageExperimentError::field(code, field));
        }
    }
    if let (Some(a), Some(b)) = (&baseline.build_inputs, &result.build_inputs) {
        for (equal, field) in [
            (a.profile_sha256 == b.profile_sha256, "profile_sha256"),
            (
                a.compile_database_sha256 == b.compile_database_sha256,
                "compile_database_sha256",
            ),
            (
                a.compile_flags_sha256 == b.compile_flags_sha256,
                "compile_flags_sha256",
            ),
            (a.sandbox_image_id == b.sandbox_image_id, "sandbox_image_id"),
            (
                a.build_input_sha256 == b.build_input_sha256,
                "build_input_sha256",
            ),
        ] {
            if !equal {
                return Err(CoverageExperimentError::field(
                    C::DifferentBuildInputs,
                    field,
                ));
            }
        }
    }
    match kind {
        CoverageExperimentKind::GrowCorpus => {
            if baseline.harness_rev != result.harness_rev {
                return Err(CoverageExperimentError::field(
                    C::DifferentHarness,
                    "harness_rev",
                ));
            }
            if baseline.binary_rev != result.binary_rev {
                return Err(CoverageExperimentError::field(
                    C::DifferentHarness,
                    "binary_rev",
                ));
            }
        }
        CoverageExperimentKind::RefineHarness => {
            if baseline.corpus_rev != result.corpus_rev {
                return Err(CoverageExperimentError::field(
                    C::DifferentCorpus,
                    "corpus_rev",
                ));
            }
            if baseline.harness_rev == result.harness_rev
                && baseline.binary_rev != result.binary_rev
            {
                return Err(CoverageExperimentError::field(
                    C::UnexpectedBinaryChange,
                    "binary_rev",
                ));
            }
        }
    }
    Ok(())
}
fn limitations(
    a: &CoverageExperimentRunEvidenceV1,
    b: &CoverageExperimentRunEvidenceV1,
    input: CoverageExperimentInputChange,
) -> Vec<CoverageExperimentLimitation> {
    use CoverageExperimentLimitation as L;
    // Lexical code order is the durable representation; all independent limitations survive.
    [
        (true, L::AggregateEdgesNotFunctionEntry),
        (a.status == RunStatus::Cancelled, L::BaselineCancelled),
        (a.edges.is_none(), L::BaselineEdgesUnavailable),
        (a.status == RunStatus::Failed, L::BaselineFailed),
        (
            a.seed.is_some() && a.engine == hf_core::engine::EngineKind::Honggfuzz,
            L::EngineIgnoresRetainedSeed,
        ),
        (
            input == CoverageExperimentInputChange::HarnessSourceChanged,
            L::HarnessInstrumentationMayDiffer,
        ),
        (
            a.build_inputs.is_none() || b.build_inputs.is_none(),
            L::LegacyBuildInputsUnavailable,
        ),
        (
            input == CoverageExperimentInputChange::NoObservedInputChange,
            L::NoObservedInputChange,
        ),
        (a.seed.is_none(), L::RandomSeedUnrecorded),
        (b.status == RunStatus::Cancelled, L::ResultCancelled),
        (b.edges.is_none(), L::ResultEdgesUnavailable),
        (b.status == RunStatus::Failed, L::ResultFailed),
    ]
    .into_iter()
    .filter_map(|(present, limitation)| present.then_some(limitation))
    .collect()
}
