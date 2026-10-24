//! Experiment-specific replay review, input verification and atomic reservation.
#[cfg(feature = "coverage-experiments")]
use super::{workspace_dir, ReplayInputs, ReplayReview, RunArtifacts, RunLaunch, ServiceContainer};
use super::{ClassifiedError, FuzzRunConfig, ReplayProvenance, RunRecord, Uuid};
use hf_storage::Store;

pub(super) async fn assign_replay_settings(
    store: &Store,
    run_id: Uuid,
    replay: Option<&ReplayProvenance>,
    config: &mut FuzzRunConfig,
) -> Result<(), ClassifiedError> {
    let Some(provenance) = replay else {
        config
            .seed
            .get_or_insert_with(|| hf_engine::seed::derive_run_seed(run_id));
        return Ok(());
    };
    config.seed = Some(provenance.seed);
    config.replay_of = Some(provenance.original_run_id);
    if provenance.experiment_review.is_none() {
        return Ok(());
    }
    let retained = baseline_config(store, provenance.original_run_id).await?;
    config.extra_args = retained.extra_args;
    config.env = retained.env;
    config.input_timeout = retained.input_timeout;
    config.cmplog = retained.cmplog;
    Ok(())
}

async fn baseline_config(store: &Store, id: Uuid) -> Result<FuzzRunConfig, ClassifiedError> {
    store
        .get_run(id)
        .await?
        .ok_or_else(|| ClassifiedError::Validation("experiment baseline disappeared".into()))?
        .config
        .ok_or_else(|| {
            ClassifiedError::Validation("experiment baseline configuration disappeared".into())
        })
}

#[cfg(feature = "coverage-experiments")]
pub(super) async fn configure_launch(
    service: &ServiceContainer,
    id: Uuid,
    launch: &mut RunLaunch,
) -> Result<(), ClassifiedError> {
    let store = service
        .store
        .as_ref()
        .ok_or_else(|| ClassifiedError::Storage("experiment storage is unavailable".into()))?;
    let config = baseline_config(store, id).await?;
    launch.resolved.cmplog = config.cmplog;
    launch.resolved.sanitizer = Some(config.sanitizer);
    Ok(())
}

/// Own the guided attempt before its durable association becomes visible.
pub(super) fn acquire_owner(
    store: &Store,
    id: Uuid,
    replay: Option<&ReplayProvenance>,
) -> Result<Option<std::fs::File>, ClassifiedError> {
    if replay
        .and_then(|value| value.experiment_review.as_ref())
        .is_none()
    {
        return Ok(None);
    }
    crate::recovery::guided::try_acquire(store, id)?
        .map(Some)
        .ok_or_else(|| ClassifiedError::Internal("guided run identifier is already owned".into()))
}

pub(super) async fn reserve_run(
    store: &Store,
    record: &RunRecord,
    replay: Option<&ReplayProvenance>,
) -> Result<(), ClassifiedError> {
    if let Some(review) = replay.and_then(|value| value.experiment_review.as_ref()) {
        let id = review.experiment_id.ok_or_else(|| {
            ClassifiedError::Validation("experiment review is missing its ID".into())
        })?;
        let json = serde_json::to_string(review)
            .map_err(|error| ClassifiedError::Internal(error.to_string()))?;
        store
            .insert_coverage_experiment_run(id, record, &json)
            .await?;
    } else {
        store.insert_run(record).await?;
    }
    Ok(())
}

#[cfg(feature = "coverage-experiments")]
pub(super) fn verify_inputs(
    replay: Option<&ReplayProvenance>,
    artifacts: &RunArtifacts,
    sandbox_image: &hf_core::runtime::ImmutableImageReference,
    config: &FuzzRunConfig,
) -> Result<(), ClassifiedError> {
    if let Some(review) = replay.and_then(|value| value.experiment_review.as_ref()) {
        let digest = super::super::retained_inputs::review_digest(
            &artifacts.input_host.join("workspace"),
            &artifacts.initial_corpus_host,
            &format!(
                "{}{}",
                super::super::EXACT_DOCKER_IMAGE_REV_PREFIX,
                sandbox_image.sha256()
            ),
            config,
        )?;
        if review.current_input_sha256.as_deref() != Some(&digest) {
            if let Some(root) = artifacts.output_host.parent() {
                if let Err(error) = std::fs::remove_dir_all(root) {
                    tracing::warn!(%error, "failed to clean stale experiment input staging");
                }
            }
            return Err(ClassifiedError::Validation(
                "Experiment inputs changed. Review the experiment again before starting.".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "coverage-experiments")]
impl ServiceContainer {
    /// Review a prepared experiment's exact current inputs through normal replay admission.
    ///
    /// # Errors
    /// Rejects wrong scope, terminal/already launched proposals, unavailable inputs or policy denial.
    #[cfg(feature = "coverage-experiments")]
    pub async fn coverage_experiment_replay_review(
        &self,
        id: Uuid,
        scope: crate::coverage_experiments::CoverageExperimentScope,
    ) -> Result<ReplayReview, ClassifiedError> {
        let experiment = self
            .coverage_experiment(id, scope)
            .await
            .map_err(|error| ClassifiedError::Validation(error.code().into()))?;
        if experiment.status != hf_storage::CoverageExperimentStatus::Prepared
            || experiment.execution.is_some()
        {
            return Err(ClassifiedError::Validation(
                "experiment is terminal or already has an execution".into(),
            ));
        }
        let (mut review, _) = self
            .resolve_replay(experiment.baseline_run_id, ReplayInputs::Current)
            .await?;
        if review.duration_secs != experiment.duration_secs {
            return Err(ClassifiedError::Validation(
                "experiment budget differs from replay duration".into(),
            ));
        }
        let _operation = self.acquire_workspace_operation().await?;
        let _revision = self
            .acquire_target_revision(&review.project, &review.target)
            .await?;
        let qualified = self
            .campaign_harness(&review.project, &review.target, review.engine, None)
            .await?;
        let workspace = workspace_dir(&review.project, &review.target);
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Storage("experiment storage is unavailable".into()))?;
        let mut config = baseline_config(store, experiment.baseline_run_id).await?;
        config.harness_id = qualified.id;
        config.sanitizer = qualified.sanitizer;
        config.seed_corpus = Some(workspace.join("corpus"));
        config.replay_of = Some(experiment.baseline_run_id);
        config.resume = false;
        // Bind the digest to the same inputs the launch side will digest:
        // the mutator environment re-derived from the CURRENT harness record
        // and the currently resolved sandbox image (a baseline-run revision
        // here would never match after a mutator/image change, which is
        // exactly when a review must stay launchable).
        super::super::managed_mutator::rebind_review_mutator_env(&qualified, &mut config)?;
        let sandbox_image =
            super::super::staging::resolve_run_sandbox_image(self.runtime.as_ref()).await?;
        super::super::managed_mutator::verify_image(&qualified, Some(sandbox_image.reference()))?;
        review.current_input_sha256 = Some(super::super::retained_inputs::review_digest(
            &workspace,
            &workspace.join("corpus"),
            &format!(
                "{}{}",
                super::super::EXACT_DOCKER_IMAGE_REV_PREFIX,
                sandbox_image.sha256()
            ),
            &config,
        )?);
        review.experiment_id = Some(id);
        Ok(review)
    }
}
