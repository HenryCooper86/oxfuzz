//! Recoverable completion of the uniquely associated guided campaign.
use super::{
    CompleteCoverageExperimentRequest, CoverageExperimentError,
    CoverageExperimentErrorCode as Code, CoverageExperimentExecutionView, CoverageExperimentScope,
    CoverageExperimentStatus, CoverageExperimentView,
};
use crate::{ReplayReview, ServiceContainer};
use uuid::Uuid;

impl ServiceContainer {
    pub(crate) async fn reconcile_coverage_experiment(
        &self,
        id: Uuid,
    ) -> Result<Option<&'static str>, CoverageExperimentError> {
        let store = self.experiment_store()?;
        let record = store
            .coverage_experiment(id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(Code::NotFound))?;
        let Some(execution) = store.coverage_experiment_execution(id).await? else {
            return Ok(None);
        };
        let run = store
            .get_run(execution.run_id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(Code::InvalidResult))?;
        if record.status != CoverageExperimentStatus::Prepared || run.ended_at.is_none() {
            return Ok(None);
        }
        match self
            .complete_coverage_experiment(
                id,
                CompleteCoverageExperimentRequest {
                    scope: CoverageExperimentScope {
                        project: record.project_root.into(),
                        target_id: record.target_id,
                    },
                    result_run_id: execution.run_id,
                },
            )
            .await
        {
            Ok(_) => Ok(None),
            Err(error) if error.code == "storage_error" || error.code == "storage_unavailable" => {
                Err(error)
            }
            Err(error) => Ok(Some(error.code)),
        }
    }

    pub(super) async fn coverage_experiment_execution_view(
        &self,
        id: Uuid,
    ) -> Result<CoverageExperimentView, CoverageExperimentError> {
        let comparison_error = self.reconcile_coverage_experiment(id).await?;
        let store = self.experiment_store()?;
        let view: CoverageExperimentView = store
            .coverage_experiment(id)
            .await?
            .ok_or_else(|| CoverageExperimentError::new(Code::NotFound))?
            .into();
        self.decorate_experiment_execution(view, comparison_error)
            .await
    }

    pub(super) async fn decorate_experiment_execution(
        &self,
        mut view: CoverageExperimentView,
        comparison_error: Option<&'static str>,
    ) -> Result<CoverageExperimentView, CoverageExperimentError> {
        let id = view.id;
        let store = self.experiment_store()?;
        if let Some(execution) = store.coverage_experiment_execution(id).await? {
            let review = validated_review(&execution.review_json, id, view.baseline_run_id)?;
            let digest = review
                .current_input_sha256
                .ok_or_else(|| CoverageExperimentError::new(Code::StorageError))?;
            let run = store
                .get_run(execution.run_id)
                .await?
                .ok_or_else(|| CoverageExperimentError::new(Code::InvalidResult))?;
            view.execution = Some(CoverageExperimentExecutionView {
                run_id: execution.run_id,
                status: run.status,
                comparison_error,
                reviewed_input_sha256: digest,
            });
        }
        Ok(view)
    }
}

pub(super) fn validated_review(
    text: &str,
    id: Uuid,
    baseline_run_id: Uuid,
) -> Result<ReplayReview, CoverageExperimentError> {
    let review: ReplayReview =
        serde_json::from_str(text).map_err(|_| CoverageExperimentError::new(Code::StorageError))?;
    if review.experiment_id != Some(id) || review.run_id != baseline_run_id {
        return Err(CoverageExperimentError::new(Code::StorageError));
    }
    Ok(review)
}
