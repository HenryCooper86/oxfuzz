//! Typed retained-evidence refusals shared by run-history consumers.
use hf_core::error::ClassifiedError;
use hf_storage::{CoverageExperimentRunRole, StorageError};
use uuid::Uuid;

/// Run-history errors preserve existing failures and exact experiment references.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RunHistoryError {
    /// Existing non-experiment failure, with its original classification and message.
    #[error(transparent)]
    Classified(#[from] ClassifiedError),
    /// Explicit project/knowledge cleanup owns removal of these references.
    #[error("run_retained_by_experiment: run {run_id}, experiment {experiment_id}, role {role:?}")]
    RunRetainedByExperiment {
        run_id: Uuid,
        experiment_id: Uuid,
        role: CoverageExperimentRunRole,
    },
}
impl From<StorageError> for RunHistoryError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::RunRetainedByExperiment {
                run_id,
                experiment_id,
                role,
            } => Self::RunRetainedByExperiment {
                run_id,
                experiment_id,
                role,
            },
            other => Self::Classified(other.into()),
        }
    }
}
impl RunHistoryError {
    pub(crate) fn deleting(error: StorageError) -> Self {
        match error {
            retained @ StorageError::RunRetainedByExperiment { .. } => retained.into(),
            other => Self::Classified(ClassifiedError::Internal(format!("delete run: {other}"))),
        }
    }
    pub(crate) fn clearing(error: StorageError) -> Self {
        match error {
            retained @ StorageError::RunRetainedByExperiment { .. } => retained.into(),
            other => Self::Classified(ClassifiedError::Internal(format!("clear runs: {other}"))),
        }
    }
}
