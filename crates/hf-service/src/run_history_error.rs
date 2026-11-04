//! Typed run-history failures shared by run-history consumers.
use hf_core::error::ClassifiedError;
use hf_storage::StorageError;

/// Run-history errors preserve the original failure classification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum RunHistoryError {
    /// A failure with its original classification and message.
    #[error(transparent)]
    Classified(#[from] ClassifiedError),
}
impl From<StorageError> for RunHistoryError {
    fn from(error: StorageError) -> Self {
        Self::Classified(error.into())
    }
}
impl RunHistoryError {
    pub(crate) fn deleting(error: &StorageError) -> Self {
        Self::Classified(ClassifiedError::Internal(format!("delete run: {error}")))
    }
    pub(crate) fn clearing(error: &StorageError) -> Self {
        Self::Classified(ClassifiedError::Internal(format!("clear runs: {error}")))
    }
}
