//! Project scanner stub.

use hf_core::target::{TargetInventory, TargetLanguage};
use std::path::Path;

/// Discover fuzzing targets in a project.
///
/// # Errors
/// Returns `ClassifiedError` if the project cannot be read.
pub async fn discover(
    project_root: &Path,
    _lang: TargetLanguage,
) -> Result<TargetInventory, hf_core::error::ClassifiedError> {
    Ok(TargetInventory {
        project_root: project_root.to_path_buf(),
        candidates: Vec::new(),
    })
}
