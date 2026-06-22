//! Harness generator stub.

use hf_core::engine::EngineKind;
use hf_core::harness::HarnessDraft;
use hf_core::target::TargetCandidate;

/// Draft a harness for a target.
///
/// # Errors
/// Returns `ClassifiedError` on LLM or validation failure.
pub async fn draft(
    _target: &TargetCandidate,
    _engine: EngineKind,
) -> Result<HarnessDraft, hf_core::error::ClassifiedError> {
    Err(hf_core::error::ClassifiedError::Harness(
        "harness draft: not implemented".to_owned(),
    ))
}
