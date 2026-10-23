//! Exact source ingress and campaign revision pinning for supplied harnesses.
use hf_core::{error::ClassifiedError, harness::Harness};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Hard ceiling for an operator-supplied UTF-8 harness source.
pub const MAX_PREPARED_HARNESS_SOURCE_BYTES: usize = 1024 * 1024;

/// Frozen source selected by the operator, independently of its authoring tool.
#[derive(Debug, Clone)]
pub struct PreparedHarnessSource {
    /// Exact UTF-8 source; no rewriting or repair is allowed.
    pub source: String,
    /// Expected lowercase SHA-256 of the exact source bytes.
    pub sha256: String,
}
impl PreparedHarnessSource {
    pub(super) fn validate(&self, target: Option<&str>) -> Result<(), ClassifiedError> {
        if target.is_none_or(|target| target.trim().is_empty()) {
            return Err(ClassifiedError::Validation(
                "prepared harness source requires an explicit target".into(),
            ));
        }
        if self.source.is_empty()
            || self.source.len() > MAX_PREPARED_HARNESS_SOURCE_BYTES
            || self.source.contains('\0')
        {
            return Err(ClassifiedError::Validation(
                "prepared harness source must contain 1–1048576 UTF-8 bytes without NUL".into(),
            ));
        }
        if self.sha256 != format!("{:x}", Sha256::digest(self.source.as_bytes())) {
            return Err(ClassifiedError::Validation(
                "prepared harness source SHA-256 does not match the supplied bytes".into(),
            ));
        }
        Ok(())
    }
}

tokio::task_local! {
    static PREPARED_EXECUTION: (Uuid, String);
}
pub(super) async fn with_harness<F: std::future::Future>(
    harness: &Harness,
    prepared: Option<&PreparedHarnessSource>,
    future: F,
) -> F::Output {
    match prepared {
        Some(source) => {
            PREPARED_EXECUTION
                .scope((harness.id, source.sha256.clone()), future)
                .await
        }
        None => future.await,
    }
}

pub(in crate::container) fn verify_prepared_harness(
    harness: &Harness,
) -> Result<(), ClassifiedError> {
    match PREPARED_EXECUTION.try_with(|(id, digest)| {
        if harness.id != *id
            || format!("{:x}", Sha256::digest(harness.source.as_bytes())) != *digest
        {
            return Err(ClassifiedError::Validation(
                "prepared harness revision changed before campaign dispatch".into(),
            ));
        }
        Ok(())
    }) {
        Ok(result) => result,
        // Ordinary campaign requests have no supplied-source execution scope.
        Err(_) => Ok(()),
    }
}
