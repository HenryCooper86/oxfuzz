//! Versioned remediation-handoff evidence and verification state machine.
//!
//! The contract records verification results but performs no patch application,
//! build, replay, or filesystem operation.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Current remediation contract version.
pub const REMEDIATION_SCHEMA_VERSION: u32 = 1;
/// Maximum inline unified-diff size.
pub const MAX_PATCH_BYTES: usize = 1_048_576;

/// Immutable finding, patch, and reproducer identities in a handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationBinding {
    /// Finding being remediated.
    pub finding_id: Uuid,
    /// Target source revision the candidate changes.
    pub source_revision_sha256: String,
    /// SHA-256 of `patch` bytes.
    pub patch_sha256: String,
    /// Bounded unified diff proposed for review.
    pub patch: String,
    /// Exact minimized reproducer identity.
    pub reproducer_sha256: String,
    /// Approved harness-source identity used for verification.
    pub harness_sha256: String,
    /// Staged binary identity used for verification.
    pub binary_sha256: String,
    /// Proof-carrying campaign evidence manifest identity.
    pub evidence_manifest_sha256: String,
}

/// Service-owned result of a bounded sandbox remediation check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxVerificationEvidence {
    /// Durable verification operation id.
    pub verification_id: Uuid,
    /// Exact source revision checked.
    pub source_revision_sha256: String,
    /// Exact patch checked.
    pub patch_sha256: String,
    /// Exact reproducer replayed.
    pub reproducer_sha256: String,
    /// Exact harness source checked.
    pub harness_sha256: String,
    /// Exact resulting binary checked.
    pub binary_sha256: String,
    /// Pinned sandbox image digest.
    pub sandbox_image_sha256: String,
    /// Whether the sandbox operation reached a normal terminal result.
    pub completed: bool,
    /// Whether the original build reproduced the finding.
    pub original_reproduced: bool,
    /// Whether the patched build still reproduced the finding.
    pub patched_reproduced: bool,
    /// Number of bounded regression cases executed.
    pub regression_cases: usize,
    /// Regression cases that failed.
    pub regression_failures: usize,
}

/// Review state of a remediation handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    /// Patch candidate exists but has no matching verification evidence.
    Draft,
    /// All exact evidence matched and both replay and regressions passed.
    Verified,
    /// Verification did not complete or could not establish the original fault.
    Inconclusive,
    /// The patched replay or regression set failed.
    Rejected,
}

/// Versioned remediation handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationHandoff {
    /// Serialization contract version.
    pub schema_version: u32,
    /// Immutable patch/finding binding.
    pub binding: RemediationBinding,
    /// Current evidence-derived state.
    pub status: RemediationStatus,
    /// Sandbox result, when one has been recorded.
    pub verification: Option<SandboxVerificationEvidence>,
}

/// Invalid remediation evidence or state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RemediationError {
    /// One of the required SHA-256 values is malformed.
    #[error("remediation contains a malformed SHA-256 digest")]
    InvalidDigest,
    /// Patch is empty, oversized, or not a unified diff.
    #[error("remediation patch must be a bounded unified diff")]
    InvalidPatch,
    /// Declared patch digest does not match its bytes.
    #[error("remediation patch digest mismatch")]
    PatchDigestMismatch,
    /// Sandbox evidence names different immutable inputs.
    #[error("sandbox verification evidence does not match the remediation binding")]
    EvidenceMismatch,
    /// The handoff does not carry a complete verified result.
    #[error("remediation handoff is not verified")]
    NotVerified,
}

impl RemediationHandoff {
    /// Create a visibly unverified handoff after validating immutable inputs.
    ///
    /// # Errors
    /// Returns [`RemediationError`] for malformed digests or patch content.
    pub fn draft(binding: RemediationBinding) -> Result<Self, RemediationError> {
        validate_binding(&binding)?;
        Ok(Self {
            schema_version: REMEDIATION_SCHEMA_VERSION,
            binding,
            status: RemediationStatus::Draft,
            verification: None,
        })
    }

    /// Record matching service-owned sandbox evidence and derive status.
    ///
    /// # Errors
    /// Returns [`RemediationError::EvidenceMismatch`] without changing the
    /// handoff when any immutable identity differs.
    pub fn record_verification(
        &mut self,
        evidence: SandboxVerificationEvidence,
    ) -> Result<(), RemediationError> {
        validate_evidence(&evidence)?;
        if !matches_binding(&self.binding, &evidence) {
            return Err(RemediationError::EvidenceMismatch);
        }
        self.status = verification_status(&evidence);
        self.verification = Some(evidence);
        Ok(())
    }

    /// Verify that a retained `verified` claim still satisfies every condition.
    ///
    /// # Errors
    /// Returns [`RemediationError::NotVerified`] for draft, inconclusive, or
    /// rejected evidence and [`RemediationError::EvidenceMismatch`] after an
    /// immutable-field mutation.
    pub fn verify_claim(&self) -> Result<(), RemediationError> {
        validate_binding(&self.binding)?;
        let evidence = self
            .verification
            .as_ref()
            .ok_or(RemediationError::NotVerified)?;
        validate_evidence(evidence)?;
        if !matches_binding(&self.binding, evidence) {
            return Err(RemediationError::EvidenceMismatch);
        }
        if self.status == RemediationStatus::Verified
            && verification_status(evidence) == RemediationStatus::Verified
        {
            Ok(())
        } else {
            Err(RemediationError::NotVerified)
        }
    }
}

fn validate_binding(binding: &RemediationBinding) -> Result<(), RemediationError> {
    if [
        binding.source_revision_sha256.as_str(),
        binding.patch_sha256.as_str(),
        binding.reproducer_sha256.as_str(),
        binding.harness_sha256.as_str(),
        binding.binary_sha256.as_str(),
        binding.evidence_manifest_sha256.as_str(),
    ]
    .iter()
    .any(|value| !is_sha256(value))
    {
        return Err(RemediationError::InvalidDigest);
    }
    if binding.patch.is_empty()
        || binding.patch.len() > MAX_PATCH_BYTES
        || !binding.patch.lines().any(|line| line.starts_with("--- "))
        || !binding.patch.lines().any(|line| line.starts_with("+++ "))
    {
        return Err(RemediationError::InvalidPatch);
    }
    if hex::encode(Sha256::digest(binding.patch.as_bytes())) != binding.patch_sha256 {
        return Err(RemediationError::PatchDigestMismatch);
    }
    Ok(())
}

fn validate_evidence(evidence: &SandboxVerificationEvidence) -> Result<(), RemediationError> {
    if [
        evidence.source_revision_sha256.as_str(),
        evidence.patch_sha256.as_str(),
        evidence.reproducer_sha256.as_str(),
        evidence.harness_sha256.as_str(),
        evidence.binary_sha256.as_str(),
        evidence.sandbox_image_sha256.as_str(),
    ]
    .iter()
    .any(|value| !is_sha256(value))
    {
        return Err(RemediationError::InvalidDigest);
    }
    Ok(())
}

fn matches_binding(binding: &RemediationBinding, evidence: &SandboxVerificationEvidence) -> bool {
    binding.source_revision_sha256 == evidence.source_revision_sha256
        && binding.patch_sha256 == evidence.patch_sha256
        && binding.reproducer_sha256 == evidence.reproducer_sha256
        && binding.harness_sha256 == evidence.harness_sha256
        && binding.binary_sha256 == evidence.binary_sha256
}

fn verification_status(evidence: &SandboxVerificationEvidence) -> RemediationStatus {
    if !evidence.completed || !evidence.original_reproduced || evidence.regression_cases == 0 {
        RemediationStatus::Inconclusive
    } else if evidence.patched_reproduced || evidence.regression_failures > 0 {
        RemediationStatus::Rejected
    } else {
        RemediationStatus::Verified
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
