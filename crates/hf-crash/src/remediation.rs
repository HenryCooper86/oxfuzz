//! Versioned remediation handoff evidence and verification state machine.
//!
//! These types derive a remediation status from exact sandbox evidence. They
//! perform no patch application, build, replay, or filesystem operation.

use std::path::{Component, Path};

use hf_core::engine::EngineKind;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Current remediation evidence version.
pub const REMEDIATION_SCHEMA_VERSION: u32 = 3;
/// Current verification-specification version.
pub const REMEDIATION_VERIFICATION_SPEC_VERSION: u32 = 1;
/// Maximum inline unified-diff size.
pub const MAX_PATCH_BYTES: usize = 1_048_576;

/// Exact limits and engine settings approved for one verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationVerificationSpec {
    pub schema_version: u32,
    pub engine: EngineKind,
    pub replay_timeout_secs: u64,
    pub max_regression_cases: usize,
    pub follow_up_fuzz_seconds: u64,
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub seed: u64,
}

impl RemediationVerificationSpec {
    /// Return the canonical SHA-256 of this specification.
    ///
    /// # Errors
    /// Returns an error when the specification is invalid or cannot serialize.
    pub fn sha256(&self) -> Result<String, RemediationError> {
        validate_verification_spec(self)?;
        serde_json::to_vec(self)
            .map(|bytes| hex::encode(Sha256::digest(bytes)))
            .map_err(|_| RemediationError::Serialization)
    }
}

/// Immutable finding, patch, artifact, and verification identities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationBinding {
    pub finding_id: Uuid,
    pub run_id: Uuid,
    pub source_revision_sha256: String,
    pub patch_sha256: String,
    pub patch: String,
    pub reproducer_sha256: String,
    pub harness_sha256: String,
    pub original_binary_sha256: String,
    pub sandbox_image_sha256: String,
    pub evidence_manifest_sha256: String,
    pub regression_corpus_sha256: String,
    pub verification_spec_sha256: String,
    pub verification_spec: RemediationVerificationSpec,
}

/// Outcome of one required verification stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStageStatus {
    Passed,
    Failed,
    Inconclusive,
    Skipped,
}

/// Bounded result for one required verification stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationStageEvidence {
    pub status: VerificationStageStatus,
    pub detail_code: String,
    pub cases: usize,
    pub failures: usize,
    pub findings: usize,
}

/// Service-owned result of the complete sandbox verification attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxVerificationEvidence {
    pub verification_id: Uuid,
    pub source_revision_sha256: String,
    pub patch_sha256: String,
    pub reproducer_sha256: String,
    pub harness_sha256: String,
    pub original_binary_sha256: String,
    pub patched_binary_sha256: Option<String>,
    pub sandbox_image_sha256: String,
    pub regression_corpus_sha256: String,
    pub verification_spec_sha256: String,
    pub original_replay: VerificationStageEvidence,
    pub patch_build: VerificationStageEvidence,
    pub patched_replay: VerificationStageEvidence,
    pub regression: VerificationStageEvidence,
    pub follow_up_fuzz: VerificationStageEvidence,
}

/// Review state of a remediation handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    Draft,
    Verified,
    Inconclusive,
    Rejected,
}

/// Versioned remediation handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemediationHandoff {
    pub schema_version: u32,
    pub binding: RemediationBinding,
    pub status: RemediationStatus,
    pub verification: Option<SandboxVerificationEvidence>,
}

/// Invalid remediation evidence or state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RemediationError {
    #[error("unsupported remediation schema")]
    UnsupportedSchema,
    #[error("remediation contains a malformed SHA-256 digest")]
    InvalidDigest,
    #[error("remediation patch must be a bounded unified diff")]
    InvalidPatch,
    #[error("remediation patch contains an unsafe path")]
    InvalidPatchPath,
    #[error("remediation patch digest mismatch")]
    PatchDigestMismatch,
    #[error("remediation verification specification is invalid")]
    InvalidVerificationSpec,
    #[error("remediation verification specification digest mismatch")]
    VerificationSpecDigestMismatch,
    #[error("sandbox verification evidence does not match the remediation binding")]
    EvidenceMismatch,
    #[error("sandbox verification evidence is malformed")]
    InvalidEvidence,
    #[error("remediation evidence could not be serialized")]
    Serialization,
    #[error("remediation handoff is not verified")]
    NotVerified,
}

impl RemediationHandoff {
    /// Create a visibly unverified handoff after validating immutable inputs.
    ///
    /// # Errors
    /// Returns an error for malformed digests, patch content, paths, or limits.
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
    /// Returns an error without changing the handoff when evidence is invalid or
    /// any immutable identity differs.
    pub fn record_verification(
        &mut self,
        evidence: SandboxVerificationEvidence,
    ) -> Result<(), RemediationError> {
        self.validate_schema()?;
        validate_evidence(&evidence)?;
        if !matches_binding(&self.binding, &evidence) {
            return Err(RemediationError::EvidenceMismatch);
        }
        self.status = verification_status(&evidence);
        self.verification = Some(evidence);
        Ok(())
    }

    /// Revalidate that a retained verified claim still meets every condition.
    ///
    /// # Errors
    /// Returns `NotVerified` for any non-verified result and an identity error
    /// for mutated evidence.
    pub fn verify_claim(&self) -> Result<(), RemediationError> {
        self.validate_schema()?;
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

    fn validate_schema(&self) -> Result<(), RemediationError> {
        if self.schema_version == REMEDIATION_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(RemediationError::UnsupportedSchema)
        }
    }
}

fn validate_binding(binding: &RemediationBinding) -> Result<(), RemediationError> {
    if [
        binding.source_revision_sha256.as_str(),
        binding.patch_sha256.as_str(),
        binding.reproducer_sha256.as_str(),
        binding.harness_sha256.as_str(),
        binding.original_binary_sha256.as_str(),
        binding.sandbox_image_sha256.as_str(),
        binding.evidence_manifest_sha256.as_str(),
        binding.regression_corpus_sha256.as_str(),
        binding.verification_spec_sha256.as_str(),
    ]
    .iter()
    .any(|value| !is_sha256(value))
    {
        return Err(RemediationError::InvalidDigest);
    }
    validate_patch(&binding.patch)?;
    if hex::encode(Sha256::digest(binding.patch.as_bytes())) != binding.patch_sha256 {
        return Err(RemediationError::PatchDigestMismatch);
    }
    if binding.verification_spec.sha256()? != binding.verification_spec_sha256 {
        return Err(RemediationError::VerificationSpecDigestMismatch);
    }
    Ok(())
}

fn validate_patch(patch: &str) -> Result<(), RemediationError> {
    if patch.is_empty() || patch.len() > MAX_PATCH_BYTES || patch.contains('\0') {
        return Err(RemediationError::InvalidPatch);
    }
    let old_paths: Vec<&str> = patch
        .lines()
        .filter_map(|line| line.strip_prefix("--- "))
        .collect();
    let new_paths: Vec<&str> = patch
        .lines()
        .filter_map(|line| line.strip_prefix("+++ "))
        .collect();
    if old_paths.is_empty() || old_paths.len() != new_paths.len() {
        return Err(RemediationError::InvalidPatch);
    }
    for path in old_paths.into_iter().chain(new_paths) {
        validate_patch_path(path)?;
    }
    Ok(())
}

fn validate_patch_path(raw: &str) -> Result<(), RemediationError> {
    let path = raw.split('\t').next().unwrap_or_default();
    if path == "/dev/null" {
        return Ok(());
    }
    if path.is_empty()
        || path.contains('\\')
        || path.chars().any(char::is_whitespace)
        || Path::new(path).is_absolute()
    {
        return Err(RemediationError::InvalidPatchPath);
    }
    let relative = path
        .strip_prefix("a/")
        .or_else(|| path.strip_prefix("b/"))
        .unwrap_or(path);
    let denied = [".git", "target", "build", "out", "runs", "fuzz_workspace"];
    let mut saw_component = false;
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(name) => {
                saw_component = true;
                if denied.iter().any(|denied| name == *denied) {
                    return Err(RemediationError::InvalidPatchPath);
                }
            }
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(RemediationError::InvalidPatchPath);
            }
        }
    }
    if saw_component {
        Ok(())
    } else {
        Err(RemediationError::InvalidPatchPath)
    }
}

fn validate_verification_spec(spec: &RemediationVerificationSpec) -> Result<(), RemediationError> {
    if spec.schema_version != REMEDIATION_VERIFICATION_SPEC_VERSION
        || spec.engine == EngineKind::Syzkaller
        || !(1..=300).contains(&spec.replay_timeout_secs)
        || !(1..=4_096).contains(&spec.max_regression_cases)
        || !(1..=3_600).contains(&spec.follow_up_fuzz_seconds)
        || !(1..=1_048_576).contains(&spec.max_mem_mb)
        || !(1..=64).contains(&spec.max_cpus)
    {
        return Err(RemediationError::InvalidVerificationSpec);
    }
    Ok(())
}

fn validate_evidence(evidence: &SandboxVerificationEvidence) -> Result<(), RemediationError> {
    if [
        evidence.source_revision_sha256.as_str(),
        evidence.patch_sha256.as_str(),
        evidence.reproducer_sha256.as_str(),
        evidence.harness_sha256.as_str(),
        evidence.original_binary_sha256.as_str(),
        evidence.sandbox_image_sha256.as_str(),
        evidence.regression_corpus_sha256.as_str(),
        evidence.verification_spec_sha256.as_str(),
    ]
    .iter()
    .any(|value| !is_sha256(value))
        || evidence
            .patched_binary_sha256
            .as_deref()
            .is_some_and(|value| !is_sha256(value))
    {
        return Err(RemediationError::InvalidDigest);
    }
    for stage in evidence.stages() {
        if stage.detail_code.is_empty()
            || stage.detail_code.len() > 128
            || stage.failures > stage.cases
            || (stage.status == VerificationStageStatus::Passed
                && (stage.failures > 0 || stage.findings > 0))
        {
            return Err(RemediationError::InvalidEvidence);
        }
    }
    if evidence.patch_build.status == VerificationStageStatus::Passed
        && evidence.patched_binary_sha256.is_none()
    {
        return Err(RemediationError::InvalidEvidence);
    }
    if matches!(
        evidence.regression.status,
        VerificationStageStatus::Passed | VerificationStageStatus::Failed
    ) && evidence.regression.cases == 0
    {
        return Err(RemediationError::InvalidEvidence);
    }
    Ok(())
}

impl SandboxVerificationEvidence {
    fn stages(&self) -> [&VerificationStageEvidence; 5] {
        [
            &self.original_replay,
            &self.patch_build,
            &self.patched_replay,
            &self.regression,
            &self.follow_up_fuzz,
        ]
    }
}

fn matches_binding(binding: &RemediationBinding, evidence: &SandboxVerificationEvidence) -> bool {
    binding.source_revision_sha256 == evidence.source_revision_sha256
        && binding.patch_sha256 == evidence.patch_sha256
        && binding.reproducer_sha256 == evidence.reproducer_sha256
        && binding.harness_sha256 == evidence.harness_sha256
        && binding.original_binary_sha256 == evidence.original_binary_sha256
        && binding.sandbox_image_sha256 == evidence.sandbox_image_sha256
        && binding.regression_corpus_sha256 == evidence.regression_corpus_sha256
        && binding.verification_spec_sha256 == evidence.verification_spec_sha256
}

fn verification_status(evidence: &SandboxVerificationEvidence) -> RemediationStatus {
    let stages = evidence.stages();
    if stages
        .iter()
        .any(|stage| stage.status == VerificationStageStatus::Inconclusive)
    {
        RemediationStatus::Inconclusive
    } else if stages
        .iter()
        .any(|stage| stage.status == VerificationStageStatus::Failed)
    {
        RemediationStatus::Rejected
    } else if stages
        .iter()
        .all(|stage| stage.status == VerificationStageStatus::Passed)
    {
        RemediationStatus::Verified
    } else {
        RemediationStatus::Inconclusive
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
