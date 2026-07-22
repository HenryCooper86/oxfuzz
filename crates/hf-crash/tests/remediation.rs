#![cfg(feature = "remediation-handoff")]

use hf_crash::remediation::{
    RemediationBinding, RemediationError, RemediationHandoff, RemediationStatus,
    SandboxVerificationEvidence,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn patch() -> String {
    "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-unsafe();\n+safe();\n".to_owned()
}

fn binding() -> RemediationBinding {
    let patch = patch();
    RemediationBinding {
        finding_id: Uuid::from_u128(1),
        source_revision_sha256: digest('a'),
        patch_sha256: hex::encode(Sha256::digest(patch.as_bytes())),
        patch,
        reproducer_sha256: digest('b'),
        harness_sha256: digest('c'),
        binary_sha256: digest('d'),
        evidence_manifest_sha256: digest('e'),
    }
}

fn verification(binding: &RemediationBinding) -> SandboxVerificationEvidence {
    SandboxVerificationEvidence {
        verification_id: Uuid::from_u128(2),
        source_revision_sha256: binding.source_revision_sha256.clone(),
        patch_sha256: binding.patch_sha256.clone(),
        reproducer_sha256: binding.reproducer_sha256.clone(),
        harness_sha256: binding.harness_sha256.clone(),
        binary_sha256: binding.binary_sha256.clone(),
        sandbox_image_sha256: digest('f'),
        completed: true,
        original_reproduced: true,
        patched_reproduced: false,
        regression_cases: 4,
        regression_failures: 0,
    }
}

#[test]
fn complete_matching_sandbox_evidence_marks_the_handoff_verified() {
    let mut handoff = RemediationHandoff::draft(binding()).expect("valid draft");
    handoff
        .record_verification(verification(&handoff.binding.clone()))
        .expect("matching evidence");

    assert_eq!(handoff.status, RemediationStatus::Verified);
    handoff
        .verify_claim()
        .expect("verified claim is internally valid");
}

#[test]
fn mismatched_evidence_cannot_change_draft_status() {
    let mut handoff = RemediationHandoff::draft(binding()).expect("valid draft");
    let mut evidence = verification(&handoff.binding);
    evidence.patch_sha256 = digest('9');

    assert_eq!(
        handoff.record_verification(evidence),
        Err(RemediationError::EvidenceMismatch)
    );
    assert_eq!(handoff.status, RemediationStatus::Draft);
    assert!(handoff.verification.is_none());
}

#[test]
fn incomplete_or_failing_regression_evidence_never_verifies() {
    let mut inconclusive = RemediationHandoff::draft(binding()).unwrap();
    let mut incomplete = verification(&inconclusive.binding);
    incomplete.completed = false;
    inconclusive.record_verification(incomplete).unwrap();
    assert_eq!(inconclusive.status, RemediationStatus::Inconclusive);
    assert_eq!(
        inconclusive.verify_claim(),
        Err(RemediationError::NotVerified)
    );

    let mut rejected = RemediationHandoff::draft(binding()).unwrap();
    let mut failed = verification(&rejected.binding);
    failed.regression_failures = 1;
    rejected.record_verification(failed).unwrap();
    assert_eq!(rejected.status, RemediationStatus::Rejected);
    assert_eq!(rejected.verify_claim(), Err(RemediationError::NotVerified));
}

#[test]
fn patch_digest_and_unified_diff_shape_are_validated() {
    let mut wrong_digest = binding();
    wrong_digest.patch_sha256 = digest('1');
    assert_eq!(
        RemediationHandoff::draft(wrong_digest),
        Err(RemediationError::PatchDigestMismatch)
    );

    let mut prose = binding();
    prose.patch = "check the length first".to_owned();
    prose.patch_sha256 = hex::encode(Sha256::digest(prose.patch.as_bytes()));
    assert_eq!(
        RemediationHandoff::draft(prose),
        Err(RemediationError::InvalidPatch)
    );
}
