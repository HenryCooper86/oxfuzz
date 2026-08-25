#![cfg(feature = "remediation-handoff")]

use hf_core::engine::EngineKind;
use hf_crash::remediation::{
    RemediationBinding, RemediationError, RemediationHandoff, RemediationStatus,
    RemediationVerificationSpec, SandboxVerificationEvidence, VerificationStageEvidence,
    VerificationStageStatus, REMEDIATION_SCHEMA_VERSION,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn digest(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn patch() -> String {
    "--- a/parser.c\n+++ b/parser.c\n@@ -1 +1 @@\n-unsafe();\n+safe();\n".to_owned()
}

fn spec() -> RemediationVerificationSpec {
    RemediationVerificationSpec {
        schema_version: 1,
        engine: EngineKind::LibFuzzer,
        replay_timeout_secs: 30,
        max_regression_cases: 256,
        follow_up_fuzz_seconds: 60,
        max_mem_mb: 2048,
        max_cpus: 1,
        seed: 42,
    }
}

fn binding() -> RemediationBinding {
    let patch = patch();
    let verification_spec = spec();
    RemediationBinding {
        finding_id: Uuid::from_u128(1),
        run_id: Uuid::from_u128(2),
        source_revision_sha256: digest('a'),
        patch_sha256: hex::encode(Sha256::digest(patch.as_bytes())),
        patch,
        reproducer_sha256: digest('b'),
        harness_sha256: digest('c'),
        original_binary_sha256: digest('d'),
        sandbox_image_sha256: digest('f'),
        evidence_manifest_sha256: digest('e'),
        regression_corpus_sha256: digest('1'),
        verification_spec_sha256: verification_spec.sha256().unwrap(),
        verification_spec,
    }
}

fn stage(
    status: VerificationStageStatus,
    cases: usize,
    failures: usize,
) -> VerificationStageEvidence {
    VerificationStageEvidence {
        status,
        detail_code: match status {
            VerificationStageStatus::Passed => "passed",
            VerificationStageStatus::Failed => "failed",
            VerificationStageStatus::Inconclusive => "inconclusive",
            VerificationStageStatus::Skipped => "skipped",
        }
        .to_owned(),
        cases,
        failures,
        findings: failures,
    }
}

fn verification(binding: &RemediationBinding) -> SandboxVerificationEvidence {
    SandboxVerificationEvidence {
        verification_id: Uuid::from_u128(3),
        source_revision_sha256: binding.source_revision_sha256.clone(),
        patch_sha256: binding.patch_sha256.clone(),
        reproducer_sha256: binding.reproducer_sha256.clone(),
        harness_sha256: binding.harness_sha256.clone(),
        original_binary_sha256: binding.original_binary_sha256.clone(),
        patched_binary_sha256: Some(digest('9')),
        sandbox_image_sha256: binding.sandbox_image_sha256.clone(),
        regression_corpus_sha256: binding.regression_corpus_sha256.clone(),
        verification_spec_sha256: binding.verification_spec_sha256.clone(),
        original_replay: stage(VerificationStageStatus::Passed, 1, 0),
        patch_build: stage(VerificationStageStatus::Passed, 1, 0),
        patched_replay: stage(VerificationStageStatus::Passed, 1, 0),
        regression: stage(VerificationStageStatus::Passed, 4, 0),
        follow_up_fuzz: stage(VerificationStageStatus::Passed, 1, 0),
    }
}

#[test]
fn all_matching_required_stages_mark_the_handoff_verified() {
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
fn exact_identity_mismatches_cannot_change_draft_status() {
    let handoff = RemediationHandoff::draft(binding()).expect("valid draft");
    let mismatches = [
        ("source", digest('8')),
        ("patch", digest('8')),
        ("reproducer", digest('8')),
        ("harness", digest('8')),
        ("original_binary", digest('8')),
        ("sandbox", digest('8')),
        ("regression_corpus", digest('8')),
        ("spec", digest('8')),
    ];

    for (field, value) in mismatches {
        let mut attempt = handoff.clone();
        let mut evidence = verification(&attempt.binding);
        match field {
            "source" => evidence.source_revision_sha256 = value,
            "patch" => evidence.patch_sha256 = value,
            "reproducer" => evidence.reproducer_sha256 = value,
            "harness" => evidence.harness_sha256 = value,
            "original_binary" => evidence.original_binary_sha256 = value,
            "sandbox" => evidence.sandbox_image_sha256 = value,
            "regression_corpus" => evidence.regression_corpus_sha256 = value,
            "spec" => evidence.verification_spec_sha256 = value,
            _ => unreachable!(),
        }
        assert_eq!(
            attempt.record_verification(evidence),
            Err(RemediationError::EvidenceMismatch),
            "{field}"
        );
        assert_eq!(attempt.status, RemediationStatus::Draft);
        assert!(attempt.verification.is_none());
    }
}

#[test]
fn rejected_and_inconclusive_stages_never_verify() {
    let mut rejected = RemediationHandoff::draft(binding()).unwrap();
    let mut failed = verification(&rejected.binding);
    failed.patched_replay = stage(VerificationStageStatus::Failed, 1, 1);
    failed.regression = stage(VerificationStageStatus::Skipped, 0, 0);
    failed.follow_up_fuzz = stage(VerificationStageStatus::Skipped, 0, 0);
    rejected.record_verification(failed).unwrap();
    assert_eq!(rejected.status, RemediationStatus::Rejected);
    assert_eq!(rejected.verify_claim(), Err(RemediationError::NotVerified));

    let mut inconclusive = RemediationHandoff::draft(binding()).unwrap();
    let mut incomplete = verification(&inconclusive.binding);
    incomplete.original_replay = stage(VerificationStageStatus::Inconclusive, 1, 0);
    incomplete.patch_build = stage(VerificationStageStatus::Skipped, 0, 0);
    incomplete.patched_binary_sha256 = None;
    incomplete.patched_replay = stage(VerificationStageStatus::Skipped, 0, 0);
    incomplete.regression = stage(VerificationStageStatus::Skipped, 0, 0);
    incomplete.follow_up_fuzz = stage(VerificationStageStatus::Skipped, 0, 0);
    inconclusive.record_verification(incomplete).unwrap();
    assert_eq!(inconclusive.status, RemediationStatus::Inconclusive);
    assert_eq!(
        inconclusive.verify_claim(),
        Err(RemediationError::NotVerified)
    );
}

#[test]
fn unsafe_patch_paths_and_spec_digests_are_rejected() {
    for unsafe_patch in [
        "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
        "--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
        "--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n",
        "--- a/src\\parser.c\n+++ b/src\\parser.c\n@@ -1 +1 @@\n-a\n+b\n",
    ] {
        let mut candidate = binding();
        candidate.patch = unsafe_patch.to_owned();
        candidate.patch_sha256 = hex::encode(Sha256::digest(candidate.patch.as_bytes()));
        assert_eq!(
            RemediationHandoff::draft(candidate),
            Err(RemediationError::InvalidPatchPath)
        );
    }

    let mut mismatch = binding();
    mismatch.verification_spec.follow_up_fuzz_seconds += 1;
    assert_eq!(
        RemediationHandoff::draft(mismatch),
        Err(RemediationError::VerificationSpecDigestMismatch)
    );
}

#[test]
fn schema_v3_rejects_other_versions() {
    let handoff = RemediationHandoff::draft(binding()).expect("valid draft");
    assert_eq!(REMEDIATION_SCHEMA_VERSION, 3);
    assert_eq!(handoff.schema_version, 3);

    for schema_version in [1, 2, 4] {
        let mut incompatible = handoff.clone();
        incompatible.schema_version = schema_version;
        let evidence = verification(&incompatible.binding);
        assert_eq!(
            incompatible.record_verification(evidence),
            Err(RemediationError::UnsupportedSchema)
        );
    }
}
