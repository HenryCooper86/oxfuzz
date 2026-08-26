//! Service-owned, evidence-grounded finding determinations.

use hf_core::crash::{Crash, CrashOrigin, CrashSeverity};
use serde::Serialize;
use uuid::Uuid;

/// Current serialized Finding Proof Card schema.
pub const FINDING_PROOF_SCHEMA_VERSION: u32 = 1;

/// Whether retained evidence supports a claim, is insufficient to verify it,
/// or is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingProofStatus {
    Supported,
    NotVerified,
    Unavailable,
}

/// Durable record kind named by a proof claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingEvidenceKind {
    CrashRecord,
    RunRecord,
    CasrReport,
    /// A Patch-to-Proof remediation operation and its terminal sandbox evidence.
    RemediationRecord,
    /// A retained harness record, cited by a campaign trust gate.
    HarnessRecord,
    /// A retained coverage measurement, cited by a campaign trust gate.
    CoverageMeasurement,
}

/// One stable reference to retained evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingEvidenceReference {
    pub kind: FindingEvidenceKind,
    pub record_id: String,
}

/// One typed determination and the retained evidence behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingProofClaim<T> {
    pub determination: T,
    pub status: FindingProofStatus,
    pub detail_code: String,
    pub detail: String,
    pub evidence: Vec<FindingEvidenceReference>,
}

/// Deterministic-reproduction determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReproductionDetermination {
    Deterministic,
    NotVerified,
}

/// CASR exploitability determination, including absence of a CASR report.
///
/// Variants are declared most severe first, so the derived order sorts the
/// most severe classification first and an absent report last. That order is
/// the triage queue's tie-break; see `triage_disposition::TriageOrderKey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CasrExploitabilityDetermination {
    Exploitable,
    ProbablyExploitable,
    NotExploitable,
    Undefined,
    Unavailable,
}

/// External-input reachability determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityDetermination {
    Demonstrated,
    NotVerified,
}

/// Exact-input remediation verification determination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FixVerificationDetermination {
    Verified,
    Rejected,
    Inconclusive,
    NotVerified,
}

/// Service-owned evidence view for one retained crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingProofCard {
    pub schema_version: u32,
    pub fault_origin: FindingProofClaim<CrashOrigin>,
    pub deterministic_reproduction: FindingProofClaim<ReproductionDetermination>,
    pub casr_exploitability: FindingProofClaim<CasrExploitabilityDetermination>,
    pub external_reachability: FindingProofClaim<ReachabilityDetermination>,
    pub fix_verification: FindingProofClaim<FixVerificationDetermination>,
}

/// Derive the versioned, read-only proof view for a persisted crash.
#[must_use]
pub fn finding_proof_card(crash: &Crash) -> FindingProofCard {
    let crash_record = evidence_reference(FindingEvidenceKind::CrashRecord, crash.id);
    let run_record = evidence_reference(FindingEvidenceKind::RunRecord, crash.run_id);
    let fault_origin = match crash.origin {
        CrashOrigin::Target => proof_claim(
            CrashOrigin::Target,
            FindingProofStatus::Supported,
            "origin_target",
            "The persisted crash classification attributes the fault to target code.",
            vec![crash_record.clone()],
        ),
        CrashOrigin::Harness => proof_claim(
            CrashOrigin::Harness,
            FindingProofStatus::Supported,
            "origin_harness",
            "The persisted crash classification attributes the fault to generated harness code.",
            vec![crash_record.clone()],
        ),
        CrashOrigin::Runtime => proof_claim(
            CrashOrigin::Runtime,
            FindingProofStatus::Supported,
            "origin_runtime",
            "The persisted crash classification attributes the fault to the fuzzer or sanitizer runtime.",
            vec![crash_record.clone()],
        ),
        CrashOrigin::Unknown => proof_claim(
            CrashOrigin::Unknown,
            FindingProofStatus::Unavailable,
            "origin_unknown",
            "The retained crash has no symbolized evidence that identifies the fault origin.",
            vec![crash_record.clone()],
        ),
    };

    let mut reproduction_evidence = vec![crash_record.clone(), run_record];
    let reproduction_detail = if crash.casr.is_some() {
        reproduction_evidence.push(evidence_reference(
            FindingEvidenceKind::CasrReport,
            crash.id,
        ));
        (
            "reproduction_casr_single_replay",
            "CASR produced sandbox analysis for this crash, but no repeated replay record is retained.",
        )
    } else {
        (
            "reproduction_no_repeated_replay",
            "No retained repeated sandbox replay record establishes deterministic reproduction.",
        )
    };
    let deterministic_reproduction = proof_claim(
        ReproductionDetermination::NotVerified,
        FindingProofStatus::NotVerified,
        reproduction_detail.0,
        reproduction_detail.1,
        reproduction_evidence,
    );

    let casr_exploitability = crash.casr.as_ref().map_or_else(
        || {
            proof_claim(
                CasrExploitabilityDetermination::Unavailable,
                FindingProofStatus::Unavailable,
                "casr_unavailable",
                "No CASR exploitability report is retained for this crash.",
                Vec::new(),
            )
        },
        |report| {
            proof_claim(
                casr_exploitability(report.severity),
                FindingProofStatus::Supported,
                "casr_available",
                "CASR classified exploitability from its retained crash analysis.",
                vec![evidence_reference(
                    FindingEvidenceKind::CasrReport,
                    crash.id,
                )],
            )
        },
    );

    FindingProofCard {
        schema_version: FINDING_PROOF_SCHEMA_VERSION,
        fault_origin,
        deterministic_reproduction,
        casr_exploitability,
        external_reachability: proof_claim(
            ReachabilityDetermination::NotVerified,
            FindingProofStatus::NotVerified,
            "external_reachability_not_verified",
            "No retained external-input-to-fault path establishes reachability.",
            Vec::new(),
        ),
        fix_verification: proof_claim(
            FixVerificationDetermination::NotVerified,
            FindingProofStatus::NotVerified,
            "fix_not_verified",
            "No matching patch and sandbox verification record is retained for this finding.",
            Vec::new(),
        ),
    }
}

fn proof_claim<T>(
    determination: T,
    status: FindingProofStatus,
    detail_code: &str,
    detail: &str,
    evidence: Vec<FindingEvidenceReference>,
) -> FindingProofClaim<T> {
    FindingProofClaim {
        determination,
        status,
        detail_code: detail_code.to_owned(),
        detail: detail.to_owned(),
        evidence,
    }
}

fn evidence_reference(kind: FindingEvidenceKind, id: Uuid) -> FindingEvidenceReference {
    FindingEvidenceReference {
        kind,
        record_id: id.to_string(),
    }
}

fn casr_exploitability(severity: CrashSeverity) -> CasrExploitabilityDetermination {
    match severity {
        CrashSeverity::Exploitable => CasrExploitabilityDetermination::Exploitable,
        CrashSeverity::ProbablyExploitable => CasrExploitabilityDetermination::ProbablyExploitable,
        CrashSeverity::NotExploitable => CasrExploitabilityDetermination::NotExploitable,
        CrashSeverity::Undefined => CasrExploitabilityDetermination::Undefined,
    }
}

/// Override the base `fix_verification` claim from the latest terminal
/// Patch-to-Proof remediation for a finding. A terminal operation (verified,
/// rejected, inconclusive) replaces the base `not_verified` claim with a
/// supported determination backed by the remediation record. A non-terminal
/// operation (draft/approved/running) or a missing record leaves the base
/// `not_verified` claim untouched.
///
/// A `verified` row is revalidated from its immutable binding and terminal
/// evidence before it is trusted; a mismatch fails closed to `inconclusive`
/// rather than reporting a stale verified claim.
#[cfg(feature = "patch-to-proof")]
pub fn enrich_fix_verification(
    mut card: FindingProofCard,
    record: Option<&hf_storage::RemediationOperationRecord>,
) -> FindingProofCard {
    use hf_storage::RemediationOperationStatus;

    let Some(record) = record else {
        return card;
    };
    let evidence_ref = FindingEvidenceReference {
        kind: FindingEvidenceKind::RemediationRecord,
        record_id: record.id.to_string(),
    };
    let (determination, status, detail_code, detail) = match record.status {
        RemediationOperationStatus::Verified => {
            if revalidate_verified_record(record) {
                (
                    FixVerificationDetermination::Verified,
                    FindingProofStatus::Supported,
                    "fix_verified",
                    "A sandbox verification workflow reproduced the finding before the patch and confirmed it no longer crashes after the patch.",
                )
            } else {
                (
                    FixVerificationDetermination::Inconclusive,
                    FindingProofStatus::Supported,
                    "fix_verified_revalidation_failed",
                    "The retained verified remediation evidence failed revalidation; the claim is not trusted.",
                )
            }
        }
        RemediationOperationStatus::Rejected => (
            FixVerificationDetermination::Rejected,
            FindingProofStatus::Supported,
            "fix_rejected",
            "A sandbox verification workflow rejected the patch: the finding still reproduces after the patch or a regression was found.",
        ),
        RemediationOperationStatus::Inconclusive => (
            FixVerificationDetermination::Inconclusive,
            FindingProofStatus::Supported,
            "fix_inconclusive",
            "A sandbox verification workflow could not reach a conclusive result for this patch.",
        ),
        RemediationOperationStatus::Draft
        | RemediationOperationStatus::Approved
        | RemediationOperationStatus::Running => return card,
    };
    card.fix_verification = proof_claim(
        determination,
        status,
        detail_code,
        detail,
        vec![evidence_ref],
    );
    card
}

#[cfg(feature = "patch-to-proof")]
fn revalidate_verified_record(record: &hf_storage::RemediationOperationRecord) -> bool {
    use hf_crash::remediation::{
        RemediationBinding, RemediationHandoff, RemediationStatus, SandboxVerificationEvidence,
        REMEDIATION_SCHEMA_VERSION,
    };
    let Ok(binding) = serde_json::from_str::<RemediationBinding>(&record.binding_json) else {
        return false;
    };
    let Some(json) = record.verification_json.as_deref() else {
        return false;
    };
    let Ok(evidence) = serde_json::from_str::<SandboxVerificationEvidence>(json) else {
        return false;
    };
    let handoff = RemediationHandoff {
        schema_version: REMEDIATION_SCHEMA_VERSION,
        binding,
        status: RemediationStatus::Verified,
        verification: Some(evidence),
    };
    handoff.verify_claim().is_ok()
}
