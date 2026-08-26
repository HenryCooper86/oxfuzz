//! Service-owned triage ordering.
//!
//! The Finding Proof Card answers, per crash, what the retained evidence
//! supports. This module answers the question an operator opens the triage
//! queue with: which crash deserves attention next, and what may anyone claim
//! about it.
//!
//! See `docs/design/triage-disposition-design.md`.
//!
//! Every value here is derived from the proof card and the persisted crash.
//! Nothing reads harness source, a coverage export, or a model opinion, so a
//! disposition is reconstructable from persisted state (AGENTS.md 2.13). The
//! card remains the single home for per-claim detail: a disposition carries the
//! tier, the action, and the ceiling, and a consumer wanting the reasoning
//! reads the card it came from (AGENTS.md 2.18).

use hf_core::crash::{Crash, CrashOrigin};
use serde::Serialize;
use uuid::Uuid;

use crate::finding_proof::{
    CasrExploitabilityDetermination, FindingEvidenceReference, FindingProofCard,
    FindingProofStatus, FixVerificationDetermination, ReachabilityDetermination,
};

/// Current serialized Triage Disposition schema.
pub const TRIAGE_DISPOSITION_SCHEMA_VERSION: u32 = 1;

/// What a crash needs next, ordered by descending operator attention.
///
/// The derived ordering is the queue order: variants are declared most-urgent
/// first, so a smaller value is opened first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// A sandbox verification workflow confirmed a patch removes the fault. No
    /// triage work remains.
    Resolved,
    /// An attributed, minimized target fault whose reachability from an
    /// external input is demonstrated.
    ///
    /// Currently unreachable by construction, and deliberately so: no oxfuzz
    /// path retains external-input-to-fault evidence, so `finding_proof_card`
    /// never reports reachability as demonstrated. The variant exists so that
    /// when such evidence is retained the ladder already has the right place
    /// for it and no consumer changes.
    ReportReady,
    /// An attributed, minimized target fault with no retained evidence
    /// connecting an external input to it. The bug is real; its security
    /// relevance is not established.
    ReachabilityUnproven,
    /// An attributed target fault whose input is not minimized.
    MinimizationPending,
    /// A fault with no symbolized frames, so it is attributed to no layer.
    /// Ranked above the two attributed non-findings because a cheap rebuild can
    /// promote it and cannot promote them.
    SymbolizationPending,
    /// A fault inside the fuzzer driver or sanitizer runtime: a configuration
    /// signal, never a finding about the target.
    RuntimeArtifact,
    /// A fault in code oxfuzz generated. It blocks the campaign and must be
    /// fixed, but it is never a finding about the target.
    HarnessDefect,
}

/// The single next step a disposition calls for.
///
/// The serialized name is the stable identifier a consumer localizes against;
/// there is no separate reason code, because a second identifier for one
/// meaning would be a second home for it (AGENTS.md 2.18).
///
/// An action names a step. It does not perform one: minimization and harness
/// repair already have approval paths, and this module does not offer a second
/// entrypoint to either (AGENTS.md 2.19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DispositionAction {
    /// Nothing to do.
    NoAction,
    /// Draft the finding from retained evidence.
    WriteReport,
    /// Establish a path from an external input to the fault.
    DemonstrateReachability,
    /// Reduce the input before further analysis.
    MinimizeInput,
    /// Rebuild the target with symbols and re-triage.
    RebuildWithSymbols,
    /// Inspect engine and sanitizer settings.
    ReviewEngineConfiguration,
    /// Fix the generated harness and re-run.
    RepairHarness,
}

/// The strongest statement the retained evidence permits.
///
/// Ordered weakest to strongest. A ceiling is reached only by raising the rung
/// below it, so no ceiling ever asserts more than its predecessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCeiling {
    /// The fault is not in the project under test.
    NoTargetClaim,
    /// A fault occurred and is attributed to no layer.
    FaultObserved,
    /// An attributed target fault whose input is not minimized.
    TargetFaultObserved,
    /// An attributed, minimized target fault.
    TargetFaultMinimized,
    /// CASR produced a supported exploitability determination for an
    /// attributed, minimized target fault.
    ExploitabilityClassified,
    /// A patch was verified against the retained input.
    RemediationVerified,
}

/// Service-owned triage view for one retained crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TriageDisposition {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// Where the crash sits in the attention order.
    pub disposition: Disposition,
    /// The single next step.
    pub action: DispositionAction,
    /// That step, in a sentence.
    pub action_detail: String,
    /// The strongest supportable claim.
    pub claim_ceiling: ClaimCeiling,
    /// What the evidence does not support, stated so a reader does not mistake
    /// the gap above the ceiling for merely unstated.
    pub claim_limit: String,
    /// The retained records this determination rests on.
    pub evidence: Vec<FindingEvidenceReference>,
}

/// Total, stable sort key for the triage queue.
///
/// Field order is the ordering: disposition, then CASR exploitability
/// most-severe-first with `Unavailable` last, then crash id. CASR breaks the
/// tie rather than crash kind because CASR is a retained determination and
/// crash kind is a label. Where CASR never ran, every crash at a disposition
/// shares the second key and falls through to the stable id order, which is
/// correct: with no exploitability evidence there is no basis to prefer one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TriageOrderKey {
    /// Primary key: attention order.
    pub disposition: Disposition,
    /// Secondary key: retained exploitability classification.
    pub exploitability: CasrExploitabilityDetermination,
    /// Final key, for a total and stable order.
    pub crash_id: Uuid,
}

/// Derive the triage view for one crash from its proof card.
#[must_use]
pub fn triage_disposition(crash: &Crash, card: &FindingProofCard) -> TriageDisposition {
    let disposition = disposition_of(crash, card);
    let claim_ceiling = claim_ceiling(disposition, card);
    TriageDisposition {
        schema_version: TRIAGE_DISPOSITION_SCHEMA_VERSION,
        disposition,
        action: action_for(disposition),
        action_detail: action_detail(disposition).to_owned(),
        claim_ceiling,
        claim_limit: claim_limit(claim_ceiling).to_owned(),
        evidence: evidence_for(disposition, claim_ceiling, card),
    }
}

/// Derive the queue sort key for one crash.
#[must_use]
pub fn triage_order_key(crash: &Crash, card: &FindingProofCard) -> TriageOrderKey {
    TriageOrderKey {
        disposition: disposition_of(crash, card),
        exploitability: card.casr_exploitability.determination,
        crash_id: crash.id,
    }
}

/// Whether a claim rests on evidence rather than on its absence.
fn is_supported(status: FindingProofStatus) -> bool {
    status == FindingProofStatus::Supported
}

fn disposition_of(crash: &Crash, card: &FindingProofCard) -> Disposition {
    if is_supported(card.fix_verification.status)
        && card.fix_verification.determination == FixVerificationDetermination::Verified
    {
        return Disposition::Resolved;
    }
    match card.fault_origin.determination {
        CrashOrigin::Harness => Disposition::HarnessDefect,
        CrashOrigin::Runtime => Disposition::RuntimeArtifact,
        CrashOrigin::Unknown => Disposition::SymbolizationPending,
        CrashOrigin::Target if !crash.minimized => Disposition::MinimizationPending,
        CrashOrigin::Target
            if is_supported(card.external_reachability.status)
                && card.external_reachability.determination
                    == ReachabilityDetermination::Demonstrated =>
        {
            Disposition::ReportReady
        }
        CrashOrigin::Target => Disposition::ReachabilityUnproven,
    }
}

/// The ceiling for a disposition.
///
/// `MinimizationPending` stops at `TargetFaultObserved` even when CASR
/// classified the fault: `ExploitabilityClassified` sits above
/// `TargetFaultMinimized`, and granting it for an input that was never
/// minimized would assert more than the rung below it.
fn claim_ceiling(disposition: Disposition, card: &FindingProofCard) -> ClaimCeiling {
    match disposition {
        Disposition::Resolved => ClaimCeiling::RemediationVerified,
        Disposition::HarnessDefect | Disposition::RuntimeArtifact => ClaimCeiling::NoTargetClaim,
        Disposition::SymbolizationPending => ClaimCeiling::FaultObserved,
        Disposition::MinimizationPending => ClaimCeiling::TargetFaultObserved,
        Disposition::ReachabilityUnproven | Disposition::ReportReady => {
            if is_supported(card.casr_exploitability.status) {
                ClaimCeiling::ExploitabilityClassified
            } else {
                ClaimCeiling::TargetFaultMinimized
            }
        }
    }
}

fn action_for(disposition: Disposition) -> DispositionAction {
    match disposition {
        Disposition::Resolved => DispositionAction::NoAction,
        Disposition::ReportReady => DispositionAction::WriteReport,
        Disposition::ReachabilityUnproven => DispositionAction::DemonstrateReachability,
        Disposition::MinimizationPending => DispositionAction::MinimizeInput,
        Disposition::SymbolizationPending => DispositionAction::RebuildWithSymbols,
        Disposition::RuntimeArtifact => DispositionAction::ReviewEngineConfiguration,
        Disposition::HarnessDefect => DispositionAction::RepairHarness,
    }
}

fn action_detail(disposition: Disposition) -> &'static str {
    match disposition {
        Disposition::Resolved => "A patch was verified against this input; no triage work remains.",
        Disposition::ReportReady => {
            "Draft the finding: attribution, minimization, and reachability are all retained."
        }
        Disposition::ReachabilityUnproven => {
            "Establish a path from an external input to this fault before treating it as a \
             security finding."
        }
        Disposition::MinimizationPending => {
            "Minimize the input; every later analysis is worth more against a reduced testcase."
        }
        Disposition::SymbolizationPending => {
            "Rebuild the target with symbols and re-triage; the fault cannot be attributed \
             without frames."
        }
        Disposition::RuntimeArtifact => {
            "Inspect the engine and sanitizer configuration; the fault is in the runtime, not \
             the target."
        }
        Disposition::HarnessDefect => {
            "Repair the generated harness and re-run; this fault is in code oxfuzz wrote."
        }
    }
}

fn claim_limit(ceiling: ClaimCeiling) -> &'static str {
    match ceiling {
        ClaimCeiling::NoTargetClaim => {
            "The fault is not in the project under test, so no claim about the target is \
             supported by this crash."
        }
        ClaimCeiling::FaultObserved => {
            "The fault is attributed to no layer, so it must not be described as a target \
             defect, and exploitability is unclassified."
        }
        ClaimCeiling::TargetFaultObserved => {
            "The input is not minimized and exploitability is unclassified; do not describe \
             this finding as exploitable."
        }
        ClaimCeiling::TargetFaultMinimized => {
            "Exploitability is unclassified; do not describe this finding as exploitable."
        }
        ClaimCeiling::ExploitabilityClassified => {
            "The classification is CASR's assessment of one crash; do not state an impact \
             stronger than it records."
        }
        ClaimCeiling::RemediationVerified => {
            "Verification covers the exact retained input; it does not establish that no \
             related defect remains."
        }
    }
}

/// The retained records a determination rests on: always the origin evidence,
/// plus whichever claim raised the ceiling.
fn evidence_for(
    disposition: Disposition,
    ceiling: ClaimCeiling,
    card: &FindingProofCard,
) -> Vec<FindingEvidenceReference> {
    let mut evidence = card.fault_origin.evidence.clone();
    if disposition == Disposition::Resolved {
        extend_unique(&mut evidence, &card.fix_verification.evidence);
    }
    if ceiling == ClaimCeiling::ExploitabilityClassified {
        extend_unique(&mut evidence, &card.casr_exploitability.evidence);
    }
    evidence
}

fn extend_unique(target: &mut Vec<FindingEvidenceReference>, extra: &[FindingEvidenceReference]) {
    for reference in extra {
        if !target.contains(reference) {
            target.push(reference.clone());
        }
    }
}
