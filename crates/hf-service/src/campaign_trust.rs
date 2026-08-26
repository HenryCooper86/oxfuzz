//! Service-owned campaign trust audit.
//!
//! A campaign that ran for six hours is not evidence that its output means
//! anything. This module answers, per target and run, which claims about a
//! campaign the retained evidence supports and which it does not.
//!
//! See `docs/design/campaign-trust-report-design.md`.
//!
//! Gates are grouped by the claim each establishes rather than by the
//! subsystem each lives in, because the report exists to qualify claims. The
//! distinction between `Unsupported` ("we looked and it is not established")
//! and `Unavailable` ("we never looked") is load-bearing: the two call for
//! different next actions and must not be merged.

use serde::Serialize;
use uuid::Uuid;

use crate::finding_proof::{FindingEvidenceKind, FindingEvidenceReference};
use hf_storage::RunStatus;

/// Current serialized Campaign Trust Report schema.
pub const CAMPAIGN_TRUST_SCHEMA_VERSION: u32 = 1;

/// A claim about a campaign that the report either licenses or withholds.
///
/// Declaration order is report order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClaim {
    /// A harness exercises the target.
    HarnessExercisesTarget,
    /// The fuzzer had inputs to work from.
    FuzzerHadInputs,
    /// The fuzzer ran.
    FuzzerRan,
    /// Coverage was measured.
    CoverageMeasured,
    /// Coverage reached target code rather than only the generated harness.
    CoverageReachedTargetCode,
    /// Every retained crash for the run carries an attributed origin.
    CrashesTriaged,
    /// At least one finding has come far enough to be worth reporting.
    FindingsWorthReporting,
}

/// The two claims whose refutation makes everything downstream moot.
const CORE_CLAIMS: [TrustClaim; 2] = [TrustClaim::HarnessExercisesTarget, TrustClaim::FuzzerRan];

/// What retained evidence says about one claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Retained evidence establishes the claim.
    Supported,
    /// Retained evidence establishes that the claim is false.
    Refuted,
    /// Evidence exists and does not establish the claim.
    Unsupported,
    /// The measurement does not exist. Never a substitute for `Refuted`.
    Unavailable,
}

/// One claim, its verdict, and the records behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustGate {
    /// The claim this gate rules on.
    pub claim: TrustClaim,
    /// The ruling.
    pub verdict: GateVerdict,
    /// Why, in a sentence.
    pub detail: String,
    /// The retained records the ruling rests on. Empty implies `Unavailable`.
    pub evidence: Vec<FindingEvidenceReference>,
}

/// The report's overall reading, evaluated in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustDetermination {
    /// A core claim is refuted. Nothing downstream means anything.
    Untrustworthy,
    /// Nothing core is refuted and at least one gate was never measured.
    Unqualified,
    /// Everything was measured and at least one claim is not established.
    Qualified,
    /// Every claim is established.
    Trusted,
}

/// What is retained about the harness used for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HarnessEvidence {
    /// No harness record is retained.
    Unavailable,
    /// A harness record is retained.
    Retained {
        /// The harness record.
        record_id: Uuid,
        /// Whether it compiled in the sandbox.
        compiled: bool,
        /// Whether it passed smoke qualification.
        smoke_passed: bool,
        /// Lint findings at error severity, which block compilation.
        blocking_lint_findings: usize,
    },
}

/// What is retained about the corpus a run worked from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusEvidence {
    /// No corpus record is retained.
    Unavailable,
    /// A corpus is retained.
    Retained {
        /// How many entries it holds.
        entries: usize,
    },
}

/// What is retained about the run itself.
#[derive(Debug, Clone, PartialEq)]
pub enum RunEvidence {
    /// No run record is retained.
    Unavailable,
    /// A run record is retained.
    Retained {
        /// The run record.
        record_id: Uuid,
        /// Its terminal or current state.
        status: RunStatus,
        /// Peak executions per second the engine reported, when it reported
        /// any. This is what the run record retains; there is no total.
        execs_per_sec: Option<f64>,
    },
}

/// What is retained about coverage for a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoverageEvidence {
    /// No coverage measurement completed.
    Unavailable,
    /// A measurement is retained.
    Retained {
        /// The measurement record.
        record_id: Uuid,
        /// Functions the measurement recorded as covered.
        covered_functions: usize,
        /// Of those, the ones belonging to project sources rather than to the
        /// generated harness.
        target_attributed_functions: usize,
    },
}

/// What is retained about the run's crashes.
///
/// Scoped by the run record: the claim is about *this run's* crashes, so the
/// run is what establishes the set, including when the set is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageEvidence {
    /// Crashes retained for the run.
    pub crashes: usize,
    /// Of those, the ones whose fault origin is attributed.
    pub attributed: usize,
    /// Of those, the ones whose disposition has reached a reportable tier.
    pub reportable: usize,
}

/// Everything the audit reads. Gathered by the container; the assessment
/// itself is pure so it can be tested without a store.
#[derive(Debug, Clone, PartialEq)]
pub struct CampaignTrustInput {
    /// The run being audited.
    pub run_id: Uuid,
    /// The target it ran against.
    pub target_id: Uuid,
    /// Harness evidence.
    pub harness: HarnessEvidence,
    /// Corpus evidence.
    pub corpus: CorpusEvidence,
    /// Run evidence.
    pub run: RunEvidence,
    /// Coverage evidence.
    pub coverage: CoverageEvidence,
    /// Triage evidence.
    pub triage: TriageEvidence,
}

/// A per-run audit of what a campaign's evidence licenses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CampaignTrustReport {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// The run audited. A report never merges two runs.
    pub run_id: Uuid,
    /// The target the run exercised.
    pub target_id: Uuid,
    /// One gate per claim, in `TrustClaim` declaration order.
    pub gates: Vec<TrustGate>,
    /// The overall reading.
    pub determination: TrustDetermination,
    /// Claims this report does not license, in gate order. A consumer
    /// exporting a finding refuses to assert these.
    pub unlicensed_claims: Vec<TrustClaim>,
}

/// Audit one run's evidence.
#[must_use]
pub fn assess_campaign_trust(input: &CampaignTrustInput) -> CampaignTrustReport {
    let gates = vec![
        harness_gate(&input.harness),
        corpus_gate(&input.corpus),
        run_gate(&input.run),
        coverage_measured_gate(&input.coverage),
        coverage_reach_gate(&input.coverage),
        crashes_triaged_gate(&input.run, &input.triage),
        findings_gate(&input.run, &input.triage),
    ];
    let determination = determine(&gates);
    let unlicensed_claims = gates
        .iter()
        .filter(|gate| gate.verdict != GateVerdict::Supported)
        .map(|gate| gate.claim)
        .collect();
    CampaignTrustReport {
        schema_version: CAMPAIGN_TRUST_SCHEMA_VERSION,
        run_id: input.run_id,
        target_id: input.target_id,
        gates,
        determination,
        unlicensed_claims,
    }
}

fn determine(gates: &[TrustGate]) -> TrustDetermination {
    let core_refuted = gates
        .iter()
        .any(|gate| gate.verdict == GateVerdict::Refuted && CORE_CLAIMS.contains(&gate.claim));
    if core_refuted {
        return TrustDetermination::Untrustworthy;
    }
    // Unmeasured outranks a known-bad non-core gate: an unmeasured gate could
    // itself turn out to be a refutation once measured.
    if gates
        .iter()
        .any(|gate| gate.verdict == GateVerdict::Unavailable)
    {
        return TrustDetermination::Unqualified;
    }
    if gates
        .iter()
        .any(|gate| gate.verdict != GateVerdict::Supported)
    {
        return TrustDetermination::Qualified;
    }
    TrustDetermination::Trusted
}

fn gate(
    claim: TrustClaim,
    verdict: GateVerdict,
    detail: &str,
    evidence: Vec<FindingEvidenceReference>,
) -> TrustGate {
    TrustGate {
        claim,
        verdict,
        detail: detail.to_owned(),
        evidence,
    }
}

fn reference(kind: FindingEvidenceKind, id: Uuid) -> Vec<FindingEvidenceReference> {
    vec![FindingEvidenceReference {
        kind,
        record_id: id.to_string(),
    }]
}

fn unavailable(claim: TrustClaim, detail: &str) -> TrustGate {
    gate(claim, GateVerdict::Unavailable, detail, Vec::new())
}

fn harness_gate(evidence: &HarnessEvidence) -> TrustGate {
    let claim = TrustClaim::HarnessExercisesTarget;
    let HarnessEvidence::Retained {
        record_id,
        compiled,
        smoke_passed,
        blocking_lint_findings,
    } = evidence
    else {
        return unavailable(claim, "No harness record is retained for this run.");
    };
    let cited = reference(FindingEvidenceKind::HarnessRecord, *record_id);
    if *blocking_lint_findings > 0 {
        return gate(
            claim,
            GateVerdict::Refuted,
            "The harness carries lint findings at error severity, which block compilation.",
            cited,
        );
    }
    if !*compiled {
        return gate(
            claim,
            GateVerdict::Refuted,
            "The harness did not compile, so nothing exercised the target.",
            cited,
        );
    }
    if !*smoke_passed {
        return gate(
            claim,
            GateVerdict::Unsupported,
            "The harness compiled but did not pass smoke qualification.",
            cited,
        );
    }
    gate(
        claim,
        GateVerdict::Supported,
        "The harness compiled and passed smoke qualification.",
        cited,
    )
}

fn corpus_gate(evidence: &CorpusEvidence) -> TrustGate {
    let claim = TrustClaim::FuzzerHadInputs;
    let CorpusEvidence::Retained { entries } = evidence else {
        return unavailable(claim, "No corpus record is retained for this run.");
    };
    if *entries == 0 {
        return gate(
            claim,
            GateVerdict::Refuted,
            "The corpus is empty, so the fuzzer started from nothing.",
            Vec::new(),
        );
    }
    gate(
        claim,
        GateVerdict::Supported,
        "The corpus holds inputs the fuzzer could mutate.",
        Vec::new(),
    )
}

fn run_gate(evidence: &RunEvidence) -> TrustGate {
    let claim = TrustClaim::FuzzerRan;
    let RunEvidence::Retained {
        record_id,
        status,
        execs_per_sec,
    } = evidence
    else {
        return unavailable(claim, "No run record is retained.");
    };
    let cited = reference(FindingEvidenceKind::RunRecord, *record_id);
    match status {
        RunStatus::Failed => gate(
            claim,
            GateVerdict::Refuted,
            "The run terminated with an error.",
            cited,
        ),
        RunStatus::Pending | RunStatus::Running => gate(
            claim,
            GateVerdict::Unsupported,
            "The run has not reached a terminal state, so its evidence is still moving.",
            cited,
        ),
        RunStatus::Cancelled => gate(
            claim,
            GateVerdict::Unsupported,
            "The run was cancelled before completing.",
            cited,
        ),
        RunStatus::Done => {
            if execs_per_sec.unwrap_or(0.0) > 0.0 {
                gate(
                    claim,
                    GateVerdict::Supported,
                    "The run completed and the engine reported executions.",
                    cited,
                )
            } else {
                gate(
                    claim,
                    GateVerdict::Unsupported,
                    "The run completed but reported no executions.",
                    cited,
                )
            }
        }
    }
}

fn coverage_measured_gate(evidence: &CoverageEvidence) -> TrustGate {
    let claim = TrustClaim::CoverageMeasured;
    let CoverageEvidence::Retained { record_id, .. } = evidence else {
        return unavailable(
            claim,
            "No coverage measurement completed for this harness and corpus.",
        );
    };
    gate(
        claim,
        GateVerdict::Supported,
        "A coverage measurement is retained for this run.",
        reference(FindingEvidenceKind::CoverageMeasurement, *record_id),
    )
}

/// Whether a completed measurement attributed anything to project sources.
///
/// Absent a measurement this is `Unavailable`, not `Unsupported`: with nothing
/// measured, nothing at all is known about what coverage reached.
fn coverage_reach_gate(evidence: &CoverageEvidence) -> TrustGate {
    let claim = TrustClaim::CoverageReachedTargetCode;
    let CoverageEvidence::Retained {
        record_id,
        covered_functions,
        target_attributed_functions,
    } = evidence
    else {
        return unavailable(
            claim,
            "Nothing is known about what coverage reached, because nothing was measured.",
        );
    };
    let cited = reference(FindingEvidenceKind::CoverageMeasurement, *record_id);
    if *target_attributed_functions == 0 {
        return gate(
            claim,
            GateVerdict::Unsupported,
            if *covered_functions == 0 {
                "The measurement recorded no covered functions at all."
            } else {
                "The measurement attributes no covered function to project sources."
            },
            cited,
        );
    }
    gate(
        claim,
        GateVerdict::Supported,
        "The measurement attributes covered functions to project sources.",
        cited,
    )
}

fn crashes_triaged_gate(run: &RunEvidence, triage: &TriageEvidence) -> TrustGate {
    let claim = TrustClaim::CrashesTriaged;
    let RunEvidence::Retained { record_id, .. } = run else {
        return unavailable(
            claim,
            "No run record is retained, so the crash set for this run is unknown.",
        );
    };
    let cited = reference(FindingEvidenceKind::RunRecord, *record_id);
    if triage.attributed < triage.crashes {
        return gate(
            claim,
            GateVerdict::Unsupported,
            "Some retained crashes have no attributed fault origin.",
            cited,
        );
    }
    gate(
        claim,
        GateVerdict::Supported,
        if triage.crashes == 0 {
            "The run retained no crashes, so none is left untriaged."
        } else {
            "Every retained crash carries an attributed fault origin."
        },
        cited,
    )
}

fn findings_gate(run: &RunEvidence, triage: &TriageEvidence) -> TrustGate {
    let claim = TrustClaim::FindingsWorthReporting;
    let RunEvidence::Retained { record_id, .. } = run else {
        return unavailable(
            claim,
            "No run record is retained, so the crash set for this run is unknown.",
        );
    };
    let cited = reference(FindingEvidenceKind::RunRecord, *record_id);
    if triage.reportable == 0 {
        return gate(
            claim,
            GateVerdict::Unsupported,
            if triage.crashes == 0 {
                "The run produced no crashes, so there is nothing to report."
            } else {
                "No retained crash has reached a reportable disposition."
            },
            cited,
        );
    }
    gate(
        claim,
        GateVerdict::Supported,
        "At least one retained crash has reached a reportable disposition.",
        cited,
    )
}
