//! Campaign Trust Report domain contract.
//!
//! A gate is grouped by the claim it supports, an unmeasured gate is never a
//! failed one, and a refuted core gate makes everything downstream moot.

#![cfg(feature = "campaign-trust")]

use hf_service::campaign_trust::{
    assess_campaign_trust, CampaignTrustInput, CorpusEvidence, CoverageEvidence, GateVerdict,
    HarnessEvidence, RunEvidence, TriageEvidence, TrustClaim, TrustDetermination,
};
use hf_storage::RunStatus;
use uuid::Uuid;

fn healthy() -> CampaignTrustInput {
    CampaignTrustInput {
        run_id: Uuid::from_u128(1),
        target_id: Uuid::from_u128(2),
        harness: HarnessEvidence::Retained {
            record_id: Uuid::from_u128(3),
            compiled: true,
            smoke_passed: true,
            blocking_lint_findings: 0,
        },
        corpus: CorpusEvidence::Retained { entries: 12 },
        run: RunEvidence::Retained {
            record_id: Uuid::from_u128(4),
            status: RunStatus::Done,
            execs_per_sec: Some(9_000.0),
        },
        coverage: CoverageEvidence::Retained {
            record_id: Uuid::from_u128(5),
            covered_functions: 40,
            target_attributed_functions: 37,
        },
        triage: TriageEvidence {
            crashes: 2,
            attributed: 2,
            reportable: 1,
        },
    }
}

fn verdict(
    report: &hf_service::campaign_trust::CampaignTrustReport,
    claim: TrustClaim,
) -> GateVerdict {
    report
        .gates
        .iter()
        .find(|gate| gate.claim == claim)
        .unwrap_or_else(|| panic!("report must carry a gate for {claim:?}"))
        .verdict
}

#[test]
fn a_fully_evidenced_campaign_is_trusted_and_licenses_every_claim() {
    let report = assess_campaign_trust(&healthy());

    assert_eq!(report.determination, TrustDetermination::Trusted);
    assert!(
        report.unlicensed_claims.is_empty(),
        "a trusted report withholds nothing"
    );
}

#[test]
fn every_claim_gets_exactly_one_gate() {
    let report = assess_campaign_trust(&healthy());
    let mut claims: Vec<TrustClaim> = report.gates.iter().map(|gate| gate.claim).collect();
    let before = claims.len();
    claims.sort_unstable();
    claims.dedup();

    assert_eq!(claims.len(), before, "a claim must not be gated twice");
    assert_eq!(claims.len(), 7, "every claim in the design must be gated");
}

#[test]
fn a_missing_measurement_is_unavailable_and_never_unsupported() {
    let mut input = healthy();
    input.coverage = CoverageEvidence::Unavailable;

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::CoverageMeasured),
        GateVerdict::Unavailable
    );
    assert_eq!(
        verdict(&report, TrustClaim::CoverageReachedTargetCode),
        GateVerdict::Unavailable,
        "nothing is known about target code when nothing was measured"
    );
    assert_eq!(report.determination, TrustDetermination::Unqualified);
}

#[test]
fn a_measurement_that_reached_no_target_code_is_unsupported_not_unavailable() {
    let mut input = healthy();
    input.coverage = CoverageEvidence::Retained {
        record_id: Uuid::from_u128(5),
        covered_functions: 6,
        target_attributed_functions: 0,
    };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::CoverageMeasured),
        GateVerdict::Supported,
        "the measurement exists"
    );
    assert_eq!(
        verdict(&report, TrustClaim::CoverageReachedTargetCode),
        GateVerdict::Unsupported,
        "we looked and it did not reach target code"
    );
}

#[test]
fn a_harness_that_did_not_compile_makes_the_whole_campaign_untrustworthy() {
    let mut input = healthy();
    input.harness = HarnessEvidence::Retained {
        record_id: Uuid::from_u128(3),
        compiled: false,
        smoke_passed: false,
        blocking_lint_findings: 0,
    };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::HarnessExercisesTarget),
        GateVerdict::Refuted
    );
    assert_eq!(report.determination, TrustDetermination::Untrustworthy);
}

#[test]
fn a_blocking_lint_finding_refutes_the_harness_claim() {
    let mut input = healthy();
    input.harness = HarnessEvidence::Retained {
        record_id: Uuid::from_u128(3),
        compiled: true,
        smoke_passed: true,
        blocking_lint_findings: 1,
    };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::HarnessExercisesTarget),
        GateVerdict::Refuted
    );
}

#[test]
fn a_failed_run_makes_the_whole_campaign_untrustworthy() {
    let mut input = healthy();
    input.run = RunEvidence::Retained {
        record_id: Uuid::from_u128(4),
        status: RunStatus::Failed,
        execs_per_sec: Some(10.0),
    };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::FuzzerRan),
        GateVerdict::Refuted
    );
    assert_eq!(report.determination, TrustDetermination::Untrustworthy);
}

#[test]
fn an_empty_corpus_is_refuted_but_does_not_invalidate_the_campaign() {
    let mut input = healthy();
    input.corpus = CorpusEvidence::Retained { entries: 0 };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::FuzzerHadInputs),
        GateVerdict::Refuted
    );
    assert_eq!(
        report.determination,
        TrustDetermination::Qualified,
        "a refuted non-core gate qualifies the report, it does not void it"
    );
    assert!(report
        .unlicensed_claims
        .contains(&TrustClaim::FuzzerHadInputs));
}

#[test]
fn an_unmeasured_gate_outranks_a_refuted_one_in_the_determination() {
    // Unmeasured could itself turn out to be a refutation, so it is reported
    // first rather than being hidden behind a known-bad non-core gate.
    let mut input = healthy();
    input.corpus = CorpusEvidence::Retained { entries: 0 };
    input.coverage = CoverageEvidence::Unavailable;

    let report = assess_campaign_trust(&input);

    assert_eq!(report.determination, TrustDetermination::Unqualified);
}

#[test]
fn an_unattributed_crash_leaves_the_triage_claim_unsupported() {
    let mut input = healthy();
    input.triage = TriageEvidence {
        crashes: 3,
        attributed: 2,
        reportable: 1,
    };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::CrashesTriaged),
        GateVerdict::Unsupported
    );
}

#[test]
fn a_run_with_no_crashes_has_nothing_untriaged_and_nothing_to_report() {
    let mut input = healthy();
    input.triage = TriageEvidence {
        crashes: 0,
        attributed: 0,
        reportable: 0,
    };

    let report = assess_campaign_trust(&input);

    assert_eq!(
        verdict(&report, TrustClaim::CrashesTriaged),
        GateVerdict::Supported,
        "no crash is left untriaged when there are none"
    );
    assert_eq!(
        verdict(&report, TrustClaim::FindingsWorthReporting),
        GateVerdict::Unsupported,
        "nothing to report is not a supported claim that there is"
    );
}

#[test]
fn a_gate_with_no_cited_evidence_is_always_unavailable() {
    let input = CampaignTrustInput {
        harness: HarnessEvidence::Unavailable,
        corpus: CorpusEvidence::Unavailable,
        run: RunEvidence::Unavailable,
        coverage: CoverageEvidence::Unavailable,
        ..healthy()
    };

    let report = assess_campaign_trust(&input);

    for gate in &report.gates {
        if gate.evidence.is_empty() {
            assert_eq!(
                gate.verdict,
                GateVerdict::Unavailable,
                "{:?} cites nothing yet claims {:?}",
                gate.claim,
                gate.verdict
            );
        }
    }
}

#[test]
fn every_gate_below_supported_is_named_as_an_unlicensed_claim() {
    let mut input = healthy();
    input.coverage = CoverageEvidence::Retained {
        record_id: Uuid::from_u128(5),
        covered_functions: 6,
        target_attributed_functions: 0,
    };
    input.triage = TriageEvidence {
        crashes: 1,
        attributed: 0,
        reportable: 0,
    };

    let report = assess_campaign_trust(&input);

    let expected: Vec<TrustClaim> = report
        .gates
        .iter()
        .filter(|gate| gate.verdict != GateVerdict::Supported)
        .map(|gate| gate.claim)
        .collect();
    assert_eq!(report.unlicensed_claims, expected);
    assert!(!report.unlicensed_claims.is_empty());
}

#[test]
fn a_report_names_the_run_it_audits() {
    let report = assess_campaign_trust(&healthy());

    assert_eq!(report.run_id, Uuid::from_u128(1));
    assert_eq!(report.target_id, Uuid::from_u128(2));
}
