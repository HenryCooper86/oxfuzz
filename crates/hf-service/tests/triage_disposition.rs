//! Triage Disposition domain contract.
//!
//! Attribution decides whether a crash can be a finding at all, evidence
//! completeness decides how far it has come, and the claim ceiling never
//! outruns either.

#![cfg(feature = "triage-disposition")]

use hf_core::crash::{CasrReport, Crash, CrashKind, CrashOrigin, CrashSeverity};
use hf_service::finding_proof::{
    finding_proof_card, FindingProofCard, FindingProofStatus, FixVerificationDetermination,
    ReachabilityDetermination,
};
use hf_service::triage_disposition::{
    triage_disposition, triage_order_key, ClaimCeiling, Disposition, DispositionAction,
};
use std::path::PathBuf;
use uuid::Uuid;

fn crash(origin: CrashOrigin, minimized: bool) -> Crash {
    Crash {
        id: Uuid::from_u128(1),
        run_id: Uuid::from_u128(2),
        target_id: Uuid::from_u128(3),
        input_path: PathBuf::from("input.bin"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow".to_owned(),
        minimized,
        bug_report: None,
        casr: None,
        origin,
    }
}

fn with_casr(mut crash: Crash, severity: CrashSeverity) -> Crash {
    crash.casr = Some(CasrReport {
        severity,
        severity_short: "heap-buffer-overflow(write)".to_owned(),
        crashline: "src/parser.c:41:9".to_owned(),
        stack: vec!["parse_header".to_owned()],
        cluster: None,
    });
    crash
}

/// A card whose fix verification is supported at `determination`.
fn card_with_fix(crash: &Crash, determination: FixVerificationDetermination) -> FindingProofCard {
    let mut card = finding_proof_card(crash);
    card.fix_verification.determination = determination;
    card.fix_verification.status = FindingProofStatus::Supported;
    card
}

/// A card whose external reachability is demonstrated. No production path
/// retains this evidence yet; the contract still has to hold when one does.
fn card_with_reachability(crash: &Crash) -> FindingProofCard {
    let mut card = finding_proof_card(crash);
    card.external_reachability.determination = ReachabilityDetermination::Demonstrated;
    card.external_reachability.status = FindingProofStatus::Supported;
    card
}

#[test]
fn a_harness_fault_is_a_harness_defect_whatever_else_is_known() {
    // Minimized, ASan, and classified exploitable by CASR: every signal that
    // would promote a target fault is present, and none of them applies to a
    // fault in code oxfuzz generated.
    let crash = with_casr(
        crash(CrashOrigin::Harness, true),
        CrashSeverity::Exploitable,
    );
    let card = finding_proof_card(&crash);

    let view = triage_disposition(&crash, &card);

    assert_eq!(view.disposition, Disposition::HarnessDefect);
    assert_eq!(view.action, DispositionAction::RepairHarness);
    assert_eq!(view.claim_ceiling, ClaimCeiling::NoTargetClaim);
}

#[test]
fn a_runtime_fault_supports_no_claim_about_the_target() {
    let crash = crash(CrashOrigin::Runtime, true);
    let card = finding_proof_card(&crash);

    let view = triage_disposition(&crash, &card);

    assert_eq!(view.disposition, Disposition::RuntimeArtifact);
    assert_eq!(view.action, DispositionAction::ReviewEngineConfiguration);
    assert_eq!(view.claim_ceiling, ClaimCeiling::NoTargetClaim);
}

#[test]
fn an_unattributed_fault_is_never_attributed_to_the_target() {
    let crash = crash(CrashOrigin::Unknown, true);
    let card = finding_proof_card(&crash);

    let view = triage_disposition(&crash, &card);

    assert_eq!(view.disposition, Disposition::SymbolizationPending);
    assert_eq!(view.action, DispositionAction::RebuildWithSymbols);
    assert_eq!(view.claim_ceiling, ClaimCeiling::FaultObserved);
}

#[test]
fn minimization_is_what_separates_the_two_unresolved_target_dispositions() {
    let unminimized = crash(CrashOrigin::Target, false);
    let minimized = crash(CrashOrigin::Target, true);

    let pending = triage_disposition(&unminimized, &finding_proof_card(&unminimized));
    let done = triage_disposition(&minimized, &finding_proof_card(&minimized));

    assert_eq!(pending.disposition, Disposition::MinimizationPending);
    assert_eq!(pending.action, DispositionAction::MinimizeInput);
    assert_eq!(pending.claim_ceiling, ClaimCeiling::TargetFaultObserved);

    assert_eq!(done.disposition, Disposition::ReachabilityUnproven);
    assert_eq!(done.action, DispositionAction::DemonstrateReachability);
    assert_eq!(done.claim_ceiling, ClaimCeiling::TargetFaultMinimized);
}

#[test]
fn demonstrated_reachability_is_what_makes_a_finding_report_ready() {
    let crash = crash(CrashOrigin::Target, true);
    let card = card_with_reachability(&crash);

    let view = triage_disposition(&crash, &card);

    assert_eq!(view.disposition, Disposition::ReportReady);
    assert_eq!(view.action, DispositionAction::WriteReport);
}

#[test]
fn a_verified_remediation_resolves_a_crash_and_outranks_every_open_one() {
    let crash = crash(CrashOrigin::Target, true);
    let card = card_with_fix(&crash, FixVerificationDetermination::Verified);

    let view = triage_disposition(&crash, &card);

    assert_eq!(view.disposition, Disposition::Resolved);
    assert_eq!(view.action, DispositionAction::NoAction);
    assert_eq!(view.claim_ceiling, ClaimCeiling::RemediationVerified);
    assert!(Disposition::Resolved < Disposition::ReportReady);
}

#[test]
fn a_remediation_that_did_not_verify_leaves_the_crash_open() {
    let crash = crash(CrashOrigin::Target, true);

    for determination in [
        FixVerificationDetermination::Rejected,
        FixVerificationDetermination::Inconclusive,
        FixVerificationDetermination::NotVerified,
    ] {
        let card = card_with_fix(&crash, determination);
        let view = triage_disposition(&crash, &card);
        assert_ne!(
            view.disposition,
            Disposition::Resolved,
            "{determination:?} must not resolve a crash"
        );
    }
}

#[test]
fn casr_evidence_raises_the_claim_ceiling_without_moving_the_disposition() {
    let plain = crash(CrashOrigin::Target, true);
    let classified = with_casr(plain.clone(), CrashSeverity::Exploitable);

    let without = triage_disposition(&plain, &finding_proof_card(&plain));
    let with = triage_disposition(&classified, &finding_proof_card(&classified));

    assert_eq!(without.claim_ceiling, ClaimCeiling::TargetFaultMinimized);
    assert_eq!(with.claim_ceiling, ClaimCeiling::ExploitabilityClassified);
    assert_eq!(
        without.disposition, with.disposition,
        "exploitability is a claim input, not an attention input"
    );
}

#[test]
fn casr_on_an_unminimized_input_does_not_raise_the_ceiling() {
    // The ladder is ordered: a claim above TargetFaultMinimized on an input
    // that was never minimized would assert more than the rung below it.
    let crash = with_casr(
        crash(CrashOrigin::Target, false),
        CrashSeverity::Exploitable,
    );

    let view = triage_disposition(&crash, &finding_proof_card(&crash));

    assert_eq!(view.claim_ceiling, ClaimCeiling::TargetFaultObserved);
}

#[test]
fn casr_never_grants_a_target_ceiling_to_a_harness_fault() {
    let crash = with_casr(
        crash(CrashOrigin::Harness, true),
        CrashSeverity::Exploitable,
    );

    let view = triage_disposition(&crash, &finding_proof_card(&crash));

    assert_eq!(view.claim_ceiling, ClaimCeiling::NoTargetClaim);
}

#[test]
fn an_unclassified_target_fault_is_stated_as_not_shown_to_be_exploitable() {
    for minimized in [false, true] {
        let crash = crash(CrashOrigin::Target, minimized);
        let view = triage_disposition(&crash, &finding_proof_card(&crash));
        let limit = view.claim_limit.to_lowercase();
        assert!(
            limit.contains("exploitab"),
            "claim limit must name exploitability as unsupported, got: {}",
            view.claim_limit
        );
    }
}

#[test]
fn every_disposition_states_something_the_evidence_does_not_support() {
    for origin in [
        CrashOrigin::Target,
        CrashOrigin::Harness,
        CrashOrigin::Runtime,
        CrashOrigin::Unknown,
    ] {
        let crash = crash(origin, true);
        let view = triage_disposition(&crash, &finding_proof_card(&crash));
        assert!(
            !view.claim_limit.trim().is_empty(),
            "{origin:?} must state a claim limit"
        );
        assert!(
            !view.action_detail.trim().is_empty(),
            "{origin:?} must state an action detail"
        );
    }
}

#[test]
fn every_disposition_cites_the_evidence_it_was_derived_from() {
    let crash = crash(CrashOrigin::Target, true);
    let view = triage_disposition(&crash, &finding_proof_card(&crash));

    assert!(
        !view.evidence.is_empty(),
        "a determination with no cited evidence is an assertion"
    );
}

#[test]
fn the_queue_orders_by_disposition_then_exploitability_then_identity() {
    let mut open_target = crash(CrashOrigin::Target, true);
    open_target.id = Uuid::from_u128(30);
    let mut harness = crash(CrashOrigin::Harness, true);
    harness.id = Uuid::from_u128(10);
    let mut exploitable = with_casr(crash(CrashOrigin::Target, true), CrashSeverity::Exploitable);
    exploitable.id = Uuid::from_u128(20);

    let mut entries = [harness, open_target, exploitable];
    entries.sort_by_key(|entry| triage_order_key(entry, &finding_proof_card(entry)));

    let order: Vec<u128> = entries.iter().map(|entry| entry.id.as_u128()).collect();
    // Both target faults precede the harness defect; between them, the one
    // CASR classified more severely is opened first.
    assert_eq!(order, vec![20, 30, 10]);
}

#[test]
fn queue_order_does_not_depend_on_input_order() {
    let build = |n: u128, origin: CrashOrigin| {
        let mut item = crash(origin, true);
        item.id = Uuid::from_u128(n);
        item
    };
    let sorted = |mut items: Vec<Crash>| {
        items.sort_by_key(|entry| triage_order_key(entry, &finding_proof_card(entry)));
        items.iter().map(|e| e.id.as_u128()).collect::<Vec<_>>()
    };

    let a = build(5, CrashOrigin::Target);
    let b = build(6, CrashOrigin::Target);
    let c = build(7, CrashOrigin::Unknown);

    assert_eq!(
        sorted(vec![a.clone(), b.clone(), c.clone()]),
        sorted(vec![c, b, a])
    );
}
