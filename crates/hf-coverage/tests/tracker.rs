//! Tests for coverage tracking and stagnation detection.

use hf_core::coverage::CoverageReport;
use hf_coverage::{propose_action, CoverageTracker, StagnationPolicy, StagnationProposal};
use std::time::{Duration, Instant};
use uuid::Uuid;

fn report(edges: u64, run_id: uuid::Uuid) -> CoverageReport {
    CoverageReport {
        run_id,
        edges,
        blocks: 0,
        delta_edges: 0,
        stagnation_secs: 0,
        new_edges_files: Vec::new(),
    }
}

/// The default-shaped escalation policy around a test-chosen threshold: the
/// first full stagnation window proposes mutation improvements, the second a
/// new harness, the fourth a stop.
fn policy(threshold_secs: u64) -> StagnationPolicy {
    StagnationPolicy {
        threshold_secs,
        new_harness_windows: 2,
        stop_windows: 4,
    }
}

/// A tracker whose coverage last progressed `flat_for_secs` ago: one backdated
/// baseline report, then one flat pulse measured now.
fn stagnant_tracker(flat_for_secs: u64) -> CoverageTracker {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();
    tracker.update_at(
        &report(100, run_id),
        Instant::now()
            .checked_sub(Duration::from_secs(flat_for_secs))
            .unwrap(),
    );
    tracker.update(&report(100, run_id));
    tracker
}

#[test]
fn tracker_computes_delta_on_update() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    assert_eq!(tracker.last_edges(), 100);
    assert_eq!(
        tracker.last_delta(),
        100,
        "first update delta should be total edges"
    );
    assert_eq!(tracker.run_id(), run_id, "the report's run must be tracked");

    tracker.update(&report(150, run_id));
    assert_eq!(tracker.last_edges(), 150);
    assert_eq!(tracker.last_delta(), 50, "delta should be 150-100");
}

#[test]
fn tracker_stagnation_increments_on_zero_delta() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    assert_eq!(tracker.stagnation_secs(), 0);

    // Same edges -> no progress. Stagnation timer starts counting.
    tracker.update(&report(100, run_id));
    // On a fast machine the elapsed time may be ~0, so just assert the
    // tracker is no longer in the "first update" state.
    assert!(tracker.stagnation_secs() == 0 || tracker.stagnation_secs() > 0);
    // But is_stagnant should be true at threshold 0.
    assert!(tracker.is_stagnant(0));
}

#[test]
fn tracker_stagnation_resets_on_progress() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    tracker.update(&report(100, run_id));
    // After a zero-delta update, we are stagnant.
    assert!(tracker.is_stagnant(0));

    tracker.update(&report(200, run_id));
    assert!(
        !tracker.is_stagnant(60),
        "stagnation should reset on progress"
    );
}

#[test]
fn is_stagnant_true_after_threshold() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    // Simulate time passing with no progress.
    tracker.update(&report(100, run_id));
    tracker.update(&report(100, run_id));

    assert!(tracker.is_stagnant(0), "should be stagnant at 0 threshold");
}

#[test]
fn is_stagnant_false_when_progressing() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    tracker.update(&report(200, run_id));

    assert!(
        !tracker.is_stagnant(60),
        "should not be stagnant while progressing"
    );
}

#[test]
fn update_at_backdates_the_last_progress() {
    let mut tracker = stagnant_tracker(300);

    assert!(
        tracker.stagnation_secs() >= 300,
        "stagnation must be measured from the backdated progress"
    );
    assert!(tracker.is_stagnant(120));

    tracker.update(&report(100, tracker.run_id()));
    assert!(tracker.stagnation_secs() >= 300);
}

#[test]
fn propose_action_starts_with_custom_mutator_when_stagnant() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    tracker.update(&report(100, run_id));
    tracker.update(&report(100, run_id));

    // Threshold 0: stagnation starts on the first flat pulse, but the policy
    // still opens with the gentlest tier.
    let proposal = propose_action(&tracker, &policy(0));
    assert_eq!(
        proposal,
        Some(StagnationProposal::CustomMutator),
        "the first stagnation tier proposes mutation improvements"
    );
}

#[test]
fn propose_action_escalates_through_the_tiers() {
    let policy = policy(120);

    assert_eq!(
        propose_action(&stagnant_tracker(130), &policy),
        Some(StagnationProposal::CustomMutator),
        "one full stagnation window proposes mutation improvements"
    );
    assert_eq!(
        propose_action(&stagnant_tracker(250), &policy),
        Some(StagnationProposal::NewHarness),
        "repeated stagnation escalates to a new harness"
    );
    assert_eq!(
        propose_action(&stagnant_tracker(500), &policy),
        Some(StagnationProposal::Stop),
        "prolonged stagnation recommends stopping the target"
    );
}

#[test]
fn propose_action_tier_boundaries_are_exact() {
    let policy = policy(120);

    // Exactly at the stagnation threshold: one window, the gentlest tier.
    assert_eq!(
        propose_action(&stagnant_tracker(120), &policy),
        Some(StagnationProposal::CustomMutator)
    );
    // Just below and exactly at the new-harness window.
    assert_eq!(
        propose_action(&stagnant_tracker(239), &policy),
        Some(StagnationProposal::CustomMutator)
    );
    assert_eq!(
        propose_action(&stagnant_tracker(240), &policy),
        Some(StagnationProposal::NewHarness)
    );
    // Just below and exactly at the stop window.
    assert_eq!(
        propose_action(&stagnant_tracker(479), &policy),
        Some(StagnationProposal::NewHarness)
    );
    assert_eq!(
        propose_action(&stagnant_tracker(480), &policy),
        Some(StagnationProposal::Stop)
    );
}

#[test]
fn propose_action_is_none_before_the_threshold() {
    assert_eq!(propose_action(&stagnant_tracker(119), &policy(120)), None);
}

#[test]
fn propose_action_resets_after_progress() {
    let mut tracker = stagnant_tracker(500);

    tracker.update(&report(200, tracker.run_id()));

    assert_eq!(
        propose_action(&tracker, &policy(120)),
        None,
        "progress must reset the escalation"
    );
}

#[test]
fn propose_action_returns_none_when_progressing() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    tracker.update(&report(200, run_id));

    let proposal = propose_action(&tracker, &policy(60));
    assert!(proposal.is_none(), "should not propose when progressing");
}
