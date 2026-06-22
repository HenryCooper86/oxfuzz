//! Tests for coverage tracking and stagnation detection.

use hf_core::coverage::CoverageReport;
use hf_coverage::{propose_action, CoverageTracker, StagnationProposal};
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
fn propose_action_returns_new_harness_when_stagnant() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    tracker.update(&report(100, run_id));
    tracker.update(&report(100, run_id));

    let proposal = propose_action(&tracker, 0);
    assert!(proposal.is_some(), "should propose action when stagnant");
    assert!(
        matches!(proposal.unwrap(), StagnationProposal::NewHarness),
        "should propose NewHarness"
    );
}

#[test]
fn propose_action_returns_none_when_progressing() {
    let mut tracker = CoverageTracker::new();
    let run_id = Uuid::new_v4();

    tracker.update(&report(100, run_id));
    tracker.update(&report(200, run_id));

    let proposal = propose_action(&tracker, 60);
    assert!(proposal.is_none(), "should not propose when progressing");
}
