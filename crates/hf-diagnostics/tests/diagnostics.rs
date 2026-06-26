//! Tests for cost tracking and run journaling.

use hf_core::types::TokenUsage;
use hf_diagnostics::{CostTracker, RunEvent, RunJournal};
use uuid::Uuid;

#[test]
fn cost_tracker_records_and_summarizes() {
    let mut tracker = CostTracker::new();
    tracker.record(
        "openai",
        &TokenUsage {
            input_tokens: 1000,
            output_tokens: 500,
            ..Default::default()
        },
        0.005,
        0.015,
    );
    tracker.record(
        "anthropic",
        &TokenUsage {
            input_tokens: 2000,
            output_tokens: 1000,
            ..Default::default()
        },
        0.003,
        0.015,
    );

    let summary = tracker.summary();
    assert_eq!(summary.total_tokens, 4500);
    // cost = (1000/1000 * 0.005) + (500/1000 * 0.015) + (2000/1000 * 0.003) + (1000/1000 * 0.015)
    //      = 0.005 + 0.0075 + 0.006 + 0.015 = 0.0335
    assert!(
        (summary.total_cost - 0.0335).abs() < 1e-6,
        "cost: {}",
        summary.total_cost
    );
    assert_eq!(summary.by_provider.len(), 2);
}

#[test]
fn cost_tracker_empty_summary() {
    let tracker = CostTracker::new();
    let summary = tracker.summary();
    assert_eq!(summary.total_tokens, 0);
    assert!(summary.total_cost.abs() < f64::EPSILON);
}

#[test]
fn run_journal_records_and_replays() {
    let mut journal = RunJournal::new();
    let run_id = Uuid::new_v4();
    journal.record(RunEvent::Started {
        run_id,
        target: "parse_value".to_owned(),
    });
    journal.record(RunEvent::Progress {
        run_id,
        edges: 100,
        execs_per_sec: 5000.0,
    });
    journal.record(RunEvent::Crash {
        run_id,
        kind: "Asan".to_owned(),
    });
    journal.record(RunEvent::Finished { run_id });

    let events = journal.replay();
    assert_eq!(events.len(), 4);
    assert!(matches!(events[0], RunEvent::Started { .. }));
    assert!(matches!(events[3], RunEvent::Finished { .. }));
}

#[test]
fn run_journal_empty_replay() {
    let journal = RunJournal::new();
    assert!(journal.replay().is_empty());
}

#[test]
fn run_journal_replay_preserves_order() {
    let mut journal = RunJournal::new();
    let run_id = Uuid::new_v4();
    journal.record(RunEvent::Started {
        run_id,
        target: "a".to_owned(),
    });
    journal.record(RunEvent::Started {
        run_id,
        target: "b".to_owned(),
    });
    journal.record(RunEvent::Started {
        run_id,
        target: "c".to_owned(),
    });

    let events = journal.replay();
    assert_eq!(events.len(), 3);
    // Verify order is preserved.
    if let RunEvent::Started { target, .. } = &events[0] {
        assert_eq!(target, "a");
    }
    if let RunEvent::Started { target, .. } = &events[2] {
        assert_eq!(target, "c");
    }
}
