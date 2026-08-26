//! Run Closeout domain contract.
//!
//! The ladder is fixed by data dependency, a skipped step is not a failed one,
//! and a failure only stops the steps that consume its output.

#![cfg(feature = "run-closeout")]

use hf_service::run_closeout::{
    blocked_by, closeout_ladder, pending_steps, CloseoutStep, StepOutcome,
};

fn completed(step: CloseoutStep) -> (CloseoutStep, StepOutcome) {
    (
        step,
        StepOutcome::Completed {
            detail: "done".to_owned(),
        },
    )
}

fn failed(step: CloseoutStep) -> (CloseoutStep, StepOutcome) {
    (
        step,
        StepOutcome::Failed {
            error: "boom".to_owned(),
        },
    )
}

fn skipped(step: CloseoutStep) -> (CloseoutStep, StepOutcome) {
    (
        step,
        StepOutcome::Skipped {
            reason: "nothing to do".to_owned(),
        },
    )
}

#[test]
fn the_ladder_is_ordered_by_data_dependency() {
    let ladder = closeout_ladder();

    assert_eq!(
        ladder,
        vec![
            CloseoutStep::Triage,
            CloseoutStep::Minimize,
            CloseoutStep::CorpusAbsorb,
            CloseoutStep::Coverage,
            CloseoutStep::Blockers,
            CloseoutStep::Disposition,
            CloseoutStep::TrustReport,
        ]
    );
}

#[test]
fn coverage_follows_corpus_absorption_because_it_measures_against_it() {
    let ladder = closeout_ladder();
    let position = |step: CloseoutStep| ladder.iter().position(|s| *s == step).unwrap();

    assert!(position(CloseoutStep::CorpusAbsorb) < position(CloseoutStep::Coverage));
    assert!(position(CloseoutStep::Coverage) < position(CloseoutStep::Blockers));
    assert_eq!(
        position(CloseoutStep::TrustReport),
        ladder.len() - 1,
        "the trust report audits the closeout that produced it, so it is last"
    );
}

#[test]
fn a_fresh_run_has_every_step_pending() {
    assert_eq!(pending_steps(&[]), closeout_ladder());
}

#[test]
fn an_interrupted_closeout_resumes_at_the_first_non_terminal_step() {
    let done = [
        completed(CloseoutStep::Triage),
        skipped(CloseoutStep::Minimize),
        completed(CloseoutStep::CorpusAbsorb),
        completed(CloseoutStep::Coverage),
    ];

    assert_eq!(
        pending_steps(&done),
        vec![
            CloseoutStep::Blockers,
            CloseoutStep::Disposition,
            CloseoutStep::TrustReport,
        ]
    );
}

#[test]
fn a_skipped_step_is_terminal_and_is_not_retried() {
    let done = [
        completed(CloseoutStep::Triage),
        skipped(CloseoutStep::Minimize),
    ];

    assert!(
        !pending_steps(&done).contains(&CloseoutStep::Minimize),
        "there was nothing to minimize; that is an answer, not an omission"
    );
}

#[test]
fn a_failed_step_is_retried_by_a_later_closeout() {
    let done = [
        completed(CloseoutStep::Triage),
        failed(CloseoutStep::Minimize),
    ];

    assert!(pending_steps(&done).contains(&CloseoutStep::Minimize));
}

#[test]
fn a_fully_terminal_closeout_has_nothing_pending() {
    let done: Vec<_> = closeout_ladder().into_iter().map(completed).collect();

    assert!(
        pending_steps(&done).is_empty(),
        "re-running a completed closeout is a no-op over the retained result"
    );
}

#[test]
fn a_failure_blocks_only_the_steps_that_consume_its_output() {
    let done = [
        completed(CloseoutStep::Triage),
        failed(CloseoutStep::Coverage),
    ];

    assert_eq!(
        blocked_by(CloseoutStep::Blockers, &done),
        Some(CloseoutStep::Coverage),
        "blockers read the coverage measurement"
    );
    assert_eq!(
        blocked_by(CloseoutStep::Disposition, &done),
        None,
        "disposition does not consume coverage, so it still runs"
    );
}

#[test]
fn the_trust_report_runs_even_when_earlier_steps_failed() {
    let done = [
        failed(CloseoutStep::Triage),
        failed(CloseoutStep::Coverage),
        failed(CloseoutStep::CorpusAbsorb),
    ];

    assert_eq!(
        blocked_by(CloseoutStep::TrustReport, &done),
        None,
        "a failed step must appear as an unavailable gate, not be silently absent"
    );
}

#[test]
fn a_step_whose_dependency_never_ran_is_not_reported_as_blocked() {
    // Nothing has run yet: the chain is about to start, not obstructed.
    assert_eq!(blocked_by(CloseoutStep::Blockers, &[]), None);
}
