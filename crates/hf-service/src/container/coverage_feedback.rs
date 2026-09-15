//! Live coverage measurements and advisory stagnation notifications.

use hf_core::engine::FuzzProgress;
use uuid::Uuid;

/// Coverage-guided feedback for a live fuzz run.
///
/// Feeds each streamed edge reading into a [`hf_coverage::CoverageTracker`]
/// and, while coverage stays flat, surfaces an escalating
/// [`StagnationProposal`](hf_coverage::StagnationProposal) to the user: a live
/// log line each time the proposal escalates a tier (improve the mutation
/// inputs -> regenerate the harness -> stop the target), and the highest
/// tier reached on the final [`super::RunSummary`]. This realizes the coverage
/// feedback loop from `docs/design/corpus-coverage-design.md` §4: we detect
/// stagnation and *propose* iterating rather than regenerating a harness
/// autonomously, which would bypass the human-in-the-loop review that harness
/// execution requires (Engineering Protocol §2.12).
pub(super) struct CoverageFeedback<'a> {
    /// The run the streamed edge readings are measured for.
    run_id: Uuid,
    tracker: std::sync::Mutex<hf_coverage::CoverageTracker>,
    /// Latched proposal: the highest tier surfaced so far, so each tier is
    /// proposed at most once.
    proposal: std::sync::Mutex<Option<hf_coverage::StagnationProposal>>,
    policy: hf_coverage::StagnationPolicy,
    emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
}

impl<'a> CoverageFeedback<'a> {
    pub(super) fn new(
        run_id: Uuid,
        policy: hf_coverage::StagnationPolicy,
        emit: &'a (dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Self {
        Self {
            run_id,
            tracker: std::sync::Mutex::new(hf_coverage::CoverageTracker::new()),
            proposal: std::sync::Mutex::new(None),
            policy,
            emit,
        }
    }

    /// Record a cumulative edge count from a stat pulse and, whenever the
    /// stagnation proposal escalates to a tier not yet surfaced, emit and
    /// latch it.
    pub(super) fn on_edges(&self, edges: u64) {
        let Ok(mut tracker) = self.tracker.lock() else {
            return;
        };
        tracker.update(&hf_core::coverage::CoverageReport {
            run_id: self.run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        });
        let Some(proposal) = hf_coverage::propose_action(&tracker, &self.policy) else {
            return;
        };
        let Ok(mut slot) = self.proposal.lock() else {
            return;
        };
        // Only a tier not yet surfaced is announced.
        if slot
            .as_ref()
            .is_some_and(|previous| proposal_priority(previous) >= proposal_priority(&proposal))
        {
            return;
        }
        let message = format!(
            "[coverage] no new edges for {}s -- {}",
            tracker.stagnation_secs(),
            describe_proposal(&proposal),
        );
        *slot = Some(proposal);
        drop(slot);
        drop(tracker);
        (self.emit)(FuzzProgress::LogLine(message));
    }

    /// The highest proposal tier surfaced during the run, if any.
    pub(super) fn proposal(&self) -> Option<hf_coverage::StagnationProposal> {
        // A poisoned feedback lock makes the advisory proposal unavailable.
        self.proposal.lock().ok().and_then(|p| p.clone())
    }
}

fn proposal_priority(proposal: &hf_coverage::StagnationProposal) -> u8 {
    match proposal {
        hf_coverage::StagnationProposal::CustomMutator => 0,
        hf_coverage::StagnationProposal::NewHarness => 1,
        hf_coverage::StagnationProposal::Stop => 2,
    }
}

/// A short, user-facing description of a stagnation proposal for the run log.
fn describe_proposal(proposal: &hf_coverage::StagnationProposal) -> &'static str {
    match proposal {
        hf_coverage::StagnationProposal::NewHarness => {
            "consider regenerating the harness to reach new code paths"
        }
        hf_coverage::StagnationProposal::CustomMutator => {
            "consider adding seeds, a dictionary, or a custom mutator"
        }
        hf_coverage::StagnationProposal::Stop => "consider stopping this target",
    }
}

#[cfg(test)]
mod coverage_feedback_tests {
    use super::{CoverageFeedback, FuzzProgress};
    use hf_coverage::{StagnationPolicy, StagnationProposal};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    fn policy(threshold_secs: u64) -> StagnationPolicy {
        StagnationPolicy {
            threshold_secs,
            new_harness_windows: 2,
            stop_windows: 3,
        }
    }

    fn log_line_count(emitted: &Mutex<Vec<FuzzProgress>>) -> usize {
        emitted
            .lock()
            .unwrap()
            .iter()
            .filter(|p| matches!(p, FuzzProgress::LogLine(_)))
            .count()
    }

    /// An instant `secs` in the past, for deterministic stagnation aging.
    fn backdated(secs: u64) -> Instant {
        Instant::now()
            .checked_sub(Duration::from_secs(secs))
            .unwrap()
    }

    #[test]
    fn proposes_once_when_edges_plateau() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        // threshold 0: the first flat pulse after the initial reading is stagnant.
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        fb.on_edges(100); // first reading -- never stagnant (needs >1 update)
        assert_eq!(fb.proposal(), None);
        fb.on_edges(100); // flat -> stagnant -> propose the first tier
        fb.on_edges(100); // still flat, same tier -> must NOT propose again (latched)

        assert_eq!(fb.proposal(), Some(StagnationProposal::CustomMutator));
        assert_eq!(
            log_line_count(&emitted),
            1,
            "the proposal must be surfaced exactly once"
        );
    }

    #[test]
    fn escalates_the_proposal_as_stagnation_drags_on() {
        let emitted: Mutex<Vec<FuzzProgress>> = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(100), &emit);
        let report = |edges| hf_core::coverage::CoverageReport {
            run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        };

        // Coverage last progressed 150s ago: one full 100s stagnation window.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(100), backdated(150));
        fb.on_edges(100);
        assert_eq!(fb.proposal(), Some(StagnationProposal::CustomMutator));

        // 250s flat: the second window escalates to a new-harness proposal.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(101), backdated(250));
        fb.on_edges(101);
        assert_eq!(fb.proposal(), Some(StagnationProposal::NewHarness));

        // 350s flat: the third window recommends stopping the target.
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(102), backdated(350));
        fb.on_edges(102);
        fb.on_edges(102); // same tier again -> not re-surfaced
        assert_eq!(fb.proposal(), Some(StagnationProposal::Stop));

        assert_eq!(
            log_line_count(&emitted),
            3,
            "each escalation tier must be surfaced exactly once"
        );
    }

    #[test]
    fn later_plateau_does_not_lower_the_highest_proposal() {
        let emitted = Mutex::new(Vec::new());
        let emit = |p: FuzzProgress| emitted.lock().unwrap().push(p);
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(100), &emit);
        let report = |edges| hf_core::coverage::CoverageReport {
            run_id,
            edges,
            blocks: 0,
            delta_edges: 0,
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        };
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(100), backdated(350));
        fb.on_edges(100);
        assert_eq!(fb.proposal(), Some(StagnationProposal::Stop));
        fb.tracker
            .lock()
            .unwrap()
            .update_at(&report(200), backdated(150));
        fb.on_edges(200);
        assert_eq!(fb.proposal(), Some(StagnationProposal::Stop));
        assert_eq!(log_line_count(&emitted), 1);
    }

    #[test]
    fn callback_observes_committed_proposal_without_holding_feedback_locks() {
        let feedback: std::sync::OnceLock<&CoverageFeedback<'_>> = std::sync::OnceLock::new();
        let emit = |_p: FuzzProgress| {
            let current = feedback.get().unwrap();
            assert!(current.tracker.try_lock().is_ok());
            let proposal = current
                .proposal
                .try_lock()
                .expect("callback must not hold proposal lock");
            assert_eq!(*proposal, Some(StagnationProposal::CustomMutator));
        };
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        assert!(feedback.set(&fb).is_ok());
        fb.on_edges(100);
        fb.on_edges(100);
    }

    #[test]
    fn no_proposal_on_a_single_reading() {
        let emit = |_p: FuzzProgress| {};
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(0), &emit);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn threshold_gates_the_proposal() {
        let emit = |_p: FuzzProgress| {};
        // A high threshold is not reached in the test's wall-clock window, so a
        // flat plateau does not (yet) propose.
        let fb = CoverageFeedback::new(uuid::Uuid::new_v4(), policy(3600), &emit);
        fb.on_edges(100);
        fb.on_edges(100);
        assert_eq!(fb.proposal(), None);
    }

    #[test]
    fn coverage_report_carries_the_run_id() {
        // The report fed to the tracker must name the run the coverage was
        // measured for, not the nil UUID.
        let emit = |_p: FuzzProgress| {};
        let run_id = uuid::Uuid::new_v4();
        let fb = CoverageFeedback::new(run_id, policy(0), &emit);
        fb.on_edges(100);
        assert_eq!(fb.tracker.lock().unwrap().run_id(), run_id);
    }
}
