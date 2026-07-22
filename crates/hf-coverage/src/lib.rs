//! hf-coverage: Coverage delta tracking and stagnation detection.
//!
//! See `docs/design/corpus-coverage-design.md`.

use std::time::Instant;

use hf_core::coverage::CoverageReport;
use uuid::Uuid;

mod summary;
pub use summary::{
    parse_llvm_cov_summary, parse_llvm_cov_uncovered, CoverageSummary, UncoveredRegion,
};

#[cfg(feature = "campaign-advisor")]
pub mod campaign_advisor;

/// A proposal when coverage stagnates.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagnationProposal {
    /// Generate a new harness variant for the target.
    NewHarness,
    /// Improve the mutation inputs: add seeds, a dictionary, or a custom
    /// mutator.
    CustomMutator,
    /// Stop fuzzing this target.
    Stop,
}

/// Escalation policy for stagnation proposals.
///
/// While a run's coverage stays flat, [`propose_action`] escalates through the
/// [`StagnationProposal`] tiers by counting whole stagnation windows -- each
/// `threshold_secs` long -- since coverage last progressed:
///
/// - below `new_harness_windows` windows: improve the mutation inputs
///   ([`StagnationProposal::CustomMutator`]);
/// - at least `new_harness_windows` windows: regenerate the harness
///   ([`StagnationProposal::NewHarness`]);
/// - at least `stop_windows` windows: recommend stopping the target
///   ([`StagnationProposal::Stop`]).
///
/// Callers must keep `1 <= new_harness_windows < stop_windows`; otherwise the
/// harness tier is unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagnationPolicy {
    /// Seconds without a positive edge delta before coverage counts as
    /// stagnant. This is also the length of one escalation window; `0`
    /// proposes immediately and measures windows in whole seconds.
    pub threshold_secs: u64,
    /// Stagnation windows at which the proposal escalates from improving the
    /// mutation inputs to regenerating the harness.
    pub new_harness_windows: u64,
    /// Stagnation windows at which the proposal escalates to recommending a
    /// stop.
    pub stop_windows: u64,
}

/// Tracks coverage deltas over time to detect stagnation.
pub struct CoverageTracker {
    /// The run the most recent report was measured for (`nil` before the
    /// first update).
    run_id: Uuid,
    last_edges: u64,
    last_delta: i64,
    last_progress: Instant,
    update_count: u64,
}

impl CoverageTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            run_id: Uuid::nil(),
            last_edges: 0,
            last_delta: 0,
            last_progress: Instant::now(),
            update_count: 0,
        }
    }

    /// Record a new coverage report and compute the delta.
    pub fn update(&mut self, report: &CoverageReport) {
        self.update_at(report, Instant::now());
    }

    /// Record a coverage report as measured at `at`, rather than now.
    ///
    /// Stagnation is measured from the last positive delta, so backdating a
    /// progressing report backdates the stagnation clock as well. Used for
    /// replayed/imported readings and for deterministic escalation tests.
    pub fn update_at(&mut self, report: &CoverageReport, at: Instant) {
        let new_edges = report.edges;
        self.run_id = report.run_id;
        self.last_delta = new_edges.cast_signed() - self.last_edges.cast_signed();
        if self.last_delta > 0 {
            self.last_progress = at;
        }
        self.last_edges = new_edges;
        self.update_count += 1;
    }

    /// The run the most recent report was measured for.
    #[must_use]
    pub fn run_id(&self) -> Uuid {
        self.run_id
    }

    /// Returns the last edge count.
    #[must_use]
    pub fn last_edges(&self) -> u64 {
        self.last_edges
    }

    /// Returns the last delta (positive = progress).
    #[must_use]
    pub fn last_delta(&self) -> i64 {
        self.last_delta
    }

    /// Seconds since the last positive delta.
    #[must_use]
    pub fn stagnation_secs(&self) -> u64 {
        // If we've never had progress (first update), stagnation is 0.
        if self.update_count <= 1 {
            return 0;
        }
        self.last_progress.elapsed().as_secs()
    }

    /// Returns true if coverage has been stagnant for at least `threshold` seconds.
    #[must_use]
    pub fn is_stagnant(&self, threshold_secs: u64) -> bool {
        if self.update_count <= 1 {
            return false;
        }
        self.stagnation_secs() >= threshold_secs
    }
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Propose an action when coverage stagnates, escalating per `policy`.
///
/// Returns `None` if coverage is still progressing (or has not been flat for
/// `policy.threshold_secs` yet). See [`StagnationPolicy`] for the tier ladder.
#[must_use]
pub fn propose_action(
    tracker: &CoverageTracker,
    policy: &StagnationPolicy,
) -> Option<StagnationProposal> {
    if !tracker.is_stagnant(policy.threshold_secs) {
        return None;
    }
    // Whole stagnation windows elapsed since coverage last progressed. The
    // window length is the threshold, floored at one second so a zero
    // threshold (propose immediately) still has a defined escalation pace.
    let windows = tracker.stagnation_secs() / policy.threshold_secs.max(1);
    if windows >= policy.stop_windows {
        Some(StagnationProposal::Stop)
    } else if windows >= policy.new_harness_windows {
        Some(StagnationProposal::NewHarness)
    } else {
        Some(StagnationProposal::CustomMutator)
    }
}
