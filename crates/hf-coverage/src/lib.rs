//! hf-coverage: Coverage delta tracking and stagnation detection.
//!
//! See `docs/design/corpus-coverage-design.md`.

use std::time::{Duration, Instant};

use hf_core::coverage::CoverageReport;

/// A proposal when coverage stagnates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StagnationProposal {
    /// Generate a new harness variant for the target.
    NewHarness,
    /// Suggest a custom mutator or dictionary.
    CustomMutator,
    /// Stop fuzzing this target.
    Stop,
}

/// Tracks coverage deltas over time to detect stagnation.
pub struct CoverageTracker {
    last_edges: u64,
    last_delta: i64,
    last_progress: Instant,
    update_count: u64,
}

impl CoverageTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_edges: 0,
            last_delta: 0,
            last_progress: Instant::now(),
            update_count: 0,
        }
    }

    /// Record a new coverage report and compute the delta.
    pub fn update(&mut self, report: &CoverageReport) {
        let new_edges = report.edges;
        self.last_delta = new_edges.cast_signed() - self.last_edges.cast_signed();
        if self.last_delta > 0 {
            self.last_progress = Instant::now();
        }
        self.last_edges = new_edges;
        self.update_count += 1;
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

/// Propose an action when coverage stagnates.
///
/// Returns `None` if coverage is still progressing.
#[must_use]
pub fn propose_action(
    tracker: &CoverageTracker,
    threshold_secs: u64,
) -> Option<StagnationProposal> {
    if tracker.is_stagnant(threshold_secs) {
        Some(StagnationProposal::NewHarness)
    } else {
        None
    }
}

#[allow(dead_code)]
fn _ensure_duration_used(_d: Duration) {}
