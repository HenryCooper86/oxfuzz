//! Service-owned unreached-surface ranking.
//!
//! `coverage_blockers` answers "what is the current harness failing to reach?"
//! -- uncovered functions with an observed call path from covered code. That
//! question presupposes a harness that already reaches nearby.
//!
//! This module answers the prior one: which entry points has no harness ever
//! reached at all, and which deserves the next harness. A parser no run has
//! ever touched does not appear in a blocker list, because a blocker list is
//! computed relative to what one harness covered.
//!
//! See `docs/design/unreached-surface-design.md`.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

/// Current serialized Unreached Surface schema.
pub const UNREACHED_SURFACE_SCHEMA_VERSION: u32 = 1;

/// Whether the project has coverage evidence to judge absence against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SurfaceMeasurement {
    /// No completed coverage measurement exists for the project.
    Unavailable {
        /// Stable reason code.
        reason: String,
    },
    /// At least one measurement is retained.
    Retained {
        /// How many measurements the covered set was unioned from.
        measurements: usize,
    },
}

/// What has already been tried against a candidate.
///
/// Declaration order is the tie-break order: effort not yet spent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AttemptHistory {
    /// No harness names this candidate.
    NeverAttempted,
    /// A harness was drafted and did not compile.
    AttemptedCompileFailed {
        /// How many harnesses were drafted.
        attempts: usize,
    },
    /// A harness compiled and did not pass smoke qualification.
    AttemptedSmokeFailed {
        /// How many harnesses were drafted.
        attempts: usize,
    },
    /// A harness reached qualification, yet the function is absent from every
    /// coverage union: it runs and does not exercise what it was written for,
    /// so the next harness needs a different shape rather than a fix.
    QualifiedYetUnreached {
        /// How many harnesses were drafted.
        attempts: usize,
    },
}

/// One candidate no retained measurement has ever covered.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UnreachedCandidate {
    /// The candidate function.
    pub symbol: String,
    /// The discovery score that ranked it, carried through unchanged.
    pub discovery_score: f64,
    /// What has already been tried here.
    pub attempt: AttemptHistory,
}

/// Everything the ranking reads.
#[derive(Debug, Clone, PartialEq)]
pub struct UnreachedSurfaceRequest {
    /// Discovery candidates and their scores, in discovery's own order.
    pub ranked_candidates: Vec<(String, f64)>,
    /// The union of covered functions across every retained measurement.
    pub covered_functions: HashSet<String>,
    /// Attempt history by candidate symbol.
    pub attempts: HashMap<String, AttemptHistory>,
    /// How many measurements the covered set was unioned from.
    pub measurements: usize,
}

/// Ranked entry points that no retained measurement has covered.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct UnreachedSurfaceView {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// Whether there was anything to judge absence against.
    pub measurement: SurfaceMeasurement,
    /// The ranked candidates. Empty when no measurement exists.
    pub candidates: Vec<UnreachedCandidate>,
}

/// Rank the entry points no retained measurement has ever covered.
///
/// With no measurement the result names why and carries no list. Absence from
/// a covered set is a statement about what was measured; derived from zero
/// measurements it would name every function in the project, which would be
/// fabrication presented as analysis.
#[must_use]
pub fn unreached_surface(request: &UnreachedSurfaceRequest) -> UnreachedSurfaceView {
    if request.measurements == 0 {
        return UnreachedSurfaceView {
            schema_version: UNREACHED_SURFACE_SCHEMA_VERSION,
            measurement: SurfaceMeasurement::Unavailable {
                reason: "no_completed_coverage_measurement".to_owned(),
            },
            candidates: Vec::new(),
        };
    }

    let mut candidates: Vec<UnreachedCandidate> = request
        .ranked_candidates
        .iter()
        .filter(|(symbol, _)| !request.covered_functions.contains(symbol))
        .map(|(symbol, score)| UnreachedCandidate {
            symbol: symbol.clone(),
            discovery_score: *score,
            attempt: request
                .attempts
                .get(symbol)
                .copied()
                .unwrap_or(AttemptHistory::NeverAttempted),
        })
        .collect();

    // Discovery's judgment leads; attempt history only orders the ties, which
    // are real because candidates frequently share a score. `total_cmp` gives a
    // total order over scores without an Ord bound on f64.
    candidates.sort_by(|a, b| {
        b.discovery_score
            .total_cmp(&a.discovery_score)
            .then_with(|| a.attempt.cmp(&b.attempt))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });

    UnreachedSurfaceView {
        schema_version: UNREACHED_SURFACE_SCHEMA_VERSION,
        measurement: SurfaceMeasurement::Retained {
            measurements: request.measurements,
        },
        candidates,
    }
}
