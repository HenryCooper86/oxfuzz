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

/// Current serialized Coverage Attribution schema.
pub const COVERAGE_ATTRIBUTION_SCHEMA_VERSION: u32 = 1;

/// One candidate's retained-coverage attribution.
///
/// The attribution set is the candidate itself plus its reachable functions;
/// the tier names how much of that set retained measurements cover.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(tag = "tier", rename_all = "snake_case")]
pub enum AttributionTier {
    /// Neither the candidate nor any reachable function is covered: new
    /// ground for the next harness.
    Untouched,
    /// Part of the attribution set is covered and part is not: the frontier
    /// where coverage stalls.
    Partial {
        /// Covered members of the attribution set.
        covered: usize,
        /// Size of the attribution set (the candidate plus its reachables).
        total: usize,
    },
    /// The whole attribution set is covered: saturated for the retained
    /// measurements; another harness here buys nothing until the target code
    /// changes.
    Saturated {
        /// Covered members of the attribution set.
        covered: usize,
        /// Size of the attribution set (the candidate plus its reachables).
        total: usize,
    },
}

/// One discovered candidate with its coverage attribution.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttributionCandidate {
    /// The candidate function.
    pub symbol: String,
    /// The discovery score that ranked it, carried through unchanged.
    pub discovery_score: f64,
    /// How much of the attribution set retained measurements cover.
    pub tier: AttributionTier,
    /// `covered / total` over the attribution set, in `[0, 1]`.
    pub covered_share: f64,
}

/// Everything the attribution ranking reads.
#[derive(Debug, Clone, PartialEq)]
pub struct CoverageAttributionRequest {
    /// Discovery candidates: symbol, discovery score, reachable functions.
    pub ranked_candidates: Vec<(String, f64, Vec<String>)>,
    /// The union of covered functions across every retained measurement.
    pub covered_functions: HashSet<String>,
    /// How many measurements the covered set was unioned from.
    pub measurements: usize,
}

/// Every discovered candidate, attributed and ordered for the next harness.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CoverageAttributionView {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// Whether there was coverage evidence to attribute with.
    pub measurement: SurfaceMeasurement,
    /// Ordered for the next harness: untouched first, then partial, saturated
    /// last. Discovery's judgment leads inside each tier; coverage only
    /// decides which tier a candidate headlines in.
    pub candidates: Vec<AttributionCandidate>,
}

/// Attribute every discovered candidate against the union of retained
/// coverage, and order the result for the next harness.
///
/// The counterpart of [`unreached_surface`] over the whole inventory rather
/// than its uncovered subset: candidates nobody covered, candidates where
/// coverage stalled mid-reach, and candidates the retained measurements
/// already saturate -- which static discovery keeps headlining because its
/// score knows nothing about what has already been exercised. With no
/// measurement the result names why and carries no list, for the same
/// honesty reason as [`unreached_surface`].
#[must_use]
pub fn coverage_attribution(request: &CoverageAttributionRequest) -> CoverageAttributionView {
    if request.measurements == 0 {
        return CoverageAttributionView {
            schema_version: COVERAGE_ATTRIBUTION_SCHEMA_VERSION,
            measurement: SurfaceMeasurement::Unavailable {
                reason: "no_completed_coverage_measurement".to_owned(),
            },
            candidates: Vec::new(),
        };
    }

    // Tier order for the next harness: untouched ground first, the stall
    // frontier next, saturated last. `total_cmp` gives a total order over
    // scores without an Ord bound on f64.
    let next_harness_rank = |tier: &AttributionTier| match tier {
        AttributionTier::Untouched => 0u8,
        AttributionTier::Partial { .. } => 1,
        AttributionTier::Saturated { .. } => 2,
    };

    let mut candidates: Vec<AttributionCandidate> = request
        .ranked_candidates
        .iter()
        .map(|(symbol, score, reachable)| {
            // The candidate itself is a function too: its own coverage counts
            // alongside its reachable set.
            let total = reachable.len() + 1;
            let covered = reachable
                .iter()
                .filter(|function| request.covered_functions.contains(*function))
                .count()
                + usize::from(request.covered_functions.contains(symbol));
            let tier = if covered == 0 {
                AttributionTier::Untouched
            } else if covered == total {
                AttributionTier::Saturated { covered, total }
            } else {
                AttributionTier::Partial { covered, total }
            };
            AttributionCandidate {
                symbol: symbol.clone(),
                discovery_score: *score,
                covered_share: covered as f64 / total as f64,
                tier,
            }
        })
        .collect();

    candidates.sort_by(|a, b| {
        next_harness_rank(&a.tier)
            .cmp(&next_harness_rank(&b.tier))
            .then_with(|| b.discovery_score.total_cmp(&a.discovery_score))
            .then_with(|| a.symbol.cmp(&b.symbol))
    });

    CoverageAttributionView {
        schema_version: COVERAGE_ATTRIBUTION_SCHEMA_VERSION,
        measurement: SurfaceMeasurement::Retained {
            measurements: request.measurements,
        },
        candidates,
    }
}
