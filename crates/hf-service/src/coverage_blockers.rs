//! Find the uncovered functions worth attacking, and propose one experiment.
//!
//! "62% of lines" says nothing about what to do next. This module names the
//! uncovered functions that would unlock the most still-unreached code, shows
//! how far each sits from where the fuzzer actually got to, and proposes a
//! single typed next experiment. It proposes only: refining a harness and
//! growing a corpus already have approved paths.
//!
//! Everything here is a pure function over a coverage measurement and the
//! discovery call graph. Nothing executes.
//!
//! See `docs/design/coverage-blocker-design.md`.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use hf_coverage::UncoveredRegion;
use serde::Serialize;

/// Schema version of the blocker view.
pub const COVERAGE_BLOCKER_SCHEMA_VERSION: u32 = 1;

/// Cap on reported blockers, so a large binary cannot flood the view.
pub const MAX_BLOCKERS: usize = 50;

/// One uncovered function worth attacking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageBlocker {
    pub function: String,
    /// `file:line` of its first uncovered region, when llvm-cov recorded one.
    pub location: Option<String>,
    /// Still-uncovered project functions transitively reachable from here,
    /// excluding this one. The leverage of reaching it.
    pub unlocked_uncovered: usize,
    /// Shortest call-edge distance from a covered function. `None` means no
    /// observed route at all, which is a different statement from "nearby".
    pub frontier_distance: Option<usize>,
    /// The covered function the distance was measured from.
    pub nearest_covered: Option<String>,
    /// Call path from that covered function to this one. Empty when there is no
    /// observed route.
    pub path: Vec<String>,
}

/// The kind of experiment the evidence supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NextExperimentKind {
    /// The top blocker has an observed route: the fuzzer reaches the caller but
    /// never takes the branch, which is an input problem.
    GrowCorpus,
    /// The top blocker has no observed route: no input to this harness gets
    /// there, so the harness shape is the problem.
    RefineHarness,
    /// No measurement, or nothing uncovered.
    NoExperimentAvailable,
}

/// One typed, deterministic proposal. It starts nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NextExperiment {
    pub kind: NextExperimentKind,
    /// The function to aim at, which is not always the ranked blocker.
    pub target_function: Option<String>,
    pub reason_code: String,
}

/// Whether a coverage measurement backs this view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum MeasurementStatus {
    /// A measurement exists, taken against this corpus-plus-harness signature.
    Available { signature: String },
    /// No measurement exists. A blocker list derived from none would be
    /// fabrication, so none is produced.
    Unavailable { reason_code: String },
}

/// Request to explore a target's coverage blockers.
#[derive(Debug, Clone, serde::Deserialize, Serialize)]
pub struct CoverageBlockerRequest {
    pub project: String,
    pub target: String,
    pub lang: hf_core::target::TargetLanguage,
}

/// Service-owned view of a target's coverage blockers and next experiment.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageBlockerView {
    pub schema_version: u32,
    pub measurement: MeasurementStatus,
    /// Empty whenever no measurement backs the view.
    pub blockers: Vec<CoverageBlocker>,
    pub experiment: NextExperiment,
}

/// Find and rank the uncovered functions worth attacking.
///
/// Ranked by unlocked reach, then shorter frontier distance (unavailable last),
/// then function name for stability.
#[must_use]
pub fn explore_blockers<S: std::hash::BuildHasher>(
    covered: &[String],
    uncovered: &[UncoveredRegion],
    call_graph: &HashMap<String, Vec<String>, S>,
) -> Vec<CoverageBlocker> {
    let covered_set: HashSet<&str> = covered.iter().map(String::as_str).collect();

    // First uncovered region per function, in llvm-cov's order.
    let mut locations: HashMap<&str, &UncoveredRegion> = HashMap::new();
    let mut functions: Vec<&str> = Vec::new();
    for region in uncovered {
        if covered_set.contains(region.function.as_str()) {
            continue;
        }
        if locations.insert(region.function.as_str(), region).is_none() {
            functions.push(region.function.as_str());
        }
    }
    let uncovered_set: HashSet<&str> = functions.iter().copied().collect();
    let routes = shortest_routes_from_covered(&covered_set, call_graph);

    let mut blockers: Vec<CoverageBlocker> = functions
        .iter()
        .map(|function| {
            let region = locations.get(function).copied();
            let route = routes.get(*function);
            CoverageBlocker {
                function: (*function).to_owned(),
                location: region.and_then(|region| {
                    (!region.file.is_empty()).then(|| format!("{}:{}", region.file, region.line))
                }),
                unlocked_uncovered: unlocked_reach(function, call_graph, &uncovered_set),
                frontier_distance: route.map(|path| path.len().saturating_sub(1)),
                nearest_covered: route.and_then(|path| path.first().cloned()),
                path: route.cloned().unwrap_or_default(),
            }
        })
        .collect();

    blockers.sort_by(|a, b| {
        b.unlocked_uncovered
            .cmp(&a.unlocked_uncovered)
            // An unavailable distance ranks after every known one.
            .then_with(|| {
                distance_key(a.frontier_distance).cmp(&distance_key(b.frontier_distance))
            })
            .then_with(|| a.function.cmp(&b.function))
    });
    blockers.truncate(MAX_BLOCKERS);
    blockers
}

/// Choose one experiment from the ranked blockers.
///
/// A blocker with an observed route is an input problem, and the proposal aims
/// at the first uncovered function on that route rather than the ranked
/// blocker: that nearer function is what an input actually has to reach first.
#[must_use]
pub fn propose_experiment(blockers: &[CoverageBlocker]) -> NextExperiment {
    let Some(top) = blockers.first() else {
        return NextExperiment {
            kind: NextExperimentKind::NoExperimentAvailable,
            target_function: None,
            reason_code: "no_uncovered_blocker".to_owned(),
        };
    };
    if top.frontier_distance.is_some() {
        // The path runs covered -> ... -> blocker and may pass through further
        // covered functions. Aim at the first *uncovered* one: that is the
        // first thing an input actually has to reach. Uncovered-ness is known
        // only from the measurement, so the blocker set is the evidence.
        let known: HashSet<&str> = blockers
            .iter()
            .map(|blocker| blocker.function.as_str())
            .collect();
        let aim = top
            .path
            .iter()
            .skip(1)
            .find(|step| known.contains(step.as_str()))
            .cloned()
            .unwrap_or_else(|| top.function.clone());
        return NextExperiment {
            kind: NextExperimentKind::GrowCorpus,
            target_function: Some(aim),
            reason_code: "observed_route_from_covered_code".to_owned(),
        };
    }
    NextExperiment {
        kind: NextExperimentKind::RefineHarness,
        target_function: Some(top.function.clone()),
        reason_code: "no_observed_route_from_covered_code".to_owned(),
    }
}

/// Sort key that places `None` after every `Some`.
fn distance_key(distance: Option<usize>) -> (u8, usize) {
    match distance {
        Some(value) => (0, value),
        None => (1, 0),
    }
}

/// Still-uncovered functions transitively reachable from `start`, excluding
/// `start`. Cycle-safe.
fn unlocked_reach<S: std::hash::BuildHasher>(
    start: &str,
    call_graph: &HashMap<String, Vec<String>, S>,
    uncovered: &HashSet<&str>,
) -> usize {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(start);
    let mut visited: HashSet<&str> = HashSet::from([start]);
    while let Some(name) = queue.pop_front() {
        let Some(callees) = call_graph.get(name) else {
            continue;
        };
        for callee in callees {
            let callee = callee.as_str();
            if !visited.insert(callee) {
                continue;
            }
            if callee != start && uncovered.contains(callee) {
                seen.insert(callee);
            }
            queue.push_back(callee);
        }
    }
    seen.len()
}

/// Shortest call path from any covered function to each reachable function.
///
/// A breadth-first walk seeded with every covered function, so the first time a
/// function is reached is by a shortest route. The returned path starts at the
/// covered function it was reached from.
fn shortest_routes_from_covered<S: std::hash::BuildHasher>(
    covered: &HashSet<&str>,
    call_graph: &HashMap<String, Vec<String>, S>,
) -> HashMap<String, Vec<String>> {
    let mut routes: HashMap<String, Vec<String>> = HashMap::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<Vec<String>> = VecDeque::new();

    // Deterministic seed order, so equal-length routes resolve the same way.
    let mut seeds: Vec<&str> = covered.iter().copied().collect();
    seeds.sort_unstable();
    for seed in seeds {
        visited.insert(seed.to_owned());
        queue.push_back(vec![seed.to_owned()]);
    }

    while let Some(path) = queue.pop_front() {
        let Some(tail) = path.last() else { continue };
        let Some(callees) = call_graph.get(tail.as_str()) else {
            continue;
        };
        for callee in callees {
            if !visited.insert(callee.clone()) {
                continue;
            }
            let mut next = path.clone();
            next.push(callee.clone());
            routes.insert(callee.clone(), next.clone());
            queue.push_back(next);
        }
    }
    routes
}
