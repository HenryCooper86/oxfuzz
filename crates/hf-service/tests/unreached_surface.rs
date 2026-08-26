//! Unreached Surface domain contract.
//!
//! Absence from every retained measurement is what makes a candidate
//! unreached; with no measurement at all, nothing is unreached and nothing is
//! reported.

#![cfg(feature = "unreached-surface")]

use std::collections::{HashMap, HashSet};

use hf_service::unreached_surface::{
    unreached_surface, AttemptHistory, SurfaceMeasurement, UnreachedSurfaceRequest,
};

fn candidates(symbols: &[(&str, f64)]) -> Vec<(String, f64)> {
    symbols
        .iter()
        .map(|(name, score)| ((*name).to_owned(), *score))
        .collect()
}

fn covered(names: &[&str]) -> HashSet<String> {
    names.iter().map(|n| (*n).to_owned()).collect()
}

fn attempts(entries: &[(&str, AttemptHistory)]) -> HashMap<String, AttemptHistory> {
    entries
        .iter()
        .map(|(name, history)| ((*name).to_owned(), *history))
        .collect()
}

fn request(
    ranked: Vec<(String, f64)>,
    covered: HashSet<String>,
    attempts: HashMap<String, AttemptHistory>,
    measurements: usize,
) -> UnreachedSurfaceRequest {
    UnreachedSurfaceRequest {
        ranked_candidates: ranked,
        covered_functions: covered,
        attempts,
        measurements,
    }
}

fn names(view: &hf_service::unreached_surface::UnreachedSurfaceView) -> Vec<&str> {
    view.candidates
        .iter()
        .map(|entry| entry.symbol.as_str())
        .collect()
}

#[test]
fn with_no_measurement_nothing_is_reported_and_the_reason_is_named() {
    let view = unreached_surface(&request(
        candidates(&[("parse_header", 0.9), ("parse_body", 0.8)]),
        covered(&[]),
        attempts(&[]),
        0,
    ));

    assert!(matches!(
        view.measurement,
        SurfaceMeasurement::Unavailable { .. }
    ));
    assert!(
        view.candidates.is_empty(),
        "a list derived from zero measurements would name every function in the \
         project and would be fabrication"
    );
}

#[test]
fn a_function_covered_by_any_retained_measurement_is_not_unreached() {
    let view = unreached_surface(&request(
        candidates(&[("parse_header", 0.9), ("parse_body", 0.8)]),
        covered(&["parse_header"]),
        attempts(&[]),
        3,
    ));

    assert_eq!(names(&view), vec!["parse_body"]);
}

#[test]
fn discovery_order_leads_and_is_never_reordered_by_attempt_history() {
    // The top candidate has already consumed effort; the bottom one has not.
    // A compile failure is cheap to fix and the value gap is not, so the
    // discovery order stands.
    let view = unreached_surface(&request(
        candidates(&[("high_value", 0.95), ("low_value", 0.10)]),
        covered(&["something_else"]),
        attempts(&[(
            "high_value",
            AttemptHistory::AttemptedCompileFailed { attempts: 2 },
        )]),
        1,
    ));

    assert_eq!(names(&view), vec!["high_value", "low_value"]);
}

#[test]
fn attempt_history_breaks_a_tie_in_discovery_rank() {
    let view = unreached_surface(&request(
        candidates(&[("tried", 0.5), ("untried", 0.5)]),
        covered(&["something_else"]),
        attempts(&[(
            "tried",
            AttemptHistory::AttemptedSmokeFailed { attempts: 1 },
        )]),
        1,
    ));

    assert_eq!(
        names(&view),
        vec!["untried", "tried"],
        "at equal value, spend effort where none has been spent"
    );
}

#[test]
fn a_candidate_with_no_harness_is_never_attempted() {
    let view = unreached_surface(&request(
        candidates(&[("parse_body", 0.8)]),
        covered(&["other"]),
        attempts(&[]),
        1,
    ));

    assert_eq!(view.candidates[0].attempt, AttemptHistory::NeverAttempted);
}

#[test]
fn a_qualified_harness_that_still_misses_the_function_is_the_informative_state() {
    let view = unreached_surface(&request(
        candidates(&[("parse_body", 0.8)]),
        covered(&["other"]),
        attempts(&[(
            "parse_body",
            AttemptHistory::QualifiedYetUnreached { attempts: 1 },
        )]),
        1,
    ));

    assert_eq!(
        view.candidates[0].attempt,
        AttemptHistory::QualifiedYetUnreached { attempts: 1 },
        "the harness runs and does not exercise what it was written for"
    );
}

#[test]
fn the_measurement_count_is_reported_so_absence_can_be_judged() {
    let view = unreached_surface(&request(
        candidates(&[("parse_body", 0.8)]),
        covered(&["other"]),
        attempts(&[]),
        7,
    ));

    assert_eq!(
        view.measurement,
        SurfaceMeasurement::Retained { measurements: 7 }
    );
}

#[test]
fn ordering_is_total_and_does_not_depend_on_input_order() {
    let ranked = candidates(&[("a", 0.5), ("b", 0.5), ("c", 0.5)]);
    let mut reversed = ranked.clone();
    reversed.reverse();

    let forward = unreached_surface(&request(ranked, covered(&["other"]), attempts(&[]), 1));
    let backward = unreached_surface(&request(reversed, covered(&["other"]), attempts(&[]), 1));

    assert_eq!(names(&forward), names(&backward));
    assert_eq!(names(&forward), vec!["a", "b", "c"]);
}

#[test]
fn every_candidate_is_reported_when_nothing_at_all_was_covered() {
    // A completed measurement that covered nothing is different from no
    // measurement: here the absence is a finding, not a gap in evidence.
    let view = unreached_surface(&request(
        candidates(&[("a", 0.9), ("b", 0.8)]),
        covered(&[]),
        attempts(&[]),
        2,
    ));

    assert_eq!(names(&view), vec!["a", "b"]);
    assert_eq!(
        view.measurement,
        SurfaceMeasurement::Retained { measurements: 2 }
    );
}
