//! Coverage Blocker Explorer domain contract.
//!
//! Leverage leads the ranking, an unobserved route is reported as unavailable
//! rather than as nearby, and the proposed experiment is deterministic.

#![cfg(feature = "coverage-blockers")]

use std::collections::HashMap;

use hf_coverage::UncoveredRegion;
use hf_service::coverage_blockers::{explore_blockers, propose_experiment, NextExperimentKind};

fn graph(edges: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
    edges
        .iter()
        .map(|(caller, callees)| {
            (
                (*caller).to_owned(),
                callees.iter().map(|c| (*c).to_owned()).collect(),
            )
        })
        .collect()
}

fn region(function: &str, line: u32) -> UncoveredRegion {
    UncoveredRegion {
        function: function.to_owned(),
        file: "src/parser.c".to_owned(),
        line,
        col: 1,
    }
}

fn names(list: &[String]) -> Vec<&str> {
    list.iter().map(String::as_str).collect()
}

#[test]
fn unlocked_reach_counts_still_uncovered_functions_behind_a_blocker() {
    // entry (covered) -> gate (uncovered) -> a, b (uncovered); c is covered.
    let call_graph = graph(&[
        ("entry", &["gate", "c"]),
        ("gate", &["a", "b"]),
        ("a", &[]),
        ("b", &[]),
        ("c", &[]),
    ]);
    let covered = vec!["entry".to_owned(), "c".to_owned()];
    let uncovered = vec![region("gate", 10), region("a", 20), region("b", 30)];

    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    let gate = blockers
        .iter()
        .find(|entry| entry.function == "gate")
        .expect("gate is a blocker");
    // a and b are still uncovered and only reachable through gate.
    assert_eq!(gate.unlocked_uncovered, 2);
    // A leaf blocker unlocks nothing further.
    let leaf = blockers.iter().find(|entry| entry.function == "a").unwrap();
    assert_eq!(leaf.unlocked_uncovered, 0);
}

#[test]
fn a_cyclic_call_graph_terminates() {
    let call_graph = graph(&[("entry", &["x"]), ("x", &["y"]), ("y", &["x"])]);
    let covered = vec!["entry".to_owned()];
    let uncovered = vec![region("x", 1), region("y", 2)];
    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    // x reaches y; y reaches x, but x is not counted twice or forever.
    let x = blockers.iter().find(|entry| entry.function == "x").unwrap();
    assert_eq!(x.unlocked_uncovered, 1);
}

#[test]
fn frontier_distance_and_path_start_at_the_nearest_covered_function() {
    // entry (covered) -> mid (uncovered) -> deep (uncovered)
    let call_graph = graph(&[("entry", &["mid"]), ("mid", &["deep"]), ("deep", &[])]);
    let covered = vec!["entry".to_owned()];
    let uncovered = vec![region("mid", 5), region("deep", 9)];

    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    let mid = blockers.iter().find(|e| e.function == "mid").unwrap();
    assert_eq!(mid.frontier_distance, Some(1));
    assert_eq!(mid.nearest_covered.as_deref(), Some("entry"));
    assert_eq!(names(&mid.path), vec!["entry", "mid"]);

    let deep = blockers.iter().find(|e| e.function == "deep").unwrap();
    assert_eq!(deep.frontier_distance, Some(2));
    assert_eq!(names(&deep.path), vec!["entry", "mid", "deep"]);
}

#[test]
fn a_blocker_with_no_observed_route_is_unavailable_not_nearby() {
    // orphan is uncovered and nothing covered calls into it.
    let call_graph = graph(&[("entry", &["seen"]), ("seen", &[]), ("orphan", &[])]);
    let covered = vec!["entry".to_owned(), "seen".to_owned()];
    let uncovered = vec![region("orphan", 42)];

    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    let orphan = blockers.iter().find(|e| e.function == "orphan").unwrap();
    assert_eq!(
        orphan.frontier_distance, None,
        "no observed route is unavailable, never distance zero"
    );
    assert_eq!(orphan.nearest_covered, None);
    assert!(orphan.path.is_empty());
}

#[test]
fn ranking_puts_leverage_first_and_breaks_ties_by_distance_then_name() {
    // big unlocks two, near unlocks one but is closer.
    let call_graph = graph(&[
        ("entry", &["near", "far"]),
        ("far", &["big"]),
        ("big", &["x", "y"]),
        ("near", &["z"]),
        ("x", &[]),
        ("y", &[]),
        ("z", &[]),
    ]);
    let covered = vec!["entry".to_owned()];
    let uncovered = vec![
        region("big", 1),
        region("near", 2),
        region("far", 3),
        region("x", 4),
        region("y", 5),
        region("z", 6),
    ];

    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    // far unlocks big, x, y = 3; big unlocks x, y = 2; near unlocks z = 1.
    assert_eq!(blockers[0].function, "far");
    assert_eq!(blockers[0].unlocked_uncovered, 3);
    assert_eq!(blockers[1].function, "big");
    assert_eq!(blockers[2].function, "near");
}

#[test]
fn an_unavailable_distance_ranks_after_every_known_distance_at_equal_leverage() {
    let call_graph = graph(&[
        ("entry", &["reachable"]),
        ("reachable", &[]),
        ("orphan", &[]),
    ]);
    let covered = vec!["entry".to_owned()];
    let uncovered = vec![region("orphan", 1), region("reachable", 2)];
    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    // Both unlock nothing; the one with an observed route comes first.
    assert_eq!(blockers[0].function, "reachable");
    assert_eq!(blockers[1].function, "orphan");
}

#[test]
fn distance_is_measured_from_the_closest_covered_function_not_the_entry_point() {
    // Both entry and helper are covered. gate is one edge from helper and two
    // from entry, so the reported frontier is helper.
    let call_graph = graph(&[
        ("entry", &["helper"]),
        ("helper", &["gate"]),
        ("gate", &["a", "b"]),
        ("a", &[]),
        ("b", &[]),
    ]);
    let covered = vec!["entry".to_owned(), "helper".to_owned()];
    let uncovered = vec![region("gate", 1), region("a", 2), region("b", 3)];

    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    assert_eq!(blockers[0].function, "gate");
    assert_eq!(blockers[0].frontier_distance, Some(1));
    assert_eq!(blockers[0].nearest_covered.as_deref(), Some("helper"));
    assert_eq!(names(&blockers[0].path), vec!["helper", "gate"]);

    // Every covered function seeds the walk, so the hop after the frontier is
    // never something the fuzzer already reaches.
    let experiment = propose_experiment(&blockers);
    assert_eq!(experiment.kind, NextExperimentKind::GrowCorpus);
    assert_eq!(experiment.target_function.as_deref(), Some("gate"));
}

#[test]
fn a_shallower_uncovered_function_outranks_what_sits_behind_it() {
    // Anything on the path to a blocker also reaches it, so it has at least as
    // much leverage: leverage-first ranking puts the shallowest one first.
    let call_graph = graph(&[("entry", &["mid"]), ("mid", &["deep"]), ("deep", &["a"])]);
    let covered = vec!["entry".to_owned()];
    let uncovered = vec![region("mid", 1), region("deep", 2), region("a", 3)];

    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    assert_eq!(blockers[0].function, "mid");
    assert_eq!(blockers[0].unlocked_uncovered, 2);
    let experiment = propose_experiment(&blockers);
    assert_eq!(experiment.target_function.as_deref(), Some("mid"));
}

#[test]
fn no_observed_route_to_the_top_blocker_proposes_refining_the_harness() {
    let call_graph = graph(&[("orphan", &["a"]), ("a", &[])]);
    let covered = vec!["entry".to_owned()];
    let uncovered = vec![region("orphan", 1), region("a", 2)];
    let blockers = explore_blockers(&covered, &uncovered, &call_graph);
    let experiment = propose_experiment(&blockers);
    assert_eq!(experiment.kind, NextExperimentKind::RefineHarness);
    assert_eq!(experiment.target_function.as_deref(), Some("orphan"));
}

#[test]
fn nothing_uncovered_proposes_no_experiment_rather_than_an_empty_suggestion() {
    let experiment = propose_experiment(&[]);
    assert_eq!(experiment.kind, NextExperimentKind::NoExperimentAvailable);
    assert_eq!(experiment.target_function, None);
    assert!(!experiment.reason_code.is_empty());
}
