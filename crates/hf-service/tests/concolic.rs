//! Concolic corpus enrichment domain contract.

#![cfg(feature = "concolic-enrichment")]

use hf_service::config::{parse_concolic_settings, ConcolicSettings};

#[test]
fn every_bound_defaults_to_something_that_actually_bounds() {
    let d = ConcolicSettings::default();
    assert!(d.max_inputs > 0);
    assert!(d.per_input_timeout_secs > 0);
    assert!(d.max_solved_inputs > 0);
    assert!(d.total_timeout_secs > 0);
}

#[test]
fn a_zero_bound_is_rejected_rather_than_read_as_unlimited() {
    // Path explosion is this subsystem's normal failure mode, so an unbounded
    // pass is never what an operator meant by zero.
    for field in [
        "max_inputs",
        "per_input_timeout_secs",
        "max_solved_inputs",
        "total_timeout_secs",
    ] {
        let toml = format!("[concolic]\n{field} = 0\n");
        assert!(
            parse_concolic_settings(&toml).is_err(),
            "{field} = 0 must be rejected"
        );
    }
}

#[test]
fn a_valid_override_is_accepted() {
    let parsed = parse_concolic_settings("[concolic]\nmax_inputs = 40\n")
        .expect("a positive bound is valid");
    assert_eq!(parsed.max_inputs, 40);
}

use hf_service::concolic::{select_inputs, summarize, ConcolicStopReason, CONCOLIC_SCHEMA_VERSION};
use std::collections::HashSet;
use std::path::PathBuf;

fn paths(n: usize) -> Vec<PathBuf> {
    (0..n)
        .map(|i| PathBuf::from(format!("in{i}.bin")))
        .collect()
}

fn bounded(max_inputs: usize, max_solved: usize) -> ConcolicSettings {
    ConcolicSettings {
        max_inputs,
        max_solved_inputs: max_solved,
        ..ConcolicSettings::default()
    }
}

#[test]
fn selection_stops_at_max_inputs_and_reports_what_it_skipped() {
    let (selected, skipped) = select_inputs(&paths(10), &bounded(4, 100));
    assert_eq!(selected.len(), 4);
    assert_eq!(
        skipped, 6,
        "skipped inputs are reported, never silently dropped"
    );
}

#[test]
fn a_corpus_within_the_bound_skips_nothing() {
    let (selected, skipped) = select_inputs(&paths(3), &bounded(10, 100));
    assert_eq!(selected.len(), 3);
    assert_eq!(skipped, 0);
}

#[test]
fn a_solved_input_already_in_the_corpus_is_counted_but_not_novel() {
    let existing: HashSet<String> = [blake_of(b"dup")].into_iter().collect();
    let out = summarize(
        4,
        0,
        &[b"dup".to_vec(), b"fresh".to_vec()],
        &existing,
        &bounded(10, 100),
        ConcolicStopReason::CorpusExhausted,
    );
    assert_eq!(out.inputs_solved, 2);
    assert_eq!(
        out.inputs_novel, 1,
        "a solver returning inputs the corpus already holds has enriched nothing"
    );
}

#[test]
fn solved_inputs_are_capped_and_the_stop_reason_says_so() {
    let out = summarize(
        4,
        0,
        &[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        &HashSet::new(),
        &bounded(10, 2),
        ConcolicStopReason::CorpusExhausted,
    );
    assert_eq!(out.inputs_novel, 2);
    assert_eq!(out.stop_reason, ConcolicStopReason::SolvedInputCap);
}

#[test]
fn a_pass_that_solved_nothing_is_a_success_with_zero_novel() {
    let out = summarize(
        5,
        0,
        &[],
        &HashSet::new(),
        &ConcolicSettings::default(),
        ConcolicStopReason::CorpusExhausted,
    );
    assert_eq!(out.inputs_solved, 0);
    assert_eq!(out.inputs_novel, 0);
    assert_eq!(out.schema_version, CONCOLIC_SCHEMA_VERSION);
}

/// The digest the corpus uses to decide whether an input is already held.
fn blake_of(bytes: &[u8]) -> String {
    hf_service::concolic::content_digest(bytes)
}

#[test]
fn the_outcome_reports_the_corpus_size_on_both_sides_of_the_fold() {
    let out = summarize_with_sizes(
        2,
        0,
        &[b"fresh".to_vec()],
        &HashSet::new(),
        &ConcolicSettings::default(),
        ConcolicStopReason::CorpusExhausted,
        7,
    );
    assert_eq!(out.corpus_size_before, 7);
    assert_eq!(
        out.corpus_size_after, 8,
        "one novel input folded in grows the corpus by exactly one"
    );
}

#[test]
fn a_pass_with_no_novel_inputs_leaves_the_corpus_size_unchanged() {
    let existing: HashSet<String> = [blake_of(b"dup")].into_iter().collect();
    let out = summarize_with_sizes(
        2,
        0,
        &[b"dup".to_vec()],
        &existing,
        &ConcolicSettings::default(),
        ConcolicStopReason::CorpusExhausted,
        7,
    );
    assert_eq!(out.inputs_novel, 0);
    assert_eq!(out.corpus_size_after, out.corpus_size_before);
}

fn summarize_with_sizes(
    explored: usize,
    skipped: usize,
    solved: &[Vec<u8>],
    existing: &HashSet<String>,
    settings: &ConcolicSettings,
    stop: ConcolicStopReason,
    before: usize,
) -> hf_service::ConcolicOutcome {
    hf_service::concolic::summarize_with_corpus(
        explored, skipped, solved, existing, settings, stop, before,
    )
}
