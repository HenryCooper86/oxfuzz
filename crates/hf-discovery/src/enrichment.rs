//! Producer-agnostic scoring for static-analysis enrichment.
//!
//! One home for the join and the boost math, shared by every producer of
//! located signals. Keeping it in one place is what makes a ranking difference
//! between two producers attributable: with separate copies, a delta could come
//! from the matcher or from the arithmetic and there would be no way to tell.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use hf_core::target::{TargetCandidate, TargetInventory};
use uuid::Uuid;

/// Maximum boost any one candidate can accumulate.
pub const MAX_BOOST: f64 = 0.20;

/// One located static-analysis signal, whatever produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct EnrichmentSignal {
    /// Path relative to the project root, as candidates record theirs.
    pub relative_path: PathBuf,
    /// One-based starting line.
    pub start_line: u32,
    /// Zero-based starting column.
    pub start_col: u32,
    /// Distinct-rule counting key: two signals sharing it count once.
    pub rule_key: String,
    /// Boost contribution when this rule matches a candidate.
    pub weight: f64,
}

/// Immutable-base score overlay for one candidate.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetScore {
    /// Stable target candidate identifier.
    pub target_id: Uuid,
    /// Candidate fit score observed in the input inventory.
    pub base_score: f64,
    /// Distinct-rule boost, capped at [`MAX_BOOST`].
    pub boost: f64,
    /// Base plus boost, capped at `1.0`.
    pub effective_score: f64,
    /// Number of distinct matched rule keys.
    pub matched_rule_count: u32,
}

/// Scores plus the candidate each input signal mapped to.
#[derive(Debug, Clone, PartialEq)]
pub struct Overlay {
    /// One row per candidate, ordered by target UUID.
    pub scores: Vec<TargetScore>,
    /// Parallel to the input signals: which candidate each mapped to.
    pub matches: Vec<Option<Uuid>>,
    /// Candidates with at least one distinct matched rule.
    pub matched_candidate_count: u32,
}

/// Compute the score overlay for `signals` against `inventory`.
///
/// Infallible: every mapped id comes from `inventory` itself, so a mapped
/// candidate cannot be absent from the result.
#[must_use]
pub fn score_overlay(inventory: &TargetInventory, signals: &[EnrichmentSignal]) -> Overlay {
    let mut rule_weights = BTreeMap::<(Uuid, String), f64>::new();
    let mut matches = Vec::with_capacity(signals.len());

    for signal in signals {
        let owner = uniquely_containing_candidate(inventory, signal);
        matches.push(owner);
        if let Some(target_id) = owner {
            rule_weights
                .entry((target_id, signal.rule_key.clone()))
                .and_modify(|weight| *weight = weight.max(signal.weight))
                .or_insert(signal.weight);
        }
    }

    let mut scores = inventory
        .candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id,
                TargetScore {
                    target_id: candidate.id,
                    base_score: candidate.fit_score,
                    boost: 0.0,
                    effective_score: candidate.fit_score,
                    matched_rule_count: 0,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    for ((target_id, _), weight) in rule_weights {
        // Unreachable by construction: `uniquely_containing_candidate` only
        // returns ids drawn from `inventory.candidates`, which seeded `scores`.
        if let Some(score) = scores.get_mut(&target_id) {
            score.boost += weight;
            score.matched_rule_count += 1;
        }
    }

    for score in scores.values_mut() {
        score.boost = ((score.boost.min(MAX_BOOST) * 100.0).round()) / 100.0;
        score.effective_score = (score.base_score + score.boost).min(1.0);
    }

    let scores = scores.into_values().collect::<Vec<_>>();
    let matched_candidate_count = u32::try_from(
        scores
            .iter()
            .filter(|score| score.matched_rule_count > 0)
            .count(),
    )
    .unwrap_or(u32::MAX);

    Overlay {
        scores,
        matches,
        matched_candidate_count,
    }
}

/// The single candidate whose span contains this signal's start, if exactly one
/// does. An ambiguous signal contributes to no candidate.
fn uniquely_containing_candidate(
    inventory: &TargetInventory,
    signal: &EnrichmentSignal,
) -> Option<Uuid> {
    let mut matches = inventory.candidates.iter().filter(|candidate| {
        candidate_relative_path(candidate) == signal.relative_path
            && contains_start(candidate, signal)
    });
    let candidate_id = matches.next()?.id;
    matches.next().is_none().then_some(candidate_id)
}

fn candidate_relative_path(candidate: &TargetCandidate) -> &Path {
    candidate
        .location
        .file
        .strip_prefix(&candidate.project_root)
        .unwrap_or(&candidate.location.file)
}

fn contains_start(candidate: &TargetCandidate, signal: &EnrichmentSignal) -> bool {
    let Some(end_line) = candidate.location.end_line else {
        return false;
    };
    let Some(end_col) = candidate.location.end_col else {
        return false;
    };
    let start = (candidate.location.line, candidate.location.col);
    let end = (end_line, end_col);
    let point = (signal.start_line, signal.start_col);
    start <= point && point <= end
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_core::target::{InputSurface, SourceLocation, TargetKind, TargetLanguage};

    const EPS: f64 = 1e-9;

    fn candidate_at(
        id: &str,
        symbol: &str,
        file: &str,
        line: u32,
        end_line: u32,
        fit_score: f64,
    ) -> TargetCandidate {
        TargetCandidate {
            id: Uuid::parse_str(id).expect("UUID should parse"),
            project_root: PathBuf::from("/proj"),
            language: TargetLanguage::C,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: PathBuf::from("/proj").join(file),
                line,
                col: 1,
                end_line: Some(end_line),
                end_col: Some(1),
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score,
            sanitizers: Vec::new(),
            rationale: String::new(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 0,
        }
    }

    fn sample_inventory() -> TargetInventory {
        TargetInventory {
            project_root: PathBuf::from("/proj"),
            candidates: vec![candidate_at(
                "00000000-0000-0000-0000-000000000001",
                "parse_header",
                "src/parse.c",
                10,
                20,
                0.50,
            )],
            call_graph: std::collections::HashMap::new(),
        }
    }

    fn signal(rule_key: &str, weight: f64) -> EnrichmentSignal {
        EnrichmentSignal {
            relative_path: PathBuf::from("src/parse.c"),
            start_line: 12,
            start_col: 4,
            rule_key: rule_key.to_owned(),
            weight,
        }
    }

    fn sample_signals(rule_key: &str) -> Vec<EnrichmentSignal> {
        vec![signal(rule_key, 0.10)]
    }

    #[test]
    fn two_producers_with_identical_signals_score_identically() {
        // The premise of the phase 1c A/B: any ranking delta between Semgrep
        // and the native analyzer comes from matching, never from arithmetic.
        let inventory = sample_inventory();
        let from_a = score_overlay(&inventory, &sample_signals("rule-a"));
        let from_b = score_overlay(&inventory, &sample_signals("rule-a"));
        assert_eq!(from_a.scores, from_b.scores);
    }

    #[test]
    fn distinct_rules_accumulate_and_repeats_do_not() {
        let inventory = sample_inventory();
        let once = score_overlay(&inventory, &[signal("rule-a", 0.10)]);
        let twice = score_overlay(
            &inventory,
            &[signal("rule-a", 0.10), signal("rule-a", 0.10)],
        );
        let two_rules = score_overlay(
            &inventory,
            &[signal("rule-a", 0.10), signal("rule-b", 0.10)],
        );

        assert!((once.scores[0].boost - twice.scores[0].boost).abs() < EPS);
        assert_eq!(once.scores[0].matched_rule_count, 1);
        assert_eq!(twice.scores[0].matched_rule_count, 1);
        assert_eq!(two_rules.scores[0].matched_rule_count, 2);
        assert!(two_rules.scores[0].boost > once.scores[0].boost);
    }

    #[test]
    fn one_rule_reporting_two_weights_uses_the_higher() {
        let inventory = sample_inventory();
        let overlay = score_overlay(
            &inventory,
            &[signal("rule-a", 0.01), signal("rule-a", 0.10)],
        );
        assert!((overlay.scores[0].boost - 0.10).abs() < EPS);
    }

    #[test]
    fn boost_and_effective_score_are_capped() {
        let inventory = TargetInventory {
            candidates: vec![candidate_at(
                "00000000-0000-0000-0000-000000000001",
                "parse_header",
                "src/parse.c",
                10,
                20,
                0.90,
            )],
            ..sample_inventory()
        };
        let overlay = score_overlay(
            &inventory,
            &[
                signal("rule-a", 0.10),
                signal("rule-b", 0.10),
                signal("rule-c", 0.05),
            ],
        );
        assert_eq!(overlay.scores[0].matched_rule_count, 3);
        assert!((overlay.scores[0].boost - MAX_BOOST).abs() < EPS);
        assert!((overlay.scores[0].effective_score - 1.0).abs() < EPS);
    }

    #[test]
    fn every_candidate_gets_a_row_even_with_no_signals() {
        let inventory = sample_inventory();
        let overlay = score_overlay(&inventory, &[]);
        assert_eq!(overlay.scores.len(), 1);
        assert!(overlay.scores[0].boost.abs() < EPS);
        assert!((overlay.scores[0].effective_score - 0.50).abs() < EPS);
        assert_eq!(overlay.matched_candidate_count, 0);
    }

    #[test]
    fn a_signal_outside_every_candidate_maps_to_nothing() {
        let inventory = sample_inventory();
        let mut outside = signal("rule-a", 0.10);
        outside.start_line = 99;
        let overlay = score_overlay(&inventory, &[outside]);
        assert_eq!(overlay.matches, vec![None]);
        assert!(overlay.scores[0].boost.abs() < EPS);
    }

    #[test]
    fn an_ambiguous_signal_contributes_to_no_candidate() {
        // Two candidates whose spans both contain the signal: attributing the
        // boost to either would be a guess, so neither receives it.
        let inventory = TargetInventory {
            candidates: vec![
                candidate_at(
                    "00000000-0000-0000-0000-000000000001",
                    "outer",
                    "src/parse.c",
                    1,
                    40,
                    0.50,
                ),
                candidate_at(
                    "00000000-0000-0000-0000-000000000002",
                    "inner",
                    "src/parse.c",
                    10,
                    20,
                    0.50,
                ),
            ],
            ..sample_inventory()
        };
        let overlay = score_overlay(&inventory, &sample_signals("rule-a"));
        assert_eq!(overlay.matches, vec![None]);
        assert!(overlay.scores.iter().all(|score| score.boost.abs() < EPS));
    }

    #[test]
    fn score_rows_are_ordered_by_target_uuid() {
        let inventory = TargetInventory {
            candidates: vec![
                candidate_at(
                    "00000000-0000-0000-0000-00000000000b",
                    "second",
                    "src/b.c",
                    1,
                    5,
                    0.5,
                ),
                candidate_at(
                    "00000000-0000-0000-0000-00000000000a",
                    "first",
                    "src/a.c",
                    1,
                    5,
                    0.5,
                ),
            ],
            ..sample_inventory()
        };
        let overlay = score_overlay(&inventory, &[]);
        let ids: Vec<Uuid> = overlay.scores.iter().map(|score| score.target_id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }
}
