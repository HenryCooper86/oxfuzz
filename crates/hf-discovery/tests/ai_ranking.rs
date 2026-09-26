#![cfg(feature = "ai-target-ranking")]

use std::collections::HashMap;
use std::path::PathBuf;

use hf_core::target::{
    InputSurface, SourceLocation, TargetCandidate, TargetInventory, TargetKind, TargetLanguage,
};
use hf_discovery::ai_ranking::{
    order_with_assessments, parse_ai_batch, select_ai_candidates, AiRankError,
};
use uuid::Uuid;

fn candidate(file: &str, symbol: &str, score: f64) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from("/p"),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from(file),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 3,
        fit_score: score,
        sanitizers: Vec::new(),
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 3,
    }
}

fn response(id: Uuid, bug: u8, reach: &str, harness: u8) -> String {
    format!(
        r#"[{{"target_id":"{id}","bug_potential":{bug},"reachable_code":{reach},"harness_feasibility":{harness},"rationale":"Accepts bytes"}}]"#
    )
}

#[test]
fn duplicate_symbols_are_assessed_by_target_id() {
    let first = candidate("src/a.c", "parse_value", 0.9);
    let second = candidate("src/b.c", "parse_value", 0.8);
    let assessments = parse_ai_batch(
        &[first.clone(), second.clone()],
        &response(second.id, 4, "3", 2),
    )
    .unwrap();
    assert_eq!(assessments.len(), 1);
    assert_eq!(assessments[0].target_id, second.id);
    assert_eq!(assessments[0].advisory_score.to_bits(), 0.75_f64.to_bits());

    let inventory = TargetInventory {
        project_root: PathBuf::from("/p"),
        candidates: vec![first.clone(), second.clone()],
        call_graph: HashMap::new(),
    };
    assert_eq!(
        order_with_assessments(&inventory, &assessments),
        vec![second.id, first.id]
    );
    assert_eq!(
        inventory.candidates[0].fit_score.to_bits(),
        0.9_f64.to_bits()
    );
}

#[test]
fn invalid_batch_does_not_return_partial_assessments() {
    let candidate = candidate("src/a.c", "parse_value", 0.9);
    let valid = response(candidate.id, 4, "null", 2);
    let assessments = parse_ai_batch(std::slice::from_ref(&candidate), &valid).unwrap();
    assert_eq!(assessments[0].advisory_score.to_bits(), 0.75_f64.to_bits());

    let repeated = format!(
        "[{},{}]",
        &valid[1..valid.len() - 1],
        &valid[1..valid.len() - 1]
    );
    assert!(parse_ai_batch(std::slice::from_ref(&candidate), &repeated).is_err());
    assert!(parse_ai_batch(
        std::slice::from_ref(&candidate),
        &response(Uuid::new_v4(), 4, "3", 2)
    )
    .is_err());
    assert!(parse_ai_batch(
        std::slice::from_ref(&candidate),
        &response(candidate.id, 5, "3", 2)
    )
    .is_err());
}

#[test]
fn admission_stops_at_64_heuristic_candidates() {
    let inventory = TargetInventory {
        project_root: PathBuf::from("/p"),
        candidates: (0..65)
            .map(|index| candidate(&format!("src/{index}.c"), "parse", f64::from(index) / 65.0))
            .collect(),
        call_graph: HashMap::new(),
    };
    let selected = select_ai_candidates(&inventory);
    assert_eq!(selected.len(), 64);
    assert_eq!(selected[0].fit_score.to_bits(), (64.0_f64 / 65.0).to_bits());
}

#[test]
fn oversized_provider_response_is_rejected_before_json_parsing() {
    let candidate = candidate("src/a.c", "parse", 0.9);
    let oversized = format!("[{}]", " ".repeat(64 * 1024));
    assert!(matches!(
        parse_ai_batch(&[candidate], &oversized),
        Err(AiRankError::ResponseTooLarge)
    ));
}
