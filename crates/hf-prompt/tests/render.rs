//! Tests for prompt rendering.

use hf_core::engine::EngineKind;
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_prompt::render_discovery_prompt;

fn sample_candidate(symbol: &str, fit: f64) -> TargetCandidate {
    TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: std::path::PathBuf::from("/p"),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: std::path::PathBuf::from("src/json.c"),
            line: 42,
            col: 1,
        },
        signature: Some(format!("int {symbol}(const char *buf, size_t len);")),
        input_surface: InputSurface::Bytes,
        complexity: 30,
        fit_score: fit,
        sanitizers: vec![Sanitizer::Address],
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    }
}

#[test]
fn discovery_prompt_includes_candidates() {
    let candidates = vec![
        sample_candidate("parse_value", 0.9),
        sample_candidate("parse_array", 0.8),
    ];
    let prompt = render_discovery_prompt(&candidates);
    assert!(
        prompt.contains("parse_value"),
        "prompt must mention parse_value"
    );
    assert!(
        prompt.contains("parse_array"),
        "prompt must mention parse_array"
    );
    assert!(
        prompt.contains("fit_score"),
        "prompt must reference fit_score"
    );
}

#[test]
fn harness_prompt_includes_target_and_engine() {
    let target = sample_candidate("parse_value", 0.9);
    let prompt = hf_prompt::render_harness_prompt(&target, EngineKind::LibFuzzer);
    assert!(prompt.contains("parse_value"), "prompt must mention target");
    assert!(
        prompt.contains("libfuzzer")
            || prompt.contains("LibFuzzer")
            || prompt.contains("LLVMFuzzerTestOneInput")
    );
}

#[test]
fn harness_prompt_for_afl_mentions_entry_point() {
    let target = sample_candidate("parse_value", 0.9);
    let prompt = hf_prompt::render_harness_prompt(&target, EngineKind::AflPlusPlus);
    assert!(prompt.contains("LLVMFuzzerTestOneInput") || prompt.contains("afl"));
}
