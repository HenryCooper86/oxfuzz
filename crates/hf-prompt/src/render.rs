//! Prompt rendering functions.

use hf_core::engine::EngineKind;
use hf_core::target::TargetCandidate;

/// Render the discovery (target ranking) prompt.
///
/// Given the heuristic-ranked candidates, produce a prompt asking the LLM
/// to refine fit scores and add rationale.
#[must_use]
pub fn render_discovery_prompt(candidates: &[TargetCandidate]) -> String {
    let mut lines = vec![
        "You are the discovery-agent for hobot_fuzz.".to_owned(),
        "Your job: refine fuzzing fit scores and add rationale for each candidate.".to_owned(),
        "Output a JSON array of objects with fields:".to_owned(),
        "  symbol, fit_score (0.0-1.0), rationale (one sentence).".to_owned(),
        "Only include functions that accept untrusted input.".to_owned(),
        "Do not include trivial wrappers or pure formatting functions.".to_owned(),
        "Prefer targets with high accumulated_complexity / reaches: they exercise \
         more reachable code per run."
            .to_owned(),
        String::new(),
        "Candidates (heuristic-ranked):".to_owned(),
    ];
    for c in candidates {
        lines.push(format!(
            "- symbol={} kind={:?} input_surface={:?} complexity={} accumulated_complexity={} reaches={} fit_score={:.3} signature={}",
            c.symbol,
            c.kind,
            c.input_surface,
            c.complexity,
            c.accumulated_complexity,
            c.reachable_functions.len(),
            c.fit_score,
            c.signature.as_deref().unwrap_or("(unknown)")
        ));
    }
    lines.join("\n")
}

/// Render the harness generation prompt for a target + engine.
#[must_use]
pub fn render_harness_prompt(target: &TargetCandidate, engine: EngineKind) -> String {
    let entry_point = engine_entry_point(engine);
    let engine_name = engine_name(engine);
    // List the project functions this target reaches, so the harness shapes its
    // input to exercise them (capped to keep the prompt focused).
    let reach_line = if target.reachable_functions.is_empty() {
        String::new()
    } else {
        let shown: Vec<&str> = target
            .reachable_functions
            .iter()
            .take(20)
            .map(String::as_str)
            .collect();
        let more = target.reachable_functions.len().saturating_sub(shown.len());
        let suffix = if more > 0 {
            format!(", +{more} more")
        } else {
            String::new()
        };
        format!(
            "\n- reaches ({n}) functions: {list}{suffix}\n\
             - shape the input so it drives execution into these where possible",
            n = target.reachable_functions.len(),
            list = shown.join(", "),
        )
    };
    format!(
        "You are the harness-agent for hobot_fuzz.\n\
         Your job: write a fuzzing harness for the target below using {engine_name}.\n\
         Rules:\n\
         - Use the engine entry point exactly: {entry_point}\n\
         - No host I/O. All input comes from the fuzzer.\n\
         - Deterministic. No time-based or RNG branches.\n\
         - Include only necessary headers.\n\
         - Output only the harness source, in a fenced code block.\n\
         \n\
         Target:\n\
         - symbol: {symbol}\n\
         - language: {lang:?}\n\
         - kind: {kind:?}\n\
         - input_surface: {input_surface:?}\n\
         - accumulated_complexity: {acc}\n\
         - signature: {sig}\n\
         - location: {file}:{line}{reach_line}",
        symbol = target.symbol,
        lang = target.language,
        kind = target.kind,
        input_surface = target.input_surface,
        acc = target.accumulated_complexity,
        sig = target.signature.as_deref().unwrap_or("(unknown)"),
        file = target.location.file.display(),
        line = target.location.line,
    )
}

fn engine_entry_point(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::Honggfuzz => {
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) // with HF_ITER"
        }
        EngineKind::LibFuzzer | EngineKind::AflPlusPlus | EngineKind::ClusterFuzzLite => {
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)"
        }
        EngineKind::Syzkaller => {
            "kernel syscall fuzzing -- no per-function harness; uses syzlang descriptions"
        }
    }
}

fn engine_name(engine: EngineKind) -> &'static str {
    match engine {
        EngineKind::LibFuzzer => "libFuzzer",
        EngineKind::AflPlusPlus => "AFL++",
        EngineKind::Honggfuzz => "honggfuzz",
        EngineKind::ClusterFuzzLite => "ClusterFuzzLite (libFuzzer-compatible)",
        EngineKind::Syzkaller => "syzkaller (kernel)",
    }
}
