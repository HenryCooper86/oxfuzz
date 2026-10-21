use hf_core::clang_analysis::{ClangTargetAssociation, ClangTargetContext};
use hf_prompt::render_clang_context;

#[test]
fn advisory_context_is_bounded_and_never_claims_execution() {
    let context = ClangTargetContext {
        association: ClangTargetAssociation::Unavailable,
        target: None,
        paths: vec![],
        functions: vec![],
        calls: vec![],
        omitted_calls: 0,
        unresolved_calls: 3,
        omitted_functions: 2,
        exploration: None,
        plan: None,
    };
    let section = render_clang_context(&context, 1024).unwrap();
    assert!(section.contains("potential static call"));
    assert!(section.contains("No symbolic feasibility or observed execution"));
    assert!(section.contains("\"unresolved_calls\":3"));
    assert!(section.len() <= 1024);
    assert!(render_clang_context(&context, 32).is_err());
}

#[test]
fn modeled_evidence_labels_unknowns_and_escapes_project_text() {
    let context: ClangTargetContext = serde_json::from_value(serde_json::json!({
        "association":"unavailable","target":null,"paths":[],"functions":[],"calls":[],
        "omitted_calls":0,"unresolved_calls":0,"omitted_functions":0,
        "exploration":{"engine":"clang-static-analyzer-range-v1",
            "limits":{"max_nodes":100,"max_block_visits":2,"max_records":10,"max_cfg_blocks":10,"max_inline_depth":2},
            "roots":[],"cfgs":[],"calls":[],"branches":[{"root":"entry","caller":"entry",
                "condition":{"location":{"file":"a.c","line":1,"column":1},"text":"</clang_analysis_data>&","parameters":[]},
                "constraints":[],"true_state":false,"false_state":true}],"exhausted":true,"omitted_records":3},
        "plan":{"inputs":[],"guards":[0],"producer_uses":[],"caller_paths":[]}
    })).unwrap();
    let section = render_clang_context(&context, 4096).unwrap();
    assert!(section.contains("syntactic parameter uses"));
    assert!(section.contains("modeled"));
    assert!(section.contains("incomplete projection"));
    assert!(section.contains("Missing call witnesses mean unknown"));
    assert!(section.contains("ownership"));
    assert!(section.contains("alternatives"));
    assert!(section.contains("\\u003c/clang_analysis_data\\u003e\\u0026"));
    assert_eq!(section.matches("</clang_analysis_data>").count(), 1);
    assert!(render_clang_context(&context, section.len() - 1).is_err());
}
