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
    };
    let section = render_clang_context(&context, 1024).unwrap();
    assert!(section.contains("potential static call"));
    assert!(section.contains("No symbolic feasibility or observed execution"));
    assert!(section.contains("\"unresolved_calls\":3"));
    assert!(section.len() <= 1024);
    assert!(render_clang_context(&context, 32).is_err());
}
