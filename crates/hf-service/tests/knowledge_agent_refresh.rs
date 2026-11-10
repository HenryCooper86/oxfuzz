//! Assistant searches must observe current project sources, including deletions.
use hf_agent::AgentBackend;

#[tokio::test]
async fn assistant_search_refreshes_edits_and_deletions() {
    let root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path().join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.path().join("workspace"));
    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let source = project.join("parser.c");
    std::fs::write(&source, "int alpha_symbol(void) { return 1; }").unwrap();
    let service = hf_service::ServiceContainer::stubbed();
    assert!(!service
        .knowledge_search(&project, "alpha_symbol", 5)
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    std::fs::write(&source, "int bravo_symbol(void) { return 2; }").unwrap();
    assert!(!service
        .knowledge_search(&project, "bravo_symbol", 5)
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert!(service
        .knowledge_search(&project, "alpha_symbol", 5)
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    std::fs::remove_file(source).unwrap();
    assert!(service
        .knowledge_search(&project, "bravo_symbol", 5)
        .await
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
}
