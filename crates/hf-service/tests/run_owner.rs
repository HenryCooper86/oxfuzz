//! Durable run ownership is available independently of optional health views.

use std::sync::Arc;

#[tokio::test]
async fn run_owner_is_available_without_campaign_health_state() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("owner-project");
    std::fs::create_dir(&project).unwrap();
    let project = std::fs::canonicalize(project).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("owner.db"))
            .await
            .unwrap(),
    );
    let run = hf_storage::RunRecord::new(
        project.to_string_lossy(),
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    store.insert_run(&run).await.unwrap();
    let container = hf_service::ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));

    let owner = container.run_owner(run.id).await.unwrap();

    assert_eq!(owner.run_id, run.id);
    assert_eq!(owner.project_root, project.to_string_lossy());
    assert_eq!(owner.target, None);
}
