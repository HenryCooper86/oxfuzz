#![cfg(feature = "ai-target-ranking")]

mod common;

use std::path::Path;
use std::sync::{Arc, LazyLock};

use hf_core::target::{TargetInventory, TargetLanguage};
use hf_service::ServiceContainer;
use hf_storage::{AiRankingSource, Store};
use uuid::Uuid;

fn cleanup_gate() -> &'static tokio::sync::Mutex<()> {
    static GATE: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));
    &GATE
}

async fn retained_scan(store: &Store, project: &Path) -> Uuid {
    let id = Uuid::new_v4();
    store
        .create_ai_discovery(id, project, TargetLanguage::C)
        .await
        .unwrap();
    let inventory = TargetInventory {
        project_root: project.to_path_buf(),
        candidates: Vec::new(),
        call_graph: std::collections::HashMap::new(),
    };
    assert!(store
        .publish_ai_scan(id, &serde_json::to_string(&inventory).unwrap(), 0)
        .await
        .unwrap());
    assert!(store
        .save_ai_rank_prompt(id, 0, "retained project metadata", "test-model")
        .await
        .unwrap());
    assert!(store
        .finish_ai_discovery(id, "[]", AiRankingSource::Heuristic, None, 0)
        .await
        .unwrap());
    id
}

#[tokio::test]
async fn delete_project_removes_retained_discovery_and_prompts_only_for_its_owner() {
    let _gate = cleanup_gate().lock().await;
    common::install_managed_workspace("oxfuzz_project_lifecycle");
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("deleted");
    let other = root.path().join("kept");
    for path in [&project, &other] {
        std::fs::create_dir(path).unwrap();
        std::fs::write(path.join("source.c"), "original source").unwrap();
    }
    let project = std::fs::canonicalize(project).unwrap();
    let other = std::fs::canonicalize(other).unwrap();
    let store = Arc::new(
        Store::connect(root.path().join("cleanup.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    let deleted_id = retained_scan(&store, &project).await;
    let kept_id = retained_scan(&store, &other).await;
    assert!(service
        .ranked_discovery_result(deleted_id)
        .await
        .unwrap()
        .is_some());

    service.delete_project(&project).await.unwrap();

    assert!(service
        .ranked_discovery_status(deleted_id)
        .await
        .unwrap()
        .is_none());
    assert!(service
        .ranked_discovery_result(deleted_id)
        .await
        .unwrap()
        .is_none());
    assert!(service
        .ranked_discovery_project(deleted_id)
        .await
        .unwrap()
        .is_none());
    assert!(service.retry_ranked_discovery(deleted_id).await.is_err());
    assert!(store
        .list_ai_rank_batches(deleted_id)
        .await
        .unwrap()
        .is_empty());
    assert!(service
        .ranked_discovery_result(kept_id)
        .await
        .unwrap()
        .is_some());
    assert_eq!(store.list_ai_rank_batches(kept_id).await.unwrap().len(), 1);
    for path in [&project, &other] {
        assert_eq!(
            std::fs::read_to_string(path.join("source.c")).unwrap(),
            "original source"
        );
    }
}

#[tokio::test]
async fn clear_knowledge_removes_all_retained_discovery_without_removing_workspaces_or_sources() {
    let _gate = cleanup_gate().lock().await;
    let workspace = common::install_managed_workspace("oxfuzz_project_lifecycle");
    let root = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(root.path().join("cleanup.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::stubbed().with_store(Arc::clone(&store));
    let mut ids = Vec::new();
    let mut markers = Vec::new();
    for name in ["first", "second"] {
        let project = root.path().join(name);
        std::fs::create_dir(&project).unwrap();
        let project = std::fs::canonicalize(project).unwrap();
        let source = project.join("source.c");
        std::fs::write(&source, "original source").unwrap();
        let project_workspace = hf_service::project_workspace_dir(&project);
        std::fs::create_dir_all(&project_workspace).unwrap();
        let marker = project_workspace.join("retained-artifact");
        std::fs::write(&marker, "retained workspace artifact").unwrap();
        markers.push((source, marker));
        ids.push(retained_scan(&store, &project).await);
    }
    let unrelated = workspace.join("unrelated-runtime-data");
    std::fs::write(&unrelated, "unrelated runtime data").unwrap();

    service.clear_knowledge().await.unwrap();

    for id in ids {
        assert!(service.ranked_discovery_status(id).await.unwrap().is_none());
        assert!(service.ranked_discovery_result(id).await.unwrap().is_none());
        assert!(service.retry_ranked_discovery(id).await.is_err());
        assert!(store.list_ai_rank_batches(id).await.unwrap().is_empty());
    }
    for (source, marker) in markers {
        assert_eq!(std::fs::read_to_string(source).unwrap(), "original source");
        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            "retained workspace artifact"
        );
    }
    assert_eq!(
        std::fs::read_to_string(unrelated).unwrap(),
        "unrelated runtime data"
    );
}
