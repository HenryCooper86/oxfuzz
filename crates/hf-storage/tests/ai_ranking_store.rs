use std::path::PathBuf;

use hf_core::target::TargetLanguage;
use hf_storage::{AiDiscoveryState, AiRankingSource, Store};
use uuid::Uuid;

#[tokio::test]
async fn scan_prompt_and_result_survive_reopen() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ranking.db");
    let id = Uuid::new_v4();
    let project = PathBuf::from("/sample");
    let prompt = "Assess target 123 exactly";
    let store = Store::connect(&path).await.unwrap();
    store
        .create_ai_discovery(id, &project, TargetLanguage::C)
        .await
        .unwrap();
    assert!(store
        .publish_ai_scan(id, r#"{"candidates":[]}"#, 0)
        .await
        .unwrap());
    assert!(store
        .save_ai_rank_prompt(id, 0, prompt, "mock-model")
        .await
        .unwrap());
    assert!(store
        .finish_ai_discovery(id, "[]", AiRankingSource::Heuristic, Some("no_provider"), 0)
        .await
        .unwrap());
    drop(store);

    let reopened = Store::connect(&path).await.unwrap();
    let record = reopened.get_ai_discovery(id).await.unwrap().unwrap();
    assert_eq!(record.revision, 2);
    assert_eq!(record.state, AiDiscoveryState::Completed);
    assert_eq!(record.scan_json.as_deref(), Some(r#"{"candidates":[]}"#));
    assert_eq!(record.assessment_json.as_deref(), Some("[]"));
    assert_eq!(
        reopened.list_ai_rank_batches(id).await.unwrap()[0].prompt,
        prompt
    );
}

#[tokio::test]
async fn cancellation_prevents_late_publication() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::connect(root.path().join("ranking.db"))
        .await
        .unwrap();
    let id = Uuid::new_v4();
    store
        .create_ai_discovery(id, root.path(), TargetLanguage::C)
        .await
        .unwrap();
    store.publish_ai_scan(id, "{}", 1).await.unwrap();
    assert!(store.cancel_ai_discovery(id).await.unwrap());
    assert!(!store
        .finish_ai_discovery(id, "[]", AiRankingSource::Ai, None, 1)
        .await
        .unwrap());
    let record = store.get_ai_discovery(id).await.unwrap().unwrap();
    assert_eq!(record.revision, 1);
    assert_eq!(record.state, AiDiscoveryState::Cancelled);
}

#[tokio::test]
async fn recovery_preserves_the_published_scan() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::connect(root.path().join("ranking.db"))
        .await
        .unwrap();
    let scanning = Uuid::new_v4();
    let ranking = Uuid::new_v4();
    store
        .create_ai_discovery(scanning, root.path(), TargetLanguage::C)
        .await
        .unwrap();
    store
        .create_ai_discovery(ranking, root.path(), TargetLanguage::C)
        .await
        .unwrap();
    store
        .publish_ai_scan(ranking, "retained scan", 1)
        .await
        .unwrap();
    assert_eq!(store.interrupt_active_ai_discoveries().await.unwrap(), 2);
    assert_eq!(
        store
            .get_ai_discovery(scanning)
            .await
            .unwrap()
            .unwrap()
            .revision,
        0
    );
    let retained = store.get_ai_discovery(ranking).await.unwrap().unwrap();
    assert_eq!(retained.revision, 1);
    assert_eq!(retained.scan_json.as_deref(), Some("retained scan"));
    assert_eq!(retained.state, AiDiscoveryState::Interrupted);
}

/// Another process's ranked discovery is live: the startup sweep of a second
/// `oxfuzz` command interrupted it and its ranking was lost. The sweep takes
/// the operations to interrupt from its caller, which knows the live owners.
#[tokio::test]
async fn the_startup_sweep_spares_operations_its_caller_names_live() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::connect(root.path().join("ranking.db"))
        .await
        .unwrap();
    let live = Uuid::new_v4();
    let lost = Uuid::new_v4();
    for id in [live, lost] {
        store
            .create_ai_discovery(id, root.path(), TargetLanguage::C)
            .await
            .unwrap();
    }

    let interrupted = store
        .interrupt_active_ai_discoveries_where(|id| id != live)
        .await
        .unwrap();

    assert_eq!(interrupted, 1);
    let live_state = store.get_ai_discovery(live).await.unwrap().unwrap().state;
    let lost_state = store.get_ai_discovery(lost).await.unwrap().unwrap().state;
    assert_eq!(lost_state, AiDiscoveryState::Interrupted);
    assert_ne!(live_state, AiDiscoveryState::Interrupted);
}
