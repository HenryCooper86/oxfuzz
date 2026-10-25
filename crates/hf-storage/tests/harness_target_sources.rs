//! Retained target-definition prompt sections (migration 0045).

use hf_storage::{HarnessTargetSourceRecord, Store};
use uuid::Uuid;

async fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("target-sources.db"))
        .await
        .unwrap();
    (directory, store)
}

fn record(project: &str) -> HarnessTargetSourceRecord {
    HarnessTargetSourceRecord {
        id: Uuid::new_v4(),
        project_root: project.to_owned(),
        target_id: Uuid::new_v4(),
        source_file: "src/parse.c".to_owned(),
        source_sha256: "a".repeat(64),
        rendered: "\n\nTarget definition (src/parse.c, line 3): ...".to_owned(),
        created_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn a_retained_section_reads_back_exactly() {
    let (_dir, store) = store().await;
    let record = record("/project");
    store.append_harness_target_source(&record).await.unwrap();
    assert_eq!(
        store.harness_target_source(record.id).await.unwrap(),
        Some(record)
    );
}

#[tokio::test]
async fn retained_sections_are_immutable() {
    let (_dir, store) = store().await;
    let record = record("/project");
    store.append_harness_target_source(&record).await.unwrap();
    // An identical retry is accepted, a differing one is refused.
    store.append_harness_target_source(&record).await.unwrap();
    let mut changed = record.clone();
    changed.rendered.push_str(" changed");
    assert!(store.append_harness_target_source(&changed).await.is_err());
    assert_eq!(
        store.harness_target_source(record.id).await.unwrap(),
        Some(record)
    );
}

#[tokio::test]
async fn malformed_sections_are_refused() {
    let (_dir, store) = store().await;
    let mut bad_digest = record("/project");
    bad_digest.source_sha256 = "not-a-digest".to_owned();
    assert!(store
        .append_harness_target_source(&bad_digest)
        .await
        .is_err());
    let mut oversized = record("/project");
    oversized.rendered = "x".repeat(16 * 1024 + 1);
    assert!(store
        .append_harness_target_source(&oversized)
        .await
        .is_err());
    let mut relative_project = record("project");
    relative_project.project_root = String::new();
    assert!(store
        .append_harness_target_source(&relative_project)
        .await
        .is_err());
}

#[tokio::test]
async fn project_deletion_and_knowledge_clearing_remove_sections() {
    let (_dir, store) = store().await;
    let kept = record("/kept");
    let deleted = record("/deleted");
    store.append_harness_target_source(&kept).await.unwrap();
    store.append_harness_target_source(&deleted).await.unwrap();
    store.delete_project("/deleted").await.unwrap();
    assert!(store
        .harness_target_source(deleted.id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .harness_target_source(kept.id)
        .await
        .unwrap()
        .is_some());
    store.clear_knowledge().await.unwrap();
    assert!(store
        .harness_target_source(kept.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn project_history_is_newest_first_and_bounded() {
    let (_dir, store) = store().await;
    let mut older = record("/project");
    older.created_at = chrono::Utc::now() - chrono::Duration::seconds(5);
    let newer = record("/project");
    let other = record("/other");
    for record in [&older, &newer, &other] {
        store.append_harness_target_source(record).await.unwrap();
    }
    let history = store
        .harness_target_sources_for_project("/project", 10)
        .await
        .unwrap();
    assert_eq!(history, vec![newer.clone(), older]);
    let bounded = store
        .harness_target_sources_for_project("/project", 1)
        .await
        .unwrap();
    assert_eq!(bounded, vec![newer]);
    assert!(store
        .harness_target_sources_for_project("/project", 0)
        .await
        .is_err());
}
