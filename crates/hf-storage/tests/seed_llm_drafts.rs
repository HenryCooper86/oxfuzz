//! Retained seed-drafting requests and responses (migration 0049).

use chrono::{DateTime, Utc};
use hf_storage::{SeedDraftPurpose, SeedLlmDraftRecord, Store};
use uuid::Uuid;

async fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("drafts.db"))
        .await
        .unwrap();
    (directory, store)
}

fn draft(
    project: &str,
    target: &str,
    purpose: SeedDraftPurpose,
    at: DateTime<Utc>,
) -> SeedLlmDraftRecord {
    SeedLlmDraftRecord {
        id: Uuid::new_v4(),
        project_root: project.to_owned(),
        target: target.to_owned(),
        purpose,
        prompt_version: 2,
        prompt: "You are the seed-corpus author for oxfuzz. ...".to_owned(),
        response: None,
        created_at: at,
        completed_at: None,
    }
}

#[tokio::test]
async fn a_draft_is_retained_before_dispatch_and_completed_once() {
    let (_dir, store) = store().await;
    let created_at = Utc::now();
    let record = draft(
        "/project",
        "parse_entry",
        SeedDraftPurpose::Initial,
        created_at,
    );
    store.begin_seed_llm_draft(&record).await.unwrap();
    let pending = store
        .seed_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap();
    assert_eq!(pending, vec![record.clone()]);

    let completed_at = Utc::now();
    store
        .complete_seed_llm_draft(record.id, r#"["89504e47"]"#, completed_at)
        .await
        .unwrap();
    let done = store
        .seed_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap();
    assert_eq!(done[0].response.as_deref(), Some(r#"["89504e47"]"#));
    assert_eq!(done[0].completed_at, Some(completed_at));
    assert_eq!(done[0].prompt, record.prompt, "the prompt never changes");

    // The response is written once.
    assert!(store
        .complete_seed_llm_draft(record.id, "other", Utc::now())
        .await
        .is_err());
    assert!(store
        .complete_seed_llm_draft(Uuid::new_v4(), "unknown", Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn drafts_carry_their_purpose_and_prompt_version() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    store
        .begin_seed_llm_draft(&draft(
            "/project",
            "parse_entry",
            SeedDraftPurpose::Initial,
            at,
        ))
        .await
        .unwrap();
    store
        .begin_seed_llm_draft(&draft(
            "/project",
            "parse_entry",
            SeedDraftPurpose::Regenerate,
            at,
        ))
        .await
        .unwrap();
    let drafts = store
        .seed_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap();
    assert_eq!(drafts.len(), 2);
    assert!(drafts
        .iter()
        .any(|d| d.purpose == SeedDraftPurpose::Initial));
    assert!(drafts
        .iter()
        .any(|d| d.purpose == SeedDraftPurpose::Regenerate));
    assert!(drafts.iter().all(|d| d.prompt_version == 2));
}

#[tokio::test]
async fn malformed_drafts_are_refused() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    let mut answered = draft("/project", "parse_entry", SeedDraftPurpose::Initial, at);
    answered.response = Some(r#"["00"]"#.to_owned());
    assert!(store.begin_seed_llm_draft(&answered).await.is_err());

    let mut oversized = draft("/project", "parse_entry", SeedDraftPurpose::Initial, at);
    oversized.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_seed_llm_draft(&oversized).await.is_err());

    let mut rootless = draft("", "parse_entry", SeedDraftPurpose::Initial, at);
    rootless.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_seed_llm_draft(&rootless).await.is_err());

    let mut unkeyed = draft("/project", "", SeedDraftPurpose::Initial, at);
    unkeyed.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_seed_llm_draft(&unkeyed).await.is_err());

    let mut unversioned = draft("/project", "parse_entry", SeedDraftPurpose::Initial, at);
    unversioned.prompt = "x".repeat(64 * 1024 + 1);
    unversioned.prompt_version = 0;
    assert!(store.begin_seed_llm_draft(&unversioned).await.is_err());

    let record = draft("/project", "parse_entry", SeedDraftPurpose::Initial, at);
    store.begin_seed_llm_draft(&record).await.unwrap();
    assert!(store
        .complete_seed_llm_draft(record.id, &"y".repeat(64 * 1024 + 1), Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn project_deletion_and_clear_knowledge_remove_drafts() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    for project in ["/project", "/other"] {
        store
            .begin_seed_llm_draft(&draft(
                project,
                "parse_entry",
                SeedDraftPurpose::Regenerate,
                at,
            ))
            .await
            .unwrap();
    }
    store.delete_project("/other").await.unwrap();
    assert!(store
        .seed_llm_drafts_for("/other", "parse_entry")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .seed_llm_drafts_for("/project", "parse_entry")
            .await
            .unwrap()
            .len(),
        1,
        "another project's drafts survive a single project deletion"
    );

    store.clear_knowledge().await.unwrap();
    assert!(store
        .seed_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap()
        .is_empty());
}
