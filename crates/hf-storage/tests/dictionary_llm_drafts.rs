//! Retained dictionary-augmentation requests and responses (migration 0047).

use chrono::{DateTime, Duration, Utc};
use hf_storage::{DictionaryLlmDraftRecord, Store};
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
    signature: &str,
    at: DateTime<Utc>,
) -> DictionaryLlmDraftRecord {
    DictionaryLlmDraftRecord {
        id: Uuid::new_v4(),
        project_root: project.to_owned(),
        target: target.to_owned(),
        static_dict_sha256: signature.to_owned(),
        prompt: "You are the fuzzing-dictionary author for oxfuzz. ...".to_owned(),
        response: None,
        created_at: at,
        completed_at: None,
    }
}

fn signature(seed: char) -> String {
    seed.to_string().repeat(64)
}

#[tokio::test]
async fn a_draft_is_retained_before_dispatch_and_completed_once() {
    let (_dir, store) = store().await;
    let created_at = Utc::now();
    let record = draft("/project", "parse_entry", &signature('a'), created_at);
    store.begin_dictionary_llm_draft(&record).await.unwrap();
    let pending = store
        .dictionary_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap();
    assert_eq!(pending, vec![record.clone()]);

    let completed_at = Utc::now();
    store
        .complete_dictionary_llm_draft(record.id, "\"ZZQQTOKEN\"\n", completed_at)
        .await
        .unwrap();
    let done = store
        .dictionary_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap();
    assert_eq!(done[0].response.as_deref(), Some("\"ZZQQTOKEN\"\n"));
    assert_eq!(done[0].completed_at, Some(completed_at));
    assert_eq!(done[0].prompt, record.prompt, "the prompt never changes");

    // The response is written once.
    assert!(store
        .complete_dictionary_llm_draft(record.id, "other", Utc::now())
        .await
        .is_err());
    assert!(store
        .complete_dictionary_llm_draft(Uuid::new_v4(), "unknown", Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn the_latest_completed_draft_for_a_source_version_is_reused() {
    let (_dir, store) = store().await;
    let base = Utc::now() - Duration::minutes(10);
    // An older completed draft and a newer pending one for the same triple.
    let older = draft("/project", "parse_entry", &signature('a'), base);
    let newer = draft(
        "/project",
        "parse_entry",
        &signature('a'),
        base + Duration::minutes(5),
    );
    store.begin_dictionary_llm_draft(&older).await.unwrap();
    store
        .complete_dictionary_llm_draft(older.id, "\"OLD\"\n", base + Duration::seconds(30))
        .await
        .unwrap();
    store.begin_dictionary_llm_draft(&newer).await.unwrap();

    let reused = store
        .latest_completed_dictionary_llm_draft("/project", "parse_entry", &signature('a'))
        .await
        .unwrap()
        .expect("the completed draft is reused");
    assert_eq!(reused.id, older.id, "a pending draft is never reused");
    assert_eq!(reused.response.as_deref(), Some("\"OLD\"\n"));

    // A different project, target, or static dictionary is a different key.
    assert!(store
        .latest_completed_dictionary_llm_draft("/other", "parse_entry", &signature('a'))
        .await
        .unwrap()
        .is_none());
    assert!(store
        .latest_completed_dictionary_llm_draft("/project", "parse_value", &signature('a'))
        .await
        .unwrap()
        .is_none());
    assert!(store
        .latest_completed_dictionary_llm_draft("/project", "parse_entry", &signature('b'))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn malformed_drafts_are_refused() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    let mut answered = draft("/project", "parse_entry", &signature('a'), at);
    answered.response = Some("\"TOKEN\"\n".to_owned());
    assert!(store.begin_dictionary_llm_draft(&answered).await.is_err());

    let mut oversized = draft("/project", "parse_entry", &signature('a'), at);
    oversized.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_dictionary_llm_draft(&oversized).await.is_err());

    let mut rootless = draft("", "parse_entry", &signature('a'), at);
    rootless.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_dictionary_llm_draft(&rootless).await.is_err());

    let mut unkeyed = draft("/project", "", &signature('a'), at);
    unkeyed.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_dictionary_llm_draft(&unkeyed).await.is_err());

    for signature in ["short", &"g!".repeat(64), ""] {
        let mut bad = draft("/project", "parse_entry", signature, at);
        bad.prompt = "x".repeat(64 * 1024 + 1);
        assert!(store.begin_dictionary_llm_draft(&bad).await.is_err());
    }

    let record = draft("/project", "parse_entry", &signature('a'), at);
    store.begin_dictionary_llm_draft(&record).await.unwrap();
    assert!(store
        .complete_dictionary_llm_draft(record.id, &"y".repeat(64 * 1024 + 1), Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn project_deletion_and_clear_knowledge_remove_drafts() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    for project in ["/project", "/other"] {
        store
            .begin_dictionary_llm_draft(&draft(project, "parse_entry", &signature('a'), at))
            .await
            .unwrap();
    }
    store.delete_project("/other").await.unwrap();
    assert!(store
        .dictionary_llm_drafts_for("/other", "parse_entry")
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .dictionary_llm_drafts_for("/project", "parse_entry")
            .await
            .unwrap()
            .len(),
        1,
        "another project's drafts survive a single project deletion"
    );

    store.clear_knowledge().await.unwrap();
    assert!(store
        .dictionary_llm_drafts_for("/project", "parse_entry")
        .await
        .unwrap()
        .is_empty());
}
