//! Retained binary-only-fuzzing model prompts and responses (migration 0056).

use chrono::{DateTime, Duration, Utc};
use hf_storage::{BinaryDraftPurpose, BinaryLlmDraftRecord, Store};
use uuid::Uuid;

async fn store() -> (tempfile::TempDir, Store) {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("drafts.db"))
        .await
        .unwrap();
    (directory, store)
}

fn sha(seed: char) -> String {
    seed.to_string().repeat(64)
}

fn draft(purpose: BinaryDraftPurpose, session: Uuid, at: DateTime<Utc>) -> BinaryLlmDraftRecord {
    let explain = purpose == BinaryDraftPurpose::Explain;
    BinaryLlmDraftRecord {
        id: Uuid::new_v4(),
        project_root: "/project".to_owned(),
        binary_sha256: sha('b'),
        purpose,
        session: explain.then_some(session),
        finding_sha256: explain.then(|| sha('f')),
        prompt_version: 1,
        prompt: "Explain this crash of the stripped binary. ...".to_owned(),
        response: None,
        created_at: at,
        completed_at: None,
    }
}

#[tokio::test]
async fn a_draft_is_retained_completed_and_found() {
    let (_dir, store) = store().await;
    let session = Uuid::new_v4();
    let record = draft(BinaryDraftPurpose::Explain, session, Utc::now());
    store.begin_binary_llm_draft(&record).await.unwrap();
    assert!(store
        .latest_binary_explanation("/project", session, &sha('f'))
        .await
        .unwrap()
        .is_none());

    let done_at = Utc::now();
    store
        .complete_binary_llm_draft(record.id, "heap overflow in the parser", done_at)
        .await
        .unwrap();
    let found = store
        .latest_binary_explanation("/project", session, &sha('f'))
        .await
        .unwrap()
        .expect("completed explanation");
    assert_eq!(found.id, record.id);
    assert_eq!(found.purpose, BinaryDraftPurpose::Explain);
    assert_eq!(found.prompt, record.prompt);
    assert_eq!(
        found.response.as_deref(),
        Some("heap overflow in the parser")
    );
    assert_eq!(found.completed_at, Some(done_at));
    assert_eq!(found.session, Some(session));
}

#[tokio::test]
async fn latest_returns_only_completed_rows_and_the_newest() {
    let (_dir, store) = store().await;
    let session = Uuid::new_v4();
    let base = Utc::now() - Duration::minutes(10);
    let older = draft(BinaryDraftPurpose::Explain, session, base);
    let newer = draft(
        BinaryDraftPurpose::Explain,
        session,
        base + Duration::minutes(2),
    );
    let pending = draft(
        BinaryDraftPurpose::Explain,
        session,
        base + Duration::minutes(5),
    );
    for record in [&older, &newer, &pending] {
        store.begin_binary_llm_draft(record).await.unwrap();
    }
    store
        .complete_binary_llm_draft(newer.id, "NEWER", base + Duration::minutes(3))
        .await
        .unwrap();
    store
        .complete_binary_llm_draft(older.id, "OLDER", base + Duration::minutes(4))
        .await
        .unwrap();

    let found = store
        .latest_binary_explanation("/project", session, &sha('f'))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, newer.id, "newest created, never the pending one");

    // A different session, finding, or project is a different key.
    assert!(store
        .latest_binary_explanation("/project", Uuid::new_v4(), &sha('f'))
        .await
        .unwrap()
        .is_none());
    assert!(store
        .latest_binary_explanation("/project", session, &sha('e'))
        .await
        .unwrap()
        .is_none());
    assert!(store
        .latest_binary_explanation("/other", session, &sha('f'))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn non_explain_purposes_round_trip_without_session_or_finding() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    for purpose in [BinaryDraftPurpose::Seeds, BinaryDraftPurpose::Dictionary] {
        let record = draft(purpose, Uuid::new_v4(), at);
        store.begin_binary_llm_draft(&record).await.unwrap();
        store
            .complete_binary_llm_draft(record.id, "ok", at)
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn purpose_session_and_finding_must_agree() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    let session = Uuid::new_v4();

    let mut no_session = draft(BinaryDraftPurpose::Explain, session, at);
    no_session.session = None;
    assert!(store.begin_binary_llm_draft(&no_session).await.is_err());

    let mut no_finding = draft(BinaryDraftPurpose::Explain, session, at);
    no_finding.finding_sha256 = None;
    assert!(store.begin_binary_llm_draft(&no_finding).await.is_err());

    for purpose in [BinaryDraftPurpose::Seeds, BinaryDraftPurpose::Dictionary] {
        let mut with_session = draft(purpose, session, at);
        with_session.session = Some(session);
        assert!(store.begin_binary_llm_draft(&with_session).await.is_err());
        let mut with_finding = draft(purpose, session, at);
        with_finding.finding_sha256 = Some(sha('f'));
        assert!(store.begin_binary_llm_draft(&with_finding).await.is_err());
    }
}

#[tokio::test]
async fn the_sql_checks_enforce_the_same_consistency() {
    let (_dir, store) = store().await;
    let insert = |purpose: &'static str, session: Option<&'static str>, finding: Option<String>| {
        let pool = store.pool().clone();
        async move {
            sqlx::query(
                "INSERT INTO binary_llm_drafts
                 (id, project_root, binary_sha256, purpose, session, finding_sha256,
                  prompt_version, prompt, created_at)
                 VALUES (?1, '/p', ?2, ?3, ?4, ?5, 1, 'prompt', '2026-11-26T00:00:00Z')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind("b".repeat(64))
            .bind(purpose)
            .bind(session)
            .bind(finding)
            .execute(&pool)
            .await
        }
    };
    let finding = Some("f".repeat(64));
    assert!(insert("explain", None, finding.clone()).await.is_err());
    assert!(insert("explain", Some("s"), None).await.is_err());
    // A non-explain row with either key set is refused.
    assert!(insert("seeds", Some("s"), finding.clone()).await.is_err());
    assert!(insert("seeds", Some("s"), None).await.is_err());
    assert!(insert("dictionary", None, finding.clone()).await.is_err());
    assert!(insert("bogus", None, None).await.is_err());
    assert!(insert("explain", Some("s"), Some("short".into()))
        .await
        .is_err());
    insert("explain", Some("s"), finding).await.unwrap();
    insert("seeds", None, None).await.unwrap();
}

#[tokio::test]
async fn malformed_drafts_are_refused() {
    let (_dir, store) = store().await;
    let at = Utc::now();
    let session = Uuid::new_v4();
    let base = draft(BinaryDraftPurpose::Explain, session, at);

    let mut answered = base.clone();
    answered.id = Uuid::new_v4();
    answered.response = Some("x".to_owned());
    assert!(store.begin_binary_llm_draft(&answered).await.is_err());

    let mut oversized = base.clone();
    oversized.prompt = "x".repeat(64 * 1024 + 1);
    assert!(store.begin_binary_llm_draft(&oversized).await.is_err());

    let mut empty = base.clone();
    empty.prompt = String::new();
    assert!(store.begin_binary_llm_draft(&empty).await.is_err());

    let mut rootless = base.clone();
    rootless.project_root = String::new();
    assert!(store.begin_binary_llm_draft(&rootless).await.is_err());

    let mut unversioned = base.clone();
    unversioned.prompt_version = 0;
    assert!(store.begin_binary_llm_draft(&unversioned).await.is_err());

    for bad in ["short", &"g".repeat(64), ""] {
        let mut record = base.clone();
        record.binary_sha256 = bad.to_owned();
        assert!(store.begin_binary_llm_draft(&record).await.is_err());
        let mut record = base.clone();
        record.finding_sha256 = Some(bad.to_owned());
        assert!(store.begin_binary_llm_draft(&record).await.is_err());
    }

    store.begin_binary_llm_draft(&base).await.unwrap();
    assert!(
        store.begin_binary_llm_draft(&base).await.is_err(),
        "duplicate id"
    );
    assert!(store
        .complete_binary_llm_draft(base.id, &"y".repeat(64 * 1024 + 1), Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn completing_twice_or_an_unknown_id_fails() {
    let (_dir, store) = store().await;
    let record = draft(BinaryDraftPurpose::Seeds, Uuid::new_v4(), Utc::now());
    store.begin_binary_llm_draft(&record).await.unwrap();
    store
        .complete_binary_llm_draft(record.id, "first", Utc::now())
        .await
        .unwrap();
    assert!(store
        .complete_binary_llm_draft(record.id, "second", Utc::now())
        .await
        .is_err());
    assert!(store
        .complete_binary_llm_draft(Uuid::new_v4(), "unknown", Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn the_trigger_blocks_rewrites_of_prompt_and_response() {
    let (_dir, store) = store().await;
    let record = draft(BinaryDraftPurpose::Seeds, Uuid::new_v4(), Utc::now());
    store.begin_binary_llm_draft(&record).await.unwrap();
    // The prompt of a pending row cannot change.
    assert!(
        sqlx::query("UPDATE binary_llm_drafts SET prompt = 'edited' WHERE id = ?1")
            .bind(record.id.to_string())
            .execute(store.pool())
            .await
            .is_err()
    );
    store
        .complete_binary_llm_draft(record.id, "answer", Utc::now())
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE binary_llm_drafts SET response = 'edited' WHERE id = ?1")
            .bind(record.id.to_string())
            .execute(store.pool())
            .await
            .is_err()
    );
}
