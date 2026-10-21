use hf_storage::{ClangOperationRecord, ClangOperationState, Store};
use uuid::Uuid;

#[tokio::test]
async fn operation_transitions_are_atomic_and_terminal_records_are_immutable() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("clang.db"))
        .await
        .unwrap();
    let id = Uuid::new_v4();
    let record = ClangOperationRecord {
        id,
        project_root: "/fixture".into(),
        language: "c".into(),
        state: ClangOperationState::Staging,
        request_json: "{}".into(),
        started_at: "2026-10-20T00:00:00Z".into(),
        ended_at: None,
        failure: None,
    };
    store.create_clang_operation(&record).await.unwrap();
    store
        .advance_clang_operation(
            id,
            ClangOperationState::Staging,
            ClangOperationState::Analyzing,
            None,
        )
        .await
        .unwrap();
    assert!(store
        .advance_clang_operation(
            id,
            ClangOperationState::Staging,
            ClangOperationState::Validating,
            None
        )
        .await
        .is_err());
    store
        .advance_clang_operation(
            id,
            ClangOperationState::Analyzing,
            ClangOperationState::Failed,
            Some("fixture failure"),
        )
        .await
        .unwrap();
    assert_eq!(
        store.clang_operation(id).await.unwrap().unwrap().state,
        ClangOperationState::Failed
    );
    assert!(store
        .advance_clang_operation(
            id,
            ClangOperationState::Failed,
            ClangOperationState::Analyzing,
            None
        )
        .await
        .is_err());
    store.delete_project("/fixture").await.unwrap();
    assert!(store.clang_operation(id).await.unwrap().is_none());
}

#[tokio::test]
async fn newer_analysis_for_another_target_does_not_hide_a_current_result() {
    use hf_core::clang_analysis::ClangIndex;
    use hf_storage::ClangResultRecord;
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("selection.db"))
        .await
        .unwrap();
    let target_a = Uuid::new_v4();
    let target_b = Uuid::new_v4();
    let first = Uuid::new_v4();
    for (id, target) in [(first, target_a), (Uuid::new_v4(), target_b)] {
        let record = ClangOperationRecord {
            id,
            project_root: "/fixture".into(),
            language: "c".into(),
            state: ClangOperationState::Staging,
            request_json: serde_json::json!({"request":{"target_ids":[target]}}).to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            ended_at: None,
            failure: None,
        };
        store.create_clang_operation(&record).await.unwrap();
        store
            .advance_clang_operation(
                id,
                ClangOperationState::Staging,
                ClangOperationState::Analyzing,
                None,
            )
            .await
            .unwrap();
        store
            .advance_clang_operation(
                id,
                ClangOperationState::Analyzing,
                ClangOperationState::Validating,
                None,
            )
            .await
            .unwrap();
        store
            .publish_clang_result(&ClangResultRecord {
                operation_id: id,
                project_root: "/fixture".into(),
                input_sha256: "a".repeat(64),
                image_id: "sha256:fixture".into(),
                inputs_json: "{}".into(),
                index: ClangIndex {
                    schema_version: 1,
                    clang_version: "18.1.3".into(),
                    helper_sha256: "b".repeat(64),
                    units: vec![],
                    functions: vec![],
                    calls: vec![],
                    exploration: None,
                },
            })
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .latest_clang_result_for_target(
                "/fixture",
                target_a,
                hf_core::target::TargetLanguage::C
            )
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        first
    );
}

#[tokio::test]
async fn published_evidence_survives_reopen_and_rejects_conflicting_or_unowned_writes() {
    use hf_core::clang_analysis::ClangIndex;
    use hf_storage::{ClangResultRecord, HarnessClangContextRecord};
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("evidence.db");
    let store = Store::connect(&database).await.unwrap();
    let id = Uuid::new_v4();
    let operation = ClangOperationRecord {
        id,
        project_root: "/fixture".into(),
        language: "c".into(),
        state: ClangOperationState::Staging,
        request_json: "{}".into(),
        started_at: chrono::Utc::now().to_rfc3339(),
        ended_at: None,
        failure: None,
    };
    let result = ClangResultRecord {
        operation_id: id,
        project_root: operation.project_root.clone(),
        input_sha256: "a".repeat(64),
        image_id: "sha256:fixture".into(),
        inputs_json: "{}".into(),
        index: ClangIndex {
            schema_version: 1,
            clang_version: "18.1.3".into(),
            helper_sha256: "b".repeat(64),
            units: vec![],
            functions: vec![],
            calls: vec![],
            exploration: None,
        },
    };
    assert!(store
        .latest_clang_result("/fixture")
        .await
        .unwrap()
        .is_none());
    assert!(store.clang_result(id).await.unwrap().is_none());
    let mut invalid_admission = operation.clone();
    invalid_admission.state = ClangOperationState::Failed;
    assert!(store
        .create_clang_operation(&invalid_admission)
        .await
        .is_err());
    store.create_clang_operation(&operation).await.unwrap();
    assert!(store.publish_clang_result(&result).await.is_err());
    for (from, to) in [
        (ClangOperationState::Staging, ClangOperationState::Analyzing),
        (
            ClangOperationState::Analyzing,
            ClangOperationState::Validating,
        ),
    ] {
        store
            .advance_clang_operation(id, from, to, None)
            .await
            .unwrap();
    }
    let mut invalid_result = result.clone();
    invalid_result.inputs_json = "invalid JSON".into();
    assert!(store.publish_clang_result(&invalid_result).await.is_err());
    assert_eq!(
        store.clang_operation(id).await.unwrap().unwrap().state,
        ClangOperationState::Validating
    );
    assert!(store.clang_result(id).await.unwrap().is_none());
    store.publish_clang_result(&result).await.unwrap();
    store.publish_clang_result(&result).await.unwrap();
    let mut replacement = result.clone();
    replacement.image_id = "sha256:changed".into();
    assert!(store.publish_clang_result(&replacement).await.is_err());
    assert_eq!(
        store.latest_clang_result("/fixture").await.unwrap(),
        Some(result.clone())
    );
    assert!(store
        .latest_clang_result_for_target(
            "/fixture",
            Uuid::new_v4(),
            hf_core::target::TargetLanguage::Cpp
        )
        .await
        .unwrap()
        .is_none());

    let context = HarnessClangContextRecord {
        id: Uuid::new_v4(),
        operation_id: id,
        project_root: "/fixture".into(),
        target_id: Uuid::new_v4(),
        renderer_version: 1,
        rendered: "exact retained provider section".into(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };
    store.append_harness_clang_context(&context).await.unwrap();
    store.append_harness_clang_context(&context).await.unwrap();
    let mut replacement = context.clone();
    replacement.rendered.push_str(" changed");
    assert!(store
        .append_harness_clang_context(&replacement)
        .await
        .is_err());
    let mut foreign = context.clone();
    foreign.id = Uuid::new_v4();
    foreign.project_root = "/other".into();
    assert!(store.append_harness_clang_context(&foreign).await.is_err());
    let mut oversized = context.clone();
    oversized.id = Uuid::new_v4();
    oversized.rendered = "x".repeat(65_537);
    assert!(store
        .append_harness_clang_context(&oversized)
        .await
        .is_err());
    let mut unsupported = context.clone();
    unsupported.renderer_version = 2;
    assert!(store
        .append_harness_clang_context(&unsupported)
        .await
        .is_err());
    drop(store);
    let store = Store::connect(&database).await.unwrap();
    assert_eq!(store.clang_result(id).await.unwrap(), Some(result));
    assert_eq!(
        store.clang_operation(id).await.unwrap().unwrap().state,
        ClangOperationState::Done
    );
    let retained: Vec<String> = sqlx::query_scalar("SELECT rendered FROM harness_clang_contexts")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert_eq!(retained, [context.rendered]);

    let abandoned = ClangOperationRecord {
        id: Uuid::new_v4(),
        ..operation.clone()
    };
    store.create_clang_operation(&abandoned).await.unwrap();
    assert_eq!(
        store.active_clang_operation_ids().await.unwrap(),
        [abandoned.id]
    );
    store.interrupt_clang_operation(abandoned.id).await.unwrap();
    store.interrupt_clang_operation(abandoned.id).await.unwrap();
    store
        .interrupt_clang_operation(Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(
        store
            .clang_operation(abandoned.id)
            .await
            .unwrap()
            .unwrap()
            .state,
        ClangOperationState::Interrupted
    );
    assert!(store.active_clang_operation_ids().await.unwrap().is_empty());
    sqlx::query("UPDATE clang_analysis_results SET index_json='{}' WHERE operation_id=?1")
        .bind(id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store.clang_result(id).await.is_err());
    let other = ClangOperationRecord {
        id: Uuid::new_v4(),
        project_root: "/other".into(),
        ..operation
    };
    store.create_clang_operation(&other).await.unwrap();
    store.delete_project("/fixture").await.unwrap();
    assert!(store.clang_result(id).await.unwrap().is_none());
    assert!(store.clang_operation(id).await.unwrap().is_none());
    assert!(store.clang_operation(other.id).await.unwrap().is_some());
    let contexts: i64 = sqlx::query_scalar("SELECT count(*) FROM harness_clang_contexts")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(contexts, 0);
    store.clear_knowledge().await.unwrap();
    assert!(store.clang_operation(other.id).await.unwrap().is_none());
}
