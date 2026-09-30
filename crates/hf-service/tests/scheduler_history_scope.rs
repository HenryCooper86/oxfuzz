//! Retained scheduler history authorization independent of live definitions.

#![cfg(feature = "test-support")]

#[tokio::test]
async fn removed_schedule_history_filters_before_limiting_and_clearing() {
    let fixture = hf_service::test_support::scheduler_history_fixture()
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let roots = vec![fixture.approved_project().canonicalize().unwrap()];
    assert!(scheduler.list().await.is_empty());
    assert!(scheduler.recent_executions(1).await.unwrap()[0]
        .execution_id
        .starts_with("foreign-"));
    let visible = scheduler
        .recent_executions_within_roots(1, &roots)
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].execution_id, "approved-new");
    assert_eq!(
        scheduler
            .recent_executions_within_roots(20, &roots)
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(scheduler
        .recent_executions_within_roots(0, &roots)
        .await
        .unwrap()
        .is_empty());
    assert!(scheduler
        .recent_executions_within_roots(20, &[])
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        scheduler.clear_history_within_roots(&roots).await.unwrap(),
        2
    );
    assert_eq!(
        scheduler.clear_history_within_roots(&roots).await.unwrap(),
        0
    );
    let remaining = scheduler.recent_executions(200).await.unwrap();
    assert_eq!(remaining.len(), 130);
    assert!(remaining
        .iter()
        .all(|view| view.execution_id.starts_with("foreign-")));
    scheduler.stop().await;
}

#[tokio::test]
async fn missing_retained_project_ownership_refuses_history_clear_before_deletion() {
    let fixture = hf_service::test_support::scheduler_history_fixture()
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let roots = vec![fixture.approved_project().canonicalize().unwrap()];
    let container = fixture.container();
    let store = container.store().unwrap();
    let rows = store.list_schedule_executions(1).await.unwrap();
    let mut legacy: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
    legacy["execution_id"] = serde_json::json!("legacy-unowned");
    legacy["triggered_at"] = serde_json::json!("2030-01-01T00:00:00Z");
    legacy["request_summary"]["parameter_values"] = serde_json::Value::Null;
    store
        .upsert_schedule_execution(
            "legacy-unowned",
            "removed",
            "2030-01-01T00:00:00Z",
            "completed",
            &legacy.to_string(),
        )
        .await
        .unwrap();
    let error = scheduler
        .recent_executions_within_roots(1, &roots)
        .await
        .unwrap_err();
    assert!(!error
        .to_string()
        .contains(fixture.foreign_project().to_str().unwrap()));
    assert!(scheduler.clear_history_within_roots(&roots).await.is_err());
    assert_eq!(
        store.list_schedule_executions(200).await.unwrap().len(),
        133
    );
    store
        .upsert_schedule_execution(
            "legacy-unowned",
            "removed",
            "2030-01-01T00:00:00Z",
            "completed",
            "{invalid",
        )
        .await
        .unwrap();
    let error = scheduler
        .recent_executions_within_roots(1, &roots)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("stored schedule execution is invalid"));
    assert!(scheduler.clear_history_within_roots(&roots).await.is_err());
    assert_eq!(
        store.list_schedule_executions(200).await.unwrap().len(),
        133
    );
    scheduler.stop().await;
}
