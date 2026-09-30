//! Recovery ownership survives definition removal and precedes cancellation.

#![cfg(feature = "test-support")]

use hf_service::scheduler::RecoveryPublicErrorCode;

#[tokio::test]
async fn retained_owner_cannot_cancel_receipt_attached_to_foreign_current_definition() {
    let fixture = hf_service::test_support::one_time_recovery_fixture(true)
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    scheduler.stop().await;
    let foreign = tempfile::tempdir().unwrap();
    let mut definitions: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture.schedules_path()).unwrap()).unwrap();
    definitions[0]["parameter_values"]["project"] = serde_json::json!(foreign.path());
    definitions[0]["name"] = serde_json::json!("private foreign campaign");
    std::fs::write(
        fixture.schedules_path(),
        serde_json::to_vec(&definitions).unwrap(),
    )
    .unwrap();
    let scheduler = hf_service::scheduler::CampaignScheduler::try_start(
        fixture.container(),
        fixture.schedules_path().to_path_buf(),
        None,
    )
    .await
    .unwrap();
    let roots = vec![fixture.directory_path().canonicalize().unwrap()];
    let before = fixture
        .container()
        .store()
        .unwrap()
        .schedule_occurrence("occ-web")
        .await
        .unwrap()
        .unwrap();
    let visible = scheduler
        .list_one_time_recoveries_within_roots(&roots)
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert!(!visible[0].schedule_exists);
    assert!(visible[0].schedule_name.is_none());
    let error = scheduler
        .acknowledge_one_time_recovery_within_roots("occ-web", &roots)
        .await
        .unwrap_err()
        .into_public_recovery_error();
    assert_eq!(error.code, RecoveryPublicErrorCode::Forbidden);
    let after = fixture
        .container()
        .store()
        .unwrap()
        .schedule_occurrence("occ-web")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    scheduler.stop().await;
}

#[tokio::test]
async fn recovery_scope_denial_preserves_receipt_and_approved_orphan_can_be_cancelled() {
    let fixture = hf_service::test_support::one_time_recovery_fixture(true)
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let roots = vec![fixture.directory_path().canonicalize().unwrap()];
    let foreign = tempfile::tempdir().unwrap();
    let foreign_roots = vec![foreign.path().canonicalize().unwrap()];
    scheduler.try_remove("schedule-web").await.unwrap();
    let store = fixture.container().store().unwrap().clone();
    let before = store.schedule_occurrence("occ-web").await.unwrap().unwrap();
    assert!(scheduler
        .list_one_time_recoveries_within_roots(&foreign_roots)
        .await
        .unwrap()
        .is_empty());
    let denied = scheduler
        .acknowledge_one_time_recovery_within_roots("occ-web", &foreign_roots)
        .await
        .unwrap_err()
        .into_public_recovery_error();
    assert_eq!(denied.code, RecoveryPublicErrorCode::Forbidden);
    let after = store.schedule_occurrence("occ-web").await.unwrap().unwrap();
    assert_eq!(after.state, before.state);
    assert_eq!(after.execution_data_json, before.execution_data_json);
    let visible = scheduler
        .list_one_time_recoveries_within_roots(&roots)
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert!(!visible[0].schedule_exists);
    let cancelled = scheduler
        .acknowledge_one_time_recovery_within_roots("occ-web", &roots)
        .await
        .unwrap();
    assert_eq!(cancelled.state, "cancelled");
    assert!(!cancelled.schedule_exists);
    assert_eq!(
        scheduler
            .acknowledge_one_time_recovery_within_roots("occ-web", &roots)
            .await
            .unwrap()
            .state,
        "cancelled"
    );
    scheduler.clear_history().await.unwrap();
    assert_eq!(
        scheduler
            .acknowledge_one_time_recovery_within_roots("occ-web", &roots)
            .await
            .unwrap_err()
            .into_public_recovery_error()
            .code,
        RecoveryPublicErrorCode::Unavailable
    );
    assert_eq!(
        scheduler
            .acknowledge_one_time_recovery("occ-web")
            .await
            .unwrap()
            .state,
        "cancelled"
    );
    scheduler.stop().await;
}

#[tokio::test]
async fn missing_retained_recovery_project_fails_before_cancelling() {
    let fixture = hf_service::test_support::one_time_recovery_fixture(true)
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let roots = vec![fixture.directory_path().canonicalize().unwrap()];
    let store = fixture.container().store().unwrap().clone();
    let row = store.schedule_occurrence("occ-web").await.unwrap().unwrap();
    let mut execution: serde_json::Value =
        serde_json::from_str(row.execution_data_json.as_ref().unwrap()).unwrap();
    execution["request_summary"] = serde_json::json!({});
    store
        .upsert_schedule_execution(
            "exec-web",
            "schedule-web",
            &row.triggered_at,
            "running",
            &execution.to_string(),
        )
        .await
        .unwrap();
    assert_eq!(
        scheduler
            .list_one_time_recoveries_within_roots(&roots)
            .await
            .unwrap_err()
            .into_public_recovery_error()
            .code,
        RecoveryPublicErrorCode::Unavailable
    );
    assert_eq!(
        scheduler
            .acknowledge_one_time_recovery_within_roots("occ-web", &roots)
            .await
            .unwrap_err()
            .into_public_recovery_error()
            .code,
        RecoveryPublicErrorCode::Unavailable
    );
    assert_eq!(
        store
            .schedule_occurrence("occ-web")
            .await
            .unwrap()
            .unwrap()
            .state,
        "running"
    );
    scheduler.stop().await;
}
