//! Shared scheduler controls use retained ownership when definitions are absent.

#![cfg(feature = "test-support")]

use hf_service::scheduler::{CampaignScheduler, CampaignSchedulerError};

#[tokio::test]
async fn restarted_shared_control_checks_nonterminal_orphan_ownership() {
    let fixture = hf_service::test_support::one_time_recovery_fixture(true)
        .await
        .unwrap();
    let original = fixture.scheduler();
    original.try_remove("schedule-web").await.unwrap();
    original.stop().await;
    let scheduler = CampaignScheduler::try_start(
        fixture.container(),
        fixture.schedules_path().to_path_buf(),
        None,
    )
    .await
    .unwrap();
    assert!(scheduler.list().await.is_empty());
    let outside = tempfile::tempdir().unwrap();
    let foreign_roots = vec![outside.path().canonicalize().unwrap()];
    let owned_roots = vec![fixture.directory_path().canonicalize().unwrap()];
    assert!(matches!(
        scheduler.set_armed_within_roots(true, &foreign_roots).await,
        Err(CampaignSchedulerError::ProjectAccessDenied)
    ));
    assert!(!scheduler.is_armed());
    assert!(
        !scheduler
            .runtime_status_within_roots(&owned_roots)
            .await
            .unwrap()
            .armed
    );
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
    assert!(scheduler
        .set_armed_within_roots(true, &owned_roots)
        .await
        .is_err());
    assert!(!scheduler.is_armed());
    scheduler.stop().await;
}
