//! Preview delivery through the existing public scheduler read API.
use hf_service::scheduler::{CampaignParams, CampaignScheduler};

#[tokio::test]
async fn schedule_list_includes_calendar_preview_without_dispatching() {
    let root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path().join("config"));
    let scheduler = CampaignScheduler::try_start(
        hf_service::ServiceContainer::stubbed(),
        root.path().join("schedules.json"),
        None,
    )
    .await
    .unwrap();
    let params = CampaignParams {
        project: root.path().display().to_string(),
        target: None,
        engine: "libfuzzer".into(),
        lang: "c".into(),
        duration_secs: 60,
        max_runs: Some(4),
        max_total_secs: Some(240),
        schedule_id: String::new(),
    };
    let schedule = scheduler
        .try_create(
            "morning",
            &params,
            hf_service::scheduler::parse_trigger("cron", "CRON_TZ=Asia/Shanghai 0 9 * * *")
                .unwrap(),
        )
        .await
        .unwrap();
    let before = serde_json::to_value(scheduler.list().await).unwrap();
    let views = serde_json::to_value(scheduler.list_views().await.unwrap()).unwrap();
    let after = serde_json::to_value(scheduler.list().await).unwrap();
    let history = scheduler.recent_executions(10).await.unwrap();
    scheduler.stop().await;
    assert_eq!(before, after);
    assert!(history.is_empty());
    assert_eq!(views[0]["id"], schedule.id);
    assert_eq!(views[0]["preview"]["timezone"], "Asia/Shanghai");
    assert_eq!(views[0]["preview"]["state"], "scheduled");
    assert_eq!(
        views[0]["preview"]["next_fires"].as_array().unwrap().len(),
        3
    );
    assert_eq!(views[0]["preview"]["remaining_runs"], 4);
    assert_eq!(views[0]["preview"]["remaining_secs"], 240);
}
