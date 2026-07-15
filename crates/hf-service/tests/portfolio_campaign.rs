//! Portfolio-campaign wiring: a campaign is created for a project (not a single
//! target), surfaces through `list_views` with its progress, and the global
//! concurrency cap round-trips. The rotation/budget *logic* is unit-tested in
//! `scheduler.rs`; this covers the scheduler surface the GUI drives.

use std::sync::Arc;

use hf_service::scheduler::{CampaignParams, CampaignScheduler};
use hf_service::ServiceContainer;
use hf_storage::Store;

async fn scheduler_with_store() -> (CampaignScheduler, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(dir.path().join("portfolio.db"))
            .await
            .unwrap(),
    );
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    let scheduler =
        CampaignScheduler::start(container, dir.path().join("schedules.json"), None).await;
    (scheduler, dir)
}

#[tokio::test]
async fn a_portfolio_campaign_has_no_fixed_target_and_starts_at_zero_progress() {
    let (scheduler, _dir) = scheduler_with_store().await;
    let params = CampaignParams {
        project: "/tmp/portfolio_project".to_owned(),
        target: None, // all promoted targets
        engine: String::new(),
        lang: "c".to_owned(),
        duration_secs: 60,
        max_runs: Some(10),
        max_total_secs: None,
        schedule_id: String::new(),
    };
    let trigger = hf_service::scheduler::parse_trigger("interval", "3600").unwrap();
    scheduler.create("nightly sweep", &params, trigger).await;

    let views = scheduler.list_views().await.unwrap();
    assert_eq!(views.len(), 1);
    let v = &views[0];
    assert!(v.target.is_none(), "portfolio campaign has no fixed target");
    assert_eq!(v.max_runs, Some(10));
    assert_eq!(v.runs_done, 0, "a fresh campaign has run nothing yet");
    // The schedule id is injected so the headless dispatcher can key state.
    assert!(!v.id.is_empty());
}

#[tokio::test]
async fn concurrency_cap_round_trips_and_floors_at_one() {
    let (scheduler, _dir) = scheduler_with_store().await;
    scheduler.set_max_concurrent(5);
    assert_eq!(scheduler.max_concurrent(), 5);
    scheduler.set_max_concurrent(0);
    assert_eq!(scheduler.max_concurrent(), 1, "never below one");
}

#[tokio::test]
async fn deleting_a_campaign_clears_it_from_the_list() {
    let (scheduler, _dir) = scheduler_with_store().await;
    let sched = scheduler
        .create(
            "one",
            &CampaignParams {
                project: "/tmp/p".to_owned(),
                duration_secs: 30,
                ..CampaignParams::default()
            },
            hf_service::scheduler::parse_trigger("interval", "60").unwrap(),
        )
        .await;
    assert_eq!(scheduler.list_views().await.unwrap().len(), 1);
    assert!(scheduler.remove(&sched.id).await);
    assert!(scheduler.list_views().await.unwrap().is_empty());
    // A bogus id is not a success.
    assert!(!scheduler.remove("no-such-id").await);
}
