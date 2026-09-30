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

#[tokio::test]
async fn scoped_definitions_refuse_foreign_mutations_and_preserve_approved_access() {
    let (scheduler, dir) = scheduler_with_store().await;
    let approved = dir.path().join("approved");
    let foreign = dir.path().join("foreign");
    std::fs::create_dir(&approved).unwrap();
    std::fs::create_dir(&foreign).unwrap();
    let roots = vec![approved.canonicalize().unwrap()];
    let mut ids = Vec::new();
    for project in [&approved, &foreign] {
        let schedule = scheduler
            .try_create(
                "campaign",
                &CampaignParams {
                    project: project.display().to_string(),
                    duration_secs: 30,
                    ..CampaignParams::default()
                },
                hf_service::scheduler::parse_trigger("cron", "0 0 1 1 *").unwrap(),
            )
            .await
            .unwrap();
        ids.push(schedule.id);
    }
    let views = scheduler.list_views_within_roots(&roots).await.unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].id, ids[0]);
    assert!(scheduler
        .list_views_within_roots(&[])
        .await
        .unwrap()
        .is_empty());
    let before = std::fs::read(dir.path().join("schedules.json")).unwrap();
    for id in [&ids[1], &ids[0]] {
        let denied_roots = if id == &ids[1] { roots.as_slice() } else { &[] };
        assert!(scheduler
            .try_set_enabled_within_roots(id, false, denied_roots)
            .await
            .is_err());
        assert!(scheduler
            .try_remove_within_roots(id, denied_roots)
            .await
            .is_err());
        assert_eq!(
            std::fs::read(dir.path().join("schedules.json")).unwrap(),
            before
        );
    }
    assert!(scheduler
        .try_set_enabled_within_roots(&ids[0], false, &roots)
        .await
        .unwrap());
    let views = scheduler.list_views_within_roots(&roots).await.unwrap();
    assert!(!views[0].enabled);
    assert!(scheduler
        .try_set_enabled_within_roots(&ids[0], true, &roots)
        .await
        .unwrap());
    assert!(scheduler
        .try_remove_within_roots(&ids[0], &roots)
        .await
        .unwrap());
    assert!(scheduler
        .list_views_within_roots(&roots)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(scheduler.list().await[0].id, ids[1]);
    assert!(!scheduler
        .try_remove_within_roots("missing", &roots)
        .await
        .unwrap());
    assert!(!scheduler
        .try_set_enabled_within_roots("missing", false, &roots)
        .await
        .unwrap());
    scheduler.stop().await;
}

#[tokio::test]
async fn scoped_definitions_fail_loudly_when_stored_project_is_unavailable() {
    let (scheduler, dir) = scheduler_with_store().await;
    let project = dir.path().join("private-project");
    std::fs::create_dir(&project).unwrap();
    let roots = vec![dir.path().canonicalize().unwrap()];
    let schedule = scheduler
        .try_create(
            "campaign",
            &CampaignParams {
                project: project.display().to_string(),
                duration_secs: 30,
                ..CampaignParams::default()
            },
            hf_service::scheduler::parse_trigger("cron", "0 0 1 1 *").unwrap(),
        )
        .await
        .unwrap();
    let before = std::fs::read(dir.path().join("schedules.json")).unwrap();
    std::fs::remove_dir(&project).unwrap();
    for replaced_by_file in [false, true] {
        if replaced_by_file {
            std::fs::write(&project, b"inert").unwrap();
        }
        let error = scheduler.list_views_within_roots(&roots).await.unwrap_err();
        assert!(!error.to_string().contains(project.to_str().unwrap()));
        assert!(scheduler
            .try_remove_within_roots(&schedule.id, &roots)
            .await
            .is_err());
        assert!(scheduler
            .try_set_enabled_within_roots(&schedule.id, false, &roots)
            .await
            .is_err());
        assert_eq!(
            std::fs::read(dir.path().join("schedules.json")).unwrap(),
            before
        );
    }
    scheduler.stop().await;
}
