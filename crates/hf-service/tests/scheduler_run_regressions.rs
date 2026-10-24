//! Real scheduler/run consumers with sandbox execution replaced by a controlled runtime.
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use hf_core::engine::EngineKind;
use hf_service as service;
use hf_service::scheduler::CampaignScheduler;
use hf_service::RunLifecycleStatus;

#[path = "common/scheduler_fixture.rs"]
mod scheduler_fixture;
use scheduler_fixture::{Fixture, TestRuntime};

impl Fixture {
    async fn scheduler(&self) -> CampaignScheduler {
        CampaignScheduler::try_start(
            self.service.clone().without_provider_pool(),
            self.root.path().join("schedules.json"),
            None,
        )
        .await
        .unwrap()
    }
}

async fn wait_for_completed(scheduler: &CampaignScheduler) {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let history = scheduler.recent_executions(10).await.unwrap();
            assert!(
                !history.iter().any(|entry| entry.status == "failed"),
                "fixture failed: {history:?}"
            );
            if history
                .iter()
                .any(|entry| entry.status == "completed" && !entry.summary.starts_with("skipped:"))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mock campaign should complete");
}

#[test]
fn excessive_interval_is_rejected_at_user_input() {
    assert!(hf_service::scheduler::parse_trigger("interval", &u64::MAX.to_string()).is_err());
}

#[tokio::test]
async fn panicking_subscribers_do_not_hang_start_or_prevent_durable_cancellation() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, true)).await;
    let run_id = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.service.start_fuzzer(
            fixture.project.clone(),
            "parse_background".into(),
            EngineKind::LibFuzzer,
            60,
            None,
            Arc::new(|_, _| panic!("progress subscriber failed")),
            Arc::new(|_, _| panic!("status subscriber failed")),
        ),
    )
    .await
    .expect("startup resolves despite subscriber panic")
    .unwrap();
    assert!(fixture.service.cancel_run(run_id));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture
                .service
                .run_control_status(run_id)
                .await
                .unwrap()
                .unwrap()
                .status
                == RunLifecycleStatus::Cancelled
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled run finalizes durably");
}

#[tokio::test]
async fn unexpected_background_panic_closes_startup_acknowledgement() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    fixture.runtime.panic_image.store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.service.start_fuzzer(
            fixture.project.clone(),
            "parse_background".into(),
            EngineKind::LibFuzzer,
            60,
            None,
            Arc::new(|_, _| {}),
            Arc::new(|_, _| {}),
        ),
    )
    .await
    .expect("task failure must close the acknowledgement channel");
    assert!(result.is_err());
}

#[tokio::test]
async fn one_run_budget_completes_only_one_iteration() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    let scheduler = fixture.scheduler().await;
    scheduler
        .try_create(
            "one run",
            &fixture.params(),
            hf_service::scheduler::parse_trigger("once", "2000-01-01T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
    scheduler.arm();
    wait_for_completed(&scheduler).await;
    let views = scheduler.list_views().await.unwrap();
    scheduler.stop().await;
    assert_eq!(views[0].runs_done, 1);
    assert_eq!(fixture.runtime.durations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn overlapping_fires_cannot_spend_the_same_run_allowance() {
    let release = Arc::new(tokio::sync::Notify::new());
    let mut runtime = TestRuntime::new(Duration::ZERO, false);
    Arc::get_mut(&mut runtime).unwrap().release = Some(Arc::clone(&release));
    let fixture = Fixture::new(runtime).await;
    let scheduler = fixture.scheduler().await;
    let mut schedule = scheduler
        .try_create(
            "overlap",
            &fixture.params(),
            hf_service::scheduler::parse_trigger("interval", "1").unwrap(),
        )
        .await
        .unwrap();
    scheduler.stop().await;
    schedule.policies.concurrency_policy = Some(hf_scheduler::config::ConcurrencyPolicy::Allow);
    std::fs::write(
        fixture.root.path().join("schedules.json"),
        serde_json::to_vec(&vec![schedule]).unwrap(),
    )
    .unwrap();
    let scheduler = fixture.scheduler().await;
    scheduler.arm();
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let history = scheduler.recent_executions(10).await.unwrap();
            if history
                .iter()
                .any(|entry| entry.summary.contains("already has work in progress"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("live scheduler must attempt an overlapping fire");
    release.notify_one();
    wait_for_completed(&scheduler).await;
    let views = scheduler.list_views().await.unwrap();
    let history = scheduler.recent_executions(10).await.unwrap();
    scheduler.stop().await;
    assert_eq!(views[0].runs_done, 1);
    assert_eq!(fixture.runtime.durations.lock().unwrap().len(), 1);
    assert!(
        history
            .iter()
            .any(|entry| entry.summary.contains("already has work in progress")),
        "overlapping occurrence exercised: {history:?}"
    );
}

#[tokio::test]
async fn direct_creation_rejects_invalid_intervals_without_registering_them() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    let scheduler = fixture.scheduler().await;
    assert!(scheduler
        .try_create(
            "invalid",
            &fixture.params(),
            hf_scheduler::store::TriggerConfig::Interval {
                interval_secs: u64::MAX
            }
        )
        .await
        .is_err());
    assert!(scheduler.list_views().await.unwrap().is_empty());
    scheduler.stop().await;
}

#[tokio::test]
async fn failed_cron_enable_restores_its_original_calendar_cursor() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    let scheduler = fixture.scheduler().await;
    let schedule = scheduler
        .try_create(
            "cron",
            &fixture.params(),
            hf_service::scheduler::parse_trigger("cron", "0 2 * * *").unwrap(),
        )
        .await
        .unwrap();
    scheduler
        .try_set_enabled(&schedule.id, false)
        .await
        .unwrap();
    let before = scheduler.list_views().await.unwrap().pop().unwrap();
    let path = fixture.root.path().join("schedules.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(scheduler.try_set_enabled(&schedule.id, true).await.is_err());
    let after = scheduler.list_views().await.unwrap().pop().unwrap();
    scheduler.stop().await;
    assert!(!after.enabled);
    assert_eq!(after.last_fire, before.last_fire);
}
