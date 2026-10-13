use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate as service;

#[path = "../../tests/common/scheduler_fixture.rs"]
mod scheduler_fixture;
use scheduler_fixture::{Fixture, TestRuntime};

use super::{
    CampaignStateStore, ConcurrencyGate, FuzzCampaignDispatcher, ScheduleFileStore,
    WorkflowDispatcher, CAMPAIGN_KIND,
};

struct SavedEnvironment(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl SavedEnvironment {
    fn capture() -> Self {
        Self(
            ["HF_CONFIG_DIR", "HF_WORKSPACE_DIR", "HF_AUTO_APPROVE"]
                .into_iter()
                .map(|name| (name, std::env::var_os(name)))
                .collect(),
        )
    }
}

impl Drop for SavedEnvironment {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            if let Some(value) = value {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }
}

/// Database I/O must not auto-advance the paused Tokio clock. Sender drop
/// releases the blocking task even when a test assertion unwinds.
fn pause_campaign_clock() -> tokio::sync::oneshot::Sender<()> {
    tokio::time::pause();
    let (release, wait) = tokio::sync::oneshot::channel();
    tokio::task::spawn_blocking(move || {
        // Sender drop is the normal end of this test's clock hold.
        let _ = wait.blocking_recv();
    });
    release
}

async fn assert_campaign_budget(seconds: u64, durations: &[u64]) {
    let _environment = service::ServiceContainer::workspace_environment_test_gate()
        .lock()
        .await;
    let _restore_environment = SavedEnvironment::capture();
    let fixture = Fixture::new(TestRuntime::new(Duration::from_millis(1100), false)).await;
    let state = Arc::new(
        CampaignStateStore::try_load(fixture.root.path().join("campaign_state.json")).unwrap(),
    );
    let dispatcher = FuzzCampaignDispatcher {
        container: fixture.service.clone().without_provider_pool(),
        state: Arc::clone(&state),
        gate: Arc::new(ConcurrencyGate::new(1)),
        notifier: Arc::new(Mutex::new(None)),
        schedules: Arc::new(ScheduleFileStore::new(
            fixture.root.path().join("schedules.json"),
        )),
        manager: Weak::new(),
    };
    let mut params = fixture.params();
    params.schedule_id = "budget".into();
    params.max_runs = None;
    params.max_total_secs = Some(seconds);
    let params = serde_json::to_value(params).unwrap();

    let _clock = pause_campaign_clock();
    let result = dispatcher
        .dispatch(CAMPAIGN_KIND, params.clone())
        .await
        .unwrap();
    assert!(result.success, "{result:?}");
    assert_eq!(*fixture.runtime.durations.lock().unwrap(), durations);
    let consumed = state.snapshot("budget");
    assert_eq!(consumed.runs_done as usize, durations.len());
    assert_eq!(consumed.secs_done, seconds);

    let exhausted = dispatcher.dispatch(CAMPAIGN_KIND, params).await.unwrap();
    assert!(exhausted.summary.starts_with("skipped:"), "{exhausted:?}");
    assert_eq!(*fixture.runtime.durations.lock().unwrap(), durations);
}

#[tokio::test]
async fn time_budget_caps_fuzzer_duration_and_stops_additional_iterations() {
    assert_campaign_budget(2, &[2, 1]).await;
}

#[tokio::test]
async fn one_second_allowance_can_launch_a_one_second_run() {
    assert_campaign_budget(1, &[1]).await;
}
