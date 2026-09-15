//! Event chains are bounded by executor admission, not payload filtering.
use async_trait::async_trait;
use chrono::Utc;
use hf_scheduler::{
    DispatchError, DispatchResult, ExecutionStatus, IncomingEvent, Schedule, SchedulerConfig,
    SchedulerManager, TriggerConfig, WorkflowDispatcher,
};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Default)]
struct EchoDispatcher {
    manager: Mutex<Weak<SchedulerManager>>,
    depths: Mutex<Vec<u64>>,
}

#[async_trait]
impl WorkflowDispatcher for EchoDispatcher {
    async fn dispatch(
        &self,
        _: &str,
        params: serde_json::Value,
    ) -> Result<DispatchResult, DispatchError> {
        let depth = hf_scheduler::current_cascade_depth();
        self.depths.lock().await.push(depth);
        let manager = self.manager.lock().await.upgrade().unwrap();
        manager
            .emit_event(IncomingEvent {
                event_type: "loop".into(),
                payload: None,
                timestamp: Utc::now(),
                source_schedule_id: Some(params["id"].as_str().unwrap().to_owned()),
                cascade_depth: depth,
            })
            .await;
        Ok(DispatchResult {
            success: true,
            summary: "echo".into(),
            output: serde_json::Value::Null,
            duration_ms: 0,
            error: None,
        })
    }
}

#[tokio::test]
async fn two_schedules_cannot_reset_each_others_cascade_budget() {
    let manager = Arc::new(SchedulerManager::new(SchedulerConfig {
        max_event_cascade_depth: 2,
        ..SchedulerConfig::default()
    }));
    let echo = Arc::new(EchoDispatcher::default());
    *echo.manager.lock().await = Arc::downgrade(&manager);
    manager.set_dispatcher(echo.clone()).await;
    for id in ["a", "b"] {
        let mut schedule = Schedule::new(
            id,
            id,
            TriggerConfig::Event {
                event_type: "loop".into(),
                debounce_secs: 0,
                filter: None,
            },
            "echo",
        );
        schedule.policies.concurrency_policy = Some(hf_scheduler::ConcurrencyPolicy::Allow);
        schedule.parameter_values = serde_json::json!({"id": id, "cascade_depth": 0});
        manager.register(schedule).await;
    }
    manager.arm();
    manager.start(Duration::from_secs(60)).await;
    manager
        .emit_event(IncomingEvent {
            event_type: "loop".into(),
            payload: None,
            timestamp: Utc::now(),
            source_schedule_id: None,
            cascade_depth: 0,
        })
        .await;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let a = manager.execution_history("a").await;
            let b = manager.execution_history("b").await;
            if a.iter()
                .chain(&b)
                .filter(|run| {
                    run.status == ExecutionStatus::Skipped
                        && run.response_summary["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains("cascade"))
                })
                .count()
                == 2
            {
                break;
            }
            assert!(
                echo.depths.lock().await.len() <= 6,
                "cascade admission failed to stop the chain"
            );
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cascade skips were not retained");
    manager.stop().await;
    let mut depths = echo.depths.lock().await.clone();
    depths.sort_unstable();
    assert_eq!(depths, [0, 0, 1, 1, 2, 2]);
    for id in ["a", "b"] {
        let history = manager.execution_history(id).await;
        let skipped = history
            .iter()
            .find(|run| run.status == ExecutionStatus::Skipped)
            .unwrap();
        assert_eq!(skipped.request_summary["cascade_depth"], 3);
    }
}

#[tokio::test]
async fn excessive_depth_is_rejected_when_the_event_bridge_is_bypassed() {
    let manager = SchedulerManager::new(SchedulerConfig {
        max_event_cascade_depth: 0,
        ..SchedulerConfig::default()
    });
    let echo = Arc::new(EchoDispatcher::default());
    manager.set_dispatcher(echo.clone()).await;
    manager
        .register(Schedule::new(
            "direct",
            "direct",
            TriggerConfig::Event {
                event_type: "loop".into(),
                debounce_secs: 0,
                filter: None,
            },
            "echo",
        ))
        .await;
    manager.start(Duration::from_secs(60)).await;
    manager
        .trigger_sender()
        .unwrap()
        .send(hf_scheduler::FiredTrigger {
            schedule_id: "direct".into(),
            fired_at: Utc::now(),
            trigger_type: hf_scheduler::TriggerType::Event,
            is_recovery: false,
            event_payload: Some(serde_json::json!({"cascade_depth": 0})),
            cascade_depth: 1,
        })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while manager.execution_history("direct").await.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    manager.stop().await;
    let history = manager.execution_history("direct").await;
    assert_eq!(history[0].status, ExecutionStatus::Skipped);
    assert_eq!(history[0].request_summary["cascade_depth"], 1);
    assert!(echo.depths.lock().await.is_empty());
}
