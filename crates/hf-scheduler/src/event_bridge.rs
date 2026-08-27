//! Event bridge: connects external event producers to `EventSchedule` triggers.
//!
//! The `EventBridge` receives events (e.g., from file watchers, webhooks) and
//! matches them against registered `EventSchedule` triggers, applying debounce
//! and optional payload filtering before enqueueing trigger events.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;
use tracing::{debug, info};

use crate::queue::TriggerSender;
use crate::store::{ScheduleStore, TriggerConfig};

// `Schedule` is used in tests.
#[cfg(test)]
use crate::store::Schedule;
use crate::trigger::{FiredTrigger, TriggerType};

/// An incoming event from an external producer.
#[derive(Debug, Clone)]
pub struct IncomingEvent {
    /// Event type identifier (e.g. `"file.changed"`).
    pub event_type: String,
    /// Optional payload with event details.
    pub payload: Option<Value>,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// The schedule whose execution produced this event, when one did.
    ///
    /// `None` for events an operator, the CLI, or an interactive run produced.
    /// A schedule is never fired by an event its own execution emitted: a
    /// campaign schedule triggered by `run.completed` runs a campaign whose run
    /// phase emits `run.completed`, so without this it re-fires itself for as
    /// long as the process lives. See [`EventBridge::process_event`].
    pub source_schedule_id: Option<String>,
}

/// Event bridge that evaluates incoming events against registered schedules.
pub struct EventBridge {
    /// Track last event time per schedule for debounce.
    last_event: HashMap<String, DateTime<Utc>>,
}

impl EventBridge {
    /// Create a new event bridge.
    pub fn new() -> Self {
        Self {
            last_event: HashMap::new(),
        }
    }

    /// Process an incoming event against registered schedules.
    ///
    /// Returns the list of schedule IDs that matched and were enqueued.
    pub async fn process_event(
        &mut self,
        event: &IncomingEvent,
        store: &ScheduleStore,
        tx: &TriggerSender,
    ) -> Vec<String> {
        let mut matched = Vec::new();

        for schedule in store.list_enabled() {
            if let TriggerConfig::Event {
                event_type,
                debounce_secs,
                filter,
            } = &schedule.trigger
            {
                // Check event type.
                if event_type != &event.event_type {
                    continue;
                }

                // A schedule never reacts to an event its own execution
                // produced. Chaining a campaign off `run.completed` is a
                // legitimate configuration, but the campaign itself emits
                // `run.completed`, so a self-fire is an unbounded cascade
                // rather than a reaction to new work.
                if event.source_schedule_id.as_deref() == Some(schedule.id.as_str()) {
                    debug!(
                        schedule_id = %schedule.id,
                        event_type = %event.event_type,
                        "Event suppressed: emitted by this schedule's own execution"
                    );
                    continue;
                }

                // Check the optional payload filter (glob on a payload field).
                if let Some(filter) = filter {
                    if !filter.matches(event.payload.as_ref()) {
                        debug!(
                            schedule_id = %schedule.id,
                            field = %filter.field,
                            pattern = %filter.pattern,
                            "Event filtered out"
                        );
                        continue;
                    }
                }

                // Apply debounce.
                if *debounce_secs > 0 {
                    if let Some(last) = self.last_event.get(&schedule.id) {
                        let elapsed = (event.timestamp - *last).num_seconds();
                        if elapsed < i64::try_from(*debounce_secs).unwrap_or(i64::MAX) {
                            debug!(
                                schedule_id = %schedule.id,
                                elapsed_secs = elapsed,
                                debounce_secs = debounce_secs,
                                "Event debounced"
                            );
                            continue;
                        }
                    }
                }

                // Match! Enqueue trigger, carrying the event payload so
                // `{{ event.payload.* }}` expressions resolve at dispatch.
                let trigger = FiredTrigger {
                    schedule_id: schedule.id.clone(),
                    fired_at: event.timestamp,
                    trigger_type: TriggerType::Event,
                    is_recovery: false,
                    event_payload: event.payload.clone(),
                };

                if tx.send(trigger).await.is_ok() {
                    info!(schedule_id = %schedule.id, event_type = %event.event_type, "Event trigger fired");
                    self.last_event.insert(schedule.id.clone(), event.timestamp);
                    matched.push(schedule.id.clone());
                }
            }
        }

        matched
    }
}

impl Default for EventBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::trigger_queue;
    use chrono::Duration;

    fn event_schedule(id: &str, event_type: &str, debounce: u64) -> Schedule {
        Schedule::new(
            id,
            id,
            TriggerConfig::Event {
                event_type: event_type.to_string(),
                debounce_secs: debounce,
                filter: None,
            },
            "wf",
        )
    }

    #[tokio::test]
    async fn test_event_bridge_matches_event_type() {
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        store.register(event_schedule("s1", "file.changed", 0));

        let (tx, mut rx) = trigger_queue();
        let event = IncomingEvent {
            event_type: "file.changed".into(),
            payload: None,
            timestamp: Utc::now(),
            source_schedule_id: None,
        };

        let matched = bridge.process_event(&event, &store, &tx).await;
        assert_eq!(matched, vec!["s1"]);

        let trigger = rx.recv().await.unwrap();
        assert_eq!(trigger.schedule_id, "s1");
        assert_eq!(trigger.trigger_type, TriggerType::Event);
    }

    #[tokio::test]
    async fn schedule_does_not_fire_on_an_event_its_own_execution_produced() {
        // A campaign schedule listening on `run.completed` runs a campaign whose
        // run phase emits `run.completed`. Without provenance the schedule fires
        // itself forever; only the overlap guard bounds it, and only while the
        // first execution is still running.
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        store.register(event_schedule("s1", "run.completed", 0));

        let (tx, _rx) = trigger_queue();
        let own = IncomingEvent {
            event_type: "run.completed".into(),
            payload: None,
            timestamp: Utc::now(),
            source_schedule_id: Some("s1".to_owned()),
        };

        assert!(
            bridge.process_event(&own, &store, &tx).await.is_empty(),
            "a schedule must not be fired by an event its own execution produced"
        );
    }

    #[tokio::test]
    async fn another_schedules_event_still_fires_a_listener() {
        // Suppression is scoped to the originating schedule: a different
        // schedule's event is ordinary chaining and must still fire.
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        store.register(event_schedule("s1", "run.completed", 0));

        let (tx, _rx) = trigger_queue();
        let other = IncomingEvent {
            event_type: "run.completed".into(),
            payload: None,
            timestamp: Utc::now(),
            source_schedule_id: Some("s2".to_owned()),
        };

        assert_eq!(bridge.process_event(&other, &store, &tx).await, vec!["s1"]);
    }

    #[tokio::test]
    async fn test_event_bridge_no_match() {
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        store.register(event_schedule("s1", "file.changed", 0));

        let (tx, _rx) = trigger_queue();
        let event = IncomingEvent {
            event_type: "file.created".into(),
            payload: None,
            timestamp: Utc::now(),
            source_schedule_id: None,
        };

        let matched = bridge.process_event(&event, &store, &tx).await;
        assert!(matched.is_empty());
    }

    #[tokio::test]
    async fn test_event_bridge_debounce() {
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        store.register(event_schedule("s1", "file.changed", 5)); // 5s debounce

        let (tx, mut rx) = trigger_queue();
        let now = Utc::now();

        // First event — should fire.
        let event1 = IncomingEvent {
            event_type: "file.changed".into(),
            payload: None,
            timestamp: now,
            source_schedule_id: None,
        };
        let matched1 = bridge.process_event(&event1, &store, &tx).await;
        assert_eq!(matched1.len(), 1);

        // Second event 2s later — should be debounced.
        let event2 = IncomingEvent {
            event_type: "file.changed".into(),
            payload: None,
            timestamp: now + Duration::seconds(2),
            source_schedule_id: None,
        };
        let matched2 = bridge.process_event(&event2, &store, &tx).await;
        assert!(matched2.is_empty());

        // Third event 10s later — should fire.
        let event3 = IncomingEvent {
            event_type: "file.changed".into(),
            payload: None,
            timestamp: now + Duration::seconds(10),
            source_schedule_id: None,
        };
        let matched3 = bridge.process_event(&event3, &store, &tx).await;
        assert_eq!(matched3.len(), 1);

        // Should have 2 triggers total.
        let t1 = rx.recv().await.unwrap();
        let t2 = rx.recv().await.unwrap();
        assert_eq!(t1.schedule_id, "s1");
        assert_eq!(t2.schedule_id, "s1");
    }

    #[tokio::test]
    async fn test_event_bridge_disabled_schedule() {
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        let mut s = event_schedule("s1", "file.changed", 0);
        s.enabled = false;
        store.register(s);

        let (tx, _rx) = trigger_queue();
        let event = IncomingEvent {
            event_type: "file.changed".into(),
            payload: None,
            timestamp: Utc::now(),
            source_schedule_id: None,
        };

        let matched = bridge.process_event(&event, &store, &tx).await;
        assert!(matched.is_empty());
    }

    #[tokio::test]
    async fn test_event_bridge_honors_payload_filter() {
        let mut bridge = EventBridge::new();
        let mut store = ScheduleStore::new();
        store.register(Schedule::new(
            "s1",
            "s1",
            TriggerConfig::Event {
                event_type: "crash.found".into(),
                debounce_secs: 0,
                filter: Some(crate::event::EventFilter {
                    field: "payload.target".into(),
                    pattern: "parse_*".into(),
                }),
            },
            "wf",
        ));

        let (tx, mut rx) = trigger_queue();
        let non_matching = IncomingEvent {
            event_type: "crash.found".into(),
            payload: Some(serde_json::json!({"target": "render_frame"})),
            timestamp: Utc::now(),
            source_schedule_id: None,
        };
        assert!(bridge
            .process_event(&non_matching, &store, &tx)
            .await
            .is_empty());

        let matching = IncomingEvent {
            event_type: "crash.found".into(),
            payload: Some(serde_json::json!({"target": "parse_input"})),
            timestamp: Utc::now(),
            source_schedule_id: None,
        };
        assert_eq!(
            bridge.process_event(&matching, &store, &tx).await,
            vec!["s1"]
        );

        // The fired trigger carries the payload for parameter resolution.
        let trigger = rx.recv().await.unwrap();
        assert_eq!(
            trigger.event_payload,
            Some(serde_json::json!({"target": "parse_input"}))
        );
    }
}
