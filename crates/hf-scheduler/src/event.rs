//! Event-driven schedule trigger.

use serde::{Deserialize, Serialize};

/// An event-driven schedule trigger.
///
/// Fires when a matching event is received from an external event producer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSchedule {
    /// Event type to match (e.g., "file.changed").
    pub event_type: String,
    /// Optional payload filter (Glob pattern on a field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<EventFilter>,
    /// Debounce window in seconds (collapse rapid events).
    #[serde(default)]
    pub debounce_secs: u64,
}

/// Filter for event payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventFilter {
    /// Field path to match (e.g., "payload.path").
    pub field: String,
    /// Glob pattern to match against the field value.
    pub pattern: String,
}

impl EventFilter {
    /// Whether the filter's glob matches the event payload.
    ///
    /// `field` is a dot-path resolved from the event root (so `payload.target`
    /// reads the event payload's `target` field). String, number, and boolean
    /// fields match against their text form; missing fields, structured
    /// values, and invalid globs never match.
    #[must_use]
    pub fn matches(&self, payload: Option<&serde_json::Value>) -> bool {
        let root = serde_json::json!({ "payload": payload });
        let text =
            crate::params::resolve_json_path(&root, &self.field).and_then(|value| match value {
                serde_json::Value::String(s) => Some(s),
                serde_json::Value::Number(n) => Some(n.to_string()),
                serde_json::Value::Bool(b) => Some(b.to_string()),
                _ => None,
            });
        let Some(text) = text else {
            return false;
        };
        // Events are rare (crash found, run terminated), so compiling the glob
        // per match beats caching a compiled set per schedule.
        globset::GlobBuilder::new(&self.pattern)
            .build()
            .is_ok_and(|glob| glob.compile_matcher().is_match(&text))
    }
}

impl EventSchedule {
    /// Create a new event schedule.
    pub fn new(event_type: &str) -> Self {
        Self {
            event_type: event_type.to_string(),
            filter: None,
            debounce_secs: 0,
        }
    }

    /// Set a debounce window.
    #[must_use]
    pub fn with_debounce(mut self, secs: u64) -> Self {
        self.debounce_secs = secs;
        self
    }

    /// Set a filter.
    #[must_use]
    pub fn with_filter(mut self, field: &str, pattern: &str) -> Self {
        self.filter = Some(EventFilter {
            field: field.to_string(),
            pattern: pattern.to_string(),
        });
        self
    }

    /// Check if an event type matches this trigger.
    pub fn matches_event_type(&self, event_type: &str) -> bool {
        self.event_type == event_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_schedule_creation() {
        let sched = EventSchedule::new("file.changed")
            .with_debounce(5)
            .with_filter("payload.path", "*.md");
        assert_eq!(sched.event_type, "file.changed");
        assert_eq!(sched.debounce_secs, 5);
        assert!(sched.filter.is_some());
    }

    #[test]
    fn test_event_matches_type() {
        let sched = EventSchedule::new("file.changed");
        assert!(sched.matches_event_type("file.changed"));
        assert!(!sched.matches_event_type("file.created"));
    }

    #[test]
    fn event_filter_glob_matches_payload_field() {
        let filter = EventFilter {
            field: "payload.target".to_owned(),
            pattern: "parse_*".to_owned(),
        };
        let payload = serde_json::json!({"target": "parse_input"});
        assert!(filter.matches(Some(&payload)));
    }

    #[test]
    fn event_filter_rejects_non_matching_and_missing_fields() {
        let filter = EventFilter {
            field: "payload.target".to_owned(),
            pattern: "parse_*".to_owned(),
        };
        let other = serde_json::json!({"target": "render_frame"});
        assert!(!filter.matches(Some(&other)));
        let missing = serde_json::json!({"crashes": 1});
        assert!(!filter.matches(Some(&missing)));
        assert!(!filter.matches(None));
    }

    #[test]
    fn event_filter_matches_scalar_values_by_their_text() {
        let filter = EventFilter {
            field: "payload.crashes".to_owned(),
            pattern: "*".to_owned(),
        };
        let payload = serde_json::json!({"crashes": 3});
        assert!(filter.matches(Some(&payload)));
    }

    #[test]
    fn event_filter_invalid_glob_never_matches() {
        let filter = EventFilter {
            field: "payload.target".to_owned(),
            pattern: "[unclosed".to_owned(),
        };
        let payload = serde_json::json!({"target": "parse_input"});
        assert!(!filter.matches(Some(&payload)));
    }
}
