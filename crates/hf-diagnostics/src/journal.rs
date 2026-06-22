//! Run journaling for replay.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A timestamped event in a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RunEvent {
    Started {
        run_id: Uuid,
        target: String,
    },
    Progress {
        run_id: Uuid,
        edges: u64,
        execs_per_sec: f64,
    },
    Crash {
        run_id: Uuid,
        kind: String,
    },
    Finished {
        run_id: Uuid,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalEntry {
    timestamp: DateTime<Utc>,
    event: RunEvent,
}

/// An append-only journal of run events.
pub struct RunJournal {
    entries: Vec<JournalEntry>,
}

impl RunJournal {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record an event with the current timestamp.
    pub fn record(&mut self, event: RunEvent) {
        self.entries.push(JournalEntry {
            timestamp: Utc::now(),
            event,
        });
    }

    /// Replay all events in order.
    #[must_use]
    pub fn replay(&self) -> Vec<RunEvent> {
        self.entries.iter().map(|e| e.event.clone()).collect()
    }
}

impl Default for RunJournal {
    fn default() -> Self {
        Self::new()
    }
}
