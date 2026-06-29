//! Agent events and the sink that delivers them to a presentation layer.

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::Mutex;

/// An event emitted as the agent works through a turn. Presentation layers
/// (GUI, CLI) render these as live progress.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentEvent {
    /// The turn has started.
    Started,
    /// The model's reasoning for the current step.
    Thinking {
        /// The thought text.
        text: String,
    },
    /// The agent is about to invoke a tool.
    ToolCall {
        /// Tool name.
        name: String,
        /// Tool arguments as JSON.
        args: serde_json::Value,
    },
    /// A tool finished; carries a short result summary.
    ToolResult {
        /// Tool name.
        name: String,
        /// Result summary (already truncated for display).
        summary: String,
    },
    /// The final assistant answer.
    Complete {
        /// The answer text.
        content: String,
    },
    /// The turn failed.
    Error {
        /// The error message.
        message: String,
    },
}

/// A destination for [`AgentEvent`]s.
#[async_trait]
pub trait EventSink: Send + Sync {
    /// Deliver one event.
    async fn emit(&self, event: AgentEvent);
}

/// A sink that discards every event.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

#[async_trait]
impl EventSink for NullSink {
    async fn emit(&self, _event: AgentEvent) {}
}

/// A sink that collects events in memory, for tests and inspection.
#[derive(Debug, Default)]
pub struct CollectingSink {
    events: Mutex<Vec<AgentEvent>>,
}

impl CollectingSink {
    /// Create an empty collecting sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the collected events.
    pub async fn events(&self) -> Vec<AgentEvent> {
        self.events.lock().await.clone()
    }
}

#[async_trait]
impl EventSink for CollectingSink {
    async fn emit(&self, event: AgentEvent) {
        self.events.lock().await.push(event);
    }
}
