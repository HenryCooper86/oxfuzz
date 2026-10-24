//! `WorkflowDispatcher` trait: bridge between scheduler triggers and real
//! workflow execution.
//!
//! Defined here (in `y-scheduler`) so that `SchedulerManager` can hold a
//! dispatcher reference without creating a circular dependency on `y-service`.
//! The implementation (`OrchestratorDispatcher`) lives in `y-service`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Result / Error types
// ---------------------------------------------------------------------------

/// Outcome of a successful dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchResult {
    /// Whether the workflow completed without errors.
    pub success: bool,
    /// Whether the dispatch declined to run the workflow at all (for example a
    /// campaign whose concurrency gate was full or whose allocation was not
    /// approved).
    ///
    /// A skip is neither a success nor a failure: the scheduled work never
    /// ran, so a one-time occurrence must not be terminally consumed as
    /// `Completed` and the execution is recorded as skipped instead.
    /// Defaults to `false` so results persisted before the field existed (or
    /// produced by dispatchers without a skip concept) decode unchanged.
    #[serde(default)]
    pub skipped: bool,
    /// Human-readable summary of the execution outcome.
    pub summary: String,
    /// Structured output from the workflow (task results, LLM content, etc.).
    pub output: serde_json::Value,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
    /// Error description when `success` is `false`.
    pub error: Option<String>,
}

/// Error returned when dispatch itself fails (not a workflow-level failure).
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("workflow not found: {id}")]
    WorkflowNotFound { id: String },

    #[error("workflow parse error: {message}")]
    ParseError { message: String },

    #[error("execution failed: {message}")]
    ExecutionFailed { message: String },

    #[error("internal dispatcher error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Dispatches a workflow execution.
///
/// Implemented by `OrchestratorDispatcher` in `y-service`. The scheduler
/// holds an `Arc<dyn WorkflowDispatcher>` so the real execution engine can
/// be swapped in after construction (same pattern as `AgentRunner`).
#[async_trait]
pub trait WorkflowDispatcher: Send + Sync {
    /// Execute a workflow by ID with the given parameter values.
    ///
    /// The implementation is responsible for:
    /// - Loading the workflow template from storage
    /// - Parsing the definition into a task DAG
    /// - Running the DAG through the orchestrator
    /// - Returning a `DispatchResult` describing the outcome
    ///
    /// A `DispatchError` is returned only for infrastructure failures (not
    /// found, parse error). Workflow-level failures (a task errored) are
    /// encoded in `DispatchResult::success = false`.
    async fn dispatch(
        &self,
        workflow_id: &str,
        parameter_values: serde_json::Value,
    ) -> Result<DispatchResult, DispatchError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dispatch_result_serde_roundtrip() {
        let result = DispatchResult {
            success: true,
            skipped: false,
            summary: "ok".into(),
            output: serde_json::json!({"tasks_completed": 3}),
            duration_ms: 42,
            error: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: DispatchResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert!(!back.skipped);
        assert_eq!(back.duration_ms, 42);
        assert!(back.error.is_none());
    }

    #[test]
    fn test_dispatch_result_failure_serde() {
        let result = DispatchResult {
            success: false,
            skipped: false,
            summary: "task failed".into(),
            output: serde_json::Value::Null,
            duration_ms: 100,
            error: Some("step_1 timed out".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: DispatchResult = serde_json::from_str(&json).unwrap();
        assert!(!back.success);
        assert!(!back.skipped);
        assert_eq!(back.error.as_deref(), Some("step_1 timed out"));
    }

    #[test]
    fn test_dispatch_result_skip_decodes_from_legacy_json_without_the_field() {
        // Results persisted before `skipped` existed carry no such field; they
        // must decode as ordinary completions rather than as skips.
        let legacy = r#"{
            "success": true,
            "summary": "ok",
            "output": null,
            "duration_ms": 7,
            "error": null
        }"#;
        let back: DispatchResult = serde_json::from_str(legacy).unwrap();
        assert!(!back.skipped);

        let skipped = r#"{
            "success": true,
            "skipped": true,
            "summary": "skipped: max concurrent campaigns reached (2)",
            "output": {"skipped": true},
            "duration_ms": 0,
            "error": null
        }"#;
        let back: DispatchResult = serde_json::from_str(skipped).unwrap();
        assert!(back.skipped);
        assert!(back.summary.contains("skipped"));
    }

    #[test]
    fn test_dispatch_error_display_variants() {
        let e = DispatchError::WorkflowNotFound {
            id: "wf-123".into(),
        };
        assert!(e.to_string().contains("wf-123"));

        let e = DispatchError::ParseError {
            message: "bad DSL".into(),
        };
        assert!(e.to_string().contains("bad DSL"));

        let e = DispatchError::ExecutionFailed {
            message: "OOM".into(),
        };
        assert!(e.to_string().contains("OOM"));

        let e = DispatchError::Internal("db offline".into());
        assert!(e.to_string().contains("db offline"));
    }
}
