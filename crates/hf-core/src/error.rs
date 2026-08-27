//! Error classification and redaction.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Severity of an error, used for provider freeze-duration decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Transient failure, safe to retry.
    Transient,
    /// Permanent failure, do not retry.
    Permanent,
    /// Requires user action (e.g., invalid config, missing API key).
    UserActionRequired,
}

/// A classified error with a category for retry/routing decisions.
#[derive(Debug, Clone, Error)]
pub enum ClassifiedError {
    #[error("provider error: {0}")]
    Provider(String),
    #[error("sandbox error: {0}")]
    Sandbox(String),
    #[error("engine error: {0}")]
    Engine(String),
    #[error("harness error: {0}")]
    Harness(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("timeout")]
    Timeout,
    #[error("internal: {0}")]
    Internal(String),
}

/// Redact secrets from a string before returning to the LLM.
pub trait Redactable {
    fn redact(&self) -> String;
}
