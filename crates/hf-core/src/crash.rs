//! Crash model.
//!
//! See `docs/design/crash-triage-design.md`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// The kind of crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CrashKind {
    Asan,
    Ubsan,
    Segv,
    Abort,
    Timeout,
    Other,
}

/// A draft bug report produced by the triage agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugReport {
    pub title: String,
    pub summary: String,
    pub repro_steps: String,
    pub stack: String,
    pub severity_guess: String,
}

/// A crash artifact from a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crash {
    pub id: Uuid,
    pub run_id: Uuid,
    pub target_id: Uuid,
    pub input_path: PathBuf,
    pub stack_signature: String,
    pub kind: CrashKind,
    pub summary: String,
    pub minimized: bool,
    pub bug_report: Option<BugReport>,
}
