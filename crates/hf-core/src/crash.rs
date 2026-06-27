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

/// CASR exploitability classification for a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum CrashSeverity {
    /// Almost certainly exploitable.
    Exploitable,
    /// Likely exploitable.
    ProbablyExploitable,
    /// Not exploitable.
    NotExploitable,
    /// CASR could not classify the crash.
    #[default]
    Undefined,
}

/// A crash analysis + severity report produced by CASR (`.casrep`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CasrReport {
    /// Exploitability classification.
    pub severity: CrashSeverity,
    /// Short description of the crash class (e.g. "`heap-buffer-overflow(write)`").
    pub severity_short: String,
    /// Crash location (`file:line:col`) as reported by CASR.
    pub crashline: String,
    /// CASR-normalized stack-trace frames.
    pub stack: Vec<String>,
    /// CASR cluster id, set when reports are clustered/deduplicated.
    #[serde(default)]
    pub cluster: Option<u32>,
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
    /// CASR severity/analysis report, when triage ran CASR.
    #[serde(default)]
    pub casr: Option<CasrReport>,
}
