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
    /// A kernel bug reported by a syzkaller campaign: a KASAN/KMSAN/KCSAN
    /// report, a `BUG_ON`/`WARN_ON`, a fault, a hung task, or a panic. Kept
    /// distinct from every userspace variant because a kernel oops is a
    /// different evidence shape, not an `Asan` finding wearing a kernel hat.
    /// The specific class is carried in the crash summary.
    KernelBug,
    /// A memory leak reported by `LeakSanitizer`. Distinct from [`CrashKind::Asan`]
    /// because a leak is an availability bug (CWE-401), not a memory-safety
    /// violation, and reports map the kind straight onto a CWE and a severity.
    Leak,
    Segv,
    Abort,
    Timeout,
    /// A managed-runtime fault: a Go panic or an uncaught Python exception
    /// (Atheris). Distinct from a C `Abort` (SIGABRT/assertion) so reports and
    /// severity reflect a language-runtime crash rather than a native abort.
    Panic,
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
    /// The likely root cause of the crash in the target source (what is wrong
    /// and why the input triggers it). `None` when triage could not infer one.
    #[serde(default)]
    pub root_cause: Option<String>,
    /// A suggested fix, ideally as a unified-diff patch against the target
    /// source. `None` when triage could not propose one.
    #[serde(default)]
    pub suggested_fix: Option<String>,
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

/// Which layer the fault that produced a crash lies in.
///
/// oxfuzz's harnesses are LLM-authored, so a fault inside the harness is an
/// expected failure mode rather than an unusual one. Recording the layer keeps
/// a harness defect out of findings about the project under test, where it
/// would otherwise be indistinguishable from a real bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CrashOrigin {
    /// The fault is in the project under test. This is a finding.
    Target,
    /// The fault is in the generated harness. This is a harness defect, not a
    /// finding about the target.
    Harness,
    /// The fault is inside the fuzzer driver or sanitizer runtime.
    Runtime,
    /// No symbolized frames, so the origin cannot be determined.
    #[default]
    Unknown,
}

/// One observed sandbox replay, distinct from a model's advisory assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReplayObservation {
    /// Exit status, absent when the runtime could not execute the request.
    pub exit_code: Option<i32>,
    /// Runtime completion status; forced termination cannot confirm a failure.
    pub termination: Option<crate::runtime::CommandTermination>,
    /// Bounded actual output from this attempt.
    pub log: String,
    /// Whether this attempt reproduced the reference failure.
    pub matches_reference: bool,
    /// Runtime error, when the request could not complete.
    pub error: Option<String>,
}

/// Empirical evidence retained by independent crash-minimization confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReproduction {
    /// Evidence format; older incomplete records cannot support confirmation.
    #[serde(default)]
    pub version: u32,
    /// Run that owns the classified reference and replay artifacts.
    #[serde(default)]
    pub run_id: Uuid,
    /// Finding whose original classification supplied the reference log.
    #[serde(default)]
    pub crash_id: Uuid,
    /// Requested observations per input, retained independently of completed counts.
    #[serde(default)]
    pub requested_runs: u32,
    /// Actual bounded log used to classify the original finding, before minimization.
    /// Absent for CASR-only evidence without a comparable sanitizer trace.
    #[serde(default)]
    pub reference_log: Option<String>,
    /// Original run-owned artifact, retained even after confirmation.
    pub original_input: PathBuf,
    /// Digest of the original bytes.
    pub original_sha256: String,
    /// Candidate derived artifact.
    pub candidate_input: PathBuf,
    /// Digest of the candidate bytes.
    pub candidate_sha256: String,
    /// Digest of the immutable run binary used for every attempt.
    pub binary_sha256: String,
    /// Exact sandbox image used for every attempt.
    pub image: String,
    /// Actual observations for the original input.
    pub original: Vec<CrashReplayObservation>,
    /// Actual observations for the minimized candidate.
    pub candidate: Vec<CrashReplayObservation>,
    /// All requested attempts completed with the same failure identity.
    pub confirmed: bool,
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
    /// Observed reproduction evidence; absent on older or unconfirmed runs.
    #[serde(default)]
    pub reproduction: Option<CrashReproduction>,
    pub bug_report: Option<BugReport>,
    /// CASR severity/analysis report, when triage ran CASR.
    #[serde(default)]
    pub casr: Option<CasrReport>,
    /// Which layer the fault lies in. Defaults to `Unknown` so crashes
    /// persisted before this field existed decode unchanged.
    #[serde(default)]
    pub origin: CrashOrigin,
}
