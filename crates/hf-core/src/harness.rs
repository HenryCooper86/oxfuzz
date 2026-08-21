//! Fuzzing harness model.
//!
//! See `docs/standards/HARNESS_STANDARD.md`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

use crate::engine::EngineKind;
use crate::target::{Sanitizer, TargetLanguage};

/// The status of a harness in the generation pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HarnessStatus {
    Draft,
    Compiled,
    SmokePassed,
    Promoted,
    Failed,
}

/// A build command for a harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildCommand {
    pub compiler: String,
    pub args: Vec<String>,
    pub output: PathBuf,
    /// Project-derived compile flags (include directories, defines, language
    /// standard), already validated by `hf_discovery::build_context` and
    /// expressed as container-internal paths. Empty when the project ships no
    /// compile database.
    ///
    /// Carried on the build command rather than passed alongside it so the
    /// flags a harness was built with travel with the harness record.
    #[serde(default)]
    pub extra_flags: Vec<String>,
}

/// Summary of a smoke fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeRunSummary {
    pub duration_secs: u64,
    pub execs_per_sec: f64,
    pub crashes: u32,
    pub passed: bool,
    /// Full SHA-256 of the exact harness source exercised by this smoke run.
    #[serde(default)]
    pub source_sha256: Option<String>,
    /// Full SHA-256 of the exact executable exercised by this smoke run.
    #[serde(default)]
    pub binary_sha256: Option<String>,
    /// Persisted run that owns the qualification evidence.
    #[serde(default)]
    pub run_id: Option<Uuid>,
}

/// A generated fuzzing harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Harness {
    pub id: Uuid,
    pub target_id: Uuid,
    pub engine: EngineKind,
    pub source: String,
    pub language: TargetLanguage,
    pub build_cmd: BuildCommand,
    pub sanitizer: Sanitizer,
    pub status: HarnessStatus,
    pub smoke_run: Option<SmokeRunSummary>,
}

/// An in-progress harness draft before compilation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessDraft {
    pub target_id: Uuid,
    pub engine: EngineKind,
    pub source: String,
    pub rationale: String,
    /// The command that will build this draft. Carried on the draft so every
    /// presentation layer shows the same command instead of re-deriving it (and
    /// drifting from) the harness naming convention.
    pub build_cmd: BuildCommand,
}
