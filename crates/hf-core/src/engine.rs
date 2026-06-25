//! Fuzzing engine types.
//!
//! The engine adapter contract (`EngineAdapter`) and the runner live in
//! `hf-engine`; this module holds only the shared, serializable types.
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

use crate::target::Sanitizer;

/// The kind of fuzzing engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EngineKind {
    AflPlusPlus,
    Honggfuzz,
    LibFuzzer,
    ClusterFuzzLite,
    /// Google's coverage-guided OS kernel fuzzer (syscall sequences).
    Syzkaller,
}

/// Configuration for a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRunConfig {
    pub harness_id: Uuid,
    pub engine: EngineKind,
    pub duration: Option<Duration>,
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub seed_corpus: Option<PathBuf>,
    pub sanitizer: Sanitizer,
    pub env: Vec<(String, String)>,
    pub extra_args: Vec<String>,
}

/// A progress event streamed from a running fuzzer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzProgress {
    ExecsPerSec(f64),
    EdgesCovered(u64),
    CrashesFound(u32),
    LogLine(String),
    Done,
}
