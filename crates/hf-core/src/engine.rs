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

impl std::str::FromStr for EngineKind {
    type Err = String;

    /// Parse an engine name (case-insensitive, with common aliases). Unknown
    /// names are rejected so every entrypoint (CLI/web/GUI) fails the same way
    /// instead of silently defaulting to a different engine.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "afl++" | "aflplusplus" | "afl" => Ok(Self::AflPlusPlus),
            "honggfuzz" | "hfuzz" => Ok(Self::Honggfuzz),
            "libfuzzer" | "libfuzz" | "lf" => Ok(Self::LibFuzzer),
            "clusterfuzzlite" | "cfl" | "cflite" => Ok(Self::ClusterFuzzLite),
            "syzkaller" | "syz" => Ok(Self::Syzkaller),
            other => Err(format!(
                "unknown fuzzing engine '{other}' (expected one of: \
                 afl++, honggfuzz, libfuzzer, clusterfuzzlite, syzkaller)"
            )),
        }
    }
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
