//! Fuzzing engine traits and types.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use uuid::Uuid;

use crate::error::ClassifiedError;
use crate::harness::Harness;
use crate::runtime::RuntimeAdapter;
use crate::target::{Sanitizer, TargetLanguage};

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

/// A compiled harness binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildArtifact {
    pub harness_id: Uuid,
    pub binary: PathBuf,
    pub log: String,
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

/// A handle to a running fuzz job.
pub struct FuzzRunHandle {
    pub run_id: Uuid,
    pub progress: Box<dyn Stream<Item = FuzzProgress> + Send + Unpin>,
}

/// The unified fuzzing engine trait.
#[async_trait]
pub trait FuzzEngine: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn supports(&self, lang: TargetLanguage, san: Sanitizer) -> bool;
    async fn build(
        &self,
        harness: &Harness,
        rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError>;
    async fn run(
        &self,
        cfg: &FuzzRunConfig,
        rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError>;
    async fn minimize(
        &self,
        crash: &crate::crash::Crash,
        rt: &dyn RuntimeAdapter,
    ) -> Result<crate::crash::Crash, ClassifiedError>;
    async fn coverage(
        &self,
        run: &FuzzRunHandle,
    ) -> Result<crate::coverage::CoverageReport, ClassifiedError>;
}
