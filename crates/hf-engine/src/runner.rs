//! Engine runner: orchestrates build + run + progress/coverage parsing.
//!
//! The `EngineRunner` is engine-agnostic: it delegates argument construction
//! to the per-engine `build_run_args` functions and parses stdout uniformly.

use std::path::Path;

use hf_core::coverage::CoverageReport;
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::RuntimeAdapter;
use uuid::Uuid;

use crate::progress::{parse_coverage, parse_progress};

/// The result of a fuzz run.
pub struct RunResult {
    pub progress: Vec<FuzzProgress>,
    pub coverage: CoverageReport,
}

/// An engine-agnostic runner that executes fuzz commands via a
/// `RuntimeAdapter` and parses progress/coverage.
pub struct EngineRunner;

impl EngineRunner {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for EngineRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl EngineRunner {
    /// Run a fuzz campaign.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the engine is not supported or the
    /// sandboxed command returns a non-zero exit code.
    pub async fn run(
        &self,
        engine: EngineKind,
        cfg: &FuzzRunConfig,
        binary: &str,
        corpus: &str,
        out: &str,
        rt: &dyn RuntimeAdapter,
        workspace: &Path,
    ) -> Result<RunResult, ClassifiedError> {
        let args = match engine {
            EngineKind::LibFuzzer => crate::libfuzzer::build_run_args(cfg, binary, corpus, out),
            EngineKind::AflPlusPlus => crate::afl::build_run_args(cfg, binary, corpus, out),
            EngineKind::Honggfuzz => crate::honggfuzz::build_run_args(cfg, binary, corpus, out),
            EngineKind::ClusterFuzzLite => {
                return Err(ClassifiedError::Engine(
                    "ClusterFuzzLite: not yet supported".to_owned(),
                ));
            }
        };
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: cfg.max_mem_mb,
            max_cpus: cfg.max_cpus,
            max_duration_secs: cfg.duration.map_or(3600, |d| d.as_secs()),
            env: cfg.env.iter().cloned().collect(),
        };
        let result = rt.run_command(&args, workspace, &limits).await?;
        if result.exit_code != 0 && !result.stdout.contains("DONE") {
            return Err(ClassifiedError::Engine(format!(
                "fuzz run exited {} : {}",
                result.exit_code,
                result.stderr.chars().take(500).collect::<String>()
            )));
        }
        let progress = parse_progress(&result.stdout);
        let run_id = Uuid::new_v4();
        let coverage = parse_coverage(&result.stdout, run_id);
        Ok(RunResult { progress, coverage })
    }
}
