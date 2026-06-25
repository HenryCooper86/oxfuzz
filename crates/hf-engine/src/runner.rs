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

/// Extra wall-clock seconds the sandbox is allowed beyond the fuzzer's own
/// `-max_total_time`, covering corpus loading and sanitizer shutdown.
const SANDBOX_TIMEOUT_HEADROOM_SECS: u64 = 60;

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
        let args = crate::registry::adapter_for(engine).build_run_args(cfg, binary, corpus, out);
        // The sandbox wall-clock timeout must exceed the fuzzer's own run time:
        // a libFuzzer `-max_total_time=N` campaign also spends time loading the
        // corpus and running ASan leak detection at exit, so without headroom
        // the container is killed as "command timed out" right at the finish.
        let max_duration_secs = cfg.duration.map_or(3600, |d| {
            d.as_secs().saturating_add(SANDBOX_TIMEOUT_HEADROOM_SECS)
        });
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: cfg.max_mem_mb,
            max_cpus: cfg.max_cpus,
            max_duration_secs,
            env: cfg.env.iter().cloned().collect(),
        };
        let result = rt.run_command(&args, workspace, &limits).await?;
        // libFuzzer writes progress to stderr; AFL++ to stdout. Parse both.
        let combined = format!("{}\n{}", result.stdout, result.stderr);
        // libFuzzer exit codes: 0 = clean exit, 77 = crash/leak found,
        // 76 = OOM, 1 = error. 0 and 77 are valid fuzzing outcomes.
        let is_valid_outcome = result.exit_code == 0
            || result.exit_code == 77
            || combined.contains("DONE")
            || combined.contains("SUMMARY");
        if !is_valid_outcome {
            return Err(ClassifiedError::Engine(format!(
                "fuzz run exited {} : {}",
                result.exit_code,
                result.stderr.chars().take(500).collect::<String>()
            )));
        }
        let progress = parse_progress(&combined);
        let run_id = Uuid::new_v4();
        let coverage = parse_coverage(&combined, run_id);
        Ok(RunResult { progress, coverage })
    }
}
