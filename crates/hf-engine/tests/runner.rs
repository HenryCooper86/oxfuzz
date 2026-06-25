//! Tests for the `EngineRunner` that orchestrates build + run + progress.

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::Sanitizer;
use hf_engine::runner::{EngineRunner, RunResult};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

/// A mock runtime that returns canned stdout for any command.
struct MockRuntime {
    exit_code: i32,
    stdout: String,
}

#[async_trait::async_trait]
impl RuntimeAdapter for MockRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(CommandResult {
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
        })
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

fn run_config(engine: EngineKind, duration_secs: u64) -> FuzzRunConfig {
    FuzzRunConfig {
        harness_id: Uuid::new_v4(),
        engine,
        duration: Some(Duration::from_secs(duration_secs)),
        max_mem_mb: 2048,
        max_cpus: 1,
        seed_corpus: Some(PathBuf::from("/work/corpus")),
        sanitizer: Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
    }
}

#[tokio::test]
async fn runner_libfuzzer_parses_progress_and_coverage() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "INFO: 512 edges covered.\n#256: 3000 execs/sec\nINFO: 1024 edges covered.\nDONE\n"
            .to_owned(),
    };
    let runner = EngineRunner::new();
    let result = runner
        .run(
            EngineKind::LibFuzzer,
            &run_config(EngineKind::LibFuzzer, 60),
            "/work/fuzz_bin",
            "/work/corpus",
            "/work/out",
            &rt,
            &PathBuf::from("/work"),
        )
        .await
        .expect("run should succeed");
    let RunResult { progress, coverage } = result;
    assert!(!progress.is_empty(), "should have progress events");
    assert!(
        progress
            .iter()
            .any(|e| matches!(e, hf_core::engine::FuzzProgress::Done)),
        "should have Done event"
    );
    assert_eq!(coverage.edges, 1024, "should pick max edge count");
}

#[tokio::test]
async fn runner_afl_parses_progress() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "execs : 1000\ncov: 500\nDONE\n".to_owned(),
    };
    let runner = EngineRunner::new();
    let result = runner
        .run(
            EngineKind::AflPlusPlus,
            &run_config(EngineKind::AflPlusPlus, 60),
            "/work/fuzz_bin",
            "/work/corpus",
            "/work/out",
            &rt,
            &PathBuf::from("/work"),
        )
        .await
        .expect("run should succeed");
    assert!(!result.progress.is_empty());
    assert_eq!(result.coverage.edges, 500);
}

#[tokio::test]
async fn runner_returns_error_on_nonzero_exit() {
    let rt = MockRuntime {
        exit_code: 1,
        stdout: String::new(),
    };
    let runner = EngineRunner::new();
    let result = runner
        .run(
            EngineKind::LibFuzzer,
            &run_config(EngineKind::LibFuzzer, 60),
            "/work/fuzz_bin",
            "/work/corpus",
            "/work/out",
            &rt,
            &PathBuf::from("/work"),
        )
        .await;
    assert!(result.is_err(), "should fail on non-zero exit");
}

#[tokio::test]
async fn runner_clusterfuzzlite_dispatches() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "cov: 100\nDONE\n".to_owned(),
    };
    let runner = EngineRunner::new();
    let result = runner
        .run(
            EngineKind::ClusterFuzzLite,
            &run_config(EngineKind::ClusterFuzzLite, 60),
            "/work/fuzz_bin",
            "/work/corpus",
            "/work/out",
            &rt,
            &PathBuf::from("/work"),
        )
        .await
        .expect("ClusterFuzzLite should now be supported");
    assert!(!result.progress.is_empty());
    assert_eq!(result.coverage.edges, 100);
}
