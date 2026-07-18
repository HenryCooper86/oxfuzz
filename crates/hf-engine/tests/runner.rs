//! Tests for the `EngineRunner` that orchestrates build + run + progress.

use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter};
use hf_core::target::Sanitizer;
use hf_engine::runner::{EngineRunner, RunResult};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

/// A mock runtime that returns canned stdout for any command.
struct MockRuntime {
    exit_code: i32,
    stdout: String,
    termination: CommandTermination,
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
            termination: self.termination,
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
        seed: None,
        replay_of: None,
    }
}

#[tokio::test]
async fn runner_libfuzzer_parses_progress_and_coverage() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "INFO: 512 edges covered.\n#256: 3000 execs/sec\nINFO: 1024 edges covered.\nDONE\n"
            .to_owned(),
        termination: CommandTermination::Completed,
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
    let RunResult {
        progress,
        coverage,
        termination,
    } = result;
    assert_eq!(termination, CommandTermination::Completed);
    assert!(!progress.is_empty(), "should have progress events");
    assert!(
        progress
            .iter()
            .any(|e| matches!(e, hf_core::engine::FuzzProgress::Done)),
        "should have Done event"
    );
    assert_eq!(coverage.edges, 1024, "should pick max edge count");
    assert!(progress.iter().any(|event| {
        matches!(event, hf_core::engine::FuzzProgress::ExecsPerSec(value) if (*value - 3000.0).abs() < f64::EPSILON)
    }));
}

#[tokio::test]
async fn runner_retains_late_metrics_after_log_capture_is_truncated() {
    let mut stdout = "noise line\n".repeat(220_000);
    stdout.push_str(
        "#999 cov: 4096 ft: 10 corp: 1/1b exec/s: 777\nAddressSanitizer: crash-abc\nDONE\n",
    );
    let rt = MockRuntime {
        exit_code: 77,
        stdout,
        termination: CommandTermination::Completed,
    };

    let result = EngineRunner::new()
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
        .unwrap();

    assert_eq!(result.coverage.edges, 4096);
    assert!(result.progress.iter().any(|event| {
        matches!(event, hf_core::engine::FuzzProgress::ExecsPerSec(value) if (*value - 777.0).abs() < f64::EPSILON)
    }));
    assert!(result
        .progress
        .iter()
        .any(|event| matches!(event, hf_core::engine::FuzzProgress::CrashesFound(1))));
}

#[tokio::test]
async fn cancelled_run_returns_ok_instead_of_erroring() {
    use tokio_util::sync::CancellationToken;

    // A non-zero exit with no DONE/SUMMARY normally fails the run.
    let rt = MockRuntime {
        exit_code: 1,
        stdout: String::new(),
        termination: CommandTermination::Completed,
    };
    let runner = EngineRunner::new();

    // Without cancellation, that exit is treated as a failure.
    let token = CancellationToken::new();
    let failed = runner
        .run_streaming(
            EngineKind::LibFuzzer,
            &run_config(EngineKind::LibFuzzer, 60),
            "/work/fuzz_bin",
            "/work/corpus",
            "/work/out",
            &rt,
            &PathBuf::from("/work"),
            &token,
            &|_| {},
        )
        .await;
    assert!(
        failed.is_err(),
        "a bad exit should error when not cancelled"
    );

    // When the run was cancelled, the same outcome is accepted: cancellation is
    // a user action, not an engine failure.
    let token = CancellationToken::new();
    token.cancel();
    let cancelled = runner
        .run_streaming(
            EngineKind::LibFuzzer,
            &run_config(EngineKind::LibFuzzer, 60),
            "/work/fuzz_bin",
            "/work/corpus",
            "/work/out",
            &rt,
            &PathBuf::from("/work"),
            &token,
            &|_| {},
        )
        .await;
    assert!(cancelled.is_ok(), "a cancelled run should not error");
}

#[tokio::test]
async fn runner_afl_parses_progress() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "execs : 1000\ncov: 500\nDONE\n".to_owned(),
        termination: CommandTermination::Completed,
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
async fn runner_accepts_libfuzzer_timeout_exit_without_a_summary_line() {
    // libFuzzer's default -timeout_exitcode is 70. A timed-out unit is a
    // finding to triage, not an engine failure, and the process may exit 70
    // without printing a "summary" line, so exit 70 must be a valid outcome on
    // its own (not only rescued by the fragile summary-substring fallback).
    let rt = MockRuntime {
        exit_code: 70,
        // Output carries progress but none of done/summary/finished, so the
        // saw_completion fallback is not what rescues this run.
        stdout: "#4096 cov: 120 ft: 300 exec/s: 900 rss: 90Mb\n".to_owned(),
        termination: CommandTermination::Completed,
    };
    let result = EngineRunner::new()
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
        .expect("a libFuzzer timeout (exit 70) is a valid outcome, not an engine error");
    assert_eq!(result.coverage.edges, 120, "coverage must be preserved");
}

#[tokio::test]
async fn runner_returns_error_on_nonzero_exit() {
    let rt = MockRuntime {
        exit_code: 1,
        stdout: String::new(),
        termination: CommandTermination::Completed,
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
        termination: CommandTermination::Completed,
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

#[tokio::test]
async fn runner_rejects_a_sandbox_timeout_even_with_clean_output() {
    let rt = MockRuntime {
        exit_code: 0,
        stdout: "cov: 100\nDONE\n".to_owned(),
        termination: CommandTermination::TimedOut,
    };

    let result = EngineRunner::new()
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

    assert!(result.is_err(), "a forced timeout must not look completed");
}

#[tokio::test]
async fn runner_preserves_runtime_cancellation_without_a_token_race() {
    let rt = MockRuntime {
        exit_code: -1,
        stdout: "cov: 100\n".to_owned(),
        termination: CommandTermination::Cancelled,
    };

    let result = EngineRunner::new()
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
        .expect("runtime cancellation is retained as a terminal result");

    assert_eq!(result.termination, CommandTermination::Cancelled);
}

#[tokio::test]
async fn runner_forwards_the_read_only_execution_profile() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct OptionsRuntime {
        saw_read_only: AtomicBool,
    }

    #[async_trait::async_trait]
    impl RuntimeAdapter for OptionsRuntime {
        async fn run_command(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
        ) -> Result<CommandResult, ClassifiedError> {
            Ok(CommandResult {
                exit_code: 0,
                stdout: "cov: 1\nDONE\n".to_owned(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Completed,
            })
        }

        async fn run_command_streaming_opts(
            &self,
            _cmd: &[String],
            cwd: &Path,
            _limits: &ResourceLimits,
            opts: &hf_core::runtime::SandboxOptions,
            _cancel: &tokio_util::sync::CancellationToken,
            _on_line: &hf_core::runtime::LineSink<'_>,
        ) -> Result<CommandResult, ClassifiedError> {
            self.saw_read_only
                .store(opts.workspace_read_only, Ordering::SeqCst);
            self.run_command(&[], cwd, &ResourceLimits::default()).await
        }

        async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
            Ok(())
        }

        async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
            Ok(String::new())
        }
    }

    let runtime = OptionsRuntime {
        saw_read_only: AtomicBool::new(false),
    };
    let sandbox = hf_core::runtime::SandboxOptions {
        workspace_read_only: true,
        ..hf_core::runtime::SandboxOptions::default()
    };
    let cancel = tokio_util::sync::CancellationToken::new();
    EngineRunner::new()
        .run_streaming_opts(
            EngineKind::LibFuzzer,
            &run_config(EngineKind::LibFuzzer, 60),
            "/work/bin",
            "/work/corpus",
            "/work/runs/id/out",
            &runtime,
            &PathBuf::from("/work"),
            &sandbox,
            &cancel,
            &|_| {},
        )
        .await
        .unwrap();

    assert!(runtime.saw_read_only.load(Ordering::SeqCst));
}
