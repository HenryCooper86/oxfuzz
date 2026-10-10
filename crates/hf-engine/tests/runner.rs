//! Tests for the `EngineRunner` that orchestrates build + run + progress.

use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
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
        input_manifest_sha256: None,
        input_timeout: None,
        resume: false,
    }
}

/// Captures the resource limits the runner applied, so tests can assert the
/// sandbox environment a run receives.
struct LimitCapturingRuntime {
    limits: std::sync::Mutex<Option<ResourceLimits>>,
}

#[async_trait::async_trait]
impl RuntimeAdapter for LimitCapturingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        *self.limits.lock().unwrap() = Some(limits.clone());
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn libfuzzer_fork_runs_disable_the_exit_time_leak_sanitizer() {
    let runtime = LimitCapturingRuntime {
        limits: std::sync::Mutex::new(None),
    };
    let mut cfg = run_config(EngineKind::LibFuzzer, 10);
    cfg.max_cpus = 4;
    EngineRunner::new()
        .run(
            EngineKind::LibFuzzer,
            &cfg,
            "/work/h",
            "/work/corpus",
            "/work/out",
            &runtime,
            Path::new("/work"),
        )
        .await
        .expect("fork run completes");
    let limits = runtime
        .limits
        .lock()
        .unwrap()
        .clone()
        .expect("captured limits");
    assert_eq!(
        limits.env.get("ASAN_OPTIONS").map(String::as_str),
        Some("detect_leaks=0"),
        "fork children run the exit-time LeakSanitizer and misreport the forked heap snapshot: {limits:?}"
    );

    // Single-process runs keep the environment untouched: leak findings are
    // real there and triage ingests leak artifacts.
    let runtime = LimitCapturingRuntime {
        limits: std::sync::Mutex::new(None),
    };
    let cfg = run_config(EngineKind::LibFuzzer, 10);
    EngineRunner::new()
        .run(
            EngineKind::LibFuzzer,
            &cfg,
            "/work/h",
            "/work/corpus",
            "/work/out",
            &runtime,
            Path::new("/work"),
        )
        .await
        .expect("single-process run completes");
    let limits = runtime
        .limits
        .lock()
        .unwrap()
        .clone()
        .expect("captured limits");
    assert!(!limits.env.contains_key("ASAN_OPTIONS"));

    // An operator-provided ASAN_OPTIONS wins outright.
    let runtime = LimitCapturingRuntime {
        limits: std::sync::Mutex::new(None),
    };
    let mut cfg = run_config(EngineKind::LibFuzzer, 10);
    cfg.max_cpus = 4;
    cfg.env
        .push(("ASAN_OPTIONS".to_owned(), "abort_on_error=1".to_owned()));
    EngineRunner::new()
        .run(
            EngineKind::LibFuzzer,
            &cfg,
            "/work/h",
            "/work/corpus",
            "/work/out",
            &runtime,
            Path::new("/work"),
        )
        .await
        .expect("fork run completes");
    let limits = runtime
        .limits
        .lock()
        .unwrap()
        .clone()
        .expect("captured limits");
    assert_eq!(
        limits.env.get("ASAN_OPTIONS").map(String::as_str),
        Some("abort_on_error=1")
    );
}

/// A UBSan build still aborts on a finding (the binary is compiled
/// `-fno-sanitize-recover=undefined`), but its default report carries no stack
/// frames, which the dedup signature feeds on. For the direct libFuzzer run the
/// runner adds `UBSAN_OPTIONS=print_stacktrace=1` unless the operator set
/// UBSAN_OPTIONS outright.
///
/// The runner must NEVER set UBSAN_OPTIONS for AFL++ or honggfuzz: both engines
/// auto-configure `abort_on_error` when they detect sanitizer instrumentation,
/// and a preset UBSAN_OPTIONS suppresses that, turning the UBSan `Die()` (exit
/// code 1, no signal) into a non-crash those signal-based engines never save.
/// Verified against the pinned sandbox image (AFL++ 4.09c, honggfuzz 2.6).
#[tokio::test]
async fn ubsan_runs_set_print_stacktrace_for_libfuzzer_only() {
    async fn captured_env(
        engine: EngineKind,
        cfg: &FuzzRunConfig,
    ) -> std::collections::HashMap<String, String> {
        let runtime = LimitCapturingRuntime {
            limits: std::sync::Mutex::new(None),
        };
        EngineRunner::new()
            .run(
                engine,
                cfg,
                "/work/h",
                "/work/corpus",
                "/work/out",
                &runtime,
                Path::new("/work"),
            )
            .await
            .expect("run completes");
        let limits = runtime
            .limits
            .lock()
            .unwrap()
            .clone()
            .expect("captured limits");
        limits.env
    }

    let mut cfg = run_config(EngineKind::LibFuzzer, 10);
    cfg.sanitizer = Sanitizer::Undefined;
    let env = captured_env(EngineKind::LibFuzzer, &cfg).await;
    assert_eq!(
        env.get("UBSAN_OPTIONS").map(String::as_str),
        Some("print_stacktrace=1"),
        "UBSan reports need frames for the dedup signature: {env:?}"
    );

    // An operator-provided UBSAN_OPTIONS wins outright (the runner does not
    // merge sanitizer options it cannot interpret).
    let mut cfg = run_config(EngineKind::LibFuzzer, 10);
    cfg.sanitizer = Sanitizer::Undefined;
    cfg.env
        .push(("UBSAN_OPTIONS".to_owned(), "abort_on_error=1".to_owned()));
    let env = captured_env(EngineKind::LibFuzzer, &cfg).await;
    assert_eq!(
        env.get("UBSAN_OPTIONS").map(String::as_str),
        Some("abort_on_error=1")
    );

    // AFL++ and honggfuzz auto-configure their sanitizer environment; a preset
    // UBSAN_OPTIONS would suppress it and silently drop UBSan findings.
    for engine in [EngineKind::AflPlusPlus, EngineKind::Honggfuzz] {
        let mut cfg = run_config(engine, 10);
        cfg.sanitizer = Sanitizer::Undefined;
        let env = captured_env(engine, &cfg).await;
        assert!(
            !env.contains_key("UBSAN_OPTIONS"),
            "{engine:?} owns its sanitizer environment: {env:?}"
        );
    }

    // An ASan build gets no UBSan environment.
    let cfg = run_config(EngineKind::LibFuzzer, 10);
    let env = captured_env(EngineKind::LibFuzzer, &cfg).await;
    assert!(!env.contains_key("UBSAN_OPTIONS"));
}

/// `cfg.env` is copied into the sandbox environment by the runner. AFL++
/// session resume is the runner's own env knob: `FuzzRunConfig.resume` injects
/// `AFL_AUTORESUME=1` so afl-fuzz continues a copied-forward output tree, and
/// a hand-set `AFL_AUTORESUME` in `cfg.env` is a second source of resume truth
/// and rejected.
#[tokio::test]
async fn afl_resume_injects_autoresume_and_rejects_a_hand_set_one() {
    async fn captured_env(
        cfg: &FuzzRunConfig,
    ) -> Result<std::collections::HashMap<String, String>, ClassifiedError> {
        let runtime = LimitCapturingRuntime {
            limits: std::sync::Mutex::new(None),
        };
        EngineRunner::new()
            .run(
                EngineKind::AflPlusPlus,
                cfg,
                "/work/h",
                "/work/corpus",
                "/work/out",
                &runtime,
                Path::new("/work"),
            )
            .await?;
        let env = runtime
            .limits
            .lock()
            .unwrap()
            .clone()
            .expect("captured limits")
            .env;
        Ok(env)
    }

    let resumed = captured_env(&FuzzRunConfig {
        resume: true,
        ..run_config(EngineKind::AflPlusPlus, 10)
    })
    .await
    .expect("a resume run completes");
    assert_eq!(
        resumed.get("AFL_AUTORESUME").map(String::as_str),
        Some("1"),
        "resume must set AFL_AUTORESUME=1: {resumed:?}"
    );

    let cold = captured_env(&run_config(EngineKind::AflPlusPlus, 10))
        .await
        .expect("a cold run completes");
    assert!(
        !cold.contains_key("AFL_AUTORESUME"),
        "a cold run must not enable resume: {cold:?}"
    );

    for resume in [false, true] {
        let mut cfg = run_config(EngineKind::AflPlusPlus, 10);
        cfg.resume = resume;
        cfg.env.push(("AFL_AUTORESUME".to_owned(), "1".to_owned()));
        let error = captured_env(&cfg)
            .await
            .expect_err("a hand-set AFL_AUTORESUME is a second resume source");
        assert!(
            error.to_string().contains("AFL_AUTORESUME"),
            "the error must name the smuggled variable: {error}"
        );
    }

    // The knob belongs to AFL++; other engines never see it.
    let libfuzzer = {
        let runtime = LimitCapturingRuntime {
            limits: std::sync::Mutex::new(None),
        };
        EngineRunner::new()
            .run(
                EngineKind::LibFuzzer,
                &run_config(EngineKind::LibFuzzer, 10),
                "/work/h",
                "/work/corpus",
                "/work/out",
                &runtime,
                Path::new("/work"),
            )
            .await
            .expect("libfuzzer run completes");
        let env = runtime
            .limits
            .lock()
            .unwrap()
            .clone()
            .expect("captured limits")
            .env;
        env
    };
    assert!(!libfuzzer.contains_key("AFL_AUTORESUME"));
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
    assert!(
        progress
            .iter()
            .any(|e| matches!(e, hf_core::engine::FuzzProgress::EdgesCovered(1024))),
        "should report the max edge count: {progress:?}"
    );
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

    assert!(result
        .progress
        .iter()
        .any(|e| matches!(e, hf_core::engine::FuzzProgress::EdgesCovered(4096))));
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
    assert!(result
        .progress
        .iter()
        .any(|e| matches!(e, hf_core::engine::FuzzProgress::EdgesCovered(500))));
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
    assert!(
        result
            .progress
            .iter()
            .any(|e| matches!(e, hf_core::engine::FuzzProgress::EdgesCovered(120))),
        "coverage must be preserved: {:?}",
        result.progress
    );
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

/// A run killed at the sandbox wall-clock cap keeps the coverage it measured.
///
/// The edge counts and exec rates come from the fuzzer's own stats lines and
/// were parsed long before the cap fired, so discarding them loses real
/// evidence. Cancellation already keeps its partial progress; a wall-clock kill
/// holds the same kind of evidence and is treated the same way here. The run is
/// still not a clean completion -- `termination` says so, and no closing `Done`
/// is emitted -- which is what the service records the run as failed on.
#[tokio::test]
async fn runner_keeps_the_coverage_of_a_run_the_sandbox_timed_out() {
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
        .await
        .expect("a wall-clock kill retains the run's measured evidence");

    assert_eq!(result.termination, CommandTermination::TimedOut);
    assert!(
        result
            .progress
            .iter()
            .any(|event| matches!(event, FuzzProgress::EdgesCovered(100))),
        "the parsed edge count must survive the kill: {:?}",
        result.progress
    );
    assert!(
        !result
            .progress
            .iter()
            .any(|event| matches!(event, FuzzProgress::Done)),
        "a timed-out run is not a clean completion: {:?}",
        result.progress
    );
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
