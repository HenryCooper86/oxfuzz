//! Engine runner: orchestrates build + run + progress/coverage parsing.
//!
//! The `EngineRunner` is engine-agnostic: it delegates argument construction
//! to the per-engine `build_run_args` functions and parses stdout uniformly.

use std::path::Path;

use hf_core::coverage::CoverageReport;
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandTermination, RuntimeAdapter};
use uuid::Uuid;

/// Extra wall-clock seconds the sandbox is allowed beyond the fuzzer's own
/// `-max_total_time`, covering corpus loading and sanitizer shutdown. Shared
/// with the smoke-qualification path in `hf-harness` so a non-crashing harness
/// that runs its full time budget is not killed at the sandbox cap before its
/// activity can be measured.
pub const SANDBOX_TIMEOUT_HEADROOM_SECS: u64 = 60;

/// Default run duration (seconds) applied when a `FuzzRunConfig` carries no
/// explicit duration, so the fuzzer always gets a self-limit and exits cleanly
/// within the sandbox window rather than being killed at the wall-clock cap.
const DEFAULT_RUN_SECS: u64 = 3600;
#[derive(Default)]
struct ProgressAggregate {
    first_edges: Option<u64>,
    peak_edges: u64,
    peak_execs: f64,
    crashes: u64,
}

impl ProgressAggregate {
    fn observe_event(&mut self, event: &FuzzProgress) {
        match event {
            FuzzProgress::EdgesCovered(edges) => {
                self.first_edges.get_or_insert(*edges);
                self.peak_edges = self.peak_edges.max(*edges);
            }
            FuzzProgress::ExecsPerSec(execs) => self.peak_execs = self.peak_execs.max(*execs),
            // Generic engine logs often emit several lines for one finding
            // (sanitizer, SUMMARY, artifact path). Preserve the durable fact
            // that at least one finding occurred; the service counts distinct
            // run-owned artifact files for the exact total.
            FuzzProgress::CrashesFound(_) => self.crashes = self.crashes.max(1),
            FuzzProgress::LogLine(_) | FuzzProgress::Done => {}
        }
    }

    fn observe_syzkaller(&mut self, cover: u64, crashes: u64) {
        self.first_edges.get_or_insert(cover);
        self.peak_edges = self.peak_edges.max(cover);
        self.crashes = self.crashes.max(crashes);
    }

    fn progress(&self, done: bool) -> Vec<FuzzProgress> {
        let mut progress = Vec::new();
        if self.peak_edges > 0 {
            progress.push(FuzzProgress::EdgesCovered(self.peak_edges));
        }
        if self.peak_execs > 0.0 {
            progress.push(FuzzProgress::ExecsPerSec(self.peak_execs));
        }
        if self.crashes > 0 {
            progress.push(FuzzProgress::CrashesFound(
                u32::try_from(self.crashes).unwrap_or(u32::MAX),
            ));
        }
        if done {
            progress.push(FuzzProgress::Done);
        }
        progress
    }

    fn coverage(&self, run_id: Uuid) -> CoverageReport {
        CoverageReport {
            run_id,
            edges: self.peak_edges,
            blocks: 0,
            delta_edges: self.peak_edges.cast_signed()
                - self.first_edges.unwrap_or(0).cast_signed(),
            stagnation_secs: 0,
            new_edges_files: Vec::new(),
        }
    }
}

/// The result of a fuzz run.
pub struct RunResult {
    pub progress: Vec<FuzzProgress>,
    pub coverage: CoverageReport,
    /// The runtime-owned reason the command stopped.
    pub termination: CommandTermination,
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
    /// Run a fuzz campaign, collecting progress/coverage from the output.
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
        let cancel = tokio_util::sync::CancellationToken::new();
        self.run_streaming(
            engine,
            cfg,
            binary,
            corpus,
            out,
            rt,
            workspace,
            &cancel,
            &|_| {},
        )
        .await
    }

    /// Run a fuzz campaign, invoking `on_progress` for each event **as the
    /// fuzzer produces it** (live), in addition to returning the final result.
    ///
    /// Each output line is forwarded as a [`FuzzProgress::LogLine`] for a live
    /// terminal view, plus any structured stats it carries (edges, exec/s,
    /// crashes). A closing [`FuzzProgress::Done`] is emitted on success.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the engine is not supported or the
    /// sandboxed command returns a non-zero exit code.
    pub async fn run_streaming(
        &self,
        engine: EngineKind,
        cfg: &FuzzRunConfig,
        binary: &str,
        corpus: &str,
        out: &str,
        rt: &dyn RuntimeAdapter,
        workspace: &Path,
        cancel: &tokio_util::sync::CancellationToken,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<RunResult, ClassifiedError> {
        self.run_streaming_opts(
            engine,
            cfg,
            binary,
            corpus,
            out,
            rt,
            workspace,
            &hf_core::runtime::SandboxOptions::default(),
            cancel,
            on_progress,
        )
        .await
    }

    /// Run a fuzz campaign with an explicit sandbox mount/profile contract.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the engine is unsupported, the runtime is
    /// force-stopped, or a completed engine process reports an invalid exit.
    pub async fn run_streaming_opts(
        &self,
        engine: EngineKind,
        cfg: &FuzzRunConfig,
        binary: &str,
        corpus: &str,
        out: &str,
        rt: &dyn RuntimeAdapter,
        workspace: &Path,
        sandbox: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<RunResult, ClassifiedError> {
        // A run with no explicit duration would otherwise get no self-limit
        // flag (`-max_total_time`/`-V`/`--run_time`) from the adapter and run
        // forever, only to be killed at the sandbox wall-clock cap -- and a
        // killed run is classified as an engine error, discarding its coverage.
        // Fill in a concrete default so the adapter bounds the fuzzer and both
        // layers agree: the fuzzer exits cleanly within the sandbox window.
        let effective_cfg = if cfg.duration.is_some() {
            std::borrow::Cow::Borrowed(cfg)
        } else {
            let mut c = cfg.clone();
            c.duration = Some(std::time::Duration::from_secs(DEFAULT_RUN_SECS));
            std::borrow::Cow::Owned(c)
        };
        let cfg = effective_cfg.as_ref();

        let args = crate::registry::adapter_for(engine).build_run_args(cfg, binary, corpus, out);
        // The sandbox wall-clock timeout must exceed the fuzzer's own run time:
        // a libFuzzer `-max_total_time=N` campaign also spends time loading the
        // corpus and running ASan leak detection at exit, so without headroom
        // the container is killed as "command timed out" right at the finish.
        let max_duration_secs = cfg.duration.map_or(DEFAULT_RUN_SECS, |d| {
            d.as_secs().saturating_add(SANDBOX_TIMEOUT_HEADROOM_SECS)
        });
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: cfg.max_mem_mb,
            max_cpus: cfg.max_cpus,
            max_duration_secs,
            env: cfg.env.iter().cloned().collect(),
            ptrace: false,
        };

        // syz-manager reports absolute counters on its status lines, so it needs
        // dedicated parsing rather than the generic per-line event extraction
        // (which would miscount each `crashes N` token as a fresh finding).
        let is_syzkaller = engine == EngineKind::Syzkaller;
        let syz_crashes = std::sync::atomic::AtomicU64::new(0);
        let aggregate = std::sync::Mutex::new(ProgressAggregate::default());
        let saw_line = std::sync::atomic::AtomicBool::new(false);
        let saw_completion = std::sync::atomic::AtomicBool::new(false);

        let on_line = |line: &str| {
            use std::sync::atomic::Ordering::Relaxed;

            saw_line.store(true, Relaxed);
            let lower = line.to_ascii_lowercase();
            if lower.contains("done") || lower.contains("summary") || lower.contains("finished") {
                saw_completion.store(true, Relaxed);
            }
            on_progress(FuzzProgress::LogLine(line.to_owned()));
            if is_syzkaller {
                // Structured syzkaller progress comes only from status lines;
                // emit coverage live and a crash event per newly-seen crash.
                if let Some((cover, _executed, crashes)) =
                    crate::progress::parse_syzkaller_status(line)
                {
                    if let Ok(mut aggregate) = aggregate.lock() {
                        aggregate.observe_syzkaller(cover, crashes);
                    }
                    on_progress(FuzzProgress::EdgesCovered(cover));
                    let prev = syz_crashes.swap(crashes, Relaxed);
                    for _ in prev..crashes {
                        on_progress(FuzzProgress::CrashesFound(1));
                    }
                }
                return;
            }
            for event in crate::progress::parse_progress_events(line) {
                if let Ok(mut aggregate) = aggregate.lock() {
                    aggregate.observe_event(&event);
                }
                on_progress(event);
            }
        };
        let result = rt
            .run_command_streaming_opts(&args, workspace, &limits, sandbox, cancel, &on_line)
            .await?;

        if !saw_line.load(std::sync::atomic::Ordering::Relaxed) {
            for line in result.stdout.lines().chain(result.stderr.lines()) {
                on_line(line);
            }
        }
        let aggregate = aggregate
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // The runtime's typed terminal outcome is authoritative. A token can be
        // cancelled just after a process exits, and a forced stop has no useful
        // exit code, so inferring either state from those values is racy.
        match result.termination {
            CommandTermination::Cancelled => {
                let run_id = Uuid::new_v4();
                let progress = aggregate.progress(false);
                let coverage = aggregate.coverage(run_id);
                return Ok(RunResult {
                    progress,
                    coverage,
                    termination: CommandTermination::Cancelled,
                });
            }
            CommandTermination::TimedOut => {
                return Err(ClassifiedError::Engine(
                    "fuzz run exceeded the sandbox wall-clock limit".to_owned(),
                ));
            }
            CommandTermination::Completed => {}
        }

        // libFuzzer exit codes: 0 = clean exit, 77 = crash/leak found,
        // 76 = OOM, 1 = error. 0, 77 and 76 are all valid fuzzing outcomes -- an
        // OOM is a finding to triage, not an engine failure, so it must not be
        // turned into an error (which would discard the run's coverage).
        let is_valid_outcome = result.exit_code == 0
            || result.exit_code == 77
            || result.exit_code == 76
            || saw_completion.load(std::sync::atomic::Ordering::Relaxed);
        if !is_valid_outcome {
            return Err(ClassifiedError::Engine(format!(
                "fuzz run exited {} : {}",
                result.exit_code,
                result.stderr.chars().take(500).collect::<String>()
            )));
        }
        let run_id = Uuid::new_v4();
        let progress = aggregate.progress(true);
        let coverage = aggregate.coverage(run_id);
        on_progress(FuzzProgress::Done);
        Ok(RunResult {
            progress,
            coverage,
            termination: CommandTermination::Completed,
        })
    }
}
