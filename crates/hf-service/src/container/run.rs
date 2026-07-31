//! Campaign execution, replay, and cooperative cancellation.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::target::TargetLanguage;
use hf_guardrails::Action;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::guards::ActiveRunGuard;
use super::project_identity::canonical_project_root;
use super::staging::ReplayProvenance;
use super::workspace::prepare_configured_workspace_root;
use super::{
    resolve_fuzzing_run, syz_kvm_usable, syzkaller_manager_command, CampaignOutcome,
    RunCancelOutcome, RunControlStatus, RunLifecycleStatus, RunSummary, ServiceContainer,
    SyzkallerRunOpts, SyzkallerSummary,
};

impl ServiceContainer {
    /// Run an approved fuzzing campaign end to end: discover (and pick the best
    /// target when none is given) -> require the active harness to have passed
    /// smoke qualification and explicit promotion -> seed the corpus -> loop
    /// [run -> triage -> feed crashes back] until a crash is found or
    /// `max_iterations` is reached.
    ///
    /// This is the coded orchestration the scheduler and "just fuzz this" flows
    /// use, so a scheduled campaign runs the whole pipeline rather than a single
    /// fixed run. Each iteration is bounded by `duration_secs`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if discovery finds no target or any mandatory
    /// qualification, persistence, run, or triage step fails.
    pub async fn run_campaign(
        &self,
        project: &Path,
        target: Option<&str>,
        engine: EngineKind,
        lang: TargetLanguage,
        duration_secs: u64,
        max_iterations: usize,
    ) -> Result<CampaignOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let resolved = resolve_fuzzing_run(engine, duration_secs)?;
        let engine = resolved.engine;
        // 1. Choose a target: the caller's, else the top-ranked candidate.
        let inv = self.discover(project, lang).await?;
        let target = match target.filter(|t| !t.is_empty()) {
            Some(t) => t.to_owned(),
            None => {
                #[cfg(feature = "semgrep-enrichment")]
                {
                    let effective = self.effective_inventory(inv, lang).await?;
                    effective
                        .candidates
                        .first()
                        .map(|candidate| candidate.candidate.symbol.clone())
                        .ok_or_else(|| {
                            ClassifiedError::Validation("no fuzzable targets discovered".to_owned())
                        })?
                }
                #[cfg(not(feature = "semgrep-enrichment"))]
                {
                    inv.ranked()
                        .first()
                        .map(|candidate| candidate.symbol.clone())
                        .ok_or_else(|| {
                            ClassifiedError::Validation("no fuzzable targets discovered".to_owned())
                        })?
                }
            }
        };

        // 2. Scheduled/agent campaigns may use only a revision a human already
        // approved. Generation, smoke, and promotion are deliberately separate
        // workbench operations.
        let harness = self.active_harness(project, &target, engine).await?;
        if harness.language != lang || harness.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(format!(
                "campaign target '{target}' needs a smoke-qualified, explicitly promoted {lang:?} harness"
            )));
        }
        let _ = self.generate_seeds_llm(project, &target, lang, 12).await;

        // 3. Run -> triage loop, stopping on the first crash or the iteration cap.
        let noop = |_: FuzzProgress| {};
        let mut edges = 0u64;
        let mut crashes = 0usize;
        let mut iterations = 0usize;
        let mut auto_reverts = 0usize;
        let mut termination = hf_core::runtime::CommandTermination::Completed;
        let mut last_stagnation: Option<hf_coverage::StagnationProposal> = None;
        let cap = max_iterations.max(1);
        while iterations < cap {
            iterations += 1;
            let summary = self
                .run_fuzzer_with_started(project, &target, resolved, &noop, &|_| {}, None)
                .await?;
            termination = summary.termination;
            edges = edges.max(summary.edges);
            last_stagnation = summary.stagnation.clone();
            // A refine step between iterations can regress coverage; the policy
            // (armed via config) then restores the last-good harness, or, in
            // notify-only mode, flags it. Count either so history shows it.
            if summary.auto_revert.is_some() {
                auto_reverts += 1;
            }

            if termination == hf_core::runtime::CommandTermination::Cancelled {
                break;
            }

            let triaged = self.triage_run(project, &target, summary.run_id).await?;
            crashes = triaged.len();
            // Feed any crash reproducers back into the corpus (close the loop).
            let _ = self
                .corpus_absorb_crashes_for_run(project, &target, summary.run_id)
                .await;

            if crashes > 0 || iterations >= cap {
                break;
            }
        }

        // Coverage-driven loop: if the campaign plateaued on coverage without
        // finding a crash, PROPOSE a targeted refined harness aimed at the
        // uncovered frontier. HITL (AGENTS.md 2.12): the proposal is left
        // `Compiled`, never promoted or auto-run, and it is only attempted when
        // the compile action is already policy-allowed -- otherwise the plateau
        // is surfaced for a human to trigger refinement through the normal
        // approval path, so the campaign never blocks here.
        let refine = if crashes == 0
            && termination != hf_core::runtime::CommandTermination::Cancelled
            && last_stagnation == Some(hf_coverage::StagnationProposal::NewHarness)
        {
            self.propose_refine_on_plateau(project, &target, engine, lang)
                .await
        } else {
            None
        };

        Ok(CampaignOutcome {
            target,
            harness_status: harness.status,
            crashes,
            edges,
            iterations,
            auto_reverts,
            termination,
            refine,
        })
    }

    /// Reserve and launch a fuzz campaign in a service-owned background task.
    ///
    /// The returned UUID is already persisted, recovery-journaled, and
    /// registered for cooperative cancellation. Progress and lifecycle sinks
    /// always receive that same service-owned id. A request future may be
    /// dropped after this method returns without aborting the campaign.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError`] when preflight or durable reservation
    /// fails. Errors after reservation are reflected in the persisted run and
    /// delivered as a [`RunLifecycleStatus::Failed`] lifecycle callback.
    pub async fn start_fuzzer(
        &self,
        project: PathBuf,
        target: String,
        engine: EngineKind,
        duration_secs: u64,
        on_progress: Arc<dyn Fn(Uuid, FuzzProgress) + Send + Sync + 'static>,
        on_status: Arc<dyn Fn(Uuid, RunLifecycleStatus) + Send + Sync + 'static>,
    ) -> Result<Uuid, ClassifiedError> {
        let resolved = resolve_fuzzing_run(engine, duration_secs)?;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let started_tx = Arc::new(std::sync::Mutex::new(Some(started_tx)));
        let active_id = Arc::new(std::sync::Mutex::new(None));
        let container = self.clone();

        tokio::spawn({
            let started_tx = Arc::clone(&started_tx);
            let active_id = Arc::clone(&active_id);
            async move {
                let progress_sink = {
                    let active_id = Arc::clone(&active_id);
                    let on_progress = Arc::clone(&on_progress);
                    move |progress| {
                        if let Ok(id) = active_id.lock() {
                            if let Some(id) = *id {
                                on_progress(id, progress);
                            }
                        }
                    }
                };
                let started_sink = {
                    let active_id = Arc::clone(&active_id);
                    let started_tx = Arc::clone(&started_tx);
                    let on_status = Arc::clone(&on_status);
                    move |run_id| {
                        if let Ok(mut id) = active_id.lock() {
                            *id = Some(run_id);
                        }
                        on_status(run_id, RunLifecycleStatus::Running);
                        if let Ok(mut sender) = started_tx.lock() {
                            if let Some(sender) = sender.take() {
                                let _ = sender.send(Ok(run_id));
                            }
                        }
                    }
                };

                let result = container
                    .run_fuzzer_with_started(
                        &project,
                        &target,
                        resolved,
                        &progress_sink,
                        &started_sink,
                        None,
                    )
                    .await;
                match result {
                    Ok(summary) => {
                        let status = if summary.termination
                            == hf_core::runtime::CommandTermination::Cancelled
                        {
                            RunLifecycleStatus::Cancelled
                        } else {
                            RunLifecycleStatus::Done
                        };
                        on_status(summary.run_id, status);
                    }
                    Err(error) => {
                        let run_id = active_id.lock().ok().and_then(|id| *id);
                        if let Some(run_id) = run_id {
                            tracing::error!(%run_id, %error, "background fuzz run failed");
                            on_status(run_id, RunLifecycleStatus::Failed);
                        } else if let Ok(mut sender) = started_tx.lock() {
                            if let Some(sender) = sender.take() {
                                let _ = sender.send(Err(error));
                            }
                        }
                    }
                }
            }
        });

        started_rx.await.map_err(|_| {
            ClassifiedError::Internal(
                "background fuzz task ended before durable reservation".to_owned(),
            )
        })?
    }

    /// Read the durable lifecycle state for one run.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError`] when persistence is unavailable or the
    /// stored row cannot be decoded.
    pub async fn run_control_status(
        &self,
        run_id: Uuid,
    ) -> Result<Option<RunControlStatus>, ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run control requires the persistent service store".into())
        })?;
        let Some(run) = store
            .get_run(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        else {
            return Ok(None);
        };
        let active = self
            .active_runs
            .lock()
            .map_err(|_| ClassifiedError::Internal("active-run registry is poisoned".into()))?
            .contains_key(&run_id);
        Ok(Some(RunControlStatus {
            run_id,
            status: run.status.into(),
            active,
            started_at: run.started_at.to_rfc3339(),
            ended_at: run.ended_at.map(|ended_at| ended_at.to_rfc3339()),
        }))
    }

    /// Request cooperative cancellation for one durable run.
    ///
    /// # Errors
    /// Returns a [`ClassifiedError`] when run state cannot be read or the
    /// active-run registry is unavailable.
    pub async fn request_run_cancel(
        &self,
        run_id: Uuid,
    ) -> Result<RunCancelOutcome, ClassifiedError> {
        let Some(status) = self.run_control_status(run_id).await? else {
            return Ok(RunCancelOutcome::NotFound);
        };
        if status.status != RunLifecycleStatus::Running || !status.active {
            return Ok(RunCancelOutcome::Inactive);
        }
        let runs = self
            .active_runs
            .lock()
            .map_err(|_| ClassifiedError::Internal("active-run registry is poisoned".into()))?;
        let Some(token) = runs.get(&run_id) else {
            return Ok(RunCancelOutcome::Inactive);
        };
        if token.is_cancelled() {
            return Ok(RunCancelOutcome::Inactive);
        }
        token.cancel();
        Ok(RunCancelOutcome::Accepted)
    }

    /// Cancel an in-flight fuzz run by id.
    ///
    /// Fires the run's cancellation token, which cooperatively tears down the
    /// sandboxed fuzzer (the container is killed) and lets [`Self::run_fuzzer`]
    /// return with the partial results it collected, marking the run
    /// `Cancelled`. Returns `true` if a matching active run was found.
    #[must_use]
    pub fn cancel_run(&self, run_id: Uuid) -> bool {
        let Ok(runs) = self.active_runs.lock() else {
            return false;
        };
        if let Some(token) = runs.get(&run_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Cancel every in-flight fuzz run, returning how many were signalled.
    ///
    /// Used for a blanket stop (e.g. a CLI Ctrl-C) where the caller does not
    /// track individual run ids.
    pub fn cancel_all_runs(&self) -> usize {
        let Ok(runs) = self.active_runs.lock() else {
            return 0;
        };
        for token in runs.values() {
            token.cancel();
        }
        runs.len()
    }

    /// The ids of fuzz runs currently in flight.
    #[must_use]
    pub fn active_run_ids(&self) -> Vec<Uuid> {
        self.active_runs
            .lock()
            .map(|runs| runs.keys().copied().collect())
            .unwrap_or_default()
    }

    /// Run a fuzz campaign via `hf-engine::runner::EngineRunner`.
    ///
    /// `on_progress` is called for each parsed `FuzzProgress` event so the
    /// caller can stream it to the UI.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the engine is not supported or the
    /// sandboxed command returns a non-zero exit code.
    pub async fn run_fuzzer(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        duration_secs: u64,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<RunSummary, ClassifiedError> {
        let resolved = resolve_fuzzing_run(engine, duration_secs)?;
        self.run_fuzzer_with_started(project, target, resolved, on_progress, &|_| {}, None)
            .await
    }

    /// Re-execute a recorded run with its exact engine, duration, resource
    /// limits, and RNG seed.
    ///
    /// The original run's persisted config supplies every reproducibility
    /// input; when it predates recorded seeds, the seed is re-derived from the
    /// original run id exactly as the original run path would have derived it.
    /// The replay launches through the normal run path (same authorization,
    /// sandboxing, corpus merge, and WAL journaling), so the replayed run is
    /// persisted as its own new campaign row whose config links back to the
    /// original via `replay_of` and pins the same `seed`. The corpus and
    /// promoted harness are intentionally taken from the target's current
    /// state: replay pins the RNG seed, not the (deliberately evolving)
    /// shared corpus. The original run's row and journal state are untouched.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run or its harness/target is unknown,
    /// the run has no recorded config, or the replayed run itself fails.
    pub async fn replay_run(
        &self,
        run_id: Uuid,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<RunSummary, ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("fuzz runs require the persistent service store".to_owned())
        })?;
        let original = store
            .get_run(run_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {run_id}")))?;
        let config = original.config.clone().ok_or_else(|| {
            ClassifiedError::Validation(format!("run {run_id} has no recorded config to replay"))
        })?;
        let project = canonical_project_root(Path::new(&original.project_root))?;
        let harness = store
            .get_harness(config.harness_id)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run {run_id} references a harness that no longer exists"
                ))
            })?;
        let target = store
            .list_targets(&original.project_root)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .find(|candidate| candidate.id == harness.target_id)
            .map(|candidate| candidate.symbol)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run {run_id} references a target that no longer exists"
                ))
            })?;

        // A config persisted before seeds were recorded replays with the seed
        // the original run would have derived from its own id.
        let seed = config
            .seed
            .unwrap_or_else(|| hf_engine::seed::derive_run_seed(run_id));
        // Replay the recorded campaign parameters verbatim rather than
        // re-resolving them against the current operator policy: the point of
        // a replay is to reproduce the original run, not a policy-clamped one.
        // Authorization still happens on the normal run path.
        let resolved = crate::config::ResolvedFuzzingRun {
            engine: original.engine,
            duration_secs: config.duration.map_or(3600, |d| d.as_secs()),
            max_mem_mb: config.max_mem_mb,
            max_cpus: config.max_cpus,
        };
        let journal = Arc::clone(&self.run_journal);
        self.run_fuzzer_with_started(
            project.as_path(),
            &target,
            resolved,
            on_progress,
            &move |replayed_run_id| {
                journal.note(
                    replayed_run_id,
                    "replay",
                    &format!("replays run {run_id} with seed {seed}"),
                );
            },
            Some(ReplayProvenance {
                original_run_id: run_id,
                seed,
            }),
        )
        .await
    }

    /// Run a syzkaller kernel-fuzzing campaign through the sandbox.
    ///
    /// syzkaller fuzzes an OS kernel by mutating syscall sequences inside a
    /// managed VM whose kernel is built with KCOV coverage. User-selected
    /// artifacts are copied into a unique service-owned directory, manager
    /// paths are rewritten to those staged copies, and `syz-manager` progress
    /// is streamed to `on_progress`.
    ///
    /// qemu runs with the standard capability and privilege hardening, no
    /// container network, and at most the `/dev/kvm` device. The selected
    /// rootfs is never mounted writable; qemu receives a disposable copy.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if Docker is unavailable, an artifact path is
    /// invalid, or the sandbox run fails.
    pub async fn run_syzkaller(
        &self,
        opts: &SyzkallerRunOpts,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<SyzkallerSummary, ClassifiedError> {
        use std::sync::atomic::{AtomicU64, Ordering};
        let _workspace_operation = self.acquire_workspace_operation().await?;

        let resolved = resolve_fuzzing_run(EngineKind::Syzkaller, opts.duration_secs)?;
        let duration_secs = resolved.duration_secs;

        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "Syzkaller".to_owned(),
                duration_secs,
            },
            "run_syzkaller",
            None,
        )
        .await?;

        let platform = opts
            .arch
            .as_deref()
            .map_or_else(hf_runtime::host_platform, hf_runtime::norm_platform);
        let target_triple = format!("linux/{}", hf_runtime::platform_short(&platform));

        let log = |s: &str| on_progress(FuzzProgress::LogLine(s.to_owned()));
        let nonempty = |o: &Option<String>| {
            o.as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        };
        let manager_cfg = nonempty(&opts.manager_cfg);
        let kernel_image = nonempty(&opts.kernel_image);
        let disk_image = nonempty(&opts.disk_image);
        let ssh_key = nonempty(&opts.ssh_key);

        let have_artifacts = kernel_image.is_some() && disk_image.is_some();

        // No artifacts at all: surface what a campaign needs and stop (no error).
        if manager_cfg.is_none() && !have_artifacts {
            for line in [
                format!("syzkaller (kernel fuzzing) -- project: {}", opts.project),
                "No campaign artifacts provided. syzkaller drives a VM against a".to_owned(),
                "KCOV-instrumented kernel; it needs one of:".to_owned(),
                "  (a) a kernel image (bzImage) + a rootfs disk image, or".to_owned(),
                "  (b) an existing syz-manager config (manager.cfg).".to_owned(),
                "Build a KCOV kernel + rootfs per the setup guide, then select them above:"
                    .to_owned(),
                "https://github.com/google/syzkaller/blob/master/docs/linux/setup.md".to_owned(),
            ] {
                log(&line);
            }
            on_progress(FuzzProgress::Done);
            return Ok(SyzkallerSummary::default());
        }

        if !hf_runtime::docker_daemon_ready() {
            return Err(ClassifiedError::Sandbox(
                "Docker daemon not running -- cannot launch syz-manager.".to_owned(),
            ));
        }

        // Use KVM when the host can (native-arch Linux with /dev/kvm); this is
        // orders of magnitude faster than TCG emulation. It drives both the
        // synthesized qemu args and the sole device passthrough below.
        let use_kvm = syz_kvm_usable(&platform);
        let run_id = Uuid::new_v4();
        let provided_config = manager_cfg.is_some();
        let workspace_root = prepare_configured_workspace_root()?;
        let stage_request = crate::syzkaller::SyzkallerStageRequest {
            workspace_root,
            run_id,
            target_triple: target_triple.clone(),
            manager_cfg: manager_cfg.map(PathBuf::from),
            kernel_image: kernel_image.map(PathBuf::from),
            disk_image: disk_image.map(PathBuf::from),
            ssh_key: ssh_key.map(PathBuf::from),
            vm_count: opts.vm_count,
            use_kvm,
            // Size the VM fan-out to the same budget the container is given so
            // the swap-less cgroup cannot OOM-kill qemu.
            container_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
        };
        // Rootfs images can be several GiB. Keep the copy off the async runtime
        // while retaining a guard that removes staging on completion or abort.
        let stage =
            tokio::task::spawn_blocking(move || crate::syzkaller::prepare_stage(&stage_request))
                .await
                .map_err(|error| {
                    ClassifiedError::Internal(format!("join syzkaller staging task: {error}"))
                })??;
        let workspace = stage.root.clone();
        let sandbox_opts = crate::syzkaller::sandbox_options(&stage, &platform, use_kvm);
        if provided_config {
            log("Validated and rewrote the provided manager.cfg into isolated staging.");
        } else {
            log(&format!(
                "Synthesized an isolated qemu manager.cfg ({target_triple})."
            ));
        }

        log(&format!(
            "Launching syz-manager in the sandbox for {duration_secs}s..."
        ));
        if use_kvm {
            log("Note: qemu uses KVM acceleration (/dev/kvm passed through) -- expect good exec rates.");
        } else {
            log("Note: qemu runs under TCG emulation inside Docker (no KVM on this host) -- expect low exec rates.");
        }

        // A graceful multi-VM syz-manager teardown scales with the VM count, so
        // the outer Docker deadline reuses the engine sandbox headroom per VM
        // rather than a flat 30s -- a slow shutdown that tripped the old margin
        // was classified as TimedOut and discarded the whole campaign summary.
        // The inner `timeout --kill-after` force-kills syz-manager well before
        // this backstop, so reaching it is genuinely exceptional.
        let vm_estimate = opts
            .vm_count
            .unwrap_or(2)
            .clamp(1, crate::syzkaller::MAX_VM_COUNT);
        let teardown_grace_secs =
            hf_engine::runner::SANDBOX_TIMEOUT_HEADROOM_SECS.saturating_mul(u64::from(vm_estimate));
        let inner_kill_after_secs = (teardown_grace_secs / 2).max(1);
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            // The inner `timeout` governs the campaign; give the sandbox deadline
            // a VM-scaled grace margin so it is only a teardown backstop.
            max_duration_secs: duration_secs.saturating_add(teardown_grace_secs),
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        // Cross-line state for the streaming callback.
        let peak_edges = AtomicU64::new(0);
        let last_execs = AtomicU64::new(0);
        let peak_crashes = AtomicU64::new(0);
        // Previous (sample time, cumulative execs) for deriving an exec *rate*
        // from syzkaller's cumulative counter.
        let exec_rate_state = std::sync::Mutex::new(Option::<(std::time::Instant, u64)>::None);
        let on_line = |line: &str| {
            if let Some((cover, executed, crash_ct)) =
                hf_engine::progress::parse_syzkaller_status(line)
            {
                peak_edges.fetch_max(cover, Ordering::Relaxed);
                last_execs.store(executed, Ordering::Relaxed);
                let prev = peak_crashes.load(Ordering::Relaxed);
                if crash_ct > prev {
                    on_progress(FuzzProgress::CrashesFound(
                        u32::try_from(crash_ct - prev).unwrap_or(u32::MAX),
                    ));
                    peak_crashes.store(crash_ct, Ordering::Relaxed);
                }
                on_progress(FuzzProgress::EdgesCovered(cover));
                // syzkaller reports a cumulative execution count; convert it to a
                // per-second rate before emitting on the rate channel so the
                // throughput chart does not render a monotonically climbing total.
                if let Ok(mut guard) = exec_rate_state.lock() {
                    let now = std::time::Instant::now();
                    if let Some((prev_time, prev_execs)) = *guard {
                        let elapsed = now.duration_since(prev_time).as_secs_f64();
                        if elapsed > 0.0 && executed >= prev_execs {
                            let rate = (executed - prev_execs) as f64 / elapsed;
                            on_progress(FuzzProgress::ExecsPerSec(rate));
                        }
                    }
                    *guard = Some((now, executed));
                }
                on_progress(FuzzProgress::LogLine(line.to_owned()));
            } else if !line.trim().is_empty() {
                on_progress(FuzzProgress::LogLine(line.to_owned()));
            }
        };

        // Register the cancellation token so the UI Stop button (which fires
        // `cancel_all_runs`) and `cancel_run` can tear down a long KVM campaign.
        // `ActiveRunGuard` removes it again even if this future is aborted.
        let cancel = CancellationToken::new();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };
        let cmd = syzkaller_manager_command(
            crate::syzkaller::CONTAINER_MANAGER_CONFIG,
            duration_secs,
            inner_kill_after_secs,
        );
        let writable_monitor =
            crate::syzkaller::WritableBudgetMonitor::start(&stage, cancel.clone());
        let run_result = self
            .runtime
            .run_command_streaming_opts(&cmd, &workspace, &limits, &sandbox_opts, &cancel, &on_line)
            .await;
        // Always stop the monitor, but surface a genuine run failure (Docker
        // died, container setup error) ahead of the budget verdict: otherwise a
        // real failure that also happened to trip the scratch budget would be
        // reported as a generic budget error, hiding the root cause.
        let within_budget = writable_monitor.finish().await;
        let result = run_result?;
        if !within_budget {
            return Err(ClassifiedError::Sandbox(
                "syzkaller scratch/workdir exceeded its 4 GiB growth or 100000-entry budget"
                    .to_owned(),
            ));
        }

        // GNU `timeout` uses 124 when the requested campaign budget expires;
        // that is the normal bounded completion path. Any other non-zero exit
        // for a genuinely Completed process means the manager or its container
        // setup failed and must not be presented as a successful campaign.
        match result.termination {
            hf_core::runtime::CommandTermination::Completed
                if result.exit_code != 0 && result.exit_code != 124 =>
            {
                let detail = result.stderr.lines().last().unwrap_or("no error output");
                return Err(ClassifiedError::Sandbox(format!(
                    "syz-manager exited with {}: {detail}",
                    result.exit_code
                )));
            }
            hf_core::runtime::CommandTermination::TimedOut => {
                // The inner `timeout --kill-after` already bounds the campaign;
                // reaching the outer deadline means a slow multi-VM teardown, not
                // a failure. Streaming already captured the coverage/crash
                // metrics, so treat it as a bounded completion instead of
                // discarding the summary.
                log("syz-manager reached the sandbox teardown backstop; treating the streamed campaign as complete.");
            }
            _ => {}
        }

        // Lift crash reproducers and the corpus database out of the disposable
        // staging workdir before the stage guard drops (and deletes) it, so
        // found crashes reach retained evidence and the corpus can be reused.
        // Best-effort: a copy hiccup is logged, never a reason to discard a
        // valid campaign summary.
        if let Some(evidence_dir) = workspace
            .parent()
            .map(|parent| parent.join("evidence").join(run_id.to_string()))
        {
            let stage_root = workspace.clone();
            let evidence = tokio::task::spawn_blocking(move || {
                crate::syzkaller::retain_campaign_evidence(&stage_root, &evidence_dir)
            })
            .await
            .map_err(|error| {
                ClassifiedError::Internal(format!("join syzkaller evidence task: {error}"))
            })?;
            match evidence {
                Ok(Some(path)) => log(&format!(
                    "Retained syzkaller crash reproducers and corpus under {}.",
                    path.display()
                )),
                Ok(None) => {}
                Err(error) => log(&format!(
                    "Warning: could not retain syzkaller campaign evidence: {error}"
                )),
            }
        }

        if matches!(
            result.termination,
            hf_core::runtime::CommandTermination::Completed
                | hf_core::runtime::CommandTermination::TimedOut
        ) {
            on_progress(FuzzProgress::Done);
        }
        Ok(SyzkallerSummary {
            edges: peak_edges.load(Ordering::Relaxed),
            execs: last_execs.load(Ordering::Relaxed) as f64,
            crashes: peak_crashes.load(Ordering::Relaxed),
            exit_code: Some(result.exit_code),
            termination: Some(result.termination),
        })
    }
}

#[cfg(all(test, feature = "semgrep-enrichment"))]
mod semgrep_ranking_consumer_tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use chrono::Utc;
    use hf_storage::Store;

    use super::*;

    async fn semgrep_run_count(store: &Store) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM semgrep_enrichment_runs")
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn campaign_uses_overlay_only_for_implicit_target_selection() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("parser.c"),
            "int parse_complex(const unsigned char *data, int size) {\n\
             if (size > 2 && data[0] == 1) { return data[1]; }\n\
             return 0;\n\
             }\n\
             int parse_simple(const unsigned char *data, int size) {\n\
             return size > 0 ? data[0] : 0;\n\
             }\n",
        )
        .unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let inventory = hf_discovery::discover(&project, TargetLanguage::C)
            .await
            .unwrap();
        assert!(inventory.candidates.len() >= 2);
        let base_first = inventory.ranked()[0].clone();
        let boosted = inventory
            .ranked()
            .into_iter()
            .find(|candidate| candidate.id != base_first.id)
            .unwrap()
            .clone();
        assert!(base_first.fit_score < 1.0);
        let store = Arc::new(
            Store::connect(root.path().join("campaign.db"))
                .await
                .unwrap(),
        );
        store.save_inventory(&inventory, Utc::now()).await.unwrap();
        let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&store));
        service
            .semgrep_test_publish_inventory(&inventory, HashMap::from([(boosted.id, 0.2)]))
            .await
            .unwrap();
        let before = semgrep_run_count(&store).await;

        let implicit = service
            .run_campaign(
                &project,
                None,
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                1,
                1,
            )
            .await
            .unwrap_err()
            .to_string();
        let explicit = service
            .run_campaign(
                &project,
                Some(&base_first.symbol),
                EngineKind::LibFuzzer,
                TargetLanguage::C,
                1,
                1,
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            implicit.contains(&format!("'{}'", boosted.symbol)),
            "implicit target error did not name boosted candidate: {implicit}"
        );
        assert!(
            explicit.contains(&format!("'{}'", base_first.symbol)),
            "explicit target changed under overlay: {explicit}"
        );
        assert_eq!(semgrep_run_count(&store).await, before);
    }
}
