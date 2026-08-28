//! Campaign execution, replay, and cooperative cancellation.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzProgress, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::target::TargetLanguage;
use hf_guardrails::{Action, Decision};
use hf_storage::{AutoRevertEvent, RunKind, RunRecord, RunStatus};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::crash_inputs::is_regular_file;
use super::guards::{
    close_run_journal, ensure_run_journal_durable, ActiveRunGuard, PersistedRunGuard,
};
use super::harness_workspace::{
    build_workspace_dictionary, dict_llm_cache, harness_binary_name, read_dictionary_source_excerpt,
};
use super::output_budget::{monitor_run_output, run_artifacts_within_budget};
use super::project_identity::canonical_project_root;
use super::staging::{
    resolve_run_sandbox_image, retain_run_context, run_context_digests, run_sandbox_options,
    stage_run_artifacts, verify_run_artifacts, verify_staged_qualification, ReplayProvenance,
};
use super::workspace::{
    prepare_configured_workspace_root, workspace_dir, workspace_relative_record,
};
use super::{
    auto_revert_baseline_compatible, auto_revert_decision, ensure_workspace_directory,
    merge_run_discoveries, persist_terminal_run_evidence, resolve_fuzzing_run, syz_kvm_usable,
    syzkaller_manager_command, terminal_run_metrics, AutoRevertOutcome, CampaignOutcome,
    CoverageFeedback, LlmProviderBridge, RefineProposal, RunCancelOutcome, RunControlStatus,
    RunLifecycleStatus, RunSummary, ServiceContainer, SyzkallerRunOpts, SyzkallerSummary,
    TerminalRunMetrics,
};

impl ServiceContainer {
    /// Draft a targeted refined harness in response to a coverage plateau, as a
    /// proposal only. Returns `None` (no proposal) when refinement is not
    /// applicable: no LLM provider, no uncovered frontier (non-C target or full
    /// coverage), or the compile action is not already policy-allowed (so we
    /// never block a headless campaign on an approval prompt, nor compile
    /// without an Allow decision). The refined harness stays `Compiled`; the
    /// existing promotion gate keeps it from being auto-run.
    async fn propose_refine_on_plateau(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Option<RefineProposal> {
        self.provider_pool()?;
        if !matches!(
            self.guardrails.policy().evaluate(&Action::CompileHarness),
            Decision::Allow
        ) {
            return None;
        }
        // Populate the frontier cache once; `harness_refine` reuses it (same
        // signature) rather than re-running the expensive coverage pipeline.
        let frontier_locations = self.coverage_uncovered(project, target).await.len();
        if frontier_locations == 0 {
            return None;
        }
        // Two corrective passes is enough for a targeted re-draft; keep it small
        // so a plateau does not turn into a long repair loop.
        match self.harness_refine(project, target, engine, lang, 2).await {
            Ok(outcome) => Some(RefineProposal {
                frontier_locations,
                compiled: outcome.status == HarnessStatus::Compiled,
                note: format!(
                    "coverage plateaued; proposed a refined harness for {frontier_locations} \
                     uncovered location(s), left Compiled for human review"
                ),
            }),
            Err(error) => {
                tracing::warn!(%error, "coverage-plateau refine proposal failed");
                Some(RefineProposal {
                    frontier_locations,
                    compiled: false,
                    note: format!("coverage plateaued; refine proposal failed: {error}"),
                })
            }
        }
    }

    /// Evaluate the auto-revert policy for a just-finished run and, if it
    /// triggered, restore the most recent comparable (last-good) harness revision.
    ///
    /// The policy fires only when it is enabled and this run's harness revision
    /// differs from a comparable finished run for the same target *and* this
    /// run's peak edge coverage dropped by at least the configured percentage
    /// versus a prior run with the same target, engine, budget, resources,
    /// sanitizer, corpus location, environment, and engine arguments. The
    /// restore reuses [`Self::revert_harness_from_run`], so exact-artifact
    /// activation is HITL-gated exactly like a manual revert -- a denied approval
    /// simply leaves the harness unchanged. Returns the outcome only when the
    /// revert applied.
    async fn maybe_auto_revert(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        this_edges: u64,
        this_rev: Option<&str>,
    ) -> Option<AutoRevertOutcome> {
        let policy = match self.effective_auto_revert_policy(project).await {
            Ok(policy) => policy,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not read its effective policy");
                return None;
            }
        };
        if !policy.enabled {
            return None;
        }
        let store = self.store.as_ref()?;
        // Without a recorded revision we cannot attribute a change to a harness.
        let this_rev = this_rev.filter(|r| !r.is_empty())?;
        // The most recent comparable finished run for this same target, before
        // this one, that recorded edge coverage and a harness revision.
        let key = project.to_string_lossy().to_string();
        let mut runs = match store.list_runs(Some(&key)).await {
            Ok(runs) => runs,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not read comparable runs");
                return None;
            }
        };
        runs.sort_by_key(|r| std::cmp::Reverse(r.started_at));
        let this_run = runs.iter().find(|r| r.id == this_run_id).cloned()?;
        let this_config = this_run.config.as_ref()?;
        if this_run.status != RunStatus::Done || this_run.kind != RunKind::Campaign {
            return None;
        }
        let this_context = this_run
            .context_rev
            .as_deref()
            .filter(|value| !value.is_empty())?;
        // Resolve the target through the run's persisted harness rather than
        // re-discovering it as C. This keeps C++, Rust, and future language runs
        // eligible for the same rollback policy.
        let target_id = match self.run_target_id(store, &this_run).await {
            Ok(Some(target_id)) => target_id,
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(%error, "auto-revert could not resolve the current run target");
                return None;
            }
        };
        let mut prev = None;
        for r in runs {
            if r.id == this_run_id
                || r.status != RunStatus::Done
                || r.kind != RunKind::Campaign
                || r.edges.is_none()
                || r.harness_rev.is_none()
                || r.harness_rev.as_deref() == Some(this_rev)
                || r.context_rev.as_deref() != Some(this_context)
            {
                continue;
            }
            if r.started_at >= this_run.started_at {
                continue;
            }
            let Some(previous_config) = r.config.as_ref() else {
                continue;
            };
            if !auto_revert_baseline_compatible(previous_config, this_config) {
                continue;
            }
            let candidate_target = match self.run_target_id(store, &r).await {
                Ok(candidate_target) => candidate_target,
                Err(error) => {
                    tracing::warn!(%error, "auto-revert could not resolve a baseline run target");
                    return None;
                }
            };
            if candidate_target == Some(target_id) {
                prev = Some(r);
                break;
            }
        }
        let prev = prev?;
        let prev_rev = prev.harness_rev.clone().unwrap_or_default();
        let prev_edges = prev.edges.unwrap_or(0);
        let drop_pct = auto_revert_decision(
            &prev_rev,
            this_rev,
            prev_edges,
            this_edges,
            policy.threshold_pct,
        )?;

        let prev_id = prev.id.to_string();
        let outcome = |reverted: bool| AutoRevertOutcome {
            reverted_to_run: prev_id.clone(),
            from_rev: this_rev.to_owned(),
            to_rev: prev_rev.clone(),
            previous_edges: prev_edges,
            regressed_edges: this_edges,
            drop_pct,
            reverted,
        };

        // Notify-only: report the regression (journal + surfaced outcome) but do
        // not touch the harness. This is the safe default for headless/scheduled
        // campaigns, which run permissively and would otherwise mutate unattended.
        if policy.notify_only {
            let detail = format!(
                "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev}; comparable last-good {prev_rev} is run {prev_id} (notify-only, not restored)"
            );
            tracing::warn!("auto-revert (notify-only): {detail}");
            self.run_journal
                .note(this_run_id, "auto-revert-notify", &detail);
            let out = outcome(false);
            self.persist_auto_revert_event(project, target, this_run_id, &out)
                .await;
            return Some(out);
        }

        // Regression confirmed: restore the comparable baseline's harness. The
        // recompile is HITL-gated inside `harness_compile`; if approval is denied
        // the active canonical revision and binary remain unchanged.
        match self.revert_harness_from_run(&prev_id).await {
            Ok(_) => {
                let detail = format!(
                    "coverage dropped {drop_pct:.1}% ({this_edges} < {prev_edges} edges) after harness {this_rev} -> restored comparable baseline {prev_rev} from run {prev_id}"
                );
                tracing::warn!("auto-revert: {detail}");
                self.run_journal.note(this_run_id, "auto-revert", &detail);
                let out = outcome(true);
                self.persist_auto_revert_event(project, target, this_run_id, &out)
                    .await;
                Some(out)
            }
            Err(e) => {
                tracing::warn!("auto-revert declined or failed: {e}");
                None
            }
        }
    }

    /// Persist an auto-revert firing to the durable audit trail (best-effort).
    async fn persist_auto_revert_event(
        &self,
        project: &Path,
        target: &str,
        this_run_id: Uuid,
        out: &AutoRevertOutcome,
    ) {
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let ev = AutoRevertEvent {
            id: Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            project_root: project.to_string_lossy().to_string(),
            target: target.to_owned(),
            run_id: this_run_id.to_string(),
            from_rev: out.from_rev.clone(),
            to_rev: out.to_rev.clone(),
            previous_edges: out.previous_edges,
            regressed_edges: out.regressed_edges,
            drop_pct: out.drop_pct,
            reverted: out.reverted,
        };
        if let Err(e) = store.record_auto_revert_event(&ev).await {
            tracing::warn!("failed to record auto-revert event: {e}");
        }
    }

    /// Build the engine dictionary flags for a run: extract the static
    /// dictionary from the target sources, augment it with LLM-proposed tokens,
    /// and return the engine-specific `-dict`/`-x`/`-w` args (empty when no
    /// dictionary was built).
    async fn build_run_dictionary_args(
        &self,
        project: &Path,
        target: &str,
        workspace: &Path,
        engine: EngineKind,
    ) -> Vec<String> {
        let dict_name = "fuzzer.dict";
        let Some(dict_path) = build_workspace_dictionary(workspace, dict_name) else {
            return Vec::new();
        };
        // Best-effort, provider-gated, cached per source version; a failure
        // leaves the static dictionary in place.
        self.augment_dictionary_llm(project, target, workspace, &dict_path)
            .await;
        hf_engine::dict::dict_run_args(engine, &format!("/work/{dict_name}"))
    }

    /// Merge LLM-proposed dictionary tokens into the static dictionary at
    /// `dict_path`: format keywords / magic sequences the lexical scan may miss.
    /// No-op without a provider or source. The LLM tokens are cached per target
    /// by the static dictionary's hash, so a repeated run on unchanged sources
    /// makes no LLM call; failures leave the static dictionary intact.
    async fn augment_dictionary_llm(
        &self,
        project: &Path,
        target: &str,
        workspace: &Path,
        dict_path: &Path,
    ) {
        use hf_core::provider::{ChatRequest, LlmProvider as _};
        use hf_core::types::Message;
        use std::hash::{Hash as _, Hasher as _};

        let Some(pool) = self.provider_pool() else {
            return;
        };
        let Ok(static_text) = std::fs::read_to_string(dict_path) else {
            return;
        };
        let mut tokens = hf_engine::dict::parse_dict(&static_text);
        let key = format!("{}::{target}", project.display());
        let signature = {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            static_text.hash(&mut hasher);
            hasher.finish()
        };
        let cached = dict_llm_cache()
            .lock()
            .ok()
            .and_then(|map| map.get(&key).cloned())
            .filter(|(cached_sig, _)| *cached_sig == signature);
        let llm_tokens = if let Some((_, cached_tokens)) = cached {
            cached_tokens
        } else {
            let excerpt = read_dictionary_source_excerpt(workspace, 8192);
            if excerpt.trim().is_empty() {
                return;
            }
            let prompt = hf_prompt::render_dictionary_prompt(target, &excerpt);
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "dict_gen");
            let req = ChatRequest::from_messages(vec![Message::user(prompt)]);
            let fresh = match provider.chat_completion(&req).await {
                Ok(resp) => hf_engine::dict::parse_dict(resp.text()),
                Err(e) => {
                    tracing::warn!("LLM dictionary generation for '{target}' failed: {e}");
                    return;
                }
            };
            if let Ok(mut map) = dict_llm_cache().lock() {
                map.insert(key, (signature, fresh.clone()));
            }
            fresh
        };
        if llm_tokens.is_empty() {
            return;
        }
        let mut seen: std::collections::HashSet<Vec<u8>> = tokens.iter().cloned().collect();
        let mut added = 0usize;
        for token in llm_tokens {
            if seen.insert(token.clone()) {
                tokens.push(token);
                added += 1;
            }
        }
        if added == 0 {
            return;
        }
        if let Err(e) = std::fs::write(dict_path, hf_engine::dict::render_dict(&tokens)) {
            tracing::warn!("failed to write augmented dictionary: {e}");
        } else {
            tracing::info!("merged {added} LLM-proposed dictionary token(s) for '{target}'");
        }
    }

    /// Run a fuzzer to termination and notify event-driven schedules about the
    /// outcome: `run.completed` on success (cancellation included), `run.failed`
    /// when a started run terminates with a failure. Errors before the run
    /// becomes durable are rejections, not run failures, and emit nothing.
    async fn run_fuzzer_with_started(
        &self,
        project: &Path,
        target: &str,
        resolved: crate::config::ResolvedFuzzingRun,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
        on_started: &(dyn Fn(Uuid) + Send + Sync),
        replay: Option<ReplayProvenance>,
    ) -> Result<RunSummary, ClassifiedError> {
        let engine = resolved.engine;
        // Capture the run id once the run is durable so a failure event can
        // name it.
        let started_run = std::sync::Arc::new(std::sync::Mutex::new(None));
        let captured = std::sync::Arc::clone(&started_run);
        let tracked_started = move |run_id: Uuid| {
            if let Ok(mut slot) = captured.lock() {
                *slot = Some(run_id);
            }
            on_started(run_id);
        };
        let result = self
            .run_fuzzer_with_started_inner(
                project,
                target,
                resolved,
                on_progress,
                &tracked_started,
                replay,
            )
            .await;
        match &result {
            Ok(summary) => {
                self.emit_scheduler_event(
                    crate::scheduler::EVENT_RUN_COMPLETED,
                    serde_json::json!({
                        "project": project.display().to_string(),
                        "target": target,
                        "run_id": summary.run_id.to_string(),
                        "engine": engine.as_str(),
                        "edges": summary.edges,
                        "execs": summary.execs,
                        "crashes": summary.crashes,
                        "termination": summary.termination,
                    }),
                )
                .await;
            }
            Err(error) => {
                let run_id = started_run.lock().ok().and_then(|slot| *slot);
                if let Some(run_id) = run_id {
                    self.emit_scheduler_event(
                        crate::scheduler::EVENT_RUN_FAILED,
                        serde_json::json!({
                            "project": project.display().to_string(),
                            "target": target,
                            "run_id": run_id.to_string(),
                            "engine": engine.as_str(),
                            "error": error.to_string(),
                        }),
                    )
                    .await;
                }
            }
        }
        result
    }

    async fn run_fuzzer_with_started_inner(
        &self,
        project: &Path,
        target: &str,
        resolved: crate::config::ResolvedFuzzingRun,
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
        on_started: &(dyn Fn(Uuid) + Send + Sync),
        replay: Option<ReplayProvenance>,
    ) -> Result<RunSummary, ClassifiedError> {
        const MAX_RAW_COVERAGE_SAMPLES: usize = 10_000;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();

        let engine = resolved.engine;
        let duration_secs = resolved.duration_secs;

        let qualified = self.active_harness(project, target, engine).await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(format!(
                "active harness '{target}' is {:?}; run smoke qualification and explicitly promote it before starting a full campaign",
                qualified.status
            )));
        }
        self.verify_harness_qualification(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: format!("{engine:?}"),
                duration_secs,
            },
            "run_fuzzer",
            Some(project),
        )
        .await?;
        ensure_run_journal_durable(&self.run_journal)?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = ensure_workspace_directory(&workspace, Path::new("corpus"))?;

        let bin = harness_binary_name(target);
        let binary = workspace.join(&bin);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{bin}' not found -- compile the harness first."
            )));
        }

        // Build a dictionary from the target sources (statically extracted, then
        // LLM-augmented) and point the engine at it -- one of the cheapest
        // coverage multipliers; absent literals just yield no flag.
        let extra_args = self
            .build_run_dictionary_args(project, target, &workspace, engine)
            .await;

        let mut run_cfg = FuzzRunConfig {
            // Link the run to the target's compiled harness so the target-scoped
            // workbench dashboard can attribute it. A throwaway id here would
            // leave every run unattributable (dashboard shows zero runs).
            harness_id: qualified.id,
            engine,
            duration: Some(std::time::Duration::from_secs(duration_secs)),
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            seed_corpus: Some(corpus_dir.clone()),
            sanitizer: hf_core::target::Sanitizer::Address,
            env: Vec::new(),
            extra_args,
            seed: None,
            replay_of: None,
        };
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("fuzz runs require the persistent service store".to_owned())
        })?;
        let mut run_record = RunRecord::new(
            project.to_string_lossy().to_string(),
            engine,
            None,
            Utc::now(),
        );
        // Every run pins its RNG seed in the persisted config. A replay
        // re-executes with the original run's seed and links back to it; a
        // fresh run derives its seed deterministically from its own id, so
        // every run is reproducible by default.
        match replay {
            Some(provenance) => {
                run_cfg.seed = Some(provenance.seed);
                run_cfg.replay_of = Some(provenance.original_run_id);
            }
            None => run_cfg.seed = Some(hf_engine::seed::derive_run_seed(run_record.id)),
        }
        run_record.config = Some(run_cfg.clone());
        let sandbox_image = resolve_run_sandbox_image(self.runtime.as_ref()).await?;
        let context = run_context_digests(&workspace, sandbox_image.sha256())?;
        retain_run_context(&mut run_record, context);
        let artifacts = stage_run_artifacts(&workspace, run_record.id, &qualified.source, &binary)?;
        if let Err(error) = verify_staged_qualification(&qualified, &artifacts) {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(error);
        }
        if let Err(error) = verify_run_artifacts(&artifacts) {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(error);
        }
        let sandbox = run_sandbox_options(&artifacts, Some(sandbox_image.reference().to_owned()));
        run_record.status = RunStatus::Running;
        run_record.harness_rev = Some(artifacts.source_sha256.clone());
        run_record.binary_rev = Some(artifacts.binary_sha256.clone());
        run_record.evidence_dir = Some(workspace_relative_record(&artifacts.output_relative));
        let run_id = run_record.id;
        if let Err(error) = store.insert_run(&run_record).await {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        self.run_journal.open_run(run_id, project, target, engine);
        if let Err(error) = ensure_run_journal_durable(&self.run_journal) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            return Err(error);
        }
        let mut persisted_run = PersistedRunGuard::new(
            Arc::clone(store),
            Some(Arc::clone(&self.run_journal)),
            run_id,
        );
        if let Err(error) = store
            .set_run_harness_source(run_record.id, &qualified.source)
            .await
        {
            let failure_recorded = store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            if failure_recorded.is_ok() {
                self.run_journal.close_run(run_id);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }

        // Register a cancellation token so `cancel_run(run_id)` can stop this
        // run cooperatively. `ActiveRunGuard` removes it again when this scope
        // ends -- crucially, even if the `run_fuzzer` future is dropped/aborted
        // (e.g. wrapped in a `timeout`) rather than returning normally. A plain
        // post-await removal would leak the entry on abort, leaving a phantom
        // run that `active_run_ids` reports and `cancel_run` can never clear.
        let cancel = CancellationToken::new();
        if let Ok(mut runs) = self.active_runs.lock() {
            runs.insert(run_id, cancel.clone());
        }
        let _active_run_guard = ActiveRunGuard {
            active_runs: Arc::clone(&self.active_runs),
            run_id,
        };
        // The run is durable and cancellable at this point. Non-blocking
        // presentation transports may now return the exact UUID; no engine
        // process has been launched yet.
        on_started(run_id);

        let runner = hf_engine::runner::EngineRunner::new();
        // Watch edge readings for stagnation while forwarding every event.
        let feedback = CoverageFeedback::new(
            run_id,
            crate::config::coverage_stagnation_policy(),
            on_progress,
        );
        // Accumulate an intra-run coverage/throughput time series live, so the
        // run's coverage curve can be charted later. Each fuzzer stats line emits
        // an EdgesCovered then an ExecsPerSec event; pair them and stamp the
        // elapsed time.
        let series: std::sync::Arc<std::sync::Mutex<Vec<(f64, u64, f64)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let last_edges = std::sync::atomic::AtomicU64::new(0);
        let run_started = std::time::Instant::now();
        let series_w = std::sync::Arc::clone(&series);
        let watched = |p: FuzzProgress| {
            use std::sync::atomic::Ordering::Relaxed;
            match &p {
                FuzzProgress::EdgesCovered(v) => {
                    feedback.on_edges(*v);
                    last_edges.store(*v, Relaxed);
                }
                FuzzProgress::ExecsPerSec(v) => {
                    let t = run_started.elapsed().as_secs_f64();
                    let e = last_edges.load(Relaxed);
                    if let Ok(mut s) = series_w.lock() {
                        if s.len() < MAX_RAW_COVERAGE_SAMPLES {
                            s.push((t, e, *v));
                        } else if let Some(last) = s.last_mut() {
                            *last = (t, e, *v);
                        }
                    }
                }
                _ => {}
            }
            on_progress(p);
        };
        let output_monitor_stop = CancellationToken::new();
        let output_budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_monitor = tokio::spawn(monitor_run_output(
            artifacts.output_host.clone(),
            artifacts.corpus_host.clone(),
            64 * 1024 * 1024,
            cancel.clone(),
            output_monitor_stop.clone(),
            Arc::clone(&output_budget_exceeded),
        ));
        // Stream progress live: `on_progress` fires for each output line and
        // stat as the fuzzer runs, not post-hoc.
        let run_result = runner
            .run_streaming_opts(
                engine,
                &run_cfg,
                &artifacts.binary_container,
                &artifacts.corpus_container,
                &artifacts.output_container,
                self.runtime.as_ref(),
                &workspace,
                &sandbox,
                &cancel,
                &watched,
            )
            .await;
        output_monitor_stop.cancel();
        let _ = output_monitor.await;
        if !run_artifacts_within_budget(&artifacts, 64 * 1024 * 1024).await {
            output_budget_exceeded.store(true, std::sync::atomic::Ordering::Release);
        }
        if output_budget_exceeded.load(std::sync::atomic::Ordering::Acquire) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
            self.run_journal.close_run(run_id);
            return Err(ClassifiedError::Sandbox(
                "fuzz run corpus/output exceeded its retained-evidence budget".to_owned(),
            ));
        }
        let result = match run_result {
            Ok(result) => result,
            Err(error) => {
                let status_update = store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await;
                status_update.map_err(|e| ClassifiedError::Storage(e.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        // A run the runtime force-stopped -- cancelled, or killed at the sandbox
        // wall-clock cap -- measured real coverage but did not run its full
        // budget. Its evidence is persisted exactly like a clean run's; what it
        // is not is a fair regression baseline.
        let truncated = result.termination != hf_core::runtime::CommandTermination::Completed;

        // Keep the retained corpus immutable throughout execution. Engines
        // write only to this run's disposable snapshot/output; after the
        // sandbox exits, bounded corpus APIs preflight those discoveries and
        // atomically merge unique inputs into the live corpus.
        let retained = match merge_run_discoveries(engine, &artifacts, &corpus_dir).await {
            Ok(corpus) => corpus,
            Err(error) => {
                store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await
                    .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        // persist_corpus derives the target from the explicit `qualified.target_id`
        // argument and `retained.entries`, never `retained.target_id`, so no
        // identity copy is needed here.
        if let Err(error) = self.persist_corpus(qualified.target_id, &retained).await {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            self.run_journal.close_run(run_id);
            return Err(error);
        }

        // Summarize from the parsed events. Live streaming already forwarded
        // them to `on_progress`, so do not re-emit here.
        let metrics = match terminal_run_metrics(engine, &artifacts, &result).await {
            Ok(metrics) => metrics,
            Err(error) => {
                store
                    .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await
                    .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
                self.run_journal.close_run(run_id);
                return Err(error);
            }
        };
        if let Err(error) =
            persist_terminal_run_evidence(store, run_record.id, &metrics, &series).await
        {
            let _ = store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            self.run_journal.close_run(run_id);
            return Err(error);
        }
        let TerminalRunMetrics {
            edges,
            execs,
            crashes,
        } = metrics;
        // A run becomes terminal only after its summary evidence is durable.
        // This prevents a `Done` record whose stats or coverage curve were lost.
        let status = match result.termination {
            hf_core::runtime::CommandTermination::Cancelled => RunStatus::Cancelled,
            // The sandbox cap is a backstop over the fuzzer's own self-limit, and
            // nothing enforces that limit but the fuzzer itself, so reaching the
            // cap can mean a slow shutdown or a wedged harness. The evidence
            // above is kept either way; the status keeps the overrun visible
            // rather than reporting a campaign that never finished as `Done`.
            hf_core::runtime::CommandTermination::TimedOut => RunStatus::Failed,
            hf_core::runtime::CommandTermination::Completed => RunStatus::Done,
        };
        let status_update = store
            .set_run_status(run_record.id, status, Some(Utc::now()))
            .await;
        status_update.map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        if let Err(error) = close_run_journal(&self.run_journal, run_id) {
            store
                .set_run_status(run_record.id, RunStatus::Failed, Some(Utc::now()))
                .await
                .map_err(|status_error| ClassifiedError::Storage(status_error.to_string()))?;
            persisted_run.disarm();
            return Err(error);
        }
        persisted_run.disarm();
        // Auto-revert policy: if this run's harness revision regressed coverage
        // past the threshold versus the latest comparable run for this target,
        // restore that last-good revision (HITL-gated recompile). Skipped for
        // truncated runs, whose partial coverage is not a fair comparison.
        let auto_revert = if truncated {
            None
        } else {
            self.maybe_auto_revert(
                project,
                target,
                run_id,
                edges,
                run_record.harness_rev.as_deref(),
            )
            .await
        };
        Ok(RunSummary {
            run_id,
            edges,
            execs,
            crashes,
            termination: result.termination,
            stagnation: feedback.proposal(),
            auto_revert,
        })
    }

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

#[cfg(all(test, unix, feature = "semgrep-enrichment"))]
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
