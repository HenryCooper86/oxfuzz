//! Harness authoring, sandbox qualification, and promotion.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessDraft, HarnessStatus};
use hf_core::target::{Sanitizer, TargetCandidate, TargetLanguage};
use hf_guardrails::Action;
use hf_storage::{RunKind, RunRecord, RunStatus};
use uuid::Uuid;

use super::coverage_cache::frontier_refine_lines;
use super::crash_inputs::is_regular_file;
use super::guards::{ensure_run_journal_durable, PersistedRunGuard};
use super::harness_workspace::{
    copy_project_sources, generate_target_seeds, harness_binary_name, read_current_harness_source,
    write_current_harness_id, write_current_harness_source,
};
use super::output_budget::{
    output_budget_status, OutputBudget, MAX_RUN_OUTPUT_BYTES, MAX_RUN_OUTPUT_ENTRIES,
};
use super::project_identity::{
    canonical_project_root, select_target_candidate, stored_project_matches,
};
use super::staging::{
    qualification_evidence, resolve_run_sandbox_image, retain_run_context, run_context_digests,
    stage_run_artifacts, verify_run_artifacts,
};
use super::workspace::{
    prepare_configured_workspace_root, workspace_dir, workspace_relative_record,
};
use super::{
    heuristic_draft, require_fuzzing_harness_engine, resolve_internal_run, CompileOutcome,
    HarnessGenOutcome, LlmProviderBridge, SeedEntry, ServiceContainer, SMOKE_FUZZ_SECS,
};

impl ServiceContainer {
    /// Resolve a target symbol to its discovered candidate id.
    ///
    /// Unknown symbols are rejected rather than being attached to the nil UUID.
    /// Shared by harness compilation and triage so persisted records key off the
    /// same canonical project and target identity.
    async fn resolve_target_id(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError> {
        let project = canonical_project_root(project)?;
        if let Some(store) = &self.store {
            let targets = store.list_all_targets().await?;
            let project_targets: Vec<TargetCandidate> = targets
                .into_iter()
                .filter(|candidate| {
                    stored_project_matches(&candidate.project_root, &project)
                        && candidate.language == lang
                })
                .collect();
            if let Some(candidate) = select_target_candidate(&project_targets, target)? {
                return Ok(candidate.id);
            }
        }
        let inventory = self.discover(&project, lang).await?;
        select_target_candidate(&inventory.candidates, target)?
            .map(|c| c.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))
    }

    /// Draft the harness source for a candidate: LLM-authored when a provider is
    /// configured, otherwise the heuristic template. Never fails -- an LLM error
    /// degrades to the heuristic draft so generation can proceed.
    async fn draft_harness_source(
        &self,
        project: &Path,
        candidate: &TargetCandidate,
        engine: EngineKind,
    ) -> String {
        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            let related = crate::knowledge::harness_related_context(project, candidate);
            match hf_harness::draft_with_context(candidate, engine, &related, Box::new(provider))
                .await
            {
                Ok(draft) => return draft.source,
                Err(e) => tracing::warn!(
                    "LLM harness draft for '{}' failed ({e}); using heuristic draft",
                    candidate.symbol
                ),
            }
        }
        heuristic_draft(candidate, engine).source
    }

    /// Compile `initial_source` in the sandbox, and on a compile failure feed the
    /// diagnostics back to the LLM for up to `max_repairs` corrective passes.
    /// Shared by harness generation and coverage-guided refinement.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Harness` if the harness still fails to build
    /// after `max_repairs` attempts, or an infrastructure error from the sandbox.
    async fn compile_source_with_repair(
        &self,
        candidate: &TargetCandidate,
        engine: EngineKind,
        lang: TargetLanguage,
        workspace: &Path,
        initial_source: String,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let target = &candidate.symbol;
        let mut source = initial_source;
        let mut repairs_used = 0usize;
        let mut last_diagnostics = String::new();

        loop {
            let mut build_cmd =
                hf_harness::build_command(engine, lang, &harness_binary_name(target));
            build_cmd.output = PathBuf::from(harness_binary_name(target));
            let harness = Harness {
                id: Uuid::new_v4(),
                target_id: candidate.id,
                engine,
                source: source.clone(),
                language: lang,
                build_cmd,
                sanitizer: Sanitizer::Address,
                status: HarnessStatus::Draft,
                smoke_run: None,
            };
            match hf_harness::try_compile(harness, self.runtime.as_ref(), workspace).await? {
                hf_harness::CompileResult::Ok(compiled) => {
                    if let Some(store) = &self.store {
                        store
                            .upsert_harness(&compiled)
                            .await
                            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
                    }
                    write_current_harness_source(workspace, &compiled.source)?;
                    // Point `harness.active` at the freshly-compiled harness, as
                    // `harness_compile` does. Without this, a repair/refine that
                    // rewrites the source leaves the marker on the previous id, so
                    // `active_harness` later reads a stale id whose source no
                    // longer matches and hard-errors ("compile it again") even
                    // though the refined harness built cleanly.
                    write_current_harness_id(workspace, compiled.id)?;
                    let binary_name = compiled
                        .build_cmd
                        .output
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(target)
                        .to_string();
                    return Ok(HarnessGenOutcome {
                        status: compiled.status,
                        binary_name,
                        workspace: workspace.to_path_buf(),
                        repairs_used,
                    });
                }
                hf_harness::CompileResult::Failed(failure) => {
                    last_diagnostics = failure.diagnostics();
                    if repairs_used >= max_repairs {
                        break;
                    }
                    let Some(pool) = self.provider_pool() else {
                        // No LLM to repair with; the first failure is terminal.
                        break;
                    };
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "harness_repair");
                    match hf_harness::repair(
                        candidate,
                        engine,
                        &source,
                        &last_diagnostics,
                        Box::new(provider),
                    )
                    .await
                    {
                        Ok(draft) => {
                            source = draft.source;
                            repairs_used += 1;
                        }
                        Err(e) => {
                            tracing::warn!("harness repair for '{target}' failed: {e}");
                            break;
                        }
                    }
                }
            }
        }

        let diag: String = last_diagnostics.chars().take(600).collect();
        Err(ClassifiedError::Harness(format!(
            "harness for '{target}' failed to build after {repairs_used} repair attempt(s): {diag}"
        )))
    }

    /// Generated harnesses that need human review or promotion.
    pub async fn harness_review_queue(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> Result<Vec<crate::workbench::HarnessReviewItem>, ClassifiedError> {
        crate::workbench::harness_review_queue(self.store.as_deref(), project, target).await
    }

    /// Draft a harness for a target using the LLM provider pool.
    ///
    /// Falls back to a heuristic template when no provider is configured so
    /// the GUI still produces a draft without an API key.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the LLM call fails or the target is not
    /// found.
    pub async fn harness_draft(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<HarnessDraft, ClassifiedError> {
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::DraftHarness, "harness_draft", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inv.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        if let Some(pool) = self.provider_pool() {
            let provider = LlmProviderBridge::new(pool)
                .with_diagnostics(Arc::clone(&self.diagnostics), "harness_draft");
            // Augment the prompt with related project context when this
            // project has been indexed; empty on any failure, which renders
            // the un-augmented prompt.
            let related = crate::knowledge::harness_related_context(project, &candidate);
            match hf_harness::draft_with_context(&candidate, engine, &related, Box::new(provider))
                .await
            {
                Ok(draft) => Ok(draft),
                // The LLM is configured but the call failed (provider down, auth,
                // bad model, network). Degrade to the heuristic draft so the
                // pipeline still produces a usable harness instead of dead-ending
                // on a red error; the warning makes the LLM failure visible.
                Err(e) => {
                    tracing::warn!(
                        "LLM harness draft for '{target}' failed ({e}); \
                         falling back to heuristic draft"
                    );
                    Ok(heuristic_draft(&candidate, engine))
                }
            }
        } else {
            // No LLM configured: generate a heuristic draft so the GUI still
            // produces something useful.
            Ok(heuristic_draft(&candidate, engine))
        }
    }

    /// Compile a harness in the sandbox via `hf-runtime`.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the build command fails.
    pub async fn harness_compile(
        &self,
        source: String,
        project: &Path,
        engine: EngineKind,
        target: &str,
        lang: TargetLanguage,
    ) -> Result<CompileOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_compile", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let build_cmd = hf_harness::build_command(engine, lang, &harness_binary_name(target));
        let harness = Harness {
            id: Uuid::new_v4(),
            target_id: self.resolve_target_id(project, target, lang).await?,
            engine,
            source,
            language: lang,
            build_cmd,
            sanitizer: hf_core::target::Sanitizer::Address,
            status: HarnessStatus::Draft,
            smoke_run: None,
        };
        let compiled = hf_harness::compile(harness, self.runtime.as_ref(), &workspace).await?;
        // Persist the compiled harness so it survives restarts and the
        // Harness/list views can show it before pointing the active marker at
        // the record. Qualification is safety-critical, so a configured store
        // must durably accept the record.
        if let Some(store) = &self.store {
            store
                .upsert_harness(&compiled)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        }
        write_current_harness_source(&workspace, &compiled.source)?;
        write_current_harness_id(&workspace, compiled.id)?;
        Ok(CompileOutcome {
            status: compiled.status,
            binary_name: compiled
                .build_cmd
                .output
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(target)
                .to_string(),
            workspace,
        })
    }

    /// Generate a harness end to end with automatic repair: draft -> compile,
    /// and on a compile failure feed the diagnostics back to the LLM for up to
    /// `max_repairs` corrective passes before giving up.
    ///
    /// This is the recommended entry point over calling `harness_draft` +
    /// `harness_compile` separately: a large fraction of first-draft harnesses
    /// fail to compile, and abandoning the target on the first failure wastes a
    /// discovered, potentially high-value target. Repair recovers many of them.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown,
    /// `ClassifiedError::Harness` if the harness still fails to build after
    /// `max_repairs` attempts, or an infrastructure error from the sandbox.
    pub async fn harness_generate(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_generate", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inv.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        std::fs::create_dir_all(&workspace)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir: {e}")))?;
        copy_project_sources(project, &workspace);

        let source = self.draft_harness_source(project, &candidate, engine).await;
        self.compile_source_with_repair(&candidate, engine, lang, &workspace, source, max_repairs)
            .await
    }

    /// Coverage-guided harness refinement: when coverage has stagnated, ask the
    /// LLM to reshape the current harness so the fuzzer reaches the target's
    /// still-uncovered reachable functions, then compile the result (with the
    /// same auto-repair loop as generation).
    ///
    /// Recomputes coverage to determine which reachable functions are still
    /// uncovered, so the model gets a concrete goal rather than "improve this".
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` if the target is unknown or has no
    /// current harness, `ClassifiedError::Provider` if no LLM is configured, or
    /// an error from the refine/compile steps.
    pub async fn harness_refine(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
        max_repairs: usize,
    ) -> Result<HarnessGenOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        require_fuzzing_harness_engine(engine, lang)?;
        self.authorize_recorded(Action::CompileHarness, "harness_refine", Some(project))
            .await?;
        let inv = self.discover(project, lang).await?;
        let candidate = select_target_candidate(&inv.candidates, target)?
            .ok_or_else(|| ClassifiedError::Validation(format!("target '{target}' not found")))?
            .clone();

        let workspace = workspace_dir(project, target);
        let current_source = read_current_harness_source(&workspace).ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "no current harness for '{target}' to refine; generate one first"
            ))
        })?;

        // Prefer the dynamic llvm-cov frontier (uncovered code with file:line
        // locations) so the refine prompt points the LLM at concrete gaps. Fall
        // back to the static reachable-minus-covered names when no source
        // coverage frontier is available (non-C targets, tooling missing) --
        // both accessors early-return without running the pipeline for a
        // non-C target, so the fallback costs nothing extra.
        let frontier = self.coverage_uncovered(project, target).await;
        let uncovered: Vec<String> = if frontier.is_empty() {
            let covered: std::collections::HashSet<String> = self
                .coverage_functions(project, target)
                .await
                .into_iter()
                .collect();
            candidate
                .reachable_functions
                .iter()
                .filter(|f| !covered.contains(*f))
                .cloned()
                .collect()
        } else {
            frontier_refine_lines(&candidate.reachable_functions, &frontier)
        };

        let pool = self.provider_pool().ok_or_else(|| {
            ClassifiedError::Provider("no LLM provider configured for refinement".to_owned())
        })?;
        let provider = LlmProviderBridge::new(pool)
            .with_diagnostics(Arc::clone(&self.diagnostics), "harness_refine");
        let refined = hf_harness::refine(
            &candidate,
            engine,
            &current_source,
            &uncovered,
            Box::new(provider),
        )
        .await?;

        self.compile_source_with_repair(
            &candidate,
            engine,
            lang,
            &workspace,
            refined.source,
            max_repairs,
        )
        .await
    }

    /// Run a short smoke fuzz (60 seconds, clamped to the configured campaign
    /// ceiling) on the active, persisted harness revision and durably record
    /// its qualification evidence.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the binary is missing or the smoke run
    /// finds zero execs/sec.
    pub async fn harness_smoke(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<crate::verification::SmokeOutcome, ClassifiedError> {
        let resolved = resolve_internal_run(engine, SMOKE_FUZZ_SECS)?;
        if !engine.supports_language(lang) {
            return Err(ClassifiedError::Validation(format!(
                "fuzzing engine '{}' does not support {lang:?} harnesses",
                engine.as_str()
            )));
        }
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        self.authorize_recorded(Action::RunHarness, "harness_smoke", Some(project))
            .await?;
        let workspace = workspace_dir(project, target);
        let harness = self.active_harness(project, target, engine).await?;
        if harness.language != lang {
            return Err(ClassifiedError::Validation(format!(
                "active harness language is {:?}, not {lang:?}",
                harness.language
            )));
        }
        if !matches!(
            harness.status,
            HarnessStatus::Compiled | HarnessStatus::SmokePassed | HarnessStatus::Promoted
        ) {
            return Err(ClassifiedError::Validation(format!(
                "only a compiled harness can be smoke-qualified; active status is {:?}",
                harness.status
            )));
        }
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness qualification requires the persistent service store".to_owned(),
            )
        })?;
        let binary_name = harness_binary_name(target);
        let binary = workspace.join(&binary_name);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "Compiled harness '{binary_name}' not found -- compile the harness first."
            )));
        }

        // Allocate the run identity before execution so its immutable inputs and
        // every finding are owned by one durable evidence directory.
        let mut smoke_config = FuzzRunConfig {
            harness_id: harness.id,
            engine: resolved.engine,
            duration: Some(std::time::Duration::from_secs(resolved.duration_secs)),
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            seed_corpus: Some(workspace.join("corpus")),
            sanitizer: harness.sanitizer,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
        };
        let mut smoke_record = RunRecord::new(
            project.to_string_lossy().to_string(),
            engine,
            None,
            Utc::now(),
        );
        // Persist the deterministic seed with the run config so the smoke run
        // is reproducible, exactly like a campaign run.
        smoke_config.seed = Some(hf_engine::seed::derive_run_seed(smoke_record.id));
        smoke_record.config = Some(smoke_config.clone());
        smoke_record.kind = RunKind::Smoke;
        let sandbox_image = resolve_run_sandbox_image(self.runtime.as_ref()).await?;
        let context = run_context_digests(&workspace, sandbox_image.sha256())?;
        retain_run_context(&mut smoke_record, context);
        let artifacts = stage_run_artifacts(&workspace, smoke_record.id, &harness.source, &binary)?;
        smoke_record.status = RunStatus::Running;
        smoke_record.harness_rev = Some(artifacts.source_sha256.clone());
        smoke_record.binary_rev = Some(artifacts.binary_sha256.clone());
        smoke_record.evidence_dir = Some(workspace_relative_record(&artifacts.output_relative));
        if let Err(error) = store.insert_run(&smoke_record).await {
            if let Some(run_root) = artifacts.output_host.parent() {
                let _ = std::fs::remove_dir_all(run_root);
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        // Journal the smoke run like a campaign run. Without this, a process
        // kill/crash during the ~60s smoke window leaves a permanent `Running`
        // row: clear_all_runs and delete_run both reject a run with no crash
        // evidence, so that orphan makes clear_all_runs fail forever and cannot
        // be removed via the service API. Journaling lets bootstrap reconcile it
        // to Failed on the next launch, exactly like a full run.
        self.run_journal
            .open_run(smoke_record.id, project, target, engine);
        if let Err(error) = ensure_run_journal_durable(&self.run_journal) {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(error);
        }
        let mut persisted_run = PersistedRunGuard::new(
            Arc::clone(store),
            Some(Arc::clone(&self.run_journal)),
            smoke_record.id,
        );
        if let Err(error) = store
            .set_run_harness_source(smoke_record.id, &harness.source)
            .await
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Storage(error.to_string()));
        }

        if let Err(error) = verify_run_artifacts(&artifacts) {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(error);
        }
        let mut staged_harness = harness;
        staged_harness.build_cmd.output = artifacts.binary_host.clone();
        let mut smoked = match hf_harness::smoke_fuzz_in_paths_with_config_and_sandbox_image(
            staged_harness,
            self.runtime.as_ref(),
            &workspace,
            &artifacts.corpus_relative,
            &artifacts.output_relative,
            &smoke_config,
            Some(sandbox_image.reference().to_owned()),
        )
        .await
        {
            Ok(smoked) => smoked,
            Err(error) => {
                let _ = store
                    .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                    .await;
                return Err(error);
            }
        };
        // Fail smoke only on a definite overflow; a transient scan race must not
        // fail a valid smoke run (mirrors the campaign monitor).
        if output_budget_status(
            &artifacts.output_host,
            MAX_RUN_OUTPUT_BYTES,
            MAX_RUN_OUTPUT_ENTRIES,
            64 * 1024 * 1024,
        ) == OutputBudget::Exceeded
            || output_budget_status(
                &artifacts.corpus_host,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_total_bytes,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_entries,
                hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            ) == OutputBudget::Exceeded
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Sandbox(
                "smoke corpus/output exceeded its retained-evidence budget".to_owned(),
            ));
        }
        let Some(summary) = smoked.smoke_run.as_mut() else {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Harness(
                "smoke run produced no summary".to_owned(),
            ));
        };
        summary.source_sha256 = Some(artifacts.source_sha256.clone());
        summary.binary_sha256 = Some(artifacts.binary_sha256.clone());
        summary.run_id = Some(smoke_record.id);
        let summary = summary.clone();
        if let Err(error) = store
            .set_run_stats(
                smoke_record.id,
                0,
                summary.execs_per_sec,
                u64::from(summary.crashes),
            )
            .await
        {
            let _ = store
                .set_run_status(smoke_record.id, RunStatus::Failed, Some(Utc::now()))
                .await;
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        store
            .set_run_status(smoke_record.id, RunStatus::Done, Some(Utc::now()))
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        store
            .upsert_harness(&smoked)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        // Close the journal entry on success before disarming the guard, so a
        // cleanly-completed smoke run is not reconciled to Failed on restart.
        self.run_journal.close_run(smoke_record.id);
        persisted_run.disarm();
        // Deterministic self-verification (grok-build lesson L2): pair the summary
        // with a verdict so every presentation layer surfaces a hollow pass -- a
        // harness that compiled and "passed" yet never drove the target -- instead
        // of re-deriving that judgment. Observation only; it changes no control flow.
        let verdict = crate::verification::assess_harness_smoke(&summary, smoked.status);
        Ok(crate::verification::SmokeOutcome { summary, verdict })
    }

    /// Promote the active harness after a clean persisted smoke run. Calling
    /// this method is the explicit human approval boundary used by every
    /// presentation layer; agents and schedulers never call it implicitly.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the active revision has not completed a
    /// crash-free smoke run or its qualification record cannot be persisted.
    pub async fn harness_promote(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let mut harness = self.active_harness(project, target, engine).await?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "harness '{target}' has no persisted smoke evidence; run smoke qualification first"
            ))
        })?;
        if harness.status != HarnessStatus::SmokePassed || !smoke.passed {
            return Err(ClassifiedError::Validation(format!(
                "harness '{target}' cannot be promoted until a crash-free smoke run passes"
            )));
        }
        self.verify_harness_qualification(project, target, &harness)
            .await?;
        let (_, source_sha256, binary_sha256) = qualification_evidence(&harness)?;
        let source_sha256 = source_sha256.to_owned();
        let binary_sha256 = binary_sha256.to_owned();
        harness.status = HarnessStatus::Promoted;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness promotion requires the persistent service store".to_owned(),
            )
        })?;
        store
            .promote_harness_with_approval(
                &harness,
                hf_storage::HarnessApprovalKind::CleanSmoke,
                &source_sha256,
                &binary_sha256,
                Utc::now(),
            )
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(harness)
    }

    /// Promote a harness with documented smoke findings. This is intentionally
    /// separate from clean promotion so callers cannot accidentally treat a
    /// crash-bearing revision as crash-free.
    pub async fn harness_promote_with_findings(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
    ) -> Result<Harness, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let mut harness = self.active_harness(project, target, engine).await?;
        let smoke = harness.smoke_run.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("run smoke qualification before approving findings".into())
        })?;
        if smoke.crashes == 0 {
            return Err(ClassifiedError::Validation(
                "known-findings approval requires at least one smoke crash".into(),
            ));
        }
        self.verify_harness_qualification(project, target, &harness)
            .await?;
        let (_, source_sha256, binary_sha256) = qualification_evidence(&harness)?;
        let source_sha256 = source_sha256.to_owned();
        let binary_sha256 = binary_sha256.to_owned();
        harness.status = HarnessStatus::Promoted;
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation(
                "harness promotion requires the persistent service store".into(),
            )
        })?;
        store
            .promote_harness_with_approval(
                &harness,
                hf_storage::HarnessApprovalKind::KnownFindings,
                &source_sha256,
                &binary_sha256,
                Utc::now(),
            )
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        Ok(harness)
    }

    /// Generate seed corpus inputs for a target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub async fn generate_seeds(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let seeds = generate_target_seeds(target);
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let corpus = hf_corpus::seed(target_id, &corpus_dir, seeds).await?;
        self.persist_corpus(target_id, &hf_corpus::list(&corpus_dir)?)
            .await?;
        corpus
            .entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| {
                        ClassifiedError::Internal(
                            "generated seed path has no UTF-8 filename".to_owned(),
                        )
                    })?
                    .to_owned();
                let size = usize::try_from(entry.size).map_err(|_| {
                    ClassifiedError::Validation("generated seed is too large".to_owned())
                })?;
                Ok(SeedEntry {
                    name,
                    size,
                    sha256: entry.sha256,
                })
            })
            .collect()
    }

    /// Generate a seed corpus for a target using the LLM (structural, format-
    /// aware seeds), falling back to the heuristic seeds when no provider is
    /// configured or the model returns nothing usable. Seeds are written into
    /// the target's corpus directory and deduplicated by content hash.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory or a seed file cannot
    /// be written.
    pub async fn generate_seeds_llm(
        &self,
        project: &Path,
        target: &str,
        lang: TargetLanguage,
        count: usize,
    ) -> Result<Vec<SeedEntry>, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        // Clamp the requested count to a sane range so no presentation layer can
        // ask the LLM for zero or an absurd number of seeds. Owning the bound
        // here keeps CLI, REST, and Tauri consistent (the clamp previously lived
        // only in the web handler).
        let count = count.clamp(1, 64);
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // LLM seeds when a provider and the target candidate are available.
        let mut datas: Vec<Vec<u8>> = Vec::new();
        if let Some(pool) = self.provider_pool() {
            if let Ok(inv) = self.discover(project, lang).await {
                if let Ok(Some(candidate)) = select_target_candidate(&inv.candidates, target) {
                    let provider = LlmProviderBridge::new(pool)
                        .with_diagnostics(Arc::clone(&self.diagnostics), "seed_gen");
                    match hf_harness::generate_seeds(candidate, count, Box::new(provider)).await {
                        Ok(seeds) => datas = seeds,
                        Err(e) => tracing::warn!("LLM seed generation for '{target}' failed: {e}"),
                    }
                }
            }
        }
        // Fall back to the heuristic seeds so a corpus is always produced.
        if datas.is_empty() {
            datas = generate_target_seeds(target)
                .into_iter()
                .map(|(data, _)| data)
                .collect();
        }

        let mut named_seeds = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (i, data) in datas.into_iter().enumerate() {
            use sha2::{Digest as _, Sha256};
            let sha = format!("{:x}", Sha256::digest(&data));
            if !seen.insert(sha.clone()) {
                continue;
            }
            let name = format!("llmseed_{i}");
            named_seeds.push((data, name));
        }

        // Make the AI seeds first-class, tracked corpus entries (parity with
        // corpus_seed/corpus_grow), so they show in the browse-all corpus view
        // and survive as persisted rows -- previously LLM seeds only landed on
        // disk. Listing the dir also folds in any pre-existing entries; the
        // exact target reconciliation stays idempotent.
        let target_id = self.resolve_target_id(project, target, lang).await?;
        let generated = hf_corpus::seed(target_id, &corpus_dir, named_seeds).await?;
        let entries = generated
            .entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .path
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                let size = usize::try_from(entry.size).map_err(|_| {
                    ClassifiedError::Validation("generated seed is too large".to_owned())
                })?;
                Ok(SeedEntry {
                    name,
                    size,
                    sha256: entry.sha256,
                })
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        let corpus = hf_corpus::list(&corpus_dir)?;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(entries)
    }
}
