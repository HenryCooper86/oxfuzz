//! Corpus seeding, growth, pruning, minimization, and crash absorption.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_guardrails::Action;
use hf_storage::RunRecord;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::crash_inputs::{collect_crash_inputs, collect_legacy_crash_inputs, is_regular_file};
use super::guards::StagingDirectoryGuard;
use super::harness_workspace::{container_input_path, harness_binary_name};
use super::output_budget::{monitor_run_output, run_artifacts_within_budget};
use super::project_identity::{canonical_project_root, stored_project_matches};
use super::staging::{
    minimization_failure_with_rollback, minimization_sandbox_options, run_output_dir,
    stage_run_artifacts, verify_run_artifacts, verify_staged_qualification,
};
use super::workspace::workspace_dir;
use super::{
    ensure_workspace_directory, prepare_configured_workspace_root, resolve_internal_run,
    run_has_crash_evidence, MinimizeOutcome, ServiceContainer, CORPUS_MINIMIZE_SECS,
    COVERAGE_PRUNE_COMMAND_SECS, COVERAGE_PRUNE_OPERATION_SECS,
};

impl ServiceContainer {
    async fn corpus_absorb_run_record(
        &self,
        project: &Path,
        target: &str,
        run: Option<RunRecord>,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_absorb_crashes", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");

        // Prefer the deduplicated crash set triage persisted for the latest run;
        // fall back to whatever crash inputs are staged under the run output.
        let mut inputs: Vec<PathBuf> = Vec::new();
        if let Some(store) = &self.store {
            if let Some(run) = &run {
                let crashes = store.list_crashes_by_run(run.id).await?;
                inputs.extend(crashes.into_iter().map(|c| c.input_path));
            }
        }
        if inputs.is_empty() {
            let out_dir = match run.as_ref() {
                Some(run) => run_output_dir(&workspace, run)?,
                None => workspace.join("out"),
            };
            inputs = run.as_ref().map_or_else(
                || collect_legacy_crash_inputs(&out_dir),
                |run| collect_crash_inputs(run.engine, &out_dir),
            );
        }

        let (mut corpus, added) = hf_corpus::absorb(&corpus_dir, &inputs)?;
        if self.store.is_some() {
            let target_id = self.resolve_target_id_any_language(project, target).await?;
            corpus.target_id = target_id;
            self.persist_corpus(target_id, &corpus).await?;
        }
        Ok(added)
    }

    /// List corpus entries for a project/target.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory cannot be read.
    pub fn corpus_list(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<hf_core::corpus::Corpus, ClassifiedError> {
        let _workspace_operation = Self::try_acquire_workspace_operation_now()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        hf_corpus::list(&corpus_dir)
    }

    /// Seed the corpus with default inputs.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be written.
    pub async fn corpus_seed(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_seed", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let seeds = vec![
            (b"{}".to_vec(), "seed_empty".to_owned()),
            (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
        ];
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        let corpus = hf_corpus::seed(target_id, &corpus_dir, seeds).await?;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(corpus.entries.len())
    }

    /// Grow the corpus from engine output.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the directories cannot be read.
    pub async fn corpus_grow(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_grow", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let latest_run = self.latest_run_record(project, Some(target)).await?;
        let out_dir = match latest_run.as_ref() {
            Some(run) => run_output_dir(&workspace, run)?,
            None => workspace.join("out"),
        };
        let mut corpus = hf_corpus::grow(&corpus_dir, &out_dir)?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        corpus.target_id = target_id;
        self.persist_corpus(target_id, &corpus).await?;
        Ok(corpus.entries.len())
    }

    /// Prune duplicate-coverage entries from the corpus.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if files cannot be removed.
    pub async fn corpus_prune(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_prune", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let corpus = hf_corpus::list(&corpus_dir)?;
        let pruned = hf_corpus::prune(corpus)?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        self.persist_corpus(target_id, &pruned).await?;
        Ok(pruned.entries.len())
    }

    /// Coverage-based corpus minimization: run each input through `afl-showmap`
    /// in the sandbox to fingerprint the edges it covers, then drop inputs whose
    /// coverage is already represented by another. This is a true distillation
    /// (keep one input per distinct coverage set), unlike `corpus_prune` which,
    /// absent coverage data, can only collapse byte-identical files.
    ///
    /// Inputs for which a successful `afl-showmap` command yields no coverage
    /// keep a `None` coverage hash and fall back to content-dedup, so this never
    /// collapses two genuinely distinct inputs under an empty key. Qualification
    /// and sandbox failures abort without pruning.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus cannot be read.
    pub async fn corpus_prune_coverage(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<MinimizeOutcome, ClassifiedError> {
        let resolved =
            resolve_internal_run(EngineKind::AflPlusPlus, COVERAGE_PRUNE_OPERATION_SECS)?;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_prune_coverage", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = workspace.join("corpus");
        let mut corpus = hf_corpus::list(&corpus_dir)?;
        let before = corpus.entries.len();
        if before == 0 {
            return Ok(MinimizeOutcome {
                before: 0,
                after: 0,
            });
        }
        if before > 10_000 {
            return Err(ClassifiedError::Validation(
                "coverage pruning is limited to 10000 corpus inputs per operation".to_owned(),
            ));
        }

        let _target_revision = self.acquire_target_revision(project, target).await?;
        let qualified = self
            .active_harness_locked(project, target, EngineKind::AflPlusPlus)
            .await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(
                "coverage pruning requires an explicitly promoted AFL++ harness".to_owned(),
            ));
        }
        self.verify_harness_qualification_locked(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "AFL++ showmap".to_owned(),
                duration_secs: resolved.duration_secs,
            },
            "corpus_prune_coverage",
            Some(project),
        )
        .await?;

        let bin = harness_binary_name(target);
        let binary = workspace.join(&bin);
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "promoted AFL++ harness binary is missing: {}",
                binary.display()
            )));
        }
        let binary_container = format!("/work/{bin}");
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            max_duration_secs: COVERAGE_PRUNE_COMMAND_SECS.min(resolved.duration_secs),
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = hf_core::runtime::SandboxOptions {
            workspace_read_only: true,
            ..hf_core::runtime::SandboxOptions::default()
        };
        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(resolved.duration_secs);
        for entry in &mut corpus.entries {
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                return Err(ClassifiedError::Sandbox(
                    "coverage pruning exceeded its 10-minute operation budget".to_owned(),
                ));
            };
            let input_container = container_input_path(&workspace, &entry.path);
            let args = hf_engine::showmap::build_showmap_args(&binary_container, &input_container);
            let result = tokio::time::timeout(
                remaining,
                self.runtime
                    .run_command_opts(&args, &workspace, &limits, &sandbox),
            )
            .await
            .map_err(|_| {
                ClassifiedError::Sandbox(
                    "coverage pruning exceeded its 10-minute operation budget".to_owned(),
                )
            })?;
            let result = result?.require_completed("AFL++ coverage pruning")?;
            if result.exit_code != 0 {
                return Err(ClassifiedError::Sandbox(format!(
                    "AFL++ coverage pruning exited with status {}: {}",
                    result.exit_code,
                    result.stderr.trim()
                )));
            }
            if let Some(hash) = hf_engine::showmap::coverage_hash(&result.stdout) {
                entry.coverage_hash = Some(hash);
            }
        }

        let pruned = hf_corpus::prune(corpus)?;
        let after = pruned.entries.len();
        self.persist_corpus(qualified.target_id, &pruned).await?;
        Ok(MinimizeOutcome { before, after })
    }

    /// Feed triaged crash reproducers back into the corpus.
    ///
    /// Closes the run -> triage -> corpus loop: every crash-triggering input
    /// surfaced by the most recent triage (persisted crashes for the target's
    /// latest run, falling back to scanning the run output directory) is copied
    /// into the corpus, deduplicated by content, so the harness keeps exercising
    /// the paths that already broke it. Returns the number of inputs newly
    /// added.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus cannot be read or written.
    pub async fn corpus_absorb_crashes(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<usize, ClassifiedError> {
        let latest_run = self.latest_run_record(project, Some(target)).await?;
        self.corpus_absorb_run_record(project, target, latest_run)
            .await
    }

    /// Feed crash reproducers from one exact run back into the target corpus.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run does not own terminal evidence for
    /// this target or the corpus cannot be read or written.
    pub async fn corpus_absorb_crashes_for_run(
        &self,
        project: &Path,
        target: &str,
        run_id: Uuid,
    ) -> Result<usize, ClassifiedError> {
        let project_root = canonical_project_root(project)?;
        let project = project_root.as_path();
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {run_id}")))?;
        let target_id = self.resolve_target_id_any_language(project, target).await?;
        if target_id.is_nil()
            || !stored_project_matches(Path::new(&run.project_root), project)
            || !run_has_crash_evidence(run.status)
            || self.run_target_id(store, &run).await? != Some(target_id)
        {
            return Err(ClassifiedError::Validation(format!(
                "run {run_id} does not own terminal evidence for target '{target}'"
            )));
        }
        self.corpus_absorb_run_record(project, target, Some(run))
            .await
    }

    /// Coverage-guided corpus minimization.
    ///
    /// Runs libFuzzer's canonical `-merge=1` pass with the exact promoted and
    /// smoke-qualified harness. The service exposes only an immutable run-owned
    /// corpus snapshot and a bounded writable output directory to the sandbox;
    /// a successful merge is then reconciled into the retained corpus and its
    /// database inventory. Returns the entry counts before and after.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the corpus directory cannot be read or
    /// rewritten.
    pub async fn corpus_minimize(
        &self,
        project: &Path,
        target: &str,
    ) -> Result<MinimizeOutcome, ClassifiedError> {
        let resolved = resolve_internal_run(EngineKind::LibFuzzer, CORPUS_MINIMIZE_SECS)?;
        let _workspace_operation = self.acquire_workspace_operation().await?;
        self.authorize_recorded(Action::CorpusOp, "corpus_minimize", Some(project))
            .await?;
        prepare_configured_workspace_root()?;
        let workspace = workspace_dir(project, target);
        let corpus_dir = ensure_workspace_directory(&workspace, Path::new("corpus"))?;
        let before = hf_corpus::list(&corpus_dir)?.entries.len();
        if before == 0 {
            return Ok(MinimizeOutcome {
                before: 0,
                after: 0,
            });
        }

        let _target_revision = self.acquire_target_revision(project, target).await?;
        let qualified = self
            .active_harness_locked(project, target, EngineKind::LibFuzzer)
            .await?;
        if qualified.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(
                "corpus minimization requires an explicitly promoted libFuzzer harness".to_owned(),
            ));
        }
        self.verify_harness_qualification_locked(project, target, &qualified)
            .await?;
        self.authorize_recorded(
            Action::RunFuzzer {
                engine: "libFuzzer corpus minimization".to_owned(),
                duration_secs: resolved.duration_secs,
            },
            "corpus_minimize",
            Some(project),
        )
        .await?;

        let binary = workspace.join(harness_binary_name(target));
        if !is_regular_file(&binary) {
            return Err(ClassifiedError::Validation(format!(
                "promoted libFuzzer harness binary is missing: {}",
                binary.display()
            )));
        }
        let artifacts =
            stage_run_artifacts(&workspace, Uuid::new_v4(), &qualified.source, &binary)?;
        let run_root = artifacts.output_host.parent().ok_or_else(|| {
            ClassifiedError::Internal("minimization output has no run directory".to_owned())
        })?;
        let _staging_guard = StagingDirectoryGuard(run_root.to_path_buf());
        verify_staged_qualification(&qualified, &artifacts)?;
        verify_run_artifacts(&artifacts)?;

        let cmd = vec![
            artifacts.binary_container.clone(),
            "-merge=1".to_owned(),
            artifacts.output_container.clone(),
            artifacts.corpus_container.clone(),
        ];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: resolved.max_mem_mb,
            max_cpus: resolved.max_cpus,
            max_duration_secs: resolved.duration_secs,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let sandbox = minimization_sandbox_options(&artifacts);
        let cancel = CancellationToken::new();
        let monitor_stop = CancellationToken::new();
        let budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let monitor = tokio::spawn(monitor_run_output(
            artifacts.output_host.clone(),
            artifacts.corpus_host.clone(),
            hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
            cancel.clone(),
            monitor_stop.clone(),
            Arc::clone(&budget_exceeded),
        ));
        let result = self
            .runtime
            .run_command_streaming_opts(&cmd, &workspace, &limits, &sandbox, &cancel, &|_| {})
            .await;
        monitor_stop.cancel();
        let _ = monitor.await;
        if !run_artifacts_within_budget(
            &artifacts,
            hf_corpus::DEFAULT_CORPUS_LIMITS.max_input_bytes,
        )
        .await
        {
            budget_exceeded.store(true, std::sync::atomic::Ordering::Release);
        }
        if budget_exceeded.load(std::sync::atomic::Ordering::Acquire) {
            return Err(ClassifiedError::Sandbox(
                "corpus minimization exceeded its corpus/output budget".to_owned(),
            ));
        }
        let result = result?.require_completed("corpus minimization")?;
        if result.exit_code != 0 {
            return Err(ClassifiedError::Sandbox(format!(
                "corpus minimization exited with status {}: {}",
                result.exit_code,
                result.stderr.trim()
            )));
        }

        let merged = hf_corpus::list(&artifacts.output_host)?;
        if merged.entries.is_empty() {
            return Err(ClassifiedError::Sandbox(
                "corpus minimization produced an empty survivor set".to_owned(),
            ));
        }
        let mut minimized = match hf_corpus::minimize(&corpus_dir, &artifacts.output_host) {
            Ok(corpus) => corpus,
            Err(error) => {
                return Err(minimization_failure_with_rollback(
                    &corpus_dir,
                    &artifacts.corpus_host,
                    error,
                ));
            }
        };
        minimized.target_id = qualified.target_id;
        if let Err(error) = self.persist_corpus(qualified.target_id, &minimized).await {
            return Err(minimization_failure_with_rollback(
                &corpus_dir,
                &artifacts.corpus_host,
                error,
            ));
        }
        Ok(MinimizeOutcome {
            before,
            after: minimized.entries.len(),
        })
    }
}
