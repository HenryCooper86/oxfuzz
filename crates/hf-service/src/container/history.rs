//! Retained evidence: run history, artifacts, deletion, and export.

use std::path::Path;

use chrono::Utc;
use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_storage::{RunKind, RunStatus};
use uuid::Uuid;

use super::crash_inputs::collect_workspace_crash_inputs;
use super::guards::ensure_run_journal_durable;
use super::harness_workspace::{
    harness_binary_name, read_current_harness_id, read_current_harness_source,
};
use super::project_identity::{
    canonical_project_root, project_lookup_identity, stored_project_matches,
};
use super::staging::quarantine_corpus_entry;
use super::workspace::workspace_dir;
use super::{
    auto_revert_comparison_key, run_has_crash_evidence, ArtifactSummary, CoverageSample,
    RunHistoryItem, ServiceContainer,
};

impl ServiceContainer {
    /// Run history for a project (or all projects when `None`), newest first,
    /// enriched with the crash count per run. Powers the Runs history view.
    pub async fn run_history(
        &self,
        project: Option<&Path>,
    ) -> Result<Vec<RunHistoryItem>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        let canonical_project = project.map(project_lookup_identity);
        let runs = store
            .list_runs(None)
            .await?
            .into_iter()
            .filter(|run| {
                canonical_project.as_ref().is_none_or(|canonical| {
                    stored_project_matches(Path::new(&run.project_root), canonical)
                })
            })
            .collect::<Vec<_>>();
        let crashes = store.list_all_crashes().await?;
        let harnesses: std::collections::HashMap<Uuid, Harness> = store
            .list_all_harnesses()
            .await?
            .into_iter()
            .map(|h| (h.id, h))
            .collect();
        let targets: std::collections::HashMap<Uuid, String> = store
            .list_all_targets()
            .await?
            .into_iter()
            .map(|t| (t.id, t.symbol))
            .collect();
        let mut crashes_by_run: std::collections::HashMap<Uuid, usize> =
            std::collections::HashMap::new();
        for c in &crashes {
            *crashes_by_run.entry(c.run_id).or_insert(0) += 1;
        }
        let mut items: Vec<RunHistoryItem> = runs
            .into_iter()
            .map(|r| {
                let target_id = r
                    .config
                    .as_ref()
                    .and_then(|cfg| harnesses.get(&cfg.harness_id))
                    .map(|h| h.target_id);
                let target = target_id.and_then(|id| targets.get(&id).cloned());
                // Presentation layers use this opaque key to compare a run only
                // with an experiment that has the same target, engine, budget,
                // sanitizer, corpus, environment, and engine arguments.
                let comparison_key = match (
                    r.status,
                    r.kind,
                    target_id,
                    r.config.as_ref(),
                    r.context_rev.as_deref(),
                ) {
                    (RunStatus::Done, RunKind::Campaign, Some(id), Some(cfg), Some(context)) => {
                        Some(auto_revert_comparison_key(id, cfg, context))
                    }
                    _ => None,
                };
                let duration_secs = r
                    .ended_at
                    .map(|end| (end - r.started_at).num_seconds().max(0));
                RunHistoryItem {
                    id: r.id.to_string(),
                    project_root: r.project_root,
                    target,
                    comparison_key,
                    engine: format!("{:?}", r.engine),
                    status: format!("{:?}", r.status),
                    started_at: r.started_at.to_rfc3339(),
                    ended_at: r.ended_at.map(|t| t.to_rfc3339()),
                    duration_secs,
                    // Prefer the fuzzer's recorded crash count (available even
                    // without triage); fall back to the deduped crashes table
                    // for runs recorded before stats were persisted.
                    crashes: r.crash_count.map_or_else(
                        || crashes_by_run.get(&r.id).copied().unwrap_or(0),
                        |c| usize::try_from(c).unwrap_or(0),
                    ),
                    edges: r.edges,
                    execs: r.execs,
                    harness_rev: r.harness_rev,
                    binary_rev: r.binary_rev,
                    evidence_dir: r.evidence_dir,
                }
            })
            .collect();
        items.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        Ok(items)
    }

    /// The intra-run coverage/throughput curve for a run (empty if none was
    /// recorded, e.g. runs from before this was captured).
    pub async fn run_coverage_series(
        &self,
        run_id: &str,
    ) -> Result<Vec<CoverageSample>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        let id = Uuid::parse_str(run_id)
            .map_err(|error| ClassifiedError::Validation(format!("bad run id: {error}")))?;
        let Some(json) = store.run_samples(id).await? else {
            return Ok(Vec::new());
        };
        serde_json::from_str(&json)
            .map_err(|error| ClassifiedError::Storage(format!("decode run samples: {error}")))
    }

    /// The harness source a run used, for diffing revisions (empty if none was
    /// recorded).
    pub async fn run_harness_source(&self, run_id: &str) -> Result<String, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(String::new());
        };
        let id = Uuid::parse_str(run_id)
            .map_err(|error| ClassifiedError::Validation(format!("bad run id: {error}")))?;
        Ok(store.run_harness_source(id).await?.unwrap_or_default())
    }

    /// Delete a single run and the crashes it produced.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn delete_run(&self, run_id: &str) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let id = Uuid::parse_str(run_id)
            .map_err(|error| ClassifiedError::Validation(format!("bad run id: {error}")))?;
        let run = store
            .get_run(id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation(format!("run not found: {id}")))?;
        if !run_has_crash_evidence(run.status) || self.active_run_ids().contains(&id) {
            return Err(ClassifiedError::Validation(format!(
                "run {id} is still active and cannot be deleted"
            )));
        }
        self.ensure_run_is_not_qualification(store, id).await?;
        let evidence_root = self.run_evidence_root(store, &run).await?;
        store
            .delete_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Internal(format!("delete run: {e}")))?;
        if let Some(root) = evidence_root {
            std::fs::remove_dir_all(&root).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "remove run evidence {}: {error}",
                    root.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Clear every persisted run and the crashes it produced (Run History).
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn clear_all_runs(&self) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let runs = store
            .list_runs(None)
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        if runs.iter().any(|run| {
            !run_has_crash_evidence(run.status) || self.active_run_ids().contains(&run.id)
        }) {
            return Err(ClassifiedError::Validation(
                "run history contains an active run and cannot be cleared".to_owned(),
            ));
        }
        for run in &runs {
            self.ensure_run_is_not_qualification(store, run.id).await?;
        }
        let mut evidence_roots = Vec::new();
        for run in &runs {
            if let Some(root) = self.run_evidence_root(store, run).await? {
                evidence_roots.push(root);
            }
        }
        store
            .clear_all_runs()
            .await
            .map_err(|e| ClassifiedError::Internal(format!("clear runs: {e}")))?;
        for root in evidence_roots {
            std::fs::remove_dir_all(&root).map_err(|error| {
                ClassifiedError::Internal(format!(
                    "remove run evidence {}: {error}",
                    root.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Runs interrupted by an app crash/quit, awaiting recovery.
    #[must_use]
    pub fn interrupted_runs(&self) -> Vec<crate::recovery::InterruptedRun> {
        self.run_journal.interrupted()
    }

    /// Dismiss an interrupted run from the recovery list.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when the recovery journal cannot durably
    /// record the dismissal.
    pub fn dismiss_interrupted_run(&self, run_id: &str) -> Result<(), ClassifiedError> {
        ensure_run_journal_durable(&self.run_journal)?;
        self.run_journal.dismiss(run_id);
        ensure_run_journal_durable(&self.run_journal)
    }

    /// A cheap snapshot of a target's on-disk artifacts (compiled harness,
    /// corpus size, crash inputs) for the Info panel. Pure filesystem reads --
    /// no sandbox, no LLM.
    #[must_use]
    pub fn artifact_summary(&self, project: &Path, target: &str) -> ArtifactSummary {
        let Ok(_workspace_operation) = Self::try_acquire_workspace_operation_now() else {
            return ArtifactSummary {
                harness_built: false,
                corpus_count: 0,
                crash_count: 0,
            };
        };
        let workspace = workspace_dir(project, target);
        let harness_built = workspace.join(harness_binary_name(target)).exists();
        let corpus_count =
            hf_corpus::list(&workspace.join("corpus")).map_or(0, |c| c.entries.len());
        let crash_count = collect_workspace_crash_inputs(&workspace).len();
        ArtifactSummary {
            harness_built,
            corpus_count,
            crash_count,
        }
    }

    /// Every crash persisted to the store, across all targets and runs.
    ///
    /// This is the correct source for a browse-all artifacts view: it returns
    /// crashes already ingested by triage regardless of which target's workspace
    /// they came from, rather than re-scanning a single (possibly wrong) target
    /// workspace. Returns an empty list when no database is configured.
    pub async fn all_crashes(&self) -> Result<Vec<hf_core::crash::Crash>, ClassifiedError> {
        match self.store.as_ref() {
            Some(store) => Ok(store.list_all_crashes().await?),
            None => Ok(Vec::new()),
        }
    }

    /// Delete a single crash reproducer by id.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn delete_crash(&self, crash_id: &str) -> Result<(), ClassifiedError> {
        if let Some(store) = self.store.as_ref() {
            store
                .delete_crash(crash_id)
                .await
                .map_err(|e| ClassifiedError::Internal(format!("delete crash: {e}")))?;
        }
        Ok(())
    }

    /// Every corpus entry persisted to the store, across all targets.
    ///
    /// The browse-all counterpart to [`Self::corpus_list`] (which is scoped to a
    /// single target's on-disk corpus). Returns an empty list when no database
    /// is configured.
    pub async fn all_corpus_entries(
        &self,
    ) -> Result<Vec<hf_core::corpus::CorpusEntry>, ClassifiedError> {
        match self.store.as_ref() {
            Some(store) => Ok(store.list_all_corpus_entries().await?),
            None => Ok(Vec::new()),
        }
    }

    /// Delete one exact persisted corpus entry and its managed file.
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn delete_corpus_entry(
        &self,
        sha256: &str,
        expected_path: &Path,
    ) -> Result<(), ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let Some(store) = self.store.as_ref() else {
            return Ok(());
        };
        let mut matches = store
            .list_all_corpus_entries_with_targets()
            .await
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?
            .into_iter()
            .filter(|(_, entry)| entry.sha256 == sha256 && entry.path == expected_path);
        let (target_id, entry) = matches.next().ok_or_else(|| {
            ClassifiedError::Validation(format!("corpus entry not found: {sha256}"))
        })?;
        if matches.next().is_some() {
            return Err(ClassifiedError::Validation(format!(
                "corpus entry identity is ambiguous: {sha256} at {}",
                expected_path.display()
            )));
        }

        let quarantined = quarantine_corpus_entry(&entry.path, sha256)?;
        if let Err(error) = store.delete_corpus_entry(target_id, sha256).await {
            if let Some(quarantined) = quarantined {
                std::fs::rename(&quarantined, &entry.path).map_err(|restore_error| {
                    ClassifiedError::Internal(format!(
                        "delete corpus entry failed: {error}; restore failed: {restore_error}"
                    ))
                })?;
            }
            return Err(ClassifiedError::Storage(error.to_string()));
        }
        if let Some(quarantined) = quarantined {
            if let Err(error) = std::fs::remove_file(&quarantined) {
                tracing::warn!(
                    path = %quarantined.display(),
                    "deleted corpus row but could not remove quarantined file: {error}"
                );
            }
        }
        Ok(())
    }

    /// Clear every persisted crash and corpus entry (the Artifacts browser).
    ///
    /// # Errors
    /// Returns `ClassifiedError` on a storage failure.
    pub async fn clear_all_artifacts(&self) -> Result<(), ClassifiedError> {
        if let Some(store) = self.store.as_ref() {
            store
                .clear_all_artifacts()
                .await
                .map_err(|e| ClassifiedError::Internal(format!("clear artifacts: {e}")))?;
        }
        Ok(())
    }

    /// A JSON bundle of a project's persisted fuzzing data (targets, runs,
    /// harnesses, crashes, corpus) for hand-off to other tools. Scoped by
    /// project; pass `None` to export everything.
    pub async fn export_project_data(
        &self,
        project: Option<&Path>,
    ) -> Result<serde_json::Value, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let Some(store) = self.store.as_ref() else {
            return Ok(serde_json::json!({ "error": "no database configured" }));
        };
        let canonical_project = project.map(canonical_project_root).transpose()?;
        let key = canonical_project
            .as_ref()
            .map(|path| path.to_string_lossy().to_string());
        let targets = store.list_all_targets().await?;
        let scoped_targets: Vec<_> = match canonical_project.as_ref() {
            Some(canonical) => targets
                .into_iter()
                .filter(|target| stored_project_matches(&target.project_root, canonical))
                .collect(),
            None => targets,
        };
        let target_ids: std::collections::HashSet<Uuid> =
            scoped_targets.iter().map(|t| t.id).collect();
        let harnesses: Vec<_> = store
            .list_all_harnesses()
            .await?
            .into_iter()
            .filter(|h| key.is_none() || target_ids.contains(&h.target_id))
            .collect();
        let crashes: Vec<_> = store
            .list_all_crashes()
            .await?
            .into_iter()
            .filter(|c| key.is_none() || target_ids.contains(&c.target_id))
            .collect();
        let corpus: Vec<_> = store
            .list_all_corpus_entries_with_targets()
            .await?
            .into_iter()
            .filter(|(target_id, _)| key.is_none() || target_ids.contains(target_id))
            .map(|(_, entry)| entry)
            .collect();
        let runs = self.run_history(canonical_project.as_deref()).await?;
        let evidence: Vec<_> = scoped_targets
            .iter()
            .map(|target| {
                let workspace = workspace_dir(&target.project_root, &target.symbol);
                serde_json::json!({
                    "target_id": target.id,
                    "target": target.symbol,
                    "workspace": workspace,
                    "active_harness_id": read_current_harness_id(&workspace),
                    "active_harness_source": read_current_harness_source(&workspace),
                    "binary": workspace.join(harness_binary_name(&target.symbol)),
                    "binary_present": workspace.join(harness_binary_name(&target.symbol)).is_file(),
                    "corpus_dir": workspace.join("corpus"),
                    "run_evidence_root": workspace.join("runs"),
                    "legacy_crash_dir": workspace.join("out"),
                })
            })
            .collect();
        Ok(serde_json::json!({
            "schema": "oxfuzz.export.v2",
            "generated_at": Utc::now().to_rfc3339(),
            "tool_version": env!("CARGO_PKG_VERSION"),
            "project": key,
            "targets": scoped_targets,
            "harnesses": harnesses,
            "crashes": crashes,
            "corpus": corpus,
            "runs": runs,
            "evidence": evidence,
        }))
    }
}
