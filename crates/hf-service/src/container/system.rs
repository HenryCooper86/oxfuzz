//! Readiness, provider status, cost, and workbench queries.

use std::path::Path;

use hf_core::error::ClassifiedError;
#[cfg(feature = "semgrep-enrichment")]
use hf_core::target::{TargetInventory, TargetLanguage};
use uuid::Uuid;

use super::crash_inputs::is_regular_file;
use super::guards::StagingDirectoryGuard;
#[cfg(feature = "semgrep-enrichment")]
use super::project_identity::{project_lookup_identity, stored_project_matches};
use super::workspace::{document_staging_dir, prepare_configured_workspace_root};
use super::{
    AgentInstanceSnapshot, AgentPoolSnapshot, MemorySnapshot, ProviderSnapshot, ServiceContainer,
    SystemSnapshot,
};

impl ServiceContainer {
    /// A snapshot of the agent turns currently executing.
    fn active_agent_pool(&self) -> AgentPoolSnapshot {
        let labels = self
            .active_agents
            .lock()
            .map(|a| a.clone())
            .unwrap_or_default();
        let instances: Vec<AgentInstanceSnapshot> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| AgentInstanceSnapshot {
                instance_id: format!("turn-{i}"),
                agent_name: label.clone(),
                state: "running".to_owned(),
                elapsed_ms: 0,
                iterations: 0,
                tokens_used: 0,
            })
            .collect();
        AgentPoolSnapshot {
            active_instances: instances.len(),
            available_slots: 0,
            total_instances: instances.len(),
            instances,
        }
    }

    /// Aggregated LLM cost/usage recorded this session.
    pub async fn cost_summary(
        &self,
    ) -> Result<crate::diagnostics::CostSummary, crate::diagnostics::DiagnosticsError> {
        self.diagnostics.summary().await
    }

    /// Per-provider health/usage for the Observability panel: freeze state,
    /// in-flight and total requests, and error counts. Empty when no provider
    /// pool is configured.
    pub async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        match self.provider_pool() {
            Some(pool) => pool.provider_statuses().await,
            None => Vec::new(),
        }
    }

    /// Thaw a provider in the live pool after a verifying health check.
    ///
    /// This is the manual recovery path for providers whose freeze has no
    /// auto-thaw (permanent freezes from invalid keys or exhausted quota):
    /// the pool health-checks the provider and only re-enables it when it
    /// responds, so a still-broken provider stays frozen.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Provider` when no pool is configured or the
    /// health check fails, and `ClassifiedError::Validation` when no provider
    /// with `provider_id` exists in the pool.
    pub async fn thaw_provider(&self, provider_id: &str) -> Result<(), ClassifiedError> {
        let pool = self
            .provider_pool()
            .ok_or_else(|| ClassifiedError::Provider("no LLM provider configured".to_owned()))?;
        let pid = hf_core::types::ProviderId::from_string(provider_id);
        // Distinguish "no such provider" (a client error) from a failed health
        // check (a provider error) instead of string-matching the pool's error.
        let known = pool.provider_statuses().await.iter().any(|s| s.id == pid);
        if !known {
            return Err(ClassifiedError::Validation(format!(
                "unknown provider id: {provider_id}"
            )));
        }
        pool.thaw(&pid)
            .await
            .map_err(|e| ClassifiedError::Provider(format!("thaw {provider_id}: {e}")))
    }

    /// A live system snapshot for the Observability panel: per-provider health
    /// and usage, the agent pool, and runtime memory counters. Merges live
    /// provider stats (concurrency/requests/errors) with the provider config
    /// (model/tags/limits), the canonical agent registry, and session
    /// diagnostics (tokens/cost by model).
    pub async fn system_snapshot(
        &self,
    ) -> Result<SystemSnapshot, crate::diagnostics::DiagnosticsError> {
        let statuses = self.provider_statuses().await;
        let configs = crate::config::get_providers();
        let cost = self.diagnostics.summary().await?;

        let providers = statuses
            .into_iter()
            .map(|s| {
                let cfg = configs.iter().find(|c| c.id == s.id.0);
                let model = cfg.map(|c| c.model.clone()).unwrap_or_default();
                let by_model = cost.by_model.iter().find(|m| m.model == model);
                let error_rate = if s.total_requests > 0 {
                    s.total_errors as f64 / s.total_requests as f64
                } else {
                    0.0
                };
                ProviderSnapshot {
                    id: s.id.0,
                    model,
                    tags: cfg.map(|c| c.tags.clone()).unwrap_or_default(),
                    is_frozen: s.is_frozen,
                    active_requests: s.active_requests,
                    max_concurrency: cfg.map_or(0, |c| c.max_concurrency),
                    total_requests: s.total_requests,
                    total_errors: s.total_errors,
                    error_rate,
                    total_input_tokens: by_model.map_or(0, |m| m.input_tokens),
                    total_output_tokens: by_model.map_or(0, |m| m.output_tokens),
                    estimated_cost_usd: by_model.map_or(0.0, |m| m.cost_usd),
                }
            })
            .collect();

        let (targets, crashes) = if let Some(store) = &self.store {
            (
                store.list_all_targets().await?.len(),
                store.list_all_crashes().await?.len(),
            )
        } else {
            (0, 0)
        };
        let memory = MemorySnapshot {
            pending_runs: self.active_run_ids().len(),
            interrupted_runs: self.interrupted_runs().len(),
            llm_calls: cost.calls,
            targets,
            crashes,
        };

        let mut agents = self.active_agent_pool();
        agents.available_slots = self.list_agent_definitions().len();

        Ok(SystemSnapshot {
            providers,
            agents,
            memory,
        })
    }

    /// Internal-team dashboard summary for the active project/target.
    pub async fn workbench_dashboard(
        &self,
        project: Option<&Path>,
        target: Option<&str>,
    ) -> Result<crate::workbench::WorkbenchDashboard, ClassifiedError> {
        #[cfg(feature = "semgrep-enrichment")]
        let mut effective_score_by_target = std::collections::HashMap::new();
        #[cfg(not(feature = "semgrep-enrichment"))]
        let effective_score_by_target = std::collections::HashMap::new();
        #[cfg(feature = "semgrep-enrichment")]
        if let (Some(store), Some(project)) = (self.store.as_deref(), project) {
            let identity = project_lookup_identity(project);
            let project_targets = store
                .list_all_targets()
                .await?
                .into_iter()
                .filter(|candidate| stored_project_matches(&candidate.project_root, &identity))
                .collect::<Vec<_>>();
            effective_score_by_target.extend(
                project_targets
                    .iter()
                    .map(|candidate| (candidate.id, candidate.fit_score)),
            );
            for language in [TargetLanguage::C, TargetLanguage::Cpp] {
                let candidates = project_targets
                    .iter()
                    .filter(|candidate| candidate.language == language)
                    .cloned()
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    continue;
                }
                let effective = self
                    .effective_inventory(
                        TargetInventory {
                            project_root: identity.clone(),
                            candidates,
                            call_graph: std::collections::HashMap::new(),
                        },
                        language,
                    )
                    .await?;
                effective_score_by_target.extend(
                    effective
                        .candidates
                        .into_iter()
                        .map(|target| (target.candidate.id, target.effective_score)),
                );
            }
        }
        crate::workbench::dashboard(
            self.store.as_deref(),
            project,
            target,
            effective_score_by_target,
        )
        .await
    }

    /// Ingest a document into a project's knowledge base.
    ///
    /// Converts the file (PDF, Office, HTML, CSV, ...) to Markdown with
    /// `markitdown` inside the sandbox (offline; network-isolated), stores the
    /// Markdown under the per-project knowledge docs dir, and re-indexes the
    /// project so the harness-author and triage agents can search it (specs,
    /// RFCs, threat models). Returns the post-index stats.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the file is missing, the sandbox conversion
    /// fails, or the Markdown cannot be written.
    pub async fn ingest_document(
        &self,
        project: &Path,
        file: &Path,
    ) -> Result<crate::knowledge::KnowledgeStats, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        if !is_regular_file(file) {
            return Err(ClassifiedError::Validation(format!(
                "document is not a regular file: {}",
                file.display()
            )));
        }
        let name = file
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| ClassifiedError::Validation("invalid document name".to_owned()))?;

        // Stage below the Docker runtime's approved workspace root, not in the
        // durable knowledge directory (which lives elsewhere in app data).
        prepare_configured_workspace_root()?;
        let docs = crate::knowledge::docs_dir(project);
        let staging = document_staging_dir(project, Uuid::new_v4());
        std::fs::create_dir_all(&staging)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir staging: {e}")))?;
        let staging_guard = StagingDirectoryGuard(staging.clone());
        std::fs::copy(file, staging.join(name))
            .map_err(|e| ClassifiedError::Internal(format!("stage document: {e}")))?;

        let cmd = vec!["markitdown".to_owned(), format!("/work/{name}")];
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 120,
            env: std::collections::HashMap::new(),
            ptrace: false,
        };
        let result = self.runtime.run_command(&cmd, &staging, &limits).await;
        drop(staging_guard);
        let result = result?.require_completed("document conversion")?;
        if result.exit_code != 0 || result.stdout.trim().is_empty() {
            return Err(ClassifiedError::Internal(format!(
                "markitdown failed (exit {}): {}",
                result.exit_code,
                result.stderr.lines().last().unwrap_or_default()
            )));
        }

        // Persist the Markdown under the docs dir, then re-index.
        std::fs::create_dir_all(&docs)
            .map_err(|e| ClassifiedError::Internal(format!("mkdir docs: {e}")))?;
        let stem = Path::new(name)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(name);
        std::fs::write(docs.join(format!("{stem}.md")), &result.stdout)
            .map_err(|e| ClassifiedError::Internal(format!("write doc markdown: {e}")))?;

        crate::knowledge::index_project(project)
    }
}

#[cfg(all(test, feature = "semgrep-enrichment"))]
mod semgrep_ranking_consumer_tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::Arc;

    use chrono::Utc;
    use hf_core::target::{
        InputSurface, SourceLocation, TargetCandidate, TargetInventory, TargetKind, TargetLanguage,
    };
    use hf_storage::Store;
    use uuid::Uuid;

    use super::ServiceContainer;

    fn candidate(
        project: &Path,
        symbol: &str,
        relative_file: &str,
        base_score: f64,
    ) -> TargetCandidate {
        TargetCandidate {
            id: Uuid::new_v4(),
            project_root: project.to_path_buf(),
            language: TargetLanguage::C,
            symbol: symbol.to_owned(),
            kind: TargetKind::Parser,
            location: SourceLocation {
                file: project.join(relative_file),
                line: 1,
                col: 1,
                end_line: Some(1),
                end_col: Some(40),
            },
            signature: None,
            input_surface: InputSurface::Bytes,
            complexity: 1,
            fit_score: base_score,
            sanitizers: Vec::new(),
            rationale: symbol.to_owned(),
            reachable_functions: Vec::new(),
            accumulated_complexity: 1,
        }
    }

    fn inventory(project: &Path) -> TargetInventory {
        TargetInventory {
            project_root: project.to_path_buf(),
            candidates: vec![
                candidate(project, "high_base", "high.c", 0.55),
                candidate(project, "boosted", "boosted.c", 0.5),
            ],
            call_graph: HashMap::new(),
        }
    }

    async fn semgrep_run_count(store: &Store) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM semgrep_enrichment_runs")
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    fn assert_f64_eq(left: f64, right: f64) {
        assert_eq!(left.to_bits(), right.to_bits());
    }

    #[tokio::test]
    async fn service_workbench_orders_by_effective_score_and_retains_base_score() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("high.c"),
            "int high_base(char *p) { return p[0]; }\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("boosted.c"),
            "int boosted(char *p) { return p[0]; }\n",
        )
        .unwrap();
        let project = std::fs::canonicalize(root.path()).unwrap();
        let inventory = inventory(&project);
        let boosted_id = inventory.candidates[1].id;
        let store = Arc::new(
            Store::connect(root.path().join("workbench.db"))
                .await
                .unwrap(),
        );
        store.save_inventory(&inventory, Utc::now()).await.unwrap();
        let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_store(Arc::clone(&store));
        service
            .semgrep_test_publish_inventory(&inventory, HashMap::from([(boosted_id, 0.2)]))
            .await
            .unwrap();
        let before = semgrep_run_count(&store).await;

        let dashboard = service
            .workbench_dashboard(Some(&project), None)
            .await
            .unwrap();

        assert_eq!(dashboard.top_targets[0].id, boosted_id.to_string());
        assert_f64_eq(dashboard.top_targets[0].fit_score, 0.5);
        assert_f64_eq(dashboard.top_targets[1].fit_score, 0.55);
        assert_eq!(semgrep_run_count(&store).await, before);
    }
}
