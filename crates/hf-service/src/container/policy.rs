//! Guardrail decision history and auto-revert policy.

use std::path::Path;

use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_guardrails::Action;
use hf_storage::{AutoRevertEvent, GuardrailDecisionRecord, ProjectAutoRevert};
use uuid::Uuid;

use super::crash_inputs::is_regular_file;
use super::harness_workspace::{
    harness_binary_name, write_current_harness_binary, write_current_harness_id,
    write_current_harness_source,
};
use super::staging::{qualification_evidence, run_binary_path, run_source_path, sha256_file};
use super::workspace::workspace_dir;
use super::{CompileOutcome, EffectiveAutoRevert, ServiceContainer};

/// Newest decisions retained in the audit trail; recording prunes beyond this
/// window on write (mirrors schedule-execution history retention).
pub(super) const GUARDRAIL_DECISION_RETENTION: usize = 1000;

impl ServiceContainer {
    /// The guardrail decision audit trail (newest first), capped at `limit`
    /// rows. Empty without a store.
    pub async fn policy_decisions(
        &self,
        limit: usize,
    ) -> Result<Vec<GuardrailDecisionRecord>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        Ok(store
            .list_guardrail_decisions(i64::try_from(limit).unwrap_or(200))
            .await?)
    }

    /// The auto-revert audit trail (newest first), scoped to `project` when given
    /// or across all projects otherwise. Empty without a store.
    pub async fn auto_revert_events(
        &self,
        project: Option<&Path>,
        limit: usize,
    ) -> Result<Vec<AutoRevertEvent>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(Vec::new());
        };
        let key = project.map(|p| p.to_string_lossy().to_string());
        Ok(store
            .list_auto_revert_events(key.as_deref(), i64::try_from(limit).unwrap_or(200))
            .await?)
    }

    /// A project's auto-revert override, or `None` when it inherits the global
    /// policy. For the settings UI to show whether an override is in effect.
    pub async fn project_auto_revert_override(
        &self,
        project: &Path,
    ) -> Result<Option<ProjectAutoRevert>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(None);
        };
        let key = project.to_string_lossy().to_string();
        Ok(store.project_auto_revert(&key).await?)
    }

    /// Every project's auto-revert override, keyed by project root -- so a
    /// projects overview can badge which ones diverge from the global policy.
    /// Empty when no store is configured or no project overrides.
    pub async fn project_auto_revert_overrides(
        &self,
    ) -> Result<std::collections::HashMap<String, ProjectAutoRevert>, ClassifiedError> {
        let Some(store) = self.store.as_ref() else {
            return Ok(std::collections::HashMap::new());
        };
        Ok(store
            .all_project_auto_reverts()
            .await?
            .into_iter()
            .collect())
    }

    /// The effective auto-revert policy for a project (its override merged over
    /// the global default) plus whether an override is in effect -- for a badge
    /// that shows the active project's resolved policy.
    pub async fn effective_auto_revert_view(
        &self,
        project: &Path,
    ) -> Result<EffectiveAutoRevert, ClassifiedError> {
        let overridden = self.project_auto_revert_override(project).await?.is_some();
        let p = self.effective_auto_revert_policy(project).await?;
        Ok(EffectiveAutoRevert {
            enabled: p.enabled,
            threshold_pct: p.threshold_pct,
            notify_only: p.notify_only,
            overridden,
        })
    }

    /// Set (or replace) a project's auto-revert override.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when no store is configured or the write fails.
    pub async fn set_project_auto_revert_override(
        &self,
        project: &Path,
        enabled: bool,
        threshold_pct: f64,
        notify_only: bool,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let key = project.to_string_lossy().to_string();
        if !crate::config::valid_auto_revert_threshold(threshold_pct) {
            return Err(ClassifiedError::Validation(format!(
                "auto-revert threshold must be a finite percentage in (0, 100], got {threshold_pct}"
            )));
        }
        store
            .set_project_auto_revert(
                &key,
                ProjectAutoRevert {
                    enabled,
                    threshold_pct,
                    notify_only,
                },
            )
            .await?;
        Ok(())
    }

    /// Clear a project's auto-revert override, so it inherits the global policy.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when no store is configured or the delete fails.
    pub async fn clear_project_auto_revert_override(
        &self,
        project: &Path,
    ) -> Result<(), ClassifiedError> {
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let key = project.to_string_lossy().to_string();
        store.clear_project_auto_revert(&key).await?;
        Ok(())
    }

    /// Restore the exact source and executable a run used, so that promoted
    /// qualification becomes current again without recompiling different bytes.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the run/harness/evidence cannot be resolved,
    /// digest verification fails, or activation cannot be committed.
    pub async fn revert_harness_from_run(
        &self,
        run_id: &str,
    ) -> Result<CompileOutcome, ClassifiedError> {
        let _workspace_operation = self.acquire_workspace_operation().await?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| ClassifiedError::Validation("no database configured".to_owned()))?;
        let id = Uuid::parse_str(run_id)
            .map_err(|e| ClassifiedError::Validation(format!("bad run id: {e}")))?;
        let run = store
            .get_run(id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation("run not found".to_owned()))?;
        let harness_id = run.config.as_ref().map(|c| c.harness_id).ok_or_else(|| {
            ClassifiedError::Validation("run has no harness reference".to_owned())
        })?;
        let harness = store.get_harness(harness_id).await?.ok_or_else(|| {
            ClassifiedError::Validation("the harness for this run no longer exists".to_owned())
        })?;
        let symbol = store
            .list_all_targets()
            .await?
            .into_iter()
            .find(|t| t.id == harness.target_id)
            .map(|t| t.symbol)
            .ok_or_else(|| {
                ClassifiedError::Validation("the target for this run no longer exists".to_owned())
            })?;
        let project = std::path::PathBuf::from(&run.project_root);
        if harness.status != HarnessStatus::Promoted {
            return Err(ClassifiedError::Validation(
                "only a promoted historical harness can be restored".to_owned(),
            ));
        }
        let (qualification_run, expected_source, expected_binary) =
            qualification_evidence(&harness)?;
        if run.harness_rev.as_deref() != Some(expected_source)
            || run.binary_rev.as_deref() != Some(expected_binary)
        {
            return Err(ClassifiedError::Validation(format!(
                "run {id} does not contain the exact promoted qualification artifacts"
            )));
        }
        if store.get_run(qualification_run).await?.is_none() {
            return Err(ClassifiedError::Validation(
                "the historical harness qualification run is missing".to_owned(),
            ));
        }

        let workspace = workspace_dir(&project, &symbol);
        let source_path = run_source_path(&workspace, &run)?;
        let binary_path = run_binary_path(&workspace, &run, &symbol)?;
        let source = std::fs::read_to_string(&source_path).map_err(|error| {
            ClassifiedError::Validation(format!(
                "read historical harness source {}: {error}",
                source_path.display()
            ))
        })?;
        if source != harness.source {
            return Err(ClassifiedError::Validation(format!(
                "run {id} source does not match its promoted harness record"
            )));
        }

        self.authorize_recorded(
            Action::CompileHarness,
            "revert_harness_from_run",
            Some(&project),
        )
        .await?;
        let active_binary = workspace.join(harness_binary_name(&symbol));
        let backup = workspace.join(format!("harness.restore.{}.backup", Uuid::new_v4()));
        let had_active_binary = is_regular_file(&active_binary);
        if had_active_binary {
            std::fs::copy(&active_binary, &backup).map_err(|error| {
                ClassifiedError::Internal(format!("back up active harness binary: {error}"))
            })?;
        }
        let old_source = std::fs::read(workspace.join("harness.source")).ok();
        let old_id = std::fs::read(workspace.join("harness.active")).ok();

        let activate = (|| -> Result<(), ClassifiedError> {
            let restored = write_current_harness_binary(&workspace, &symbol, &binary_path)?;
            if sha256_file(&restored)? != expected_binary {
                return Err(ClassifiedError::Validation(
                    "restored harness binary failed post-copy digest verification".to_owned(),
                ));
            }
            write_current_harness_source(&workspace, &source)?;
            write_current_harness_id(&workspace, harness.id)?;
            Ok(())
        })();
        if let Err(error) = activate {
            if had_active_binary {
                let _ = std::fs::copy(&backup, &active_binary);
            } else {
                let _ = std::fs::remove_file(&active_binary);
            }
            if let Some(bytes) = old_source {
                let _ = std::fs::write(workspace.join("harness.source"), bytes);
            }
            if let Some(bytes) = old_id {
                let _ = std::fs::write(workspace.join("harness.active"), bytes);
            }
            let _ = std::fs::remove_file(&backup);
            return Err(error);
        }
        let _ = std::fs::remove_file(&backup);
        self.verify_harness_qualification(&project, &symbol, &harness)
            .await?;
        Ok(CompileOutcome {
            status: HarnessStatus::Promoted,
            binary_name: harness_binary_name(&symbol),
            workspace,
        })
    }

    /// Ask the operator to approve an agent's tool call, for an agent running
    /// with manual autonomy that gates every action. Returns whether it was
    /// approved. Tighten-only: it only ever adds a prompt via the guardrail
    /// gate; it never bypasses the policy or auto-allows.
    pub async fn approve_agent_tool(&self, tool: &str, agent: &str) -> bool {
        self.guardrails
            .require_approval(
                &Action::AgentTool {
                    name: tool.to_owned(),
                },
                &format!("agent '{agent}' runs with manual autonomy and requests tool '{tool}'"),
            )
            .await
    }
}

#[cfg(test)]
mod guardrail_decision_tests {
    use std::sync::Arc;

    use hf_guardrails::{Action, AutoApprove, DenyAll, GuardrailPolicy, Guardrails, RiskTier};
    use hf_storage::Store;

    use super::ServiceContainer;

    async fn container_with_store(guardrails: Guardrails) -> (ServiceContainer, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::connect(dir.path().join("decisions.db"))
            .await
            .unwrap();
        let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
            .with_guardrails(guardrails)
            .with_store(Arc::new(store));
        (container, dir)
    }

    fn strict_deny_guardrails() -> Guardrails {
        Guardrails::new(
            GuardrailPolicy {
                auto_allow_max: RiskTier::Low,
                deny_at: Some(RiskTier::Low),
            },
            Arc::new(DenyAll),
        )
    }

    #[tokio::test]
    async fn allowed_decisions_are_recorded_with_action_tier_origin_and_project() {
        let (container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;

        container
            .authorize_recorded(
                Action::Discover,
                "unit_origin",
                Some(std::path::Path::new("/proj")),
            )
            .await
            .unwrap();

        let rows = container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.action, "discover");
        assert_eq!(row.risk_tier, "low");
        assert_eq!(row.decision, "allowed");
        assert_eq!(row.origin, "unit_origin");
        assert_eq!(row.project.as_deref(), Some("/proj"));
        assert_eq!(row.detail, None);
    }

    #[tokio::test]
    async fn policy_denials_are_recorded_and_the_error_path_is_unchanged() {
        let (container, _dir) = container_with_store(strict_deny_guardrails()).await;

        let error = container
            .authorize_recorded(Action::Discover, "unit_origin", None)
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("guardrail denied"),
            "the denial surfaces through the existing error path: {error}"
        );
        let rows = container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "denied");
        assert!(
            rows[0]
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("denied by policy")),
            "the denial detail names the policy rule: {:?}",
            rows[0].detail
        );
    }

    #[tokio::test]
    async fn approval_gate_outcomes_are_recorded() {
        let (approved_container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(AutoApprove),
        ))
        .await;
        approved_container
            .authorize_recorded(Action::RunHarness, "harness_smoke", None)
            .await
            .unwrap();
        let rows = approved_container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "approved");
        assert_eq!(rows[0].risk_tier, "high");

        let (declined_container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;
        let error = declined_container
            .authorize_recorded(Action::RunHarness, "harness_smoke", None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("approval declined"));
        let rows = declined_container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "denied_by_operator");
    }

    #[tokio::test]
    async fn recording_failure_never_changes_the_authorization_outcome() {
        let (allowed, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;
        allowed.store().unwrap().pool().close().await;
        assert!(
            allowed
                .authorize_recorded(Action::Discover, "unit_origin", None)
                .await
                .is_ok(),
            "a broken decision store must not block an allowed action"
        );

        let (denied, _dir) = container_with_store(strict_deny_guardrails()).await;
        denied.store().unwrap().pool().close().await;
        assert!(
            denied
                .authorize_recorded(Action::Discover, "unit_origin", None)
                .await
                .is_err(),
            "a broken decision store must not unblock a denied action"
        );
    }

    #[tokio::test]
    async fn decision_details_are_bounded() {
        let (container, _dir) = container_with_store(strict_deny_guardrails()).await;
        let long_command = "x".repeat(10_000);

        let _ = container
            .authorize_recorded(
                Action::ShellExec {
                    command: long_command,
                },
                "unit_origin",
                None,
            )
            .await;

        let rows = container.policy_decisions(10).await.unwrap();
        assert_eq!(rows.len(), 1);
        let detail = rows[0].detail.as_deref().unwrap_or_default();
        assert!(
            detail.chars().count() <= 256,
            "detail is bounded, got {} chars",
            detail.chars().count()
        );
    }

    #[tokio::test]
    async fn policy_decisions_are_newest_first_and_bounded() {
        let (container, _dir) = container_with_store(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ))
        .await;
        for origin in ["first", "second", "third"] {
            container
                .authorize_recorded(Action::Discover, origin, None)
                .await
                .unwrap();
        }

        let rows = container.policy_decisions(2).await.unwrap();
        assert_eq!(rows.len(), 2);
        let origins: Vec<&str> = rows.iter().map(|row| row.origin.as_str()).collect();
        assert_eq!(origins, ["third", "second"], "newest first");
    }

    #[tokio::test]
    async fn containers_without_a_store_record_nothing_and_read_empty() {
        let container =
            ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_guardrails(
                Guardrails::new(GuardrailPolicy::default(), Arc::new(DenyAll)),
            );

        container
            .authorize_recorded(Action::Discover, "unit_origin", None)
            .await
            .unwrap();

        assert!(container.policy_decisions(10).await.unwrap().is_empty());
    }
}
