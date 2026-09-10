//! Resolve allocation evidence and authority in the service, not presentation code.
use super::{
    canonical_project_root, ensure_workspace_directory, initialize_workspace_root,
    project_identity, project_lookup_identity, qualified_target_selector, stored_project_matches,
    workspace_root, ClassifiedError, HarnessStatus, Path, ServiceContainer, Uuid,
};
use crate::campaign_allocation::{
    invalid, make_proposal, AllocationCandidate, AllocationGrant, AllocationRequest,
    AllocationStatus, AllocationStore, AllocationView,
};
use sha2::Digest;

fn allocation_store(project: &Path) -> AllocationStore {
    AllocationStore::new(
        &workspace_root().join("allocations-v1"),
        project_lookup_identity(project),
    )
}
async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, ClassifiedError> + Send + 'static,
) -> Result<T, ClassifiedError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| ClassifiedError::Internal(format!("allocation worker failed: {error}")))?
}

impl ServiceContainer {
    /// Resolve active, explicitly promoted harness identities for operator selection.
    ///
    /// # Errors
    /// Returns unavailable storage, feature, project or qualification errors.
    pub async fn allocation_candidates(
        &self,
        project: &Path,
    ) -> Result<Vec<AllocationCandidate>, ClassifiedError> {
        if !cfg!(feature = "campaign-allocation") {
            return Err(invalid("campaign-allocation is disabled"));
        }
        let project = canonical_project_root(project)?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| invalid("allocation requires persistent storage"))?;
        let mut candidates = Vec::new();
        for target in store
            .list_all_targets()
            .await?
            .into_iter()
            .filter(|target| stored_project_matches(&target.project_root, &project))
        {
            let selector = qualified_target_selector(&target);
            let active_ids = [&target.symbol, &selector]
                .into_iter()
                .filter_map(|name| {
                    super::harness_workspace::read_current_harness_id(&super::workspace_dir(
                        &project, name,
                    ))
                })
                .collect::<Vec<_>>();
            for harness in store
                .list_harnesses(target.id)
                .await?
                .into_iter()
                .filter(|harness| {
                    harness.status == HarnessStatus::Promoted
                        && (active_ids.is_empty() || active_ids.contains(&harness.id))
                })
            {
                let qualification_id = harness
                    .smoke_run
                    .as_ref()
                    .and_then(|smoke| smoke.run_id)
                    .ok_or_else(|| {
                        invalid("promoted harness lacks retained qualification; qualify it again")
                    })?;
                let qualification = self.run_record(qualification_id).await?;
                if !stored_project_matches(Path::new(&qualification.project_root), &project)
                    || qualification
                        .config
                        .as_ref()
                        .is_none_or(|config| config.harness_id != harness.id)
                {
                    return Err(invalid(
                        "allocation qualification ownership does not match its harness",
                    ));
                }
                let dispatch_target =
                    project_identity::retained_run_target_selector(&qualification, &target)?;
                let active = self
                    .active_harness(&project, &dispatch_target, harness.engine)
                    .await?;
                if active.id != harness.id {
                    continue;
                }
                candidates.push(AllocationCandidate {
                    target: selector.clone(),
                    dispatch_target,
                    target_id: target.id,
                    harness_id: harness.id,
                    engine: harness.engine.as_str().into(),
                    language: harness.language.as_str().into(),
                    source_sha256: format!("{:x}", sha2::Sha256::digest(harness.source.as_bytes())),
                });
            }
        }
        candidates.sort_by(|a, b| (&a.target, &a.engine).cmp(&(&b.target, &b.engine)));
        Ok(candidates)
    }

    /// Freeze service-owned evidence and finite quotas without authorizing execution.
    ///
    /// # Errors
    /// Rejects invalid budgets, stale selections, an existing unrevoked plan or storage failure.
    pub async fn propose_allocation(
        &self,
        request: AllocationRequest,
    ) -> Result<AllocationView, ClassifiedError> {
        let project = canonical_project_root(Path::new(&request.project))?;
        if request.harness_ids.is_empty() || request.harness_ids.len() > 64 {
            return Err(invalid("select 1–64 promoted harnesses"));
        }
        let ids = request
            .harness_ids
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if ids.len() != request.harness_ids.len() {
            return Err(invalid("duplicate allocation harness selection"));
        }
        let candidates = self
            .allocation_candidates(&project)
            .await?
            .into_iter()
            .filter(|candidate| ids.contains(&candidate.harness_id))
            .collect::<Vec<_>>();
        if candidates.len() != ids.len() {
            return Err(invalid("selected harness is missing, belongs to another project, or is no longer active and promoted"));
        }
        let history = self.run_history(Some(&project)).await?;
        let proposal = make_proposal(
            &project,
            candidates,
            &history,
            request.max_runs,
            request.max_total_secs,
        )?;
        blocking(move || {
            let root = initialize_workspace_root()?;
            ensure_workspace_directory(&root, Path::new("allocations-v1"))?;
            allocation_store(&project).propose(proposal)
        })
        .await
    }

    /// Inspect exact review and consumed reservations without changing them.
    ///
    /// # Errors
    /// Returns corrupt or unreadable retained state.
    pub async fn allocation_status(
        &self,
        project: &Path,
    ) -> Result<Option<AllocationView>, ClassifiedError> {
        let store = allocation_store(project);
        blocking(move || store.inspect()).await
    }

    /// Approve an exact draft or revoke future admissions. Issued grants stay charged.
    ///
    /// # Errors
    /// Rejects stale IDs/digests, invalid review transitions and storage errors.
    pub async fn review_allocation(
        &self,
        project: &Path,
        id: Uuid,
        digest: &str,
        approve: bool,
    ) -> Result<AllocationView, ClassifiedError> {
        if approve && !cfg!(feature = "campaign-allocation") {
            return Err(invalid("campaign-allocation is disabled"));
        }
        let store = allocation_store(project);
        let digest = digest.to_owned();
        blocking(move || store.review(id, &digest, approve)).await
    }

    pub(crate) async fn admit_scheduled_allocation(
        &self,
        project: &Path,
        target: Option<&str>,
        engine: Option<hf_core::engine::EngineKind>,
        schedule: &str,
        requested_secs: u64,
    ) -> Result<Option<AllocationGrant>, ClassifiedError> {
        let Some(view) = self.allocation_status(project).await? else {
            return Ok(None);
        };
        if view.status != AllocationStatus::Approved {
            return Err(invalid("project allocation is not approved"));
        }
        let target_id = match target.filter(|value| !value.is_empty()) {
            Some(selector) => Some(
                self.resolve_target_id_any_language(project, selector)
                    .await?,
            ),
            None => None,
        };
        let candidates = self
            .allocation_candidates(project)
            .await?
            .into_iter()
            .filter(|candidate| {
                target_id.is_none_or(|id| id == candidate.target_id)
                    && engine.is_none_or(|engine| engine.as_str() == candidate.engine)
            })
            .collect::<Vec<_>>();
        let store = allocation_store(project);
        let schedule = schedule.to_owned();
        blocking(move || store.reserve(&schedule, &candidates, requested_secs)).await
    }
}
