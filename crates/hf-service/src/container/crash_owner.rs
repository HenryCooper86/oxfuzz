//! Durable crash ownership and referenced-record resolution.

use std::path::Path;

use hf_core::crash::Crash;
use hf_core::error::ClassifiedError;
use hf_core::target::TargetCandidate;
use hf_storage::RunRecord;
use uuid::Uuid;

use super::project_identity::{project_lookup_identity, stored_project_matches};
use super::ServiceContainer;

#[cfg(any(feature = "triage-disposition", feature = "patch-to-proof"))]
pub(crate) struct CrashOwner {
    pub crash: Crash,
    pub run: RunRecord,
    pub target: TargetCandidate,
}

impl ServiceContainer {
    async fn resolve_crash_owner_for_project(
        &self,
        project: &Path,
        crash_id: Uuid,
    ) -> Result<(Crash, RunRecord, TargetCandidate), ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Storage("finding review requires persistent storage".to_owned())
        })?;
        let crash = store
            .get_crash(crash_id)
            .await?
            .ok_or_else(|| ClassifiedError::Validation(format!("finding {crash_id} not found")))?;
        let run = store.get_run(crash.run_id).await?.ok_or_else(|| {
            ClassifiedError::Validation(format!(
                "finding {crash_id} names missing run {}",
                crash.run_id
            ))
        })?;
        let target = store
            .list_all_targets()
            .await?
            .into_iter()
            .find(|candidate| candidate.id == crash.target_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "finding {crash_id} names missing target {}",
                    crash.target_id
                ))
            })?;
        let requested = project_lookup_identity(project);
        if !stored_project_matches(Path::new(&run.project_root), &requested)
            || !stored_project_matches(&target.project_root, &requested)
        {
            return Err(ClassifiedError::Validation(format!(
                "finding {crash_id} belongs to project {}, not {}",
                run.project_root,
                project.display()
            )));
        }
        if !stored_project_matches(&target.project_root, Path::new(&run.project_root)) {
            return Err(ClassifiedError::Validation(format!(
                "finding {crash_id} has inconsistent run and target projects"
            )));
        }
        Ok((crash, run, target))
    }

    pub(crate) async fn ensure_crash_owned_by_project(
        &self,
        project: &Path,
        crash_id: Uuid,
    ) -> Result<(), ClassifiedError> {
        self.resolve_crash_owner_for_project(project, crash_id)
            .await
            .map(|_| ())
    }

    #[cfg(any(feature = "triage-disposition", feature = "patch-to-proof"))]
    pub(crate) async fn crash_owner_for_project(
        &self,
        project: &Path,
        crash_id: Uuid,
    ) -> Result<CrashOwner, ClassifiedError> {
        let (crash, run, target) = self
            .resolve_crash_owner_for_project(project, crash_id)
            .await?;
        Ok(CrashOwner { crash, run, target })
    }
}
