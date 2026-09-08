//! Service-owned finding queue and exact retained detail.

use std::collections::HashMap;
use std::path::Path;

use hf_core::error::ClassifiedError;
use hf_storage::RemediationOperationRecord;
use uuid::Uuid;

use crate::finding_review::{FindingDispositionFilter, FindingReviewFilter, FindingReviewItem};
use crate::triage_disposition::Disposition;
use crate::workbench::crash_review_items;

use super::project_identity::{
    project_lookup_identity, retained_run_target_selector, stored_project_matches,
};
use super::ServiceContainer;

const HISTORICAL_ACTION_REASON: &str =
    "This finding belongs to a historical run. Report, reproduction, and DefectDojo actions currently operate on the latest target run.";

impl ServiceContainer {
    /// Return the retained finding queue for one project in service-owned order.
    pub async fn finding_review_queue(
        &self,
        project: &Path,
        filter: FindingReviewFilter,
    ) -> Result<Vec<FindingReviewItem>, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("finding review requires persistent storage".to_owned())
        })?;
        let requested = project_lookup_identity(project);
        let all_targets = store
            .list_all_targets()
            .await?
            .into_iter()
            .map(|target| (target.id, target))
            .collect::<HashMap<_, _>>();
        let targets = all_targets
            .iter()
            .filter(|(_, target)| stored_project_matches(&target.project_root, &requested))
            .map(|(id, target)| (*id, target.clone()))
            .collect::<HashMap<_, _>>();
        let newest_first_runs = store.list_runs(None).await?;
        let all_runs = newest_first_runs
            .iter()
            .cloned()
            .map(|run| (run.id, run))
            .collect::<HashMap<_, _>>();
        let project_run_ids = all_runs
            .iter()
            .filter(|(_, run)| stored_project_matches(Path::new(&run.project_root), &requested))
            .map(|(id, _)| *id)
            .collect::<std::collections::HashSet<_>>();
        let crashes = store
            .list_all_crashes()
            .await?
            .into_iter()
            .filter(|crash| {
                targets.contains_key(&crash.target_id) || project_run_ids.contains(&crash.run_id)
            })
            .collect::<Vec<_>>();

        for crash in &crashes {
            let run = all_runs.get(&crash.run_id).ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "finding {} names missing run {}",
                    crash.id, crash.run_id
                ))
            })?;
            let target = all_targets.get(&crash.target_id).ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "finding {} names missing target {}",
                    crash.id, crash.target_id
                ))
            })?;
            if !stored_project_matches(Path::new(&run.project_root), &requested)
                || !stored_project_matches(&target.project_root, &requested)
                || !stored_project_matches(&target.project_root, Path::new(&run.project_root))
            {
                return Err(ClassifiedError::Validation(format!(
                    "finding {} has inconsistent run and target projects",
                    crash.id
                )));
            }
        }

        let latest_run_by_target = self
            .latest_run_records_for_targets(
                project,
                crashes.iter().map(|crash| crash.target_id).collect(),
                &newest_first_runs,
            )
            .await?;

        #[cfg(feature = "patch-to-proof")]
        let remediation_by_crash: HashMap<Uuid, RemediationOperationRecord> = {
            let mut records = HashMap::new();
            for crash in &crashes {
                if let Some(record) = store.latest_remediation_for_finding(crash.id).await? {
                    records.insert(crash.id, record);
                }
            }
            records
        };
        #[cfg(not(feature = "patch-to-proof"))]
        let remediation_by_crash: HashMap<Uuid, RemediationOperationRecord> = HashMap::new();

        let reviews = crash_review_items(crashes.clone(), &targets, &remediation_by_crash);
        let crash_by_id = crashes
            .into_iter()
            .map(|crash| (crash.id, crash))
            .collect::<HashMap<_, _>>();
        let mut items = Vec::with_capacity(reviews.len());
        for review in reviews {
            let crash_id = Uuid::parse_str(&review.crash_id).map_err(|error| {
                ClassifiedError::Storage(format!("decode retained crash id: {error}"))
            })?;
            let crash = crash_by_id.get(&crash_id).cloned().ok_or_else(|| {
                ClassifiedError::Storage(format!("review lost retained finding {crash_id}"))
            })?;
            let run = all_runs.get(&crash.run_id).ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "finding {} names missing run {}",
                    crash.id, crash.run_id
                ))
            })?;
            let target = targets.get(&crash.target_id).ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "finding {} names missing target {}",
                    crash.id, crash.target_id
                ))
            })?;
            let latest = latest_run_by_target.get(&target.id).map(|run| run.id) == Some(run.id);
            let target_selector = retained_run_target_selector(run, target)?;
            let item = FindingReviewItem {
                crash,
                project_root: run.project_root.clone(),
                target_id: target.id,
                target_symbol: target.symbol.clone(),
                target_selector,
                target_language: target.language,
                engine: run.engine,
                proof: review.proof,
                disposition: review.disposition,
                latest_scoped_actions_allowed: latest,
                latest_scoped_action_reason: (!latest).then(|| HISTORICAL_ACTION_REASON.to_owned()),
            };
            if matches_filter(&item, &filter) {
                items.push(item);
            }
        }
        Ok(items)
    }

    /// Resolve one finding by its persisted identity and require project ownership.
    pub async fn finding_review_for_project(
        &self,
        project: &Path,
        crash_id: Uuid,
    ) -> Result<FindingReviewItem, ClassifiedError> {
        let owner = self.crash_owner_for_project(project, crash_id).await?;
        let mut filter = FindingReviewFilter {
            run_id: Some(owner.run.id),
            disposition: FindingDispositionFilter::All,
            ..FindingReviewFilter::default()
        };
        filter.target_id = Some(owner.target.id);
        self.finding_review_queue(project, filter)
            .await?
            .into_iter()
            .find(|item| item.crash.id == owner.crash.id)
            .ok_or_else(|| ClassifiedError::Validation(format!("finding {crash_id} not found")))
    }
}

fn matches_filter(item: &FindingReviewItem, filter: &FindingReviewFilter) -> bool {
    filter.target_id.is_none_or(|id| item.target_id == id)
        && filter.run_id.is_none_or(|id| item.crash.run_id == id)
        && match filter.disposition {
            FindingDispositionFilter::Open => item.disposition.disposition != Disposition::Resolved,
            FindingDispositionFilter::All => true,
            FindingDispositionFilter::Only(disposition) => {
                item.disposition.disposition == disposition
            }
        }
        && filter
            .origin
            .is_none_or(|origin| item.crash.origin == origin)
        && filter
            .severity
            .is_none_or(|severity| item.proof.casr_exploitability.determination == severity)
}
