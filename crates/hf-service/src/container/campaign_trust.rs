//! Gathering for the Campaign Trust Report.
//!
//! The audit itself is pure (`crate::campaign_trust`); this reads the retained
//! records it rules on. Absence of a record becomes `Unavailable` evidence, so
//! a missing measurement never arrives as a negative determination.

use std::path::Path;
use uuid::Uuid;

use super::project_identity::stored_project_matches;
use crate::campaign_trust::{
    assess_campaign_trust, CampaignTrustInput, CampaignTrustReport, CorpusEvidence,
    CoverageEvidence, HarnessEvidence, RunEvidence, TriageEvidence,
};
use crate::container::ServiceContainer;
use crate::finding_review::{FindingDispositionFilter, FindingReviewFilter, FindingReviewItem};
use crate::run_closeout::{decode_outcome, decode_step, CloseoutStep, StepOutcome};
use crate::ClassifiedError;

impl ServiceContainer {
    /// Audit one run's evidence and report which claims it licenses.
    ///
    /// Reads only retained records. Starts no build, no run, and no coverage
    /// measurement: a measurement that has not happened is reported as absent
    /// rather than produced on demand, because producing one here would make an
    /// audit a side-effecting operation.
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the run is unknown or the
    /// persistent store is not configured.
    pub async fn campaign_trust_report(
        &self,
        run_id: Uuid,
    ) -> Result<CampaignTrustReport, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("campaign trust requires the persistent store".to_owned())
        })?;

        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Validation(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run '{run_id}' not found")))?;

        let harness = match run.config.as_ref().map(|config| config.harness_id) {
            Some(id) => store
                .get_harness(id)
                .await
                .map_err(|e| ClassifiedError::Validation(e.to_string()))?,
            None => None,
        };

        let target = if let Some(harness) = &harness {
            let target = store
                .list_all_targets()
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?
                .into_iter()
                .find(|target| target.id == harness.target_id)
                .ok_or_else(|| {
                    ClassifiedError::Validation(format!("run '{run_id}' names an unknown target"))
                })?;
            if !stored_project_matches(&target.project_root, Path::new(&run.project_root)) {
                return Err(ClassifiedError::Validation(format!(
                    "run '{run_id}' target project does not match its retained project"
                )));
            }
            Some(target)
        } else {
            None
        };

        let target_id = harness.as_ref().map_or_else(Uuid::nil, |h| h.target_id);

        let harness_evidence = match (
            harness.as_ref(),
            run.harness_rev.as_deref(),
            run.binary_rev.as_deref(),
        ) {
            (Some(harness), Some(source), Some(binary)) => store
                .harness_approval(harness.id, source, binary)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?
                .map_or(HarnessEvidence::Unavailable, |approval| {
                    HarnessEvidence::Retained {
                        record_id: harness.id,
                        compiled: true,
                        smoke_passed: true,
                        blocking_lint_findings: 0,
                        approval_kind: approval.approval_kind,
                    }
                }),
            _ => HarnessEvidence::Unavailable,
        };

        // The run retains a corpus digest but not its starting entry count.
        // Current target rows and run-local files can change after the run.
        let corpus_evidence = CorpusEvidence::Unavailable;

        // Aggregate run edges do not identify covered project functions, and
        // the current workspace cache is not evidence for this exact run.
        // Until source coverage is retained with the run, the audit must stay
        // unavailable and must not build or replay anything on demand.
        let coverage_evidence = CoverageEvidence::Unavailable;

        let closeout = store
            .closeout_steps(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .into_iter()
            .map(|(step_name, outcome, detail)| {
                let step = decode_step(&step_name).ok_or_else(|| {
                    ClassifiedError::Storage(format!(
                        "decode retained closeout step '{step_name}' for run '{run_id}'"
                    ))
                })?;
                let outcome = decode_outcome(step, &outcome, detail).ok_or_else(|| {
                    ClassifiedError::Storage(format!(
                        "decode retained closeout outcome '{outcome}' for step '{step_name}' and run '{run_id}'"
                    ))
                })?;
                Ok((step, outcome))
            })
            .collect::<Result<Vec<_>, ClassifiedError>>()?;
        let reviews = self
            .finding_review_queue(
                Path::new(&run.project_root),
                FindingReviewFilter {
                    run_id: Some(run_id),
                    disposition: FindingDispositionFilter::All,
                    ..FindingReviewFilter::default()
                },
            )
            .await?;
        let triage = triage_evidence(&closeout, run.crash_count, &reviews);

        Ok(assess_campaign_trust(&CampaignTrustInput {
            run_id,
            target_id: target.as_ref().map_or(target_id, |value| value.id),
            harness: harness_evidence,
            corpus: corpus_evidence,
            run: RunEvidence::Retained {
                record_id: run.id,
                status: run.status,
                execs_per_sec: run.execs,
            },
            coverage: coverage_evidence,
            triage,
        }))
    }
}

fn triage_evidence(
    closeout: &[(CloseoutStep, StepOutcome)],
    run_crash_count: Option<u64>,
    items: &[FindingReviewItem],
) -> TriageEvidence {
    use crate::triage_disposition::Disposition;
    use hf_core::crash::CrashOrigin;

    let attributed = items
        .iter()
        .filter(|item| item.crash.origin != CrashOrigin::Unknown)
        .count();
    let reportable = items
        .iter()
        .filter(|item| {
            matches!(
                item.disposition.disposition,
                Disposition::ReportReady | Disposition::ReachabilityUnproven
            )
        })
        .count();
    let counts = TriageEvidence::Retained {
        crashes: items.len(),
        attributed,
        reportable,
    };
    match closeout
        .iter()
        .rev()
        .find(|(step, _)| *step == CloseoutStep::Triage)
        .map(|(_, outcome)| outcome)
    {
        Some(StepOutcome::Completed { .. }) => counts,
        Some(StepOutcome::Failed { .. } | StepOutcome::Blocked { .. }) => {
            TriageEvidence::Unavailable {
                reason: "Crash ingestion did not complete for this run.".to_owned(),
            }
        }
        Some(StepOutcome::Skipped { .. }) => TriageEvidence::Unavailable {
            reason: "Crash ingestion has no successful retained outcome for this run.".to_owned(),
        },
        None if run_crash_count == Some(0) => counts,
        None if run_crash_count.is_some() && !items.is_empty() => counts,
        None => TriageEvidence::Unavailable {
            reason: "Crash ingestion completion is not retained for this run.".to_owned(),
        },
    }
}
