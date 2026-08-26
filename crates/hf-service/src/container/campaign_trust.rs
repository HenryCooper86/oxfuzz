//! Gathering for the Campaign Trust Report.
//!
//! The audit itself is pure (`crate::campaign_trust`); this reads the retained
//! records it rules on. Absence of a record becomes `Unavailable` evidence, so
//! a missing measurement never arrives as a negative determination.

use std::path::Path;

use uuid::Uuid;

use crate::campaign_trust::{
    assess_campaign_trust, CampaignTrustInput, CampaignTrustReport, CorpusEvidence,
    CoverageEvidence, HarnessEvidence, RunEvidence, TriageEvidence,
};
use crate::container::ServiceContainer;
use crate::ClassifiedError;
use hf_core::harness::HarnessStatus;

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

        // Without a harness record there is no target to scope the corpus or
        // the coverage measurement to, so both stay unavailable rather than
        // being read against a guessed target.
        let target_id = harness.as_ref().map_or_else(Uuid::nil, |h| h.target_id);

        let harness_evidence = harness.as_ref().map_or(HarnessEvidence::Unavailable, |h| {
            HarnessEvidence::Retained {
                record_id: h.id,
                compiled: !matches!(h.status, HarnessStatus::Draft | HarnessStatus::Failed),
                smoke_passed: h.smoke_run.as_ref().is_some_and(|s| s.passed),
                // Compilation already blocks on a lint error, so a harness that
                // compiled carries none. Re-linting retained source here would
                // give one rule two homes.
                blocking_lint_findings: 0,
            }
        });

        let corpus_evidence = if harness.is_some() {
            let entries = store
                .list_corpus_entries(target_id)
                .await
                .map_err(|e| ClassifiedError::Validation(e.to_string()))?;
            CorpusEvidence::Retained {
                entries: entries.len(),
            }
        } else {
            CorpusEvidence::Unavailable
        };

        let coverage_evidence = self.coverage_evidence(&run, target_id).await;

        let crashes = store
            .list_crashes_by_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Validation(e.to_string()))?;
        let triage = triage_evidence(&crashes);

        Ok(assess_campaign_trust(&CampaignTrustInput {
            run_id,
            target_id,
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

    /// Coverage evidence for the run's target, from the cached measurement.
    ///
    /// Never triggers a measurement. A target whose symbol cannot be resolved,
    /// or whose measurement has not been produced, yields `Unavailable`.
    async fn coverage_evidence(
        &self,
        run: &hf_storage::RunRecord,
        target_id: Uuid,
    ) -> CoverageEvidence {
        let Some(store) = self.store() else {
            return CoverageEvidence::Unavailable;
        };
        let Ok(targets) = store.list_all_targets().await else {
            return CoverageEvidence::Unavailable;
        };
        let Some(target) = targets.into_iter().find(|t| t.id == target_id) else {
            return CoverageEvidence::Unavailable;
        };

        let covered = self
            .coverage_functions(Path::new(&run.project_root), &target.symbol)
            .await;
        if covered.is_empty() {
            // No cached export exists, or it recorded nothing. Either way this
            // is an absent measurement, not a measurement that found nothing:
            // `coverage_functions` cannot distinguish the two, so the weaker
            // and honest reading is the one reported.
            return CoverageEvidence::Unavailable;
        }
        let target_attributed = covered
            .iter()
            .filter(|name| !hf_crash::is_harness_function(name))
            .count();
        CoverageEvidence::Retained {
            record_id: run.id,
            covered_functions: covered.len(),
            target_attributed_functions: target_attributed,
        }
    }
}

fn triage_evidence(crashes: &[hf_core::crash::Crash]) -> TriageEvidence {
    use crate::finding_proof::finding_proof_card;
    use crate::triage_disposition::{triage_disposition, Disposition};
    use hf_core::crash::CrashOrigin;

    let attributed = crashes
        .iter()
        .filter(|c| c.origin != CrashOrigin::Unknown)
        .count();
    let reportable = crashes
        .iter()
        .filter(|c| {
            matches!(
                triage_disposition(c, &finding_proof_card(c)).disposition,
                Disposition::ReportReady | Disposition::ReachabilityUnproven
            )
        })
        .count();
    TriageEvidence {
        crashes: crashes.len(),
        attributed,
        reportable,
    }
}
