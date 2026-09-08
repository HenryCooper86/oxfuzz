//! Execution of the run closeout chain.
//!
//! The ladder, the outcome vocabulary, and the resume rule live in
//! `crate::run_closeout`. This runs the chain, composing service operations
//! that already exist and implementing none of their logic.
//!
//! Each step's terminal outcome is written before the next begins. Coverage
//! and blocker rows written by older versions are projected to unavailable
//! because they were derived from mutable workspace state.

use std::path::PathBuf;

use uuid::Uuid;

use super::project_identity::stored_project_matches;
use crate::container::ServiceContainer;
use crate::run_closeout::{
    blocked_by, closeout_ladder, decode_outcome, decode_step, pending_steps, CloseoutAvailability,
    CloseoutReport, CloseoutStep, CloseoutStepRecord, StepOutcome, RUN_CLOSEOUT_SCHEMA_VERSION,
};
use crate::ClassifiedError;
use hf_storage::{RunKind, RunStatus};

/// What every step needs to address the run it is closing out.
struct RunScope {
    project: PathBuf,
    target: String,
}

impl ServiceContainer {
    /// Run the closeout chain for one finished run.
    ///
    /// Resumes at the first step without a terminal outcome, so a repeated
    /// invocation over a finished closeout reports the retained result without
    /// redoing work. A failed step does not abort the chain: steps that do not
    /// consume its output still run.
    ///
    /// Closeout performs sandboxed work and is therefore invoked deliberately
    /// rather than fired automatically when a run ends (AGENTS.md 2.12).
    ///
    /// # Errors
    /// Returns `ClassifiedError::Validation` when the run is unknown, its
    /// target cannot be resolved, or the store is not configured.
    pub async fn close_out_run(&self, run_id: Uuid) -> Result<CloseoutReport, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("run closeout requires the persistent store".to_owned())
        })?;
        let scope = self.run_scope(run_id).await?;
        let _closeout_lease = super::acquire_run_closeout_lease(run_id)?;

        let mut recorded = self.recorded_steps(run_id).await?;
        project_legacy_workspace_evidence(&mut recorded, true);
        let initial_pending = pending_steps(&recorded);
        if let Some(changed_step) = initial_pending
            .iter()
            .copied()
            .find(|step| *step != CloseoutStep::TrustReport)
        {
            let trust_is_terminal = recorded
                .iter()
                .any(|(step, outcome)| *step == CloseoutStep::TrustReport && outcome.is_terminal());
            if trust_is_terminal {
                let invalidated = StepOutcome::Blocked {
                    dependency: changed_step,
                };
                let (name, label, detail) = encode(CloseoutStep::TrustReport, &invalidated);
                store
                    .record_closeout_step(run_id, &name, label, &detail)
                    .await
                    .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
                replace_recorded(&mut recorded, CloseoutStep::TrustReport, invalidated);
            }
        }
        let pending = pending_steps(&recorded);
        let resumed_at = (pending.len() < closeout_ladder().len())
            .then(|| pending.first().copied())
            .flatten();

        for step in pending {
            let outcome = match blocked_by(step, &recorded) {
                Some(dependency) => StepOutcome::Blocked { dependency },
                None => self.run_step(step, run_id, &scope).await,
            };
            let (name, label, detail) = encode(step, &outcome);
            store
                .record_closeout_step(run_id, &name, label, &detail)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
            replace_recorded(&mut recorded, step, outcome);
        }
        Ok(report_from_recorded(
            run_id,
            CloseoutAvailability::Available,
            &recorded,
            resumed_at,
        ))
    }

    /// Read retained closeout state without running or resuming any step.
    pub async fn retained_run_closeout(
        &self,
        run_id: Uuid,
    ) -> Result<CloseoutReport, ClassifiedError> {
        let mut recorded = self.recorded_steps(run_id).await?;
        project_legacy_workspace_evidence(&mut recorded, false);
        let availability = match self.run_scope(run_id).await {
            Ok(_) => CloseoutAvailability::Available,
            Err(ClassifiedError::Validation(reason)) => {
                CloseoutAvailability::Unavailable { reason }
            }
            Err(error) => return Err(error),
        };
        let pending = pending_steps(&recorded);
        let resumed_at = (!recorded.is_empty())
            .then(|| pending.first().copied())
            .flatten();
        Ok(report_from_recorded(
            run_id,
            availability,
            &recorded,
            resumed_at,
        ))
    }

    /// The project and target the run belongs to.
    async fn run_scope(&self, run_id: Uuid) -> Result<RunScope, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("run closeout requires the persistent store".to_owned())
        })?;
        let run = self.run_record(run_id).await?;
        if run.kind != RunKind::Campaign {
            return Err(ClassifiedError::Validation(format!(
                "run '{run_id}' is not a campaign run"
            )));
        }
        if !matches!(
            run.status,
            RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled
        ) {
            return Err(ClassifiedError::Validation(format!(
                "run '{run_id}' is not terminal"
            )));
        }
        let harness_id = run
            .config
            .as_ref()
            .map(|config| config.harness_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "run '{run_id}' retained no harness-backed target; closeout is unavailable"
                ))
            })?;
        let harness = store
            .get_harness(harness_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run '{run_id}' names an unknown harness"))
            })?;
        let targets = store
            .list_all_targets()
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        let target = targets
            .into_iter()
            .find(|candidate| candidate.id == harness.target_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run '{run_id}' names an unknown target"))
            })?;
        if !stored_project_matches(
            &target.project_root,
            std::path::Path::new(&run.project_root),
        ) {
            return Err(ClassifiedError::Validation(format!(
                "run '{run_id}' target project does not match its retained project"
            )));
        }
        let selector = super::project_identity::retained_run_target_selector(&run, &target)?;
        Ok(RunScope {
            project: PathBuf::from(run.project_root),
            target: selector,
        })
    }

    /// Outcomes already recorded for a run, decoded back into the ladder's
    /// vocabulary. An unrecognized row is a durable-data error.
    async fn recorded_steps(
        &self,
        run_id: Uuid,
    ) -> Result<Vec<(CloseoutStep, StepOutcome)>, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("run closeout requires the persistent store".to_owned())
        })?;
        let rows = store
            .closeout_steps(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
        rows.into_iter()
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
            .collect()
    }

    /// Run one step, turning any failure into a recorded outcome rather than
    /// aborting the chain.
    async fn run_step(&self, step: CloseoutStep, run_id: Uuid, scope: &RunScope) -> StepOutcome {
        let project = scope.project.as_path();
        let target = scope.target.as_str();
        match step {
            CloseoutStep::Triage => match self.triage_run(project, target, run_id).await {
                Ok(crashes) => StepOutcome::Completed {
                    detail: format!("{} crash(es) attributed", crashes.len()),
                },
                Err(error) => StepOutcome::Failed {
                    error: error.to_string(),
                },
            },
            CloseoutStep::Minimize => self.closeout_minimize(run_id).await,
            CloseoutStep::CorpusAbsorb => {
                match self
                    .corpus_absorb_crashes_for_run(project, target, run_id)
                    .await
                {
                    Ok(count) => StepOutcome::Completed {
                        detail: format!("{count} input(s) absorbed"),
                    },
                    Err(error) => StepOutcome::Failed {
                        error: error.to_string(),
                    },
                }
            }
            CloseoutStep::Coverage => StepOutcome::Skipped {
                reason: "exact run-bound source coverage is unavailable; use current-workspace coverage analysis separately".to_owned(),
            },
            CloseoutStep::Blockers => StepOutcome::Skipped {
                reason: "exact run-bound coverage blockers are unavailable; use current-workspace blocker analysis separately".to_owned(),
            },
            CloseoutStep::Disposition => self.closeout_disposition(project, run_id).await,
            CloseoutStep::TrustReport => match self.campaign_trust_report(run_id).await {
                Ok(report) => StepOutcome::Completed {
                    detail: format!("{:?}", report.determination),
                },
                Err(error) => StepOutcome::Failed {
                    error: error.to_string(),
                },
            },
        }
    }

    /// Minimization, skipped when triage retained nothing to minimize.
    async fn closeout_minimize(&self, run_id: Uuid) -> StepOutcome {
        let Some(store) = self.store() else {
            return StepOutcome::Failed {
                error: "no persistent store".to_owned(),
            };
        };
        match store.list_crashes_by_run(run_id).await {
            Ok(crashes) if crashes.is_empty() => StepOutcome::Skipped {
                reason: "the run retained no crashes".to_owned(),
            },
            Ok(crashes) => {
                let already = crashes.iter().filter(|crash| crash.minimized).count();
                StepOutcome::Completed {
                    detail: format!(
                        "triage retained {already} of {} crash(es) as already minimized",
                        crashes.len()
                    ),
                }
            }
            Err(error) => StepOutcome::Failed {
                error: error.to_string(),
            },
        }
    }

    /// Disposition derivation over the run's retained crashes.
    async fn closeout_disposition(&self, project: &std::path::Path, run_id: Uuid) -> StepOutcome {
        use crate::finding_review::{FindingDispositionFilter, FindingReviewFilter};
        use crate::triage_disposition::Disposition;

        let filter = FindingReviewFilter {
            run_id: Some(run_id),
            disposition: FindingDispositionFilter::All,
            ..FindingReviewFilter::default()
        };
        match self.finding_review_queue(project, filter).await {
            Ok(items) if items.is_empty() => StepOutcome::Skipped {
                reason: "the run retained no crashes".to_owned(),
            },
            Ok(items) => {
                let harness_defects = items
                    .iter()
                    .filter(|item| item.disposition.disposition == Disposition::HarnessDefect)
                    .count();
                StepOutcome::Completed {
                    detail: format!(
                        "{} crash(es) dispositioned, {harness_defects} of them harness defects",
                        items.len()
                    ),
                }
            }
            Err(error) => StepOutcome::Failed {
                error: error.to_string(),
            },
        }
    }
}

/// The persisted spelling of a step and its outcome.
fn encode(step: CloseoutStep, outcome: &StepOutcome) -> (String, &'static str, String) {
    let name = format!("{step:?}");
    match outcome {
        StepOutcome::Completed { detail } => (name, "completed", detail.clone()),
        StepOutcome::Skipped { reason } => (name, "skipped", reason.clone()),
        StepOutcome::Blocked { dependency } => (name, "blocked", format!("{dependency:?}")),
        StepOutcome::Failed { error } => (name, "failed", error.clone()),
    }
}

fn replace_recorded(
    recorded: &mut Vec<(CloseoutStep, StepOutcome)>,
    step: CloseoutStep,
    outcome: StepOutcome,
) {
    recorded.retain(|(recorded_step, _)| *recorded_step != step);
    recorded.push((step, outcome));
}

fn project_legacy_workspace_evidence(recorded: &mut Vec<(CloseoutStep, StepOutcome)>, retry: bool) {
    let mut projected_legacy = false;
    for (step, reason) in [
        (
            CloseoutStep::Coverage,
            "exact run-bound source coverage is unavailable; use current-workspace coverage analysis separately",
        ),
        (
            CloseoutStep::Blockers,
            "exact run-bound coverage blockers are unavailable; use current-workspace blocker analysis separately",
        ),
    ] {
        let legacy_completed = recorded
            .iter()
            .rev()
            .find(|(recorded_step, _)| *recorded_step == step)
            .is_some_and(|(_, outcome)| matches!(outcome, StepOutcome::Completed { .. }));
        if legacy_completed {
            projected_legacy = true;
            let outcome = if retry {
                StepOutcome::Failed {
                    error: reason.to_owned(),
                }
            } else {
                StepOutcome::Skipped {
                    reason: reason.to_owned(),
                }
            };
            replace_recorded(recorded, step, outcome);
        }
    }
    if projected_legacy && !retry {
        replace_recorded(
            recorded,
            CloseoutStep::TrustReport,
            StepOutcome::Blocked {
                dependency: CloseoutStep::Coverage,
            },
        );
    }
}

fn report_from_recorded(
    run_id: Uuid,
    availability: CloseoutAvailability,
    recorded: &[(CloseoutStep, StepOutcome)],
    resumed_at: Option<CloseoutStep>,
) -> CloseoutReport {
    let steps = closeout_ladder()
        .into_iter()
        .filter_map(|step| {
            recorded
                .iter()
                .rev()
                .find(|(done, _)| *done == step)
                .map(|(_, outcome)| CloseoutStepRecord {
                    step,
                    outcome: outcome.clone(),
                })
        })
        .collect();
    CloseoutReport {
        schema_version: RUN_CLOSEOUT_SCHEMA_VERSION,
        run_id,
        availability,
        steps,
        resumed_at,
    }
}
