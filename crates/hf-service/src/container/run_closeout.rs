//! Execution of the run closeout chain.
//!
//! The ladder, the outcome vocabulary, and the resume rule live in
//! `crate::run_closeout`. This runs the chain, composing service operations
//! that already exist and implementing none of their logic.
//!
//! Each step's terminal outcome is written before the next begins, so a
//! closeout interrupted after coverage resumes at blocker exploration rather
//! than repeating the corpus replay that coverage measurement performs.

use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::container::ServiceContainer;
use crate::run_closeout::{
    blocked_by, closeout_ladder, pending_steps, CloseoutReport, CloseoutStep, CloseoutStepRecord,
    StepOutcome, RUN_CLOSEOUT_SCHEMA_VERSION,
};
use crate::ClassifiedError;

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

        let mut recorded = self.recorded_steps(run_id).await?;
        let pending = pending_steps(&recorded);
        let resumed_at = (pending.len() < closeout_ladder().len())
            .then(|| pending.first().copied())
            .flatten();

        for step in pending {
            let outcome = match blocked_by(step, &recorded) {
                Some(dependency) => StepOutcome::Skipped {
                    reason: format!("{dependency:?} failed, and this step reads its output"),
                },
                None => self.run_step(step, run_id, &scope).await,
            };
            let (name, label, detail) = encode(step, &outcome);
            store
                .record_closeout_step(run_id, &name, label, &detail)
                .await
                .map_err(|e| ClassifiedError::Storage(e.to_string()))?;
            recorded.push((step, outcome));
        }

        let steps = closeout_ladder()
            .into_iter()
            .filter_map(|step| {
                recorded
                    .iter()
                    .find(|(done, _)| *done == step)
                    .map(|(_, outcome)| CloseoutStepRecord {
                        step,
                        outcome: outcome.clone(),
                    })
            })
            .collect();

        Ok(CloseoutReport {
            schema_version: RUN_CLOSEOUT_SCHEMA_VERSION,
            run_id,
            steps,
            resumed_at,
        })
    }

    /// The project and target the run belongs to.
    async fn run_scope(&self, run_id: Uuid) -> Result<RunScope, ClassifiedError> {
        let store = self.store().ok_or_else(|| {
            ClassifiedError::Validation("run closeout requires the persistent store".to_owned())
        })?;
        let run = store
            .get_run(run_id)
            .await
            .map_err(|e| ClassifiedError::Storage(e.to_string()))?
            .ok_or_else(|| ClassifiedError::Validation(format!("run '{run_id}' not found")))?;
        let harness_id = run
            .config
            .as_ref()
            .map(|config| config.harness_id)
            .ok_or_else(|| {
                ClassifiedError::Validation(format!("run '{run_id}' retained no run configuration"))
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
        Ok(RunScope {
            project: PathBuf::from(run.project_root),
            target: target.symbol,
        })
    }

    /// Outcomes already recorded for a run, decoded back into the ladder's
    /// vocabulary. An unrecognized row is ignored rather than guessed at, so a
    /// step recorded by a newer version simply re-runs.
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
        Ok(rows
            .into_iter()
            .filter_map(|(step, outcome, detail)| {
                Some((decode_step(&step)?, decode(&outcome, detail)?))
            })
            .collect())
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
            CloseoutStep::Coverage => match self.coverage_summary(project, target).await {
                Some(summary) => StepOutcome::Completed {
                    detail: format!("{:.1}% of lines covered", summary.line_percent()),
                },
                None => StepOutcome::Skipped {
                    reason: "no coverage measurement is available for this harness".to_owned(),
                },
            },
            CloseoutStep::Blockers => self.closeout_blockers(project, target).await,
            CloseoutStep::Disposition => self.closeout_disposition(run_id).await,
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
                    detail: format!("{already} of {} crash(es) minimized", crashes.len()),
                }
            }
            Err(error) => StepOutcome::Failed {
                error: error.to_string(),
            },
        }
    }

    /// Blocker exploration over the retained coverage measurement.
    async fn closeout_blockers(&self, project: &Path, target: &str) -> StepOutcome {
        #[cfg(feature = "coverage-blockers")]
        {
            use crate::coverage_blockers::CoverageBlockerRequest;
            let request = CoverageBlockerRequest {
                project: project.to_string_lossy().into_owned(),
                target: target.to_owned(),
                lang: hf_core::target::TargetLanguage::C,
            };
            return match self.explore_coverage_blockers(request).await {
                Ok(view) => StepOutcome::Completed {
                    detail: format!("{} blocker(s) ranked", view.blockers.len()),
                },
                Err(error) => StepOutcome::Failed {
                    error: error.to_string(),
                },
            };
        }
        #[cfg(not(feature = "coverage-blockers"))]
        {
            let _ = (project, target);
            StepOutcome::Skipped {
                reason: "coverage blockers are not enabled in this build".to_owned(),
            }
        }
    }

    /// Disposition derivation over the run's retained crashes.
    async fn closeout_disposition(&self, run_id: Uuid) -> StepOutcome {
        use crate::finding_proof::finding_proof_card;
        use crate::triage_disposition::{triage_disposition, Disposition};

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
                // Dispositions are derived on read rather than stored, so the
                // useful output of this step is the shape of the queue it
                // produces, not a count of derivations performed.
                let harness_defects = crashes
                    .iter()
                    .filter(|crash| {
                        triage_disposition(crash, &finding_proof_card(crash)).disposition
                            == Disposition::HarnessDefect
                    })
                    .count();
                StepOutcome::Completed {
                    detail: format!(
                        "{} crash(es) dispositioned, {harness_defects} of them harness defects",
                        crashes.len()
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
        StepOutcome::Failed { error } => (name, "failed", error.clone()),
    }
}

fn decode_step(name: &str) -> Option<CloseoutStep> {
    closeout_ladder()
        .into_iter()
        .find(|step| format!("{step:?}") == name)
}

fn decode(outcome: &str, detail: String) -> Option<StepOutcome> {
    match outcome {
        "completed" => Some(StepOutcome::Completed { detail }),
        "skipped" => Some(StepOutcome::Skipped { reason: detail }),
        "failed" => Some(StepOutcome::Failed { error: detail }),
        _ => None,
    }
}
