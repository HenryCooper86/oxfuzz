//! Service-owned run closeout ladder.
//!
//! After a run ends, seven things should happen: triage, minimization, corpus
//! absorption, coverage measurement, blocker exploration, disposition
//! derivation, and a trust report. Each already exists and each is invoked
//! separately, so a finished run sits half-analyzed until someone remembers the
//! next command.
//!
//! See `docs/design/run-closeout-design.md`.
//!
//! This module owns the ladder, the outcome vocabulary, and the resume rule.
//! It composes existing service operations and implements none of their logic.

use serde::Serialize;

/// Current serialized Run Closeout schema.
pub const RUN_CLOSEOUT_SCHEMA_VERSION: u32 = 2;

/// One step of the closeout chain.
///
/// Declaration order is execution order, fixed by data dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseoutStep {
    /// Attribute fault origin and produce crash records.
    Triage,
    /// Reduce reproducing inputs.
    Minimize,
    /// Fold run inputs into the retained corpus.
    CorpusAbsorb,
    /// Measure coverage against the absorbed corpus.
    Coverage,
    /// Rank uncovered blockers from that measurement.
    Blockers,
    /// Derive a disposition for each retained crash.
    Disposition,
    /// Audit which claims the closeout's own evidence licenses.
    TrustReport,
}

/// What became of one step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum StepOutcome {
    /// The step ran and produced something.
    Completed {
        /// What it produced.
        detail: String,
    },
    /// The step did not need to run. A run with no crashes skips minimization,
    /// and that is a correct outcome rather than an omission.
    Skipped {
        /// Why it did not need to run.
        reason: String,
    },
    /// An earlier required step failed. This is retryable after the dependency
    /// changes, unlike a legitimate terminal skip.
    Blocked {
        /// The failed step whose output is required.
        dependency: CloseoutStep,
    },
    /// The step ran and failed. Retried by a later closeout.
    Failed {
        /// What went wrong.
        error: String,
    },
}

impl StepOutcome {
    /// Whether this outcome ends the step's work.
    ///
    /// Completed and skipped are terminal. Failure and blocked are retried by a
    /// later closeout.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::Skipped { .. })
    }
}

/// One recorded step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloseoutStepRecord {
    /// Which step.
    pub step: CloseoutStep,
    /// What became of it.
    pub outcome: StepOutcome,
}

/// Whether the retained run has enough exact scope to execute closeout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CloseoutAvailability {
    /// The run is a terminal campaign with a retained harness-backed target.
    Available,
    /// Closeout cannot safely address this retained run.
    Unavailable {
        /// Operator-facing reason owned by the service.
        reason: String,
    },
}

/// One closeout pass over a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CloseoutReport {
    /// Serialization version of this view.
    pub schema_version: u32,
    /// The run closed out.
    pub run_id: uuid::Uuid,
    /// Whether explicit Analyze/Resume is supported for this run.
    pub availability: CloseoutAvailability,
    /// Every step's outcome, in ladder order.
    pub steps: Vec<CloseoutStepRecord>,
    /// The step this pass resumed at, when it resumed rather than started.
    pub resumed_at: Option<CloseoutStep>,
}

/// The closeout chain, in execution order.
///
/// Coverage follows corpus absorption because it measures against the absorbed
/// corpus. The trust report is last because it audits the closeout that
/// produced it, so a step that failed appears as an unavailable gate rather
/// than being silently absent.
#[must_use]
pub fn closeout_ladder() -> Vec<CloseoutStep> {
    vec![
        CloseoutStep::Triage,
        CloseoutStep::Minimize,
        CloseoutStep::CorpusAbsorb,
        CloseoutStep::Coverage,
        CloseoutStep::Blockers,
        CloseoutStep::Disposition,
        CloseoutStep::TrustReport,
    ]
}

/// What each step reads from an earlier one.
///
/// The trust report deliberately consumes nothing: it must run even when every
/// earlier step failed, so those failures surface as unavailable gates.
#[must_use]
pub fn consumes(step: CloseoutStep) -> &'static [CloseoutStep] {
    match step {
        CloseoutStep::Triage | CloseoutStep::TrustReport => &[],
        CloseoutStep::Minimize | CloseoutStep::CorpusAbsorb | CloseoutStep::Disposition => {
            &[CloseoutStep::Triage]
        }
        CloseoutStep::Coverage => &[CloseoutStep::CorpusAbsorb],
        CloseoutStep::Blockers => &[CloseoutStep::Coverage],
    }
}

/// The steps still to run, in ladder order.
///
/// A step with a terminal outcome is done; anything else is pending, so an
/// interrupted closeout resumes at the first step that never reached one.
#[must_use]
pub fn pending_steps(recorded: &[(CloseoutStep, StepOutcome)]) -> Vec<CloseoutStep> {
    closeout_ladder()
        .into_iter()
        .filter(|step| {
            !recorded
                .iter()
                .rev()
                .find(|(done, _)| done == step)
                .is_some_and(|(_, outcome)| outcome.is_terminal())
        })
        .collect()
}

/// The failed step that prevents `step` from running, if any.
///
/// A dependency that has not run yet does not block: the chain is about to
/// start, not obstructed.
#[must_use]
pub fn blocked_by(
    step: CloseoutStep,
    recorded: &[(CloseoutStep, StepOutcome)],
) -> Option<CloseoutStep> {
    consumes(step).iter().copied().find(|dependency| {
        recorded
            .iter()
            .rev()
            .find(|(done, _)| done == dependency)
            .is_some_and(|(_, outcome)| {
                matches!(
                    outcome,
                    StepOutcome::Failed { .. } | StepOutcome::Blocked { .. }
                )
            })
    })
}

/// Decode one retained step name from `SQLite`.
pub(crate) fn decode_step(name: &str) -> Option<CloseoutStep> {
    closeout_ladder()
        .into_iter()
        .find(|step| format!("{step:?}") == name)
}

/// Decode one retained outcome using the current and legacy spellings.
pub(crate) fn decode_outcome(
    step: CloseoutStep,
    outcome: &str,
    detail: String,
) -> Option<StepOutcome> {
    match outcome {
        "completed" => Some(StepOutcome::Completed { detail }),
        "skipped" => {
            let legacy_dependency = consumes(step).iter().copied().find(|dependency| {
                detail == format!("{dependency:?} failed, and this step reads its output")
            });
            legacy_dependency.map_or_else(
                || Some(StepOutcome::Skipped { reason: detail }),
                |dependency| Some(StepOutcome::Blocked { dependency }),
            )
        }
        "blocked" => decode_step(&detail).and_then(|dependency| {
            let valid = if step == CloseoutStep::TrustReport {
                dependency < CloseoutStep::TrustReport
            } else {
                consumes(step).contains(&dependency)
            };
            valid.then_some(StepOutcome::Blocked { dependency })
        }),
        "failed" => Some(StepOutcome::Failed { error: detail }),
        _ => None,
    }
}
