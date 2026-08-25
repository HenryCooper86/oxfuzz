//! Sequence-aware planning and protocol-state coverage over retained automotive
//! evidence.
//!
//! A single request tells you little about a protocol implementation whose
//! defects depend on the order of calls. This reports which protocol states the
//! retained evidence actually reached and produces an ordered, reviewable plan
//! for reaching what it has not.
//!
//! Plans cover `OfflinePcap` and `VirtualCan` only. The physical bench gains no
//! sequence path: each physical transmission requires a fresh, single-use human
//! approval, and a sequence runner would convert one approval into many
//! transmissions. Nothing here executes or opens an interface.
//!
//! See `docs/design/automotive-protocol-fuzzing-design.md`, section 8.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use hf_automotive::{AutomotiveMode, AutomotiveProtocol, StateSignature};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema version of the lab views.
pub const AUTOMOTIVE_LAB_SCHEMA_VERSION: u32 = 1;

/// Cap on planned steps, so a wide model cannot produce an unreviewable plan.
pub const MAX_PLAN_STEPS: usize = 64;

/// One state the retained evidence shows was reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedStateEvidence {
    pub signature: StateSignature,
    /// Operation that produced the observation.
    pub source_operation_id: Uuid,
    pub observed_at: DateTime<Utc>,
}

/// A reviewed model of the states a protocol is expected to have.
///
/// Supplied explicitly. Retained evidence cannot establish how many states
/// exist, so without a model there is no denominator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateModel {
    pub name: String,
    /// Expected state digests.
    pub states: Vec<String>,
}

/// One distinct state, as the evidence recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedState {
    pub digest: String,
    pub source_operation_id: Uuid,
    pub first_observed_at: DateTime<Utc>,
    pub last_observed_at: DateTime<Utc>,
}

/// What the retained evidence shows about a protocol's states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProtocolStateCoverage {
    pub schema_version: u32,
    pub protocol: AutomotiveProtocol,
    /// Distinct states the evidence reached.
    pub observed: Vec<ObservedState>,
    /// Present only when a reviewed model supplied one. Retained evidence
    /// cannot establish how many states exist, and reporting the observed count
    /// as the total would render every campaign as complete coverage of itself.
    pub expected_total: Option<usize>,
    /// The model the denominator came from.
    pub model_name: Option<String>,
    /// Model states no evidence reached. Empty without a model.
    pub unreached: Vec<String>,
}

/// Why a plan produced no steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanRefusal {
    /// The physical bench is not sequenceable. Each physical transmission
    /// requires a fresh single-use approval; a sequence would convert one
    /// approval into many transmissions.
    PhysicalBenchNotSequenceable,
    /// No operations were offered to sequence.
    NoOperations,
}

/// Request for an ordered, reviewable sequence plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencePlanRequest {
    pub protocol: AutomotiveProtocol,
    pub mode: AutomotiveMode,
    /// Named automotive operations available to sequence.
    pub operations: Vec<String>,
    #[serde(default)]
    pub state_model: Option<StateModel>,
}

/// One step of a plan. Advisory: running it uses the existing approved
/// automotive execution path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SequenceStep {
    pub index: usize,
    pub operation: String,
    /// Retained state this step is expected to start from, when one is known.
    pub expected_start_state: Option<String>,
    /// Stable code for why this step was chosen.
    pub reason_code: String,
}

/// An ordered plan, or a refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SequencePlan {
    pub schema_version: u32,
    pub protocol: AutomotiveProtocol,
    pub mode: AutomotiveMode,
    pub steps: Vec<SequenceStep>,
    /// Set when the plan produced no steps, naming why.
    pub refusal: Option<PlanRefusal>,
}

/// Summarize which protocol states the retained evidence reached.
///
/// Without a reviewed model there is no denominator, no percentage, and no
/// unreached list.
#[must_use]
pub fn protocol_state_coverage(
    protocol: AutomotiveProtocol,
    observed: &[ObservedStateEvidence],
    model: Option<&StateModel>,
) -> ProtocolStateCoverage {
    let mut states: Vec<ObservedState> = Vec::new();
    for entry in observed {
        let digest = entry.signature.digest.as_str().to_owned();
        if let Some(existing) = states.iter_mut().find(|state| state.digest == digest) {
            existing.first_observed_at = existing.first_observed_at.min(entry.observed_at);
            existing.last_observed_at = existing.last_observed_at.max(entry.observed_at);
            continue;
        }
        states.push(ObservedState {
            digest,
            source_operation_id: entry.source_operation_id,
            first_observed_at: entry.observed_at,
            last_observed_at: entry.observed_at,
        });
    }
    states.sort_by(|a, b| a.digest.cmp(&b.digest));

    let seen: BTreeSet<&str> = states.iter().map(|state| state.digest.as_str()).collect();
    let (expected_total, model_name, unreached) = match model {
        Some(model) => {
            let mut unreached: Vec<String> = model
                .states
                .iter()
                .filter(|digest| !seen.contains(digest.as_str()))
                .cloned()
                .collect();
            unreached.sort();
            (
                Some(model.states.len()),
                Some(model.name.clone()),
                unreached,
            )
        }
        None => (None, None, Vec::new()),
    };

    ProtocolStateCoverage {
        schema_version: AUTOMOTIVE_LAB_SCHEMA_VERSION,
        protocol,
        observed: states,
        expected_total,
        model_name,
        unreached,
    }
}

/// Produce an ordered, deterministic plan for reaching unvisited states.
///
/// Unreached model states lead, then states observed least recently, then
/// digest order for stability. Executes nothing.
#[must_use]
pub fn plan_sequence(
    req: &SequencePlanRequest,
    observed: &[ObservedStateEvidence],
) -> SequencePlan {
    let empty = |refusal| SequencePlan {
        schema_version: AUTOMOTIVE_LAB_SCHEMA_VERSION,
        protocol: req.protocol,
        mode: req.mode,
        steps: Vec::new(),
        refusal: Some(refusal),
    };
    // The bench is excluded by construction, not by a gate that has to hold.
    if req.mode == AutomotiveMode::PhysicalBench {
        return empty(PlanRefusal::PhysicalBenchNotSequenceable);
    }
    if req.operations.is_empty() {
        return empty(PlanRefusal::NoOperations);
    }

    let coverage = protocol_state_coverage(req.protocol, observed, req.state_model.as_ref());
    let mut targets: Vec<(String, &'static str)> = coverage
        .unreached
        .iter()
        .map(|digest| (digest.clone(), "unreached_state"))
        .collect();

    // Then revisit what was seen longest ago: a state the campaign has drifted
    // away from is the one it is least likely to re-enter on its own.
    let mut revisit: Vec<&ObservedState> = coverage.observed.iter().collect();
    revisit.sort_by(|a, b| {
        a.last_observed_at
            .cmp(&b.last_observed_at)
            .then_with(|| a.digest.cmp(&b.digest))
    });
    targets.extend(
        revisit
            .into_iter()
            .map(|state| (state.digest.clone(), "least_recently_observed")),
    );

    // With no retained state there is nothing to aim at, so exercise each
    // available operation once rather than only the first: without evidence,
    // breadth is the only thing that distinguishes one plan from another.
    if targets.is_empty() {
        targets.extend(
            req.operations
                .iter()
                .map(|_| (String::new(), "no_retained_state")),
        );
    }

    let steps: Vec<SequenceStep> = targets
        .into_iter()
        .take(MAX_PLAN_STEPS)
        .enumerate()
        .map(|(index, (digest, reason))| SequenceStep {
            index,
            operation: req.operations[index % req.operations.len()].clone(),
            expected_start_state: (!digest.is_empty()).then_some(digest),
            reason_code: reason.to_owned(),
        })
        .collect();

    SequencePlan {
        schema_version: AUTOMOTIVE_LAB_SCHEMA_VERSION,
        protocol: req.protocol,
        mode: req.mode,
        steps,
        refusal: None,
    }
}

/// Request to summarize a project's protocol-state coverage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabCoverageRequest {
    pub project: String,
    pub protocol: AutomotiveProtocol,
    #[serde(default)]
    pub state_model: Option<StateModel>,
}

/// Request to plan a sequence for a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabPlanRequest {
    pub project: String,
    #[serde(flatten)]
    pub plan: SequencePlanRequest,
}

impl crate::container::ServiceContainer {
    /// Observed protocol states for a project, from retained operation evidence.
    ///
    /// Reads only durable records. Opens no interface and executes nothing.
    ///
    /// # Errors
    /// Returns a classified error when the project or retained evidence cannot
    /// be read.
    pub async fn automotive_state_coverage(
        &self,
        req: LabCoverageRequest,
    ) -> Result<ProtocolStateCoverage, hf_core::error::ClassifiedError> {
        let observed = self.observed_states(&req.project, req.protocol).await?;
        Ok(protocol_state_coverage(
            req.protocol,
            &observed,
            req.state_model.as_ref(),
        ))
    }

    /// An ordered, reviewable sequence plan for a project.
    ///
    /// Advisory: running it uses the existing approved automotive execution
    /// path. A plan naming the physical bench is refused, because each physical
    /// transmission requires a fresh single-use approval.
    ///
    /// # Errors
    /// Returns a classified error when the project or retained evidence cannot
    /// be read.
    pub async fn automotive_sequence_plan(
        &self,
        req: LabPlanRequest,
    ) -> Result<SequencePlan, hf_core::error::ClassifiedError> {
        // Refuse before touching evidence: the bench is excluded by
        // construction, and a refusal should not depend on a successful read.
        if req.plan.mode == AutomotiveMode::PhysicalBench {
            return Ok(plan_sequence(&req.plan, &[]));
        }
        let observed = self
            .observed_states(&req.project, req.plan.protocol)
            .await?;
        Ok(plan_sequence(&req.plan, &observed))
    }

    /// Retained state observations for one protocol.
    async fn observed_states(
        &self,
        project: &str,
        protocol: AutomotiveProtocol,
    ) -> Result<Vec<ObservedStateEvidence>, hf_core::error::ClassifiedError> {
        const HISTORY_LIMIT: u32 = 200;

        let operations = self
            .list_automotive_operations(std::path::Path::new(project), HISTORY_LIMIT)
            .await?;
        let mut observed = Vec::new();
        for operation in operations {
            let at = operation.ended_at.unwrap_or(operation.started_at);
            for signature in operation.state_signatures {
                if signature.protocol != protocol {
                    continue;
                }
                observed.push(ObservedStateEvidence {
                    signature,
                    source_operation_id: operation.id,
                    observed_at: at,
                });
            }
        }
        Ok(observed)
    }
}

/// Cap on script rules, so a reviewed script stays reviewable.
pub const MAX_SCRIPT_RULES: usize = 256;

/// Cap on any script identifier.
const MAX_SCRIPT_IDENT: usize = 128;

/// One scripted transition: in `from_state`, `request` yields `response` and
/// moves to `to_state`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcuRule {
    pub from_state: String,
    pub request: String,
    pub response: String,
    pub to_state: String,
}

/// A reviewed responder script.
///
/// This drives a **model**, not a bus participant. Every verdict derived from it
/// is a statement about the script, never about a real ECU: the sidecar has no
/// responder operation, so nothing here answers a real request on an interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcuScript {
    pub name: String,
    pub initial_state: String,
    pub rules: Vec<EcuRule>,
}

/// Why a script could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScriptError {
    #[error("script identifiers must be present and under {MAX_SCRIPT_IDENT} characters")]
    Identifier,
    #[error("a script must have between 1 and {MAX_SCRIPT_RULES} rules")]
    RuleCount,
    #[error("a script must be deterministic: {state} and {request} have more than one rule")]
    NotDeterministic { state: String, request: String },
    #[error("the initial state {state} appears in no rule, so the model starts nowhere")]
    InitialStateUnknown { state: String },
}

impl EcuScript {
    /// Validate the script. Fails closed.
    ///
    /// # Errors
    /// Returns the first problem found.
    pub fn validate(&self) -> Result<(), ScriptError> {
        let bounded = |value: &str| !value.is_empty() && value.len() <= MAX_SCRIPT_IDENT;
        if !bounded(&self.name) || !bounded(&self.initial_state) {
            return Err(ScriptError::Identifier);
        }
        if self.rules.is_empty() || self.rules.len() > MAX_SCRIPT_RULES {
            return Err(ScriptError::RuleCount);
        }
        let mut seen: BTreeSet<(&str, &str)> = BTreeSet::new();
        for rule in &self.rules {
            if !bounded(&rule.from_state)
                || !bounded(&rule.request)
                || !bounded(&rule.response)
                || !bounded(&rule.to_state)
            {
                return Err(ScriptError::Identifier);
            }
            // A non-deterministic model cannot validate anything, because it
            // could not decide what it would do.
            if !seen.insert((rule.from_state.as_str(), rule.request.as_str())) {
                return Err(ScriptError::NotDeterministic {
                    state: rule.from_state.clone(),
                    request: rule.request.clone(),
                });
            }
        }
        let known = self.rules.iter().any(|rule| {
            rule.from_state == self.initial_state || rule.to_state == self.initial_state
        });
        if !known {
            return Err(ScriptError::InitialStateUnknown {
                state: self.initial_state.clone(),
            });
        }
        Ok(())
    }

    /// The transition for a request in a state, if the script has one.
    fn transition(&self, state: &str, request: &str) -> Option<&EcuRule> {
        self.rules
            .iter()
            .find(|rule| rule.from_state == state && rule.request == request)
    }
}

/// Whether the model could take a planned step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepReachability {
    Reachable,
    /// The script has no transition here. Usually an incomplete script, which
    /// is what a reviewer needs to see, rather than a defect.
    UnreachableUnderScript,
}

/// One step, as the model would have taken it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulatedStep {
    pub index: usize,
    pub operation: String,
    pub state_before: String,
    pub state_after: Option<String>,
    pub reachability: StepReachability,
}

/// What a script says about a plan. A statement about the script, not hardware.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlanSimulation {
    pub schema_version: u32,
    /// Retained so a later reader can see what the model assumed.
    pub script_name: String,
    pub steps: Vec<SimulatedStep>,
}

/// Walk a plan against a script, reporting what the model would do.
///
/// The plan's order is preserved: the planner owns ordering from retained
/// evidence, and a model rewriting it would substitute the script's assumptions
/// for the campaign's.
///
/// # Errors
/// Returns a [`ScriptError`] when the script does not validate.
pub fn simulate_plan(
    script: &EcuScript,
    plan: &SequencePlan,
) -> Result<PlanSimulation, ScriptError> {
    script.validate()?;
    let mut state = script.initial_state.clone();
    let mut steps = Vec::with_capacity(plan.steps.len());
    for step in &plan.steps {
        match script.transition(&state, &step.operation) {
            Some(rule) => {
                steps.push(SimulatedStep {
                    index: step.index,
                    operation: step.operation.clone(),
                    state_before: state.clone(),
                    state_after: Some(rule.to_state.clone()),
                    reachability: StepReachability::Reachable,
                });
                state = rule.to_state.clone();
            }
            None => steps.push(SimulatedStep {
                index: step.index,
                operation: step.operation.clone(),
                state_before: state.clone(),
                state_after: None,
                reachability: StepReachability::UnreachableUnderScript,
            }),
        }
    }
    Ok(PlanSimulation {
        schema_version: AUTOMOTIVE_LAB_SCHEMA_VERSION,
        script_name: script.name.clone(),
        steps,
    })
}

/// Whether a reset restored the recorded baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetOutcome {
    /// The observed digest equals the baseline.
    Confirmed,
    /// Both digests are present and differ.
    Mismatched,
    /// A digest is missing, so nothing was compared. Never a success.
    Unconfirmed,
}

/// The result of checking a reset claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResetEvidence {
    pub outcome: ResetOutcome,
    pub baseline_digest: Option<String>,
    pub observed_digest: Option<String>,
    pub reason_code: String,
    /// Whether findings after this reset can be attributed to the sequence that
    /// followed it. False unless the reset was confirmed: without a known
    /// starting state, an attribution would be a guess presented as evidence.
    pub attributable: bool,
}

/// Check a reset claim against a recorded baseline.
#[must_use]
pub fn reset_evidence(baseline: Option<&str>, observed: Option<&str>) -> ResetEvidence {
    let (outcome, reason) = match (baseline, observed) {
        (Some(expected), Some(actual)) if expected == actual => {
            (ResetOutcome::Confirmed, "baseline_restored")
        }
        (Some(_), Some(_)) => (ResetOutcome::Mismatched, "baseline_not_restored"),
        (None, _) => (ResetOutcome::Unconfirmed, "no_recorded_baseline"),
        (_, None) => (ResetOutcome::Unconfirmed, "no_observed_state_after_reset"),
    };
    ResetEvidence {
        outcome,
        baseline_digest: baseline.map(str::to_owned),
        observed_digest: observed.map(str::to_owned),
        reason_code: reason.to_owned(),
        attributable: outcome == ResetOutcome::Confirmed,
    }
}

/// Request to walk a plan against a reviewed script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabSimulateRequest {
    pub project: String,
    pub script: EcuScript,
    #[serde(flatten)]
    pub plan: SequencePlanRequest,
}

/// Request to check a reset claim against a recorded baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabResetRequest {
    #[serde(default)]
    pub baseline_digest: Option<String>,
    #[serde(default)]
    pub observed_digest: Option<String>,
}

impl crate::container::ServiceContainer {
    /// Walk a plan against a reviewed script and report what the model would do.
    ///
    /// A statement about the script, never about hardware. Executes nothing.
    ///
    /// # Errors
    /// Returns a classified error when the script does not validate or the
    /// retained evidence cannot be read.
    pub async fn automotive_simulate_plan(
        &self,
        req: LabSimulateRequest,
    ) -> Result<PlanSimulation, hf_core::error::ClassifiedError> {
        use hf_core::error::ClassifiedError;

        let plan = self
            .automotive_sequence_plan(LabPlanRequest {
                project: req.project,
                plan: req.plan,
            })
            .await?;
        simulate_plan(&req.script, &plan)
            .map_err(|error| ClassifiedError::Validation(error.to_string()))
    }

    /// Check a reset claim. Pure over the supplied digests; executes nothing.
    #[must_use]
    pub fn automotive_reset_evidence(&self, req: &LabResetRequest) -> ResetEvidence {
        reset_evidence(
            req.baseline_digest.as_deref(),
            req.observed_digest.as_deref(),
        )
    }
}
