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

    // A plan with no known states still exercises the operations once.
    if targets.is_empty() {
        targets.push((String::new(), "no_retained_state"));
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
