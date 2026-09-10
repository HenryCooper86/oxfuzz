//! Reviewed, finite resource allocations for scheduled project campaigns.

use std::path::Path;

use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::container::RunHistoryItem;
mod storage;
pub(crate) use storage::AllocationStore;

/// One exact promoted harness eligible for an allocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationCandidate {
    /// File-qualified target selector.
    pub target: String,
    /// Service-resolved workspace selector from qualification evidence.
    pub dispatch_target: String,
    /// Canonical engine name.
    pub engine: String,
    /// Canonical source language.
    pub language: String,
    /// Retained discovery identity.
    pub target_id: Uuid,
    /// Exact promoted harness identity.
    pub harness_id: Uuid,
    /// Approved harness source digest.
    pub source_sha256: String,
}

/// Operator inputs; evidence and weights are resolved by the service.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationRequest {
    /// Project whose scheduled campaigns will share this allowance.
    pub project: String,
    /// Selected promoted harnesses from the candidate list.
    pub harness_ids: Vec<Uuid>,
    /// Finite number of reservations, including unsuccessful attempts.
    pub max_runs: u32,
    /// Requested sandbox fuzz seconds, excluding preparation and triage.
    pub max_total_secs: u64,
}

/// Retained coverage facts used to compute a target's weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationEvidence {
    /// Durable campaign identity.
    pub run_id: String,
    /// Recorded start time.
    pub started_at: String,
    /// Service-owned setup grouping key.
    pub comparison_key: String,
    /// Exact executable digest; raw totals require the same executable.
    pub binary_rev: String,
    /// Retained edge total.
    pub edges: u64,
}

/// A target's reserved share and its reproducible explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationEntry {
    /// Approved execution identity.
    pub candidate: AllocationCandidate,
    /// One for unavailable/plateau evidence, two for positive growth.
    pub weight: u32,
    /// Reserved opportunities, unavailable to other targets.
    pub max_runs: u32,
    /// Why this weight was assigned.
    pub reason: String,
    /// At most two retained, comparable run observations.
    pub evidence: Vec<AllocationEvidence>,
}

/// Immutable proposal approved by UUID and digest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationProposal {
    /// Durable format version.
    pub schema_version: u32,
    /// Exact proposal identity.
    pub id: Uuid,
    /// Canonical project owner.
    pub project: String,
    /// Proposal creation time.
    pub created_at: String,
    /// Finite project run allowance.
    pub max_runs: u32,
    /// Operator's total requested fuzz-time ceiling.
    pub max_total_secs: u64,
    /// Maximum requested fuzz seconds per reservation.
    pub per_run_secs: u64,
    /// Remainder that cannot fund another full reservation.
    pub unallocated_secs: u64,
    /// Deterministically ordered targets and reserved shares.
    pub entries: Vec<AllocationEntry>,
}

/// Review lifecycle; revocation never refunds previously issued grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllocationStatus {
    /// Awaiting approval of the exact proposal.
    Draft,
    /// New reservations are permitted within the retained quotas.
    Approved,
    /// Future admission is denied.
    Revoked,
}

/// A durable charge issued before a scheduled campaign starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationGrant {
    /// Unique reservation identity.
    pub id: Uuid,
    /// Approved proposal identity.
    pub plan_id: Uuid,
    /// Schedule that obtained the grant.
    pub schedule_id: String,
    /// Time of durable admission.
    pub created_at: String,
    /// Exact execution identity permitted by this grant.
    pub candidate: AllocationCandidate,
    /// Reserved requested sandbox fuzz seconds.
    pub duration_secs: u64,
}

/// Current proposal, review and consumption; also the persisted state format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllocationView {
    /// Immutable proposal body.
    pub proposal: AllocationProposal,
    /// SHA-256 of the serialized proposal.
    pub digest: String,
    /// Current review state.
    pub status: AllocationStatus,
    /// Latest explicit review time.
    pub reviewed_at: Option<String>,
    /// Charges remain present after failed, cancelled, or interrupted work.
    pub reservations: Vec<AllocationGrant>,
}

pub(crate) fn invalid(message: impl Into<String>) -> ClassifiedError {
    ClassifiedError::Validation(message.into())
}

pub(crate) fn proposal_digest(proposal: &AllocationProposal) -> Result<String, ClassifiedError> {
    let bytes = serde_json::to_vec(proposal)
        .map_err(|error| ClassifiedError::Internal(error.to_string()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub(crate) fn make_proposal(
    project: &Path,
    mut candidates: Vec<AllocationCandidate>,
    history: &[RunHistoryItem],
    max_runs: u32,
    max_total_secs: u64,
) -> Result<AllocationProposal, ClassifiedError> {
    if candidates.is_empty()
        || candidates.len() > 64
        || max_runs < candidates.len() as u32
        || max_runs > 10_000
        || max_total_secs < u64::from(max_runs)
        || max_total_secs > 31_536_000
    {
        return Err(invalid("select 1–64 targets, reserve at least one run each (at most 10000), and supply 1–31536000 fuzz seconds with at least one second per run"));
    }
    candidates.sort_by(|a, b| (&a.target, &a.engine).cmp(&(&b.target, &b.engine)));
    if candidates
        .windows(2)
        .any(|pair| pair[0].target == pair[1].target && pair[0].engine == pair[1].engine)
    {
        return Err(invalid(
            "an allocation may select each target/engine only once",
        ));
    }
    let mut entries = candidates
        .into_iter()
        .map(|candidate| {
            let evidence = comparable_evidence(&candidate, history);
            let growing = evidence.len() == 2 && evidence[1].edges > evidence[0].edges;
            AllocationEntry {
                candidate,
                weight: if growing { 2 } else { 1 },
                max_runs: 1,
                reason: if growing {
                    "Recent comparable runs gained edges"
                } else if evidence.len() == 2 {
                    "Comparable runs did not gain edges; minimum service retained"
                } else {
                    "Two comparable retained runs are unavailable; equal service"
                }
                .into(),
                evidence,
            }
        })
        .collect::<Vec<_>>();
    let cycle = entries
        .iter()
        .enumerate()
        .flat_map(|(index, entry)| std::iter::repeat_n(index, entry.weight as usize))
        .collect::<Vec<_>>();
    for index in cycle.iter().cycle().take(max_runs as usize - entries.len()) {
        entries[*index].max_runs += 1;
    }
    Ok(AllocationProposal {
        schema_version: 1,
        id: Uuid::new_v4(),
        project: project.to_string_lossy().into_owned(),
        created_at: chrono::Utc::now().to_rfc3339(),
        max_runs,
        max_total_secs,
        per_run_secs: max_total_secs / u64::from(max_runs),
        unallocated_secs: max_total_secs % u64::from(max_runs),
        entries,
    })
}

fn comparable_evidence(
    candidate: &AllocationCandidate,
    history: &[RunHistoryItem],
) -> Vec<AllocationEvidence> {
    let mut runs = history
        .iter()
        .filter(|run| {
            run.target_id == Some(candidate.target_id)
                && crate::run_comparison::comparison_reason(run, run)
                    == crate::run_comparison::RunComparisonReason::Comparable
                && run
                    .engine
                    .parse::<hf_core::engine::EngineKind>()
                    .is_ok_and(|engine| engine.as_str() == candidate.engine)
                && run.harness_rev.as_deref() == Some(candidate.source_sha256.as_str())
        })
        .collect::<Vec<_>>();
    runs.sort_by(|a, b| (&b.started_at, &b.id).cmp(&(&a.started_at, &a.id)));
    let Some(latest) = runs.first() else {
        return Vec::new();
    };
    let mut selected = runs
        .iter()
        .filter(|run| {
            crate::run_comparison::comparison_reason(run, latest)
                == crate::run_comparison::RunComparisonReason::Comparable
        })
        .take(2)
        .filter_map(|run| {
            Some(AllocationEvidence {
                run_id: run.id.clone(),
                started_at: run.started_at.clone(),
                comparison_key: run.comparison_key.clone()?,
                binary_rev: run.binary_rev.clone()?,
                edges: run.edges?,
            })
        })
        .collect::<Vec<_>>();
    selected.reverse();
    selected
}

struct GrantExecution {
    candidate: AllocationCandidate,
    duration_secs: u64,
    attempted: std::sync::atomic::AtomicBool,
}

tokio::task_local! {
    static GRANT_EXECUTION: GrantExecution;
}

pub(crate) async fn with_grant<F: std::future::Future>(
    grant: &AllocationGrant,
    future: F,
) -> F::Output {
    GRANT_EXECUTION
        .scope(
            GrantExecution {
                candidate: grant.candidate.clone(),
                duration_secs: grant.duration_secs,
                attempted: std::sync::atomic::AtomicBool::new(false),
            },
            future,
        )
        .await
}

/// Check exact authority inside userspace preparation while revision locks are held.
pub(crate) fn verify_granted_harness(
    harness: &hf_core::harness::Harness,
    duration_secs: u64,
) -> Result<(), ClassifiedError> {
    match GRANT_EXECUTION.try_with(|grant| {
        let candidate = &grant.candidate;
        if candidate.harness_id != harness.id
            || candidate.target_id != harness.target_id
            || candidate.engine != harness.engine.as_str()
            || candidate.source_sha256 != format!("{:x}", Sha256::digest(harness.source.as_bytes()))
        {
            return Err(invalid(
                "active harness changed since allocation approval; review a new allocation",
            ));
        }
        if duration_secs > grant.duration_secs {
            return Err(invalid("run exceeds allocation duration"));
        }
        if grant
            .attempted
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(invalid("allocation grant was already attempted"));
        }
        Ok(())
    }) {
        Ok(result) => result,
        // A manually requested run has independent authority and no allocation scope.
        Err(_) => Ok(()),
    }
}

#[cfg(all(test, feature = "campaign-allocation"))]
mod tests;

#[cfg(all(test, not(feature = "campaign-allocation")))]
mod disabled_tests {
    use super::*;
    #[test]
    fn retained_approval_cannot_execute_when_the_feature_is_disabled() {
        let root = tempfile::tempdir().unwrap();
        let candidate = AllocationCandidate {
            target: "a.c::parse".into(),
            dispatch_target: "parse".into(),
            engine: "libfuzzer".into(),
            language: "c".into(),
            target_id: Uuid::new_v4(),
            harness_id: Uuid::new_v4(),
            source_sha256: "a".repeat(64),
        };
        let store = AllocationStore::new(&root.path().join("state"), root.path().into());
        let plan = store
            .propose(make_proposal(root.path(), vec![candidate.clone()], &[], 1, 10).unwrap())
            .unwrap();
        store.review(plan.proposal.id, &plan.digest, true).unwrap();
        let error = store.reserve("schedule", &[candidate], 10).unwrap_err();
        assert!(error.to_string().contains("disabled"));
        assert!(store.inspect().unwrap().unwrap().reservations.is_empty());
    }
}
