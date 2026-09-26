//! Pure parsing and ordering for AI target assessments.

use std::collections::{HashMap, HashSet};

use hf_core::target::{TargetCandidate, TargetInventory};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A validated model assessment. The advisory score is computed locally.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TargetAssessment {
    pub target_id: Uuid,
    pub bug_potential: u8,
    pub reachable_code: Option<u8>,
    pub harness_feasibility: u8,
    pub rationale: String,
    pub advisory_score: f64,
}

/// Invalid model output for a complete batch.
#[derive(Debug, thiserror::Error)]
pub enum AiRankError {
    #[error("malformed AI assessment JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("AI assessment names an unknown or repeated target ID")]
    InvalidTargetId,
    #[error("AI assessment rating must be between 0 and 4")]
    InvalidRating,
    #[error("AI assessment explanation is too long")]
    ExplanationTooLong,
    #[error("AI assessment response exceeds 64 KiB")]
    ResponseTooLarge,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAssessment {
    target_id: Uuid,
    bug_potential: u8,
    reachable_code: Option<u8>,
    harness_feasibility: u8,
    rationale: String,
}

/// Select at most 64 candidates in deterministic heuristic order.
#[must_use]
pub fn select_ai_candidates(inventory: &TargetInventory) -> Vec<TargetCandidate> {
    let mut candidates = inventory.candidates.clone();
    candidates.sort_by(|a, b| {
        b.fit_score
            .total_cmp(&a.fit_score)
            .then_with(|| a.relative_file().cmp(&b.relative_file()))
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates.truncate(64);
    candidates
}

/// Compute the advisory score from the available factor ratings.
///
/// # Errors
/// Returns [`AiRankError::InvalidRating`] for a value outside 0 through 4.
pub fn advisory_score(bug: u8, reach: Option<u8>, harness: u8) -> Result<f64, AiRankError> {
    if bug > 4 || harness > 4 || reach.is_some_and(|value| value > 4) {
        return Err(AiRankError::InvalidRating);
    }
    let sum = f64::from(bug) + f64::from(harness) + reach.map_or(0.0, f64::from);
    let count = if reach.is_some() { 3.0 } else { 2.0 };
    Ok(sum / (4.0 * count))
}

/// Parse a complete model batch. Any invalid row rejects the entire batch.
///
/// # Errors
/// Returns [`AiRankError`] for malformed JSON, IDs, ratings, or explanation.
pub fn parse_ai_batch(
    candidates: &[TargetCandidate],
    response: &str,
) -> Result<Vec<TargetAssessment>, AiRankError> {
    if response.len() > 64 * 1024 {
        return Err(AiRankError::ResponseTooLarge);
    }
    let allowed: HashSet<Uuid> = candidates.iter().map(|candidate| candidate.id).collect();
    let rows: Vec<RawAssessment> = serde_json::from_str(response)?;
    let mut seen = HashSet::new();
    rows.into_iter()
        .map(|row| {
            if !allowed.contains(&row.target_id) || !seen.insert(row.target_id) {
                return Err(AiRankError::InvalidTargetId);
            }
            if row.rationale.chars().count() > 300 {
                return Err(AiRankError::ExplanationTooLong);
            }
            Ok(TargetAssessment {
                target_id: row.target_id,
                bug_potential: row.bug_potential,
                reachable_code: row.reachable_code,
                harness_feasibility: row.harness_feasibility,
                rationale: row.rationale,
                advisory_score: advisory_score(
                    row.bug_potential,
                    row.reachable_code,
                    row.harness_feasibility,
                )?,
            })
        })
        .collect()
}

/// Order assessed candidates first and scan-only candidates in heuristic order.
#[must_use]
pub fn order_with_assessments(
    inventory: &TargetInventory,
    assessments: &[TargetAssessment],
) -> Vec<Uuid> {
    let by_id: HashMap<Uuid, &TargetAssessment> = assessments
        .iter()
        .map(|assessment| (assessment.target_id, assessment))
        .collect();
    let mut ordered = inventory.candidates.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| {
        let a_assessment = by_id.get(&a.id);
        let b_assessment = by_id.get(&b.id);
        b_assessment
            .is_some()
            .cmp(&a_assessment.is_some())
            .then_with(|| match (a_assessment, b_assessment) {
                (Some(a), Some(b)) => b.advisory_score.total_cmp(&a.advisory_score),
                _ => std::cmp::Ordering::Equal,
            })
            .then_with(|| b.fit_score.total_cmp(&a.fit_score))
            .then_with(|| a.relative_file().cmp(&b.relative_file()))
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.id.cmp(&b.id))
    });
    ordered.into_iter().map(|candidate| candidate.id).collect()
}
