//! Service-owned explanations for comparing retained campaign measurements.
use crate::container::{project_lookup_identity, RunHistoryItem, ServiceContainer};
use hf_core::error::ClassifiedError;
use serde::Serialize;
use uuid::Uuid;

/// Why a pair does or does not support a direct edge-total comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunComparisonReason {
    /// Both measurements retain matching setup and executable identities.
    Comparable,
    /// At least one row is not a completed campaign.
    UnfinishedCampaign,
    /// A retained setup grouping key is unavailable.
    MissingSetup,
    /// Recorded target, settings or captured context differ.
    DifferentSetup,
    /// An exact executable digest is unavailable.
    MissingExecutable,
    /// Executables differ and may use different instrumented edges.
    DifferentExecutable,
    /// At least one edge total is unavailable.
    MissingCoverage,
}

/// Read-only assessment of the explicitly selected baseline and result.
#[derive(Debug, Clone, Serialize)]
pub struct RunComparisonAssessment {
    /// First selected retained run.
    pub baseline_id: String,
    /// Second selected retained run.
    pub result_id: String,
    /// Whether a direct numeric edge delta is supported by retained metadata.
    pub comparable: bool,
    /// Service-derived explanation for availability.
    pub reason: RunComparisonReason,
    /// Whether known target/settings/context keys match; absent when unavailable.
    pub setup_matches: Option<bool>,
    /// Whether known approved harness source digests differ.
    pub harness_changed: Option<bool>,
    /// Whether known executable digests differ.
    pub binary_changed: Option<bool>,
    /// Result minus baseline as an exact signed decimal string.
    pub edge_delta: Option<String>,
}
fn digest(value: Option<&str>) -> Option<&str> {
    value.filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
}
fn digest_changed(first: Option<&str>, second: Option<&str>) -> Option<bool> {
    Some(digest(first)? != digest(second)?)
}
fn setup_matches(first: &RunHistoryItem, second: &RunHistoryItem) -> Option<bool> {
    Some(
        first
            .comparison_key
            .as_deref()
            .filter(|key| !key.is_empty())?
            == second
                .comparison_key
                .as_deref()
                .filter(|key| !key.is_empty())?,
    )
}

pub(crate) fn comparison_reason(
    first: &RunHistoryItem,
    second: &RunHistoryItem,
) -> RunComparisonReason {
    if first.kind != "Campaign"
        || second.kind != "Campaign"
        || first.status != "Done"
        || second.status != "Done"
    {
        return RunComparisonReason::UnfinishedCampaign;
    }
    match setup_matches(first, second) {
        None => return RunComparisonReason::MissingSetup,
        Some(false) => return RunComparisonReason::DifferentSetup,
        Some(true) => {}
    }
    match digest_changed(first.binary_rev.as_deref(), second.binary_rev.as_deref()) {
        None => return RunComparisonReason::MissingExecutable,
        Some(true) => return RunComparisonReason::DifferentExecutable,
        Some(false) => {}
    }
    if first.edges.is_none() || second.edges.is_none() {
        return RunComparisonReason::MissingCoverage;
    }
    RunComparisonReason::Comparable
}

fn assess(first: &RunHistoryItem, second: &RunHistoryItem) -> RunComparisonAssessment {
    let reason = comparison_reason(first, second);
    let comparable = reason == RunComparisonReason::Comparable;
    RunComparisonAssessment {
        baseline_id: first.id.clone(),
        result_id: second.id.clone(),
        comparable,
        reason,
        setup_matches: setup_matches(first, second),
        harness_changed: digest_changed(
            first.harness_rev.as_deref(),
            second.harness_rev.as_deref(),
        ),
        binary_changed: digest_changed(first.binary_rev.as_deref(), second.binary_rev.as_deref()),
        edge_delta: if comparable {
            first
                .edges
                .zip(second.edges)
                .map(|(before, after)| (i128::from(after) - i128::from(before)).to_string())
        } else {
            None
        },
    }
}

impl ServiceContainer {
    /// Explain comparison availability using retained run metadata only.
    ///
    /// # Errors
    /// Rejects identical/missing run IDs, different project owners or unavailable storage.
    pub async fn run_comparison(
        &self,
        baseline_id: Uuid,
        result_id: Uuid,
    ) -> Result<RunComparisonAssessment, ClassifiedError> {
        if baseline_id == result_id {
            return Err(ClassifiedError::Validation(
                "select two distinct runs".into(),
            ));
        }
        let baseline = self.run_record(baseline_id).await?;
        let result = self.run_record(result_id).await?;
        let project = project_lookup_identity(std::path::Path::new(&baseline.project_root));
        if project != project_lookup_identity(std::path::Path::new(&result.project_root)) {
            return Err(ClassifiedError::Validation(
                "select two runs from the same project".into(),
            ));
        }
        let history = self.run_history(Some(&project)).await?;
        let first_id = baseline_id.to_string();
        let second_id = result_id.to_string();
        let first = history.iter().find(|run| run.id == first_id);
        let second = history.iter().find(|run| run.id == second_id);
        match (first, second) {
            (Some(first), Some(second)) => Ok(assess(first, second)),
            _ => Err(ClassifiedError::Validation(
                "selected run history changed; refresh and select again".into(),
            )),
        }
    }
}
