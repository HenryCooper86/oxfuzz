//! Bounded behavioral evidence collected during approved smoke qualification.
use super::ServiceContainer;
use hf_core::error::ClassifiedError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One measured check, or an explicit explanation of missing evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum BehaviorCheck {
    Pass { detail: String },
    Suspect { detail: String },
    Unavailable { detail: String },
}

impl BehaviorCheck {
    fn unavailable(detail: &str) -> Self {
        Self::Unavailable {
            detail: detail.to_owned(),
        }
    }
    #[cfg(feature = "harness-behavior")]
    fn measured(passed: bool, pass: &str, suspect: &str) -> Self {
        if passed {
            Self::Pass {
                detail: pass.to_owned(),
            }
        } else {
            Self::Suspect {
                detail: suspect.to_owned(),
            }
        }
    }
}

/// One exact input and its normalized AFL edge/count tuples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorObservation {
    pub label: String,
    pub input_hex: String,
    pub input_sha256: String,
    pub tuples: Vec<(u64, u8)>,
}

/// Versioned, attributable evidence; passing samples never prove all inputs safe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessBehaviorReport {
    pub version: u32,
    pub run_id: Option<Uuid>,
    pub source_sha256: Option<String>,
    pub binary_sha256: Option<String>,
    pub sandbox_rev: Option<String>,
    pub input_sensitivity: BehaviorCheck,
    pub entry_rejection: BehaviorCheck,
    pub repeated_input_stability: BehaviorCheck,
    pub persistent_state: BehaviorCheck,
    pub target_coverage_growth: BehaviorCheck,
    pub observations: Vec<BehaviorObservation>,
    pub commands: Vec<Vec<String>>,
    pub command_timeout_secs: u64,
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub environment: std::collections::BTreeMap<String, String>,
    pub issues: Vec<String>,
}

impl HarnessBehaviorReport {
    /// Explicit absence for unsupported engines, feature-off builds, and old runs.
    #[must_use]
    pub fn unavailable(reason: &str) -> Self {
        Self {
            version: 1,
            run_id: None,
            source_sha256: None,
            binary_sha256: None,
            sandbox_rev: None,
            input_sensitivity: BehaviorCheck::unavailable(reason),
            entry_rejection: BehaviorCheck::unavailable(reason),
            repeated_input_stability: BehaviorCheck::unavailable(reason),
            persistent_state: BehaviorCheck::unavailable(reason),
            target_coverage_growth: BehaviorCheck::unavailable(
                "AFL maps include harness code; no per-input target-only profile was retained",
            ),
            observations: Vec::new(),
            commands: Vec::new(),
            command_timeout_secs: 0,
            max_mem_mb: 0,
            max_cpus: 0,
            environment: std::collections::BTreeMap::new(),
            issues: Vec::new(),
        }
    }

    pub(super) fn promotion_failure(&self) -> Option<&str> {
        for check in [&self.repeated_input_stability, &self.persistent_state] {
            if let BehaviorCheck::Suspect { detail } = check {
                return Some(detail);
            }
        }
        None
    }

    pub(super) fn augment_verdict(&self, verdict: &mut crate::verification::HarnessVerdict) {
        for check in [
            &self.input_sensitivity,
            &self.entry_rejection,
            &self.repeated_input_stability,
            &self.persistent_state,
        ] {
            if let BehaviorCheck::Suspect { detail } = check {
                if verdict.level == crate::verification::VerdictLevel::Pass {
                    verdict.level = crate::verification::VerdictLevel::Suspect;
                }
                verdict.reasons.push(detail.clone());
            }
        }
    }
}

impl ServiceContainer {
    /// Read persisted behavioral evidence without running any target code.
    ///
    /// # Errors
    /// Rejects missing runs, invalid reports, and storage failures.
    pub async fn harness_behavior(
        &self,
        run_id: Uuid,
    ) -> Result<HarnessBehaviorReport, ClassifiedError> {
        let store = self.store.as_ref().ok_or_else(|| {
            ClassifiedError::Validation("harness behavior requires persistent storage".to_owned())
        })?;
        if store.get_run(run_id).await?.is_none() {
            return Err(ClassifiedError::Validation(format!(
                "run not found: {run_id}"
            )));
        }
        let Some(record) = store.harness_behavior(run_id).await? else {
            return Ok(HarnessBehaviorReport::unavailable(
                "No behavioral evidence was retained for this run",
            ));
        };
        let report: HarnessBehaviorReport = serde_json::from_str(&record.report_json)
            .map_err(|e| ClassifiedError::Validation(format!("invalid behavioral report: {e}")))?;
        if report.version != 1
            || report.run_id != Some(run_id)
            || report.source_sha256.as_ref() != Some(&record.source_sha256)
            || report.binary_sha256.as_ref() != Some(&record.binary_sha256)
            || report.sandbox_rev.as_ref() != Some(&record.sandbox_rev)
        {
            return Err(ClassifiedError::Validation(
                "behavior report artifact identity mismatch".to_owned(),
            ));
        }
        Ok(report)
    }

    pub(super) async fn require_behavior_promotion(
        &self,
        run_id: Option<Uuid>,
    ) -> Result<(), ClassifiedError> {
        if let Some(run_id) = run_id {
            if let Some(reason) = self.harness_behavior(run_id).await?.promotion_failure() {
                return Err(ClassifiedError::Validation(format!("behavioral qualification refuses promotion: {reason}; repair and requalify this harness")));
            }
        }
        Ok(())
    }
}

#[cfg(feature = "harness-behavior")]
mod collection;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instability_and_contamination_refuse_promotion_but_input_proxy_does_not() {
        let mut report = HarnessBehaviorReport::unavailable("not measured");
        report.input_sensitivity = BehaviorCheck::Suspect {
            detail: "same observed map".into(),
        };
        assert!(report.promotion_failure().is_none());
        report.repeated_input_stability = BehaviorCheck::Suspect {
            detail: "unstable fresh A".into(),
        };
        assert_eq!(report.promotion_failure(), Some("unstable fresh A"));
        report.repeated_input_stability = BehaviorCheck::unavailable("not measured");
        report.persistent_state = BehaviorCheck::Suspect {
            detail: "A-B-A differed".into(),
        };
        assert_eq!(report.promotion_failure(), Some("A-B-A differed"));
    }
}
