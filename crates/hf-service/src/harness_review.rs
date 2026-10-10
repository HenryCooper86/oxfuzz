//! Durable evidence model for the mandatory pre-execution review of one exact
//! harness revision.
//!
//! Two record shapes share the `harness_ai_reviews` table, both bound to the
//! source and binary SHA-256 digests carried by the record columns:
//!
//! - the independent LLM review envelope (`HarnessAiReviewEvidence`), written
//!   after a model accepted or refused the exact source; and
//! - the operator-bypass marker (`HarnessBypassedReviewEvidence`), written
//!   when smoke qualification ran without the model review because the
//!   operator explicitly opted in (`--no-llm-review` for one invocation, or
//!   `harness.allow_unreviewed_smoke` for the deployment).
//!
//! The bypass marker keeps "was this exact revision reviewed?" durable and
//! distinguishable (Engineering Protocol 2.13): it satisfies the
//! review-existence check for execution while remaining visible to promotion
//! and audit surfaces as a review that never happened. It never promotes a
//! harness and never overrides a persisted negative LLM verdict.

use hf_core::error::ClassifiedError;
use hf_core::provider::ChatResponse;

pub(crate) const MAX_HARNESS_REVIEW_SOURCE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_HARNESS_REVIEW_RESPONSE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_HARNESS_REVIEW_REASONS: usize = 32;
pub(crate) const MAX_HARNESS_REVIEW_REASON_BYTES: usize = 1024;
pub(crate) const HARNESS_AI_REVIEW_SCHEMA_VERSION: u32 = 1;
pub(crate) const HARNESS_AI_REVIEW_PROMPT_VERSION: u32 = 1;

/// The structured opinion the independent model returns for one exact source.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessPreExecutionOpinion {
    pub exercises_target: bool,
    pub safe_to_execute: bool,
    pub reasons: Vec<String>,
}

/// The independent LLM review: normalized provider metadata plus the verdict.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessAiReviewEvidence {
    pub schema_version: u32,
    pub prompt_version: u32,
    pub target: String,
    pub opinion: HarnessPreExecutionOpinion,
    pub response: ChatResponse,
}

/// How the operator authorized skipping the independent LLM review.
///
/// Carried by the persisted bypass marker and surfaced on the approval
/// views, so a review that never happened stays attributable to the exact
/// opt-in surface that allowed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessReviewBypassSource {
    /// The `--no-llm-review` flag on one `oxfuzz harness` invocation.
    CliFlag,
    /// The deployment-wide `harness.allow_unreviewed_smoke = true` setting.
    Config,
}

impl HarnessReviewBypassSource {
    /// The user-facing opt-in surface, named exactly as an operator sets it.
    #[must_use]
    pub fn surface(self) -> &'static str {
        match self {
            Self::CliFlag => "--no-llm-review",
            Self::Config => "harness.allow_unreviewed_smoke = true",
        }
    }
}

/// Per-invocation request to skip the mandatory independent LLM review before
/// a harness smoke run.
///
/// Presentation layers carry this request; the qualification operation
/// resolves it against the deployment config and enforces the outcome
/// (Engineering Protocol 2.19). `Requested` alone permits one bypass; the
/// deployment setting alone permits every one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessReviewBypass {
    /// No per-invocation opt-in. The review runs unless the deployment opted
    /// out in `harness.allow_unreviewed_smoke`.
    #[default]
    NotRequested,
    /// The operator accepted the risk for this invocation (`--no-llm-review`).
    Requested,
}

/// The marker values of a bypassed review record. Typed single-variant fields
/// make a malformed marker a parse error rather than a validation branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum BypassedReviewMarker {
    #[serde(rename = "bypassed")]
    Bypassed,
}

/// The reviewer attribution of a bypassed review record: no one reviewed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum BypassedReviewer {
    #[serde(rename = "none")]
    None,
}

/// The persisted marker written when smoke qualification ran without the
/// independent LLM review. Same digest binding and schema versioning as the
/// LLM envelope; the `verdict`/`reviewer` markers make the bypass visible on
/// every audit surface that reads the record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessBypassedReviewEvidence {
    pub schema_version: u32,
    pub verdict: BypassedReviewMarker,
    pub reviewer: BypassedReviewer,
    pub target: String,
    pub bypass_source: HarnessReviewBypassSource,
    /// Why the operator accepted the risk, naming the opt-in surface.
    pub rationale: String,
}

impl HarnessBypassedReviewEvidence {
    pub(crate) fn new(target: &str, source: HarnessReviewBypassSource) -> Self {
        Self {
            schema_version: HARNESS_AI_REVIEW_SCHEMA_VERSION,
            verdict: BypassedReviewMarker::Bypassed,
            reviewer: BypassedReviewer::None,
            target: target.to_owned(),
            bypass_source: source,
            rationale: format!(
                "the operator bypassed the independent LLM pre-execution review via {}; \
                 only the lexical lint gate and the human promotion gate checked this revision",
                source.surface()
            ),
        }
    }
}

/// Parsed content of a persisted review record.
#[derive(Debug, Clone)]
pub(crate) enum HarnessReviewEvidence {
    /// An independent model reviewed the exact revision.
    Llm(Box<HarnessAiReviewEvidence>),
    /// The operator bypassed the review for the exact revision.
    Bypassed(HarnessBypassedReviewEvidence),
}

/// Parse the durable review evidence, dispatching on the bypass marker.
///
/// The LLM envelope has no `verdict` field and denies unknown fields, so a
/// bypassed marker can never parse as a model review; any other `verdict`
/// value fails the probe and then the strict envelope parse.
///
/// # Errors
/// Returns an error when the JSON parses as neither record shape.
pub(crate) fn parse_review_evidence(
    review_json: &str,
) -> Result<HarnessReviewEvidence, ClassifiedError> {
    #[derive(serde::Deserialize)]
    struct VerdictProbe {
        verdict: Option<BypassedReviewMarker>,
    }
    let probe: VerdictProbe = serde_json::from_str(review_json).map_err(|error| {
        ClassifiedError::Storage(format!(
            "stored harness review is not recognizable: {error}"
        ))
    })?;
    if probe.verdict == Some(BypassedReviewMarker::Bypassed) {
        return serde_json::from_str(review_json)
            .map(HarnessReviewEvidence::Bypassed)
            .map_err(|error| {
                ClassifiedError::Storage(format!(
                    "stored bypassed harness review is malformed: {error}"
                ))
            });
    }
    serde_json::from_str(review_json)
        .map(|evidence| HarnessReviewEvidence::Llm(Box::new(evidence)))
        .map_err(|error| {
            ClassifiedError::Storage(format!("stored LLM harness review is malformed: {error}"))
        })
}

/// Validate the binding and bounds of a parsed bypassed record against the
/// target under qualification. Digest binding lives on the record columns and
/// is checked by the caller, exactly like the LLM path.
///
/// # Errors
/// Returns an error when the record is versioned, scoped, or sized wrong.
pub(crate) fn validate_bypassed_review(
    evidence: &HarnessBypassedReviewEvidence,
    target: &str,
) -> Result<(), ClassifiedError> {
    if evidence.schema_version != HARNESS_AI_REVIEW_SCHEMA_VERSION || evidence.target != target {
        return Err(ClassifiedError::Storage(
            "stored bypassed harness review has invalid provenance".to_owned(),
        ));
    }
    if evidence.rationale.trim().is_empty()
        || evidence.rationale.len() > MAX_HARNESS_REVIEW_REASON_BYTES
    {
        return Err(ClassifiedError::Storage(
            "stored bypassed harness review has an invalid rationale".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn llm_envelope_json() -> String {
        let response = serde_json::to_value(hf_test_utils::fixtures::make_chat_response(
            r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["drives the target"]}"#,
        ))
        .expect("response serializes");
        serde_json::json!({
            "schema_version": HARNESS_AI_REVIEW_SCHEMA_VERSION,
            "prompt_version": HARNESS_AI_REVIEW_PROMPT_VERSION,
            "target": "parse_entry",
            "opinion": {
                "exercises_target": true,
                "safe_to_execute": true,
                "reasons": ["drives the target"],
            },
            "response": response,
        })
        .to_string()
    }

    #[test]
    fn the_llm_envelope_parses_as_a_model_review() {
        let parsed = parse_review_evidence(&llm_envelope_json()).expect("LLM envelope parses");
        let HarnessReviewEvidence::Llm(evidence) = parsed else {
            panic!("the LLM envelope must dispatch to the model review");
        };
        assert_eq!(evidence.target, "parse_entry");
        assert!(evidence.opinion.exercises_target);
        assert!(evidence.opinion.safe_to_execute);
    }

    #[test]
    fn the_bypass_marker_round_trips_with_its_opt_in_source() {
        for source in [
            HarnessReviewBypassSource::CliFlag,
            HarnessReviewBypassSource::Config,
        ] {
            let evidence = HarnessBypassedReviewEvidence::new("parse_entry", source);
            let json = serde_json::to_string(&evidence).expect("marker serializes");
            assert!(json.contains("\"verdict\":\"bypassed\""), "{json}");
            assert!(json.contains("\"reviewer\":\"none\""), "{json}");

            let parsed = parse_review_evidence(&json).expect("marker parses");
            let HarnessReviewEvidence::Bypassed(parsed) = parsed else {
                panic!("the bypass marker must dispatch to the bypass record");
            };
            assert_eq!(parsed.bypass_source, source);
            assert_eq!(parsed.target, "parse_entry");
            validate_bypassed_review(&parsed, "parse_entry").expect("fresh marker is valid");
        }
    }

    #[test]
    fn the_opt_in_source_names_its_exact_surface() {
        assert_eq!(
            HarnessReviewBypassSource::CliFlag.surface(),
            "--no-llm-review"
        );
        assert_eq!(
            HarnessReviewBypassSource::Config.surface(),
            "harness.allow_unreviewed_smoke = true"
        );
    }

    #[test]
    fn a_bypass_marker_with_a_wrong_version_or_target_is_rejected() {
        let mut evidence =
            HarnessBypassedReviewEvidence::new("parse_entry", HarnessReviewBypassSource::CliFlag);
        evidence.schema_version += 1;
        assert!(validate_bypassed_review(&evidence, "parse_entry").is_err());

        let evidence =
            HarnessBypassedReviewEvidence::new("parse_entry", HarnessReviewBypassSource::CliFlag);
        assert!(validate_bypassed_review(&evidence, "other_target").is_err());
    }

    #[test]
    fn a_bypass_marker_with_an_empty_or_oversized_rationale_is_rejected() {
        let mut evidence =
            HarnessBypassedReviewEvidence::new("parse_entry", HarnessReviewBypassSource::CliFlag);
        evidence.rationale = "   ".to_owned();
        assert!(validate_bypassed_review(&evidence, "parse_entry").is_err());
        evidence.rationale = "x".repeat(MAX_HARNESS_REVIEW_REASON_BYTES + 1);
        assert!(validate_bypassed_review(&evidence, "parse_entry").is_err());
    }

    #[test]
    fn an_unknown_verdict_marker_fails_closed() {
        let mut json = serde_json::to_value(HarnessBypassedReviewEvidence::new(
            "parse_entry",
            HarnessReviewBypassSource::CliFlag,
        ))
        .expect("marker serializes");
        json["verdict"] = serde_json::json!("approved");
        assert!(parse_review_evidence(&json.to_string()).is_err());
    }

    #[test]
    fn neither_shape_accepts_garbage() {
        assert!(parse_review_evidence("approved").is_err());
        assert!(parse_review_evidence("[]").is_err());
        assert!(parse_review_evidence("{}").is_err());
    }
}
