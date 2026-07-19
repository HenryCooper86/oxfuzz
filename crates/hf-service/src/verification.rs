//! Deterministic self-verification of harness-generation outcomes.
//!
//! Implements the cheapest tier of lesson L2 (see
//! `docs/design/grok-build-lessons-20260719.md`): before a compiled, "passed"
//! harness flows downstream, inspect the concrete smoke-run signals for a hollow
//! pass -- a harness that builds and reports success yet never actually drives
//! the target (near-zero execs). Pure and deterministic: no LLM, sandbox, or
//! store, so it runs at zero model cost and is fully unit-testable. The LLM
//! verifier and adversarial skeptic-panel tiers are deferred follow-ons (see
//! `.claude/plans/2026-07-19-agent-self-verification-loop.md`).

use hf_core::harness::{HarnessStatus, SmokeRunSummary};
use serde::{Deserialize, Serialize};

/// Below this observed throughput, a smoke run that "passed" is treated as a
/// hollow pass: the harness compiled and ran but is not meaningfully exercising
/// the target (e.g. the fuzz entrypoint never reaches the target function). The
/// floor is deliberately conservative -- even a trivial target smoke-runs orders
/// of magnitude above this -- so it flags only genuinely dead harnesses.
pub const MIN_MEANINGFUL_EXECS_PER_SEC: f64 = 1.0;

/// The outcome of a deterministic verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictLevel {
    /// Evidence supports the claimed success.
    Pass,
    /// Built and reported success, but a signal contradicts a healthy result;
    /// worth a human or LLM second look before trusting it downstream.
    Suspect,
    /// The step did not actually succeed.
    Fail,
}

/// A structured verdict over a harness smoke outcome. Every non-`Pass` verdict
/// carries at least one concrete, signal-naming reason so the fix-and-recheck
/// loop and the UI both have actionable text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HarnessVerdict {
    pub level: VerdictLevel,
    pub reasons: Vec<String>,
}

/// A harness smoke result paired with its deterministic verdict -- the value
/// `harness_smoke` returns so every presentation layer surfaces the same
/// judgment (e.g. a "hollow pass" warning) instead of re-deriving it. The
/// summary is `#[serde(flatten)]`ed so existing consumers that read its fields
/// on the wire are unaffected; `verdict` is purely additive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeOutcome {
    #[serde(flatten)]
    pub summary: SmokeRunSummary,
    pub verdict: HarnessVerdict,
}

/// Assess a harness smoke outcome from its concrete signals, cheapest checks
/// first: never-built and self-reported failure are hard `Fail`s; a built,
/// passed run with a contradicting signal (hollow-pass execs, or crashes at
/// smoke scale) is `Suspect`; otherwise `Pass`.
#[must_use]
pub fn assess_harness_smoke(summary: &SmokeRunSummary, status: HarnessStatus) -> HarnessVerdict {
    // Fail: the harness never actually built, so no downstream signal is
    // trustworthy. A smoke verdict is only meaningful for a compiled artifact.
    if !matches!(
        status,
        HarnessStatus::Compiled | HarnessStatus::SmokePassed | HarnessStatus::Promoted
    ) {
        return HarnessVerdict {
            level: VerdictLevel::Fail,
            reasons: vec![format!(
                "harness was never built (status {status:?}); a smoke verdict requires a \
                 compiled harness"
            )],
        };
    }
    // Fail: the smoke run itself reported failure.
    if !summary.passed {
        return HarnessVerdict {
            level: VerdictLevel::Fail,
            reasons: vec!["smoke run reported passed=false".to_owned()],
        };
    }

    // Built and passed -- collect any signal that contradicts a healthy result.
    let mut reasons = Vec::new();
    if summary.execs_per_sec < MIN_MEANINGFUL_EXECS_PER_SEC {
        reasons.push(format!(
            "hollow pass: {:.2} execs/sec is below the {MIN_MEANINGFUL_EXECS_PER_SEC:.2} floor -- \
             the harness likely never reaches the target",
            summary.execs_per_sec
        ));
    }
    if summary.crashes > 0 {
        reasons.push(format!(
            "{} crash(es) during the smoke run -- rule out a harness bug before trusting this as \
             a target find",
            summary.crashes
        ));
    }

    if reasons.is_empty() {
        HarnessVerdict {
            level: VerdictLevel::Pass,
            reasons: vec![format!(
                "built, passed, and exercised the target at {:.0} execs/sec",
                summary.execs_per_sec
            )],
        }
    } else {
        HarnessVerdict {
            level: VerdictLevel::Suspect,
            reasons,
        }
    }
}

/// What the orchestrator should do next given a harness smoke verdict. Purely
/// advisory -- it is fed back as the harness tool result so the agent refines a
/// hollow pass instead of moving to promote it. It enforces nothing and
/// auto-runs nothing: promotion stays an explicit human action (AGENTS.md 2.12),
/// and a refine, if the agent chooses one, only ever PROPOSES a new revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessNextStep {
    /// True only when the verdict clears review for human promotion. A `Suspect`
    /// or `Fail` verdict is never promotion-ready.
    pub promotion_ready: bool,
    /// One-line instruction the orchestrator reads in its tool result.
    pub guidance: String,
}

/// Derive the orchestration guidance from a smoke verdict: a `Pass` points at
/// human promotion; a `Suspect`/`Fail` steers the agent to refine and re-smoke,
/// carrying the verdict's reasons so the correction is actionable.
#[must_use]
pub fn harness_next_step(verdict: &HarnessVerdict) -> HarnessNextStep {
    match verdict.level {
        VerdictLevel::Pass => HarnessNextStep {
            promotion_ready: true,
            guidance: "Smoke qualified. Ask the operator to review and explicitly promote \
                       this exact revision."
                .to_owned(),
        },
        VerdictLevel::Suspect | VerdictLevel::Fail => HarnessNextStep {
            promotion_ready: false,
            guidance: format!(
                "Do NOT promote this revision: the smoke verdict is not a clean pass -- {}. \
                 Call the `refine` tool to propose a coverage-guided revision, then re-run \
                 smoke qualification; only a clean pass is worth asking a human to promote.",
                verdict.reasons.join("; ")
            ),
        },
    }
}

/// The confidence an LLM crash verifier attaches to its judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// An LLM verifier's structured judgment of a triaged crash: whether it looks
/// like a deterministically-reproducing, genuine target bug versus a harness or
/// setup artifact. Advisory only -- it informs the human reviewer and never
/// closes, files, or reclassifies a crash on its own (AGENTS.md 2.12).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrashVerdict {
    pub reproduces_deterministically: bool,
    pub likely_target_bug: bool,
    pub confidence: Confidence,
    pub reasons: Vec<String>,
}

/// Parse an LLM response into a [`CrashVerdict`]. The model is asked for a strict
/// JSON object; real responses often wrap it in prose or code fences, so extract
/// the outermost `{...}` and deserialize leniently. Returns `None` on any
/// malformed response so the caller falls back to "no LLM opinion" rather than a
/// fabricated verdict.
#[must_use]
pub fn parse_crash_verdict(text: &str) -> Option<CrashVerdict> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        reproduces_deterministically: bool,
        #[serde(default)]
        likely_target_bug: bool,
        #[serde(default)]
        confidence: String,
        #[serde(default)]
        reasons: Vec<String>,
    }

    let raw: Raw = serde_json::from_str(extract_json_object(text)?).ok()?;
    let confidence = match raw.confidence.trim().to_ascii_lowercase().as_str() {
        "high" => Confidence::High,
        "medium" | "med" => Confidence::Medium,
        // Unknown or missing confidence is conservatively the lowest.
        _ => Confidence::Low,
    };
    Some(CrashVerdict {
        reproduces_deterministically: raw.reproduces_deterministically,
        likely_target_bug: raw.likely_target_bug,
        confidence,
        reasons: raw.reasons,
    })
}

/// Extract the outermost `{...}` from an LLM response so surrounding prose or
/// code fences do not defeat a JSON parse. Returns `None` when no brace pair is
/// present.
fn extract_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    (end > start).then(|| &text[start..=end])
}

/// An LLM harness verifier's opinion of whether a compiled, "passed" harness
/// actually drives the target with the fuzz input -- the judgment the execs/sec
/// heuristic cannot make (e.g. a harness that runs fast but ignores `data`/`size`
/// and calls the target with a constant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessLlmOpinion {
    pub exercises_target: bool,
    pub reasons: Vec<String>,
}

/// Parse an LLM response into a [`HarnessLlmOpinion`], leniently (prose/fences
/// tolerated). Returns `None` on any malformed response so the caller keeps the
/// deterministic verdict rather than acting on a fabricated opinion.
#[must_use]
pub fn parse_harness_llm_opinion(text: &str) -> Option<HarnessLlmOpinion> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        exercises_target: bool,
        #[serde(default)]
        reasons: Vec<String>,
    }
    let raw: Raw = serde_json::from_str(extract_json_object(text)?).ok()?;
    Some(HarnessLlmOpinion {
        exercises_target: raw.exercises_target,
        reasons: raw.reasons,
    })
}

/// Merge an LLM harness opinion into the deterministic verdict. The LLM may only
/// add caution: it downgrades a deterministic `Pass` to `Suspect` when it judges
/// the harness does not meaningfully exercise the target, and does nothing
/// otherwise -- it never upgrades a `Suspect`/`Fail`, and a `Pass` it agrees with
/// stays a `Pass`. A downgrade always carries a reason.
#[must_use]
pub fn merge_llm_harness_opinion(
    deterministic: HarnessVerdict,
    opinion: &HarnessLlmOpinion,
) -> HarnessVerdict {
    if deterministic.level == VerdictLevel::Pass && !opinion.exercises_target {
        let mut reasons = opinion.reasons.clone();
        if reasons.is_empty() {
            reasons.push(
                "LLM verifier judged the harness does not meaningfully exercise the target"
                    .to_owned(),
            );
        }
        return HarnessVerdict {
            level: VerdictLevel::Suspect,
            reasons,
        };
    }
    deterministic
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smoke(passed: bool, execs_per_sec: f64, crashes: u32) -> SmokeRunSummary {
        SmokeRunSummary {
            duration_secs: 5,
            execs_per_sec,
            crashes,
            passed,
            source_sha256: None,
            binary_sha256: None,
            run_id: None,
        }
    }

    #[test]
    fn a_never_built_harness_fails() {
        let verdict = assess_harness_smoke(&smoke(true, 5000.0, 0), HarnessStatus::Draft);
        assert_eq!(verdict.level, VerdictLevel::Fail);
        assert!(
            !verdict.reasons.is_empty(),
            "a fail must explain itself: {verdict:?}"
        );
    }

    #[test]
    fn a_failed_smoke_fails() {
        let verdict = assess_harness_smoke(&smoke(false, 5000.0, 0), HarnessStatus::Compiled);
        assert_eq!(verdict.level, VerdictLevel::Fail);
        assert!(!verdict.reasons.is_empty(), "{verdict:?}");
    }

    #[test]
    fn a_healthy_smoke_passes() {
        let verdict = assess_harness_smoke(&smoke(true, 5000.0, 0), HarnessStatus::SmokePassed);
        assert_eq!(verdict.level, VerdictLevel::Pass, "{verdict:?}");
    }

    #[test]
    fn a_pass_verdict_is_promotion_ready_and_points_at_promotion() {
        let step = harness_next_step(&HarnessVerdict {
            level: VerdictLevel::Pass,
            reasons: vec!["exercised the target".to_owned()],
        });
        assert!(step.promotion_ready, "{step:?}");
        assert!(
            step.guidance.to_lowercase().contains("promote"),
            "a pass points at promotion: {step:?}"
        );
    }

    #[test]
    fn a_suspect_verdict_is_not_promotion_ready_and_steers_to_refine_with_reasons() {
        let step = harness_next_step(&HarnessVerdict {
            level: VerdictLevel::Suspect,
            reasons: vec!["hollow pass: 0.00 execs/sec below floor".to_owned()],
        });
        assert!(
            !step.promotion_ready,
            "a hollow pass is never promotion-ready: {step:?}"
        );
        let lower = step.guidance.to_lowercase();
        assert!(lower.contains("refine"), "steers to refine: {step:?}");
        assert!(
            lower.contains("not promote"),
            "warns off promotion: {step:?}"
        );
        assert!(
            step.guidance.contains("0.00 execs/sec"),
            "carries the verdict reasons: {step:?}"
        );
    }

    #[test]
    fn a_fail_verdict_is_not_promotion_ready() {
        let step = harness_next_step(&HarnessVerdict {
            level: VerdictLevel::Fail,
            reasons: vec!["smoke run reported passed=false".to_owned()],
        });
        assert!(!step.promotion_ready, "{step:?}");
        assert!(step.guidance.to_lowercase().contains("refine"), "{step:?}");
    }

    #[test]
    fn parses_a_clean_crash_verdict() {
        let text = r#"{"reproduces_deterministically": true, "likely_target_bug": true,
            "confidence": "high", "reasons": ["ASan heap-buffer-overflow at a concrete line"]}"#;
        let verdict = parse_crash_verdict(text).expect("clean JSON parses");
        assert!(verdict.reproduces_deterministically && verdict.likely_target_bug);
        assert_eq!(verdict.confidence, Confidence::High);
        assert!(!verdict.reasons.is_empty());
    }

    #[test]
    fn parses_a_verdict_wrapped_in_prose_and_code_fences() {
        // LLMs rarely return bare JSON; the parser must dig it out of prose/fences.
        let text = "Here is my assessment:\n```json\n{\"reproduces_deterministically\": false, \
            \"likely_target_bug\": false, \"confidence\": \"LOW\", \
            \"reasons\": [\"timeout only, no stack\"]}\n```\nHope that helps.";
        let verdict = parse_crash_verdict(text).expect("embedded JSON is extracted");
        assert!(!verdict.reproduces_deterministically && !verdict.likely_target_bug);
        assert_eq!(
            verdict.confidence,
            Confidence::Low,
            "confidence is case-insensitive"
        );
    }

    #[test]
    fn a_malformed_response_yields_no_verdict() {
        // No fabricated verdict: the caller falls back to no-opinion.
        assert!(parse_crash_verdict("I cannot determine this.").is_none());
        assert!(parse_crash_verdict("").is_none());
    }

    #[test]
    fn unknown_confidence_defaults_to_low_and_missing_fields_default() {
        let text = r#"{"likely_target_bug": true, "confidence": "banana"}"#;
        let verdict = parse_crash_verdict(text).expect("partial JSON still parses");
        assert_eq!(
            verdict.confidence,
            Confidence::Low,
            "unknown confidence -> Low"
        );
        assert!(
            !verdict.reproduces_deterministically,
            "missing bool -> false"
        );
        assert!(verdict.reasons.is_empty(), "missing reasons -> empty");
    }

    #[test]
    fn parses_a_harness_llm_opinion_from_prose() {
        let text = "Assessment:\n```json\n{\"exercises_target\": false, \
            \"reasons\": [\"ignores data/size; calls parse() with a fixed literal\"]}\n```";
        let opinion = parse_harness_llm_opinion(text).expect("embedded JSON parses");
        assert!(!opinion.exercises_target);
        assert!(opinion
            .reasons
            .iter()
            .any(|r| r.contains("ignores data/size")));
        assert!(parse_harness_llm_opinion("no json here").is_none());
    }

    #[test]
    fn llm_downgrades_a_pass_it_judges_a_hollow_harness() {
        let deterministic = HarnessVerdict {
            level: VerdictLevel::Pass,
            reasons: vec!["exercised at 5000 execs/sec".to_owned()],
        };
        let opinion = HarnessLlmOpinion {
            exercises_target: false,
            reasons: vec!["harness ignores the fuzz input".to_owned()],
        };
        let merged = merge_llm_harness_opinion(deterministic, &opinion);
        assert_eq!(merged.level, VerdictLevel::Suspect, "{merged:?}");
        assert!(
            merged
                .reasons
                .iter()
                .any(|r| r.contains("ignores the fuzz input")),
            "carries the LLM reason: {merged:?}"
        );
    }

    #[test]
    fn a_downgrade_always_carries_a_reason_even_when_the_llm_gave_none() {
        let merged = merge_llm_harness_opinion(
            HarnessVerdict {
                level: VerdictLevel::Pass,
                reasons: Vec::new(),
            },
            &HarnessLlmOpinion {
                exercises_target: false,
                reasons: Vec::new(),
            },
        );
        assert_eq!(merged.level, VerdictLevel::Suspect);
        assert!(
            !merged.reasons.is_empty(),
            "a suspect verdict must explain itself"
        );
    }

    #[test]
    fn llm_never_upgrades_or_touches_a_verdict_it_agrees_with() {
        // Agreeing with a Pass leaves it a Pass.
        let pass = HarnessVerdict {
            level: VerdictLevel::Pass,
            reasons: vec!["ok".to_owned()],
        };
        let agree = HarnessLlmOpinion {
            exercises_target: true,
            reasons: Vec::new(),
        };
        assert_eq!(
            merge_llm_harness_opinion(pass, &agree).level,
            VerdictLevel::Pass
        );
        // The LLM never upgrades a Suspect/Fail, regardless of its opinion.
        for level in [VerdictLevel::Suspect, VerdictLevel::Fail] {
            let determ = HarnessVerdict {
                level,
                reasons: vec!["deterministic".to_owned()],
            };
            let optimistic = HarnessLlmOpinion {
                exercises_target: true,
                reasons: Vec::new(),
            };
            assert_eq!(merge_llm_harness_opinion(determ, &optimistic).level, level);
        }
    }

    #[test]
    fn smoke_outcome_serializes_the_summary_flat_with_an_additive_verdict() {
        // The wire contract the web/GUI handlers depend on: the summary fields
        // stay at the top level (existing consumers unaffected) and `verdict` is
        // added alongside, never nesting the summary under a new key.
        let summary = smoke(true, 0.0, 0);
        let outcome = SmokeOutcome {
            verdict: assess_harness_smoke(&summary, HarnessStatus::SmokePassed),
            summary,
        };
        let json = serde_json::to_value(&outcome).unwrap();
        assert!(
            json.get("execs_per_sec").is_some() && json.get("passed").is_some(),
            "summary must be flattened to the top level: {json}"
        );
        assert_eq!(
            json["verdict"]["level"], "suspect",
            "verdict is additive: {json}"
        );
        assert!(
            json["verdict"]["reasons"]
                .as_array()
                .is_some_and(|reasons| !reasons.is_empty()),
            "a suspect verdict carries reasons: {json}"
        );
    }

    #[test]
    fn a_hollow_pass_with_near_zero_execs_is_suspect() {
        // Compiled + passed, but the harness never meaningfully ran: the classic
        // silent failure this tier exists to catch.
        let verdict = assess_harness_smoke(&smoke(true, 0.0, 0), HarnessStatus::SmokePassed);
        assert_eq!(verdict.level, VerdictLevel::Suspect, "{verdict:?}");
        assert!(
            verdict.reasons.iter().any(|reason| reason.contains("exec")),
            "must name the execs/sec signal: {verdict:?}"
        );
    }

    #[test]
    fn crashes_during_smoke_are_suspect() {
        let verdict = assess_harness_smoke(&smoke(true, 5000.0, 3), HarnessStatus::SmokePassed);
        assert_eq!(verdict.level, VerdictLevel::Suspect, "{verdict:?}");
        assert!(
            verdict
                .reasons
                .iter()
                .any(|reason| reason.to_lowercase().contains("crash")),
            "must name the crash signal: {verdict:?}"
        );
    }

    #[test]
    fn every_non_pass_verdict_carries_a_reason() {
        let cases = [
            (true, 5000.0, 0_u32, HarnessStatus::Draft),
            (false, 5000.0, 0, HarnessStatus::Compiled),
            (true, 0.0, 0, HarnessStatus::SmokePassed),
            (true, 5000.0, 2, HarnessStatus::SmokePassed),
        ];
        for (passed, execs, crashes, status) in cases {
            let verdict = assess_harness_smoke(&smoke(passed, execs, crashes), status);
            if verdict.level != VerdictLevel::Pass {
                assert!(
                    !verdict.reasons.is_empty(),
                    "non-pass must explain: {verdict:?}"
                );
            }
        }
    }
}
