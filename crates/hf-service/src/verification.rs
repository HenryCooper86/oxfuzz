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
