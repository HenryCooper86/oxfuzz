//! One-command onboarding pipeline (`oxfuzz fuzz`): discover -> harness ->
//! smoke -> promote -> campaign, composed from the existing container
//! operations so every presentation layer shares one orchestration
//! (Engineering Protocol 2.9).
//!
//! The pipeline is a composition, not a new code path: target discovery is
//! [`ServiceContainer::discover`], harness work is
//! [`ServiceContainer::harness_generate`] +
//! [`ServiceContainer::harness_smoke_with_review_bypass`], the human gate is
//! [`ServiceContainer::harness_promote`] (which enforces
//! `Action::PromoteHarness` approval, smoke evidence, and digest matches), and
//! the run is [`ServiceContainer::run_campaign_observed`]. Promotion is never
//! skipped for a fresh harness, and a denied promotion stops the pipeline
//! before any campaign rather than falling back to an un-promoted run.

use std::path::Path;

use hf_core::engine::{EngineKind, FuzzProgress};
use hf_core::error::ClassifiedError;
use hf_core::harness::{Harness, HarnessStatus};
use hf_core::target::{TargetCandidate, TargetLanguage};
use uuid::Uuid;

use super::project_identity::select_target_candidate;
use super::{CampaignOutcome, ServiceContainer};
use crate::harness_review::HarnessReviewBypass;
use crate::verification::VerdictLevel;

/// Auto-repair passes granted to the pipeline's compile stage. The standalone
/// `harness` command defaults to no repairs because the operator watches a
/// single draft; the pipeline drafts unattended, so it always repairs before
/// giving up on a target. Owned here (Engineering Protocol 2.15): no CLI flag
/// or config field varies it.
pub const FUZZ_PIPELINE_REPAIRS: usize = 2;

/// Operator request for the onboarding pipeline. Every field is explicit:
/// `target: None` auto-picks the highest-fit candidate the engine can drive,
/// and `lang: None` scans every supported language instead of defaulting one.
pub struct FuzzRequest<'a> {
    /// Project root path.
    pub project: &'a Path,
    /// Target symbol (or `file::symbol`); `None` auto-picks by fit score.
    pub target: Option<&'a str>,
    /// Fuzzing engine.
    pub engine: EngineKind,
    /// Target language; `None` auto-detects from discovery.
    pub lang: Option<TargetLanguage>,
    /// Per-iteration fuzz duration in seconds.
    pub duration_secs: u64,
    /// Max run -> triage iterations.
    pub iterations: usize,
    /// Per-input timeout override in milliseconds; `None` applies the
    /// configured `fuzzing.default_timeout_ms`.
    pub timeout_ms: Option<u64>,
    /// Per-invocation AFL++ session resume request (the CLI's `--resume`);
    /// `None` applies the configured `fuzzing.default_resume`. Applies to
    /// every campaign iteration: iteration N continues iteration N-1's tree.
    pub resume: Option<bool>,
    /// Per-invocation opt-out of the independent LLM pre-execution review
    /// (the CLI's `--no-llm-review`); the human promotion gate is unaffected.
    pub review_bypass: HarnessReviewBypass,
    /// Force a fresh draft even when a promoted harness already exists for the
    /// target and engine.
    pub fresh: bool,
    /// Sanitizer for a freshly built harness (the CLI's `--sanitizer`);
    /// `None` applies the configured `fuzzing.default_sanitizer`. A promoted
    /// harness built with a DIFFERENT sanitizer is not reused: the request is
    /// honored by drafting and qualifying a fresh revision (the promotion gate
    /// still applies). The same value constrains the campaign stage.
    pub sanitizer: Option<hf_core::target::Sanitizer>,
}

/// A stage boundary of the onboarding pipeline, reported through the stage
/// sink so the operator watches the pipeline advance. Carries the facts the
/// stage acts on (target, engine, reuse); rendering belongs to the
/// presentation layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzStage {
    /// Scanning the project and picking a target. `lang: None` means the scan
    /// covers every supported language.
    Discover {
        /// The requested language, or `None` for auto-detection.
        lang: Option<TargetLanguage>,
    },
    /// Drafting and compiling (with the repair loop), or reusing the promoted
    /// revision when `reused` is set.
    Harness {
        /// The selected target symbol.
        target: String,
        /// The fuzzing engine the harness is built for.
        engine: EngineKind,
        /// `true` when an already-promoted revision is reused and no draft,
        /// compile, or repair runs.
        reused: bool,
    },
    /// Smoke-qualifying the compiled harness (after the pre-execution review).
    Smoke {
        /// The selected target symbol.
        target: String,
        /// The fuzzing engine the harness is built for.
        engine: EngineKind,
    },
    /// The human promotion gate for the smoke-qualified revision.
    Promote {
        /// The selected target symbol.
        target: String,
        /// The fuzzing engine the harness is built for.
        engine: EngineKind,
    },
    /// The bounded campaign over the promoted harness.
    Campaign {
        /// The selected target symbol.
        target: String,
        /// The fuzzing engine driving the campaign.
        engine: EngineKind,
        /// Per-iteration fuzz duration in seconds.
        duration_secs: u64,
        /// Max run -> triage iterations.
        iterations: usize,
    },
}

/// What a completed pipeline produced: the promoted harness revision and the
/// campaign outcome over it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FuzzOutcome {
    /// The fuzzed target symbol.
    pub target: String,
    /// The target's language (auto-detected unless the request pinned it).
    pub lang: TargetLanguage,
    /// The engine the campaign ran.
    pub engine: EngineKind,
    /// Persisted id of the promoted harness revision the campaign ran.
    pub harness_id: Uuid,
    /// `true` when an already-promoted harness was reused and no draft, smoke,
    /// or promotion ran in this invocation.
    pub harness_reused: bool,
    /// LLM repair passes the compile needed (always 0 for a reused harness).
    pub repairs_used: usize,
    /// The campaign outcome (iterations, coverage, crashes, termination).
    pub campaign: CampaignOutcome,
}

/// Wrap a stage failure with the stage name and a remediation hint, so a
/// failure at any point of the pipeline says both what stopped and what to try
/// next. The underlying error's own text (and classification prefix) is kept.
fn stage_failure(stage: &str, error: &ClassifiedError, remediation: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!(
        "fuzz {stage} failed: {error}; remediation: {remediation}"
    ))
}

/// The promote stage is the human gate (Engineering Protocol 2.12): a denial
/// stops the pipeline before any campaign, and the message must name what was
/// denied and how to approve it.
fn promote_failure(target: &str, error: &ClassifiedError) -> ClassifiedError {
    let text = error.to_string();
    if text.contains("guardrail denied") {
        ClassifiedError::Validation(format!(
            "fuzz stopped at the promote stage: promotion of the smoke-qualified harness for \
             '{target}' was denied ({text}). Nothing was promoted and no fuzzer ran. Answer the \
             approval prompt with 'y', or export HF_AUTO_APPROVE=1 for an unattended run, then \
             re-run `oxfuzz fuzz`."
        ))
    } else {
        stage_failure(
            "promote",
            error,
            "promotion requires a crash-free smoke run of the exact active revision; \
             re-run `oxfuzz fuzz`, or inspect the harness with `oxfuzz harness`",
        )
    }
}

impl ServiceContainer {
    /// Run the whole onboarding pipeline in one operation: discover (and pick)
    /// a target, reuse its promoted harness or draft + compile + smoke + promote
    /// a fresh one, then run a bounded campaign over it.
    ///
    /// Every stage boundary is reported through `on_stage`; campaign progress
    /// flows through `on_progress` exactly as for
    /// [`ServiceContainer::run_campaign_observed`]. A failure at any stage
    /// returns an error naming the stage and a remediation; a denied promotion
    /// stops the pipeline before any campaign.
    ///
    /// # Errors
    /// Returns `ClassifiedError` when discovery finds no usable target, the
    /// harness fails to compile after [`FUZZ_PIPELINE_REPAIRS`] repairs, smoke
    /// qualification fails or finds crashes, promotion is denied, or the
    /// campaign itself fails.
    pub async fn fuzz_onboard(
        &self,
        request: FuzzRequest<'_>,
        on_stage: &(dyn Fn(FuzzStage) + Send + Sync),
        on_progress: &(dyn Fn(FuzzProgress) + Send + Sync),
    ) -> Result<FuzzOutcome, ClassifiedError> {
        let project = request.project;
        let engine = request.engine;

        // Stage 1: discover targets and pick one (explicit or top-ranked).
        on_stage(FuzzStage::Discover { lang: request.lang });
        let (target, lang) = self
            .fuzz_pick_target(project, request.target, request.lang, engine)
            .await
            .map_err(|error| {
                stage_failure(
                    "discover",
                    &error,
                    "pass --lang to force a language scan or --target to name a function; \
                     `oxfuzz discover` lists what the scanners see",
                )
            })?;

        // Stage 2: reuse the promoted revision for (target, engine) when one is
        // active, unless the operator asked for a fresh draft. A requested
        // sanitizer the active revision was not built with forces a fresh
        // draft: reusing it would silently fuzz a different build than asked.
        let reused = if request.fresh {
            None
        } else {
            self.reusable_promoted_harness(project, &target, engine, lang)
                .await
                .map_err(|error| {
                    stage_failure(
                        "harness",
                        &error,
                        "the retained harness state could not be read; re-run with --fresh to re-draft",
                    )
                })?
                .filter(|harness| {
                    request
                        .sanitizer
                        .is_none_or(|requested| requested == harness.sanitizer)
                })
        };

        let (harness, repairs_used, harness_reused) = if let Some(harness) = reused {
            on_stage(FuzzStage::Harness {
                target: target.clone(),
                engine,
                reused: true,
            });
            (harness, 0, true)
        } else {
            on_stage(FuzzStage::Harness {
                target: target.clone(),
                engine,
                reused: false,
            });
            let generated = self
                .harness_generate(
                    project,
                    &target,
                    engine,
                    lang,
                    FUZZ_PIPELINE_REPAIRS,
                    request.sanitizer,
                )
                .await
                .map_err(|error| {
                    stage_failure(
                        "harness",
                        &error,
                        "for a compile failure, --ai require makes a missing model an explicit \
                         error and the work-order flow authors the harness manually; for a \
                         sandbox error, `oxfuzz doctor` checks the sandbox image",
                    )
                })?;

            // Stage 3: smoke qualification behind the pre-execution review.
            on_stage(FuzzStage::Smoke {
                target: target.clone(),
                engine,
            });
            let smoke = self
                .harness_smoke_with_review_bypass(
                    project,
                    &target,
                    engine,
                    lang,
                    request.review_bypass,
                )
                .await
                .map_err(|error| {
                    stage_failure(
                        "smoke",
                        &error,
                        "fix the harness and re-run; without a provider the review gate needs \
                         the explicit --no-llm-review opt-in",
                    )
                })?;
            if smoke.summary.crashes > 0 {
                return Err(ClassifiedError::Validation(format!(
                    "fuzz smoke stopped: the qualification run of '{target}' found {} \
                     crash(es), so the revision cannot be promoted as crash-free. This is \
                     likely a real finding: review it with `oxfuzz triage`; approving a \
                     crash-bearing revision is a separate, explicit human decision.",
                    smoke.summary.crashes
                )));
            }
            match smoke.verdict.level {
                VerdictLevel::Pass => {}
                VerdictLevel::Suspect => on_progress(FuzzProgress::LogLine(format!(
                    "smoke verdict SUSPECT for '{target}' (verify at the promotion prompt): {}",
                    smoke.verdict.reasons.join("; ")
                ))),
                VerdictLevel::Fail => {
                    return Err(ClassifiedError::Validation(format!(
                        "fuzz smoke failed for '{target}': {}; fix the harness and re-run",
                        smoke.verdict.reasons.join("; ")
                    )));
                }
            }

            // Stage 4: the human promotion gate. A denial stops here.
            on_stage(FuzzStage::Promote {
                target: target.clone(),
                engine,
            });
            let promoted = self
                .harness_promote(project, &target, engine)
                .await
                .map_err(|error| promote_failure(&target, &error))?;
            (promoted, generated.repairs_used, false)
        };

        // Stage 5: the bounded campaign over the promoted revision. The campaign
        // re-verifies promotion and build inputs itself (Engineering Protocol
        // 2.19), so a stale reuse decision cannot slip an un-promoted harness in.
        on_stage(FuzzStage::Campaign {
            target: target.clone(),
            engine,
            duration_secs: request.duration_secs,
            iterations: request.iterations,
        });
        let campaign = self
            .run_campaign_observed(
                project,
                Some(&target),
                engine,
                lang,
                request.duration_secs,
                request.timeout_ms,
                request.resume,
                request.sanitizer,
                request.iterations,
                on_progress,
            )
            .await
            .map_err(|error| {
                stage_failure(
                    "campaign",
                    &error,
                    "the harness is promoted; `oxfuzz campaign` reruns just this stage",
                )
            })?;

        Ok(FuzzOutcome {
            target,
            lang,
            engine,
            harness_id: harness.id,
            harness_reused,
            repairs_used,
            campaign,
        })
    }

    /// Discover candidates and pick the pipeline's target.
    ///
    /// With `lang` set, one scan runs; with `lang: None` every supported
    /// language is scanned and the merged candidates compete. An explicit
    /// `target` is resolved against the discovered candidates (with the
    /// `file::symbol` ambiguity rules of the other commands); otherwise the
    /// highest-fit candidate the engine can drive wins.
    async fn fuzz_pick_target(
        &self,
        project: &Path,
        target: Option<&str>,
        lang: Option<TargetLanguage>,
        engine: EngineKind,
    ) -> Result<(String, TargetLanguage), ClassifiedError> {
        let candidates: Vec<TargetCandidate> = match lang {
            Some(lang) => self.discover(project, lang).await?.candidates,
            None => self.discover_every_language(project).await?,
        };
        if let Some(target) = target {
            let candidate = select_target_candidate(&candidates, target)?.ok_or_else(|| {
                ClassifiedError::Validation(format!(
                    "target '{target}' not found among the {} discovered candidate(s)",
                    candidates.len()
                ))
            })?;
            if !engine.supports_language(candidate.language) {
                return Err(ClassifiedError::Validation(format!(
                    "engine '{}' cannot drive a {:?} harness for '{target}'; \
                     choose an engine that supports {:?}",
                    engine.as_str(),
                    candidate.language,
                    candidate.language
                )));
            }
            return Ok((candidate.symbol.clone(), candidate.language));
        }
        // Auto-pick is a deterministic fit-score sort over the candidates the
        // chosen engine can actually drive (same rule as `run_campaign`).
        let mut drivable: Vec<&TargetCandidate> = candidates
            .iter()
            .filter(|candidate| engine.supports_language(candidate.language))
            .collect();
        drivable.sort_by(|a, b| {
            b.fit_score
                .partial_cmp(&a.fit_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let Some(best) = drivable.first() else {
            if candidates.is_empty() {
                return Err(ClassifiedError::Validation(
                    "no fuzzable targets discovered in the project".to_owned(),
                ));
            }
            return Err(ClassifiedError::Validation(format!(
                "discovered {} candidate(s), but engine '{}' cannot drive any of their languages",
                candidates.len(),
                engine.as_str()
            )));
        };
        Ok((best.symbol.clone(), best.language))
    }

    /// Scan every supported language and merge the candidates. Languages whose
    /// scanner is unavailable in this build are skipped (the same tolerance
    /// `resolve_target_candidate_any_language` applies); every other discovery
    /// error propagates.
    async fn discover_every_language(
        &self,
        project: &Path,
    ) -> Result<Vec<TargetCandidate>, ClassifiedError> {
        let mut all = Vec::new();
        for language in [
            TargetLanguage::C,
            TargetLanguage::Cpp,
            TargetLanguage::Rust,
            TargetLanguage::Go,
            TargetLanguage::Python,
        ] {
            match self.discover(project, language).await {
                Ok(inventory) => all.extend(inventory.candidates),
                Err(ClassifiedError::Validation(message))
                    if message.contains("not yet supported by the scanner") => {}
                Err(error) => return Err(error),
            }
        }
        Ok(all)
    }

    /// The workspace-active harness for (target, engine) when it is already
    /// promoted for the requested language, i.e. exactly the revision
    /// `run_campaign` would admit. `None` means the pipeline drafts and
    /// qualifies a fresh one: anything short of a promoted active revision --
    /// never compiled, stale markers, a draft or smoked-but-unapproved
    /// revision -- is not reusable campaign evidence.
    async fn reusable_promoted_harness(
        &self,
        project: &Path,
        target: &str,
        engine: EngineKind,
        lang: TargetLanguage,
    ) -> Result<Option<Harness>, ClassifiedError> {
        match self.active_harness(project, target, engine).await {
            Ok(harness)
                if harness.status == HarnessStatus::Promoted && harness.language == lang =>
            {
                Ok(Some(harness))
            }
            // A non-promoted active revision is not reusable campaign evidence,
            // and every Validation failure names a way there is no usable
            // active revision at all (never compiled, stale workspace markers,
            // engine mismatch); either way the pipeline drafts and qualifies a
            // fresh one.
            Ok(_) | Err(ClassifiedError::Validation(_)) => Ok(None),
            // Infrastructure failures still propagate.
            Err(error) => Err(error),
        }
    }
}
