//! `oxfuzz fuzz`: the one-command onboarding pipeline. The orchestration lives
//! in `hf-service` (`ServiceContainer::fuzz_onboard`); this module parses
//! flags, renders stage headers and the outcome, and owns the `--json` output
//! routing (Engineering Protocol 2.9).

use std::path::Path;

use hf_service::{FuzzOutcome, FuzzRequest, FuzzStage};

use crate::ai_policy::apply_ai_policy;
use crate::args::AiOption;
use crate::parse::{parse_engine, parse_lang, parse_sanitizer};

/// Print one operator-facing line on stdout, or on stderr when `--json` keeps
/// stdout machine-readable.
fn print_line(json: bool, line: &str) {
    if json {
        eprintln!("{line}");
    } else {
        println!("{line}");
    }
}

/// Render one stage boundary as a short header line: which stage, and the
/// target/engine/revision facts it acts on.
fn render_stage(project: &Path, stage: &FuzzStage) -> String {
    match stage {
        FuzzStage::Discover { lang } => {
            let language = lang.map_or("auto-detect".to_owned(), |lang| lang.as_str().to_owned());
            format!(
                "--- [1/5] discover: scanning {} (language: {language}) ---",
                project.display()
            )
        }
        FuzzStage::Harness {
            target,
            engine,
            reused,
        } => {
            if *reused {
                format!(
                    "--- [2/5] harness: reusing the promoted {} revision for '{target}' ---",
                    engine.as_str()
                )
            } else {
                format!(
                    "--- [2/5] harness: drafting and compiling '{target}' for {} (auto-repair up to {}x) ---",
                    engine.as_str(),
                    hf_service::FUZZ_PIPELINE_REPAIRS
                )
            }
        }
        FuzzStage::Smoke { target, .. } => {
            format!("--- [3/5] smoke: qualifying '{target}' ---")
        }
        FuzzStage::Promote { target, .. } => {
            format!("--- [4/5] promote: '{target}' needs your approval ---")
        }
        FuzzStage::Campaign {
            target,
            engine,
            duration_secs,
            iterations,
        } => format!(
            "--- [5/5] campaign: {iterations} iteration(s) x {duration_secs}s on '{target}' ({}) ---",
            engine.as_str()
        ),
    }
}

fn render_outcome(outcome: &FuzzOutcome) {
    println!(
        "[fuzz] done: target={} lang={} engine={} harness={} reused={} repairs={}",
        outcome.target,
        outcome.lang.as_str(),
        outcome.engine.as_str(),
        outcome.harness_id,
        outcome.harness_reused,
        outcome.repairs_used,
    );
    println!(
        "[fuzz] campaign: iterations={} edges={} crashes={} termination={:?}",
        outcome.campaign.iterations,
        outcome.campaign.edges,
        outcome.campaign.crashes,
        outcome.campaign.termination,
    );
    if let Some(hangs) = outcome.campaign.hangs {
        println!("  hangs (per-input timeouts across iterations): {hangs}");
    }
    if let Some(refine) = &outcome.campaign.refine {
        // A coverage plateau proposed a targeted refined harness. It is only
        // Compiled (never promoted/auto-run); the operator reviews and promotes.
        println!("  coverage-plateau refine: {}", refine.note);
    }
}

pub(crate) async fn cmd_fuzz(args: crate::args::FuzzArgs) -> anyhow::Result<()> {
    let crate::args::FuzzArgs {
        project,
        target,
        engine,
        lang,
        duration_secs,
        iterations,
        timeout_ms,
        sanitizer,
        ai,
        switches,
        json,
    } = args;
    let crate::args::FuzzSwitchArgs {
        no_llm_review,
        fresh,
        resume,
    } = switches;
    let target = target.as_deref();
    let engine = parse_engine(&engine)?;
    let lang = lang.as_deref().map(parse_lang).transpose()?;
    let sanitizer = sanitizer.as_deref().map(parse_sanitizer).transpose()?;
    let container =
        apply_ai_policy(crate::approval::bootstrap().await, ai, "this fuzz pipeline").await?;
    if ai == AiOption::Off {
        print_line(
            json,
            "[fuzz] --ai off: no model is called at any stage of this pipeline.",
        );
    }
    let on_stage = |stage: FuzzStage| print_line(json, &render_stage(&project, &stage));
    let on_progress: Box<dyn Fn(hf_service::FuzzProgress) + Send + Sync> = if json {
        Box::new(crate::commands::status::eprinting_sink())
    } else {
        Box::new(crate::commands::status::printing_sink())
    };
    let outcome = container
        .fuzz_onboard(
            FuzzRequest {
                project: &project,
                target,
                engine,
                lang,
                duration_secs,
                iterations,
                timeout_ms,
                // An absent flag defers to the configured
                // `fuzzing.default_resume`.
                resume: resume.then_some(true),
                review_bypass: if no_llm_review {
                    hf_service::HarnessReviewBypass::Requested
                } else {
                    hf_service::HarnessReviewBypass::NotRequested
                },
                fresh,
                // An absent flag defers to the configured
                // `fuzzing.default_sanitizer` for a fresh build and imposes no
                // constraint on a reused promoted harness.
                sanitizer,
            },
            &on_stage,
            on_progress.as_ref(),
        )
        .await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        render_outcome(&outcome);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hf_service::FuzzStage;
    use hf_service::{EngineKind, TargetLanguage};

    use super::render_stage;

    #[test]
    fn stage_headers_name_the_stage_target_and_engine() {
        let project = std::path::Path::new("/proj");
        let discover = render_stage(&project, &FuzzStage::Discover { lang: None });
        assert!(discover.contains("discover"), "{discover}");
        assert!(discover.contains("auto-detect"), "{discover}");
        assert!(discover.contains("/proj"), "{discover}");

        let discover = render_stage(
            &project,
            &FuzzStage::Discover {
                lang: Some(TargetLanguage::C),
            },
        );
        assert!(discover.contains("language: c"), "{discover}");

        let fresh = render_stage(
            &project,
            &FuzzStage::Harness {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
                reused: false,
            },
        );
        assert!(fresh.contains("parse_entry"), "{fresh}");
        assert!(fresh.contains("libfuzzer"), "{fresh}");
        assert!(!fresh.contains("reusing"), "{fresh}");

        let reused = render_stage(
            &project,
            &FuzzStage::Harness {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
                reused: true,
            },
        );
        assert!(reused.contains("reusing"), "{reused}");

        let promote = render_stage(
            &project,
            &FuzzStage::Promote {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
            },
        );
        assert!(promote.contains("approval"), "{promote}");

        let campaign = render_stage(
            &project,
            &FuzzStage::Campaign {
                target: "parse_entry".to_owned(),
                engine: EngineKind::AflPlusPlus,
                duration_secs: 60,
                iterations: 3,
            },
        );
        assert!(campaign.contains("60s"), "{campaign}");
        assert!(campaign.contains("afl++"), "{campaign}");
    }
}
