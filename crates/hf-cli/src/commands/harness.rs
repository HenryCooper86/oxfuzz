use hf_service::{EngineKind, ServiceContainer, TargetLanguage, VerdictLevel};
use std::path::PathBuf;

use crate::args::AiOption;
use crate::parse::{parse_duration, parse_engine, parse_lang, parse_sanitizer};

pub(crate) enum HarnessOutput {
    Text,
    Json,
}

pub(crate) async fn cmd_harness(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    draft_only: bool,
    ai: AiOption,
    repair: usize,
    refine: bool,
    promote: bool,
    review_bypass: hf_service::HarnessReviewBypass,
    sanitizer: Option<&str>,
    output: HarnessOutput,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let sanitizer = sanitizer.map(parse_sanitizer).transpose()?;
    // --draft-only stops before compile/smoke/promotion, so flags that only
    // take effect in those stages must not be silently ignored. (--refine is
    // exempt: it honors --repair during its recompile.)
    if draft_only && !refine && repair > 0 {
        eprintln!("warning: --repair is ignored with --draft-only (the harness is not compiled)");
    }
    if draft_only && promote {
        eprintln!("warning: --promote is ignored with --draft-only (no smoke qualification runs)");
    }
    if draft_only && review_bypass == hf_service::HarnessReviewBypass::Requested {
        eprintln!(
            "warning: --no-llm-review is ignored with --draft-only (no smoke qualification runs)"
        );
    }
    let container = crate::approval::bootstrap().await;

    // With --refine, reshape the existing harness toward uncovered reachable
    // functions (coverage-guided), then recompile with auto-repair.
    if refine {
        if sanitizer.is_some() {
            // Refinement rebuilds the SAME harness identity: it keeps the
            // active revision's sanitizer rather than taking a new one, so a
            // requested sanitizer here would be silently ignored.
            anyhow::bail!(
                "--sanitizer does not combine with --refine: refinement keeps the active \
                 revision's build sanitizer; use a fresh `oxfuzz harness --sanitizer ...` to \
                 change it"
            );
        }
        println!("--- Refining harness (coverage-guided) ---");
        let outcome = container
            .harness_refine(&project, target, engine, lang, repair.max(1))
            .await?;
        println!(
            "refined: status={:?} repairs_used={}",
            outcome.status, outcome.repairs_used
        );
        // Refine must recompile to measure coverage, but --draft-only still means
        // "stop before smoke qualification and promotion".
        if draft_only {
            println!(
                "--draft-only: refined and recompiled; skipping smoke qualification and promotion."
            );
            return Ok(());
        }
        qualify_harness(
            &container,
            &project,
            target,
            engine,
            lang,
            promote,
            review_bypass,
        )
        .await?;
        return Ok(());
    }

    // With --repair, use the draft -> compile -> repair loop, which recovers
    // harnesses that fail to build on the first draft.
    if repair > 0 && !draft_only {
        println!("--- Generating harness (auto-repair up to {repair}x) ---");
        let outcome = container
            .harness_generate(&project, target, engine, lang, repair, sanitizer)
            .await?;
        println!(
            "compile: status={:?} repairs_used={}",
            outcome.status, outcome.repairs_used
        );
        print_lint_findings(&outcome.lint);
        qualify_harness(
            &container,
            &project,
            target,
            engine,
            lang,
            promote,
            review_bypass,
        )
        .await?;
        return Ok(());
    }

    let draft = container
        .harness_draft_with_policy(&project, target, engine, lang, ai.into(), sanitizer)
        .await?;
    if matches!(output, HarnessOutput::Json) {
        println!("{}", serde_json::to_string_pretty(&draft)?);
        return Ok(());
    }
    println!("--- Harness draft ---");
    println!("{}", draft.source);
    // Say which generator answered. Under `auto` a provider outage silently
    // substitutes the template, and the two are materially different: the
    // template writes a signature-driven call and nothing else.
    match draft.generator {
        hf_service::DraftGenerator::Llm => println!("generator: llm"),
        hf_service::DraftGenerator::Heuristic if ai == AiOption::Off => {
            println!("generator: heuristic (--ai off)");
        }
        hf_service::DraftGenerator::Heuristic => {
            println!("generator: heuristic");
            eprintln!(
                "note: no model wrote this harness (no provider configured, or the call \
                 failed); pass --ai require to make that an error"
            );
        }
    }
    if draft_only {
        return Ok(());
    }
    println!("\n--- Compiling in sandbox ---");
    let outcome = container
        .harness_compile(draft.source, &project, engine, target, lang, sanitizer)
        .await?;
    println!("compile: status={:?}", outcome.status);
    print_lint_findings(&outcome.lint);
    qualify_harness(
        &container,
        &project,
        target,
        engine,
        lang,
        promote,
        review_bypass,
    )
    .await?;
    Ok(())
}

/// Print non-blocking harness lint findings. A blocking finding never reaches
/// here: it fails the compile with the same text in the error.
fn print_lint_findings(findings: &[hf_service::LintFinding]) {
    for finding in findings {
        let severity = match finding.severity {
            hf_service::LintSeverity::Error => "error",
            hf_service::LintSeverity::Warning => "warning",
        };
        println!(
            "lint {severity} {} (line {}): {}",
            finding.rule, finding.line, finding.message
        );
    }
}

fn promotion_required_message() -> &'static str {
    "promotion required: review this harness before a full campaign; rerunning `oxfuzz harness` creates a new draft. To approve a retained source after separate review, use the Work Order import/qualify flow and `oxfuzz work-order promote --attempt <attempt UUID>`"
}

async fn qualify_harness(
    container: &ServiceContainer,
    project: &std::path::Path,
    target: &str,
    engine: EngineKind,
    lang: TargetLanguage,
    promote: bool,
    review_bypass: hf_service::HarnessReviewBypass,
) -> anyhow::Result<()> {
    if review_bypass == hf_service::HarnessReviewBypass::Requested {
        eprintln!(
            "WARNING: --no-llm-review: smoke-qualifying WITHOUT the independent LLM review; \
             the lexical lint gate and the human promotion decision are the only remaining \
             checks before sandboxed execution."
        );
    }
    println!("\n--- Smoke qualification ---");
    let smoke = container
        .harness_smoke_with_review_bypass(project, target, engine, lang, review_bypass)
        .await?;
    println!(
        "smoke: execs/sec={:.0} crashes={} passed={}",
        smoke.summary.execs_per_sec, smoke.summary.crashes, smoke.summary.passed
    );
    // Surface the deterministic verdict so a hollow pass -- compiled and "passed"
    // yet never actually exercising the target -- is not silently promoted.
    match smoke.verdict.level {
        VerdictLevel::Pass => {}
        VerdictLevel::Suspect => println!(
            "  SUSPECT (verify before promoting): {}",
            smoke.verdict.reasons.join("; ")
        ),
        VerdictLevel::Fail => {
            println!("  FAIL: {}", smoke.verdict.reasons.join("; "));
        }
    }
    if promote {
        let harness = container.harness_promote(project, target, engine).await?;
        println!("promotion: {:?} ({})", harness.status, harness.id);
    } else {
        println!("{}", promotion_required_message());
    }
    Ok(())
}

pub(crate) async fn cmd_run(
    project: PathBuf,
    target: Option<&str>,
    engine: Option<&str>,
    lang: &str,
    duration: Option<&str>,
    requested_cpus: Option<u32>,
    timeout_ms: Option<u64>,
    resume: bool,
    sanitizer: Option<&str>,
    replay: Option<&str>,
) -> anyhow::Result<()> {
    let on_progress = crate::commands::status::printing_sink();

    let summary = if let Some(run_id) = replay {
        // Replay pins the recorded engine/duration/seed; target/engine/duration
        // flags are intentionally not required in this mode.
        let run_id = uuid::Uuid::parse_str(run_id)
            .map_err(|e| anyhow::anyhow!("invalid --replay run id {run_id:?}: {e}"))?;
        let container = std::sync::Arc::new(crate::approval::bootstrap().await);
        println!("\n--- Replaying run {run_id} (live, Ctrl-C to stop) ---");
        let mut handle = {
            let container = std::sync::Arc::clone(&container);
            tokio::spawn(async move { container.replay_run(run_id, &on_progress).await })
        };
        tokio::select! {
            res = &mut handle => res?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n--- Ctrl-C received: cancelling run ---");
                container.cancel_all_runs();
                handle.await?
            }
        }?
    } else {
        let (Some(target), Some(engine)) = (target, engine) else {
            anyhow::bail!("--target and --engine are required unless --replay is given");
        };
        let engine_kind = parse_engine(engine)?;
        // `run` drives the already-built harness, which carries its own language, so
        // the value is not threaded further. Still validate it (like triage/ci) so an
        // invalid `--lang` is rejected up front rather than silently ignored.
        parse_lang(lang)?;
        let sanitizer = sanitizer.map(parse_sanitizer).transpose()?;
        let requested_duration = duration.map(parse_duration).transpose()?;
        // An absent flag defers to the configured `fuzzing.default_resume`;
        // the flag only ever requests resume, never forces a cold start.
        let resume = resume.then_some(true);
        let resolved = hf_service::config::resolve_fuzzing_run(
            Some(engine_kind),
            requested_duration,
            requested_cpus,
            timeout_ms,
            resume,
            sanitizer,
        )
        .map_err(anyhow::Error::msg)?;
        let duration_secs = resolved.duration_secs;
        let container = std::sync::Arc::new(crate::approval::bootstrap().await);
        // Ensure a seed corpus exists before running. A failure here is not fatal
        // (the engine can still run on an empty corpus) but must not be silent.
        if let Err(e) = container.generate_seeds(&project, target).await {
            eprintln!("warning: could not generate seed corpus: {e}");
        }

        println!("\n--- Running {engine} for {duration_secs}s (live, Ctrl-C to stop) ---");
        // Run on a task so a Ctrl-C can cancel it cooperatively: the run keeps
        // executing long enough to tear down the sandbox cleanly and return its
        // partial results, rather than being dropped mid-flight.
        let mut handle = {
            let container = std::sync::Arc::clone(&container);
            let project = project.clone();
            let target = target.to_owned();
            tokio::spawn(async move {
                container
                    .run_fuzzer(
                        &project,
                        &target,
                        engine_kind,
                        duration_secs,
                        requested_cpus,
                        timeout_ms,
                        resume,
                        sanitizer,
                        &on_progress,
                    )
                    .await
            })
        };
        tokio::select! {
            res = &mut handle => res?,
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\n--- Ctrl-C received: cancelling run ---");
                container.cancel_all_runs();
                handle.await?
            }
        }?
    };
    println!("\n--- Run summary ---");
    println!("  execs/sec: {:.0}", summary.execs);
    println!("  crashes detected: {}", summary.crashes);
    if let Some(hangs) = summary.hangs {
        println!("  hangs (per-input timeouts): {hangs}");
    }
    println!("  edges covered: {}", summary.edges);
    if let Some(proposal) = &summary.stagnation {
        println!("  coverage stalled: {proposal:?} -- consider regenerating the harness or adding seeds/a dictionary");
    }
    Ok(())
}

pub(crate) async fn cmd_triage(project: PathBuf, target: &str, lang: &str) -> anyhow::Result<()> {
    // Language is validated for a clear error, though triage works off the
    // already-compiled workspace.
    let _lang = parse_lang(lang)?;
    let container = crate::approval::bootstrap().await;
    let crashes = container.triage(&project, target).await?;
    if crashes.is_empty() {
        println!("No crash artifacts found.");
        return Ok(());
    }
    println!("{} unique crash(es) after dedup.", crashes.len());
    // Advisory per-crash LLM verdict (best-effort: None when no provider is
    // configured; the verdict never reclassifies a crash, only informs review).
    let verdicts = container.verify_crashes(target, &crashes).await;
    let reports: Vec<serde_json::Value> = crashes
        .iter()
        .zip(verdicts)
        .map(|(c, verdict)| {
            serde_json::json!({
                "id": c.id,
                "kind": format!("{:?}", c.kind),
                "summary": c.summary,
                "stack_signature": c.stack_signature,
                "input_path": c.input_path,
                "minimized": c.minimized,
                "verdict": verdict,
            })
        })
        .collect();
    println!("\n{}", serde_json::to_string_pretty(&reports)?);
    Ok(())
}

pub(crate) async fn cmd_corpus(
    project: PathBuf,
    target: &str,
    op: &str,
    from: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    match op {
        "seed" => {
            let n = container.corpus_seed(&project, target).await?;
            println!("Seeded {n} entries.");
        }
        "llmseed" => {
            let entries = container
                .generate_seeds_llm(&project, target, TargetLanguage::C, 12)
                .await?;
            println!("Generated {} LLM seed(s).", entries.len());
        }
        "grow" => {
            let n = container.corpus_grow(&project, target).await?;
            println!("Corpus now has {n} entries.");
        }
        "prune" => {
            let outcome = container.corpus_prune(&project, target).await?;
            println!(
                "Removed byte duplicates: {} -> {} entries ({} -> {} bytes).",
                outcome.before, outcome.after, outcome.before_bytes, outcome.after_bytes
            );
        }
        "cprune" => {
            let outcome = container.corpus_prune_coverage(&project, target).await?;
            println!(
                "Coverage-pruned {} -> {} entries.",
                outcome.before, outcome.after
            );
        }
        "survival" => {
            let report = container.seed_survival(&project, target).await?;
            let ratio = report.survival_ratio.map_or_else(
                || "n/a".to_owned(),
                |ratio| format!("{:.0}%", ratio * 100.0),
            );
            println!(
                "Seed survival for '{target}': {} survive, {} die at entry, {} not measured, of {} seeds (ratio {ratio}).",
                report.survives, report.dies_at_entry, report.not_measured, report.total
            );
        }
        "regen" => {
            let outcome = container
                .regenerate_dead_seeds(&project, target, TargetLanguage::C)
                .await?;
            println!(
                "Regenerated {}/{} dying seed(s); {} replacement(s) written: {} survive, {} die at entry, {} not measured.",
                outcome.removed_dead,
                outcome.replacements_requested,
                outcome.replacements_added,
                outcome.replacement_survives,
                outcome.replacement_dies_at_entry,
                outcome.replacement_not_measured
            );
        }
        "import" => {
            let source =
                from.ok_or_else(|| anyhow::anyhow!("corpus import requires --from <directory>"))?;
            let outcome = container.corpus_import(&project, target, source).await?;
            println!(
                "Imported {} input(s) / {} bytes; {} duplicate(s), {} skipped; corpus {} -> {} inputs ({} -> {} bytes).",
                outcome.added,
                outcome.added_bytes,
                outcome.duplicates,
                outcome.skipped,
                outcome.before.inputs,
                outcome.after.inputs,
                outcome.before.bytes,
                outcome.after.bytes
            );
        }
        "minimize" | "cmin" => {
            let outcome = container.corpus_minimize(&project, target).await?;
            println!("Minimized {} -> {} entries.", outcome.before, outcome.after);
        }
        "absorb" => {
            let n = container.corpus_absorb_crashes(&project, target).await?;
            println!("Absorbed {n} crash reproducer(s) into the corpus.");
        }
        #[cfg(feature = "concolic-enrichment")]
        "concolic" => {
            let outcome = container.corpus_concolic(&project, target).await?;
            println!(
                "Explored {} input(s), skipped {} ({:?}).",
                outcome.inputs_explored, outcome.inputs_skipped, outcome.stop_reason
            );
            println!(
                "Solver produced {} input(s), {} of them novel.",
                outcome.inputs_solved, outcome.inputs_novel
            );
            println!(
                "Corpus {} -> {} entries.",
                outcome.corpus_size_before, outcome.corpus_size_after
            );
        }
        "list" => {
            let corpus = container.corpus_list(&project, target)?;
            println!("{}", serde_json::to_string_pretty(&corpus.entries)?);
        }
        other => {
            anyhow::bail!(
                "unknown corpus op: {other} \
                 (use seed|llmseed|grow|prune|cprune|survival|regen|minimize|absorb|concolic|import|list)"
            )
        }
    }
    Ok(())
}

/// Print the entry points no retained measurement has covered.
///
/// Rendering only: the ranking, the attempt history, and the unavailable
/// reason all arrive decided by `hf-service` (Engineering Protocol 2.9).
#[cfg(feature = "unreached-surface")]
pub(crate) async fn cmd_unreached(project: PathBuf, lang: &str) -> anyhow::Result<()> {
    use hf_service::SurfaceMeasurement;

    let language = parse_lang(lang)?;
    let container = crate::approval::bootstrap().await;
    let view = container.unreached_surface(&project, language).await?;

    match &view.measurement {
        SurfaceMeasurement::Unavailable { reason } => {
            eprintln!(
                "No coverage measurement is retained for this project ({reason}); \
                 nothing can be called unreached until something has been measured."
            );
            return Ok(());
        }
        SurfaceMeasurement::Retained { measurements } => {
            println!(
                "Unreached entry points (absent from {measurements} retained measurement(s)):"
            );
        }
    }
    if view.candidates.is_empty() {
        println!("  none -- every discovered candidate has been covered.");
        return Ok(());
    }
    for candidate in &view.candidates {
        println!(
            "  {:<40} score {:.2}  {:?}",
            candidate.symbol, candidate.discovery_score, candidate.attempt
        );
    }
    Ok(())
}

/// Rendering only: the attribution tiers and ordering arrive decided by
/// `hf-service` (Engineering Protocol 2.9).
#[cfg(feature = "unreached-surface")]
pub(crate) async fn cmd_attribution(project: PathBuf, lang: &str) -> anyhow::Result<()> {
    use hf_service::{AttributionTier, SurfaceMeasurement};

    let language = parse_lang(lang)?;
    let container = crate::approval::bootstrap().await;
    let view = container.coverage_attribution(&project, language).await?;

    match &view.measurement {
        SurfaceMeasurement::Unavailable { reason } => {
            eprintln!(
                "No coverage measurement is retained for this project ({reason}); \
                 nothing can be attributed until something has been measured."
            );
            return Ok(());
        }
        SurfaceMeasurement::Retained { measurements } => {
            println!(
                "Coverage attribution over {measurements} retained measurement(s), \
                 ordered for the next harness:"
            );
        }
    }
    if view.candidates.is_empty() {
        println!("  none -- no discovered candidates.");
        return Ok(());
    }
    for candidate in &view.candidates {
        let tier = match &candidate.tier {
            AttributionTier::Untouched => "untouched".to_owned(),
            AttributionTier::Partial { covered, total } => {
                format!("partial {covered}/{total}")
            }
            AttributionTier::Saturated { covered, total } => {
                format!("saturated {covered}/{total}")
            }
        };
        println!(
            "  {:<40} score {:.2}  covered {:.0}%  {}",
            candidate.symbol,
            candidate.discovery_score,
            candidate.covered_share * 100.0,
            tier
        );
    }
    Ok(())
}

#[cfg(test)]
mod promotion_guidance_tests {
    use super::promotion_required_message;

    #[test]
    fn non_promoting_harness_run_explains_that_rerunning_creates_a_new_draft() {
        let message = promotion_required_message();

        assert!(message.contains("rerunning `oxfuzz harness` creates a new draft"));
        assert!(message.contains("work-order promote --attempt"));
        assert!(!message.contains("rerun this command with --promote"));
    }
}
