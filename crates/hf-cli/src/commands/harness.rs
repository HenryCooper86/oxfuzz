use hf_service::{EngineKind, FuzzProgress, ServiceContainer, TargetLanguage, VerdictLevel};
use std::path::PathBuf;

use crate::args::AiOption;
use crate::parse::{parse_duration, parse_engine, parse_lang};

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
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    // --draft-only stops before compile/smoke/promotion, so flags that only
    // take effect in those stages must not be silently ignored. (--refine is
    // exempt: it honors --repair during its recompile.)
    if draft_only && !refine && repair > 0 {
        eprintln!("warning: --repair is ignored with --draft-only (the harness is not compiled)");
    }
    if draft_only && promote {
        eprintln!("warning: --promote is ignored with --draft-only (no smoke qualification runs)");
    }
    let container = ServiceContainer::bootstrap().await;

    // With --refine, reshape the existing harness toward uncovered reachable
    // functions (coverage-guided), then recompile with auto-repair.
    if refine {
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
        qualify_harness(&container, &project, target, engine, lang, promote).await?;
        return Ok(());
    }

    // With --repair, use the draft -> compile -> repair loop, which recovers
    // harnesses that fail to build on the first draft.
    if repair > 0 && !draft_only {
        println!("--- Generating harness (auto-repair up to {repair}x) ---");
        let outcome = container
            .harness_generate(&project, target, engine, lang, repair)
            .await?;
        println!(
            "compile: status={:?} repairs_used={}",
            outcome.status, outcome.repairs_used
        );
        print_lint_findings(&outcome.lint);
        qualify_harness(&container, &project, target, engine, lang, promote).await?;
        return Ok(());
    }

    let draft = container
        .harness_draft_with_policy(&project, target, engine, lang, ai.into())
        .await?;
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
        .harness_compile(draft.source, &project, engine, target, lang)
        .await?;
    println!("compile: status={:?}", outcome.status);
    print_lint_findings(&outcome.lint);
    qualify_harness(&container, &project, target, engine, lang, promote).await?;
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

async fn qualify_harness(
    container: &ServiceContainer,
    project: &std::path::Path,
    target: &str,
    engine: EngineKind,
    lang: TargetLanguage,
    promote: bool,
) -> anyhow::Result<()> {
    println!("\n--- Smoke qualification ---");
    let smoke = container
        .harness_smoke(project, target, engine, lang)
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
        println!(
            "promotion required: review the harness and rerun this command with --promote before a full campaign"
        );
    }
    Ok(())
}

pub(crate) async fn cmd_run(
    project: PathBuf,
    target: Option<&str>,
    engine: Option<&str>,
    lang: &str,
    duration: Option<&str>,
    replay: Option<&str>,
) -> anyhow::Result<()> {
    let container = std::sync::Arc::new(ServiceContainer::bootstrap().await);
    let on_progress = |p: FuzzProgress| match p {
        FuzzProgress::LogLine(line) => println!("  {line}"),
        FuzzProgress::CrashesFound(_) => println!("  >> crash found"),
        _ => {}
    };

    let summary = if let Some(run_id) = replay {
        // Replay pins the recorded engine/duration/seed; target/engine/duration
        // flags are intentionally not required in this mode.
        let run_id = uuid::Uuid::parse_str(run_id)
            .map_err(|e| anyhow::anyhow!("invalid --replay run id {run_id:?}: {e}"))?;
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
        let duration_secs = duration.map(parse_duration).transpose()?.unwrap_or(3600);
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
                    .run_fuzzer(&project, &target, engine_kind, duration_secs, &on_progress)
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
    let container = ServiceContainer::bootstrap().await;
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

pub(crate) async fn cmd_corpus(project: PathBuf, target: &str, op: &str) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
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
            let n = container.corpus_prune(&project, target).await?;
            println!("Pruned to {n} entries.");
        }
        "cprune" => {
            let outcome = container.corpus_prune_coverage(&project, target).await?;
            println!(
                "Coverage-pruned {} -> {} entries.",
                outcome.before, outcome.after
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
                 (use seed|llmseed|grow|prune|cprune|minimize|absorb|concolic|list)"
            )
        }
    }
    Ok(())
}

/// Print the entry points no retained measurement has covered.
///
/// Rendering only: the ranking, the attempt history, and the unavailable
/// reason all arrive decided by `hf-service` (AGENTS.md 2.9).
#[cfg(feature = "unreached-surface")]
pub(crate) async fn cmd_unreached(project: PathBuf, lang: &str) -> anyhow::Result<()> {
    use hf_service::SurfaceMeasurement;

    let language = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
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
