use hf_service::{FuzzProgress, ServiceContainer};
use std::path::PathBuf;

use crate::ai_policy::apply_ai_policy;
use crate::args::AiOption;
use crate::parse::{parse_duration, parse_engine, parse_lang};

/// Print campaign health conditions for one run.
///
/// Rendering only: every condition, severity, and sentence arrives decided by
/// `hf-service` (AGENTS.md 2.9).
#[cfg(feature = "campaign-health")]
pub(crate) async fn cmd_health(run: &str) -> anyhow::Result<()> {
    use hf_service::PlateauCheck;

    let run_id = uuid::Uuid::parse_str(run)
        .map_err(|_| anyhow::anyhow!("run id '{run}' is not a valid UUID"))?;
    let container = ServiceContainer::bootstrap().await;
    let report = container.campaign_health(run_id).await?;

    match &report.plateau_check {
        PlateauCheck::Unavailable { reason } => {
            println!("Coverage plateau: not evaluated ({reason})");
        }
        PlateauCheck::Evaluated { window } => {
            println!("Coverage plateau: evaluated over the last {window} measurements");
        }
    }
    if report.events.is_empty() {
        println!("No campaign health conditions for run {}.", report.run_id);
        return Ok(());
    }
    println!();
    for event in &report.events {
        println!("  {:?} [{:?}]", event.condition, event.severity);
        println!("      {}", event.detail);
    }
    Ok(())
}

/// Run and print the closeout chain for one run.
///
/// Rendering only: every step, outcome, and sentence arrives decided by
/// `hf-service` (AGENTS.md 2.9).
#[cfg(feature = "run-closeout")]
pub(crate) async fn cmd_closeout(run: &str) -> anyhow::Result<()> {
    use hf_service::StepOutcome;

    let run_id = uuid::Uuid::parse_str(run)
        .map_err(|_| anyhow::anyhow!("run id '{run}' is not a valid UUID"))?;
    let container = ServiceContainer::bootstrap().await;
    let report = container.close_out_run(run_id).await?;

    if let Some(step) = report.resumed_at {
        println!("Closeout for run {} resumed at {step:?}:", report.run_id);
    } else {
        println!("Closeout for run {}:", report.run_id);
    }
    for record in &report.steps {
        let (label, text) = match &record.outcome {
            StepOutcome::Completed { detail } => ("completed", detail.as_str()),
            StepOutcome::Skipped { reason } => ("skipped  ", reason.as_str()),
            StepOutcome::Failed { error } => ("failed   ", error.as_str()),
        };
        println!("  {label} {:?}", record.step);
        println!("            {text}");
    }
    Ok(())
}

/// Print the campaign trust audit for one run.
///
/// Rendering only: every verdict, sentence, and withheld claim arrives decided
/// by `hf-service` (AGENTS.md 2.9).
#[cfg(feature = "campaign-trust")]
pub(crate) async fn cmd_trust(run: &str) -> anyhow::Result<()> {
    use hf_service::GateVerdict;

    let run_id = uuid::Uuid::parse_str(run)
        .map_err(|_| anyhow::anyhow!("run id '{run}' is not a valid UUID"))?;
    let container = ServiceContainer::bootstrap().await;
    let report = container.campaign_trust_report(run_id).await?;

    println!("Campaign trust for run {}:", report.run_id);
    println!("  determination: {:?}", report.determination);
    println!();
    for gate in &report.gates {
        let mark = match gate.verdict {
            GateVerdict::Supported => "supported  ",
            GateVerdict::Refuted => "refuted    ",
            GateVerdict::Unsupported => "unsupported",
            GateVerdict::Unavailable => "unavailable",
        };
        println!("  {mark} {:?}", gate.claim);
        println!("               {}", gate.detail);
    }
    if !report.unlicensed_claims.is_empty() {
        println!();
        println!("Not licensed by this evidence:");
        for claim in &report.unlicensed_claims {
            println!("  - {claim:?}");
        }
    }
    Ok(())
}

pub(crate) async fn cmd_coverage(project: PathBuf, target: &str) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match container.coverage_summary(&project, target).await {
        Some(s) => {
            println!("Coverage for {target}:");
            println!(
                "  lines:     {}/{} ({:.1}%)",
                s.lines_covered,
                s.lines_total,
                s.line_percent()
            );
            println!(
                "  functions: {}/{} ({:.1}%)",
                s.functions_covered,
                s.functions_total,
                s.function_percent()
            );
            println!(
                "  regions:   {}/{} ({:.1}%)",
                s.regions_covered,
                s.regions_total,
                s.region_percent()
            );
        }
        None => {
            eprintln!(
                "No coverage available -- compile a harness and build a corpus first, \
                 and ensure the sandbox has clang/llvm-cov."
            );
        }
    }
    Ok(())
}

pub(crate) async fn cmd_ci(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    duration: &str,
    sarif: &std::path::Path,
    ai: AiOption,
) -> anyhow::Result<()> {
    let engine_kind = parse_engine(engine)?;
    let _lang = parse_lang(lang)?;
    let duration_secs = parse_duration(duration)?;
    let container =
        apply_ai_policy(ServiceContainer::bootstrap().await, ai, "this CI gate").await?;
    if ai == AiOption::Off {
        println!("[ci] --ai off: no model is called at any step of this gate.");
    }

    println!("[ci] requiring a previously smoke-qualified and promoted harness for {target}...");
    println!("[ci] fuzzing {target} for {duration_secs}s...");
    let on_progress = |p: FuzzProgress| {
        if let FuzzProgress::CrashesFound(_) = p {
            println!("[ci] >> crash found");
        }
    };
    let outcome = container
        .run_ci_gate(
            hf_service::sarif::CiGateRequest {
                project: &project,
                target,
                engine: engine_kind,
                duration_secs,
            },
            &on_progress,
        )
        .await?;
    if let Some(warning) = &outcome.seed_warning {
        eprintln!("[ci] warning: seed generation failed: {warning}");
    }

    // Always emit SARIF (even with zero results) so code scanning can clear
    // stale alerts when a bug is fixed.
    std::fs::write(sarif, &outcome.sarif)?;
    println!("[ci] SARIF written to {}", sarif.display());

    if outcome.passed() {
        println!("[ci] PASS: no crashes found.");
        Ok(())
    } else {
        eprintln!("[ci] FAIL: {} crash(es) found.", outcome.findings.len());
        for finding in &outcome.findings {
            eprintln!("[ci]   {}: {}", finding.kind, finding.summary);
        }
        anyhow::bail!("CI fuzzing gate found crashing inputs")
    }
}

pub(crate) async fn cmd_sarif(
    project: PathBuf,
    target: &str,
    out: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let sarif = container.export_sarif(&project, target).await?;
    match out {
        Some(path) => {
            std::fs::write(path, &sarif)?;
            println!("SARIF written to {}", path.display());
        }
        None => println!("{sarif}"),
    }
    Ok(())
}

pub(crate) async fn cmd_repro(
    project: PathBuf,
    target: &str,
    engine: &str,
    lang: &str,
    crash: Option<&str>,
    out: &std::path::Path,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let container = ServiceContainer::bootstrap().await;
    let dir = container
        .export_repro_bundle_for_latest(&project, target, engine, lang, crash, out)
        .await?;
    println!("Reproduction bundle written to {}", dir.display());
    println!("  Build and reproduce: see {}/REPRODUCE.md", dir.display());
    Ok(())
}

pub(crate) async fn cmd_defectdojo(
    project: PathBuf,
    target: Option<&str>,
    test_only: bool,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    if test_only {
        container.defectdojo_test_connection().await?;
        println!("DefectDojo connection OK.");
        return Ok(());
    }
    let outcome = container.push_to_defectdojo(&project, target).await?;
    println!(
        "Pushed {} finding(s) to DefectDojo{}{}.",
        outcome.findings_pushed,
        if outcome.reimported {
            " (reimport)"
        } else {
            ""
        },
        outcome
            .url
            .as_ref()
            .map(|u| format!(" -- {u}"))
            .unwrap_or_default()
    );
    Ok(())
}

pub(crate) async fn cmd_ingest(project: PathBuf, file: &std::path::Path) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let stats = container.ingest_document(&project, file).await?;
    println!(
        "Ingested {} -> knowledge base now has {} file(s), {} chunk(s).",
        file.display(),
        stats.files,
        stats.chunks
    );
    Ok(())
}

pub(crate) async fn cmd_regress(project: PathBuf, target: &str) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let results = container.verify_regressions(&project, target).await?;
    if results.is_empty() {
        println!("No stored crashes to replay.");
        return Ok(());
    }
    let still = results.iter().filter(|r| r.still_crashes).count();
    let fixed = results
        .iter()
        .filter(|r| r.verified && !r.still_crashes)
        .count();
    let inconclusive = results.iter().filter(|r| !r.verified).count();
    println!(
        "Replayed {} crash(es): {still} still crashing, {fixed} fixed, {inconclusive} inconclusive.",
        results.len(),
    );
    for r in &results {
        let tag = if r.still_crashes {
            "STILL CRASHES"
        } else if !r.verified {
            "INCONCLUSIVE"
        } else {
            "fixed"
        };
        let id = if r.crash_id.is_empty() {
            ""
        } else {
            &r.crash_id[..r.crash_id.len().min(8)]
        };
        println!("  [{tag}] {id} {} -- {}", r.input, r.summary);
    }
    Ok(())
}

pub(crate) async fn cmd_campaign(
    project: PathBuf,
    target: Option<&str>,
    engine: &str,
    lang: &str,
    duration_secs: u64,
    iterations: usize,
    ai: AiOption,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let container =
        apply_ai_policy(ServiceContainer::bootstrap().await, ai, "this campaign").await?;
    if ai == AiOption::Off {
        println!("--ai off: no model is called at any step of this campaign.");
    }
    println!("--- Running autonomous campaign ---");
    let outcome = container
        .run_campaign(&project, target, engine, lang, duration_secs, iterations)
        .await?;
    println!(
        "target={} harness={:?} iterations={} edges={} crashes={} termination={:?}",
        outcome.target,
        outcome.harness_status,
        outcome.iterations,
        outcome.edges,
        outcome.crashes,
        outcome.termination
    );
    if let Some(refine) = &outcome.refine {
        // A coverage plateau proposed a targeted refined harness. It is only
        // Compiled (never promoted/auto-run); the operator reviews and promotes.
        println!("  coverage-plateau refine: {}", refine.note);
    }
    Ok(())
}

/// The single service call `oxfuzz report` makes. Behind a trait so a test can
/// observe the language the command hands over without bootstrapping a real
/// container -- the parse and the hand-off are otherwise unobservable together.
#[async_trait::async_trait]
trait ReportCommandService {
    async fn compose_report(
        &self,
        project: &std::path::Path,
        target: &str,
        language: hf_service::ReportLanguage,
    ) -> Result<String, hf_service::ClassifiedError>;
}

#[async_trait::async_trait]
impl ReportCommandService for ServiceContainer {
    async fn compose_report(
        &self,
        project: &std::path::Path,
        target: &str,
        language: hf_service::ReportLanguage,
    ) -> Result<String, hf_service::ClassifiedError> {
        self.generate_report(project, target, language).await
    }
}

/// Parse the language, build the service, compose, then emit. `bootstrap` is
/// injected rather than called directly so the whole path -- flag string in,
/// `ReportLanguage` at the service boundary, document out -- is one testable
/// unit, and so a rejected language is provably free of bootstrap side effects.
async fn run_report_command<S, Bootstrap, BootstrapFuture>(
    project: &std::path::Path,
    target: &str,
    out: Option<&std::path::Path>,
    lang: &str,
    bootstrap: Bootstrap,
) -> anyhow::Result<()>
where
    S: ReportCommandService + Sync,
    Bootstrap: FnOnce() -> BootstrapFuture,
    BootstrapFuture: std::future::Future<Output = S>,
{
    // An unknown identifier is rejected here, before any composition work.
    let language = lang.parse::<hf_service::ReportLanguage>()?;
    let service = bootstrap().await;
    let markdown = service.compose_report(project, target, language).await?;
    match out {
        Some(path) => {
            std::fs::write(path, &markdown)?;
            println!("Report written to {}", path.display());
        }
        None => println!("{markdown}"),
    }
    Ok(())
}

pub(crate) async fn cmd_report(
    project: PathBuf,
    target: &str,
    out: Option<&std::path::Path>,
    lang: &str,
) -> anyhow::Result<()> {
    run_report_command(&project, target, out, lang, ServiceContainer::bootstrap).await
}

#[cfg(test)]
mod report_cli_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use clap::Parser as _;

    use super::{run_report_command, ReportCommandService};
    use crate::args::{Cli, Commands};

    /// Records the language the command handed to the service.
    #[derive(Default)]
    struct RecordingReportService {
        received: Arc<Mutex<Option<hf_service::ReportLanguage>>>,
    }

    #[async_trait::async_trait]
    impl ReportCommandService for RecordingReportService {
        async fn compose_report(
            &self,
            _project: &std::path::Path,
            target: &str,
            language: hf_service::ReportLanguage,
        ) -> Result<String, hf_service::ClassifiedError> {
            *self.received.lock().unwrap() = Some(language);
            Ok(format!("# report for {target} composed as {language:?}\n"))
        }
    }

    /// Drive the command end to end and report which language the service saw.
    async fn language_handed_to_the_service(flag: &str) -> hf_service::ReportLanguage {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("report.md");
        let received = Arc::new(Mutex::new(None));
        let service = RecordingReportService {
            received: Arc::clone(&received),
        };

        run_report_command(
            std::path::Path::new("/tmp/project"),
            "parse_header",
            Some(&out),
            flag,
            move || std::future::ready(service),
        )
        .await
        .unwrap();

        // The composed document is what reaches the file, so this also pins
        // that the service's output is the thing written out.
        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains("parse_header"), "{written}");

        let language = received.lock().unwrap().unwrap();
        assert!(
            written.contains(&format!("{language:?}")),
            "the written document must be the one the service composed: {written}"
        );
        language
    }

    #[tokio::test]
    async fn the_parsed_language_reaches_the_service() {
        // The hand-off, not the parse: `--lang zh` must arrive at
        // generate_report rather than being parsed and then discarded.
        assert_eq!(
            language_handed_to_the_service("zh").await,
            hf_service::ReportLanguage::Zh
        );
        assert_eq!(
            language_handed_to_the_service("en").await,
            hf_service::ReportLanguage::En
        );
    }

    #[tokio::test]
    async fn an_unknown_language_is_rejected_before_any_bootstrap() {
        let bootstrapped = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&bootstrapped);

        let error = run_report_command(
            std::path::Path::new("/tmp/project"),
            "parse_header",
            None,
            "fr",
            move || {
                called.store(true, Ordering::SeqCst);
                std::future::ready(RecordingReportService::default())
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("unknown report language 'fr'"));
        assert!(
            !bootstrapped.load(Ordering::SeqCst),
            "an unusable language must cost nothing: no container is built"
        );
    }

    #[test]
    fn report_language_defaults_to_english_and_accepts_chinese() {
        let default_cli =
            Cli::try_parse_from(["oxfuzz", "report", "/tmp/project", "--target", "parse"]).unwrap();
        let Commands::Report { report_lang, .. } = default_cli.command else {
            panic!("expected the report command");
        };
        assert_eq!(
            report_lang.parse::<hf_service::ReportLanguage>().unwrap(),
            hf_service::ReportLanguage::En
        );

        let chinese = Cli::try_parse_from([
            "oxfuzz",
            "report",
            "/tmp/project",
            "--target",
            "parse",
            "--report-lang",
            "zh",
        ])
        .unwrap();
        let Commands::Report { report_lang, .. } = chinese.command else {
            panic!("expected the report command");
        };
        assert_eq!(
            report_lang.parse::<hf_service::ReportLanguage>().unwrap(),
            hf_service::ReportLanguage::Zh
        );
    }

    #[test]
    fn an_unknown_report_language_names_the_accepted_values() {
        let error = "fr".parse::<hf_service::ReportLanguage>().unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("'en'") && message.contains("'zh'"),
            "{message}"
        );
    }
}
