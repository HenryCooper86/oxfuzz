use hf_service::{FuzzProgress, ServiceContainer};
use std::path::PathBuf;

use crate::ai_policy::apply_ai_policy;
use crate::args::AiOption;
use crate::parse::{parse_duration, parse_engine, parse_lang, parse_sanitizer};

/// Print campaign health conditions for one run.
///
/// Rendering only: every condition, severity, and sentence arrives decided by
/// `hf-service` (Engineering Protocol 2.9).
#[cfg(feature = "campaign-health")]
pub(crate) async fn cmd_health(run: &str) -> anyhow::Result<()> {
    use hf_service::PlateauCheck;

    let run_id = uuid::Uuid::parse_str(run)
        .map_err(|_| anyhow::anyhow!("run id '{run}' is not a valid UUID"))?;
    let container = crate::approval::bootstrap().await;
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
/// `hf-service` (Engineering Protocol 2.9).
#[cfg(feature = "run-closeout")]
fn render_closeout_outcome(outcome: &hf_service::StepOutcome) -> (&'static str, String) {
    use hf_service::StepOutcome;

    match outcome {
        StepOutcome::Completed { detail } => ("completed", detail.clone()),
        StepOutcome::Skipped { reason } => ("skipped  ", reason.clone()),
        StepOutcome::Failed { error } => ("failed   ", error.clone()),
        StepOutcome::Blocked { dependency } => ("blocked  ", format!("blocked by {dependency:?}")),
    }
}

#[cfg(feature = "run-closeout")]
pub(crate) async fn cmd_closeout(run: &str) -> anyhow::Result<()> {
    let run_id = uuid::Uuid::parse_str(run)
        .map_err(|_| anyhow::anyhow!("run id '{run}' is not a valid UUID"))?;
    let container = crate::approval::bootstrap().await;
    let report = container.close_out_run(run_id).await?;

    if let Some(step) = report.resumed_at {
        println!("Closeout for run {} resumed at {step:?}:", report.run_id);
    } else {
        println!("Closeout for run {}:", report.run_id);
    }
    for record in &report.steps {
        let (label, text) = render_closeout_outcome(&record.outcome);
        println!("  {label} {:?}", record.step);
        println!("            {text}");
    }
    Ok(())
}

#[cfg(all(test, feature = "run-closeout"))]
mod closeout_render_tests {
    use hf_service::{CloseoutStep, StepOutcome};

    use super::render_closeout_outcome;

    #[test]
    fn blocked_outcome_names_the_dependency() {
        let (label, text) = render_closeout_outcome(&StepOutcome::Blocked {
            dependency: CloseoutStep::Triage,
        });

        assert_eq!(label, "blocked  ");
        assert_eq!(text, "blocked by Triage");
    }
}

/// Print the campaign trust audit for one run.
///
/// Rendering only: every verdict, sentence, and withheld claim arrives decided
/// by `hf-service` (Engineering Protocol 2.9).
#[cfg(feature = "campaign-trust")]
pub(crate) async fn cmd_trust(run: &str) -> anyhow::Result<()> {
    use hf_service::GateVerdict;

    let run_id = uuid::Uuid::parse_str(run)
        .map_err(|_| anyhow::anyhow!("run id '{run}' is not a valid UUID"))?;
    let container = crate::approval::bootstrap().await;
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

pub(crate) async fn cmd_coverage(args: crate::args::CoverageArgs) -> anyhow::Result<()> {
    let crate::args::CoverageArgs {
        project,
        target,
        lcov,
        html,
    } = args;
    let (target, lcov, html) = (target.as_str(), lcov.as_deref(), html.as_deref());
    let container = crate::approval::bootstrap().await;
    if lcov.is_some() || html.is_some() {
        // A requested report that cannot be produced is a failure, not a
        // printed hint: a CI step must not pass with no file written.
        let report = container.coverage_line_report(&project, target).await?;
        if let Some(path) = lcov {
            std::fs::write(path, &report.lcov)?;
            println!("lcov tracefile written to {}", path.display());
        }
        if let Some(path) = html {
            std::fs::write(path, &report.html)?;
            println!("HTML coverage report written to {}", path.display());
        }
        println!(
            "  {} of {} instrumented lines executed in {} file(s)",
            report.lines_hit, report.lines_total, report.files
        );
        if report.skipped_files > 0 {
            println!(
                "  {} file(s) exceeded the report bounds and were left out",
                report.skipped_files
            );
        }
    }
    match container.coverage_summary(&project, target).await? {
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
    duration: &str,
    sarif: &std::path::Path,
    ai: AiOption,
) -> anyhow::Result<()> {
    let engine_kind = parse_engine(engine)?;
    let duration_secs = parse_duration(duration)?;
    let container = apply_ai_policy(crate::approval::bootstrap().await, ai, "this CI gate").await?;
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
    let container = crate::approval::bootstrap().await;
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
    let container = crate::approval::bootstrap().await;
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
    let container = crate::approval::bootstrap().await;
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
    if outcome.findings_held > 0 {
        println!(
            "{} finding(s) held for a harness usage review; see `oxfuzz triage --accept-usage`.",
            outcome.findings_held
        );
    }
    Ok(())
}

pub(crate) async fn cmd_issue(args: crate::args::IssueArgs) -> anyhow::Result<()> {
    let crate::args::IssueArgs {
        project,
        crash,
        draft,
        test: test_only,
    } = args;
    let crash = crash.as_deref();
    let container = crate::approval::bootstrap().await;
    if test_only {
        container.issue_tracker_test_connection().await?;
        println!("Issue tracker connection OK.");
        return Ok(());
    }
    // clap requires `--crash` whenever `--test` is absent.
    let crash = crash.ok_or_else(|| anyhow::anyhow!("--crash is required"))?;
    if draft {
        print_issue_draft(&container.issue_export(&project, crash).await?);
        return Ok(());
    }
    print_filed_issue(&container.file_issue(&project, crash).await?);
    Ok(())
}

fn print_issue_draft(export: &hf_service::IssueExport) {
    println!("Title:  {}", export.title);
    println!("Labels: {}", export.labels.join(", "));
    if let Some(url) = &export.issue_url {
        println!("Open a prefilled issue: {url}");
    }
    println!("\n{}", export.description);
}

fn print_filed_issue(created: &hf_service::CreatedIssue) {
    match created.number {
        Some(number) => println!("Filed issue #{number}: {}", created.url),
        None => println!("Filed issue: {}", created.url),
    }
}

#[cfg(feature = "binary-only-fuzzing")]
pub(crate) async fn cmd_binary_issue(args: crate::args::BinaryIssueArgs) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    if args.draft {
        print_issue_draft(&container.binary_issue_export(
            &args.project,
            &args.report,
            &args.finding,
        )?);
        return Ok(());
    }
    print_filed_issue(
        &container
            .binary_file_issue(&args.project, &args.report, &args.finding)
            .await?,
    );
    Ok(())
}

pub(crate) async fn cmd_kernel(args: crate::args::KernelArgs) -> anyhow::Result<()> {
    let duration_secs = crate::parse::parse_duration(&args.duration)?;
    let container = crate::approval::bootstrap().await;
    let path = |path: Option<PathBuf>| path.map(|path| path.to_string_lossy().into_owned());
    let opts = hf_service::SyzkallerRunOpts {
        project: args.project,
        arch: args.arch,
        duration_secs,
        kernel_image: path(args.kernel_image),
        disk_image: path(args.rootfs),
        ssh_key: path(args.ssh_key),
        manager_cfg: path(args.manager_cfg),
        vm_count: args.vms,
    };
    let on_progress: Box<dyn Fn(FuzzProgress) + Send + Sync> = if args.json {
        Box::new(crate::commands::status::eprinting_sink())
    } else {
        Box::new(crate::commands::status::printing_sink())
    };
    let summary = container.run_syzkaller(&opts, on_progress.as_ref()).await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else {
        println!("{}", kernel_summary(&summary, duration_secs));
    }
    Ok(())
}

/// The plain-text result of a kernel campaign.
fn kernel_summary(summary: &hf_service::SyzkallerSummary, duration_secs: u64) -> String {
    use hf_service::CommandTermination;
    let Some(run_id) = summary.run_id else {
        return "No kernel campaign was launched; see the guidance above.".to_owned();
    };
    let stopped = match summary.termination {
        Some(CommandTermination::Completed) => "syz-manager exited",
        Some(CommandTermination::TimedOut) => "the sandbox time limit ended it",
        Some(CommandTermination::Cancelled) => "it was cancelled",
        None => "the stop reason was not recorded",
    };
    let rate = summary.execs.map_or_else(
        || "unavailable".to_owned(),
        |rate| format!("{rate:.1} per second at peak"),
    );
    let exit = summary
        .exit_code
        .map_or_else(|| "none".to_owned(), |code| code.to_string());
    // The programs syzkaller runs to probe the guest are counted as executed,
    // so only coverage shows whether any fuzzing happened.
    let without_coverage = if summary.edges == 0 {
        "No coverage was recorded, so this campaign tested nothing: the guest did not finish a \
         fuzzing program. Look above for a boot or SSH error. Without /dev/kvm the guest is \
         emulated and needs ten minutes or more before its first program: use a longer \
         --duration, and more CPUs and memory under [fuzzing.sandbox].\n"
    } else {
        ""
    };
    format!(
        "Kernel campaign {run_id} on {} ran for up to {duration_secs}s: {stopped} (exit code {exit}).\n\
         Programs executed: {}  ({rate})\n\
         Coverage: {} edges  Crashes: {}\n\
         {without_coverage}\
         Triage it with: oxfuzz triage {} --target {}",
        summary.target,
        summary.execs_total,
        summary.edges,
        summary.crashes,
        summary.project_root.display(),
        summary.target,
    )
}

#[cfg(feature = "binary-only-fuzzing")]
pub(crate) async fn cmd_binary(args: crate::args::BinaryArgs) -> anyhow::Result<()> {
    use hf_service::{BinaryFuzzRequest, BinaryInput};
    let duration_secs = crate::parse::parse_duration(&args.duration)?;
    let dictionary = match &args.dictionary {
        Some(path) => hf_service::parse_binary_dictionary(&std::fs::read_to_string(path)?)?,
        None => Vec::new(),
    };
    let container = crate::approval::bootstrap().await;
    let outcome = container
        .binary_fuzz(&BinaryFuzzRequest {
            project: args.project,
            binary: args.binary,
            input: if args.input.messages {
                BinaryInput::SocketMessages
            } else if args.input.socket {
                BinaryInput::Socket
            } else if args.input.stdin {
                BinaryInput::Stdin
            } else {
                BinaryInput::File
            },
            seeds: args.seeds,
            libraries: args.libs,
            duration_secs,
            timeout_ms: args.timeout_ms,
            dictionary,
            continue_from: args.continue_from,
            compcov: args.compcov,
            persistent: args.persistent.map(|entry| hf_service::BinaryPersistent {
                entry,
                iterations: args.persistent_iterations,
                restore_memory: args.restore_memory,
            }),
            target_args: args.target_args,
        })
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
        return Ok(());
    }
    println!("{}", binary_summary(&outcome));
    Ok(())
}

/// The plain-text result of a binary-only session.
#[cfg(feature = "binary-only-fuzzing")]
fn binary_summary(outcome: &hf_service::BinaryFuzzOutcome) -> String {
    use std::fmt::Write as _;
    let count =
        |value: Option<u64>| value.map_or_else(|| "unavailable".to_owned(), |v| v.to_string());
    let mut text = format!(
        "Fuzzed {} binary {} for {}s under AFL++ QEMU mode.\n\
         Executions: {}  Edges: {}  Corpus: {}  Hangs: {}\n",
        outcome.machine.uname(),
        &outcome.binary_sha256[..16],
        outcome.duration_secs,
        count(outcome.execs_done),
        count(outcome.edges_found),
        count(outcome.corpus_count),
        count(outcome.saved_hangs),
    );
    if outcome.findings.is_empty() {
        text.push_str("No crashing input was saved.\n");
    } else {
        let _ = writeln!(
            text,
            "Crashing inputs: {} ({} distinct by stack signature)",
            outcome.findings.len(),
            outcome.distinct_findings
        );
    }
    for finding in &outcome.findings {
        let what = if finding.summary.is_empty() {
            finding.fuzzer_signal.map_or_else(
                || "signal unknown, no replay report".to_owned(),
                |signal| {
                    format!(
                        "{} ({signal}), no replay report",
                        hf_service::binary_signal_name(signal)
                    )
                },
            )
        } else {
            finding.summary.clone()
        };
        let replay = if !finding.replayed {
            "not replayed"
        } else if finding.confirmed {
            "replay confirmed"
        } else {
            "replay did not reproduce the signal"
        };
        let id = &finding.sha256[..finding.sha256.len().min(12)];
        let _ = writeln!(text, "  {id}  {what}");
        let _ = writeln!(
            text,
            "      {} bytes  {replay}  {}",
            finding.size,
            finding.input.display()
        );
        if let Some(first) = &finding.duplicate_of {
            let _ = writeln!(
                text,
                "      same stack signature as {}",
                &first[..first.len().min(12)]
            );
        }
        if let Some(minimized) = &finding.minimized {
            let _ = writeln!(
                text,
                "      minimized to {} bytes  {}",
                minimized.size,
                minimized.input.display()
            );
        }
    }
    if !outcome.findings.is_empty() {
        let _ = writeln!(
            text,
            "Draft an issue for one: oxfuzz binary-issue <project> --report {} --finding <id> --draft",
            outcome.workspace.join("report.json").display()
        );
    }
    if outcome.findings_omitted > 0 {
        let _ = writeln!(
            text,
            "{} more crash file(s) were saved by AFL++ and not read.",
            outcome.findings_omitted
        );
    }
    let _ = write!(text, "Session directory: {}", outcome.workspace.display());
    text
}

#[cfg(feature = "crash-bisection")]
pub(crate) async fn cmd_bisect(args: crate::args::BisectArgs) -> anyhow::Result<()> {
    use hf_service::{BisectResult, BisectVerdict};
    let container = crate::approval::bootstrap().await;
    let outcome = container
        .bisect_crash(
            &args.project,
            &args.target,
            &args.crash,
            &args.good,
            Some(&args.bad),
        )
        .await?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
        return Ok(());
    }
    let short = |commit: &str| commit.chars().take(12).collect::<String>();
    println!(
        "Bisected {} commit(s) between {} (good) and {} (bad):",
        outcome.candidates,
        short(&outcome.good),
        short(&outcome.bad)
    );
    for step in &outcome.steps {
        let verdict = match step.verdict {
            BisectVerdict::Good => "good",
            BisectVerdict::Bad => "bad ",
            BisectVerdict::Skip => "skip",
        };
        if step.note.is_empty() {
            println!("  {verdict}  {}", short(&step.commit));
        } else {
            println!("  {verdict}  {}  {}", short(&step.commit), step.note);
        }
    }
    match &outcome.result {
        BisectResult::FirstBad { commit, subject } => {
            println!("First commit at which the input crashes: {commit}");
            println!("  {subject}");
            println!(
                "This is the first commit where the crash is observed; it may expose an older \
                 defect rather than introduce it."
            );
        }
        BisectResult::Undecided { commits } => {
            println!(
                "Undecided: the first crashing commit is one of these {} (oldest first); the \
                 others could not be built or replayed:",
                commits.len()
            );
            for commit in commits {
                println!("  {commit}");
            }
        }
    }
    Ok(())
}

/// Store `file` as the operator's dictionary for `target`.
pub(crate) async fn store_user_dictionary(
    container: &hf_service::ServiceContainer,
    project: &std::path::Path,
    target: &str,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(file)
        .map_err(|error| anyhow::anyhow!("cannot read dictionary {}: {error}", file.display()))?;
    let tokens = container
        .set_user_dictionary(project, target, &text)
        .await?;
    println!("Stored {tokens} dictionary token(s) for {target}; later runs use them first.");
    Ok(())
}

/// The `run --dict` step: store the dictionary, then let the run proceed.
pub(crate) async fn cmd_dict_before_run(
    project: &std::path::Path,
    target: &str,
    file: &std::path::Path,
) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    store_user_dictionary(&container, project, target, file).await
}

pub(crate) async fn cmd_dict(args: crate::args::DictArgs) -> anyhow::Result<()> {
    let crate::args::DictArgs {
        project,
        target,
        set,
        clear,
    } = args;
    let target = target.as_str();
    let container = crate::approval::bootstrap().await;
    if let Some(file) = set.as_deref() {
        return store_user_dictionary(&container, &project, target, file).await;
    }
    if clear {
        container.clear_user_dictionary(&project, target).await?;
        println!("Cleared the stored dictionary for {target}.");
        return Ok(());
    }
    match container.user_dictionary(&project, target) {
        Some(text) => print!("{text}"),
        None => eprintln!("No dictionary is stored for {target}."),
    }
    Ok(())
}

#[cfg(feature = "crash-alerts")]
pub(crate) async fn cmd_notify(args: crate::args::NotifyArgs) -> anyhow::Result<()> {
    let crate::args::NotifyArgs {
        project,
        target,
        test: test_only,
    } = args;
    let (project, target) = (project.as_deref(), target.as_deref());
    let container = crate::approval::bootstrap().await;
    if test_only {
        container.notifications_test().await?;
        println!("Notification webhook accepted the test message.");
        return Ok(());
    }
    // clap requires both whenever `--test` is absent.
    let project = project.ok_or_else(|| anyhow::anyhow!("a project path is required"))?;
    let target = target.ok_or_else(|| anyhow::anyhow!("--target is required"))?;
    match container.notify_latest_run(project, target).await? {
        0 => println!("The latest run of {target} has no crashes; nothing was sent."),
        crashes => println!("Sent an alert for {crashes} crash(es) in {target}."),
    }
    Ok(())
}

pub(crate) async fn cmd_ingest(project: PathBuf, file: &std::path::Path) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
    let stats = container.ingest_document(&project, file).await?;
    println!(
        "Ingested {} -> knowledge base now has {} file(s), {} chunk(s).",
        file.display(),
        stats.files,
        stats.chunks
    );
    Ok(())
}

/// The label for one replayed reproducer. A clean replay is reported as what
/// was observed, not as a fix: an input that only faults under its engine's
/// own instrumentation also replays cleanly against unchanged code.
fn regression_tag(still_crashes: bool, verified: bool) -> &'static str {
    if still_crashes {
        "STILL CRASHES"
    } else if verified {
        "NO CRASH ON REPLAY"
    } else {
        "INCONCLUSIVE"
    }
}

pub(crate) async fn cmd_regress(project: PathBuf, target: &str) -> anyhow::Result<()> {
    let container = crate::approval::bootstrap().await;
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
        "Replayed {} crash(es): {still} still crashing, {fixed} no longer crashing, {inconclusive} inconclusive.",
        results.len(),
    );
    for r in &results {
        let tag = regression_tag(r.still_crashes, r.verified);
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
    timeout_ms: Option<u64>,
    resume: bool,
    sanitizer: Option<&str>,
    cmplog: bool,
    seed: Option<u64>,
    iterations: usize,
    ai: AiOption,
) -> anyhow::Result<()> {
    let engine = parse_engine(engine)?;
    let lang = parse_lang(lang)?;
    let sanitizer = sanitizer.map(parse_sanitizer).transpose()?;
    let container =
        apply_ai_policy(crate::approval::bootstrap().await, ai, "this campaign").await?;
    if ai == AiOption::Off {
        println!("--ai off: no model is called at any step of this campaign.");
    }
    println!("--- Running autonomous campaign ---");
    let on_progress = crate::commands::status::printing_sink();
    let outcome = container
        .run_campaign_observed(
            &project,
            target,
            engine,
            lang,
            duration_secs,
            timeout_ms,
            // An absent flag defers to the configured `fuzzing.default_resume`.
            resume.then_some(true),
            // An absent flag is no constraint: the run records the harness's
            // own sanitizer.
            sanitizer,
            // CmpLog has no configured default: the flag is the only opt-in.
            cmplog.then_some(true),
            // An explicit --seed applies to every iteration; omitted, each
            // iteration's run derives its own run-id seed.
            seed,
            iterations,
            &on_progress,
        )
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
    if let Some(hangs) = outcome.hangs {
        println!("  hangs (per-input timeouts across iterations): {hangs}");
    }
    if let Some(refine) = &outcome.refine {
        // A coverage plateau proposed a targeted refined harness beside the
        // promoted one; the operator adopts, qualifies and promotes it.
        crate::commands::harness::print_refine_proposal(
            &refine.note,
            refine.harness_id,
            &project,
            &outcome.target,
            engine,
        );
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
    run_report_command(&project, target, out, lang, crate::approval::bootstrap).await
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
        let Commands::Report(crate::args::ReportArgs { report_lang, .. }) = default_cli.command
        else {
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
        let Commands::Report(crate::args::ReportArgs { report_lang, .. }) = chinese.command else {
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

#[cfg(test)]
mod kernel_summary_tests {
    use std::path::PathBuf;

    use hf_service::CommandTermination;
    use hf_service::SyzkallerSummary;

    #[test]
    fn the_summary_reports_the_run_its_counters_and_the_triage_command() {
        let run_id = uuid::Uuid::from_u128(7);
        let text = super::kernel_summary(
            &SyzkallerSummary {
                edges: 4821,
                execs: Some(12.5),
                execs_total: 930,
                crashes: 2,
                exit_code: Some(124),
                termination: Some(CommandTermination::Completed),
                run_id: Some(run_id),
                project_root: PathBuf::from("/p"),
                target: "Image".to_owned(),
            },
            1800,
        );
        assert!(
            text.starts_with(&format!(
                "Kernel campaign {run_id} on Image ran for up to 1800s: syz-manager exited (exit code 124)."
            )),
            "{text}"
        );
        assert!(
            text.contains("Programs executed: 930  (12.5 per second at peak)"),
            "{text}"
        );
        assert!(text.contains("Coverage: 4821 edges  Crashes: 2"), "{text}");
        assert!(
            text.ends_with("Triage it with: oxfuzz triage /p --target Image"),
            "{text}"
        );
    }

    /// A campaign whose guest never completed a program is still recorded,
    /// and its zero is easy to read as "nothing found".
    #[test]
    fn a_campaign_without_coverage_says_what_that_means() {
        let summary = SyzkallerSummary {
            edges: 0,
            execs: Some(0.0),
            execs_total: 647,
            crashes: 0,
            exit_code: Some(124),
            termination: Some(CommandTermination::Completed),
            run_id: Some(uuid::Uuid::from_u128(9)),
            project_root: PathBuf::from("/p"),
            target: "Image".to_owned(),
        };
        let text = super::kernel_summary(&summary, 1200);
        assert!(text.contains("Coverage: 0 edges"), "{text}");
        assert!(
            text.contains(
                "No coverage was recorded, so this campaign tested nothing: the guest did not \
                 finish a fuzzing program."
            ),
            "{text}"
        );
        assert!(text.contains("/dev/kvm"), "{text}");
        assert!(text.contains("--duration"), "{text}");
        let covered = super::kernel_summary(
            &SyzkallerSummary {
                edges: 12,
                ..summary
            },
            1200,
        );
        assert!(!covered.contains("No coverage was recorded"), "{covered}");
    }

    #[test]
    fn a_call_that_only_printed_guidance_is_not_reported_as_a_campaign() {
        let text = super::kernel_summary(&SyzkallerSummary::default(), 60);
        assert_eq!(
            text,
            "No kernel campaign was launched; see the guidance above."
        );
    }
}

#[cfg(all(test, feature = "binary-only-fuzzing"))]
mod binary_summary_tests {
    use std::path::PathBuf;

    use hf_service::{BinaryFinding, BinaryFuzzOutcome, MinimizedInput};

    #[test]
    fn a_clean_replay_is_not_labelled_as_a_fix() {
        assert_eq!(super::regression_tag(true, true), "STILL CRASHES");
        assert_eq!(super::regression_tag(false, true), "NO CRASH ON REPLAY");
        assert_eq!(super::regression_tag(false, false), "INCONCLUSIVE");
    }

    #[test]
    fn the_summary_groups_findings_and_names_the_minimized_input() {
        let finding = |sha256: &str, duplicate_of: Option<&str>| BinaryFinding {
            input: PathBuf::from(format!("/w/findings/crash-{sha256}")),
            sha256: sha256.to_owned(),
            size: 34,
            fuzzer_signal: Some(11),
            replay_signal: Some(11),
            replayed: true,
            confirmed: true,
            kind: None,
            signature: "sig".to_owned(),
            summary: "SEGV (signal 11) at (/work/target+0x89c)".to_owned(),
            frames: Vec::new(),
            duplicate_of: duplicate_of.map(str::to_owned),
            minimized: duplicate_of.is_none().then(|| MinimizedInput {
                input: PathBuf::from("/w/minimized/crash"),
                sha256: "d4".to_owned(),
                size: 4,
            }),
        };
        let unsigned = BinaryFinding {
            signature: String::new(),
            summary: String::new(),
            minimized: None,
            ..finding("0528e25a6f55564a8927", None)
        };
        let outcome: BinaryFuzzOutcome = serde_json::from_value(serde_json::json!({
            "session": "00000000-0000-0000-0000-000000000000",
            "workspace": "/w",
            "binary_name": "decoder",
            "binary_sha256": "ab".repeat(32),
            "machine": "aarch64",
            "input": "file",
            "duration_secs": 60,
            "execs_done": 1000,
            "execs_per_sec": 10.0,
            "edges_found": 5,
            "corpus_count": 3,
            "saved_hangs": 0,
            "findings": [
                finding("e87a3081cfe02e7f0a06", None),
                finding("d4ecd6ef93448e5ae208", Some("e87a3081cfe02e7f0a06")),
                unsigned
            ],
            "distinct_findings": 2,
            "findings_omitted": 0
        }))
        .unwrap();
        let text = super::binary_summary(&outcome);
        // The report path is joined on the host, so its separator is the
        // host's.
        let report_hint = format!(
            "oxfuzz binary-issue <project> --report {} --finding <id> --draft",
            PathBuf::from("/w").join("report.json").display()
        );
        for expected in [
            "Crashing inputs: 3 (2 distinct by stack signature)",
            "  e87a3081cfe0  SEGV (signal 11) at (/work/target+0x89c)",
            "      minimized to 4 bytes  /w/minimized/crash",
            "      same stack signature as e87a3081cfe0",
            "  0528e25a6f55  SIGSEGV (11), no replay report",
            report_hint.as_str(),
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
    }
}
