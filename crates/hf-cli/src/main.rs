//! oxfuzz CLI entry point.
//!
//! The CLI is a thin presentation layer (Engineering Protocol 2.9): every command builds
//! the canonical [`hf_service::ServiceContainer`] via [`approval::bootstrap`] -- the
//! canonical bootstrap with the CLI's approval gate installed -- and calls
//! service methods through it. No domain logic lives here.

mod ai_policy;
mod approval;
mod args;
mod commands;
mod parse;
mod tui;
#[cfg(feature = "harness-work-order")]
mod work_order;

// work_order.rs imports these from the crate root (`crate::parse_engine`).
#[cfg(feature = "harness-work-order")]
pub(crate) use parse::{parse_engine, parse_lang};

use clap::Parser;

use crate::args::{Cli, Commands};
#[cfg(feature = "automotive-scapy")]
use crate::commands::automotive::cmd_automotive;
#[cfg(feature = "run-closeout")]
use crate::commands::campaign::cmd_closeout;
#[cfg(feature = "campaign-health")]
use crate::commands::campaign::cmd_health;
#[cfg(feature = "campaign-trust")]
use crate::commands::campaign::cmd_trust;
use crate::commands::campaign::{
    cmd_campaign, cmd_ci, cmd_coverage, cmd_defectdojo, cmd_ingest, cmd_regress, cmd_report,
    cmd_repro, cmd_sarif,
};
use crate::commands::discovery::cmd_discover;
use crate::commands::fuzz::cmd_fuzz;
#[cfg(feature = "unreached-surface")]
use crate::commands::harness::{cmd_attribution, cmd_unreached};
use crate::commands::harness::{cmd_corpus, cmd_harness, cmd_run, cmd_triage};
use crate::commands::runs::{cmd_runs_list, cmd_runs_status, cmd_runs_stop};
use crate::commands::system::{
    cmd_agent, cmd_arm, cmd_doctor, cmd_export, cmd_knowledge, cmd_policy, cmd_providers,
    cmd_schedule, cmd_session,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    // Resolve the config directory before any command runs so an invalid
    // explicit choice (`--config`/`HF_CONFIG_DIR` naming a non-directory)
    // fails here with the operator's own words rather than deep in a command
    // (Engineering Protocol 2.16), and so an implicit binding is announced once.
    if let Some(dir) = &cli.config {
        hf_service::set_cli_config_dir(dir.clone())?;
    }
    let resolution = hf_service::config_resolution()?;
    // `init` is how the resolved directory comes to exist; warning about where
    // config resolved to while it is being written would be noise.
    if !matches!(cli.command, Commands::Init) {
        if let Some(warning) = &resolution.warning {
            eprintln!("warning: {warning}");
        }
    }
    // The dispatch future is enormous: every command arm's state machine nests
    // the service bootstrap inline, and `block_on` would hold all of it on the
    // main-thread stack for the process's lifetime. Boxing keeps startup within
    // a small RLIMIT_STACK (crates/hf-cli/tests/startup.rs runs with 1 MiB).
    Box::pin(dispatch(cli.command)).await
}

async fn dispatch(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Init => {
            let report = hf_service::init_workspace().await?;
            println!("Initialized oxfuzz workspace.");
            println!("  config dir: {}", report.config_dir.display());
            if report.created_configs.is_empty() {
                println!("  config: all files already present");
            } else {
                println!("  created: {}", report.created_configs.join(", "));
            }
            println!("  database: {}", report.db_path.display());
        }
        Commands::Doctor(args::DoctorArgs {
            json,
            engine,
            duration,
            require_provider,
            build_image,
        }) => {
            cmd_doctor(
                json,
                engine.as_deref(),
                duration.as_deref(),
                require_provider,
                build_image,
            )
            .await?;
        }
        Commands::Build(args::BuildArgs { command }) => commands::build::run(command).await?,
        Commands::Discover(args::DiscoverArgs {
            project,
            lang,
            rank,
            ai,
            #[cfg(feature = "semgrep-enrichment")]
            semgrep,
        }) => {
            cmd_discover(
                project,
                &lang,
                rank,
                ai,
                #[cfg(feature = "semgrep-enrichment")]
                semgrep,
            )
            .await?;
        }
        Commands::Harness(args::HarnessArgs {
            project,
            target,
            engine,
            lang,
            draft: args::HarnessDraftArgs { draft_only, json },
            ai,
            repair,
            refine,
            promote,
            no_llm_review,
            sanitizer,
        }) => {
            let output = if json {
                commands::harness::HarnessOutput::Json
            } else {
                commands::harness::HarnessOutput::Text
            };
            let review_bypass = if no_llm_review {
                hf_service::HarnessReviewBypass::Requested
            } else {
                hf_service::HarnessReviewBypass::NotRequested
            };
            cmd_harness(
                project,
                &target,
                &engine,
                &lang,
                draft_only,
                ai,
                repair,
                refine,
                promote,
                review_bypass,
                sanitizer.as_deref(),
                output,
            )
            .await?;
        }
        Commands::Run(args::RunArgs {
            project,
            target,
            engine,
            lang,
            duration,
            cpus,
            timeout_ms,
            resume,
            sanitizer,
            replay,
        }) => {
            cmd_run(
                project,
                target.as_deref(),
                engine.as_deref(),
                &lang,
                duration.as_deref(),
                cpus,
                timeout_ms,
                resume,
                sanitizer.as_deref(),
                replay.as_deref(),
            )
            .await?;
        }
        Commands::Runs(args::RunsArgs { op }) => match op {
            args::RunsOp::List {
                project,
                active,
                json,
                limit,
            } => cmd_runs_list(project, active, json, limit).await?,
            args::RunsOp::Status { id, json } => cmd_runs_status(&id, json).await?,
            args::RunsOp::Stop { id } => cmd_runs_stop(&id).await?,
        },
        Commands::Campaign(args::CampaignArgs {
            project,
            target,
            engine,
            lang,
            duration_secs,
            timeout_ms,
            resume,
            sanitizer,
            iterations,
            ai,
        }) => {
            cmd_campaign(
                project,
                target.as_deref(),
                &engine,
                &lang,
                duration_secs,
                timeout_ms,
                resume,
                sanitizer.as_deref(),
                iterations,
                ai,
            )
            .await?;
        }
        Commands::Fuzz(fuzz_args) => {
            cmd_fuzz(fuzz_args).await?;
        }
        Commands::Triage(args::TriageArgs {
            project,
            target,
            lang,
        }) => cmd_triage(project, &target, &lang).await?,
        Commands::Corpus(args::CorpusArgs {
            project,
            target,
            op,
            from,
        }) => cmd_corpus(project, &target, &op, from.as_deref()).await?,
        Commands::Coverage(args::CoverageArgs { project, target }) => {
            cmd_coverage(project, &target).await?;
        }
        #[cfg(feature = "campaign-trust")]
        Commands::Trust(args::TrustArgs { run }) => cmd_trust(&run).await?,
        #[cfg(feature = "unreached-surface")]
        Commands::Unreached(args::UnreachedArgs { project, lang }) => {
            cmd_unreached(project, &lang).await?;
        }
        #[cfg(feature = "unreached-surface")]
        Commands::Attribution(args::AttributionArgs { project, lang }) => {
            cmd_attribution(project, &lang).await?;
        }
        #[cfg(feature = "campaign-health")]
        Commands::Health(args::HealthArgs { run }) => cmd_health(&run).await?,
        #[cfg(feature = "run-closeout")]
        Commands::Closeout(args::CloseoutArgs { run }) => cmd_closeout(&run).await?,
        #[cfg(feature = "harness-work-order")]
        Commands::WorkOrder(args::WorkOrderArgs { command }) => work_order::run(command).await?,
        Commands::Ci(args::CiArgs {
            project,
            target,
            engine,
            lang,
            duration,
            sarif,
            ai,
        }) => cmd_ci(project, &target, &engine, &lang, &duration, &sarif, ai).await?,
        Commands::Regress(args::RegressArgs { project, target }) => {
            cmd_regress(project, &target).await?;
        }
        Commands::Ingest(args::IngestArgs { project, file }) => cmd_ingest(project, &file).await?,
        Commands::Sarif(args::SarifArgs {
            project,
            target,
            out,
        }) => cmd_sarif(project, &target, out.as_deref()).await?,
        Commands::Repro(args::ReproArgs {
            project,
            target,
            engine,
            lang,
            crash,
            out,
        }) => cmd_repro(project, &target, &engine, &lang, crash.as_deref(), &out).await?,
        Commands::Defectdojo(args::DefectdojoArgs {
            project,
            target,
            test,
        }) => cmd_defectdojo(project, target.as_deref(), test).await?,
        Commands::Export(args::ExportArgs { project, output }) => {
            cmd_export(project, output).await?;
        }
        Commands::Report(args::ReportArgs {
            project,
            target,
            out,
            report_lang,
        }) => cmd_report(project, &target, out.as_deref(), &report_lang).await?,
        Commands::Serve(args::ServeArgs { host, port }) => {
            let security = hf_web::WebSecurityConfig::from_env();
            let addr = std::net::SocketAddr::new(host, port);
            hf_web::validate_bind_addr(addr, security.token_configured())?;
            let app = hf_web::build_bootstrapped_with_security(security).await?;
            println!("oxfuzz web server listening on http://{addr}");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Arm(args::ArmArgs { url, off, status }) => cmd_arm(&url, off, status).await?,
        Commands::Tui(args::TuiArgs { project }) => {
            tui::Tui::run(&project).await?;
        }
        Commands::Agent(args::AgentArgs {
            message,
            project,
            agent,
        }) => cmd_agent(&message, project, agent.as_deref()).await?,
        Commands::Knowledge(args::KnowledgeArgs { op }) => cmd_knowledge(op)?,
        Commands::Schedule(args::ScheduleArgs { op }) => cmd_schedule(op).await?,
        Commands::Session(args::SessionArgs { op }) => cmd_session(op).await?,
        Commands::Providers(args::ProvidersArgs { op }) => cmd_providers(op).await?,
        Commands::Policy(args::PolicyArgs { op }) => cmd_policy(op).await?,
        #[cfg(feature = "automotive-scapy")]
        Commands::Automotive(args::AutomotiveArgs { op }) => cmd_automotive(op).await?,
    }
    Ok(())
}
