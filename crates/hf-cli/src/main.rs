//! oxfuzz CLI entry point.
//!
//! The CLI is a thin presentation layer (AGENTS.md 2.9): every command builds
//! the canonical [`hf_service::ServiceContainer`] via `bootstrap()` and calls
//! service methods through it. No domain logic lives here.

mod ai_policy;
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
#[cfg(feature = "unreached-surface")]
use crate::commands::harness::cmd_attribution;
use crate::commands::harness::cmd_unreached;
use crate::commands::harness::{cmd_corpus, cmd_harness, cmd_run, cmd_triage};
use crate::commands::system::{
    cmd_agent, cmd_arm, cmd_doctor, cmd_export, cmd_knowledge, cmd_policy, cmd_providers,
    cmd_schedule, cmd_session,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
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
        Commands::Doctor { json } => cmd_doctor(json).await?,
        Commands::Discover {
            project,
            lang,
            rank,
            ai,
            #[cfg(feature = "semgrep-enrichment")]
            semgrep,
        } => {
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
        Commands::Harness {
            project,
            target,
            engine,
            lang,
            draft_only,
            ai,
            repair,
            refine,
            promote,
        } => {
            cmd_harness(
                project, &target, &engine, &lang, draft_only, ai, repair, refine, promote,
            )
            .await?;
        }
        Commands::Run {
            project,
            target,
            engine,
            lang,
            duration,
            replay,
        } => {
            cmd_run(
                project,
                target.as_deref(),
                engine.as_deref(),
                &lang,
                duration.as_deref(),
                replay.as_deref(),
            )
            .await?;
        }
        Commands::Campaign {
            project,
            target,
            engine,
            lang,
            duration_secs,
            iterations,
            ai,
        } => {
            cmd_campaign(
                project,
                target.as_deref(),
                &engine,
                &lang,
                duration_secs,
                iterations,
                ai,
            )
            .await?;
        }
        Commands::Triage {
            project,
            target,
            lang,
        } => cmd_triage(project, &target, &lang).await?,
        Commands::Corpus {
            project,
            target,
            op,
        } => cmd_corpus(project, &target, &op).await?,
        Commands::Coverage { project, target } => cmd_coverage(project, &target).await?,
        #[cfg(feature = "campaign-trust")]
        Commands::Trust { run } => cmd_trust(&run).await?,
        #[cfg(feature = "unreached-surface")]
        Commands::Unreached { project, lang } => cmd_unreached(project, &lang).await?,
        #[cfg(feature = "unreached-surface")]
        Commands::Attribution { project, lang } => cmd_attribution(project, &lang).await?,
        #[cfg(feature = "campaign-health")]
        Commands::Health { run } => cmd_health(&run).await?,
        #[cfg(feature = "run-closeout")]
        Commands::Closeout { run } => cmd_closeout(&run).await?,
        #[cfg(feature = "harness-work-order")]
        Commands::WorkOrder { command } => work_order::run(command).await?,
        Commands::Ci {
            project,
            target,
            engine,
            lang,
            duration,
            sarif,
            ai,
        } => cmd_ci(project, &target, &engine, &lang, &duration, &sarif, ai).await?,
        Commands::Regress { project, target } => cmd_regress(project, &target).await?,
        Commands::Ingest { project, file } => cmd_ingest(project, &file).await?,
        Commands::Sarif {
            project,
            target,
            out,
        } => cmd_sarif(project, &target, out.as_deref()).await?,
        Commands::Repro {
            project,
            target,
            engine,
            lang,
            crash,
            out,
        } => cmd_repro(project, &target, &engine, &lang, crash.as_deref(), &out).await?,
        Commands::Defectdojo {
            project,
            target,
            test,
        } => cmd_defectdojo(project, target.as_deref(), test).await?,
        Commands::Export { project, output } => cmd_export(project, output).await?,
        Commands::Report {
            project,
            target,
            out,
            report_lang,
        } => cmd_report(project, &target, out.as_deref(), &report_lang).await?,
        Commands::Serve { host, port } => {
            let security = hf_web::WebSecurityConfig::from_env();
            let addr = std::net::SocketAddr::new(host, port);
            hf_web::validate_bind_addr(addr, security.token_configured())?;
            let app = hf_web::build_bootstrapped_with_security(security).await?;
            println!("oxfuzz web server listening on http://{addr}");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
        Commands::Arm { url, off, status } => cmd_arm(&url, off, status).await?,
        Commands::Tui { project } => {
            tui::Tui::run(&project).await?;
        }
        Commands::Agent {
            message,
            project,
            agent,
        } => cmd_agent(&message, project, agent.as_deref()).await?,
        Commands::Knowledge { op } => cmd_knowledge(op)?,
        Commands::Schedule { op } => cmd_schedule(op).await?,
        Commands::Session { op } => cmd_session(op).await?,
        Commands::Providers { op } => cmd_providers(op).await?,
        Commands::Policy { op } => cmd_policy(op).await?,
        #[cfg(feature = "automotive-scapy")]
        Commands::Automotive { op } => cmd_automotive(op).await?,
    }
    Ok(())
}
