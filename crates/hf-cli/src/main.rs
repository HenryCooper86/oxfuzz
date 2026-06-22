//! hobot-fuzz CLI entry point.

use clap::{Parser, Subcommand};

/// AI fuzzing agent.
#[derive(Parser)]
#[command(name = "hobot-fuzz", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize configuration.
    Init,
    /// Discover fuzzing targets in a project.
    Discover {
        /// Project root path.
        project: String,
        /// Target language.
        #[arg(long)]
        lang: String,
    },
    /// Generate a harness for a target.
    Harness {
        /// Project root path.
        project: String,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine.
        #[arg(long)]
        engine: String,
    },
    /// Run a fuzz campaign.
    Run {
        /// Project root path.
        project: String,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Fuzzing engine.
        #[arg(long)]
        engine: String,
        /// Duration (e.g. 60m).
        #[arg(long)]
        duration: Option<String>,
    },
    /// Triage crashes from a run.
    Triage {
        /// Project root path.
        project: String,
        /// Target symbol.
        #[arg(long)]
        target: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Init => println!("init: not implemented"),
        Commands::Discover { project, lang } => {
            println!("discover: {project} ({lang}) -- not implemented");
        }
        Commands::Harness {
            project,
            target,
            engine,
        } => {
            println!("harness: {project} target={target} engine={engine} -- not implemented");
        }
        Commands::Run {
            project,
            target,
            engine,
            duration,
        } => {
            println!(
                "run: {project} target={target} engine={engine} duration={:?} -- not implemented",
                duration
            );
        }
        Commands::Triage { project, target } => {
            println!("triage: {project} target={target} -- not implemented");
        }
    }
    Ok(())
}
