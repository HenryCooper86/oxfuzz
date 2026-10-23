//! Native mutator file input and service result rendering.
use crate::args::{MutatorArgs, MutatorCommand};
use std::io::Read;

pub(crate) async fn run(args: MutatorArgs) -> anyhow::Result<()> {
    let service = crate::approval::bootstrap().await;
    let engine = crate::parse::parse_engine(&args.engine)?;
    let current = service
        .managed_mutator_status(&args.project, &args.target, engine)
        .await?;
    let result = match args.command {
        MutatorCommand::Status => serde_json::to_value(&current)?,
        MutatorCommand::Qualify => {
            service
                .harness_smoke(&args.project, &args.target, engine, current.language)
                .await?;
            serde_json::to_value(
                service
                    .managed_mutator_status(&args.project, &args.target, engine)
                    .await?,
            )?
        }
        MutatorCommand::Promote => serde_json::to_value(
            service
                .harness_promote(&args.project, &args.target, engine)
                .await?,
        )?,
        MutatorCommand::Attach { source } => {
            // Bound file I/O; source/API validation remains owned by the service.
            let mut text = String::new();
            std::fs::File::open(source)?
                .take(65537)
                .read_to_string(&mut text)?;
            serde_json::to_value(
                service
                    .attach_managed_mutator(
                        &args.project,
                        &args.target,
                        engine,
                        current.harness_id,
                        text,
                    )
                    .await?,
            )?
        }
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
