use std::{
    fs::{self, File},
    future::Future,
    io::Read as _,
    path::{Path, PathBuf},
};

use anyhow::Context as _;
use clap::{Subcommand, ValueEnum};
use hf_service::{
    HarnessWorkOrderExportRequest, ImportHarnessWorkOrderSubmissionRequest, ServiceContainer,
    WorkOrderSubmissionOrigin,
};
use uuid::Uuid;

use crate::{parse_engine, parse_lang};

/// Maximum number of source bytes accepted for one imported submission.
const MAX_SUBMISSION_SOURCE_BYTES: u64 = 65_536;

/// Work-order operations available from the terminal.
#[derive(Subcommand)]
pub enum WorkOrderCommand {
    /// Export one immutable authoring packet.
    Export {
        /// Project root path.
        project: PathBuf,
        /// Target symbol.
        #[arg(long)]
        target: String,
        /// Target language.
        #[arg(long)]
        lang: String,
        /// Fuzzing engine.
        #[arg(long)]
        engine: String,
        /// Write the rendered packet here instead of standard output.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Import one immutable harness source submission.
    Import {
        /// Immutable work-order identifier.
        #[arg(long)]
        work_order: String,
        /// Regular UTF-8 source file to import.
        #[arg(long)]
        source: PathBuf,
        /// Who authored the submission.
        #[arg(long, value_enum)]
        origin: SubmissionOriginArg,
        /// External authoring tool name.
        #[arg(long)]
        tool: Option<String>,
        /// Optional external model label.
        #[arg(long)]
        model: Option<String>,
        /// Optional external response identifier.
        #[arg(long)]
        response_id: Option<String>,
        /// Earlier submission repaired by this submission.
        #[arg(long)]
        parent: Option<Uuid>,
    },
    /// List immutable work orders.
    List {
        /// Restrict results to this project.
        #[arg(long)]
        project: Option<PathBuf>,
    },
    /// List immutable source submissions for one work order.
    Submissions {
        /// Immutable work-order identifier.
        #[arg(long)]
        work_order: String,
    },
    /// Qualify one immutable submission.
    Qualify {
        /// Immutable submission identifier.
        #[arg(long)]
        submission: Uuid,
    },
    /// Rank retained qualification attempts.
    Rank {
        /// Qualification attempt identifier. Repeat for every candidate.
        #[arg(long, required = true)]
        attempt: Vec<Uuid>,
    },
    /// Promote one exact smoke-qualified attempt.
    Promote {
        /// Qualification attempt identifier.
        #[arg(long)]
        attempt: Uuid,
    },
}

/// Origin selector accepted by the work-order import command.
#[derive(Clone, Copy, ValueEnum)]
pub enum SubmissionOriginArg {
    /// The source was authored directly by a person.
    Human,
    /// The source was returned by an external authoring tool.
    ExternalTool,
}

impl WorkOrderCommand {
    fn provenance(&self) -> anyhow::Result<WorkOrderSubmissionOrigin> {
        let Self::Import {
            origin,
            tool,
            model,
            response_id,
            ..
        } = self
        else {
            anyhow::bail!("submission provenance is only valid for work-order import");
        };

        match origin {
            SubmissionOriginArg::Human => {
                if tool.is_some() || model.is_some() || response_id.is_some() {
                    anyhow::bail!(
                        "--tool, --model, and --response-id require --origin external-tool"
                    );
                }
                Ok(WorkOrderSubmissionOrigin::Human)
            }
            SubmissionOriginArg::ExternalTool => {
                let tool = tool.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("--origin external-tool requires --tool <name>")
                })?;
                Ok(WorkOrderSubmissionOrigin::ExternalTool {
                    tool: tool.clone(),
                    model: model.clone(),
                    response_id: response_id.clone(),
                })
            }
        }
    }
}

/// Read one bounded, regular, non-symlink UTF-8 submission source file.
pub fn read_submission_source(path: &Path) -> anyhow::Result<String> {
    read_submission_source_after_check(path, || {})
}

fn read_submission_source_after_check(
    path: &Path,
    before_open: impl FnOnce(),
) -> anyhow::Result<String> {
    let preliminary = fs::symlink_metadata(path).context("cannot inspect submission source")?;
    let file_type = preliminary.file_type();
    if file_type.is_symlink() {
        anyhow::bail!("submission source must not be a symlink");
    }
    if !file_type.is_file() {
        anyhow::bail!("submission source must be a regular file");
    }

    before_open();
    let file = open_submission_source_without_following_final_link(path)?;
    let metadata = file
        .metadata()
        .context("cannot inspect opened submission source")?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("submission source must be a regular file");
    }
    if metadata.len() == 0 {
        anyhow::bail!("submission source must not be empty");
    }
    if metadata.len() > MAX_SUBMISSION_SOURCE_BYTES {
        anyhow::bail!("submission source exceeds 65536 bytes");
    }

    let mut source = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SUBMISSION_SOURCE_BYTES + 1)
        .read_to_end(&mut source)
        .context("cannot read submission source")?;
    if source.len() as u64 > MAX_SUBMISSION_SOURCE_BYTES {
        anyhow::bail!("submission source exceeds 65536 bytes");
    }
    if source.is_empty() {
        anyhow::bail!("submission source must not be empty");
    }
    String::from_utf8(source).map_err(|_| anyhow::anyhow!("submission source must be valid UTF-8"))
}

#[cfg(unix)]
fn open_submission_source_without_following_final_link(path: &Path) -> anyhow::Result<File> {
    use rustix::{
        fs::{open, Mode, OFlags},
        io::Errno,
    };

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == Errno::LOOP {
            anyhow::anyhow!("submission source must not be a symlink")
        } else {
            anyhow::anyhow!("cannot securely open submission source: {error}")
        }
    })?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_submission_source_without_following_final_link(_path: &Path) -> anyhow::Result<File> {
    anyhow::bail!("secure no-follow submission source reads are unsupported on this platform")
}

/// Dispatch one work-order command through `hf-service`.
pub async fn run(command: WorkOrderCommand) -> anyhow::Result<()> {
    run_with_bootstrap(command, ServiceContainer::bootstrap).await
}

async fn run_with_bootstrap<F, Fut>(command: WorkOrderCommand, bootstrap: F) -> anyhow::Result<()>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ServiceContainer>,
{
    match command {
        WorkOrderCommand::Export {
            project,
            target,
            lang,
            engine,
            out,
        } => {
            let language = parse_lang(&lang)?;
            let engine = parse_engine(&engine)?;
            let container = bootstrap().await;
            let work_order = container
                .export_harness_work_order(HarnessWorkOrderExportRequest {
                    project,
                    target,
                    language,
                    engine,
                })
                .await?;
            let rendered = hf_service::render_work_order(&work_order);
            write_export(&rendered, out.as_deref())?;
        }
        command @ WorkOrderCommand::Import { .. } => {
            let request = import_submission_request(command)?;
            let container = bootstrap().await;
            let submission = container
                .import_harness_work_order_submission(request)
                .await?;
            let value = serde_json::to_value(submission)?;
            print_json(&value)?;
        }
        WorkOrderCommand::List { project } => {
            let container = bootstrap().await;
            let work_orders = container
                .list_harness_work_orders(project.as_deref())
                .await?;
            let value = serde_json::to_value(work_orders)?;
            print_json(&value)?;
        }
        WorkOrderCommand::Submissions { work_order } => {
            let container = bootstrap().await;
            let submissions = container
                .list_harness_work_order_submissions(&work_order)
                .await?;
            let value = serde_json::to_value(submissions)?;
            print_json(&value)?;
        }
        WorkOrderCommand::Qualify { submission } => {
            let container = bootstrap().await;
            let attempt = container
                .qualify_harness_work_order_submission(submission)
                .await?;
            let value = serde_json::to_value(attempt)?;
            print_json(&value)?;
        }
        WorkOrderCommand::Rank { attempt } => {
            let container = bootstrap().await;
            let ranking = container.rank_harness_work_order_attempts(&attempt).await?;
            let value = serde_json::to_value(ranking)?;
            print_json(&value)?;
        }
        WorkOrderCommand::Promote { attempt } => {
            let container = bootstrap().await;
            let harness = container
                .promote_harness_work_order_attempt(attempt)
                .await?;
            let value = serde_json::to_value(harness)?;
            print_json(&value)?;
        }
    }
    Ok(())
}

fn import_submission_request(
    command: WorkOrderCommand,
) -> anyhow::Result<ImportHarnessWorkOrderSubmissionRequest> {
    let provenance = command.provenance()?;
    let WorkOrderCommand::Import {
        work_order,
        source,
        parent,
        ..
    } = command
    else {
        anyhow::bail!("submission source is only valid for work-order import");
    };
    let source = read_submission_source(&source)?;
    Ok(ImportHarnessWorkOrderSubmissionRequest {
        work_order_id: work_order,
        source,
        origin: provenance,
        parent_submission_id: parent,
    })
}

fn write_export(rendered: &str, out: Option<&Path>) -> anyhow::Result<()> {
    match out {
        Some(path) => {
            fs::write(path, rendered)?;
            println!("work order written to {}", path.display());
        }
        None => print!("{rendered}"),
    }
    Ok(())
}

fn print_json(value: &serde_json::Value) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use clap::{CommandFactory as _, Parser as _};
    use hf_service::{
        work_order_commands, HarnessWorkOrder, ServiceContainer, WorkOrderArg,
        WorkOrderPlaceholder, WorkOrderStep,
    };
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::{
        import_submission_request, read_submission_source, read_submission_source_after_check,
        run_with_bootstrap, SubmissionOriginArg, WorkOrderCommand,
    };
    use crate::{Cli, Commands};

    #[test]
    fn parses_every_approved_work_order_command() {
        let commands = [
            (
                vec![
                    "oxfuzz",
                    "work-order",
                    "export",
                    "/tmp/project",
                    "--target",
                    "parse",
                    "--lang",
                    "c",
                    "--engine",
                    "libfuzzer",
                ],
                "export",
            ),
            (
                vec![
                    "oxfuzz",
                    "work-order",
                    "import",
                    "--work-order",
                    "order",
                    "--source",
                    "harness.c",
                    "--origin",
                    "human",
                ],
                "import",
            ),
            (vec!["oxfuzz", "work-order", "list"], "list"),
            (
                vec![
                    "oxfuzz",
                    "work-order",
                    "submissions",
                    "--work-order",
                    "order",
                ],
                "submissions",
            ),
            (
                vec![
                    "oxfuzz",
                    "work-order",
                    "qualify",
                    "--submission",
                    "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
                ],
                "qualify",
            ),
            (
                vec![
                    "oxfuzz",
                    "work-order",
                    "rank",
                    "--attempt",
                    "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
                    "--attempt",
                    "bd909496-01df-4be3-8ff9-76ff5386c4a8",
                ],
                "rank",
            ),
            (
                vec![
                    "oxfuzz",
                    "work-order",
                    "promote",
                    "--attempt",
                    "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
                ],
                "promote",
            ),
        ];

        for (args, expected) in commands {
            let cli = Cli::try_parse_from(args).expect("approved command parses");
            let Commands::WorkOrder { command } = cli.command else {
                panic!("expected work-order command");
            };
            let actual = match command {
                WorkOrderCommand::Export { .. } => "export",
                WorkOrderCommand::Import { .. } => "import",
                WorkOrderCommand::List { .. } => "list",
                WorkOrderCommand::Submissions { .. } => "submissions",
                WorkOrderCommand::Qualify { .. } => "qualify",
                WorkOrderCommand::Rank { .. } => "rank",
                WorkOrderCommand::Promote { .. } => "promote",
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn emitted_validation_commands_round_trip_through_the_real_cli() {
        let packet: HarnessWorkOrder = serde_json::from_value(serde_json::json!({
            "schema_version": 2,
            "id": "a".repeat(64),
            "payload": {
                "target": {
                    "symbol": "ns::parse_packet",
                    "signature": "int ns::parse_packet(const unsigned char *, size_t)",
                    "language": "Cpp",
                    "relative_source": "src/parser.cpp",
                    "line": 42,
                    "rationale": "parses an untrusted packet"
                },
                "engine": "libfuzzer",
                "source": {
                    "excerpt": "int ns::parse_packet() { return 0; }",
                    "excerpt_truncated": false,
                    "sha256": "b".repeat(64)
                },
                "compile_context": {
                    "include_dirs": [],
                    "defines": [],
                    "std_flag": "-std=c++17",
                    "extra_flags": [],
                    "compile_units": 1,
                    "dropped_flags": []
                },
                "compile_context_sha256": "c".repeat(64),
                "harness_rules": [],
                "seeds": [],
                "validation_steps": [
                    "import",
                    "qualify",
                    "rank",
                    "promote",
                    {"run_campaign": {"duration_secs": 300}},
                    "coverage"
                ]
            }
        }))
        .expect("construct command packet");
        let submission_id = "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6";
        let attempt_id = "bd909496-01df-4be3-8ff9-76ff5386c4a8";

        for command in work_order_commands(&packet) {
            let step = command.step;
            let args = command
                .argv
                .into_iter()
                .map(|argument| match argument {
                    WorkOrderArg::Literal(value) => value,
                    WorkOrderArg::Placeholder(WorkOrderPlaceholder::Project) => {
                        "/tmp/project".to_owned()
                    }
                    WorkOrderArg::Placeholder(WorkOrderPlaceholder::SourceFile) => {
                        "/tmp/harness.cpp".to_owned()
                    }
                    WorkOrderArg::Placeholder(WorkOrderPlaceholder::SubmissionOrigin) => {
                        "human".to_owned()
                    }
                    WorkOrderArg::Placeholder(WorkOrderPlaceholder::SubmissionId) => {
                        submission_id.to_owned()
                    }
                    WorkOrderArg::Placeholder(
                        WorkOrderPlaceholder::AttemptIds | WorkOrderPlaceholder::AttemptId,
                    ) => attempt_id.to_owned(),
                })
                .collect::<Vec<_>>();
            let cli = Cli::try_parse_from(args).expect("emitted argv parses through the real CLI");

            match (step, cli.command) {
                (WorkOrderStep::Import, Commands::WorkOrder { command }) => {
                    assert!(matches!(command, WorkOrderCommand::Import { .. }));
                }
                (WorkOrderStep::Qualify, Commands::WorkOrder { command }) => {
                    assert!(matches!(command, WorkOrderCommand::Qualify { .. }));
                }
                (WorkOrderStep::Rank, Commands::WorkOrder { command }) => {
                    assert!(matches!(command, WorkOrderCommand::Rank { .. }));
                }
                (WorkOrderStep::Promote, Commands::WorkOrder { command }) => {
                    assert!(matches!(command, WorkOrderCommand::Promote { .. }));
                }
                (
                    WorkOrderStep::RunCampaign { duration_secs: 300 },
                    Commands::Run {
                        project,
                        target,
                        engine,
                        lang,
                        duration,
                        replay,
                    },
                ) => {
                    assert_eq!(project, PathBuf::from("/tmp/project"));
                    assert_eq!(target.as_deref(), Some("src/parser.cpp::ns::parse_packet"));
                    assert_eq!(engine.as_deref(), Some("libfuzzer"));
                    assert_eq!(lang, "cpp");
                    assert_eq!(duration.as_deref(), Some("300s"));
                    assert!(replay.is_none());
                }
                (WorkOrderStep::Coverage, Commands::Coverage { project, target }) => {
                    assert_eq!(project, PathBuf::from("/tmp/project"));
                    assert_eq!(target, "src/parser.cpp::ns::parse_packet");
                }
                (step, _) => panic!("unexpected parsed command for {step:?}"),
            }
        }
    }

    #[test]
    fn parser_preserves_every_approved_work_order_field() {
        let export = parse_work_order_command([
            "oxfuzz",
            "work-order",
            "export",
            "/tmp/project",
            "--target",
            "parse",
            "--lang",
            "c",
            "--engine",
            "libfuzzer",
            "--out",
            "packet.md",
        ]);
        let WorkOrderCommand::Export {
            project,
            target,
            lang,
            engine,
            out,
        } = export
        else {
            panic!("expected export command");
        };
        assert_eq!(project, PathBuf::from("/tmp/project"));
        assert_eq!(target, "parse");
        assert_eq!(lang, "c");
        assert_eq!(engine, "libfuzzer");
        assert_eq!(out, Some(PathBuf::from("packet.md")));

        let import = parse_work_order_command([
            "oxfuzz",
            "work-order",
            "import",
            "--work-order",
            "order",
            "--source",
            "harness.c",
            "--origin",
            "external-tool",
            "--tool",
            "author",
            "--model",
            "model-a",
            "--response-id",
            "response-1",
            "--parent",
            "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
        ]);
        let WorkOrderCommand::Import {
            work_order,
            source,
            origin,
            tool,
            model,
            response_id,
            parent,
        } = import
        else {
            panic!("expected import command");
        };
        assert_eq!(work_order, "order");
        assert_eq!(source, PathBuf::from("harness.c"));
        assert!(matches!(origin, SubmissionOriginArg::ExternalTool));
        assert_eq!(tool.as_deref(), Some("author"));
        assert_eq!(model.as_deref(), Some("model-a"));
        assert_eq!(response_id.as_deref(), Some("response-1"));
        assert_eq!(
            parent.unwrap(),
            "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6"
                .parse::<Uuid>()
                .unwrap()
        );

        let list =
            parse_work_order_command(["oxfuzz", "work-order", "list", "--project", "/tmp/project"]);
        let WorkOrderCommand::List { project } = list else {
            panic!("expected list command");
        };
        assert_eq!(project, Some(PathBuf::from("/tmp/project")));

        let submissions = parse_work_order_command([
            "oxfuzz",
            "work-order",
            "submissions",
            "--work-order",
            "order",
        ]);
        let WorkOrderCommand::Submissions { work_order } = submissions else {
            panic!("expected submissions command");
        };
        assert_eq!(work_order, "order");

        let qualify = parse_work_order_command([
            "oxfuzz",
            "work-order",
            "qualify",
            "--submission",
            "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
        ]);
        let WorkOrderCommand::Qualify { submission } = qualify else {
            panic!("expected qualify command");
        };
        assert_eq!(
            submission,
            "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6"
                .parse::<Uuid>()
                .unwrap()
        );

        let rank = parse_work_order_command([
            "oxfuzz",
            "work-order",
            "rank",
            "--attempt",
            "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6",
            "--attempt",
            "bd909496-01df-4be3-8ff9-76ff5386c4a8",
        ]);
        let WorkOrderCommand::Rank { attempt } = rank else {
            panic!("expected rank command");
        };
        assert_eq!(
            attempt,
            vec![
                "0e1c781f-7ff1-4bd3-a4e6-a8faf94067a6"
                    .parse::<Uuid>()
                    .unwrap(),
                "bd909496-01df-4be3-8ff9-76ff5386c4a8"
                    .parse::<Uuid>()
                    .unwrap(),
            ]
        );

        let promote = parse_work_order_command([
            "oxfuzz",
            "work-order",
            "promote",
            "--attempt",
            "bd909496-01df-4be3-8ff9-76ff5386c4a8",
        ]);
        let WorkOrderCommand::Promote { attempt } = promote else {
            panic!("expected promote command");
        };
        assert_eq!(
            attempt,
            "bd909496-01df-4be3-8ff9-76ff5386c4a8"
                .parse::<Uuid>()
                .unwrap()
        );
    }

    #[test]
    fn rejects_the_old_flat_work_order_form() {
        let Err(error) = Cli::try_parse_from([
            "oxfuzz",
            "work-order",
            "/tmp/project",
            "--target",
            "parse",
            "--lang",
            "c",
            "--engine",
            "libfuzzer",
        ]) else {
            panic!("old flat command must not parse");
        };

        assert!(error.to_string().contains("unrecognized subcommand"));
    }

    #[test]
    fn external_tool_import_requires_tool_provenance() {
        let command = WorkOrderCommand::Import {
            work_order: "order".to_owned(),
            source: "harness.c".into(),
            origin: SubmissionOriginArg::ExternalTool,
            tool: None,
            model: None,
            response_id: None,
            parent: None,
        };

        let error = command.provenance().expect_err("tool is required");
        assert_eq!(
            error.to_string(),
            "--origin external-tool requires --tool <name>"
        );
    }

    #[test]
    fn human_import_rejects_external_tool_provenance_fields() {
        let command = WorkOrderCommand::Import {
            work_order: "order".to_owned(),
            source: "harness.c".into(),
            origin: SubmissionOriginArg::Human,
            tool: Some("author".to_owned()),
            model: None,
            response_id: None,
            parent: None,
        };

        let error = command
            .provenance()
            .expect_err("human has no tool provenance");
        assert_eq!(
            error.to_string(),
            "--tool, --model, and --response-id require --origin external-tool"
        );
    }

    #[test]
    fn work_order_help_lists_exactly_the_seven_approved_commands() {
        let mut command = Cli::command();
        let work_order = command
            .find_subcommand_mut("work-order")
            .expect("work-order subcommand");
        let subcommands = work_order
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect::<Vec<_>>();
        assert_eq!(
            subcommands,
            [
                "export",
                "import",
                "list",
                "submissions",
                "qualify",
                "rank",
                "promote",
            ]
        );
        let help = work_order.render_long_help().to_string();

        for subcommand in [
            "export",
            "import",
            "list",
            "submissions",
            "qualify",
            "rank",
            "promote",
        ] {
            assert!(help.contains(subcommand), "{help}");
        }
        assert!(!help.contains("/tmp/project"), "{help}");
    }

    #[test]
    fn reads_a_regular_utf8_source_file() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("harness.c");
        fs::write(&path, "int main(void) { return 0; }\n").unwrap();

        assert_eq!(
            read_submission_source(&path).unwrap(),
            "int main(void) { return 0; }\n"
        );
    }

    #[test]
    fn accepts_a_submission_source_of_exactly_65536_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("maximum.c");
        fs::write(&path, vec![b'a'; 65_536]).unwrap();

        assert_eq!(read_submission_source(&path).unwrap().len(), 65_536);
    }

    #[test]
    fn rejects_symlink_directory_empty_invalid_utf8_and_oversized_source_files() {
        let directory = tempdir().unwrap();
        let empty = directory.path().join("empty.c");
        let invalid_utf8 = directory.path().join("invalid.c");
        let oversized = directory.path().join("oversized.c");
        fs::write(&empty, []).unwrap();
        fs::write(&invalid_utf8, [0xff]).unwrap();
        fs::write(&oversized, vec![b'a'; 65_537]).unwrap();

        assert_eq!(
            read_submission_source(directory.path())
                .unwrap_err()
                .to_string(),
            "submission source must be a regular file"
        );
        assert_eq!(
            read_submission_source(&empty).unwrap_err().to_string(),
            "submission source must not be empty"
        );
        assert_eq!(
            read_submission_source(&invalid_utf8)
                .unwrap_err()
                .to_string(),
            "submission source must be valid UTF-8"
        );
        assert_eq!(
            read_submission_source(&oversized).unwrap_err().to_string(),
            "submission source exceeds 65536 bytes"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let target = directory.path().join("target.c");
            let link = directory.path().join("link.c");
            fs::write(&target, "int main(void) { return 0; }").unwrap();
            symlink(&target, &link).unwrap();
            assert_eq!(
                read_submission_source(Path::new(&link))
                    .unwrap_err()
                    .to_string(),
                "submission source must not be a symlink"
            );
        }
    }

    #[test]
    fn rejects_invalid_source_before_constructing_an_import_request() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("empty.c");
        fs::write(&path, []).unwrap();
        let command = WorkOrderCommand::Import {
            work_order: "order".to_owned(),
            source: path,
            origin: SubmissionOriginArg::Human,
            tool: None,
            model: None,
            response_id: None,
            parent: None,
        };

        let error = import_submission_request(command).expect_err("empty source is rejected");
        assert_eq!(error.to_string(), "submission source must not be empty");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_final_symlink_swapped_after_the_preliminary_check() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let source = directory.path().join("harness.c");
        let target = directory.path().join("target.c");
        fs::write(&source, "regular source").unwrap();
        fs::write(&target, "target bytes must never be returned").unwrap();

        let error = read_submission_source_after_check(&source, || {
            fs::remove_file(&source).unwrap();
            symlink(&target, &source).unwrap();
        })
        .expect_err("final symlink swap must be rejected");
        assert_eq!(error.to_string(), "submission source must not be a symlink");
    }

    #[tokio::test]
    async fn run_rejects_invalid_import_before_bootstrapping_the_service() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("empty.c");
        fs::write(&source, []).unwrap();
        let command = WorkOrderCommand::Import {
            work_order: "order".to_owned(),
            source,
            origin: SubmissionOriginArg::Human,
            tool: None,
            model: None,
            response_id: None,
            parent: None,
        };
        let bootstrap_count = Arc::new(AtomicUsize::new(0));
        let count_for_bootstrap = Arc::clone(&bootstrap_count);

        let error: anyhow::Error = run_with_bootstrap(command, move || {
            count_for_bootstrap.fetch_add(1, Ordering::SeqCst);
            ServiceContainer::bootstrap()
        })
        .await
        .expect_err("invalid import input must fail");

        assert_eq!(error.to_string(), "submission source must not be empty");
        assert_eq!(bootstrap_count.load(Ordering::SeqCst), 0);
    }

    fn parse_work_order_command<const N: usize>(args: [&str; N]) -> WorkOrderCommand {
        let cli = Cli::try_parse_from(args).expect("work-order command parses");
        let Commands::WorkOrder { command } = cli.command else {
            panic!("expected work-order command");
        };
        command
    }
}
