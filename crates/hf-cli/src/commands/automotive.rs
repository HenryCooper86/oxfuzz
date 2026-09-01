use hf_service::ServiceContainer;
use std::path::PathBuf;

use crate::args::AutomotiveOp;
use crate::parse::parse_u32_list;

#[cfg(feature = "automotive-scapy")]
fn parse_automotive_protocol(
    value: &str,
) -> anyhow::Result<hf_service::automotive::AutomotiveProtocol> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| anyhow::anyhow!("invalid automotive protocol '{value}': {error}"))
}

#[cfg(feature = "automotive-scapy")]
fn parse_automotive_mode(value: &str) -> anyhow::Result<hf_service::automotive::AutomotiveMode> {
    let mode = serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| anyhow::anyhow!("invalid automotive mode '{value}': {error}"))?;
    if mode == hf_service::automotive::AutomotiveMode::OfflinePcap {
        anyhow::bail!("replay plans must target virtual_can or physical_bench");
    }
    Ok(mode)
}

#[cfg(feature = "automotive-scapy")]
fn parse_virtual_replay_plan(encoded: &str) -> anyhow::Result<hf_service::automotive::ReplayPlan> {
    let plan: hf_service::automotive::ReplayPlan = serde_json::from_str(encoded)
        .map_err(|error| anyhow::anyhow!("invalid automotive replay plan: {error}"))?;
    if plan.mode != hf_service::automotive::AutomotiveMode::VirtualCan {
        anyhow::bail!("the CLI replay command accepts only virtual_can plans");
    }
    Ok(plan)
}

/// The two protocol-state commands that read a structured request from disk.
///
/// Behind a function so the parse and dispatch stay together: both subcommands
/// shell out to service calls that are exercised end to end by hf-service's
/// promotion tests, so the CLI adds only file reading and selection.
#[cfg(feature = "automotive-scapy")]
/// Build the typed promotion request the service takes from the CLI's inputs.
///
/// Project identity, the source operation, and the artifact selector come from
/// the flags and supersede whatever the request file carries, so each of the
/// three has exactly one home on the command line.
fn automotive_promotion_request(
    project: PathBuf,
    operation: uuid::Uuid,
    request: &std::path::Path,
    input_artifact: Option<String>,
    output_artifact: Option<String>,
) -> anyhow::Result<hf_service::automotive::AutomotiveStatePromotionRequest> {
    use hf_service::automotive::{AutomotiveStateArtifactSource, AutomotiveStatePromotionRequest};

    let artifact = match (input_artifact, output_artifact) {
        (Some(artifact_id), None) => AutomotiveStateArtifactSource::Input { artifact_id },
        (None, Some(artifact_id)) => AutomotiveStateArtifactSource::Output { artifact_id },
        _ => anyhow::bail!("select exactly one of --input-artifact / --output-artifact"),
    };
    let source = std::fs::read_to_string(request).map_err(|error| {
        anyhow::anyhow!(
            "read automotive promotion request {}: {error}",
            request.display()
        )
    })?;
    let mut parsed: AutomotiveStatePromotionRequest = serde_json::from_str(&source)
        .map_err(|error| anyhow::anyhow!("invalid automotive promotion request: {error}"))?;
    parsed.project_root = project;
    parsed.source_operation_id = operation;
    parsed.artifact = artifact;
    Ok(parsed)
}

#[cfg(feature = "automotive-scapy")]
pub(crate) async fn cmd_automotive(op: AutomotiveOp) -> anyhow::Result<()> {
    use hf_service::automotive::{
        AutomotiveCommand, AutomotiveOperationRequest, AutomotiveOperationSummary,
    };

    match op {
        AutomotiveOp::Settings => {
            let settings = hf_service::config::AutomotiveConfigStore::default()
                .get()
                .map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        command @ (AutomotiveOp::Enable | AutomotiveOp::Disable) => {
            let enabled = matches!(command, AutomotiveOp::Enable);
            let store = hf_service::config::AutomotiveConfigStore::default();
            let mut settings = store.get().map_err(anyhow::Error::msg)?;
            settings.enabled = enabled;
            let settings = store.set(settings).map_err(anyhow::Error::msg)?;
            println!("{}", serde_json::to_string_pretty(&settings)?);
        }
        AutomotiveOp::Capabilities { project } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::Capabilities,
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Analyze {
            project,
            protocol,
            capture,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::AnalyzeCapture {
                        protocol: parse_automotive_protocol(&protocol)?,
                        capture_path: capture,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Import {
            capture,
            format,
            dbc,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let import = container.automotive_import_capture(&capture, &format, dbc.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&import)?);
        }
        AutomotiveOp::Diff {
            first,
            second,
            format,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let diff = container.automotive_diff_captures(&first, &second, &format)?;
            println!("{}", serde_json::to_string_pretty(&diff)?);
        }
        AutomotiveOp::Monitor {
            project,
            interface,
            protocol,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::LiveMonitor {
                        mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                        protocol: parse_automotive_protocol(&protocol)?,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Scan {
            project,
            interface,
            request_ids,
            services,
        } => {
            let request_ids = parse_u32_list(&request_ids)?;
            let services = parse_u32_list(&services)?
                .into_iter()
                .map(|value| {
                    u8::try_from(value)
                        .map_err(|_| anyhow::anyhow!("service id out of range: {value}"))
                })
                .collect::<anyhow::Result<Vec<u8>>>()?;
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::ScanUds {
                        mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                        protocol: parse_automotive_protocol("uds")?,
                        request_ids,
                        services,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Mutate {
            project,
            protocol,
            source,
            count,
            seed,
            media_type,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::GenerateMutations {
                        protocol: parse_automotive_protocol(&protocol)?,
                        source_path: source,
                        deterministic_seed: seed,
                        mutation_count: count,
                        media_type,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Plan {
            project,
            protocol,
            source,
            mode,
            seed,
        } => {
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::BuildReplayPlan {
                        protocol: parse_automotive_protocol(&protocol)?,
                        source_path: source,
                        target_mode: parse_automotive_mode(&mode)?,
                        deterministic_seed: seed,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Replay {
            project,
            plan,
            interface,
        } => {
            let encoded = std::fs::read_to_string(&plan).map_err(|error| {
                anyhow::anyhow!("read automotive replay plan {}: {error}", plan.display())
            })?;
            let plan = parse_virtual_replay_plan(&encoded)?;
            let container = ServiceContainer::bootstrap().await;
            let outcome = container
                .execute_automotive(AutomotiveOperationRequest {
                    project_root: project,
                    command: AutomotiveCommand::ExecuteReplay {
                        mode: hf_service::automotive::ModeConfig::VirtualCan { interface },
                        plan,
                    },
                    approval: None,
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        AutomotiveOp::Operations { project, limit } => {
            let container = ServiceContainer::bootstrap().await;
            let operations: Vec<AutomotiveOperationSummary> = container
                .list_automotive_operations(&project, limit)
                .await?;
            println!("{}", serde_json::to_string_pretty(&operations)?);
        }
        AutomotiveOp::Operation { project, id } => {
            use hf_service::automotive::AutomotiveOperationSummary;
            let container = ServiceContainer::bootstrap().await;
            let operation: AutomotiveOperationSummary =
                container
                    .automotive_operation(id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("no retained automotive operation {id}"))?;
            if std::path::Path::new(&operation.project_root) != project.canonicalize()?.as_path() {
                anyhow::bail!("retained automotive operation {id} belongs to another project");
            }
            println!("{}", serde_json::to_string_pretty(&operation)?);
        }
        AutomotiveOp::StateCorpus { project, limit } => {
            let container = ServiceContainer::bootstrap().await;
            let entries = container
                .list_automotive_state_corpus(&project, limit)
                .await?;
            println!("{}", serde_json::to_string_pretty(&entries)?);
        }
        AutomotiveOp::PromoteState {
            project,
            operation,
            request,
            input_artifact,
            output_artifact,
        } => {
            let promotion = automotive_promotion_request(
                project,
                operation,
                &request,
                input_artifact,
                output_artifact,
            )?;
            let container = ServiceContainer::bootstrap().await;
            let entry = container
                .promote_automotive_state_artifact(promotion)
                .await?;
            println!("{}", serde_json::to_string_pretty(&entry)?);
        }
        AutomotiveOp::Report {
            project,
            ai,
            format,
            output,
            report_lang,
        } => {
            run_automotive_report_command(
                &project,
                ai,
                &format,
                output.as_deref(),
                &report_lang,
                &mut std::io::stdout(),
                ServiceContainer::bootstrap,
            )
            .await?;
        }
    }
    Ok(())
}

/// The two service calls `oxfuzz automotive report` makes. Behind a trait so a
/// test can observe the language the command hands over and the title it
/// exports under, without bootstrapping a real container.
#[cfg(feature = "automotive-scapy")]
#[async_trait::async_trait]
trait AutomotiveReportCommandService {
    async fn compose_automotive_report(
        &self,
        project: &std::path::Path,
        include_ai: bool,
        language: hf_service::ReportLanguage,
    ) -> Result<hf_service::automotive_report::AutomotiveCampaignReport, hf_service::ClassifiedError>;

    fn export_automotive_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &std::path::Path,
        language: hf_service::ReportLanguage,
    ) -> Result<(), hf_service::ClassifiedError>;
}

#[cfg(feature = "automotive-scapy")]
#[async_trait::async_trait]
impl AutomotiveReportCommandService for ServiceContainer {
    async fn compose_automotive_report(
        &self,
        project: &std::path::Path,
        include_ai: bool,
        language: hf_service::ReportLanguage,
    ) -> Result<hf_service::automotive_report::AutomotiveCampaignReport, hf_service::ClassifiedError>
    {
        self.generate_automotive_report(project, include_ai, language)
            .await
    }

    fn export_automotive_markdown(
        &self,
        markdown: &str,
        title: &str,
        format: &str,
        out_path: &std::path::Path,
        language: hf_service::ReportLanguage,
    ) -> Result<(), hf_service::ClassifiedError> {
        self.export_markdown(markdown, title, format, out_path, language)
    }
}

/// Parse the language, build the service, compose, then emit. `bootstrap` is
/// injected for the same reason `run_report_command` injects it: the whole path
/// -- flag string in, `ReportLanguage` at the service boundary, document out --
/// becomes one testable unit. `sink` is the emission target for the same
/// reason: without it neither the printed Markdown nor the printed export path
/// is observable, so deleting either changes nothing a test can see.
#[cfg(feature = "automotive-scapy")]
async fn run_automotive_report_command<S, Bootstrap, BootstrapFuture>(
    project: &std::path::Path,
    include_ai: bool,
    format: &str,
    output: Option<&std::path::Path>,
    lang: &str,
    sink: &mut dyn std::io::Write,
    bootstrap: Bootstrap,
) -> anyhow::Result<()>
where
    S: AutomotiveReportCommandService + Sync,
    Bootstrap: FnOnce() -> BootstrapFuture,
    BootstrapFuture: std::future::Future<Output = S>,
{
    // An unknown identifier is rejected here, before any composition work.
    let language = lang.parse::<hf_service::ReportLanguage>()?;
    let service = bootstrap().await;
    let report = service
        .compose_automotive_report(project, include_ai, language)
        .await?;
    if let Some(output) = output {
        // The exported document's title is metadata rather than report body
        // content, so the renderer never writes it -- but it is still prose, and
        // is assembled from the same label set the body was rendered from
        // instead of from a second literal that only one language could satisfy.
        let labels = hf_service::automotive_report::AutomotiveLabels::for_language(language);
        let title = format!(
            "{}{}{}",
            labels.title_prefix, labels.label_colon, report.project_name
        );
        // The report was composed here, so its language is known and the
        // exported document declares it rather than the global English default.
        service.export_automotive_markdown(&report.markdown, &title, format, output, language)?;
        writeln!(sink, "{}", output.display())?;
    } else {
        if !matches!(format, "md" | "markdown") {
            anyhow::bail!("--format requires --output for automotive reports");
        }
        writeln!(sink, "{}", report.markdown)?;
    }
    Ok(())
}

#[cfg(all(test, feature = "automotive-scapy"))]
mod automotive_tests {
    use clap::Parser as _;

    use super::parse_virtual_replay_plan;
    use crate::args::{AutomotiveOp, Cli, Commands};

    fn plan(mode: &str) -> String {
        format!(
            r#"{{"protocol":"uds","mode":"{mode}","deterministic_seed":7,"steps":[{{"sequence":0,"delay_micros":0,"action":"send","message":{{"protocol":"uds","payload_hex":"221234","fields":{{"arbitration_id":"0x7e0","service":"0x22"}}}}}}]}}"#
        )
    }

    #[test]
    fn cli_replay_accepts_only_typed_virtual_can_plans() {
        let parsed = parse_virtual_replay_plan(&plan("virtual_can")).unwrap();
        assert_eq!(parsed.steps.len(), 1);

        let error = parse_virtual_replay_plan(&plan("physical_bench")).unwrap_err();
        assert!(error.to_string().contains("virtual_can"));

        assert!(parse_virtual_replay_plan("{not-json").is_err());
    }

    fn promotion_request_json() -> String {
        // Shape only: the parser validates the request the same way it
        // validates a replay plan file.
        r#"{
            "project_root": "/tmp/project",
            "source_operation_id": "00000000-0000-4000-8000-000000000001",
            "state_signature": {
                "protocol": "uds",
                "digest": "660296f1a2b63c7e341b0c23e414cc8c38e712ee0614f1fabc08870562b706fe",
                "observations": {"session": "extended"}
            },
            "artifact": {"location": "output", "artifact_id": "canonical-transcript.json"}
        }"#
        .to_owned()
    }

    #[test]
    fn cli_promote_state_parses_a_typed_request_from_a_file() {
        let directory = tempfile::tempdir().unwrap();
        let signature = directory.path().join("signature.json");
        std::fs::write(&signature, promotion_request_json()).unwrap();

        let cli = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "promote-state",
            "/tmp/project",
            "--operation",
            "00000000-0000-4000-8000-000000000001",
            "--request",
            signature.to_str().unwrap(),
            "--output-artifact",
            "canonical-transcript.json",
        ])
        .unwrap();

        let Commands::Automotive {
            op:
                AutomotiveOp::PromoteState {
                    project,
                    operation,
                    request,
                    output_artifact,
                    input_artifact,
                },
        } = cli.command
        else {
            panic!("expected the automotive promote-state command");
        };
        assert_eq!(project, std::path::PathBuf::from("/tmp/project"));
        assert_eq!(
            operation,
            uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()
        );
        assert_eq!(request, signature);
        assert_eq!(
            output_artifact.as_deref(),
            Some("canonical-transcript.json")
        );
        assert_eq!(input_artifact, None);

        let promotion = super::automotive_promotion_request(
            project,
            operation,
            &request,
            input_artifact,
            output_artifact,
        )
        .expect("a well-formed request file builds a promotion");
        assert_eq!(
            promotion.project_root,
            std::path::PathBuf::from("/tmp/project")
        );
        assert_eq!(
            promotion.source_operation_id,
            uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()
        );
        assert_eq!(
            promotion.artifact,
            hf_service::automotive::AutomotiveStateArtifactSource::Output {
                artifact_id: "canonical-transcript.json".to_owned()
            }
        );
    }

    #[test]
    fn cli_promote_state_reports_an_unreadable_or_malformed_request_file() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("absent.json");
        let error = super::automotive_promotion_request(
            std::path::PathBuf::from("/tmp/project"),
            uuid::Uuid::nil(),
            &missing,
            None,
            Some("canonical-transcript.json".to_owned()),
        )
        .expect_err("an absent request file is an error");
        assert!(
            error
                .to_string()
                .contains("read automotive promotion request"),
            "unexpected error: {error}"
        );

        let broken = directory.path().join("broken.json");
        std::fs::write(&broken, "{not-json").unwrap();
        let error = super::automotive_promotion_request(
            std::path::PathBuf::from("/tmp/project"),
            uuid::Uuid::nil(),
            &broken,
            None,
            Some("canonical-transcript.json".to_owned()),
        )
        .expect_err("malformed JSON is an error");
        assert!(
            error
                .to_string()
                .contains("invalid automotive promotion request"),
            "unexpected error: {error}"
        );

        let error = super::automotive_promotion_request(
            std::path::PathBuf::from("/tmp/project"),
            uuid::Uuid::nil(),
            &broken,
            None,
            None,
        )
        .expect_err("neither artifact selector is an error");
        assert!(
            error.to_string().contains("exactly one of"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn cli_promote_state_rejects_two_artifact_selectors_at_once() {
        let parsed = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "promote-state",
            "/tmp/project",
            "--operation",
            "00000000-0000-4000-8000-000000000001",
            "--request",
            "does-not-exist.json",
            "--input-artifact",
            "capture.pcap",
            "--output-artifact",
            "canonical-transcript.json",
        ]);
        assert!(parsed.is_err(), "input and output are mutually exclusive");
    }

    #[test]
    fn cli_lists_the_state_corpus_and_reads_one_operation() {
        let list = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "state-corpus",
            "/tmp/project",
            "--limit",
            "25",
        ])
        .unwrap();
        let Commands::Automotive {
            op: AutomotiveOp::StateCorpus { project, limit },
        } = list.command
        else {
            panic!("expected the automotive state-corpus command");
        };
        assert_eq!(project, std::path::PathBuf::from("/tmp/project"));
        assert_eq!(limit, 25);

        let one = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "operation",
            "/tmp/project",
            "--id",
            "00000000-0000-4000-8000-000000000001",
        ])
        .unwrap();
        let Commands::Automotive {
            op: AutomotiveOp::Operation { project, id },
        } = one.command
        else {
            panic!("expected the automotive operation command");
        };
        assert_eq!(project, std::path::PathBuf::from("/tmp/project"));
        assert_eq!(
            id,
            uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap()
        );
    }

    #[test]
    fn cli_exposes_ai_assisted_automotive_report_export() {
        let cli = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "report",
            "/tmp/project",
            "--ai",
            "--format",
            "html",
            "--output",
            "/tmp/automotive-report.html",
        ])
        .unwrap();

        let Commands::Automotive {
            op:
                AutomotiveOp::Report {
                    project,
                    ai,
                    format,
                    output,
                    report_lang,
                },
        } = cli.command
        else {
            panic!("expected the automotive report command");
        };
        assert_eq!(project, std::path::PathBuf::from("/tmp/project"));
        assert!(ai);
        assert_eq!(format, "html");
        assert_eq!(
            output,
            Some(std::path::PathBuf::from("/tmp/automotive-report.html"))
        );
        // Omitting the flag composes in English, so an existing invocation is
        // unaffected.
        assert_eq!(report_lang, "en");
    }

    #[test]
    fn the_automotive_report_language_flag_does_not_collide_with_the_source_language() {
        // `--lang` already means the target's *source* language on `discover`
        // and `harness`. The report language is a separate axis and takes its
        // own name, matching `oxfuzz report`.
        let cli = Cli::try_parse_from([
            "oxfuzz",
            "automotive",
            "report",
            "/tmp/project",
            "--report-lang",
            "zh",
        ])
        .unwrap();

        let Commands::Automotive {
            op: AutomotiveOp::Report { report_lang, .. },
        } = cli.command
        else {
            panic!("expected the automotive report command");
        };
        assert_eq!(
            report_lang.parse::<hf_service::ReportLanguage>().unwrap(),
            hf_service::ReportLanguage::Zh
        );

        assert!(
            Cli::try_parse_from([
                "oxfuzz",
                "automotive",
                "report",
                "/tmp/project",
                "--lang",
                "zh"
            ])
            .is_err(),
            "--lang must not silently be accepted as the report language"
        );
    }
}

#[cfg(all(test, feature = "automotive-scapy"))]
mod automotive_report_cli_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use hf_service::automotive_report::{AutomotiveCampaignReport, AutomotiveReportAiStatus};

    use super::{run_automotive_report_command, AutomotiveReportCommandService};

    /// Everything the command handed to the service, so each argument it
    /// forwards can be asserted on its own.
    #[derive(Clone, Debug, Default)]
    struct Handoff {
        language: Option<hf_service::ReportLanguage>,
        include_ai: Option<bool>,
        exported_title: Option<String>,
        exported_format: Option<String>,
        exported_language: Option<hf_service::ReportLanguage>,
    }

    /// Records what the command handed to the service.
    #[derive(Default)]
    struct RecordingAutomotiveReportService {
        handoff: Arc<Mutex<Handoff>>,
    }

    #[async_trait::async_trait]
    impl AutomotiveReportCommandService for RecordingAutomotiveReportService {
        async fn compose_automotive_report(
            &self,
            _project: &std::path::Path,
            include_ai: bool,
            language: hf_service::ReportLanguage,
        ) -> Result<AutomotiveCampaignReport, hf_service::ClassifiedError> {
            {
                let mut handoff = self.handoff.lock().unwrap();
                handoff.language = Some(language);
                handoff.include_ai = Some(include_ai);
            }
            Ok(AutomotiveCampaignReport {
                generated_at: "2026-07-16T09:00:00Z".to_owned(),
                project_name: "vehicle-gateway".to_owned(),
                ai_status: AutomotiveReportAiStatus::NotRequested,
                ai_model: None,
                operation_count: 0,
                failed_operation_count: 0,
                unique_state_count: 0,
                promoted_state_count: 0,
                markdown: format!("# composed as {language:?}\n"),
            })
        }

        fn export_automotive_markdown(
            &self,
            _markdown: &str,
            title: &str,
            format: &str,
            _out_path: &std::path::Path,
            language: hf_service::ReportLanguage,
        ) -> Result<(), hf_service::ClassifiedError> {
            let mut handoff = self.handoff.lock().unwrap();
            handoff.exported_title = Some(title.to_owned());
            handoff.exported_format = Some(format.to_owned());
            handoff.exported_language = Some(language);
            Ok(())
        }
    }

    /// Drive the command and return what the service saw alongside everything
    /// written to the command's emission sink.
    async fn drive(
        include_ai: bool,
        format: &str,
        output: Option<&std::path::Path>,
        flag: &str,
    ) -> anyhow::Result<(Handoff, String)> {
        let service = RecordingAutomotiveReportService::default();
        let handoff = Arc::clone(&service.handoff);
        let mut sink = Vec::new();

        run_automotive_report_command(
            std::path::Path::new("/tmp/project"),
            include_ai,
            format,
            output,
            flag,
            &mut sink,
            move || std::future::ready(service),
        )
        .await?;

        let recorded = handoff.lock().unwrap().clone();
        Ok((recorded, String::from_utf8(sink).unwrap()))
    }

    /// Drive the export path and report the language the service saw together
    /// with the title the document was exported under.
    async fn export_under(flag: &str) -> (hf_service::ReportLanguage, String) {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("report.html");
        let (handoff, emitted) = drive(false, "html", Some(&out), flag).await.unwrap();

        // The export path reports where it wrote. Deleting that line would
        // otherwise be invisible.
        assert_eq!(emitted, format!("{}\n", out.display()));
        (
            handoff.language.unwrap(),
            handoff.exported_title.clone().unwrap(),
        )
    }

    #[tokio::test]
    async fn the_report_language_flag_reaches_the_service() {
        // The hand-off, not the parse: `--report-lang zh` must arrive at
        // generate_automotive_report rather than being parsed and discarded.
        assert_eq!(export_under("zh").await.0, hf_service::ReportLanguage::Zh);
        assert_eq!(export_under("en").await.0, hf_service::ReportLanguage::En);
    }

    #[tokio::test]
    async fn the_exported_document_title_follows_the_report_language() {
        // The title is document metadata the renderer never writes, so it is
        // the one piece of prose on this path that a second English literal
        // could leave behind on a Chinese report.
        assert_eq!(
            export_under("zh").await.1,
            "汽车协议模糊测试活动报告：vehicle-gateway"
        );
        // Byte-identical to the literal it replaced: the English export does
        // not move.
        assert_eq!(
            export_under("en").await.1,
            "Automotive Fuzzing Campaign Report: vehicle-gateway"
        );
    }

    #[tokio::test]
    async fn the_exported_document_declares_the_report_language() {
        // The title being Chinese does not make the document Chinese. The
        // `lang` attribute assistive technology reads comes from this argument,
        // and until it was threaded a Chinese report was served as English.
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("report.html");

        let (chinese, _) = drive(false, "html", Some(&out), "zh").await.unwrap();
        assert_eq!(
            chinese.exported_language,
            Some(hf_service::ReportLanguage::Zh)
        );
        // And the format reaches the export unchanged, so the assertion above
        // cannot be satisfied by an export that ignored its arguments.
        assert_eq!(chinese.exported_format.as_deref(), Some("html"));

        let (english, _) = drive(false, "html", Some(&out), "en").await.unwrap();
        assert_eq!(
            english.exported_language,
            Some(hf_service::ReportLanguage::En)
        );
    }

    #[tokio::test]
    async fn the_ai_flag_reaches_the_service() {
        // `--ai` is the difference between a deterministic fact sheet and one
        // carrying a provider interpretation. Silently ignoring it would have
        // passed every other test here.
        assert_eq!(
            drive(true, "md", None, "en").await.unwrap().0.include_ai,
            Some(true)
        );
        assert_eq!(
            drive(false, "md", None, "en").await.unwrap().0.include_ai,
            Some(false)
        );
    }

    #[tokio::test]
    async fn the_stdout_path_emits_the_composed_markdown() {
        let (handoff, emitted) = drive(false, "md", None, "zh").await.unwrap();
        assert_eq!(handoff.language, Some(hf_service::ReportLanguage::Zh));
        assert_eq!(emitted, "# composed as Zh\n\n");
        // Nothing was exported: the stdout path must not write a file.
        assert_eq!(handoff.exported_title, None);
    }

    #[tokio::test]
    async fn a_non_markdown_format_without_an_output_path_is_rejected() {
        // A user-facing error: `--format html` alone silently printing Markdown
        // would be worse than refusing.
        for format in ["html", "pdf", "docx"] {
            let error = drive(false, format, None, "en").await.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("--format requires --output for automotive reports"),
                "{format}: {error}"
            );
        }
        // And the two formats that mean Markdown are accepted.
        for format in ["md", "markdown"] {
            assert!(drive(false, format, None, "en").await.is_ok(), "{format}");
        }
    }

    #[tokio::test]
    async fn an_unknown_report_language_is_rejected_before_any_bootstrap() {
        let bootstrapped = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&bootstrapped);
        let mut sink = Vec::new();

        let error = run_automotive_report_command(
            std::path::Path::new("/tmp/project"),
            false,
            "md",
            None,
            "fr",
            &mut sink,
            move || {
                called.store(true, Ordering::SeqCst);
                std::future::ready(RecordingAutomotiveReportService::default())
            },
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("'en' and 'zh'"), "{error}");
        assert!(
            !bootstrapped.load(Ordering::SeqCst),
            "a rejected language must not bootstrap the service"
        );
    }
}
