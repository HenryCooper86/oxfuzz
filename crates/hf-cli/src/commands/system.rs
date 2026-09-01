use hf_service::scheduler::{CampaignScheduler, CampaignSchedulerError};
use hf_service::{ServiceContainer, SessionId};
use std::path::PathBuf;

use crate::args::{KnowledgeOp, PolicyOp, ProvidersOp, ScheduleOp, ScheduleRecoveryOp, SessionOp};
use crate::parse::parse_duration;

fn doctor_lines(status: &hf_service::SystemStatus) -> Vec<String> {
    let required =
        |ready: bool, label: &str| format!("{}  {label}", if ready { "READY" } else { "MISSING" });
    let engine = |ready: bool, label: &str| {
        format!("{}  {label}", if ready { "READY" } else { "UNAVAILABLE" })
    };

    vec![
        required(status.docker.is_ready(), "Docker daemon"),
        required(status.sandbox_image.is_ready(), "sandbox image"),
        engine(status.libfuzzer.is_ready(), "libFuzzer"),
        engine(status.aflplusplus.is_ready(), "AFL++"),
        engine(status.honggfuzz.is_ready(), "honggfuzz"),
        engine(status.syzkaller.is_ready(), "syzkaller"),
        format!(
            "{}  DefectDojo",
            if status.defectdojo.is_ready() {
                "READY"
            } else {
                "OPTIONAL"
            }
        ),
    ]
}

/// One line per provider: readiness state, id, cumulative request/error
/// counts, and the freeze reason when frozen (mirrors `doctor_lines`).
fn provider_status_lines(statuses: &[hf_service::ProviderStatus]) -> Vec<String> {
    statuses
        .iter()
        .map(|s| {
            let state = if s.is_frozen { "FROZEN" } else { "READY" };
            let reason = s
                .freeze_reason
                .as_ref()
                .map_or(String::new(), |r| format!("  (reason: {r})"));
            format!(
                "{state}  {}  requests={} errors={}{reason}",
                s.id.0, s.total_requests, s.total_errors
            )
        })
        .collect()
}

/// Arm, disarm, or report the arming state of a running server.
///
/// Thin by design: the decision and its consequences live in the scheduler;
/// this only carries the operator's answer to it over the same HTTP surface
/// the GUI uses.
pub(crate) async fn cmd_arm(url: &str, off: bool, status: bool) -> anyhow::Result<()> {
    let endpoint = format!("{}/schedule/arm", url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let request = if status {
        client.get(&endpoint)
    } else if off {
        client.delete(&endpoint)
    } else {
        client.post(&endpoint)
    };
    // Non-loopback binds require a token; send it when one is configured so the
    // command works against the same server the operator started.
    let request = match std::env::var("HF_WEB_TOKEN") {
        Ok(token) if !token.is_empty() => request.bearer_auth(token),
        _ => request,
    };

    let response = request
        .send()
        .await
        .map_err(|error| anyhow::anyhow!("could not reach {endpoint}: {error}"))?;
    if !response.status().is_success() {
        anyhow::bail!("{endpoint} returned {}", response.status());
    }
    let body: serde_json::Value = response.json().await?;
    let armed = body.get("armed").and_then(serde_json::Value::as_bool);

    match armed {
        Some(true) => println!("armed: restored work may run"),
        Some(false) if status || off => println!("disarmed: restored work is held"),
        Some(false) => {
            println!("disarmed: the server reports no scheduler, so there is nothing to arm");
        }
        None => println!("{body}"),
    }
    Ok(())
}

pub(crate) async fn cmd_doctor(json: bool) -> anyhow::Result<()> {
    let status = hf_service::system_status().await;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("oxfuzz sandbox readiness");
        for line in doctor_lines(&status) {
            println!("{line}");
        }

        #[cfg(feature = "concolic-enrichment")]
        {
            use hf_service::ConcolicAvailability;
            let container = ServiceContainer::bootstrap().await;
            // The service returns a typed reason code; the CLI renders it and
            // does not assert a cause it cannot know (an absent SymCC layer is
            // only one of the ways the probe comes back unavailable).
            let line = match container.concolic_availability().await {
                ConcolicAvailability::Available => "concolic enrichment: available".to_owned(),
                ConcolicAvailability::Unavailable { reason } => {
                    format!("concolic enrichment: unavailable ({reason})")
                }
            };
            println!("{line}");
        }
    }

    if !status.fuzzing_ready() {
        anyhow::bail!(
            "fuzzing is not ready: start Docker, build the sandbox image, and verify at least one engine"
        );
    }
    Ok(())
}

pub(crate) async fn cmd_export(project: Option<PathBuf>, output: PathBuf) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    let bundle = container.export_project_data(project.as_deref()).await?;
    let json = serde_json::to_string_pretty(&bundle)?;
    std::fs::write(&output, json)?;
    println!("Exported evidence bundle to {}", output.display());
    Ok(())
}

/// An [`EventSink`](hf_service::EventSink) that renders agent progress to stderr,
/// keeping stdout reserved for the final answer (so it can be piped).
struct CliEventSink;

#[async_trait::async_trait]
impl hf_service::EventSink for CliEventSink {
    async fn emit(&self, event: hf_service::AgentEvent) {
        match event {
            hf_service::AgentEvent::Thinking { text } => eprintln!("[thinking] {text}"),
            hf_service::AgentEvent::ToolCall { name, args } => {
                eprintln!("[tool] {name} {args}");
            }
            hf_service::AgentEvent::ToolResult { name, summary } => {
                eprintln!("[result] {name}: {summary}");
            }
            hf_service::AgentEvent::Error { message } => eprintln!("[error] {message}"),
            hf_service::AgentEvent::Started | hf_service::AgentEvent::Complete { .. } => {}
        }
    }
}

pub(crate) async fn cmd_agent(
    message: &str,
    project: Option<PathBuf>,
    agent: Option<&str>,
) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    if container.provider_pool().is_none() {
        anyhow::bail!("agent requires an LLM provider; set HF_PROVIDER_API_KEY");
    }
    let sink = CliEventSink;
    let answer = container
        .run_chat_turn(
            hf_service::AgentTurnRequest {
                project,
                agent_id: agent.map(str::to_owned),
                session: None,
                history_fallback: Vec::new(),
                message: message.to_owned(),
                display_message: None,
            },
            &sink,
        )
        .await?;
    println!("{answer}");
    Ok(())
}

pub(crate) fn cmd_knowledge(op: KnowledgeOp) -> anyhow::Result<()> {
    match op {
        KnowledgeOp::Index { project } => {
            let stats = hf_service::knowledge::index_project(&project)
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            println!(
                "Indexed {} file(s), {} chunk(s).",
                stats.files, stats.chunks
            );
        }
        KnowledgeOp::Search {
            project,
            query,
            limit,
        } => {
            // The BM25 index is process-local (in-memory), so a fresh CLI
            // process must build it before searching -- a `knowledge index` run
            // in a separate process left no on-disk index to reuse.
            if !hf_service::knowledge::is_indexed(&project) {
                hf_service::knowledge::index_project(&project)
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            }
            let hits = hf_service::knowledge::search_project(&project, &query, limit);
            if hits.is_empty() {
                println!("No results.");
            }
            for h in hits {
                println!("{:.3}  {}", h.score, h.file);
                println!("    {}", h.snippet.replace('\n', " "));
            }
        }
    }
    Ok(())
}

/// Start a campaign scheduler for a one-shot CLI operation. Background ticking
/// stops when the process exits; persisted schedules live under the user data
/// dir (shared with the GUI and web server).
async fn start_scheduler() -> Result<CampaignScheduler, CampaignSchedulerError> {
    let container = ServiceContainer::bootstrap().await;
    let store_path = hf_service::init::user_app_dir().join("schedules.json");
    CampaignScheduler::try_start(container, store_path, None).await
}

fn recovery_cli_error(error: CampaignSchedulerError) -> anyhow::Error {
    anyhow::Error::new(error.into_public_recovery_error())
}

pub(crate) async fn cmd_schedule(op: ScheduleOp) -> anyhow::Result<()> {
    let recovery_command = matches!(&op, ScheduleOp::Recovery { .. });
    let scheduler = match start_scheduler().await {
        Ok(scheduler) => scheduler,
        Err(error) if recovery_command => return Err(recovery_cli_error(error)),
        Err(error) => return Err(error.into()),
    };
    match op {
        ScheduleOp::List => {
            let views = scheduler.list_views().await?;
            if views.is_empty() {
                println!("No scheduled campaigns.");
            }
            for v in views {
                let target = v.target.as_deref().unwrap_or("all promoted targets");
                let budget = v
                    .max_runs
                    .map(|m| format!(" runs={}/{m}", v.runs_done))
                    .or_else(|| {
                        v.max_total_secs
                            .map(|m| format!(" secs={}/{m}", v.secs_done))
                    })
                    .unwrap_or_default();
                println!(
                    "{}  {}  [{}]  {}  target={target} engine={} {}s{budget}  last={}",
                    v.id,
                    v.name,
                    if v.enabled { "enabled" } else { "disabled" },
                    v.trigger,
                    v.engine,
                    v.duration_secs,
                    v.last_fire.unwrap_or_else(|| "never".to_owned()),
                );
            }
        }
        ScheduleOp::Recovery {
            op: ScheduleRecoveryOp::List,
        } => {
            for recovery in scheduler
                .list_one_time_recoveries()
                .await
                .map_err(recovery_cli_error)?
            {
                println!(
                    "{}  {}  {}  {}  {}",
                    recovery.occurrence_id,
                    recovery
                        .schedule_name
                        .as_deref()
                        .unwrap_or("<deleted schedule>"),
                    recovery.triggered_at,
                    recovery.state,
                    recovery
                        .recovery_detail
                        .as_deref()
                        .unwrap_or("unknown outcome"),
                );
            }
        }
        ScheduleOp::Recovery {
            op: ScheduleRecoveryOp::Acknowledge { occurrence_id },
        } => {
            let recovery = scheduler
                .acknowledge_one_time_recovery(&occurrence_id)
                .await
                .map_err(recovery_cli_error)?;
            println!(
                "{} recorded as {}. This did not terminate or adopt an orphaned sandbox process.",
                recovery.occurrence_id, recovery.state,
            );
        }
        ScheduleOp::History { limit } => {
            for e in scheduler.recent_executions(limit).await? {
                println!(
                    "{}  {}  {}  {}",
                    e.triggered_at, e.campaign, e.status, e.summary
                );
            }
        }
        ScheduleOp::Create {
            name,
            project,
            target,
            engine,
            lang,
            trigger_kind,
            trigger_value,
            duration,
            max_runs,
            max_total_secs,
        } => {
            let trigger = hf_service::scheduler::parse_trigger(&trigger_kind, &trigger_value)
                .map_err(|e| anyhow::anyhow!(e))?;
            let params = hf_service::scheduler::CampaignParams {
                // Empty target = portfolio campaign over all promoted targets.
                target: (!target.trim().is_empty()).then_some(target),
                project: project.display().to_string(),
                engine,
                lang,
                duration_secs: parse_duration(&duration)?,
                max_runs,
                max_total_secs,
                schedule_id: String::new(),
            };
            scheduler.try_create(&name, &params, trigger).await?;
            println!("Created schedule '{name}'.");
        }
        ScheduleOp::Delete { id } => {
            let msg = if scheduler.try_remove(&id).await? {
                "Deleted."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
        ScheduleOp::Enable { id } => {
            let msg = if scheduler.try_set_enabled(&id, true).await? {
                "Enabled."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
        ScheduleOp::Disable { id } => {
            let msg = if scheduler.try_set_enabled(&id, false).await? {
                "Disabled."
            } else {
                "No such schedule."
            };
            println!("{msg}");
        }
    }
    Ok(())
}

pub(crate) async fn cmd_session(op: SessionOp) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        SessionOp::New { title } => match container.create_chat_session(title).await? {
            Some(id) => println!("{id}"),
            None => {
                println!("No database configured (set HF_DB_PATH); cannot persist sessions.");
            }
        },
        SessionOp::History { id } => {
            let sid = SessionId(id);
            for m in container.chat_history(&sid).await? {
                println!("[{:?}] {}", m.role, m.content);
            }
        }
        SessionOp::Checkpoints { id } => {
            let sid = SessionId(id);
            for c in container.chat_checkpoints(&sid).await? {
                println!("{c:?}");
            }
        }
        SessionOp::Branches { id } => {
            let sid = SessionId(id);
            for b in container.chat_branches(&sid).await? {
                println!("{b:?}");
            }
        }
        SessionOp::Rollback { id } => {
            let sid = SessionId(id);
            let n = container.chat_rollback_last(&sid).await?;
            println!("Rolled back {n} message(s).");
        }
    }
    Ok(())
}

pub(crate) async fn cmd_providers(op: Option<ProvidersOp>) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        None => {
            let statuses = container.provider_statuses().await;
            if statuses.is_empty() {
                println!("No providers configured.");
            } else {
                for line in provider_status_lines(&statuses) {
                    println!("{line}");
                }
            }
        }
        Some(ProvidersOp::Thaw { id }) => {
            container.thaw_provider(&id).await?;
            println!("Provider '{id}' passed the health check and was thawed.");
        }
    }
    Ok(())
}

pub(crate) async fn cmd_policy(op: PolicyOp) -> anyhow::Result<()> {
    let container = ServiceContainer::bootstrap().await;
    match op {
        PolicyOp::Decisions { limit } => {
            let decisions = container.policy_decisions(limit).await?;
            if decisions.is_empty() {
                println!("No guardrail decisions recorded.");
            }
            for d in decisions {
                let detail = d.detail.map(|s| format!("  ({s})")).unwrap_or_default();
                println!(
                    "{}  {}  {}  {}  {}{detail}",
                    d.decided_at.to_rfc3339(),
                    d.decision,
                    d.risk_tier,
                    d.action,
                    d.origin,
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod doctor_tests {
    #[cfg(feature = "semgrep-enrichment")]
    use clap::Parser as _;
    use hf_service::system::StatusFlag;
    use hf_service::{SystemStatus, RETIRED_ENGINE_ID};

    use super::doctor_lines;
    #[cfg(feature = "semgrep-enrichment")]
    use crate::args::{Cli, Commands};
    use crate::parse::{parse_engine, parse_lang};

    #[test]
    #[cfg(feature = "semgrep-enrichment")]
    fn cli_parses_semgrep_opt_in() {
        let cli = Cli::try_parse_from([
            "oxfuzz",
            "discover",
            "/tmp/project",
            "--lang",
            "c",
            "--semgrep",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
            Commands::Discover { semgrep: true, .. }
        ));
    }

    #[test]
    fn doctor_output_distinguishes_required_and_optional_checks() {
        let status = SystemStatus {
            docker: StatusFlag::from(true),
            sandbox_image: StatusFlag::from(true),
            libfuzzer: StatusFlag::from(true),
            aflplusplus: StatusFlag::from(false),
            honggfuzz: StatusFlag::from(false),
            syzkaller: StatusFlag::from(false),
            defectdojo: StatusFlag::from(false),
        };

        let output = doctor_lines(&status).join("\n");
        assert!(output.contains("READY  Docker daemon"));
        assert!(output.contains("READY  sandbox image"));
        assert!(output.contains("READY  libFuzzer"));
        assert!(output.contains("UNAVAILABLE  AFL++"));
        assert!(output.contains("UNAVAILABLE  honggfuzz"));
        assert!(output.contains("UNAVAILABLE  syzkaller"));
        let retired_engine_label = RETIRED_ENGINE_ID;
        assert!(!output.contains(retired_engine_label));
        assert!(output.contains("OPTIONAL  DefectDojo"));
        assert!(status.fuzzing_ready());
    }

    #[test]
    fn cli_rejects_the_retired_engine_with_an_actionable_error() {
        let retired_engine_id = RETIRED_ENGINE_ID;
        let error = parse_engine(retired_engine_id).unwrap_err();
        assert!(error.to_string().contains("has been retired"));
    }

    #[test]
    fn cli_accepts_languages_with_a_production_discovery_pipeline() {
        assert!(parse_lang("c").is_ok());
        assert!(parse_lang("cpp").is_ok());
        assert!(parse_lang("rust").is_ok());
        assert!(parse_lang("go").is_ok());
        assert!(parse_lang("python").is_ok());
        assert!(parse_lang("cobol").is_err());
    }
}

#[cfg(test)]
mod providers_tests {
    use clap::Parser as _;
    use hf_service::{ProviderId, ProviderStatus};

    use super::provider_status_lines;
    use crate::args::{Cli, Commands, ProvidersOp};

    #[test]
    fn providers_command_parses_bare_list_and_thaw() {
        let cli = Cli::try_parse_from(["oxfuzz", "providers"]).unwrap();
        assert!(matches!(cli.command, Commands::Providers { op: None }));

        let cli = Cli::try_parse_from(["oxfuzz", "providers", "thaw", "openai-main"]).unwrap();
        let Commands::Providers {
            op: Some(ProvidersOp::Thaw { id }),
        } = cli.command
        else {
            panic!("expected providers thaw");
        };
        assert_eq!(id, "openai-main");
    }

    #[test]
    fn provider_status_lines_distinguish_frozen_and_healthy() {
        let statuses = vec![
            ProviderStatus {
                id: ProviderId::from_string("openai-main"),
                is_frozen: false,
                frozen_since: None,
                thaw_at: None,
                freeze_reason: None,
                active_requests: 0,
                total_requests: 12,
                total_errors: 0,
            },
            ProviderStatus {
                id: ProviderId::from_string("anthropic-main"),
                is_frozen: true,
                frozen_since: None,
                thaw_at: None,
                freeze_reason: Some("invalid api key".into()),
                active_requests: 0,
                total_requests: 3,
                total_errors: 3,
            },
        ];

        let lines = provider_status_lines(&statuses);

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("READY") && lines[0].contains("openai-main"));
        assert!(lines[0].contains("requests=12"));
        assert!(lines[1].contains("FROZEN") && lines[1].contains("anthropic-main"));
        assert!(lines[1].contains("invalid api key"));
    }
}

#[cfg(test)]
mod policy_tests {
    use clap::Parser as _;

    use crate::args::{Cli, Commands, PolicyOp};

    #[test]
    fn policy_decisions_parses_with_a_bounded_limit() {
        let cli = Cli::try_parse_from(["oxfuzz", "policy", "decisions"]).unwrap();
        let Commands::Policy {
            op: PolicyOp::Decisions { limit },
        } = cli.command
        else {
            panic!("expected policy decisions");
        };
        assert_eq!(limit, 50);

        let cli = Cli::try_parse_from(["oxfuzz", "policy", "decisions", "--limit", "5"]).unwrap();
        let Commands::Policy {
            op: PolicyOp::Decisions { limit },
        } = cli.command
        else {
            panic!("expected policy decisions");
        };
        assert_eq!(limit, 5);
    }
}

#[cfg(test)]
mod schedule_cli_tests {
    use clap::Parser as _;
    use hf_service::scheduler::CampaignSchedulerError;

    use super::recovery_cli_error;
    use crate::args::{Cli, Commands, ScheduleOp, ScheduleRecoveryOp};

    #[test]
    fn schedule_recovery_commands_parse() {
        let list = Cli::try_parse_from(["oxfuzz", "schedule", "recovery", "list"]).unwrap();
        assert!(matches!(
            list.command,
            Commands::Schedule {
                op: ScheduleOp::Recovery {
                    op: ScheduleRecoveryOp::List
                }
            }
        ));

        let acknowledge =
            Cli::try_parse_from(["oxfuzz", "schedule", "recovery", "acknowledge", "occ-123"])
                .unwrap();
        let Commands::Schedule {
            op:
                ScheduleOp::Recovery {
                    op: ScheduleRecoveryOp::Acknowledge { occurrence_id },
                },
        } = acknowledge.command
        else {
            panic!("expected recovery acknowledgement");
        };
        assert_eq!(occurrence_id, "occ-123");
    }

    #[test]
    fn cli_recovery_error_excludes_stored_json_diagnostics() {
        let public = recovery_cli_error(CampaignSchedulerError::History(
            r#"STORED_JSON_PRIVATE_MARKER: {"project":"/private/source"}"#.to_owned(),
        ))
        .to_string();

        assert_eq!(public, "one-time recovery is temporarily unavailable");
        assert!(!public.contains("STORED_JSON_PRIVATE_MARKER"));
        assert!(!public.contains("/private/source"));
    }
}
