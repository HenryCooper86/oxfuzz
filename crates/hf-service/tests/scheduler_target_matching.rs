//! A bare-symbol campaign schedule must fire a harness promoted under its
//! file-qualified selector.
//!
//! `schedulable_targets` emits the file-qualified spelling (`parse.c::parse_x`)
//! whenever the promoted harness lives under that workspace, so a schedule
//! spelled with the bare symbol would find no target under exact-string
//! matching and fail every fire with "no promoted harness" -- the exact
//! regression SVC-002 describes. This test drives the whole scheduler: create
//! the schedule with the bare symbol, let an interval trigger fire it, and
//! require a completed campaign execution against the qualified workspace.

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter, SandboxOptions,
};
use hf_core::target::TargetLanguage;
use hf_service::scheduler::{parse_trigger, CampaignParams, CampaignScheduler};
use hf_service::ServiceContainer;
use sha2::{Digest as _, Sha256};

/// A runtime that reports success for every command and writes files for real
/// (the same shape as the campaign fixtures in `scheduler_events.rs`).
struct CampaignRuntime;

#[async_trait]
impl RuntimeAdapter for CampaignRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(cmd, cwd, limits, &SandboxOptions::default())
            .await
    }

    async fn run_command_opts(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _options: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).map_err(|e| ClassifiedError::Internal(e.to_string()))
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// Returns a fenced C harness for every completion (draft/seed steps).
struct CodeBlockPool;

#[async_trait]
impl hf_core::provider::ProviderPool for CodeBlockPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if hf_test_utils::is_harness_review_request(request) {
            return Ok(hf_test_utils::approving_harness_review_response());
        }
        Ok(hf_test_utils::fixtures::make_chat_response(
            "```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return 0; }\n```",
        ))
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "unused".to_owned(),
        })
    }
    fn report_error(
        &self,
        _provider_id: &hf_core::types::ProviderId,
        _error: &hf_core::provider::ProviderError,
    ) {
    }
    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}
    async fn thaw(
        &self,
        _provider_id: &hf_core::types::ProviderId,
    ) -> Result<(), hf_core::provider::ProviderError> {
        Ok(())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    project: std::path::PathBuf,
    container: ServiceContainer,
}

/// A project whose harness is promoted under the file-qualified selector, so
/// `schedulable_targets` emits `parse.c::parse_entry` rather than the bare
/// symbol (the work-order / CLI-disambiguation spelling).
/// Pre-create the compiled harness binary the runner checks for (a real
/// build would produce it; the fake runtime does not). The name mirrors
/// `harness_binary_name`: sanitized selector stem plus a short digest of
/// the full spelling whenever the mapping changed it.
fn binary_stem(target: &str) -> String {
    let mut safe: String = target
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let changed = safe != target || safe.is_empty() || safe.len() > 64;
    if safe.is_empty() {
        safe.push_str("default");
    }
    safe.truncate(64);
    if changed {
        safe.push('-');
        safe.push_str(&format!("{:x}", Sha256::digest(target.as_bytes()))[..8]);
    }
    safe
}

async fn fixture(name: &str) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    common::install_managed_workspace("oxfuzz_scheduler_target_matching_tests");
    // Scheduled campaigns run through the env-gated approval dispatcher; this
    // test exercises target matching, not the approval gate.
    std::env::set_var("HF_AUTO_APPROVE", "1");
    let project = root.path().join(format!("{name}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("campaign.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(CampaignRuntime), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::clone(&store));

    let qualified = "parse.c::parse_entry";
    container
        .harness_generate(
            &project,
            qualified,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            None,
            false,
            false,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("qualified harness generated");
    let workspace = hf_service::workspace_dir(&project, qualified);
    std::fs::create_dir_all(workspace.join("corpus")).unwrap();
    std::fs::write(
        workspace.join(format!("fuzz_{}", binary_stem(qualified))),
        b"#!/bin/true",
    )
    .unwrap();
    container
        .harness_smoke(
            &project,
            qualified,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(&project, qualified, EngineKind::LibFuzzer)
        .await
        .expect("operator promotes harness");

    // The promotion lives under the qualified workspace, so the scheduler
    // offers exactly the qualified selector.
    let schedulable = container
        .schedulable_targets(&project)
        .await
        .expect("schedulable targets readable");
    assert_eq!(
        schedulable
            .iter()
            .map(|target| target.target.as_str())
            .collect::<Vec<_>>(),
        vec![qualified],
        "the qualified spelling is what the scheduler offers"
    );

    Fixture {
        root,
        project,
        container,
    }
}

#[tokio::test]
async fn a_bare_symbol_schedule_fires_a_qualified_promoted_harness() {
    let fixture = fixture("bare-matches-qualified").await;
    let scheduler = CampaignScheduler::try_start(
        fixture.container.clone(),
        fixture.root.path().join("schedules.json"),
        None,
    )
    .await
    .expect("scheduler starts");
    // The schedule is spelled with the bare symbol only.
    let params = CampaignParams {
        project: fixture.project.display().to_string(),
        target: Some("parse_entry".to_owned()),
        engine: "libfuzzer".to_owned(),
        lang: "c".to_owned(),
        duration_secs: 60,
        max_runs: Some(1),
        max_total_secs: None,
        schedule_id: String::new(),
    };
    let schedule = scheduler
        .try_create(
            "bare symbol",
            &params,
            parse_trigger("interval", "1").unwrap(),
        )
        .await
        .expect("schedule created");

    // Wait for one terminal execution of this schedule; before the suffix
    // match this recorded a failure ("target 'parse_entry' has no promoted
    // harness") instead of a completed campaign.
    let execution = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let executions = scheduler
                .recent_executions(10)
                .await
                .expect("execution history readable");
            if let Some(execution) = executions
                .iter()
                .find(|execution| execution.schedule_id == schedule.id)
                .filter(|execution| execution.status == "completed" || execution.status == "failed")
            {
                return execution.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("schedule fired");

    scheduler.stop().await;
    assert_eq!(
        execution.status, "completed",
        "the bare-symbol schedule must run the qualified promoted harness: {}",
        execution.summary
    );
    assert!(
        execution.summary.contains("iteration"),
        "{}",
        execution.summary
    );
}

/// The CLI campaign path (`oxfuzz campaign --target parse_entry`) admits a
/// harness promoted under the file-qualified selector. Before the admission
/// lookup resolved the spelling the same way a direct run does, the bare
/// symbol failed with "no active harness source for `parse_entry`" even
/// though the qualified workspace held a promoted harness.
#[tokio::test]
async fn a_bare_symbol_campaign_admission_finds_the_qualified_harness() {
    let fixture = fixture("bare-admission").await;
    let outcome = fixture
        .container
        .run_campaign(
            fixture.project.as_path(),
            Some("parse_entry"),
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
            None,
            None,
            None,
            None,
            None,
            1,
        )
        .await
        .expect("the bare-symbol campaign must admit the qualified promoted harness");
    assert_eq!(outcome.iterations, 1, "{outcome:?}");
    assert_eq!(
        outcome.target, "parse.c::parse_entry",
        "the campaign reports the qualified spelling it actually ran"
    );
}
