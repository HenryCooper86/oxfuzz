//! Integration test for the autonomous campaign controller
//! (`ServiceContainer::run_campaign`).

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

/// A runtime that writes files for real (so the harness source lands on disk)
/// and reports every command as a clean success with smoke activity.
struct WritingRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for WritingRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, content)
            .map_err(|e| hf_core::error::ClassifiedError::Internal(e.to_string()))
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

/// Returns a fenced C harness for every completion (used for draft/repair/refine).
struct CodeBlockPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for CodeBlockPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
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

#[tokio::test]
async fn run_campaign_runs_full_pipeline_and_picks_a_target() {
    let dir = tempfile::tempdir().unwrap();
    let workspace_root = dir.path().join("workspace");
    std::env::set_var("HF_WORKSPACE_DIR", &workspace_root);
    let project = dir.path().join("campproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("campaign.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(WritingRuntime), Some(Arc::new(CodeBlockPool)))
        .with_store(store);
    container
        .harness_generate(
            &project,
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        )
        .await
        .expect("prepare harness");
    assert!(
        workspace_root.join(".hobot-fuzz-workspace.json").is_file(),
        "the production initializer must claim the empty test workspace"
    );

    // Pre-create the compiled harness binary the runner checks for (a real
    // Docker build would produce it; the fake runtime does not). This happens
    // only after harness generation has initialized the managed root and
    // committed its ownership manifest.
    let workspace = hf_service::workspace_dir(&project, "parse_entry");
    std::fs::write(workspace.join("fuzz_parse_entry"), b"#!/bin/true").unwrap();
    container
        .harness_smoke(
            &project,
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("smoke harness");
    container
        .harness_promote(&project, "parse_entry", EngineKind::LibFuzzer)
        .await
        .expect("operator promotes harness");
    let outcome = container
        .run_campaign(
            &project,
            None, // auto-pick the top-ranked target
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1, // duration secs (fake runtime returns instantly)
            1, // max repairs
            2, // max iterations
        )
        .await
        .expect("campaign should complete");

    assert_eq!(outcome.target, "parse_entry", "should auto-pick the target");
    assert_eq!(
        outcome.harness_status,
        hf_core::harness::HarnessStatus::Promoted
    );
    assert!(outcome.iterations >= 1, "should run at least one iteration");
    // Clean fake runtime => no crashes.
    assert_eq!(outcome.crashes, 0);
}
