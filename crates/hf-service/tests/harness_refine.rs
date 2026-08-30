//! Integration test for coverage-guided harness refinement
//! (`ServiceContainer::harness_refine`).

mod common;

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_refine_it");
}

/// A runtime whose commands all succeed (exit 0). Coverage collection returns
/// empty (so all reachable functions count as uncovered), and the refined
/// harness compiles cleanly.
struct OkRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for OkRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }
    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

/// Returns an improved harness (fenced code block) for any completion.
struct RefinePool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for RefinePool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Ok(hf_test_utils::fixtures::make_chat_response(
            "```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ if(n>0) parse_entry(d,n); return 0; }\n```",
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
async fn harness_refine_recompiles_from_existing_harness() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("refproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();
    let target = "parse_entry";

    // Pre-existing harness in the workspace (refine requires one).
    let workspace = hf_service::workspace_dir(&project, target);
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(
        workspace.join("harness.c"),
        "int LLVMFuzzerTestOneInput(const uint8_t*d,size_t n){return 0;}",
    )
    .unwrap();

    let container = ServiceContainer::new(Arc::new(OkRuntime), Some(Arc::new(RefinePool)));
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        container.harness_refine(
            &project,
            target,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        ),
    )
    .await
    .expect("refinement must not recursively acquire its workspace lease")
    .expect("refine should produce a compiled harness");
    assert_eq!(outcome.status, hf_core::harness::HarnessStatus::Compiled);
}

#[tokio::test]
async fn harness_refine_errors_without_existing_harness() {
    isolate_workspace();
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("refproj_missing");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0; }\n",
    )
    .unwrap();

    let container = ServiceContainer::new(Arc::new(OkRuntime), Some(Arc::new(RefinePool)));
    let err = container
        .harness_refine(
            &project,
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        )
        .await;
    assert!(
        err.is_err(),
        "refine without an existing harness should error"
    );
}
