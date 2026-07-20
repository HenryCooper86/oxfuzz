//! Regression tests for release-critical identity and persistence contracts.

mod common;

use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, ProviderError, ProviderPool, ProviderStatus,
    RouteRequest,
};
use hf_core::target::TargetLanguage;
use hf_core::types::ProviderId;
use hf_service::ServiceContainer;

struct SuccessfulRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for SuccessfulRuntime {
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
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content)
            .map_err(|error| hf_core::error::ClassifiedError::Internal(error.to_string()))
    }

    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        std::fs::read_to_string(path)
            .map_err(|error| hf_core::error::ClassifiedError::Internal(error.to_string()))
    }
}

struct EmptyRankingPool;

#[async_trait::async_trait]
impl ProviderPool for EmptyRankingPool {
    async fn chat_completion(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        Ok(hf_test_utils::fixtures::make_chat_response("[]"))
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "streaming is not used by ranking".to_owned(),
        })
    }

    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn sample_project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "#include <stddef.h>\nint parse_release(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    project
}

async fn store_in(project: &tempfile::TempDir) -> Arc<hf_storage::Store> {
    Arc::new(
        hf_storage::Store::connect(project.path().join("release-readiness.db"))
            .await
            .unwrap(),
    )
}

#[tokio::test]
async fn discovery_propagates_a_configured_store_write_failure() {
    let project = sample_project();
    let store = store_in(&project).await;
    sqlx::query("DROP TABLE targets")
        .execute(store.pool())
        .await
        .unwrap();
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);

    let error = service
        .discover(project.path(), TargetLanguage::C)
        .await
        .expect_err("a configured broken store must not look like disabled persistence");
    assert!(matches!(error, hf_core::error::ClassifiedError::Storage(_)));
}

#[tokio::test]
async fn ranking_propagates_a_configured_store_write_failure() {
    let project = sample_project();
    let inventory = hf_discovery::discover(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    let store = store_in(&project).await;
    sqlx::query("DROP TABLE targets")
        .execute(store.pool())
        .await
        .unwrap();
    let service = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(EmptyRankingPool)),
    )
    .with_store(store);

    let error = service
        .rank(inventory)
        .await
        .expect_err("ranked evidence must be durable before success is returned");
    assert!(matches!(error, hf_core::error::ClassifiedError::Storage(_)));
}

#[tokio::test]
async fn harness_compile_rejects_an_unknown_target_before_runtime_execution() {
    common::install_managed_workspace("oxfuzz_release_identity_it");
    let project = sample_project();
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let error = service
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "misspelled_target",
            TargetLanguage::C,
        )
        .await
        .expect_err("unknown targets must not be assigned the nil UUID");
    assert!(
        error
            .to_string()
            .contains("target 'misspelled_target' not found"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn harness_compile_does_not_activate_metadata_that_failed_to_persist() {
    common::install_managed_workspace("oxfuzz_release_harness_it");
    let project = sample_project();
    let store = store_in(&project).await;
    sqlx::query("DROP TABLE harnesses")
        .execute(store.pool())
        .await
        .unwrap();
    let service = ServiceContainer::new(Arc::new(SuccessfulRuntime), None).with_store(store);

    let error = service
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_release",
            TargetLanguage::C,
        )
        .await
        .expect_err("a compiled harness must be durable before becoming active");

    assert!(matches!(error, hf_core::error::ClassifiedError::Storage(_)));
    assert!(
        !hf_service::workspace_dir(project.path(), "parse_release")
            .join("harness.active")
            .exists(),
        "the active marker must not reference a missing database record"
    );
}

#[tokio::test]
async fn generated_harness_propagates_a_configured_store_write_failure() {
    common::install_managed_workspace("oxfuzz_release_generate_it");
    let project = sample_project();
    let store = store_in(&project).await;
    sqlx::query("DROP TABLE harnesses")
        .execute(store.pool())
        .await
        .unwrap();
    let service = ServiceContainer::new(Arc::new(SuccessfulRuntime), None).with_store(store);

    let error = service
        .harness_generate(
            project.path(),
            "parse_release",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await
        .expect_err("generated harness persistence is part of successful generation");

    assert!(matches!(error, hf_core::error::ClassifiedError::Storage(_)));
    assert!(
        !hf_service::workspace_dir(project.path(), "parse_release")
            .join("harness.active")
            .exists(),
        "the repair path must not activate an unpersisted harness"
    );
}

#[cfg(unix)]
#[test]
fn project_workspace_identity_is_canonical() {
    common::install_managed_workspace("oxfuzz_release_workspace_it");
    let project = sample_project();
    let links = tempfile::tempdir().unwrap();
    let alias = links.path().join("project-link");
    std::os::unix::fs::symlink(project.path(), &alias).unwrap();

    assert_eq!(
        hf_service::project_workspace_dir(project.path()),
        hf_service::project_workspace_dir(&alias)
    );
    assert_eq!(
        hf_service::workspace_dir(project.path(), "parse_release"),
        hf_service::workspace_dir(&alias, "parse_release")
    );
}
