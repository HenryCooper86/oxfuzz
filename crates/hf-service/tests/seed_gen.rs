//! Integration test for LLM seed generation (`generate_seeds_llm`).

mod common;

use std::sync::Arc;

use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_seedgen_it");
}

/// A pool that returns a JSON array of hex-encoded seeds for every completion.
struct HexSeedPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for HexSeedPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        // "89504e47" = PNG magic, "7b7d" = "{}".
        Ok(hf_test_utils::fixtures::make_chat_response(
            "[\"89504e47\", \"7b7d\"]",
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

fn write_sample_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size) {\n\
         \x20 if (size > 0 && data[0] == 'A') { return 1; }\n\
         \x20 return 0;\n}\n",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn generate_seeds_llm_writes_decoded_seeds() {
    isolate_workspace();
    let project = write_sample_project();
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(HexSeedPool)),
    );

    let entries = container
        .generate_seeds_llm(project.path(), "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation should succeed");

    assert_eq!(entries.len(), 2, "expected two decoded seeds");
    // The PNG-magic seed (4 bytes) is present.
    assert!(entries.iter().any(|e| e.size == 4));
    // The "{}" seed (2 bytes) is present.
    assert!(entries.iter().any(|e| e.size == 2));
}

#[tokio::test]
async fn generate_seeds_llm_falls_back_to_heuristics_without_provider() {
    isolate_workspace();
    let project = write_sample_project();
    // No provider pool -> heuristic seeds.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let entries = container
        .generate_seeds_llm(project.path(), "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation should succeed");
    assert!(
        !entries.is_empty(),
        "heuristic fallback should seed something"
    );
}

#[tokio::test]
async fn generate_seeds_llm_reports_only_the_seeds_it_wrote() {
    isolate_workspace();
    let project = write_sample_project();
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(HexSeedPool)),
    );
    // An input the fuzzer earned before this call: part of the persisted
    // inventory, never something this seeding "generated".
    let corpus = hf_service::workspace_dir(project.path(), "parse_entry").join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("fuzzer_earned"), b"kept").unwrap();

    let first = container
        .generate_seeds_llm(project.path(), "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation should succeed");
    assert_eq!(first.len(), 2, "{first:?}");
    assert!(
        !first.iter().any(|entry| entry.name == "fuzzer_earned"),
        "a pre-existing entry is not reported as generated"
    );

    // Repeated calls rewrite the same names over the same inventory; the
    // reported set must stay exactly as large as what the call wrote.
    let second = container
        .generate_seeds_llm(project.path(), "parse_entry", TargetLanguage::C, 8)
        .await
        .expect("seed generation should succeed");
    assert_eq!(
        first.len(),
        second.len(),
        "counts are stable across repeated calls"
    );
    let names_of = |entries: &[hf_service::SeedEntry]| -> Vec<String> {
        let mut names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        names.sort();
        names
    };
    assert_eq!(names_of(&first), names_of(&second));
    assert!(
        std::fs::read_dir(&corpus).unwrap().count() >= 3,
        "the earned input stays on disk alongside the seeds"
    );
}

#[tokio::test]
async fn generate_seeds_reports_only_the_seeds_it_wrote() {
    isolate_workspace();
    let project = write_sample_project();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let corpus = hf_service::workspace_dir(project.path(), "parse_entry").join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();
    std::fs::write(corpus.join("fuzzer_earned"), b"kept").unwrap();

    let entries = container
        .generate_seeds(project.path(), "parse_entry")
        .await
        .expect("seed generation should succeed");
    assert!(
        !entries.is_empty(),
        "the heuristic seeder writes its own seeds"
    );
    assert!(
        !entries.iter().any(|entry| entry.name == "fuzzer_earned"),
        "a pre-existing entry is not reported as generated"
    );
}
