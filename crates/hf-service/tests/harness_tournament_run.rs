//! Harness Tournament orchestration contract.
//!
//! Every candidate's evidence is retained, a tournament with no compiling
//! candidate is a result rather than an error, and the tournament promotes
//! nothing.

#![cfg(feature = "harness-tournament")]

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::harness_tournament::{CandidateOrigin, MAX_CANDIDATES};
use hf_service::{HarnessTournamentRequest, ServiceContainer};

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_tournament_it");
}

/// A runtime whose compile command always exits with `exit_code`.
struct FixedRuntime {
    exit_code: i32,
    compiles: AtomicUsize,
}

impl FixedRuntime {
    fn new(exit_code: i32) -> Arc<Self> {
        Arc::new(Self {
            exit_code,
            compiles: AtomicUsize::new(0),
        })
    }
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for FixedRuntime {
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
        self.compiles.fetch_add(1, Ordering::SeqCst);
        Ok(hf_core::runtime::CommandResult {
            exit_code: self.exit_code,
            stdout: String::new(),
            stderr: if self.exit_code == 0 {
                String::new()
            } else {
                "harness.c:2:5: error: implicit declaration of function 'frob'".to_owned()
            },
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

/// A pool that returns a valid fenced C harness for every completion.
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

fn request(project: &std::path::Path, candidates: usize) -> HarnessTournamentRequest {
    HarnessTournamentRequest {
        project: project.display().to_string(),
        target: "parse_entry".to_owned(),
        engine: EngineKind::LibFuzzer,
        lang: TargetLanguage::C,
        candidates,
        max_repairs: 0,
    }
}

#[tokio::test]
async fn every_candidate_is_evaluated_and_its_evidence_retained() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = FixedRuntime::new(0);
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)));

    let result = container
        .run_harness_tournament(request(project.path(), 3))
        .await
        .expect("a tournament runs");

    assert_eq!(result.candidates.len(), 3);
    // The deterministic baseline is always included, so a tournament whose
    // model drafts all fail still leaves something that builds.
    assert_eq!(result.candidates[0].origin, CandidateOrigin::Heuristic);
    assert!(result.candidates[1..]
        .iter()
        .all(|entry| entry.origin == CandidateOrigin::Llm));
    assert!(result.candidates.iter().all(|entry| entry.compiled));
    assert!(
        result
            .candidates
            .iter()
            .all(|entry| entry.source_sha256.len() == 64),
        "every candidate is reconstructable from its digest"
    );

    assert_eq!(result.ranking.len(), 3);
    assert_eq!(result.winner_index, Some(0));
    assert!(
        !result.promoted,
        "a tournament never promotes; promotion stays a human step"
    );
}

#[tokio::test]
async fn a_tournament_with_no_compiling_candidate_is_a_result_with_diagnostics() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = FixedRuntime::new(1);
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)));

    let result = container
        .run_harness_tournament(request(project.path(), 2))
        .await
        .expect("no compiling candidate is a result, not an error");

    assert_eq!(result.candidates.len(), 2);
    assert!(result.candidates.iter().all(|entry| !entry.compiled));
    assert!(
        result.candidates.iter().all(|entry| entry
            .compile_error
            .as_deref()
            .is_some_and(|error| error.contains("implicit declaration"))),
        "each losing candidate retains its own diagnostics"
    );
    assert_eq!(result.winner_index, None);
    assert!(!result.promoted);
}

#[tokio::test]
async fn the_candidate_count_is_validated_before_any_model_call_or_sandbox_run() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = FixedRuntime::new(0);
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)));

    for count in [0, MAX_CANDIDATES + 1] {
        let error = container
            .run_harness_tournament(request(project.path(), count))
            .await
            .expect_err("an out-of-range tournament is refused");
        assert!(
            error.to_string().contains("candidate"),
            "the refusal names the candidate count: {error}"
        );
    }
    assert_eq!(
        runtime.compiles.load(Ordering::SeqCst),
        0,
        "nothing was compiled for a refused tournament"
    );
}
