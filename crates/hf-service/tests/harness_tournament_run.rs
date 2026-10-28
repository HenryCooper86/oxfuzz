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
    materialize_artifacts: bool,
}

impl FixedRuntime {
    fn new(exit_code: i32) -> Arc<Self> {
        Arc::new(Self {
            exit_code,
            compiles: AtomicUsize::new(0),
            materialize_artifacts: false,
        })
    }

    fn with_artifacts() -> Arc<Self> {
        Arc::new(Self {
            exit_code: 0,
            compiles: AtomicUsize::new(0),
            materialize_artifacts: true,
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
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.compiles.fetch_add(1, Ordering::SeqCst);
        if self.materialize_artifacts {
            if let Some((_, output)) = cmd.get(2).and_then(|script| script.rsplit_once("/work/'")) {
                let (name, _) = output.split_once('\'').expect("quoted compile output");
                std::fs::write(cwd.join(name), b"inert compiled harness").unwrap();
            }
        }
        Ok(hf_core::runtime::CommandResult {
            exit_code: self.exit_code,
            stdout: if self.materialize_artifacts {
                "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned()
            } else {
                String::new()
            },
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
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        if self.materialize_artifacts {
            std::fs::write(path, content).unwrap();
        }
        Ok(())
    }

    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        if self.materialize_artifacts {
            return std::fs::read_to_string(path)
                .map_err(|error| hf_core::error::ClassifiedError::Sandbox(error.to_string()));
        }
        Ok(String::new())
    }
}

/// A pool that returns a valid fenced C harness for every completion.
struct CodeBlockPool;

#[async_trait::async_trait]
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
            "```c\n#include <stddef.h>\n#include <stdint.h>\nint parse_entry(const uint8_t *, size_t);\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return parse_entry(d, n); }\n```",
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
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        ));

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
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        ));

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
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        ));

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

async fn qualified_fixture() -> (tempfile::TempDir, ServiceContainer) {
    isolate_workspace();
    let project = write_sample_project();
    std::fs::write(
        project.path().join("compile_commands.json"),
        serde_json::to_vec(&serde_json::json!([{
            "directory":project.path(), "file":"parse.c", "arguments":["cc","-c","parse.c"],
        }]))
        .unwrap(),
    )
    .unwrap();
    let container = ServiceContainer::new(
        FixedRuntime::with_artifacts(),
        Some(Arc::new(CodeBlockPool)),
    )
    .with_store(Arc::new(
        hf_storage::Store::connect(project.path().join("state.db"))
            .await
            .unwrap(),
    ))
    .with_guardrails(hf_guardrails::Guardrails::new(
        hf_guardrails::GuardrailPolicy::default(),
        Arc::new(hf_guardrails::AutoApprove),
    ));
    (project, container)
}

#[tokio::test]
async fn qualified_tournament_smokes_candidates_and_leaves_a_requalifiable_winner() {
    let (project, container) = qualified_fixture().await;
    let mut request = request(project.path(), 2);
    request.target = "parse.c::parse_entry".to_owned();
    let result = container
        .run_harness_tournament(request.clone())
        .await
        .unwrap();
    assert!(
        result.candidates.iter().all(|candidate| candidate.compiled),
        "{result:?}"
    );
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.smoke.is_some()),
        "{result:?}"
    );
    assert!(!result.promoted);
    let winner = container
        .harness_smoke(
            project.path(),
            &request.target,
            request.engine,
            request.lang,
        )
        .await
        .expect("restored winner uses the same qualified binary name");
    assert!(winner.summary.passed);
}

#[tokio::test]
async fn qualified_generated_harness_can_be_smoke_qualified() {
    let (project, container) = qualified_fixture().await;
    let target = "parse.c::parse_entry";
    let generated = container
        .harness_generate(
            project.path(),
            target,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
            None,
            false,
            false,
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap();
    assert!(generated.workspace.join(&generated.binary_name).is_file());
    let smoke = container
        .harness_smoke(
            project.path(),
            target,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("generated artifacts use the requested file-qualified selector");
    assert!(smoke.summary.passed);
}

#[tokio::test]
async fn qualified_refinement_keeps_the_active_binary_name() {
    let (project, container) = qualified_fixture().await;
    let target = "parse.c::parse_entry";
    let source = "#include <stddef.h>\n#include <stdint.h>\nint parse_entry(const uint8_t *, size_t);\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { return parse_entry(data, size); }";
    let compiled = container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            target,
            TargetLanguage::C,
            None,
            false,
        )
        .await
        .unwrap();
    let refined = container
        .harness_refine(
            project.path(),
            target,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
            hf_service::AiPolicy::Auto,
        )
        .await
        .unwrap();
    assert_eq!(refined.binary_name, compiled.binary_name);
    let smoke = container
        .harness_smoke(
            project.path(),
            target,
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("refined artifacts preserve the file-qualified selector");
    assert!(smoke.summary.passed);
}

/// A runtime that only compiles harness sources carrying the `REPAIRED`
/// marker: every original draft (heuristic or model) fails to build, and each
/// repair pass produces a source that does.
struct RepairOnlyRuntime {
    compiles: AtomicUsize,
    last_harness_source: std::sync::Mutex<String>,
}

impl RepairOnlyRuntime {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            compiles: AtomicUsize::new(0),
            last_harness_source: std::sync::Mutex::new(String::new()),
        })
    }
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for RepairOnlyRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.compiles.fetch_add(1, Ordering::SeqCst);
        let source = self.last_harness_source.lock().unwrap().clone();
        let builds = source.contains("REPAIRED");
        if builds {
            if let Some((_, output)) = cmd.get(2).and_then(|script| script.rsplit_once("/work/'")) {
                let (name, _) = output.split_once('\'').expect("quoted compile output");
                std::fs::write(cwd.join(name), b"inert compiled harness").unwrap();
            }
        }
        Ok(hf_core::runtime::CommandResult {
            exit_code: i32::from(!builds),
            stdout: if builds {
                "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned()
            } else {
                String::new()
            },
            stderr: if builds {
                String::new()
            } else {
                "harness.c:2:5: error: implicit declaration of function 'deliberate_missing_symbol_xyz'"
                    .to_owned()
            },
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        std::fs::write(path, content).unwrap();
        if content.contains("LLVMFuzzerTestOneInput") {
            *self.last_harness_source.lock().unwrap() = content.to_string();
        }
        Ok(())
    }

    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        std::fs::read_to_string(path)
            .map_err(|error| hf_core::error::ClassifiedError::Sandbox(error.to_string()))
    }
}

/// Answers model drafts with a harness calling a deliberately missing
/// function, and repair requests (recognized by the compiler diagnostics
/// embedded in the repair prompt) with a distinct repair per pass.
struct RepairPool {
    repairs: AtomicUsize,
}

impl RepairPool {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            repairs: AtomicUsize::new(0),
        })
    }

    fn harness(mark: &str) -> String {
        format!(
            "```c\n#include <stddef.h>\n#include <stdint.h>\n\
             int parse_entry(const uint8_t *, size_t);\n\
             int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {{ \
             {mark} return parse_entry(d, n); }}\n```"
        )
    }
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for RepairPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let prompt = request
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect::<String>();
        let reply = if prompt.contains("deliberate_missing_symbol_xyz") {
            let pass = self.repairs.fetch_add(1, Ordering::SeqCst) + 1;
            Self::harness(&format!("/* REPAIRED-{pass} */"))
        } else {
            Self::harness("deliberate_missing_symbol_xyz();")
        };
        Ok(hf_test_utils::fixtures::make_chat_response(&reply))
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
async fn the_workspace_is_restored_to_the_winners_post_repair_source() {
    let (project, _root) = {
        isolate_workspace();
        let project = write_sample_project();
        std::fs::write(
            project.path().join("compile_commands.json"),
            serde_json::to_vec(&serde_json::json!([{
                "directory":project.path(), "file":"parse.c", "arguments":["cc","-c","parse.c"],
            }]))
            .unwrap(),
        )
        .unwrap();
        (project, ())
    };
    let container = ServiceContainer::new(RepairOnlyRuntime::new(), Some(RepairPool::new()))
        .with_store(Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        ))
        .with_guardrails(hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy::default(),
            Arc::new(hf_guardrails::AutoApprove),
        ));

    let mut request = request(project.path(), 2);
    request.max_repairs = 1;
    request.target = "parse.c::parse_entry".to_owned();
    let result = container.run_harness_tournament(request).await.unwrap();

    assert!(
        result.candidates.iter().all(|candidate| candidate.compiled),
        "{result:?}"
    );
    assert!(
        result
            .candidates
            .iter()
            .all(|candidate| candidate.repairs_used == 1),
        "{result:?}"
    );
    assert_eq!(result.winner_index, Some(0));

    // The winner compiled only after its repair pass, so the workspace must
    // hold the winner's POST-REPAIR source -- not the last-evaluated
    // candidate's, and not the winner's original draft.
    let workspace = hf_service::workspace_dir(project.path(), "parse.c::parse_entry");
    let restored = std::fs::read_to_string(workspace.join("harness.source")).unwrap();
    assert!(
        restored.contains("REPAIRED-1"),
        "the winner's post-repair source must be restored: {restored}"
    );
    assert!(
        !restored.contains("REPAIRED-2"),
        "the last-evaluated candidate's source must not remain: {restored}"
    );
    assert!(
        !restored.contains("deliberate_missing_symbol_xyz"),
        "the winner's never-compiling draft must not be restored: {restored}"
    );
}
