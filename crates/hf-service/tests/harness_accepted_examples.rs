//! Executor tests for accepted-example conditioning: a harness draft must
//! carry the project's previously promoted harnesses, and a project without
//! promotions must draft exactly as before.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::{TargetCandidate, TargetLanguage};
use hf_service::ServiceContainer;

const DRAFT_RESPONSE: &str = "```c\nint LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }\n```";

/// Records every prompt it serves and always answers with a draftable
/// harness, so tests can assert what reached the model.
struct DraftCapturePool {
    prompts: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for DraftCapturePool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        let last = request
            .messages
            .last()
            .map(|message| message.content.clone())
            .unwrap_or_default();
        self.prompts.lock().unwrap().push(last);
        Ok(hf_test_utils::fixtures::make_chat_response(DRAFT_RESPONSE))
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

struct CompilingRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for CompilingRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn run_command_streaming(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

fn example_target(project: &Path, symbol: &str) -> TargetCandidate {
    TargetCandidate {
        id: uuid::Uuid::new_v4(),
        project_root: project.to_path_buf(),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: hf_core::target::TargetKind::Parser,
        location: hf_core::target::SourceLocation {
            file: PathBuf::from("other.c"),
            line: 3,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some(format!("int {symbol}(const unsigned char *, size_t)")),
        input_surface: hf_core::target::InputSurface::Bytes,
        complexity: 5,
        fit_score: 0.7,
        sanitizers: vec![hf_core::target::Sanitizer::Address],
        rationale: "fixture".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 5,
    }
}

async fn fixture_with_pool(
    pool: Arc<DraftCapturePool>,
) -> (tempfile::TempDir, Arc<hf_storage::Store>, ServiceContainer) {
    common::install_managed_workspace("oxfuzz_accepted_examples_it");
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("accepted-examples.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(CompilingRuntime), Some(pool))
        .with_store(Arc::clone(&store));
    (project, store, container)
}

#[tokio::test]
async fn harness_generate_conditions_the_draft_on_promoted_harnesses() {
    let pool = Arc::new(DraftCapturePool {
        prompts: Mutex::new(Vec::new()),
    });
    let (project, store, container) = fixture_with_pool(Arc::clone(&pool)).await;

    // One promoted harness for another target of the same project, and one
    // draft-status harness that must never qualify.
    let canonical = std::fs::canonicalize(project.path()).unwrap();
    let promoted_target = example_target(&canonical, "parse_other");
    let draft_target = example_target(&canonical, "parse_yetAnother");
    let now = chrono::Utc::now();
    store.upsert_target(&promoted_target, now).await.unwrap();
    store.upsert_target(&draft_target, now).await.unwrap();
    let promoted = Harness {
        id: uuid::Uuid::new_v4(),
        target_id: promoted_target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return parse_other(d, n); }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_other"),
            extra_flags: Vec::new(),
        },
        sanitizer: hf_core::target::Sanitizer::Address,
        status: HarnessStatus::Promoted,
        smoke_run: None,
    };
    let not_promoted = Harness {
        id: uuid::Uuid::new_v4(),
        target_id: draft_target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return parse_yetAnother(d, n); }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz_parse_yetAnother"),
            extra_flags: Vec::new(),
        },
        sanitizer: hf_core::target::Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    };
    store.upsert_harness(&promoted).await.unwrap();
    store.upsert_harness(&not_promoted).await.unwrap();

    container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await
        .expect("generation should complete");

    let prompts = pool.prompts.lock().unwrap().clone();
    let draft = prompts
        .iter()
        .find(|prompt| prompt.contains("Previously accepted"))
        .expect("the draft prompt must carry the accepted examples");
    assert!(
        draft.contains("parse_other"),
        "the example must name its target: {draft}"
    );
    assert!(
        draft.contains("return parse_other(d, n);"),
        "the example must carry the promoted source: {draft}"
    );
    assert!(
        !draft.contains("parse_yetAnother"),
        "a draft-status harness is not an accepted example: {draft}"
    );
}

#[tokio::test]
async fn harness_generate_without_promotions_drafts_without_the_section() {
    let pool = Arc::new(DraftCapturePool {
        prompts: Mutex::new(Vec::new()),
    });
    let (project, _store, container) = fixture_with_pool(Arc::clone(&pool)).await;

    container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await
        .expect("generation should complete");

    let prompts = pool.prompts.lock().unwrap().clone();
    assert!(
        !prompts.is_empty(),
        "the draft call must have reached the provider"
    );
    assert!(
        prompts
            .iter()
            .all(|prompt| !prompt.contains("Previously accepted")),
        "no promotions means no examples section: {prompts:?}"
    );
}
