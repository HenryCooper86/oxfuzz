//! Integration tests for LLM dictionary augmentation during campaign runs:
//! the prompt is retained before dispatch, its response is completed once,
//! and a repeated run over unchanged sources reuses the durable draft without
//! a provider call.

mod common;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::{FuzzRequest, HarnessReviewBypass, ServiceContainer};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// The one token the capturing pool proposes; it never appears in the project
/// sources, so its presence in the dictionary proves the merge.
const DICTIONARY_RESPONSE: &str = "\"ZZQQTOKEN\"\n";

/// A runtime that writes files for real and reports every command as a clean
/// success, mirroring the fuzz-pipeline fixture.
struct PipelineRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for PipelineRuntime {
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
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
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

/// A capturing provider pool: answers the dictionary prompt with a fixed
/// dictionary while checking that the exact prompt is already retained as a
/// pending draft (the dispatch happens after persistence), approves harness
/// reviews, and answers every other prompt with a harness code block like the
/// fuzz-pipeline fixture.
struct DictionaryPool {
    store: Arc<hf_storage::Store>,
    project_root: String,
    target: &'static str,
    dictionary_calls: AtomicUsize,
    prompt_was_pending: AtomicBool,
}

impl DictionaryPool {
    fn dictionary_calls(&self) -> usize {
        self.dictionary_calls.load(Ordering::SeqCst)
    }

    fn prompt_was_pending(&self) -> bool {
        self.prompt_was_pending.load(Ordering::SeqCst)
    }

    fn dictionary_prompt(request: &hf_core::provider::ChatRequest) -> Option<String> {
        let prompt = request
            .messages
            .last()
            .map(|message| message.content.clone())?;
        prompt
            .contains("fuzzing-dictionary author")
            .then_some(prompt)
    }
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for DictionaryPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if let Some(prompt) = Self::dictionary_prompt(request) {
            self.dictionary_calls.fetch_add(1, Ordering::SeqCst);
            let pending = self
                .store
                .dictionary_llm_drafts_for(&self.project_root, self.target)
                .await
                .expect("drafts readable at dispatch time")
                .iter()
                .any(|draft| draft.response.is_none() && draft.prompt == prompt);
            self.prompt_was_pending.store(pending, Ordering::SeqCst);
            return Ok(hf_test_utils::fixtures::make_chat_response(
                DICTIONARY_RESPONSE,
            ));
        }
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
            message: "streaming is not used by the dictionary fixture".to_owned(),
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
    _directory: tempfile::TempDir,
    project: PathBuf,
    canonical_root: String,
    store: Arc<hf_storage::Store>,
    pool: Arc<DictionaryPool>,
}

impl Fixture {
    async fn new() -> Self {
        common::install_managed_workspace("oxfuzz_dictionary_llm_it");
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("fuzzproj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("parse.c"),
            "#include <stddef.h>\n#include <stdint.h>\n#include <string.h>\n\
             int parse_entry(const uint8_t *data, size_t size){\n\
             \x20 if (size > 4 && memcmp(data, \"IHDR\", 4) == 0) { return 1; }\n\
             \x20 return 0; }\n",
        )
        .unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("fuzz.db"))
                .await
                .unwrap(),
        );
        let canonical_root = std::fs::canonicalize(&project)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let pool = Arc::new(DictionaryPool {
            store: Arc::clone(&store),
            project_root: canonical_root.clone(),
            target: "parse_entry",
            dictionary_calls: AtomicUsize::new(0),
            prompt_was_pending: AtomicBool::new(false),
        });
        Self {
            _directory: directory,
            project,
            canonical_root,
            store,
            pool,
        }
    }

    fn container(&self) -> ServiceContainer {
        ServiceContainer::new(
            Arc::new(PipelineRuntime),
            Some(Arc::clone(&self.pool) as Arc<dyn hf_core::provider::ProviderPool>),
        )
        .with_store(Arc::clone(&self.store))
    }

    fn dictionary(&self) -> String {
        std::fs::read_to_string(
            hf_service::workspace_dir(&self.project, "parse_entry").join("fuzzer.dict"),
        )
        .unwrap()
    }

    async fn drafts(&self) -> Vec<hf_storage::DictionaryLlmDraftRecord> {
        self.store
            .dictionary_llm_drafts_for(&self.canonical_root, "parse_entry")
            .await
            .unwrap()
    }
}

fn noop_stage() -> impl Fn(hf_service::FuzzStage) + Send + Sync {
    |_| {}
}

fn noop_progress() -> impl Fn(hf_service::FuzzProgress) + Send + Sync {
    |_| {}
}

fn fuzz_request(project: &std::path::Path) -> FuzzRequest<'_> {
    FuzzRequest {
        prepared_harness: None,
        project,
        target: None,
        engine: EngineKind::LibFuzzer,
        lang: None,
        duration_secs: 1,
        iterations: 1,
        timeout_ms: None,
        resume: None,
        review_bypass: HarnessReviewBypass::NotRequested,
        fresh: false,
        sanitizer: None,
        cmplog: false,
        seed: None,
    }
}

async fn onboard(container: &ServiceContainer, project: &std::path::Path) {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        container.fuzz_onboard(fuzz_request(project), &noop_stage(), &noop_progress()),
    )
    .await
    .expect("the pipeline must not wedge")
    .expect("onboarding completes");
}

#[tokio::test]
async fn the_dictionary_prompt_is_retained_before_dispatch_and_completed_once() {
    let fixture = Fixture::new().await;
    onboard(&fixture.container(), &fixture.project).await;

    assert_eq!(
        fixture.pool.dictionary_calls(),
        1,
        "the campaign dispatches the dictionary prompt once"
    );
    assert!(
        fixture.pool.prompt_was_pending(),
        "the exact prompt was already retained when the provider was called"
    );

    let drafts = fixture.drafts().await;
    assert_eq!(drafts.len(), 1, "one draft row per dispatch");
    let draft = &drafts[0];
    assert_eq!(
        draft.response.as_deref(),
        Some(DICTIONARY_RESPONSE),
        "the exact response is completed once"
    );
    assert!(
        draft.completed_at.is_some(),
        "the completion time is recorded"
    );
    assert!(
        draft.prompt.contains("\"IHDR\""),
        "the prompt lists the static tokens: {}",
        draft.prompt
    );
    assert!(
        draft.prompt.contains("Do not re-propose"),
        "the prompt forbids re-proposing: {}",
        draft.prompt
    );
    assert!(
        draft.prompt.contains("parse_entry"),
        "the prompt names the target: {}",
        draft.prompt
    );
    assert_eq!(draft.static_dict_sha256.len(), 64);

    let dictionary = fixture.dictionary();
    assert!(
        dictionary.contains("IHDR"),
        "static tokens stay: {dictionary}"
    );
    assert!(
        dictionary.contains("ZZQQTOKEN"),
        "the proposed token merged: {dictionary}"
    );
}

#[tokio::test]
async fn a_second_run_with_unchanged_sources_makes_no_provider_call() {
    let fixture = Fixture::new().await;
    onboard(&fixture.container(), &fixture.project).await;
    assert_eq!(fixture.pool.dictionary_calls(), 1);
    let after_first = fixture.dictionary();
    assert!(after_first.contains("ZZQQTOKEN"), "{after_first}");

    // A second campaign over the same project, target, and static dictionary
    // reuses the durable draft instead of dispatching again.
    let second = fixture.container();
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        second.run_campaign(
            &fixture.project,
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
        ),
    )
    .await
    .expect("the campaign must not wedge")
    .expect("the campaign completes");

    assert_eq!(
        fixture.pool.dictionary_calls(),
        1,
        "the durable draft is reused without a provider call"
    );
    assert_eq!(
        fixture.drafts().await.len(),
        1,
        "no second draft row is created"
    );
    assert_eq!(fixture.dictionary(), after_first);
}
