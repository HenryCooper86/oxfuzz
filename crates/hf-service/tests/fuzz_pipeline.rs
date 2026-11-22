//! Integration tests for the one-command onboarding pipeline
//! (`ServiceContainer::fuzz_onboard`): discover -> harness -> smoke -> promote
//! -> campaign, composed from the existing service operations. No Docker, no
//! live providers: a writing stub runtime and a fixed-reply provider pool.

mod common;

use std::sync::{Arc, Mutex};

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::{FuzzRequest, FuzzStage, HarnessStep, ServiceContainer};

/// A runtime that writes files for real and reports every command as a clean
/// success with smoke activity. Every `run_command` also (re)writes the
/// compiled harness binary with constant content, so the compile stage leaves
/// the artifact the smoke and campaign stages check, and every digest
/// comparison between stages sees identical bytes.
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

/// Returns a fenced C harness for every completion (draft/repair), and approves
/// the mandatory pre-execution harness review.
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

/// A C project with one fuzzable parser function.
fn c_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("fuzzproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();
    project
}

fn pipeline_container(store: &Arc<hf_storage::Store>) -> ServiceContainer {
    ServiceContainer::new(Arc::new(PipelineRuntime), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::clone(store))
}

/// Collect stage notifications for later assertions.
#[derive(Clone, Default)]
struct StageLog {
    stages: Arc<Mutex<Vec<FuzzStage>>>,
}

impl StageLog {
    fn sink(&self) -> impl Fn(FuzzStage) + Send + Sync {
        let stages = Arc::clone(&self.stages);
        move |stage| {
            stages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(stage);
        }
    }

    /// Stage boundaries, in order; harness steps are left out.
    fn stages(&self) -> Vec<FuzzStage> {
        self.events()
            .into_iter()
            .filter(|stage| !matches!(stage, FuzzStage::HarnessStep { .. }))
            .collect()
    }

    fn events(&self) -> Vec<FuzzStage> {
        self.stages
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

fn noop_progress() -> impl Fn(hf_service::FuzzProgress) + Send + Sync {
    |_| {}
}

fn noop_stage() -> impl Fn(FuzzStage) + Send + Sync {
    |_| {}
}

#[tokio::test]
async fn fuzz_runs_the_whole_pipeline_and_auto_picks_the_top_target() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_pipeline_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);
    let log = StageLog::default();
    let on_stage = log.sink();

    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        container.fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None, // auto-detect
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &on_stage,
            &noop_progress(),
        ),
    )
    .await
    .expect("the pipeline must not wedge on nested workspace leases")
    .expect("the pipeline completes with a promoted harness and a clean campaign");

    assert_eq!(outcome.target, "parse_entry");
    assert_eq!(outcome.lang, TargetLanguage::C, "language auto-detection");
    assert!(!outcome.harness_reused, "a first run drafts its harness");
    assert_eq!(outcome.campaign.iterations, 1);
    assert_eq!(outcome.campaign.crashes, 0);
    assert_eq!(
        outcome.campaign.harness_status,
        hf_core::harness::HarnessStatus::Promoted
    );

    let stages = log.stages();
    assert_eq!(
        stages,
        vec![
            FuzzStage::Discover { lang: None },
            FuzzStage::Harness {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
                reused: false,
            },
            FuzzStage::Smoke {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
            },
            FuzzStage::Promote {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
            },
            FuzzStage::Campaign {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
                duration_secs: 1,
                iterations: 1,
            },
        ],
        "the operator sees every stage boundary in order: {stages:?}"
    );

    // The pipeline outcome stays machine-readable for `--json`.
    let json = serde_json::to_value(&outcome).unwrap();
    assert_eq!(json["target"], "parse_entry");
    assert_eq!(json["harness_reused"], false);
}

#[tokio::test]
async fn fuzz_reuses_a_promoted_harness_and_fresh_forces_a_redraft() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_reuse_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);

    let request = |fresh: bool| FuzzRequest {
        prepared_harness: None,
        project: &project,
        target: Some("parse_entry"),
        engine: EngineKind::LibFuzzer,
        lang: None,
        duration_secs: 1,
        iterations: 1,
        timeout_ms: None,
        resume: None,
        review_bypass: hf_service::HarnessReviewBypass::NotRequested,
        fresh,
        sanitizer: None,
        cmplog: false,
        seed: None,
    };

    let first = container
        .fuzz_onboard(request(false), &noop_stage(), &noop_progress())
        .await
        .expect("first run drafts, qualifies, and promotes");

    // Second run: the already-promoted harness is reused, so the pipeline never
    // re-drafts, re-smokes, or re-asks for promotion.
    let log = StageLog::default();
    let on_stage = log.sink();
    let second = container
        .fuzz_onboard(request(false), &on_stage, &noop_progress())
        .await
        .expect("second run reuses the promoted harness");
    assert!(second.harness_reused, "same target+engine must be reused");
    assert_eq!(
        second.harness_id, first.harness_id,
        "reuse runs the exact promoted revision"
    );
    assert_eq!(second.repairs_used, 0);
    let stages = log.stages();
    assert!(
        stages.contains(&FuzzStage::Harness {
            target: "parse_entry".to_owned(),
            engine: EngineKind::LibFuzzer,
            reused: true,
        }),
        "the reuse is announced: {stages:?}"
    );
    assert!(
        !stages
            .iter()
            .any(|stage| matches!(stage, FuzzStage::Smoke { .. } | FuzzStage::Promote { .. })),
        "a reused harness skips smoke and the promotion gate: {stages:?}"
    );

    // --fresh forces a full re-qualification even though a promoted harness exists.
    let log = StageLog::default();
    let on_stage = log.sink();
    let third = container
        .fuzz_onboard(request(true), &on_stage, &noop_progress())
        .await
        .expect("--fresh re-drafts and re-qualifies");
    assert!(!third.harness_reused);
    let stages = log.stages();
    assert!(
        stages.contains(&FuzzStage::Harness {
            target: "parse_entry".to_owned(),
            engine: EngineKind::LibFuzzer,
            reused: false,
        }) && stages
            .iter()
            .any(|stage| matches!(stage, FuzzStage::Promote { .. })),
        "--fresh runs the promotion gate again: {stages:?}"
    );
}

/// Approves every high-risk action except promotion: the pipeline must stop at
/// the human gate and never reach the campaign.
struct ApproveExceptPromote;

#[async_trait::async_trait]
impl hf_guardrails::ApprovalGate for ApproveExceptPromote {
    async fn request_approval(&self, action: &hf_service::Action, _reason: &str) -> bool {
        !matches!(action, hf_service::Action::PromoteHarness)
    }
}

#[tokio::test]
async fn fuzz_stops_at_promotion_when_the_operator_denies_it() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_denied_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store).with_guardrails(hf_guardrails::Guardrails::new(
        hf_guardrails::GuardrailPolicy::default(),
        Arc::new(ApproveExceptPromote),
    ));
    let log = StageLog::default();
    let on_stage = log.sink();

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &on_stage,
            &noop_progress(),
        )
        .await
        .expect_err("a denied promotion stops the pipeline");

    let message = error.to_string();
    assert!(
        message.contains("promote"),
        "the failing stage is named: {message}"
    );
    assert!(
        message.contains("denied"),
        "the denial is named as such: {message}"
    );
    assert!(
        message.contains("HF_AUTO_APPROVE=1"),
        "the message says how to approve unattended: {message}"
    );
    let stages = log.stages();
    assert!(
        !stages
            .iter()
            .any(|stage| matches!(stage, FuzzStage::Campaign { .. })),
        "no campaign runs without promotion: {stages:?}"
    );

    // Nothing was promoted, so a direct campaign still refuses to run.
    let refused = container
        .run_campaign(
            &project,
            None,
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
        .await;
    assert!(
        refused.is_err(),
        "the pipeline must not fall back to an un-promoted campaign"
    );
}

/// A project holding a C parser AND a higher-scoring Go parser. The Go
/// candidate tops the fit ranking, so auto-pick proves the harnessability
/// filter by still choosing the C target.
fn mixed_c_and_go_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("mixedproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();
    // The control flow raises the Go candidate's complexity (and with it the
    // fit score) above the C parser's: exclusion by language, not by score.
    std::fs::write(
        project.join("parser.go"),
        "package parser\n\nfunc ParsePacket(data []byte, offset int) bool {\n\
         \tif len(data) > offset {\n\t\treturn data[0] == 'A'\n\t}\n\treturn false\n}\n",
    )
    .unwrap();
    project
}

/// A project whose only candidates are Go (discovery-only today).
fn go_only_project(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let project = dir.path().join("goproj");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("parser.go"),
        "package parser\n\nfunc ParsePacket(data []byte, offset int) bool {\n\treturn len(data) > offset\n}\n",
    )
    .unwrap();
    project
}

#[tokio::test]
async fn fuzz_auto_pick_excludes_a_higher_scoring_not_yet_harnessable_target() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_pipeline_it");
    let project = mixed_c_and_go_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);

    let outcome = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None, // auto-detect: the Go candidate outscores the C one
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect("the pipeline runs on the harnessable C target");

    assert_eq!(
        outcome.target, "parse_entry",
        "the Go candidate outranks it on fit but has no harness path"
    );
    assert_eq!(outcome.lang, TargetLanguage::C);
}

#[tokio::test]
async fn fuzz_on_a_go_only_project_fails_at_discovery_naming_the_engine_that_runs_go() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_pipeline_it");
    let project = go_only_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);
    let log = StageLog::default();
    let on_stage = log.sink();

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &on_stage,
            &noop_progress(),
        )
        .await
        .expect_err("libFuzzer cannot drive a Go-only project");

    let message = error.to_string();
    assert!(
        message.contains("discover"),
        "the failing stage is named: {message}"
    );
    assert!(
        message.contains("discovered 1 candidate(s)"),
        "the discovery result is reported, not hidden: {message}"
    );
    assert!(
        message.contains(
            "engine 'libfuzzer' cannot drive any of their languages (go targets run under \
             --engine go-native)"
        ),
        "the engine that does drive Go is named: {message}"
    );
    assert_eq!(
        log.stages(),
        vec![FuzzStage::Discover { lang: None }],
        "the pipeline stopped at discovery: no later stage was announced"
    );
}

#[tokio::test]
async fn fuzz_fails_loud_when_discovery_finds_no_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_empty_it");
    let project = dir.path().join("empty");
    std::fs::create_dir_all(&project).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);
    let log = StageLog::default();
    let on_stage = log.sink();

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &on_stage,
            &noop_progress(),
        )
        .await
        .expect_err("an empty project cannot be fuzzed");

    let message = error.to_string();
    assert!(
        message.contains("discover"),
        "the failing stage is named: {message}"
    );
    assert!(
        message.contains("no fuzzable targets"),
        "the cause is named: {message}"
    );
    assert!(
        message.contains("--lang"),
        "the remediation is actionable: {message}"
    );
    assert_eq!(
        log.stages(),
        vec![FuzzStage::Discover { lang: None }],
        "the pipeline stopped at discovery: no later stage was announced"
    );
}

#[tokio::test]
async fn fuzz_explains_a_project_that_is_itself_a_fuzz_harness() {
    // The shape of honggfuzz's examples/glibc: one persistent-mode harness
    // whose only externally visible function is `main`, plus static helpers.
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_harness_only_it");
    let project = dir.path().join("glibc");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join("resolver.c"),
        "#include <libhfuzz/libhfuzz.h>\n\
         static void unsh(void) { linuxEnterNs(0); }\n\
         int main(int argc, char *argv[]) {\n\
           unsh();\n\
           for (;;) { const char *buf; size_t len; HF_ITER((const uint8_t **)&buf, &len); }\n\
         }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);
    let log = StageLog::default();

    let error = container
        .fuzz_prepare(prepare_request(&project), &log.sink(), &noop_progress())
        .await
        .expect_err("a project that is only a fuzz harness has no target to draft for");

    let message = error.to_string();
    assert!(
        message.contains("no fuzzable targets"),
        "the cause is named: {message}"
    );
    assert!(
        message.contains("resolver.c") && message.contains("already a fuzz harness"),
        "the shipped harness is named: {message}"
    );
    assert_eq!(
        log.stages(),
        vec![FuzzStage::Discover { lang: None }],
        "no harness was drafted for `main`"
    );
}

#[tokio::test]
async fn fuzz_fails_loud_for_an_unknown_explicit_target() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_unknown_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: Some("no_such_function"),
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect_err("an unknown target is a discovery-stage failure");

    let message = error.to_string();
    assert!(
        message.contains("no_such_function"),
        "the missing target is named: {message}"
    );
    assert!(
        message.contains("discover"),
        "the failing stage is named: {message}"
    );
}

#[tokio::test]
async fn fuzz_smoke_without_a_provider_fails_closed_and_names_the_bypass() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_noprovider_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    // No provider pool: the mandatory pre-execution LLM review cannot run.
    let container = ServiceContainer::new(Arc::new(PipelineRuntime), None).with_store(store);
    let log = StageLog::default();
    let on_stage = log.sink();

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &on_stage,
            &noop_progress(),
        )
        .await
        .expect_err("without a provider or an explicit bypass, smoke fails closed");

    let message = error.to_string();
    assert!(
        message.contains("smoke"),
        "the failing stage is named: {message}"
    );
    assert!(
        message.contains("--no-llm-review"),
        "the opt-in surface is named: {message}"
    );
    let stages = log.stages();
    assert!(
        !stages.iter().any(|stage| matches!(
            stage,
            FuzzStage::Promote { .. } | FuzzStage::Campaign { .. }
        )),
        "nothing past smoke ran: {stages:?}"
    );
}

fn supplied(source: &str) -> hf_service::PreparedHarnessSource {
    use sha2::{Digest, Sha256};
    hf_service::PreparedHarnessSource {
        source: source.into(),
        sha256: format!("{:x}", Sha256::digest(source.as_bytes())),
    }
}
fn prepared_request<'a>(project: &'a std::path::Path, source: &str) -> FuzzRequest<'a> {
    FuzzRequest {
        project,
        target: Some("parse_entry"),
        engine: EngineKind::LibFuzzer,
        lang: Some(TargetLanguage::C),
        duration_secs: 1,
        iterations: 1,
        timeout_ms: None,
        resume: None,
        review_bypass: hf_service::HarnessReviewBypass::NotRequested,
        fresh: false,
        sanitizer: None,
        cmplog: false,
        seed: None,
        prepared_harness: Some(supplied(source)),
    }
}
const FROZEN_SOURCE: &str = "#include <stdint.h>\n#include <stddef.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) { (void)d; (void)n; return 0; }\n";

#[tokio::test]
async fn prepared_source_is_exact_and_never_reuses_a_promoted_revision() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace = common::install_managed_workspace("oxfuzz_prepared_exact");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("runs.db"))
            .await
            .unwrap(),
    );
    let service = pipeline_container(&store);
    let first = service
        .fuzz_onboard(
            prepared_request(&project, FROZEN_SOURCE),
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .unwrap();
    let second_source = format!("{FROZEN_SOURCE}\n/* Frozen second revision */\n");
    let second = service
        .fuzz_onboard(
            prepared_request(&project, &second_source),
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .unwrap();
    assert_ne!(first.harness_id, second.harness_id);
    assert!(!second.harness_reused);
    assert_eq!(second.repairs_used, 0);
    assert_eq!(
        second.prepared_harness_sha256,
        Some(supplied(&second_source).sha256)
    );
    assert_eq!(
        store
            .get_harness(second.harness_id)
            .await
            .unwrap()
            .unwrap()
            .source,
        second_source
    );
}

#[tokio::test]
async fn prepared_source_validation_precedes_discovery_and_execution() {
    let service = ServiceContainer::stubbed();
    let root = std::path::Path::new("/not-a-project");
    for invalid in ["digest", "target", "size", "nul"] {
        let mut request = prepared_request(root, FROZEN_SOURCE);
        match invalid {
            "digest" => request.prepared_harness.as_mut().unwrap().sha256 = "0".repeat(64),
            "target" => request.target = None,
            "size" => {
                request.prepared_harness = Some(supplied(
                    &"x".repeat(hf_service::MAX_PREPARED_HARNESS_SOURCE_BYTES + 1),
                ));
            }
            "nul" => request.prepared_harness = Some(supplied("source\0")),
            _ => unreachable!(),
        }
        let log = StageLog::default();
        assert!(service
            .fuzz_onboard(request, &log.sink(), &noop_progress())
            .await
            .is_err());
        assert!(
            log.stages().is_empty(),
            "{invalid} must fail before discovery"
        );
    }
}

#[tokio::test]
async fn prepared_source_still_requires_human_promotion() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace = common::install_managed_workspace("oxfuzz_prepared_denied");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("runs.db"))
            .await
            .unwrap(),
    );
    let service = pipeline_container(&store).with_guardrails(hf_guardrails::Guardrails::new(
        hf_guardrails::GuardrailPolicy::default(),
        Arc::new(ApproveExceptPromote),
    ));
    let log = StageLog::default();
    let error = service
        .fuzz_onboard(
            prepared_request(&project, FROZEN_SOURCE),
            &log.sink(),
            &noop_progress(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("denied"));
    assert!(!log
        .stages()
        .iter()
        .any(|stage| matches!(stage, FuzzStage::Campaign { .. })));
    assert!(store
        .list_runs(None)
        .await
        .unwrap()
        .iter()
        .all(|run| run.kind != hf_storage::RunKind::Campaign));
}

struct FailedPreparedCompile(std::sync::atomic::AtomicUsize);
#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for FailedPreparedCompile {
    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        hf_core::runtime::RuntimeAdapter::resolve_image_reference(&PipelineRuntime, image).await
    }
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(hf_core::runtime::CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "controlled compile failure".into(),
            workspace: cwd.into(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        hf_core::runtime::RuntimeAdapter::write_file(&PipelineRuntime, path, content).await
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        hf_core::runtime::RuntimeAdapter::read_file(&PipelineRuntime, path).await
    }
}
#[tokio::test]
async fn prepared_source_compile_failure_never_enters_ai_repair_or_execution() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace = common::install_managed_workspace("oxfuzz_prepared_compile_failure");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("runs.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(FailedPreparedCompile(std::sync::atomic::AtomicUsize::new(
        0,
    )));
    let service = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(store.clone());
    let log = StageLog::default();
    assert!(service
        .fuzz_onboard(
            prepared_request(&project, FROZEN_SOURCE),
            &log.sink(),
            &noop_progress()
        )
        .await
        .is_err());
    assert_eq!(
        runtime.0.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "one sandbox compile and no retry/repair"
    );
    assert!(!log
        .stages()
        .iter()
        .any(|stage| matches!(stage, FuzzStage::Smoke { .. } | FuzzStage::Campaign { .. })));
    assert!(store.list_runs(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn prepared_source_rejects_another_promoted_revision_at_campaign_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace = common::install_managed_workspace("oxfuzz_prepared_replaced");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("runs.db"))
            .await
            .unwrap(),
    );
    let service = pipeline_container(&store);
    let first = service
        .fuzz_onboard(
            prepared_request(&project, FROZEN_SOURCE),
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .unwrap();
    let workspace = hf_service::workspace_dir(&project, "parse_entry");
    let changed = format!("{FROZEN_SOURCE}\n/* Approved second revision */\n");
    let swap = |stage| {
        if matches!(stage, FuzzStage::Campaign { .. }) {
            std::fs::write(
                workspace.join("harness.active"),
                first.harness_id.to_string(),
            )
            .unwrap();
            std::fs::write(workspace.join("harness.source"), FROZEN_SOURCE).unwrap();
        }
    };
    let error = service
        .fuzz_onboard(
            prepared_request(&project, &changed),
            &swap,
            &noop_progress(),
        )
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("prepared harness revision changed"),
        "{error}"
    );
    assert_eq!(
        store
            .list_runs(None)
            .await
            .unwrap()
            .iter()
            .filter(|run| run.kind == hf_storage::RunKind::Campaign)
            .count(),
        1
    );
}

/// Like [`PipelineRuntime`], but the first smoke run never reaches the
/// harness (no fuzzer activity); every later one reports throughput.
struct SilentFirstSmokeRuntime {
    smokes: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for SilentFirstSmokeRuntime {
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
        limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let smoke = cmd.iter().any(|arg| arg.starts_with("-max_total_time"));
        if smoke
            && self
                .smokes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
        {
            return Ok(hf_core::runtime::CommandResult {
                exit_code: 0,
                stdout: "[!] the entry point never ran".to_owned(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: hf_core::runtime::CommandTermination::Completed,
            });
        }
        PipelineRuntime.run_command(cmd, cwd, limits).await
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        PipelineRuntime.write_file(path, content).await
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        PipelineRuntime.read_file(path).await
    }
}

#[tokio::test]
async fn fuzz_repairs_a_harness_whose_smoke_run_never_reaches_it() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_smoke_repair_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let pool = hf_test_utils::RecordingHarnessPool::new(|index, _| {
        format!(
            "```c\n/* revision {index} */\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){{ return 0; }}\n```"
        )
    });
    let container = ServiceContainer::new(
        Arc::new(SilentFirstSmokeRuntime {
            smokes: std::sync::atomic::AtomicUsize::new(0),
        }),
        Some(pool.clone()),
    )
    .with_store(Arc::clone(&store));
    let lines = Arc::new(Mutex::new(Vec::new()));
    let on_progress = {
        let lines = Arc::clone(&lines);
        move |progress: hf_service::FuzzProgress| {
            if let hf_service::FuzzProgress::LogLine(line) = progress {
                lines.lock().unwrap().push(line);
            }
        }
    };

    let outcome = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: Some("parse_entry"),
                engine: EngineKind::LibFuzzer,
                lang: Some(TargetLanguage::C),
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &noop_stage(),
            &on_progress,
        )
        .await
        .expect("the repaired harness qualifies and the campaign runs");

    assert_eq!(outcome.smoke_repairs, 1);
    assert_eq!(
        outcome.campaign.harness_status,
        hf_core::harness::HarnessStatus::Promoted
    );
    let repair = pool.prompts_containing("A previous attempt");
    assert_eq!(repair.len(), 1, "one smoke repair prompt");
    assert!(
        repair[0].contains("the entry point never ran"),
        "{}",
        repair[0]
    );
    assert!(
        lines
            .lock()
            .unwrap()
            .iter()
            .any(|line| line.contains("smoke repair 1/")),
        "the operator sees the repair: {:?}",
        lines.lock().unwrap()
    );
}

/// Grants only the sandboxed smoke run (and anything below an approval
/// prompt), and records every approval asked for: the GUI's one-click action
/// carries exactly this consent.
#[derive(Clone, Default)]
struct SmokeOnlyConsent {
    asked: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl hf_guardrails::ApprovalGate for SmokeOnlyConsent {
    async fn request_approval(&self, action: &hf_service::Action, _reason: &str) -> bool {
        self.asked
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(action.label());
        matches!(action, hf_service::Action::RunHarness)
    }
}

/// What a preparation reported, stage events and progress lines interleaved.
#[derive(Debug, Clone, PartialEq)]
enum Reported {
    Stage(FuzzStage),
    Line(String),
}

#[derive(Clone, Default)]
struct ReportLog {
    events: Arc<Mutex<Vec<Reported>>>,
}

impl ReportLog {
    fn stage_sink(&self) -> impl Fn(FuzzStage) + Send + Sync {
        let events = Arc::clone(&self.events);
        move |stage| {
            events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(Reported::Stage(stage));
        }
    }

    fn progress_sink(&self) -> impl Fn(hf_service::FuzzProgress) + Send + Sync {
        let events = Arc::clone(&self.events);
        move |progress| {
            if let hf_service::FuzzProgress::LogLine(line) = progress {
                events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(Reported::Line(line));
            }
        }
    }

    fn events(&self) -> Vec<Reported> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn steps(&self) -> Vec<HarnessStep> {
        self.events()
            .into_iter()
            .filter_map(|event| match event {
                Reported::Stage(FuzzStage::HarnessStep { step, .. }) => Some(step),
                _ => None,
            })
            .collect()
    }

    fn position(&self, wanted: &Reported) -> usize {
        self.events()
            .iter()
            .position(|event| event == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} was not reported: {:?}", self.events()))
    }
}

#[tokio::test]
async fn fuzz_prepare_reports_harness_steps_and_streams_compiler_output() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_steps_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);
    let log = ReportLog::default();

    container
        .fuzz_prepare(
            prepare_request(&project),
            &log.stage_sink(),
            &log.progress_sink(),
        )
        .await
        .expect("preparation completes");

    assert_eq!(
        log.steps(),
        vec![HarnessStep::Drafting, HarnessStep::Compiling { attempt: 1 }],
        "the harness stage reports drafting and each compile attempt"
    );
    let compiling = log.position(&Reported::Stage(FuzzStage::HarnessStep {
        target: "parse_entry".to_owned(),
        step: HarnessStep::Compiling { attempt: 1 },
    }));
    let output = log.position(&Reported::Line("DONE exec/s: 64".to_owned()));
    let smoke = log.position(&Reported::Stage(FuzzStage::Smoke {
        target: "parse_entry".to_owned(),
        engine: EngineKind::LibFuzzer,
    }));
    assert!(
        compiling < output && output < smoke,
        "compiler output streams during the compile attempt: {:?}",
        log.events()
    );
}

/// Like [`PipelineRuntime`], but the first harness compile fails with a
/// compiler diagnostic, so the repair loop runs once.
#[derive(Default)]
struct FailFirstCompileRuntime {
    compiles: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for FailFirstCompileRuntime {
    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        PipelineRuntime.resolve_image_reference(image).await
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let is_compile = cmd.iter().any(|arg| arg.contains("/work/'harness.c'"));
        if is_compile
            && self
                .compiles
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 0
        {
            return Ok(hf_core::runtime::CommandResult {
                exit_code: 1,
                stdout: String::new(),
                stderr: "harness.c:1: error: expected ';'".to_owned(),
                workspace: cwd.to_path_buf(),
                termination: hf_core::runtime::CommandTermination::Completed,
            });
        }
        PipelineRuntime.run_command(cmd, cwd, limits).await
    }

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        PipelineRuntime.write_file(path, content).await
    }

    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        PipelineRuntime.read_file(path).await
    }
}

#[tokio::test]
async fn fuzz_prepare_reports_a_failed_compile_and_its_repair() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_repair_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(FailFirstCompileRuntime::default()),
        Some(Arc::new(CodeBlockPool)),
    )
    .with_store(Arc::clone(&store));
    let log = ReportLog::default();

    container
        .fuzz_prepare(
            prepare_request(&project),
            &log.stage_sink(),
            &log.progress_sink(),
        )
        .await
        .expect("the repaired harness compiles");

    assert_eq!(
        log.steps(),
        vec![
            HarnessStep::Drafting,
            HarnessStep::Compiling { attempt: 1 },
            HarnessStep::CompileFailed { attempt: 1 },
            HarnessStep::Repairing {
                repair: 1,
                max: hf_service::FUZZ_PIPELINE_REPAIRS,
            },
            HarnessStep::Compiling { attempt: 2 },
        ]
    );
    let failed = log.position(&Reported::Stage(FuzzStage::HarnessStep {
        target: "parse_entry".to_owned(),
        step: HarnessStep::CompileFailed { attempt: 1 },
    }));
    let diagnostic = log.position(&Reported::Line(
        "harness.c:1: error: expected ';'".to_owned(),
    ));
    assert!(diagnostic < failed, "{:?}", log.events());
}

fn prepare_request(project: &std::path::Path) -> hf_service::FuzzPrepareRequest<'_> {
    hf_service::FuzzPrepareRequest {
        project,
        target: None,
        engine: EngineKind::LibFuzzer,
        lang: None,
        review_bypass: hf_service::HarnessReviewBypass::NotRequested,
        fresh: false,
        sanitizer: None,
        cmplog: false,
    }
}

#[tokio::test]
async fn fuzz_prepare_stops_before_approval_and_never_asks_for_it() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let consent = SmokeOnlyConsent::default();
    let container = pipeline_container(&store).with_guardrails(hf_guardrails::Guardrails::new(
        hf_guardrails::GuardrailPolicy::default(),
        Arc::new(consent.clone()),
    ));
    let log = StageLog::default();

    let prepared = container
        .fuzz_prepare(prepare_request(&project), &log.sink(), &noop_progress())
        .await
        .expect("preparation completes with a smoke-tested harness");

    assert_eq!(prepared.target, "parse_entry");
    assert_eq!(prepared.lang, TargetLanguage::C);
    assert_eq!(prepared.engine, EngineKind::LibFuzzer);
    assert!(!prepared.harness_reused);
    assert_eq!(
        log.stages(),
        vec![
            FuzzStage::Discover { lang: None },
            FuzzStage::Harness {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
                reused: false,
            },
            FuzzStage::Smoke {
                target: "parse_entry".to_owned(),
                engine: EngineKind::LibFuzzer,
            },
        ]
    );
    let asked = consent
        .asked
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        !asked
            .iter()
            .any(|label| label.contains("promote") || label.starts_with("run libfuzzer")),
        "preparation never asks to approve the harness or start a campaign: {asked:?}"
    );

    // Nothing was approved, so a campaign still refuses to run.
    let refused = container
        .run_campaign(
            &project,
            None,
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
        .await;
    assert!(refused.is_err(), "preparation must not approve the harness");
}

#[tokio::test]
async fn fuzz_prepare_reuses_an_approved_harness_without_smoke() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_reuse_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = pipeline_container(&store);
    container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &noop_stage(),
            &noop_progress(),
        )
        .await
        .expect("the first pipeline approves a harness");

    let log = StageLog::default();
    let prepared = container
        .fuzz_prepare(prepare_request(&project), &log.sink(), &noop_progress())
        .await
        .expect("preparation reuses the approved harness");
    assert!(prepared.harness_reused);
    assert!(
        !log.stages()
            .iter()
            .any(|stage| matches!(stage, FuzzStage::Smoke { .. })),
        "a reused approved harness is not smoke-tested again: {:?}",
        log.stages()
    );
}

/// [`PipelineRuntime`], except that any command given a run-owned output
/// mount leaves a crash reproducer there, as a smoke test of a target with a
/// shallow memory error does.
struct CrashingSmokeRuntime;

impl CrashingSmokeRuntime {
    fn leave_crash(opts: &hf_core::runtime::SandboxOptions) {
        if let Some(out) = opts
            .extra_mounts
            .iter()
            .find(|mount| mount.container_path.ends_with("/out"))
        {
            std::fs::write(out.host_path.join("crash-smoke-0001"), b"\xf0").unwrap();
        }
    }
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for CrashingSmokeRuntime {
    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        PipelineRuntime.resolve_image_reference(image).await
    }
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        PipelineRuntime.run_command(cmd, cwd, limits).await
    }
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Self::leave_crash(opts);
        PipelineRuntime.run_command(cmd, cwd, limits).await
    }
    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Self::leave_crash(opts);
        PipelineRuntime.run_command(cmd, cwd, limits).await
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        PipelineRuntime.write_file(path, content).await
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        PipelineRuntime.read_file(path).await
    }
}

/// A smoke test that finds a crash has found what the person came for. The
/// revision and its crash evidence are retained and can be approved with known
/// findings, so preparation reports the count instead of failing: the one-click
/// action otherwise ends on an error for a project whose bug is shallow.
#[tokio::test]
async fn fuzz_prepare_reports_smoke_crashes_as_a_reviewable_result() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_crash_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let consent = SmokeOnlyConsent::default();
    let container = ServiceContainer::new(
        Arc::new(CrashingSmokeRuntime),
        Some(Arc::new(CodeBlockPool)),
    )
    .with_store(Arc::clone(&store))
    .with_guardrails(hf_guardrails::Guardrails::new(
        hf_guardrails::GuardrailPolicy::default(),
        Arc::new(consent.clone()),
    ));

    let prepared = container
        .fuzz_prepare(prepare_request(&project), &noop_stage(), &noop_progress())
        .await
        .expect("a crash found by the smoke test is a result, not a preparation failure");

    assert_eq!(prepared.target, "parse_entry");
    assert!(!prepared.harness_reused);
    assert_eq!(prepared.smoke_crashes, 1);
    let asked = consent
        .asked
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        !asked.iter().any(|label| label.contains("promote")),
        "preparation never asks to approve a crash-bearing revision: {asked:?}"
    );
}

/// The unattended pipeline promotes on its own prompt, so it still stops on a
/// crash-bearing smoke test rather than promoting past it.
#[tokio::test]
async fn fuzz_onboard_still_stops_when_the_smoke_test_finds_a_crash() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_onboard_crash_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(CrashingSmokeRuntime),
        Some(Arc::new(CodeBlockPool)),
    )
    .with_store(Arc::clone(&store));
    let log = StageLog::default();

    let error = container
        .fuzz_onboard(
            FuzzRequest {
                prepared_harness: None,
                project: &project,
                target: None,
                engine: EngineKind::LibFuzzer,
                lang: None,
                duration_secs: 1,
                iterations: 1,
                timeout_ms: None,
                resume: None,
                review_bypass: hf_service::HarnessReviewBypass::NotRequested,
                fresh: false,
                sanitizer: None,
                cmplog: false,
                seed: None,
            },
            &log.sink(),
            &noop_progress(),
        )
        .await
        .expect_err("a crash-bearing revision is never promoted automatically");

    assert!(error.to_string().contains("found 1 crash(es)"), "{error}");
    // A presentation layer reads the stop back as a finding to report.
    assert_eq!(
        hf_service::smoke_crash_stop(&error),
        Some(hf_service::SmokeCrashStop {
            target: "parse_entry".to_owned(),
            crashes: 1,
        })
    );
    assert_eq!(
        hf_service::smoke_crash_stop(&hf_core::error::ClassifiedError::Validation(
            "fuzz smoke failed for 'parse_entry': hollow pass".to_owned()
        )),
        None
    );
    assert!(
        !log.stages()
            .iter()
            .any(|stage| matches!(stage, FuzzStage::Promote { .. })),
        "the promotion gate is never reached"
    );
}

/// [`PipelineRuntime`], recording every sandbox command line.
#[derive(Clone, Default)]
struct RecordingRuntime {
    commands: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for RecordingRuntime {
    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        PipelineRuntime.resolve_image_reference(image).await
    }
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(cmd.join(" "));
        PipelineRuntime.run_command(cmd, cwd, limits).await
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        PipelineRuntime.write_file(path, content).await
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        PipelineRuntime.read_file(path).await
    }
}

/// [`CodeBlockPool`], recording every request it is sent.
#[derive(Clone, Default)]
struct RecordingPool {
    requests: Arc<Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for RecordingPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(format!("{request:?}"));
        CodeBlockPool.chat_completion(request, route).await
    }
    async fn chat_completion_stream(
        &self,
        request: &hf_core::provider::ChatRequest,
        route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        CodeBlockPool.chat_completion_stream(request, route).await
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

/// A project that keeps its public header under `include/` and has no compile
/// database, the layout of the bundled `cmake_tlv_lib` example. Its sources
/// did not compile next to the harness, and the model was left to guess the
/// header's spelling.
#[tokio::test]
async fn fuzz_prepare_infers_the_include_directory_of_a_project_without_a_compile_database() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_include_it");
    let project = std::fs::canonicalize(dir.path()).unwrap().join("layout");
    std::fs::create_dir_all(project.join("include/pkt")).unwrap();
    std::fs::create_dir_all(project.join("src")).unwrap();
    std::fs::write(
        project.join("include/pkt/pkt.h"),
        "#include <stddef.h>\n#include <stdint.h>\nint parse_entry(const uint8_t *data, size_t size);\n",
    )
    .unwrap();
    std::fs::write(
        project.join("src/pkt.c"),
        "#include \"pkt/pkt.h\"\n\
         int parse_entry(const uint8_t *data, size_t size){ return size>0 && data[0]=='A'; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let runtime = RecordingRuntime::default();
    let pool = RecordingPool::default();
    let container = ServiceContainer::new(Arc::new(runtime.clone()), Some(Arc::new(pool.clone())))
        .with_store(Arc::clone(&store))
        .with_guardrails(hf_guardrails::Guardrails::new(
            hf_guardrails::GuardrailPolicy::default(),
            Arc::new(SmokeOnlyConsent::default()),
        ));

    container
        .fuzz_prepare(prepare_request(&project), &noop_stage(), &noop_progress())
        .await
        .expect("preparation completes");

    let commands = runtime
        .commands
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        commands
            .iter()
            .any(|command| command.contains("-I/work/include")),
        "the harness build searches the inferred include directory: {commands:#?}"
    );
    let requests = pool
        .requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    assert!(
        requests
            .iter()
            .any(|request| request.contains("include directories: include")),
        "the draft prompt names the include directory"
    );
    assert!(
        requests.iter().any(|request| request
            .contains("declared in the project header include/pkt/pkt.h")
            && request.contains("#include \\\"pkt/pkt.h\\\"")),
        "the draft prompt gives the exact include directive: {requests:#?}"
    );
}

/// Every compile fails in the project's own code, as an unconfigured
/// libxml2 does on its generated `xmlversion.h`.
struct ProjectBuildFailsRuntime;

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for ProjectBuildFailsRuntime {
    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        PipelineRuntime.resolve_image_reference(image).await
    }
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        Ok(hf_core::runtime::CommandResult {
            exit_code: 1,
            stdout: String::new(),
            stderr: "In file included from /work/parse.c:1:\n/work/api.h:16:10: fatal error: \
                     'version.h' file not found\n1 error generated."
                .to_owned(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }
    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        PipelineRuntime.write_file(path, content).await
    }
    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        PipelineRuntime.read_file(path).await
    }
}

#[tokio::test]
async fn fuzz_prepare_spends_no_repair_on_a_project_that_does_not_compile() {
    let dir = tempfile::tempdir().unwrap();
    let _workspace_root = common::install_managed_workspace("oxfuzz_fuzz_prepare_projfail_it");
    let project = c_project(&dir);
    let store = Arc::new(
        hf_storage::Store::connect(dir.path().join("fuzz.db"))
            .await
            .unwrap(),
    );
    let pool = RecordingPool::default();
    let container = ServiceContainer::new(
        Arc::new(ProjectBuildFailsRuntime),
        Some(Arc::new(pool.clone())),
    )
    .with_store(Arc::clone(&store));
    let log = ReportLog::default();

    let error = container
        .fuzz_prepare(
            prepare_request(&project),
            &log.stage_sink(),
            &log.progress_sink(),
        )
        .await
        .expect_err("the project does not compile");

    let message = error.to_string();
    assert!(message.contains("'version.h' file not found"), "{message}");
    assert!(message.contains("oxfuzz build diagnose"), "{message}");
    assert!(message.contains("Build Doctor"), "{message}");
    assert!(
        !log.steps()
            .iter()
            .any(|step| matches!(step, HarnessStep::Repairing { .. })),
        "no repair is attempted: {:?}",
        log.steps()
    );
    let drafts = pool
        .requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    assert_eq!(drafts, 1, "only the first draft reaches the model");
}
