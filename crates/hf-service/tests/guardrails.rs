//! Guardrail authorization wiring for the low-risk service entry points:
//! target discovery, harness drafting, corpus operations, and chat.
//!
//! The default policy auto-allows these tiers (AGENTS.md 2.5), so behavior is
//! unchanged under default/permissive guardrails; a policy that denies the
//! tier must block the operation through the same
//! `GuardrailError -> ClassifiedError::Validation` mapping the already-gated
//! execution actions (compile/run/triage) use.

use std::sync::{Arc, Mutex};

use hf_guardrails::{Action, ApprovalGate, GuardrailPolicy, Guardrails, RiskTier};
use hf_service::{ClassifiedError, EngineKind, ServiceContainer, TargetLanguage};

/// An approval gate that records every action it is consulted about. These
/// low-risk actions never reach a gate under the default policy, so an empty
/// log after an operation proves no approval prompt was introduced.
#[derive(Default)]
struct RecordingGate {
    consulted: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ApprovalGate for RecordingGate {
    async fn request_approval(&self, action: &Action, _reason: &str) -> bool {
        self.consulted.lock().unwrap().push(action.label());
        false
    }
}

/// A container on the default policy (auto-allow Medium and below) backed by
/// the recording gate.
fn default_container(
    pool: Option<Arc<dyn hf_core::provider::ProviderPool>>,
) -> (ServiceContainer, Arc<RecordingGate>) {
    let gate = Arc::new(RecordingGate::default());
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), pool).with_guardrails(
        Guardrails::new(
            GuardrailPolicy::default(),
            Arc::clone(&gate) as Arc<dyn ApprovalGate>,
        ),
    );
    (container, gate)
}

/// Attach a temporary persistent store, so decision recording is exercised
/// end to end through the public service API.
async fn with_temp_store(container: ServiceContainer) -> (ServiceContainer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let container = container
        .with_store_path(dir.path().join("decisions.db"))
        .await
        .unwrap();
    (container, dir)
}

/// A container on a policy that denies every action at or above Low risk, so
/// any authorized operation is blocked outright before it executes.
fn strict_container(
    pool: Option<Arc<dyn hf_core::provider::ProviderPool>>,
) -> (ServiceContainer, Arc<RecordingGate>) {
    let gate = Arc::new(RecordingGate::default());
    let policy = GuardrailPolicy {
        auto_allow_max: RiskTier::Low,
        deny_at: Some(RiskTier::Low),
    };
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), pool).with_guardrails(
        Guardrails::new(policy, Arc::clone(&gate) as Arc<dyn ApprovalGate>),
    );
    (container, gate)
}

/// The denial must surface through the same mapping the execution actions use:
/// `GuardrailError::Denied` -> `ClassifiedError::Validation`, naming the action.
fn assert_guardrail_denied(error: &ClassifiedError, action_label: &str) {
    let message = error.to_string();
    assert!(
        matches!(error, ClassifiedError::Validation(_)),
        "a guardrail denial maps to a validation error, got {error}"
    );
    assert!(
        message.contains("guardrail denied"),
        "expected a guardrail denial, got: {message}"
    );
    assert!(
        message.contains(action_label),
        "the denial must name the '{action_label}' action, got: {message}"
    );
}

const FIXTURE: &str = r"
#include <stddef.h>
#include <stdint.h>

// A parser-shaped function: a byte buffer + length is an obvious fuzz target.
int parse_value(const uint8_t *data, size_t len) {
    if (len >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        return 1;
    }
    return 0;
}
";

fn fixture_project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("parser.c"), FIXTURE).unwrap();
    project
}

/// Redirect the fuzz workspace to a temp dir for the duration of the test
/// process, so corpus operations don't pollute the real per-user data dir.
fn isolate_workspace() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_guardrails_it_{}_{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        let initialized = hf_service::initialize_workspace_root()
            .expect("initialize managed integration-test workspace");
        assert_eq!(initialized, std::fs::canonicalize(&root).unwrap());
    });
}

/// A provider pool that answers every chat with a fixed reply, so chat tests
/// don't depend on provider routing.
struct ChatPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for ChatPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Ok(hf_core::provider::ChatResponse {
            id: uuid::Uuid::new_v4().to_string(),
            model: "mock-model".to_owned(),
            content: Some("ok".to_owned()),
            reasoning_content: None,
            tool_calls: Vec::new(),
            usage: hf_core::types::TokenUsage::default(),
            finish_reason: hf_core::provider::FinishReason::Stop,
            raw_request: None,
            raw_response: None,
            provider_id: None,
            generated_images: Vec::new(),
        })
    }

    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "streaming not used by chat_send".to_owned(),
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
async fn default_policy_allows_discover_without_prompting() {
    let (container, gate) = default_container(None);
    let project = fixture_project();

    let inventory = container
        .discover(project.path(), TargetLanguage::C)
        .await
        .unwrap();

    assert!(inventory
        .candidates
        .iter()
        .any(|c| c.symbol == "parse_value"));
    assert!(
        gate.consulted.lock().unwrap().is_empty(),
        "discovery is auto-allowed under the default policy"
    );
}

#[tokio::test]
async fn strict_policy_denies_discover() {
    let (container, _gate) = strict_container(None);
    let project = fixture_project();

    let error = container
        .discover(project.path(), TargetLanguage::C)
        .await
        .unwrap_err();

    assert_guardrail_denied(&error, "discover targets");
}

#[tokio::test]
async fn default_policy_allows_harness_draft_without_prompting() {
    let (container, gate) = default_container(None);
    let project = fixture_project();

    let draft = container
        .harness_draft(
            project.path(),
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();

    assert!(draft.source.contains("parse_value"));
    assert!(
        gate.consulted.lock().unwrap().is_empty(),
        "harness drafting is auto-allowed under the default policy"
    );
}

#[tokio::test]
async fn strict_policy_denies_harness_draft() {
    let (container, _gate) = strict_container(None);
    let project = fixture_project();

    let error = container
        .harness_draft(
            project.path(),
            "parse_value",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap_err();

    assert_guardrail_denied(&error, "draft harness");
}

#[tokio::test]
async fn default_policy_allows_corpus_operations_without_prompting() {
    isolate_workspace();
    let (container, gate) = default_container(None);
    let project = fixture_project();
    let target = "parse_value";

    assert_eq!(
        container.corpus_seed(project.path(), target).await.unwrap(),
        2
    );
    container.corpus_grow(project.path(), target).await.unwrap();
    container
        .corpus_prune(project.path(), target)
        .await
        .unwrap();
    container
        .corpus_absorb_crashes(project.path(), target)
        .await
        .unwrap();
    // The coverage/merge minimizers short-circuit on an empty corpus before
    // needing a promoted harness or the sandbox, so a fresh target exercises
    // only the guardrail and the early return.
    let fresh_workspace = hf_service::workspace_dir(project.path(), "fresh_target");
    std::fs::create_dir_all(&fresh_workspace).unwrap();
    let coverage = container
        .corpus_prune_coverage(project.path(), "fresh_target")
        .await
        .unwrap();
    assert_eq!(coverage.after, 0);
    let minimized = container
        .corpus_minimize(project.path(), "fresh_target")
        .await
        .unwrap();
    assert_eq!(minimized.after, 0);
    assert!(
        gate.consulted.lock().unwrap().is_empty(),
        "corpus operations are auto-allowed under the default policy"
    );
}

#[tokio::test]
async fn strict_policy_denies_corpus_operations() {
    isolate_workspace();
    let (container, _gate) = strict_container(None);
    let project = fixture_project();
    let target = "parse_value";

    let error = container
        .corpus_seed(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
    let error = container
        .corpus_grow(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
    let error = container
        .corpus_prune(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
    let error = container
        .corpus_prune_coverage(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
    let error = container
        .corpus_minimize(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
    let error = container
        .corpus_absorb_crashes(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
}

/// `corpus_concolic` authorizes `CorpusOp` before it does anything else --
/// before the toolchain availability probe, before it looks for a promoted
/// harness, before it touches the sandbox at all -- so a policy that denies
/// `CorpusOp` blocks it exactly like every sibling corpus operation, with no
/// project store or promoted harness required to reach the denial.
#[cfg(feature = "concolic-enrichment")]
#[tokio::test]
async fn strict_policy_denies_corpus_concolic() {
    isolate_workspace();
    let (container, _gate) = strict_container(None);
    let project = fixture_project();
    let target = "parse_value";

    let error = container
        .corpus_concolic(project.path(), target)
        .await
        .unwrap_err();
    assert_guardrail_denied(&error, "corpus operation");
}

#[tokio::test]
async fn default_policy_allows_chat_send_without_prompting() {
    let (container, gate) = default_container(Some(Arc::new(ChatPool)));

    let reply = container.chat_send("hello").await.unwrap();

    assert_eq!(reply, "ok");
    assert!(
        gate.consulted.lock().unwrap().is_empty(),
        "chat is auto-allowed under the default policy"
    );
}

#[tokio::test]
async fn strict_policy_denies_chat_send() {
    let (container, _gate) = strict_container(None);

    let error = container.chat_send("hello").await.unwrap_err();

    assert_guardrail_denied(&error, "chat turn");
}

#[tokio::test]
async fn strict_policy_denies_external_finding_publication_before_integration_io() {
    let (container, _gate) = strict_container(None);
    let project = fixture_project();

    let issue_error = container.file_issue("missing-crash").await.unwrap_err();
    assert_guardrail_denied(&issue_error, "publish findings to issue-tracker");

    let defectdojo_error = container
        .push_to_defectdojo(project.path(), None)
        .await
        .unwrap_err();
    assert_guardrail_denied(&defectdojo_error, "publish findings to defectdojo");
}

#[tokio::test]
async fn default_policy_records_an_allowed_decision() {
    let (container, _gate) = default_container(None);
    let (container, _dir) = with_temp_store(container).await;
    let project = fixture_project();

    container
        .discover(project.path(), TargetLanguage::C)
        .await
        .unwrap();

    let rows = container.policy_decisions(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];
    assert_eq!(row.action, "discover");
    assert_eq!(row.risk_tier, "low");
    assert_eq!(row.decision, "allowed");
    assert_eq!(row.origin, "discover");
    assert_eq!(
        row.project.as_deref(),
        Some(project.path().to_string_lossy().as_ref())
    );
}

#[tokio::test]
async fn strict_policy_records_the_denial_and_the_operation_still_fails() {
    let (container, _gate) = strict_container(None);
    let (container, _dir) = with_temp_store(container).await;
    let project = fixture_project();

    let error = container
        .discover(project.path(), TargetLanguage::C)
        .await
        .unwrap_err();

    assert_guardrail_denied(&error, "discover targets");
    let rows = container.policy_decisions(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].decision, "denied");
    assert_eq!(rows[0].action, "discover");
}

#[tokio::test]
async fn chat_send_succeeds_when_the_decision_store_is_broken() {
    let (container, _gate) = default_container(Some(Arc::new(ChatPool)));
    let (container, _dir) = with_temp_store(container).await;
    container.store().unwrap().pool().close().await;

    let reply = container.chat_send("hello").await.unwrap();

    assert_eq!(
        reply, "ok",
        "a broken decision store must not change the outcome"
    );
}
