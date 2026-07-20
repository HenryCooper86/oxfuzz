//! Integration test for the LLM crash verifier (`ServiceContainer::verify_crashes`).

use std::path::PathBuf;
use std::sync::Arc;

use hf_core::crash::{CasrReport, Crash, CrashKind, CrashSeverity};
use hf_service::{Confidence, ServiceContainer};
use uuid::Uuid;

/// A pool that returns a fixed, well-formed crash verdict for every completion.
struct VerdictPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for VerdictPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Ok(hf_test_utils::fixtures::make_chat_response(
            "{\"reproduces_deterministically\": true, \"likely_target_bug\": true, \
             \"confidence\": \"high\", \"reasons\": [\"deterministic ASan overflow\"]}",
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

fn asan_crash() -> Crash {
    Crash {
        id: Uuid::nil(),
        run_id: Uuid::nil(),
        target_id: Uuid::nil(),
        input_path: PathBuf::from("/work/out/crash-001"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow in parse_header".to_owned(),
        minimized: true,
        bug_report: None,
        casr: Some(CasrReport {
            severity: CrashSeverity::Exploitable,
            severity_short: "heap-buffer-overflow(write)".to_owned(),
            crashline: "src/parse.c:48:5".to_owned(),
            stack: vec!["parse_header".to_owned(), "main".to_owned()],
            cluster: None,
        }),
    }
}

#[tokio::test]
async fn verify_crashes_parses_the_llm_verdict_per_crash() {
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(VerdictPool)),
    );
    let crashes = vec![asan_crash(), asan_crash()];
    let verdicts = container.verify_crashes("parse_header", &crashes).await;
    assert_eq!(verdicts.len(), crashes.len(), "one verdict slot per crash");
    for verdict in verdicts {
        let verdict = verdict.expect("the LLM verdict is parsed for each crash");
        assert!(verdict.reproduces_deterministically && verdict.likely_target_bug);
        assert_eq!(verdict.confidence, Confidence::High);
    }
}

#[tokio::test]
async fn verify_crashes_yields_no_opinion_without_a_provider() {
    // Best-effort: with no LLM configured there are no fabricated verdicts.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let verdicts = container
        .verify_crashes("parse_header", &[asan_crash()])
        .await;
    assert_eq!(verdicts, vec![None]);
}

#[tokio::test]
async fn verify_crash_returns_the_single_crash_verdict() {
    // L2 4c: the on-demand per-crash wrapper returns just that crash's verdict.
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(VerdictPool)),
    );
    let verdict = container
        .verify_crash("parse_header", &asan_crash())
        .await
        .expect("a verdict for the single crash");
    assert!(verdict.reproduces_deterministically && verdict.likely_target_bug);
    assert_eq!(verdict.confidence, Confidence::High);
}
