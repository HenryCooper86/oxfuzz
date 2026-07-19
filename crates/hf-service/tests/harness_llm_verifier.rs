//! Integration test for the LLM harness verifier (`verify_harness_source`).

use std::sync::Arc;

use hf_core::harness::SmokeRunSummary;
use hf_service::{HarnessVerdict, ServiceContainer, VerdictLevel};

/// A pool that always judges the harness hollow (does not exercise the target).
struct HollowOpinionPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for HollowOpinionPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Ok(hf_test_utils::fixtures::make_chat_response(
            "{\"exercises_target\": false, \"reasons\": [\"ignores data/size\"]}",
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

/// A pool that panics if the model is ever called -- proves the verifier skips
/// the LLM for a non-`Pass` verdict.
struct PanicPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for PanicPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        panic!("the LLM harness verifier must not run on a non-Pass verdict");
    }
    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        panic!("unused");
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

fn smoke_summary(execs_per_sec: f64) -> SmokeRunSummary {
    SmokeRunSummary {
        duration_secs: 5,
        execs_per_sec,
        crashes: 0,
        passed: true,
        source_sha256: None,
        binary_sha256: None,
        run_id: None,
    }
}

fn pass() -> HarnessVerdict {
    HarnessVerdict {
        level: VerdictLevel::Pass,
        reasons: vec!["exercised at 5000 execs/sec".to_owned()],
    }
}

#[tokio::test]
async fn the_llm_downgrades_a_pass_it_judges_hollow() {
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::new(HollowOpinionPool)),
    );
    let merged = container
        .verify_harness_source(
            "parse_header",
            "harness source",
            &smoke_summary(5000.0),
            pass(),
        )
        .await;
    assert_eq!(merged.level, VerdictLevel::Suspect, "{merged:?}");
    assert!(
        merged
            .reasons
            .iter()
            .any(|r| r.contains("ignores data/size")),
        "carries the LLM reason: {merged:?}"
    );
}

#[tokio::test]
async fn without_a_provider_the_deterministic_verdict_is_unchanged() {
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);
    let merged = container
        .verify_harness_source("t", "src", &smoke_summary(5000.0), pass())
        .await;
    assert_eq!(merged, pass(), "best-effort: no provider -> no change");
}

#[tokio::test]
async fn a_non_pass_verdict_skips_the_llm_entirely() {
    // The PanicPool asserts the model is never called; the Suspect must survive
    // unchanged, proving the verifier is cost-bounded to Pass verdicts.
    let container =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), Some(Arc::new(PanicPool)));
    let suspect = HarnessVerdict {
        level: VerdictLevel::Suspect,
        reasons: vec!["hollow pass: near-zero execs".to_owned()],
    };
    let merged = container
        .verify_harness_source("t", "src", &smoke_summary(0.0), suspect.clone())
        .await;
    assert_eq!(merged, suspect);
}
