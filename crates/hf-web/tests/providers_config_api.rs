//! Providers config REST surface, isolated in its own test binary because the
//! had-pool-then-none verdict depends on process-global config-dir
//! environment variables that must not leak into other api tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn allow_open_dev_mode() {
    // SAFETY: tests in this binary only ever set this to "1" and never set
    // HF_WEB_TOKEN, so there is no conflicting concurrent mutation.
    unsafe {
        std::env::set_var("HF_WEB_TOKEN_OPTIONAL", "1");
    }
}

/// A provider pool that panics if reached: the providers tests only observe
/// whether a pool was loaded, never call it.
struct UnreachedPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for UnreachedPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        panic!("the providers tests never call the pool");
    }

    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        panic!("the providers tests never call the pool");
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
async fn disabling_every_provider_succeeds_even_with_a_loaded_pool() {
    allow_open_dev_mode();
    // Replacing a loaded pool with an intentionally all-disabled set is the
    // documented shutdown path and must stay a success; the had-pool-then-none
    // transition that IS an error (a failed reload of enabled providers) is
    // the one save_config reports.
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", dir.path());
    std::env::remove_var("HF_PROVIDER_API_KEY");

    let container = hf_service::ServiceContainer::stubbed()
        .with_provider_pool(std::sync::Arc::new(UnreachedPool));
    let app = hf_web::router::build_with_state(hf_web::router::AppState::new(container));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config/providers")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"providers":[{"id":"a","provider_type":"openai","model":"gpt-test","enabled":false}]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "an intentional all-disabled shutdown is a success, not a failed reload"
    );
}
