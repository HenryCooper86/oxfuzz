//! The header snapshot uses live pool evidence, not saved configuration or model totals.
use std::sync::Arc;

use hf_core::provider::{ChatRequest, ProviderPool, RouteRequest};
use hf_provider::{ProviderPoolConfig, ProviderPoolImpl};
use hf_service::ServiceContainer;

#[tokio::test]
async fn snapshot_uses_live_provider_metadata_and_usage() {
    let pool = Arc::new(ProviderPoolImpl::from_providers(
        vec![Arc::new(hf_test_utils::mock_provider::MockProvider::fixed(
            "hello",
        ))],
        &ProviderPoolConfig::default(),
    ));
    let response = pool
        .chat_completion(
            &ChatRequest::from_messages(vec![]),
            &RouteRequest::default(),
        )
        .await
        .unwrap();
    let service = ServiceContainer::stubbed().with_provider_pool(pool);
    let snapshot = service.system_snapshot().await.unwrap();
    let provider = &snapshot.providers[0];
    assert_eq!(provider.model, "mock-model");
    assert_eq!(provider.tags, ["test"]);
    assert_eq!(provider.max_concurrency, 10);
    assert_eq!(provider.total_requests, 1);
    assert_eq!(
        provider.total_input_tokens,
        u64::from(response.usage.input_tokens)
    );
    assert_eq!(
        provider.total_output_tokens,
        u64::from(response.usage.output_tokens)
    );
}

#[tokio::test]
async fn registered_agents_are_not_reported_as_execution_capacity() {
    let service = ServiceContainer::stubbed();
    let _turn = service.track_agent("review");
    let snapshot = serde_json::to_value(service.system_snapshot().await.unwrap()).unwrap();
    assert_eq!(
        snapshot["agents"]["registered_definitions"],
        service.list_agent_definitions().len()
    );
    assert!(snapshot["agents"].get("available_slots").is_none());
    assert_eq!(snapshot["agents"]["active_instances"], 1);
    assert!(snapshot["agents"]["instances"][0]
        .get("tokens_used")
        .is_none());
}

struct PricedProvider {
    inner: hf_test_utils::mock_provider::MockProvider,
    metadata: hf_core::provider::ProviderMetadata,
}

impl PricedProvider {
    fn new(id: &str) -> Self {
        use hf_core::provider::LlmProvider;
        let inner = hf_test_utils::mock_provider::MockProvider::fixed("a test response");
        let mut metadata = inner.metadata().clone();
        metadata.id = hf_core::types::ProviderId::from_string(id);
        metadata.cost_per_1k_input = 1.0;
        metadata.cost_per_1k_output = 2.0;
        Self { inner, metadata }
    }
}

#[async_trait::async_trait]
impl hf_core::provider::LlmProvider for PricedProvider {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.inner.chat_completion(request).await
    }
    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        self.inner.chat_completion_stream(request).await
    }
    fn metadata(&self) -> &hf_core::provider::ProviderMetadata {
        &self.metadata
    }
}

#[tokio::test]
async fn providers_sharing_a_model_keep_separate_usage_and_cost() {
    let pool = Arc::new(ProviderPoolImpl::from_providers(
        vec![
            Arc::new(PricedProvider::new("first")),
            Arc::new(PricedProvider::new("second")),
        ],
        &ProviderPoolConfig::default(),
    ));
    for id in ["first", "second", "second"] {
        pool.chat_completion(
            &ChatRequest::from_messages(vec![]),
            &RouteRequest {
                pinned_provider_id: Some(hf_core::types::ProviderId::from_string(id)),
                ..RouteRequest::default()
            },
        )
        .await
        .unwrap();
    }
    let service = ServiceContainer::stubbed().with_provider_pool(pool);
    let snapshot = service.system_snapshot().await.unwrap();
    let first = snapshot.providers.iter().find(|p| p.id == "first").unwrap();
    let second = snapshot
        .providers
        .iter()
        .find(|p| p.id == "second")
        .unwrap();
    assert_eq!(first.model, second.model);
    assert_eq!(first.total_requests, 1);
    assert_eq!(second.total_requests, 2);
    assert!(first.total_output_tokens > 0);
    assert_eq!(second.total_output_tokens, first.total_output_tokens * 2);
    assert!(first.estimated_cost_usd > 0.0);
    assert!((second.estimated_cost_usd - first.estimated_cost_usd * 2.0).abs() < 0.000_001);
}
