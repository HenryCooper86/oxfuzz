#![cfg(feature = "model-budgets")]

use hf_core::provider::{ChatRequest, ProviderError, ProviderPool, RouteRequest};
use hf_provider::{ProviderPoolConfig, ProviderPoolImpl};
use hf_service::model_budget::{budget_providers, ModelBudgetSettings};
use hf_storage::Store;
use hf_test_utils::mock_provider::MockProvider;
use std::sync::Arc;

async fn fixture(max_calls: u64) -> (tempfile::TempDir, Arc<Store>, ModelBudgetSettings) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(directory.path().join("budget.db"))
            .await
            .unwrap(),
    );
    let settings = ModelBudgetSettings {
        scope_id: Some("trial-1".into()),
        max_calls: Some(max_calls),
        ..ModelBudgetSettings::default()
    };
    (directory, store, settings)
}

fn pool(
    store: Arc<Store>,
    settings: ModelBudgetSettings,
    mock: Arc<MockProvider>,
) -> ProviderPoolImpl {
    ProviderPoolImpl::from_providers(
        budget_providers(vec![mock], settings, store).unwrap(),
        &ProviderPoolConfig::default(),
    )
}

fn request() -> ChatRequest {
    ChatRequest::from_messages(vec![hf_core::types::Message::user("input")])
}
fn route() -> RouteRequest {
    RouteRequest::default()
}

#[tokio::test]
async fn concurrent_requests_share_durable_call_allowance() {
    let (_directory, store, settings) = fixture(1).await;
    let mock = Arc::new(MockProvider::fixed("done"));
    let pool = Arc::new(pool(store.clone(), settings, mock.clone()));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let pool = pool.clone();
        tasks.spawn(async move { pool.chat_completion(&request(), &route()).await });
    }
    let mut admitted = 0;
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            Ok(_) => admitted += 1,
            Err(ProviderError::ModelBudgetDenied { .. }) => {}
            Err(error) => panic!("unexpected error: {error}"),
        }
    }
    assert_eq!(admitted, 1);
    assert_eq!(mock.call_count(), 1);
    let snapshot = store
        .model_budget_snapshot("trial-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.calls, 1);
    assert_eq!(snapshot.terminal_reason.as_deref(), Some("calls_exhausted"));
}

#[tokio::test]
async fn retries_reserve_each_attempt_without_freezing_budget_denial() {
    let (_directory, store, settings) = fixture(1).await;
    let mock = Arc::new(MockProvider::failing("temporary upstream failure"));
    let pool = pool(store, settings, mock.clone());
    assert!(matches!(
        pool.chat_completion(&request(), &route()).await,
        Err(ProviderError::ModelBudgetDenied { .. })
    ));
    assert_eq!(mock.call_count(), 1);
    assert!(!pool.provider_statuses().await[0].is_frozen);
}

#[tokio::test]
async fn reopening_database_does_not_reset_spend() {
    let (directory, store, settings) = fixture(1).await;
    let first = pool(
        store,
        settings.clone(),
        Arc::new(MockProvider::fixed("done")),
    );
    first.chat_completion(&request(), &route()).await.unwrap();
    drop(first);
    let store = Arc::new(
        Store::connect(directory.path().join("budget.db"))
            .await
            .unwrap(),
    );
    let mock = Arc::new(MockProvider::fixed("done"));
    let restarted = pool(store, settings, mock.clone());
    assert!(matches!(
        restarted.chat_completion(&request(), &route()).await,
        Err(ProviderError::ModelBudgetDenied { .. })
    ));
    assert_eq!(mock.call_count(), 0);
}

#[tokio::test]
async fn dollar_limit_rejects_unknown_prices_before_dispatch() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_cost_microusd = Some(1_000_000);
    let mock = Arc::new(MockProvider::fixed("done"));
    let pool = pool(store, settings, mock.clone());
    let error = pool
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unknown_pricing"));
    assert_eq!(mock.call_count(), 0);
}

#[tokio::test]
async fn changed_limits_cannot_reset_an_existing_scope() {
    let (_directory, store, settings) = fixture(1).await;
    pool(
        store.clone(),
        settings.clone(),
        Arc::new(MockProvider::fixed("done")),
    )
    .chat_completion(&request(), &route())
    .await
    .unwrap();
    let mock = Arc::new(MockProvider::fixed("done"));
    let mut changed = settings;
    changed.max_calls = Some(10);
    let error = pool(store, changed, mock.clone())
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("scope_limits_changed"));
    assert_eq!(mock.call_count(), 0);
}

#[tokio::test]
async fn token_limit_denies_worst_case_before_dispatch() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_tokens = Some(4096);
    let mock = Arc::new(MockProvider::fixed("done"));
    let error = pool(store, settings, mock.clone())
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("tokens_exhausted"));
    assert_eq!(mock.call_count(), 0);
}

#[tokio::test]
async fn successful_usage_refunds_unused_tokens_but_not_call_count() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_tokens = Some(8192);
    let provider = pool(
        store.clone(),
        settings,
        Arc::new(MockProvider::fixed("done")),
    );
    let first = provider
        .chat_completion(&request(), &route())
        .await
        .unwrap();
    let second = provider
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    // A second request still needs the full context plus output reservation;
    // even the first response's one charged token leaves insufficient room.
    assert!(second.to_string().contains("tokens_exhausted"));
    let snapshot = store
        .model_budget_snapshot("trial-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.calls, 1);
    assert_eq!(snapshot.tokens, i64::from(first.usage.total()));
}

#[tokio::test]
async fn dropped_stream_keeps_its_reservation_after_restart() {
    let (directory, store, mut settings) = fixture(5).await;
    settings.max_tokens = Some(8192);
    let provider = pool(
        store.clone(),
        settings.clone(),
        Arc::new(MockProvider::fixed("done")),
    );
    let response = provider
        .chat_completion_stream(&request(), &route())
        .await
        .unwrap();
    drop(response);
    drop(provider);
    let reopened = Arc::new(
        Store::connect(directory.path().join("budget.db"))
            .await
            .unwrap(),
    );
    let mock = Arc::new(MockProvider::fixed("done"));
    let error = pool(reopened, settings, mock.clone())
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("tokens_exhausted"));
    assert_eq!(mock.call_count(), 0);
    assert_eq!(
        store
            .model_budget_snapshot("trial-1")
            .await
            .unwrap()
            .unwrap()
            .tokens,
        8192
    );
}

#[tokio::test]
async fn paid_health_probes_share_the_workflow_allowance() {
    let (_directory, store, settings) = fixture(1).await;
    let mock = Arc::new(MockProvider::fixed("done"));
    let provider = pool(store, settings, mock.clone());
    provider
        .chat_completion(&request(), &route())
        .await
        .unwrap();
    let id = provider.provider_statuses().await[0].id.clone();
    provider.freeze(&id, "test health recovery".into()).await;
    let error = provider.thaw(&id).await.unwrap_err();
    assert!(error.to_string().contains("calls_exhausted"));
    assert_eq!(mock.call_count(), 1);
}

#[tokio::test]
async fn metered_model_override_cannot_use_an_unpriced_model() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_tokens = Some(100_000);
    let mock = Arc::new(MockProvider::fixed("done"));
    let mut req = request();
    req.model = Some("different-model".into());
    let error = pool(store, settings, mock.clone())
        .chat_completion(&req, &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("unbounded_request_parameters"));
    assert_eq!(mock.call_count(), 0);
}

struct PricedProvider {
    inner: MockProvider,
    metadata: hf_core::provider::ProviderMetadata,
    estimated: bool,
}

impl PricedProvider {
    fn new(text: &str) -> Self {
        use hf_core::provider::LlmProvider;
        let inner = MockProvider::fixed(text);
        let mut metadata = inner.metadata().clone();
        metadata.cost_per_1k_input = 1.0;
        metadata.cost_per_1k_output = 1.0;
        Self {
            inner,
            metadata,
            estimated: false,
        }
    }
}

#[async_trait::async_trait]
impl hf_core::provider::LlmProvider for PricedProvider {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
    ) -> Result<hf_core::provider::ChatResponse, ProviderError> {
        let mut response = self.inner.chat_completion(request).await?;
        if self.estimated {
            response.usage.source = hf_core::types::TokenUsageSource::Estimated;
        }
        Ok(response)
    }
    async fn chat_completion_stream(
        &self,
        request: &ChatRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, ProviderError> {
        self.inner.chat_completion_stream(request).await
    }
    fn metadata(&self) -> &hf_core::provider::ProviderMetadata {
        &self.metadata
    }
}

fn priced_pool(
    store: Arc<Store>,
    settings: ModelBudgetSettings,
    provider: Arc<PricedProvider>,
) -> ProviderPoolImpl {
    ProviderPoolImpl::from_providers(
        budget_providers(vec![provider], settings, store).unwrap(),
        &ProviderPoolConfig::default(),
    )
}

#[tokio::test]
async fn priced_request_is_denied_before_upstream_when_reservation_exceeds_dollars() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_cost_microusd = Some(8_191_999);
    let mock = Arc::new(PricedProvider::new("done"));
    let error = priced_pool(store, settings, mock.clone())
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cost_exhausted"));
    assert_eq!(mock.inner.call_count(), 0);
}

#[tokio::test]
async fn completed_usage_refunds_cost_allowing_the_next_reservation() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_cost_microusd = Some(10_000_000);
    let provider = priced_pool(
        store.clone(),
        settings,
        Arc::new(PricedProvider::new("done")),
    );
    provider
        .chat_completion(&request(), &route())
        .await
        .unwrap();
    provider
        .chat_completion(&request(), &route())
        .await
        .unwrap();
    let snapshot = store
        .model_budget_snapshot("trial-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.calls, 2);
    assert_eq!(snapshot.tokens, 4);
    assert_eq!(snapshot.cost_microusd, 4000);
}

#[tokio::test]
async fn estimated_usage_cannot_refund_a_reservation() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_cost_microusd = Some(10_000_000);
    let mut mock = PricedProvider::new("done");
    mock.estimated = true;
    let provider = priced_pool(store.clone(), settings, Arc::new(mock));
    provider
        .chat_completion(&request(), &route())
        .await
        .unwrap();
    let snapshot = store
        .model_budget_snapshot("trial-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.tokens, 8192);
    assert_eq!(snapshot.cost_microusd, 8_192_000);
}

#[tokio::test]
async fn usage_beyond_reservation_blocks_further_requests() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_output_tokens = 1;
    let mock = Arc::new(MockProvider::fixed("long output with many tokens"));
    let provider = pool(store.clone(), settings, mock.clone());
    let error = provider
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("usage_exceeded_reservation"));
    let error = provider
        .chat_completion(&request(), &route())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("usage_exceeded_reservation"));
    assert_eq!(mock.call_count(), 1);
    assert!(
        store
            .model_budget_snapshot("trial-1")
            .await
            .unwrap()
            .unwrap()
            .blocked
    );
}

#[tokio::test]
async fn separate_connections_cannot_reserve_the_same_allowance() {
    let (directory, first_store, settings) = fixture(1).await;
    let second_store = Arc::new(
        Store::connect(directory.path().join("budget.db"))
            .await
            .unwrap(),
    );
    let first = pool(
        first_store.clone(),
        settings.clone(),
        Arc::new(MockProvider::fixed("done")),
    );
    let second = pool(
        second_store,
        settings,
        Arc::new(MockProvider::fixed("done")),
    );
    let request = request();
    let route = route();
    let (a, b) = tokio::join!(
        first.chat_completion(&request, &route),
        second.chat_completion(&request, &route)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        first_store
            .model_budget_snapshot("trial-1")
            .await
            .unwrap()
            .unwrap()
            .calls,
        1
    );
}

#[tokio::test]
async fn partial_usage_cannot_refund_unknown_input_tokens() {
    let (_directory, store, mut settings) = fixture(5).await;
    settings.max_tokens = Some(8192);
    let provider = pool(
        store.clone(),
        settings,
        Arc::new(MockProvider::fixed("done")),
    );
    let empty = ChatRequest::from_messages(vec![]);
    provider.chat_completion(&empty, &route()).await.unwrap();
    assert_eq!(
        store
            .model_budget_snapshot("trial-1")
            .await
            .unwrap()
            .unwrap()
            .tokens,
        8192
    );
}

#[tokio::test]
async fn repeated_settlement_does_not_refund_twice() {
    let (_directory, store, settings) = fixture(5).await;
    let provider = pool(
        store.clone(),
        settings,
        Arc::new(MockProvider::fixed("done")),
    );
    provider
        .chat_completion(&request(), &route())
        .await
        .unwrap();
    let id: String =
        sqlx::query_scalar("SELECT id FROM model_budget_attempts WHERE scope_id = 'trial-1'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    store
        .settle_model_budget(uuid::Uuid::parse_str(&id).unwrap(), 1, 1, 0)
        .await
        .unwrap();
    let snapshot = store
        .model_budget_snapshot("trial-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot.tokens, 2);
    assert_eq!(snapshot.calls, 1);
}
