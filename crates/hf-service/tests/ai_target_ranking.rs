#![cfg(feature = "ai-target-ranking")]

use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, ProviderError, ProviderPool, ProviderStatus,
    RouteRequest,
};
use hf_core::target::TargetLanguage;
use hf_core::types::ProviderId;
use hf_guardrails::{DenyAll, GuardrailPolicy, Guardrails, RiskTier};
use hf_service::{AiPolicy, RankedDiscoveryState, RankingSource, ServiceContainer};
use tokio::sync::Notify;
use uuid::Uuid;

struct PausedPool {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct AssessmentPool {
    fail: bool,
    fail_second: bool,
    calls: AtomicUsize,
}

impl AssessmentPool {
    fn new(fail: bool) -> Self {
        Self {
            fail,
            fail_second: false,
            calls: AtomicUsize::new(0),
        }
    }

    fn fail_second_batch() -> Self {
        Self {
            fail: false,
            fail_second: true,
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait::async_trait]
impl ProviderPool for AssessmentPool {
    async fn chat_completion(
        &self,
        request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail || (self.fail_second && call == 1) {
            return Err(ProviderError::Other {
                message: "test provider failure".to_owned(),
            });
        }
        let prompt = &request.messages.last().unwrap().content;
        let data = prompt.split_once("Candidates: ").unwrap().1;
        let candidates: Vec<serde_json::Value> = serde_json::from_str(data).unwrap();
        let rows = candidates
            .iter()
            .map(|candidate| {
                serde_json::json!({
                    "target_id": candidate["target_id"],
                    "bug_potential": 4,
                    "reachable_code": 3,
                    "harness_feasibility": 2,
                    "rationale": "Byte input and reachable calls"
                })
            })
            .collect::<Vec<_>>();
        Ok(hf_test_utils::fixtures::make_chat_response(
            &serde_json::to_string(&rows).unwrap(),
        ))
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "unused".to_owned(),
        })
    }
    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}
    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}
    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl ProviderPool for PausedPool {
    async fn chat_completion(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(hf_test_utils::fixtures::make_chat_response("[]"))
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "unused".to_owned(),
        })
    }

    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}
    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}
    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn sample_project() -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "#include <stddef.h>\nint parse_bytes(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    ).unwrap();
    project
}

async fn wait_for_revision(service: &ServiceContainer, id: Uuid, revision: u8) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if service
                .ranked_discovery_status(id)
                .await
                .unwrap()
                .unwrap()
                .revision
                >= revision
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn scan_is_visible_while_model_is_still_running() {
    let project = sample_project();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("rank.db"))
            .await
            .unwrap(),
    );
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let pool = Arc::new(PausedPool {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let service = ServiceContainer::stubbed()
        .with_store(store)
        .with_provider_pool(pool);

    let id = service
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    wait_for_revision(&service, id, 1).await;
    let status = service.ranked_discovery_status(id).await.unwrap().unwrap();
    let provisional = service.ranked_discovery_result(id).await.unwrap().unwrap();
    assert_eq!(status.state, RankedDiscoveryState::Ranking);
    assert_eq!(provisional.revision, 1);
    assert!(!provisional.inventory.candidates.is_empty());
    assert_eq!(provisional.ranking_source, RankingSource::Pending);

    entered.notified().await;
    release.notify_one();
    wait_for_revision(&service, id, 2).await;
    assert_eq!(
        service
            .ranked_discovery_status(id)
            .await
            .unwrap()
            .unwrap()
            .state,
        RankedDiscoveryState::Completed
    );
}

#[tokio::test]
async fn opening_a_service_marks_unfinished_ranking_interrupted() {
    let project = sample_project();
    let path = project.path().join("rank.db");
    let store = hf_storage::Store::connect(&path).await.unwrap();
    let id = Uuid::new_v4();
    store
        .create_ai_discovery(id, project.path(), TargetLanguage::C)
        .await
        .unwrap();
    store
        .publish_ai_scan(
            id,
            r#"{"project_root":"/sample","candidates":[],"call_graph":{}}"#,
            0,
        )
        .await
        .unwrap();
    drop(store);

    let service = ServiceContainer::stubbed()
        .with_store_path(path)
        .await
        .unwrap();
    let status = service.ranked_discovery_status(id).await.unwrap().unwrap();
    assert_eq!(status.state, RankedDiscoveryState::Interrupted);
    assert_eq!(status.revision, 1);
}

#[tokio::test]
async fn valid_ai_result_shows_three_factors_without_changing_base_score() {
    let project = sample_project();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("rank.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::stubbed()
        .with_store(Arc::clone(&store))
        .with_provider_pool(Arc::new(AssessmentPool::new(false)));
    let id = service
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    wait_for_revision(&service, id, 2).await;
    let result = service.ranked_discovery_result(id).await.unwrap().unwrap();
    assert_eq!(result.ranking_source, RankingSource::Ai);
    assert_eq!(result.assessments.len(), result.inventory.candidates.len());
    assert_eq!(result.assessments[0].bug_potential, 4);
    assert_eq!(result.assessments[0].reachable_code, Some(3));
    assert_eq!(result.assessments[0].harness_feasibility, 2);
    assert_eq!(
        result.assessments[0].advisory_score.to_bits(),
        0.75_f64.to_bits()
    );
    assert!(result.inventory.candidates[0].fit_score > 0.0);
    let saved = service.store().unwrap().list_all_targets().await.unwrap();
    assert_eq!(
        saved[0].fit_score.to_bits(),
        result.inventory.candidates[0].fit_score.to_bits()
    );
    let batches = store.list_ai_rank_batches(id).await.unwrap();
    assert_eq!(batches[0].resolved_model.as_deref(), Some("test-model"));
}

#[tokio::test]
async fn provider_failure_keeps_the_scan_and_retry_reuses_its_timestamp() {
    let project = sample_project();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("rank.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::stubbed()
        .with_store(store)
        .with_provider_pool(Arc::new(AssessmentPool::new(true)));
    let id = service
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    wait_for_revision(&service, id, 2).await;
    let first = service.ranked_discovery_result(id).await.unwrap().unwrap();
    assert_eq!(first.ranking_source, RankingSource::Heuristic);
    assert!(!first.inventory.candidates.is_empty());

    let service = service.with_provider_pool(Arc::new(AssessmentPool::new(false)));
    let retry_id = service.retry_ranked_discovery(id).await.unwrap();
    wait_for_revision(&service, retry_id, 2).await;
    let retried = service
        .ranked_discovery_result(retry_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried.ranking_source, RankingSource::Ai);
    assert_eq!(retried.scanned_at, first.scanned_at);
    assert_eq!(
        retried.inventory.candidates[0].id,
        first.inventory.candidates[0].id
    );
}

#[tokio::test]
async fn cancellation_and_direct_policy_denial_stop_publication() {
    let project = sample_project();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("rank.db"))
            .await
            .unwrap(),
    );
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let pool = Arc::new(PausedPool {
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });
    let service = ServiceContainer::stubbed()
        .with_store(store)
        .with_provider_pool(pool);
    let id = service
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    entered.notified().await;
    assert!(service.cancel_ranked_discovery(id).await.unwrap());
    release.notify_one();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        service
            .ranked_discovery_status(id)
            .await
            .unwrap()
            .unwrap()
            .state,
        RankedDiscoveryState::Cancelled
    );
    assert_eq!(
        service
            .ranked_discovery_status(id)
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );

    let denied = service.with_guardrails(Guardrails::new(
        GuardrailPolicy {
            auto_allow_max: RiskTier::Low,
            deny_at: Some(RiskTier::Low),
        },
        Arc::new(DenyAll),
    ));
    assert!(denied
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .is_err());
    assert!(denied.retry_ranked_discovery(id).await.is_err());
}

#[tokio::test]
async fn missing_provider_completes_with_an_explicit_scan_source() {
    let project = sample_project();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("rank.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::stubbed().with_store(store);
    let id = service
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    wait_for_revision(&service, id, 2).await;
    let result = service.ranked_discovery_result(id).await.unwrap().unwrap();
    assert_eq!(result.ranking_source, RankingSource::Heuristic);
    assert_eq!(result.reason_code.as_deref(), Some("no_provider"));
    assert!(result.assessments.is_empty());
    assert!(!result.inventory.candidates.is_empty());
}

#[tokio::test]
async fn one_failed_batch_keeps_valid_assessments_and_scan_only_rows() {
    let project = tempfile::tempdir().unwrap();
    let mut source = String::new();
    for index in 0..17 {
        writeln!(source, "int parse_{index}(const unsigned char *data, unsigned long size) {{ return size && data[0]; }}").unwrap();
    }
    std::fs::write(project.path().join("parsers.c"), source).unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("rank.db"))
            .await
            .unwrap(),
    );
    let service = ServiceContainer::stubbed()
        .with_store(store)
        .with_provider_pool(Arc::new(AssessmentPool::fail_second_batch()));
    let id = service
        .start_ranked_discovery(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    wait_for_revision(&service, id, 2).await;
    let result = service.ranked_discovery_result(id).await.unwrap().unwrap();
    assert_eq!(result.inventory.candidates.len(), 17);
    assert_eq!(result.assessments.len(), 16);
    assert_eq!(result.ranking_source, RankingSource::Mixed);
    assert_eq!(result.reason_code.as_deref(), Some("partial_or_failed_ai"));
}

#[tokio::test]
async fn inventory_policy_is_owned_by_service() {
    let project = sample_project();
    let inventory = hf_discovery::discover(project.path(), TargetLanguage::C)
        .await
        .unwrap();
    let service = ServiceContainer::stubbed();
    let off = service
        .rank_discovered_inventory(inventory.clone(), TargetLanguage::C, AiPolicy::Off)
        .await
        .unwrap();
    assert_eq!(off.ranking_source, RankingSource::Heuristic);
    assert_eq!(off.reason_code.as_deref(), Some("ai_off"));
    let automatic = service
        .rank_discovered_inventory(inventory.clone(), TargetLanguage::C, AiPolicy::Auto)
        .await
        .unwrap();
    assert_eq!(automatic.reason_code.as_deref(), Some("no_provider"));
    assert!(service
        .rank_discovered_inventory(inventory, TargetLanguage::C, AiPolicy::Require)
        .await
        .is_err());
}
