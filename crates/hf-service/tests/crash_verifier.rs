//! Integration tests for the LLM crash verifier (`ServiceContainer::verify_crashes`
//! and `ServiceContainer::verify_crash_by_id`): each prompt is retained before
//! dispatch, its raw reply is recorded once answered, and nothing is verified
//! from state the store cannot reconstruct (Engineering Protocol 2.13).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::crash::{CasrReport, Crash, CrashKind, CrashSeverity};
use hf_service::{Confidence, ServiceContainer};
use uuid::Uuid;

const VERDICT_REPLY: &str = "{\"reproduces_deterministically\": true, \
                             \"likely_target_bug\": true, \"confidence\": \"high\", \
                             \"reasons\": [\"deterministic ASan overflow\"]}";
const UNPARSABLE_REPLY: &str = "the crash artifacts alone do not support a verdict";

/// A pool that answers every completion with a fixed, well-formed verdict and
/// counts the dispatches.
struct FixedVerdictPool {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for FixedVerdictPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(hf_test_utils::fixtures::make_chat_response(VERDICT_REPLY))
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

/// A pool that answers the verification prompt with a fixed reply while
/// checking that the exact prompt is already retained as a pending draft: the
/// dispatch must happen after persistence, never before.
struct CapturingPool {
    store: Arc<hf_storage::Store>,
    crash_id: Uuid,
    reply: &'static str,
    calls: AtomicUsize,
    prompt_was_pending: AtomicBool,
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for CapturingPool {
    async fn chat_completion(
        &self,
        request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let prompt = request
            .messages
            .last()
            .map(|message| message.content.clone())
            .expect("the verification request carries a prompt");
        let pending = self
            .store
            .crash_verify_drafts_for_crash(self.crash_id)
            .await
            .expect("drafts readable at dispatch time")
            .iter()
            .any(|draft| draft.response.is_none() && draft.prompt == prompt);
        self.prompt_was_pending.store(pending, Ordering::SeqCst);
        Ok(hf_test_utils::fixtures::make_chat_response(self.reply))
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

fn asan_crash(run_id: Uuid) -> Crash {
    Crash {
        reproduction: None,
        id: Uuid::new_v4(),
        run_id,
        target_id: Uuid::new_v4(),
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
        origin: hf_core::crash::CrashOrigin::Unknown,
    }
}

struct CrashFixture {
    _directory: tempfile::TempDir,
    project: PathBuf,
    store: Arc<hf_storage::Store>,
    run_id: Uuid,
    crash: Crash,
}

impl CrashFixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let store = Arc::new(
            hf_storage::Store::connect(directory.path().join("verifier.db"))
                .await
                .unwrap(),
        );
        let run = hf_storage::RunRecord::new(
            project.to_string_lossy().into_owned(),
            hf_core::engine::EngineKind::LibFuzzer,
            None,
            chrono::Utc::now(),
        );
        store.insert_run(&run).await.unwrap();
        let crash = asan_crash(run.id);
        store
            .upsert_crashes(std::slice::from_ref(&crash))
            .await
            .unwrap();
        Self {
            _directory: directory,
            project,
            store,
            run_id: run.id,
            crash,
        }
    }

    async fn persist(&self, crash: &Crash) {
        self.store
            .upsert_crashes(std::slice::from_ref(crash))
            .await
            .unwrap();
    }

    async fn drafts(&self, crash_id: Uuid) -> Vec<hf_storage::CrashVerifyDraftRecord> {
        self.store
            .crash_verify_drafts_for_crash(crash_id)
            .await
            .unwrap()
    }

    fn container(&self, pool: Arc<dyn hf_core::provider::ProviderPool>) -> ServiceContainer {
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), Some(pool))
            .with_store(Arc::clone(&self.store))
    }
}

#[tokio::test]
async fn verify_crashes_parses_the_llm_verdict_per_crash_and_retains_the_exchange() {
    let fixture = CrashFixture::new().await;
    let second = asan_crash(fixture.run_id);
    fixture.persist(&second).await;
    let pool = Arc::new(FixedVerdictPool {
        calls: AtomicUsize::new(0),
    });
    let container = fixture.container(Arc::clone(&pool) as _);

    let crashes = vec![fixture.crash.clone(), second.clone()];
    let verdicts = container
        .verify_crashes(
            "parse_header",
            &fixture.project,
            &crashes,
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("auto verification is advisory and never errors");
    assert_eq!(verdicts.len(), crashes.len(), "one verdict slot per crash");
    for verdict in verdicts {
        let verdict = verdict.expect("the LLM verdict is parsed for each crash");
        assert!(verdict.reproduces_deterministically && verdict.likely_target_bug);
        assert_eq!(verdict.confidence, Confidence::High);
    }
    assert_eq!(pool.calls.load(Ordering::SeqCst), 2);

    for crash in &crashes {
        let drafts = fixture.drafts(crash.id).await;
        assert_eq!(drafts.len(), 1, "exactly one retained exchange per crash");
        assert_eq!(
            drafts[0].response.as_deref(),
            Some(VERDICT_REPLY),
            "the raw reply is retained"
        );
        assert!(drafts[0].completed_at.is_some());
    }
}

#[tokio::test]
async fn verify_crashes_yields_no_opinion_without_a_provider() {
    // Best-effort: with no LLM configured there are no fabricated verdicts.
    let fixture = CrashFixture::new().await;
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&fixture.store));
    let verdicts = container
        .verify_crashes(
            "parse_header",
            &fixture.project,
            std::slice::from_ref(&fixture.crash),
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("auto verification is advisory and never errors");
    assert_eq!(verdicts, vec![None]);
}

#[tokio::test]
async fn verify_crashes_without_a_store_dispatches_nothing() {
    // Nothing model-visible may be sent without retention (2.13), so a
    // store-less container yields no verdicts at all.
    let pool = Arc::new(FixedVerdictPool {
        calls: AtomicUsize::new(0),
    });
    let container = ServiceContainer::new(
        Arc::new(hf_runtime::StubRuntime),
        Some(Arc::clone(&pool) as _),
    );
    let crash = asan_crash(Uuid::new_v4());
    let verdicts = container
        .verify_crashes(
            "parse_header",
            PathBuf::from("/nonexistent-project").as_path(),
            &[crash],
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("auto verification is advisory and never errors");
    assert_eq!(verdicts, vec![None]);
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "no dispatch without a store"
    );
}

#[tokio::test]
async fn the_verify_prompt_is_retained_before_dispatch_and_an_unparsed_reply_is_still_retained() {
    let fixture = CrashFixture::new().await;
    let pool = Arc::new(CapturingPool {
        store: Arc::clone(&fixture.store),
        crash_id: fixture.crash.id,
        reply: UNPARSABLE_REPLY,
        calls: AtomicUsize::new(0),
        prompt_was_pending: AtomicBool::new(false),
    });
    let container = fixture.container(Arc::clone(&pool) as _);

    let verdicts = container
        .verify_crashes(
            "parse_header",
            &fixture.project,
            std::slice::from_ref(&fixture.crash),
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("auto verification is advisory and never errors");
    assert_eq!(verdicts, vec![None], "an unparsable reply is no verdict");
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
    assert!(
        pool.prompt_was_pending.load(Ordering::SeqCst),
        "the prompt row exists before dispatch"
    );
    let drafts = fixture.drafts(fixture.crash.id).await;
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        drafts[0].response.as_deref(),
        Some(UNPARSABLE_REPLY),
        "the raw reply is retained even when no verdict parses"
    );
}

#[tokio::test]
async fn a_crash_missing_from_the_store_gets_no_verdict_and_no_row() {
    let fixture = CrashFixture::new().await;
    let pool = Arc::new(FixedVerdictPool {
        calls: AtomicUsize::new(0),
    });
    let container = fixture.container(Arc::clone(&pool) as _);
    let unpersisted = asan_crash(fixture.run_id);

    let verdicts = container
        .verify_crashes(
            "parse_header",
            &fixture.project,
            std::slice::from_ref(&unpersisted),
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("auto verification is advisory and never errors");
    assert_eq!(verdicts, vec![None], "no verdict is fabricated");
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "nothing is dispatched"
    );
    assert!(
        fixture.drafts(unpersisted.id).await.is_empty(),
        "no draft row is written for an unknown crash"
    );
}

#[tokio::test]
async fn verify_crash_by_id_loads_the_persisted_crash_and_verifies_it() {
    let fixture = CrashFixture::new().await;
    let pool = Arc::new(CapturingPool {
        store: Arc::clone(&fixture.store),
        crash_id: fixture.crash.id,
        reply: VERDICT_REPLY,
        calls: AtomicUsize::new(0),
        prompt_was_pending: AtomicBool::new(false),
    });
    let container = fixture.container(Arc::clone(&pool) as _);

    let verdict = container
        .verify_crash_by_id(
            &fixture.project,
            fixture.crash.id,
            fixture.run_id,
            "parse_header",
            hf_service::AiPolicy::Auto,
        )
        .await
        .expect("auto verification is advisory and never errors")
        .expect("a verdict for the persisted crash");
    assert!(verdict.reproduces_deterministically && verdict.likely_target_bug);
    assert_eq!(verdict.confidence, Confidence::High);
    assert_eq!(pool.calls.load(Ordering::SeqCst), 1);
    let drafts = fixture.drafts(fixture.crash.id).await;
    assert_eq!(drafts.len(), 1);
    assert_eq!(drafts[0].response.as_deref(), Some(VERDICT_REPLY));
}

#[tokio::test]
async fn verify_crash_by_id_yields_no_verdict_for_unknown_or_mismatched_ids() {
    let fixture = CrashFixture::new().await;
    let pool = Arc::new(FixedVerdictPool {
        calls: AtomicUsize::new(0),
    });
    let container = fixture.container(Arc::clone(&pool) as _);

    // An unknown crash id.
    assert!(container
        .verify_crash_by_id(
            &fixture.project,
            Uuid::new_v4(),
            fixture.run_id,
            "parse_header",
            hf_service::AiPolicy::Auto
        )
        .await
        .expect("auto verification is advisory and never errors")
        .is_none());
    // A crash presented under another run's id.
    assert!(container
        .verify_crash_by_id(
            &fixture.project,
            fixture.crash.id,
            Uuid::new_v4(),
            "parse_header",
            hf_service::AiPolicy::Auto
        )
        .await
        .expect("auto verification is advisory and never errors")
        .is_none());
    // A crash belonging to another project's run.
    let other_project = tempfile::tempdir().unwrap();
    let other_run = hf_storage::RunRecord::new(
        other_project.path().to_string_lossy().into_owned(),
        hf_core::engine::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    fixture.store.insert_run(&other_run).await.unwrap();
    let foreign_crash = asan_crash(other_run.id);
    fixture.persist(&foreign_crash).await;
    assert!(container
        .verify_crash_by_id(
            &fixture.project,
            foreign_crash.id,
            other_run.id,
            "parse_header",
            hf_service::AiPolicy::Auto
        )
        .await
        .expect("auto verification is advisory and never errors")
        .is_none());
    assert_eq!(
        pool.calls.load(Ordering::SeqCst),
        0,
        "no mismatched request reaches the provider"
    );
    assert!(
        fixture.drafts(fixture.crash.id).await.is_empty()
            && fixture.drafts(foreign_crash.id).await.is_empty(),
        "no draft rows are written for rejected ids"
    );
}
