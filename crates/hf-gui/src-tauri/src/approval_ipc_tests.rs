//! Explicit desktop clicks carry approval only for their selected operation.

use std::sync::Arc;

use hf_service::test_support::desktop_approval::{
    in_isolated_test_process, DesktopApprovalFixture,
};
use hf_service::test_support::HarnessApprovalKind;
use hf_service::{Action, EngineKind, HarnessStatus};
use serde_json::{json, Value};

struct DesktopApp {
    _app: tauri::App<tauri::test::MockRuntime>,
    window: tauri::WebviewWindow<tauri::test::MockRuntime>,
    scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
}

impl DesktopApp {
    async fn new(fixture: &DesktopApprovalFixture) -> Self {
        let scheduler = Arc::new(
            hf_service::scheduler::CampaignScheduler::try_start(
                fixture.service.clone(),
                fixture.directory.path().join("schedules.json"),
                None,
            )
            .await
            .unwrap(),
        );
        let app = tauri::test::mock_builder()
            .manage(crate::state::AppState::new(
                fixture.service.clone(),
                Arc::clone(&scheduler),
            ))
            .invoke_handler(tauri::generate_handler![
                crate::commands::harness_promote,
                crate::commands::harness_promote_with_findings,
                crate::work_order_commands::work_order_qualify,
                crate::work_order_commands::work_order_promote,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let window = tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
            .build()
            .unwrap();
        Self {
            _app: app,
            window,
            scheduler,
        }
    }

    fn invoke(&self, command: &str, body: Value) -> Result<Value, Value> {
        tauri::test::get_ipc_response(
            &self.window,
            tauri::webview::InvokeRequest {
                cmd: command.to_owned(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: self.window.url().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: tauri::http::HeaderMap::new(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .map(|body| body.deserialize().unwrap())
    }
}

async fn assert_startup_still_denies(fixture: &DesktopApprovalFixture) {
    for action in [
        Action::RunHarness,
        Action::PromoteHarness,
        Action::RunFuzzer {
            engine: "libfuzzer".to_owned(),
            duration_secs: 60,
        },
    ] {
        assert!(fixture
            .service
            .guardrails()
            .authorize(action)
            .await
            .is_err());
    }
}

#[cfg(feature = "harness-work-order")]
#[tokio::test(flavor = "multi_thread")]
async fn desktop_work_order_qualify_records_review_and_smoke_without_promoting() {
    if in_isolated_test_process(
        "approval_ipc_tests::desktop_work_order_qualify_records_review_and_smoke_without_promoting",
    ) {
        return;
    }
    let fixture = DesktopApprovalFixture::new(false).await;
    let submission = fixture.submission().await;
    assert_startup_still_denies(&fixture).await;
    let app = DesktopApp::new(&fixture).await;
    let response = app.invoke(
        "work_order_qualify",
        json!({ "submissionId": submission.id }),
    );
    app.scheduler.stop().await;
    let response = response.expect("explicit desktop qualification must complete");
    assert_eq!(response["status"], "smoke_passed", "{response}");
    let attempt: hf_service::HarnessWorkOrderAttempt = serde_json::from_value(response).unwrap();
    let retained = fixture
        .service
        .harness_work_order_attempt(attempt.id)
        .await
        .unwrap();
    assert_eq!(retained, attempt);
    let harness_id = attempt.harness_id.unwrap();
    let evidence = attempt.result.unwrap();
    assert_eq!(
        evidence.source_sha256.as_deref(),
        Some(submission.source_sha256.as_str())
    );
    assert!(attempt.smoke_run_id.is_some());
    let store = fixture.service.store().unwrap();
    assert_eq!(
        store.get_harness(harness_id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );
    assert!(store
        .harness_approval(
            harness_id,
            evidence.source_sha256.as_ref().unwrap(),
            evidence.binary_sha256.as_ref().unwrap()
        )
        .await
        .unwrap()
        .is_none());
    let review = fixture
        .service
        .harness_review_queue(Some(&fixture.project), Some(&fixture.target))
        .await
        .unwrap();
    let reviewed = review
        .iter()
        .find(|item| item.harness_id == harness_id.to_string())
        .unwrap();
    assert!(reviewed.ai_review.as_ref().unwrap().safe_to_execute);
    assert_startup_still_denies(&fixture).await;
}

#[cfg(feature = "harness-work-order")]
#[tokio::test(flavor = "multi_thread")]
async fn desktop_work_order_promote_approves_exact_qualified_attempt() {
    if in_isolated_test_process(
        "approval_ipc_tests::desktop_work_order_promote_approves_exact_qualified_attempt",
    ) {
        return;
    }
    let fixture = DesktopApprovalFixture::new(false).await;
    let attempt = fixture.prepare_qualified_attempt().await;
    assert_startup_still_denies(&fixture).await;
    let app = DesktopApp::new(&fixture).await;
    let response = app.invoke("work_order_promote", json!({ "attemptId": attempt.id }));
    app.scheduler.stop().await;
    let response = response.expect("explicit desktop promotion must approve the selected attempt");
    let harness_id = attempt.harness_id.unwrap();
    assert_eq!(response["id"], harness_id.to_string());
    assert_eq!(response["status"], "Promoted");
    assert_eq!(
        fixture
            .service
            .harness_work_order_attempt(attempt.id)
            .await
            .unwrap(),
        attempt
    );
    let result = attempt.result.unwrap();
    let approval = fixture
        .service
        .store()
        .unwrap()
        .harness_approval(
            harness_id,
            result.source_sha256.as_ref().unwrap(),
            result.binary_sha256.as_ref().unwrap(),
        )
        .await
        .unwrap()
        .expect("persist exact human approval");
    assert_eq!(approval.approval_kind, HarnessApprovalKind::CleanSmoke);
    assert_startup_still_denies(&fixture).await;
}

#[cfg(feature = "harness-work-order")]
struct DeclineApproval;

#[cfg(feature = "harness-work-order")]
#[async_trait::async_trait]
impl hf_service::ApprovalGate for DeclineApproval {
    async fn request_approval(&self, _: &Action, _: &str) -> bool {
        false
    }
}

#[cfg(feature = "harness-work-order")]
#[tokio::test(flavor = "multi_thread")]
async fn desktop_work_order_promotion_preserves_policy_denial_reason() {
    if in_isolated_test_process(
        "approval_ipc_tests::desktop_work_order_promotion_preserves_policy_denial_reason",
    ) {
        return;
    }
    let mut fixture = DesktopApprovalFixture::new(false).await;
    let attempt = fixture.prepare_qualified_attempt().await;
    fixture.service = fixture
        .service
        .clone()
        .with_guardrails(hf_service::Guardrails::new(
            hf_service::GuardrailPolicy {
                deny_at: Some(hf_service::RiskTier::High),
                ..hf_service::GuardrailPolicy::default()
            },
            Arc::new(DeclineApproval),
        ));
    let app = DesktopApp::new(&fixture).await;
    let response = app.invoke("work_order_promote", json!({ "attemptId": attempt.id }));
    app.scheduler.stop().await;
    let error = response.expect_err("desktop consent must retain the configured policy denial");
    assert_eq!(error["code"], "promotion_denied", "{error}");
    assert_eq!(error["kind"], "validation");
    assert_eq!(
        error["message"],
        "guardrail denied: High-risk action 'promote harness' is denied by policy"
    );
    let harness_id = attempt.harness_id.unwrap();
    let evidence = attempt.result.unwrap();
    let store = fixture.service.store().unwrap();
    assert_eq!(
        store.get_harness(harness_id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );
    assert!(store
        .harness_approval(
            harness_id,
            evidence.source_sha256.as_ref().unwrap(),
            evidence.binary_sha256.as_ref().unwrap()
        )
        .await
        .unwrap()
        .is_none());
    let decisions = store.list_guardrail_decisions(100).await.unwrap();
    let promotion_decisions = decisions
        .iter()
        .filter(|decision| decision.origin == "harness_promote")
        .collect::<Vec<_>>();
    assert_eq!(promotion_decisions.len(), 1);
    assert_eq!(promotion_decisions[0].decision, "denied");
    assert_startup_still_denies(&fixture).await;
}

#[cfg(feature = "harness-work-order")]
#[tokio::test(flavor = "multi_thread")]
async fn desktop_work_order_qualification_then_promotion_uses_same_retained_revision() {
    if in_isolated_test_process(
        "approval_ipc_tests::desktop_work_order_qualification_then_promotion_uses_same_retained_revision",
    ) {
        return;
    }
    let fixture = DesktopApprovalFixture::new(false).await;
    let submission = fixture.submission().await;
    let app = DesktopApp::new(&fixture).await;
    let response = app.invoke(
        "work_order_qualify",
        json!({ "submissionId": submission.id }),
    );
    let attempt: hf_service::HarnessWorkOrderAttempt =
        serde_json::from_value(response.expect("qualify through desktop IPC")).unwrap();
    assert_eq!(
        attempt.status,
        hf_service::HarnessWorkOrderAttemptStatus::SmokePassed
    );
    let promotion = app.invoke("work_order_promote", json!({ "attemptId": attempt.id }));
    app.scheduler.stop().await;
    let promoted = promotion.expect("promote the desktop-qualified attempt");
    let harness_id = attempt.harness_id.unwrap();
    assert_eq!(promoted["id"], harness_id.to_string());
    assert_eq!(promoted["status"], "Promoted");
    let evidence = attempt.result.unwrap();
    let approval = fixture
        .service
        .store()
        .unwrap()
        .harness_approval(
            harness_id,
            evidence.source_sha256.as_ref().unwrap(),
            evidence.binary_sha256.as_ref().unwrap(),
        )
        .await
        .unwrap()
        .expect("retain approval for qualified source and binary");
    assert_eq!(approval.approval_kind, HarnessApprovalKind::CleanSmoke);
    assert_startup_still_denies(&fixture).await;
}

async fn promote_harness(known_findings: bool) {
    let fixture = DesktopApprovalFixture::new(known_findings).await;
    let harness = fixture.prepare_harness(EngineKind::LibFuzzer).await;
    let smoke = harness.smoke_run.as_ref().unwrap();
    assert_eq!(smoke.crashes > 0, known_findings);
    assert_startup_still_denies(&fixture).await;
    let app = DesktopApp::new(&fixture).await;
    let command = if known_findings {
        "harness_promote_with_findings"
    } else {
        "harness_promote"
    };
    let response = app.invoke(
        command,
        json!({
            "project": fixture.project, "target": fixture.target, "engine": "libfuzzer",
        }),
    );
    app.scheduler.stop().await;
    let response =
        response.expect("explicit desktop promotion must approve the active reviewed revision");
    assert_eq!(response["status"], "Promoted");
    let store = fixture.service.store().unwrap();
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::Promoted
    );
    let approval = store
        .harness_approval(
            harness.id,
            smoke.source_sha256.as_ref().unwrap(),
            smoke.binary_sha256.as_ref().unwrap(),
        )
        .await
        .unwrap()
        .expect("retain source and binary approval");
    assert_eq!(
        approval.approval_kind,
        if known_findings {
            HarnessApprovalKind::KnownFindings
        } else {
            HarnessApprovalKind::CleanSmoke
        }
    );
    assert_startup_still_denies(&fixture).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn desktop_harness_promote_records_clean_smoke_approval() {
    if !in_isolated_test_process(
        "approval_ipc_tests::desktop_harness_promote_records_clean_smoke_approval",
    ) {
        promote_harness(false).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn desktop_harness_promote_with_findings_records_distinct_approval() {
    if !in_isolated_test_process(
        "approval_ipc_tests::desktop_harness_promote_with_findings_records_distinct_approval",
    ) {
        promote_harness(true).await;
    }
}
