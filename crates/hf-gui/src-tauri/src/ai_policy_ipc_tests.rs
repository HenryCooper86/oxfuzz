//! The optional `ai` command argument on the wire: omitted -> auto, and an
//! unknown value is rejected at deserialization before any service work.

use std::path::Path;
use std::sync::Arc;

use serde_json::{json, Value};

use hf_service::test_support::desktop_approval::{
    in_isolated_test_process, DesktopApprovalFixture,
};
use hf_service::ServiceContainer;

struct AiPolicyIpc {
    _app: tauri::App<tauri::test::MockRuntime>,
    window: tauri::WebviewWindow<tauri::test::MockRuntime>,
    _scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
}

impl AiPolicyIpc {
    async fn new(service: ServiceContainer, schedules: &Path) -> Self {
        let scheduler_handle = Arc::new(
            hf_service::scheduler::CampaignScheduler::try_start(
                service.clone(),
                schedules.to_path_buf(),
                None,
            )
            .await
            .expect("start the fixture scheduler"),
        );
        let app = tauri::test::mock_builder()
            .manage(crate::state::AppState::new(
                service,
                Arc::clone(&scheduler_handle),
            ))
            .invoke_handler(tauri::generate_handler![crate::commands::verify_crash])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("build test application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
            .build()
            .expect("build test window");
        Self {
            _app: app,
            window,
            _scheduler: scheduler_handle,
        }
    }

    fn invoke(&self, command: &str, body: Value) -> Result<Value, Value> {
        tauri::test::get_ipc_response(
            &self.window,
            tauri::webview::InvokeRequest {
                cmd: command.to_owned(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: self.window.url().expect("test window URL"),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: tauri::http::HeaderMap::new(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .map(|body| body.deserialize::<Value>().expect("JSON IPC response"))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn verify_crash_ai_field_defaults_to_auto_and_rejects_unknown_policies() {
    const NIL: &str = "00000000-0000-0000-0000-000000000000";
    if in_isolated_test_process(
        "ai_policy_ipc_tests::verify_crash_ai_field_defaults_to_auto_and_rejects_unknown_policies",
    ) {
        return;
    }
    let fixture = DesktopApprovalFixture::new(false).await;
    let ipc = AiPolicyIpc::new(
        fixture.service.clone(),
        &fixture.directory.path().join("schedules.json"),
    )
    .await;
    let base = || json!({"project":"/p","target":"parse_packet","runId":NIL,"crashId":NIL});

    // Omitted `ai` and an explicit `off` both reach the service: the fixture
    // has no such crash, so the advisory verdict is `null` in either case.
    let omitted = ipc.invoke("verify_crash", base());
    assert_eq!(
        omitted.expect("omitted ai defaults to auto and reaches the service"),
        Value::Null,
    );
    let mut off = base();
    off["ai"] = json!("off");
    let off = ipc.invoke("verify_crash", off);
    assert_eq!(
        off.expect("explicit off deserializes and reaches the service"),
        Value::Null
    );

    // An unknown policy is rejected at deserialization, before any service call.
    let mut bogus = base();
    bogus["ai"] = json!("bogus");
    let rejected = ipc.invoke("verify_crash", bogus);
    assert!(
        rejected.is_err(),
        "an unknown ai policy must be rejected: {rejected:?}"
    );
}
