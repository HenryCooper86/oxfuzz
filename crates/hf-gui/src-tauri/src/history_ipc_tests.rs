//! Run-history clearing preserves projects outside the selected desktop scope.

use std::sync::Arc;

use hf_service::test_support::desktop_approval::{
    in_isolated_test_process, DesktopApprovalFixture,
};
use hf_service::test_support::{RunRecord, RunStatus};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn desktop_history_clear_respects_project_selection_and_explicit_all_projects() {
    if in_isolated_test_process(
        "history_ipc_tests::desktop_history_clear_respects_project_selection_and_explicit_all_projects",
    ) {
        return;
    }
    let fixture = DesktopApprovalFixture::new(false).await;
    let other_project = fixture.directory.path().join("other");
    std::fs::create_dir(&other_project).unwrap();
    let other_project = std::fs::canonicalize(other_project).unwrap();
    let store = fixture.service.store().unwrap();
    let mut runs = Vec::new();
    for project in [&fixture.project, &other_project] {
        let mut run = RunRecord::new(
            project.to_string_lossy(),
            hf_service::EngineKind::LibFuzzer,
            None,
            chrono::Utc::now(),
        );
        run.status = RunStatus::Done;
        store.insert_run(&run).await.unwrap();
        runs.push(run);
    }
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
        .invoke_handler(tauri::generate_handler![crate::commands::clear_all_runs])
        .build(tauri::test::mock_context(tauri::test::noop_assets()))
        .unwrap();
    let window = tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
        .build()
        .unwrap();
    let clear = |body| {
        tauri::test::get_ipc_response(
            &window,
            tauri::webview::InvokeRequest {
                cmd: "clear_all_runs".to_owned(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: window.url().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: tauri::http::HeaderMap::new(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .unwrap();
    };

    clear(json!({ "project": fixture.project }));
    assert!(store.get_run(runs[0].id).await.unwrap().is_none());
    assert_eq!(
        store.get_run(runs[1].id).await.unwrap().unwrap().id,
        runs[1].id
    );

    clear(json!({}));
    assert!(store.get_run(runs[1].id).await.unwrap().is_none());
    scheduler.stop().await;
}
