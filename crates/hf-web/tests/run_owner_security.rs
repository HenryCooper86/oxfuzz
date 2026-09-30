//! Run-ID routes must authorize the persisted run owner before use.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hf_service::test_support::{RunRecord, RunStatus, Store};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn run_id_routes_reject_a_run_outside_approved_project_roots() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(approved.path().join("records.db"))
            .await
            .unwrap(),
    );
    let mut run = RunRecord::new(
        outside.path().to_string_lossy(),
        hf_service::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    run.status = RunStatus::Done;
    store.insert_run(&run).await.unwrap();

    let container = hf_service::ServiceContainer::stubbed().with_store(store);
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![approved.path().to_path_buf()])
            .unwrap();
    let app = hf_web::build_with_state_and_security(hf_web::AppState::new(container), security);

    for uri in [
        "/runs/coverage",
        "/runs/harness-source",
        "/runs/revert-harness",
        "/runs/delete",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({"run_id": run.id.to_string()}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(outside.path().to_str().unwrap()));
    }
}
