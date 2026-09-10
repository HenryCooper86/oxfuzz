//! Comparison authorizes both run owners before exposing retained assessment.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hf_service::test_support::{RunRecord, RunStatus, Store};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
async fn compare(app: &axum::Router, first: uuid::Uuid, second: uuid::Uuid) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/runs/compare")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"baseline_id": first, "result_id": second}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
#[tokio::test]
async fn both_run_projects_must_be_authorized() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(root.path().join("records.db"))
            .await
            .unwrap(),
    );
    let mut first = RunRecord::new(
        root.path().to_string_lossy(),
        hf_service::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    first.status = RunStatus::Done;
    let mut second = first.clone();
    second.id = uuid::Uuid::new_v4();
    let mut foreign = second.clone();
    foreign.id = uuid::Uuid::new_v4();
    foreign.project_root = outside.path().to_string_lossy().into_owned();
    for run in [&first, &second, &foreign] {
        store.insert_run(run).await.unwrap();
    }
    let container = hf_service::ServiceContainer::stubbed().with_store(store);
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![root.path().into()]).unwrap();
    let app = hf_web::build_with_state_and_security(hf_web::AppState::new(container), security);
    let (status, assessment) = compare(&app, first.id, second.id).await;
    assert_eq!(status, StatusCode::OK, "{assessment}");
    assert_eq!(assessment["reason"], "missing_setup");
    assert_eq!(assessment["edge_delta"], Value::Null);
    for (a, b) in [(first.id, foreign.id), (foreign.id, first.id)] {
        let (status, body) = compare(&app, a, b).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(!body.to_string().contains(outside.path().to_str().unwrap()));
    }
}
