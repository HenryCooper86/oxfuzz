//! Run closeout and trust REST ownership and read semantics.

#![cfg(all(feature = "run-closeout", feature = "campaign-trust"))]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt as _;

async fn request(app: &axum::Router, method: Method, uri: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn retained_read_and_execute_authorize_the_durable_run_owner() {
    let directory = tempfile::tempdir().unwrap();
    let allowed = directory.path().join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    let allowed = std::fs::canonicalize(allowed).unwrap();
    let fixture = hf_service::test_support::run_closeout_fixture()
        .await
        .unwrap();
    let run_id = fixture.run_id();
    let security = WebSecurityConfig::new(None, true, Vec::new(), vec![allowed]).unwrap();
    let app = build_with_state_and_security(AppState::new(fixture.container()), security);

    for (method, uri) in [
        (Method::GET, format!("/runs/{run_id}/closeout")),
        (Method::POST, format!("/runs/{run_id}/closeout")),
        (Method::GET, format!("/runs/{run_id}/trust")),
    ] {
        assert_eq!(
            request(&app, method, &uri).await.status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn get_closeout_returns_retained_pending_state_without_execution() {
    let fixture = hf_service::test_support::run_closeout_fixture()
        .await
        .unwrap();
    let run_id = fixture.run_id();
    let security = WebSecurityConfig::new(
        None,
        true,
        Vec::new(),
        vec![fixture.project_root().to_path_buf()],
    )
    .unwrap();
    let app = build_with_state_and_security(AppState::new(fixture.container()), security);

    let response = request(&app, Method::GET, &format!("/runs/{run_id}/closeout")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["availability"]["status"], "available");
    assert_eq!(json["steps"], serde_json::json!([]));
}

#[tokio::test]
async fn closeout_execute_rejects_a_nonempty_body() {
    let fixture = hf_service::test_support::run_closeout_fixture()
        .await
        .unwrap();
    let run_id = fixture.run_id();
    let security = WebSecurityConfig::new(
        None,
        true,
        Vec::new(),
        vec![fixture.project_root().to_path_buf()],
    )
    .unwrap();
    let app = build_with_state_and_security(AppState::new(fixture.container()), security);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/runs/{run_id}/closeout"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
