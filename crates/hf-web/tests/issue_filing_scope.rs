#![cfg(feature = "change-aware")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn filing_requires_an_approved_project_and_matching_crash_owner() {
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .unwrap();
    let container = fixture.container();
    let crash = container
        .all_crashes()
        .await
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let approved = tempfile::tempdir().unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![approved.path().to_path_buf()])
            .unwrap();
    let app = hf_web::build_with_state_and_security(hf_web::AppState::new(container), security);
    for (body, expected) in [
        (
            json!({"crash_id":crash.id}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            json!({"project":fixture.project_root(), "crash_id":crash.id}),
            StatusCode::FORBIDDEN,
        ),
        (
            json!({"project":approved.path(), "crash_id":crash.id}),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/issues/file")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{body}");
        if expected == StatusCode::BAD_REQUEST {
            let bytes = axum::body::to_bytes(response.into_body(), 65536)
                .await
                .unwrap();
            assert!(
                String::from_utf8_lossy(&bytes).contains("belongs to project"),
                "{}",
                String::from_utf8_lossy(&bytes)
            );
        }
    }
}
