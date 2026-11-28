//! The Corpus view's coverage summary and concolic availability over REST.
//! In the browser both failed as unsupported commands while the desktop app
//! answered them.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hf_service::ServiceContainer;
use tower::ServiceExt;

async fn app_for(project: &std::path::Path) -> axum::Router {
    let service = ServiceContainer::stubbed()
        .with_store_path(project.join("routes.db"))
        .await
        .unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.to_path_buf()])
            .unwrap();
    hf_web::router::build_with_state_and_security(hf_web::router::AppState::new(service), security)
}

#[tokio::test]
async fn a_target_without_a_coverage_build_has_no_summary_yet() {
    let project = tempfile::tempdir().unwrap();
    let response = app_for(project.path())
        .await
        .oneshot(
            Request::builder()
                .uri("/coverage/summary")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "project": project.path(), "target": "parse" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    assert_eq!(body.as_ref(), b"null");
}

#[cfg(feature = "concolic-enrichment")]
#[tokio::test]
async fn concolic_availability_answers_with_a_state() {
    let project = tempfile::tempdir().unwrap();
    let response = app_for(project.path())
        .await
        .oneshot(
            Request::builder()
                .uri("/corpus/concolic/availability")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 4096).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        matches!(value["state"].as_str(), Some("available" | "unavailable")),
        "{value}"
    );
}
