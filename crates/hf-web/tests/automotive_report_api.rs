#![cfg(feature = "automotive-scapy")]

//! Isolated `/automotive/report` language contract.
//!
//! A sibling of `report_api.rs`, and separate from it for the same reason: this
//! target owns a durable store on disk and a project allowlist of its own, and
//! Cargo runs each integration target in its own process.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// POST `/automotive/report` and return the composed report's Markdown.
async fn post_automotive_report(app: &axum::Router, body: serde_json::Value) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/automotive/report")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the route returns the campaign report as JSON");
    report["markdown"]
        .as_str()
        .expect("the campaign report carries its Markdown")
        .to_owned()
}

#[tokio::test]
async fn automotive_report_route_composes_in_the_requested_language() {
    let project = tempfile::tempdir().unwrap();
    let database = tempfile::tempdir().unwrap();

    // A real store with no retained automotive evidence yet: enough to exercise
    // the deterministic fact-sheet path end to end -- request body through the
    // router, into ServiceContainer::generate_automotive_report, back out as a
    // campaign report -- without staging a sidecar operation.
    let container = hf_service::ServiceContainer::stubbed()
        .with_store_path(database.path().join("automotive.db"))
        .await
        .unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.path().to_path_buf()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(container),
        security,
    );

    let chinese = post_automotive_report(
        &app,
        serde_json::json!({
            "project_root": project.path(),
            "language": "zh",
        }),
    )
    .await;
    assert!(
        chinese.starts_with("# 汽车协议模糊测试活动报告："),
        "the request's language must reach generate_automotive_report: {chinese}"
    );
    assert!(chinese.contains("## 证据清单"), "{chinese}");

    // Omitting the field is still English, so existing clients are unaffected.
    let default =
        post_automotive_report(&app, serde_json::json!({ "project_root": project.path() })).await;
    assert!(
        default.starts_with("# Automotive Fuzzing Campaign Report: "),
        "an omitted language must compose in English: {default}"
    );
    assert!(default.contains("## Evidence Manifest"), "{default}");
}
