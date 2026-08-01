//! Isolated `/report` language contract.
//!
//! This integration target intentionally contains exactly one test. Cargo runs
//! each integration target in its own process, so its `HF_WORKSPACE_DIR`
//! override cannot race with unrelated `hf-web` tests.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// POST `/report` and return the composed Markdown.
async fn post_report(app: &axum::Router, body: serde_json::Value) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/report")
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
    serde_json::from_slice::<String>(&bytes).expect("the route returns the report as a JSON string")
}

#[tokio::test]
async fn report_route_composes_in_the_requested_language() {
    let project = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    // SAFETY: this dedicated integration-test binary contains exactly one
    // test, and Cargo executes integration binaries in separate processes.
    // No sibling test can observe or replace this process-local override.
    unsafe {
        std::env::set_var("HF_WORKSPACE_DIR", workspace.path().join("managed"));
    }
    std::fs::write(
        project.path().join("parser.c"),
        "int parse_packet(const unsigned char *data) { return data[0]; }\n",
    )
    .unwrap();

    // A store-less, stub-runtime container, so this exercises the deterministic
    // fact-sheet path end to end -- request body through the router, into
    // ServiceContainer::generate_report, back out as Markdown.
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.path().to_path_buf()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let chinese = post_report(
        &app,
        serde_json::json!({
            "project": project.path(),
            "target": "parse_packet",
            "language": "zh",
        }),
    )
    .await;
    assert!(
        chinese.starts_with("# 模糊测试报告"),
        "the request's language must reach generate_report: {chinese}"
    );
    assert!(chinese.contains("## 发现项"));
    // The target symbol is a technical token and is never translated.
    assert!(chinese.contains("parse_packet"));

    // Omitting the field is still English, so existing clients are unaffected.
    let default = post_report(
        &app,
        serde_json::json!({
            "project": project.path(),
            "target": "parse_packet",
        }),
    )
    .await;
    assert!(
        default.starts_with("# Fuzzing Report"),
        "an omitted language must compose in English: {default}"
    );
    assert!(default.contains("## Findings"));
}
