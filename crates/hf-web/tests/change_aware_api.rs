//! Isolated Change-Aware REST contract.
//!
//! This integration target intentionally contains exactly one test. Cargo runs
//! each integration target in its own process, so its process-global auth
//! override cannot race with unrelated `hf-web` tests.

#![cfg(feature = "change-aware")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

fn allow_open_dev_mode() {
    // SAFETY: this binary contains exactly one test, only ever sets this to
    // "1", and never sets HF_WEB_TOKEN, so there is no conflicting concurrent
    // mutation.
    unsafe {
        std::env::set_var("HF_WEB_TOKEN_OPTIONAL", "1");
    }
}

async fn post(
    app: &axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn rest_serves_the_service_comparison_and_never_publishes_on_its_own() {
    allow_open_dev_mode();
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .expect("change-aware fixture");
    let app = hf_web::router::build_with_state(hf_web::router::AppState::new(fixture.container()));

    // A supplied diff needs no checkout and maps onto the retained targets.
    let (status, impact) = post(
        &app,
        "/change/impact",
        serde_json::json!({
            "project": fixture.project_root().display().to_string(),
            "diff": "--- a/parser.c\n+++ b/parser.c\n@@ -4,0 +5,1 @@\n+    int extra = 1;\n",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "impact: {impact}");
    assert_eq!(impact["files"][0]["new_path"], "parser.c");
    let affected = impact["affected"].as_array().expect("affected targets");
    assert!(affected
        .iter()
        .any(|entry| entry["symbol"] == fixture.target_symbol() && entry["impact"] == "changed"));

    // The comparison is the service's, rendered verbatim.
    let (status, comparison) = post(
        &app,
        "/change/compare",
        serde_json::json!({
            "base_run_id": fixture.base_run().to_string(),
            "head_run_id": fixture.head_run().to_string(),
            "regression_threshold_pct": 5.0,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "compare: {comparison}");
    assert_eq!(comparison["comparable"], true);
    assert_eq!(comparison["coverage"]["status"], "regressed");
    let findings = comparison["findings"].as_array().expect("findings");
    assert!(findings
        .iter()
        .any(|entry| entry["stack_signature"] == "fresh" && entry["change"] == "introduced"));

    // Publication is outward-facing: the transport cannot make it happen
    // without an authorized, configured integration.
    let (status, published) = post(
        &app,
        "/change/publish",
        serde_json::json!({
            "base_run_id": fixture.base_run().to_string(),
            "head_run_id": fixture.head_run().to_string(),
            "regression_threshold_pct": 5.0,
            "destination": "issue_tracker",
        }),
    )
    .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "publication must not succeed unprompted, got {status}: {published}"
    );
}
