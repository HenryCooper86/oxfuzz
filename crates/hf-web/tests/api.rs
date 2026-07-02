//! Tests for the REST API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[test]
fn manifest_does_not_depend_on_domain_or_runtime_crates() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("read hf-web manifest");
    let forbidden = [
        "hf-core",
        "hf-runtime",
        "hf-harness",
        "hf-discovery",
        "hf-corpus",
        "hf-crash",
    ];

    for crate_name in forbidden {
        let prefix = format!("{crate_name} =");
        assert!(
            !manifest
                .lines()
                .any(|line| line.trim_start().starts_with(&prefix)),
            "hf-web must go through hf-service, but depends directly on {crate_name}"
        );
    }
}

/// These integration tests exercise endpoints without a bearer token, so they
/// run in the explicit unauthenticated local-dev mode. Setting the same value
/// in every test (and never `HF_WEB_TOKEN`) keeps the process-global env
/// consistent regardless of test execution order. The fail-closed auth logic
/// itself is covered by the pure `auth_tests` unit tests in `router.rs`.
fn allow_open_dev_mode() {
    // SAFETY: tests in this binary only ever set this to "1" and never set
    // HF_WEB_TOKEN, so there is no conflicting concurrent mutation.
    unsafe {
        std::env::set_var("HF_WEB_TOKEN_OPTIONAL", "1");
    }
}

#[tokio::test]
async fn health_returns_ok() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn discover_returns_json() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("sample_c");
    let body = serde_json::json!({
        "project": fixture,
        "lang": "c"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/discover")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        json["candidates"].is_array(),
        "response should have candidates array"
    );
    assert!(
        !json["candidates"].as_array().unwrap().is_empty(),
        "fixture project should have candidates"
    );
}

#[tokio::test]
async fn corpus_list_returns_json() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/corpus/list")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"project": ".", "target": "x"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(json.is_array(), "corpus list should return array");
}

/// POST a JSON body to `uri` and return (status, parsed-json).
async fn post_json(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
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
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn create_session_without_db_returns_null() {
    // No database in the bare test state -> create returns null, not an error.
    let (status, json) = post_json("/chat/session", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.is_null(), "expected null session id, got {json}");
}

#[tokio::test]
async fn chat_history_without_db_returns_empty_array() {
    let (status, json) = post_json("/chat/history", serde_json::json!({"session_id": "s1"})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json.as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn config_conversion_endpoints_round_trip_json_and_toml() {
    let (status, json) = post_json(
        "/config/toml_to_value",
        serde_json::json!({"content": "enabled = true"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["enabled"], true);

    let (status, json) = post_json(
        "/config/value_to_toml",
        serde_json::json!({"value": {"enabled": true}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json, "enabled = true\n");
}

#[tokio::test]
async fn system_status_returns_json_flags() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["docker"].is_boolean());
    assert!(json["sandbox_image"].is_boolean());
    assert!(json["libfuzzer"].is_boolean());
}

#[tokio::test]
async fn knowledge_search_unindexed_returns_empty_array() {
    let (status, json) = post_json(
        "/knowledge/search",
        serde_json::json!({"project": ".", "query": "anything"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.is_array(), "search should return an array");
}

#[tokio::test]
async fn workbench_dashboard_without_db_returns_empty_summary() {
    let (status, json) = post_json(
        "/workbench/dashboard",
        serde_json::json!({"project": ".", "target": "parse_packet"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["totals"]["targets"], 0);
    assert!(json["next_actions"].is_array());
}

#[tokio::test]
async fn schedule_list_without_scheduler_returns_empty_array() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/schedule")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json.as_array().map(Vec::len), Some(0));
}
