//! Tests for the REST API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok() {
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
