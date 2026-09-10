//! First-run provider persistence and live availability without model traffic.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn first_provider_is_saved_and_available_without_restarting_the_service() {
    let root = tempfile::tempdir().unwrap();
    // This integration binary has one test; only its process uses this fixture.
    std::env::set_var("HF_CONFIG_DIR", root.path());
    let container = hf_service::ServiceContainer::stubbed();
    let observer = container.clone();
    assert!(observer.provider_pool().is_none());
    let security = hf_web::WebSecurityConfig::new(
        Some("fixture-token".into()),
        false,
        Vec::new(),
        vec![root.path().into()],
    )
    .unwrap();
    let app = hf_web::build_with_state_and_security(hf_web::AppState::new(container), security);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/setup/providers")
                .header("authorization", "Bearer fixture-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), 1024).await.unwrap().as_ref(),
        b"[]"
    );
    let provider = serde_json::json!({"provider": {"id": "fixture", "provider_type": "openai", "api_key": "fixture-key", "base_url": "http://127.0.0.1:9/v1", "model": "fixture-model"}});
    for expected in [StatusCode::OK, StatusCode::BAD_REQUEST] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/system/setup/providers")
                    .header("authorization", "Bearer fixture-token")
                    .header("content-type", "application/json")
                    .body(Body::from(provider.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert!(
        observer.provider_pool().is_some(),
        "the saved provider must be usable without restarting"
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/system/setup/providers")
                .header("authorization", "Bearer fixture-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 16384).await.unwrap();
    let providers: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(providers[0]["model"], "fixture-model");
    assert_eq!(providers[0]["api_key"], serde_json::Value::Null);
    assert_eq!(providers[0]["api_key_configured"], true);
}
