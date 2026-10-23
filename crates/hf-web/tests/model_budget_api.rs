//! GUI budget ingress uses service configuration and exact decimal presentation.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn budget_view_and_settings_conversion_preserve_service_policy() {
    let directory = tempfile::tempdir().unwrap();
    // This integration binary has one test; environment is isolated to its process.
    std::env::set_var("HF_CONFIG_DIR", directory.path());
    std::fs::write(directory.path().join("oxfuzz.toml"), "").unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, vec![], vec![directory.path().into()]).unwrap();
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/model-budget")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let view: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(view["available"], cfg!(feature = "model-budgets"));
    assert!(view["settings"]["scope_id"].is_null());
    assert_eq!(view["settings"]["max_output_tokens"], "4096");
    assert!(view["usage"].is_null());
    let body = serde_json::json!({"content":"[model_budget]\nscope_id='trial'\nmax_tokens=9007199254740993"});
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config/toml_to_value")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 16_384).await.unwrap()).unwrap();
    assert_eq!(value["model_budget"]["max_tokens"], "9007199254740993");
}
