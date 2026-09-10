//! Provider connection tests require the same authorization as configuration.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

#[tokio::test]
async fn provider_probe_authorizes_before_validating_an_unusable_provider() {
    let root = tempfile::tempdir().unwrap();
    let security = hf_web::WebSecurityConfig::new(
        Some("test-token".into()),
        false,
        Vec::new(),
        vec![root.path().into()],
    )
    .unwrap();
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    for (method, uri) in [
        ("GET", "/system/setup"),
        ("GET", "/system/setup/providers"),
        ("POST", "/system/setup/providers"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some("Bearer test-token"), StatusCode::BAD_REQUEST),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/config/providers/test")
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", token);
        }
        let body = serde_json::json!({"provider": {"id": "fixture", "provider_type": "unsupported-fixture", "model": "unused"}});
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}
