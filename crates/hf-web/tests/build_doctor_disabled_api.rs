//! Profile reads survive feature-disabled builds; excluded operations explain their absence.
#![cfg(not(feature = "build-doctor"))]
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt;

async fn response(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    // Route-absence replies in the RED implementation are empty, not JSON.
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
    });
    (status, value)
}

#[tokio::test]
async fn feature_disabled_build_operations_explain_unavailability_and_authorize_project_roots() {
    let project = tempfile::tempdir().unwrap();
    let denied = tempfile::tempdir().unwrap();
    let container = hf_service::ServiceContainer::stubbed()
        .with_store_path(project.path().join("state.db"))
        .await
        .unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.path().to_owned()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(container),
        security.clone(),
    );
    assert_eq!(
        response(
            &app,
            "GET",
            &format!("/build/profile?project={}", project.path().display()),
            serde_json::Value::Null
        )
        .await,
        (StatusCode::OK, serde_json::Value::Null)
    );
    assert_eq!(
        response(
            &app,
            "GET",
            &format!("/build/profile?project={}", denied.path().display()),
            serde_json::Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    // Excluded operations also work without a store: they must not call a service operation.
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    for root in [project.path(), denied.path()] {
        let project_name = root.to_string_lossy();
        for (method, uri, body) in [
            (
                "PUT",
                "/build/profile".to_owned(),
                serde_json::json!({"project":project_name,"component_root":".","build_system":"cmake","compile_database_path":"build/compile_commands.json","cmake_definitions":{},"dependencies":[]}),
            ),
            (
                "DELETE",
                "/build/profile".to_owned(),
                serde_json::json!({"project":project_name}),
            ),
            (
                "POST",
                "/build/diagnose".to_owned(),
                serde_json::json!({"project":project_name}),
            ),
            (
                "POST",
                "/build/run".to_owned(),
                serde_json::json!({"project":project_name,"expected_profile_sha256":"a".repeat(64)}),
            ),
            (
                "GET",
                format!("/build/history?project={project_name}&limit=20"),
                serde_json::Value::Null,
            ),
        ] {
            let (status, value) = response(&app, method, &uri, body).await;
            if root == denied.path() {
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {value}");
            } else {
                assert_eq!(
                    status,
                    StatusCode::NOT_IMPLEMENTED,
                    "{method} {uri}: {value}"
                );
                assert_eq!(
                    value,
                    serde_json::json!({"code":"build_doctor_unavailable","error":"build diagnosis is not included in this application build"})
                );
            }
        }
    }
}
