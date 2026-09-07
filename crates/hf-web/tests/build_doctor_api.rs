//! Build profile REST behavior through the real service and durable store.
#![cfg(feature = "build-doctor")]

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hf_service::{
    ClassifiedError, CommandResult, ImmutableImageReference, ResourceLimits, RuntimeAdapter,
    ServiceContainer,
};
use std::{path::Path, sync::Arc};
use tower::ServiceExt;

struct ImageOnly;
#[async_trait]
impl RuntimeAdapter for ImageOnly {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_service::test_support::immutable_test_image()?))
    }
    async fn run_command(
        &self,
        _: &[String],
        _: &Path,
        _: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        panic!("no build or probe expected")
    }
    async fn write_file(&self, _: &Path, _: &str) -> Result<(), ClassifiedError> {
        panic!("no runtime write")
    }
    async fn read_file(&self, _: &Path) -> Result<String, ClassifiedError> {
        panic!("no runtime read")
    }
}

async fn request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .method(method)
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
    // Rejection bodies from Axum can be plain text rather than service JSON.
    let value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        serde_json::Value::String(String::from_utf8_lossy(&bytes).into_owned())
    });
    (status, value)
}

#[tokio::test]
async fn profile_round_trip_history_validation_and_project_authorization() {
    let project = tempfile::tempdir().unwrap();
    let denied = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("CMakeLists.txt"), "project(p)\n").unwrap();
    let root = project.path().to_string_lossy().into_owned();
    let container = ServiceContainer::new(Arc::new(ImageOnly), None)
        .with_store_path(project.path().join("state.db"))
        .await
        .unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.path().to_owned()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(container),
        security,
    );
    let profile_uri = format!("/build/profile?project={root}");
    let history_uri = format!("/build/history?project={root}&limit=10");
    assert_eq!(
        request(&app, "GET", &profile_uri, serde_json::Value::Null).await,
        (StatusCode::OK, serde_json::Value::Null)
    );
    let (status, diagnosis) = request(
        &app,
        "POST",
        "/build/diagnose",
        serde_json::json!({"project":root}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{diagnosis}");
    assert_eq!(diagnosis["profile_state"], "unconfigured");
    assert!(diagnosis["plan"].is_null());
    let (status, history) = request(&app, "GET", &history_uri, serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(history[0]["diagnosis"], diagnosis);
    let save = serde_json::json!({"project":root,"component_root":".","build_system":"cmake","compile_database_path":"build/compile_commands.json","cmake_definitions":{"BUILD_TESTING":"OFF"},"dependencies":[{"kind":"pkg_config","name":"zlib"}]});
    let (status, saved) = request(&app, "PUT", "/build/profile", save.clone()).await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(saved["component_root"], ".");
    assert_eq!(
        saved["sandbox_image_id"],
        format!("sha256:{}", "a".repeat(64))
    );
    assert_eq!(
        request(&app, "GET", &profile_uri, serde_json::Value::Null)
            .await
            .1,
        saved
    );
    for (field, value) in [
        ("component_root", serde_json::json!("../escape")),
        ("cmake_definitions", serde_json::json!({"NOT_ALLOWED":"ON"})),
        (
            "dependencies",
            serde_json::json!([{"kind":"command","name":"a;b"}]),
        ),
    ] {
        let mut invalid = save.clone();
        invalid[field] = value;
        assert_eq!(
            request(&app, "PUT", "/build/profile", invalid).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    let (status, stale) = request(
        &app,
        "POST",
        "/build/run",
        serde_json::json!({"project":root,"expected_profile_sha256":"b".repeat(64)}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{stale}");
    assert!(stale["error"]
        .as_str()
        .unwrap()
        .contains("digest does not match"));
    assert!(request(
        &app,
        "POST",
        "/build/run",
        serde_json::json!({"project":root,"build_system":"cmake"})
    )
    .await
    .0
    .is_client_error());
    assert_eq!(
        request(
            &app,
            "GET",
            &format!("/build/history?project={root}&limit=0"),
            serde_json::Value::Null
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let retained_before_clear = request(&app, "GET", &history_uri, serde_json::Value::Null)
        .await
        .1;
    assert_eq!(
        request(
            &app,
            "DELETE",
            "/build/profile",
            serde_json::json!({"project":root})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(request(&app, "GET", &profile_uri, serde_json::Value::Null)
        .await
        .1
        .is_null());
    assert_eq!(
        request(&app, "GET", &history_uri, serde_json::Value::Null)
            .await
            .1,
        retained_before_clear
    );
    let forbidden = denied.path().to_string_lossy();
    for (method, uri, body) in [
        (
            "GET",
            format!("/build/profile?project={forbidden}"),
            serde_json::Value::Null,
        ),
        (
            "GET",
            format!("/build/history?project={forbidden}&limit=10"),
            serde_json::Value::Null,
        ),
        (
            "DELETE",
            "/build/profile".to_owned(),
            serde_json::json!({"project":forbidden}),
        ),
        (
            "POST",
            "/build/diagnose".to_owned(),
            serde_json::json!({"project":forbidden}),
        ),
        (
            "POST",
            "/build/run".to_owned(),
            serde_json::json!({"project":forbidden,"expected_profile_sha256":"b".repeat(64)}),
        ),
        ("PUT", "/build/profile".to_owned(), {
            let mut value = save;
            value["project"] = serde_json::json!(forbidden);
            value
        }),
    ] {
        assert_eq!(
            request(&app, method, &uri, body).await.0,
            StatusCode::FORBIDDEN,
            "{method} {uri}"
        );
    }
}
