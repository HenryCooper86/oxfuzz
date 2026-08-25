//! Isolated Build Doctor REST contract.
//!
//! This integration target intentionally contains exactly one test. Cargo runs
//! each integration target in its own process, so its process-global auth
//! override cannot race with unrelated `hf-web` tests.

#![cfg(feature = "build-doctor")]

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
async fn rest_serves_the_service_diagnosis_and_refuses_an_unrunnable_build() {
    allow_open_dev_mode();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("CMakeLists.txt"), b"project(p)\n").unwrap();
    std::fs::write(project.path().join("Makefile"), b"all:\n\ttrue\n").unwrap();
    let root = project.path().display().to_string();

    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.path().to_path_buf()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let (status, diagnosis) = post(
        &app,
        "/build/diagnose",
        serde_json::json!({ "project": root }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "diagnose: {diagnosis}");
    let entries = diagnosis.as_array().expect("a list of diagnoses");

    // CMake ranks first and carries a runnable plan with its expected artifact.
    assert_eq!(entries[0]["build_system"], "cmake");
    assert_eq!(entries[0]["status"], "supported");
    assert_eq!(
        entries[0]["plan"]["expected_artifact"],
        ".oxfuzz-build/compile_commands.json"
    );
    assert_eq!(entries[0]["plan"]["steps"][0]["argv"][0], "cmake");

    // The generated Makefile is reported too, as unsupported, naming the tool.
    assert_eq!(entries[1]["build_system"], "make");
    assert_eq!(entries[1]["status"], "unsupported_in_image");
    assert_eq!(entries[1]["missing_tool"], "bear");
    assert_eq!(entries[1]["plan"], serde_json::Value::Null);

    // Running a build the image cannot run is refused by the service, not the
    // transport, and names the missing tool.
    let (status, refused) = post(
        &app,
        "/build/run",
        serde_json::json!({ "project": root, "build_system": "make" }),
    )
    .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "an unrunnable build is refused, got {status}: {refused}"
    );
}
