//! Project selection validates paths without scanning or executing the project.
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt;

#[tokio::test]
async fn selection_returns_only_an_authorized_canonical_directory() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let child = root.path().join("sample");
    std::fs::create_dir(&child).unwrap();
    let file = root.path().join("file.c");
    std::fs::write(&file, "fixture").unwrap();
    let security = WebSecurityConfig::new(
        Some("fixture-token".into()),
        false,
        vec![],
        vec![root.path().into()],
    )
    .unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    for (path, token, expected) in [
        (child.join("."), true, StatusCode::OK),
        (outside.path().to_path_buf(), true, StatusCode::FORBIDDEN),
        (root.path().join("missing"), true, StatusCode::FORBIDDEN),
        (file, true, StatusCode::FORBIDDEN),
        (child.clone(), false, StatusCode::UNAUTHORIZED),
    ] {
        let mut request = Request::builder()
            .method("POST")
            .uri("/projects/select")
            .header("content-type", "application/json");
        if token {
            request = request.header("authorization", "Bearer fixture-token");
        }
        let response = app
            .clone()
            .oneshot(
                request
                    .body(Body::from(serde_json::json!({"project":path}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        if expected == StatusCode::OK {
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(
                value["project"],
                child.canonicalize().unwrap().to_str().unwrap()
            );
        } else {
            assert!(!String::from_utf8_lossy(&bytes).contains(outside.path().to_str().unwrap()));
        }
    }
}

#[cfg(unix)]
#[tokio::test]
async fn selection_rejects_a_symlink_outside_approved_roots() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let link = root.path().join("escape");
    std::os::unix::fs::symlink(outside.path(), &link).unwrap();
    let security = WebSecurityConfig::new(None, true, vec![], vec![root.path().into()]).unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/projects/select")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"project":link}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
