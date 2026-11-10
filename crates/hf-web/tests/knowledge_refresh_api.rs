//! Real HTTP refresh and status, using an isolated source tree and no provider.
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use tower::ServiceExt;

static ENVIRONMENT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn request(app: &Router, method: &str, uri: &str, body: Value) -> Value {
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
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn http_search_refreshes_edits_and_deletions_and_reports_index_settings() {
    let _environment = ENVIRONMENT.lock().await;
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path().join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.path().join("workspace"));
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()]).unwrap();
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    let file = project.join("parser.c");
    std::fs::write(&file, "int alpha_symbol(void) { return 1; }").unwrap();
    let search = |query: &str| json!({ "project": project, "query": query, "limit": 10 });
    let first = request(&app, "POST", "/knowledge/search", search("alpha_symbol")).await;
    assert!(!first.as_array().unwrap().is_empty());
    let status_uri = format!("/knowledge/stats?project={}", project.display());
    let status = request(&app, "GET", &status_uri, Value::Null).await;
    assert_eq!(status["stale"], false);
    assert_eq!(status["effective"]["embedding_model"], Value::Null);
    assert!(status["configured"]["chunk_max_tokens"].is_number());
    std::fs::write(&file, "int bravo_symbol(void) { return 2; }").unwrap();
    assert_eq!(
        request(&app, "GET", &status_uri, Value::Null).await["stale"],
        true
    );
    let changed = request(&app, "POST", "/knowledge/search", search("bravo_symbol")).await;
    assert!(!changed.as_array().unwrap().is_empty());
    assert!(
        request(&app, "POST", "/knowledge/search", search("alpha_symbol"))
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    std::fs::remove_file(file).unwrap();
    assert!(
        request(&app, "POST", "/knowledge/search", search("bravo_symbol"))
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn search_reports_invalid_configuration_instead_of_no_matches() {
    let _environment = ENVIRONMENT.lock().await;
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(config.join("oxfuzz.toml"), "invalid = [").unwrap();
    std::env::set_var("HF_CONFIG_DIR", &config);
    std::env::set_var("HF_WORKSPACE_DIR", root.path().join("workspace"));
    let response = failing_search(root.path()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn search_reports_busy_knowledge_instead_of_no_matches() {
    let _environment = ENVIRONMENT.lock().await;
    let root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path().join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.path().join("workspace"));
    hf_service::knowledge::index_project(root.path()).unwrap();
    let docs = hf_service::knowledge::docs_dir(root.path());
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            docs.parent()
                .unwrap()
                .join(".locks")
                .join(docs.file_name().unwrap()),
        )
        .unwrap();
    lock.try_lock().unwrap();
    let response = failing_search(root.path()).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

async fn failing_search(project: &std::path::Path) -> axum::response::Response {
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.to_path_buf()])
            .unwrap();
    let app = hf_web::build_with_state_and_security(
        hf_web::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );
    app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/knowledge/search")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "project": project, "query": "parser" }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap()
}
