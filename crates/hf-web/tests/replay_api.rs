//! Replay authorizes retained ownership before disclosing settings or executing.
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hf_service::test_support::{RunRecord, Store};
use tower::ServiceExt;
#[tokio::test]
async fn replay_authorizes_the_retained_owner_before_review_or_start() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = std::sync::Arc::new(Store::connect(root.path().join("runs.db")).await.unwrap());
    let run = RunRecord::new(
        outside.path().to_string_lossy(),
        hf_service::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    store.insert_run(&run).await.unwrap();
    let service = hf_service::ServiceContainer::stubbed().with_store(store);
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![root.path().into()]).unwrap();
    let app = hf_web::build_with_state_and_security(hf_web::AppState::new(service), security);
    for method in ["GET", "POST"] {
        let body = if method == "POST" {
            serde_json::json!({"review": {
            "run_id": run.id, "project": root.path(), "target": "parse", "engine": "LibFuzzer",
            "seed": "18446744073709551615", "duration_secs": 60, "max_mem_mb": "512", "max_cpus": 1
        }}).to_string()
        } else {
            String::new()
        };
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(format!("/runs/{}/replay", run.id))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(outside.path().to_str().unwrap()));
    }
}
