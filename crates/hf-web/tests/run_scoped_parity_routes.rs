//! The run-scoped routes added for the browser GUI (run detail, edge-set
//! capture and diff) authorize the persisted run owner before any work.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hf_service::test_support::{RunRecord, RunStatus, Store};
use tower::ServiceExt;

fn done_run(project: &std::path::Path) -> RunRecord {
    let mut run = RunRecord::new(
        project.to_string_lossy(),
        hf_service::EngineKind::LibFuzzer,
        None,
        chrono::Utc::now(),
    );
    run.status = RunStatus::Done;
    run
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let mut request = Request::builder().method(method).uri(uri);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn run_scoped_routes_refuse_a_run_outside_the_approved_roots() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::connect(approved.path().join("records.db"))
            .await
            .unwrap(),
    );
    let foreign = done_run(outside.path());
    let own = done_run(approved.path());
    store.insert_run(&foreign).await.unwrap();
    store.insert_run(&own).await.unwrap();
    let container = hf_service::ServiceContainer::stubbed().with_store(store);
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![approved.path().to_path_buf()])
            .unwrap();
    let app = hf_web::build_with_state_and_security(hf_web::AppState::new(container), security);
    let outside_text = outside.path().to_str().unwrap().to_owned();

    let (status, body) = send(&app, "GET", &format!("/runs/detail/{}", foreign.id), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains(&outside_text));

    // The approved project's own run resolves, by a short id prefix too.
    let short = &own.id.to_string()[..8];
    let (status, body) = send(&app, "GET", &format!("/runs/detail/{short}"), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(detail["id"], own.id.to_string());

    #[cfg(feature = "run-closeout")]
    {
        let (status, body) = send(&app, "POST", &format!("/runs/{}/edges", foreign.id), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        for (baseline, result) in [(foreign.id, own.id), (own.id, foreign.id)] {
            let (status, body) = send(
                &app,
                "POST",
                "/runs/edge-diff",
                Some(serde_json::json!({ "baseline_id": baseline, "result_id": result })),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{baseline} -> {result}: {body}"
            );
            assert!(!body.contains(&outside_text));
        }
    }
}
