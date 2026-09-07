//! Campaign Health REST ownership, hydration, and summary semantics.

#![cfg(feature = "campaign-health")]

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use futures::StreamExt as _;
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt as _;

async fn request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Body,
) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap()
}

async fn fixture() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    uuid::Uuid,
    hf_service::ServiceContainer,
) {
    hf_service::test_support::campaign_health_presentation_fixture()
        .await
        .unwrap()
}

#[tokio::test]
async fn durable_health_events_reach_only_an_authorized_sse_stream() {
    let (_directory, project, run_id, container) = fixture().await;
    let security = WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()]).unwrap();
    let producer = container.clone();
    let app = build_with_state_and_security(AppState::new(container), security);
    let response = request(&app, Method::GET, "/events", Body::empty()).await;
    let mut body = response.into_body().into_data_stream();

    let inserted = producer
        .assess_and_emit_campaign_health(run_id, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(inserted.len(), 1);
    let chunk = tokio::time::timeout(std::time::Duration::from_secs(1), body.next())
        .await
        .expect("authorized health delivery")
        .expect("open SSE stream")
        .expect("readable SSE chunk");
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("event: campaign:health"), "{text}");
    assert!(text.contains(&run_id.to_string()), "{text}");

    let (_directory, _project, outside_run_id, outside_container) = fixture().await;
    let unrelated = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        None,
        true,
        Vec::new(),
        vec![std::fs::canonicalize(unrelated.path()).unwrap()],
    )
    .unwrap();
    let producer = outside_container.clone();
    let app = build_with_state_and_security(AppState::new(outside_container), security);
    let response = request(&app, Method::GET, "/events", Body::empty()).await;
    let mut body = response.into_body().into_data_stream();
    assert_eq!(
        producer
            .assess_and_emit_campaign_health(outside_run_id, chrono::Utc::now())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), body.next())
            .await
            .is_err(),
        "outside-root health must not enter the SSE stream"
    );
}

#[tokio::test]
async fn exact_run_reads_authorize_the_durable_owner() {
    let (_directory, project, run_id, container) = fixture().await;
    let outside = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        None,
        true,
        Vec::new(),
        vec![std::fs::canonicalize(outside.path()).unwrap()],
    )
    .unwrap();
    let app = build_with_state_and_security(AppState::new(container), security);

    for uri in [
        format!("/runs/{run_id}/owner"),
        format!("/runs/{run_id}/health"),
        format!("/runs/{run_id}/telemetry"),
        format!("/runs/{run_id}/health/events"),
        format!("/runs/{run_id}/status"),
    ] {
        assert_eq!(
            request(&app, Method::GET, &uri, Body::empty())
                .await
                .status(),
            StatusCode::FORBIDDEN,
            "{uri} must authorize retained owner {project:?}"
        );
    }
    assert_eq!(
        request(
            &app,
            Method::POST,
            &format!("/runs/{run_id}/cancel"),
            Body::empty(),
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn owner_health_hydration_and_morning_summary_are_project_scoped() {
    let (_directory, project, run_id, container) = fixture().await;
    let security = WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()]).unwrap();
    let app = build_with_state_and_security(AppState::new(container), security);

    for uri in [
        format!("/runs/{run_id}/owner"),
        format!("/runs/{run_id}/health"),
    ] {
        assert_eq!(
            request(&app, Method::GET, &uri, Body::empty())
                .await
                .status(),
            StatusCode::OK,
            "{uri}"
        );
    }

    let response = request(
        &app,
        Method::GET,
        &format!("/runs/{run_id}/health/events?limit=25"),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(page["events"].is_array());
    assert!(page.get("next_cursor").is_some());
    assert_eq!(
        request(
            &app,
            Method::GET,
            &format!("/runs/{run_id}/health/events?limit=0"),
            Body::empty(),
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    let response = request(
        &app,
        Method::GET,
        &format!("/runs/{run_id}/telemetry"),
        Body::empty(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let telemetry: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(telemetry["throughput_sample_count"], 1);
    assert_eq!(telemetry["throughput_sample_sum"], 5.0);
    assert_eq!(telemetry["mean_execs"], 5.0);

    let body = serde_json::json!({ "project": project });
    let response = request(
        &app,
        Method::POST,
        "/campaign-health/morning",
        Body::from(serde_json::to_vec(&body).unwrap()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let summary: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(summary["failed"], serde_json::json!([run_id]));
    assert_eq!(summary["unprocessed"], serde_json::json!([run_id]));
}
