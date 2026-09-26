#![cfg(feature = "ai-target-ranking")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hf_service::ServiceContainer;
use tower::ServiceExt;

#[tokio::test]
async fn rest_exposes_ranked_discovery_and_protects_its_project() {
    let project = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("parser.c"),
        "int parse_bytes(const unsigned char *data) { return data[0]; }\n",
    )
    .unwrap();
    let service = ServiceContainer::stubbed()
        .with_store_path(project.path().join("ranking.db"))
        .await
        .unwrap();
    let allowed =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.path().to_path_buf()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(service.clone()),
        allowed,
    );
    let start = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/discover/operations")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"project": project.path(), "lang": "c"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::ACCEPTED);
    let body = to_bytes(start.into_body(), 4096).await.unwrap();
    let started: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let id = started["operation_id"].as_str().unwrap();
    let operation_id = uuid::Uuid::parse_str(id).unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if service
                .ranked_discovery_status(operation_id)
                .await
                .unwrap()
                .unwrap()
                .revision
                == 2
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/discover/operations/{id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let status_body = to_bytes(status.into_body(), 4096).await.unwrap();
    let status: serde_json::Value = serde_json::from_slice(&status_body).unwrap();
    assert_eq!(status["state"], "completed");
    assert_eq!(status["revision"], 2);

    let result = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/discover/operations/{id}/result"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    let body = to_bytes(result.into_body(), 1024 * 1024).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["operation_id"], id);
    assert_eq!(result["ranking_source"], "heuristic");
    assert!(!result["inventory"]["candidates"]
        .as_array()
        .unwrap()
        .is_empty());

    let retry = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/discover/operations/{id}/retry"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry.status(), StatusCode::ACCEPTED);
    let retry_body = to_bytes(retry.into_body(), 4096).await.unwrap();
    let retry: serde_json::Value = serde_json::from_slice(&retry_body).unwrap();
    assert_ne!(retry["operation_id"], id);

    let cancel = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/discover/operations/{id}/cancel"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cancel.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(cancel.into_body(), 16).await.unwrap().as_ref(),
        b"false"
    );

    let forbidden =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![other.path().to_path_buf()])
            .unwrap();
    let foreign_app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(service),
        forbidden,
    );
    let foreign_read = foreign_app
        .oneshot(
            Request::builder()
                .uri(format!("/discover/operations/{id}/result"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(foreign_read.status(), StatusCode::FORBIDDEN);
}
