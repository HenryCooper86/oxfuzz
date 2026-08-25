//! Isolated Patch-to-Proof REST contract.
//!
//! This integration target intentionally contains exactly one test. Cargo runs
//! each integration target in its own process, so its process-global auth
//! override cannot race with unrelated `hf-web` tests.
//!
//! The transport is proved to be a transport: it cannot start verification for
//! an unapproved operation, and no request body can talk the service into a
//! verified determination.

#![cfg(feature = "patch-to-proof")]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// These tests exercise endpoints without a bearer token, so they run in the
/// explicit unauthenticated local-dev mode.
fn allow_open_dev_mode() {
    // SAFETY: this binary contains exactly one test, only ever sets this to
    // "1", and never sets HF_WEB_TOKEN, so there is no conflicting concurrent
    // mutation.
    unsafe {
        std::env::set_var("HF_WEB_TOKEN_OPTIONAL", "1");
    }
}

async fn send(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let builder = Request::builder()
        .uri(uri)
        .method(method)
        .header("content-type", "application/json");
    let request = match body {
        Some(value) => builder.body(Body::from(value.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn rest_transports_the_service_workflow_and_cannot_claim_verification() {
    allow_open_dev_mode();
    let fixture = hf_service::test_support::patch_to_proof_fixture()
        .await
        .expect("patch-to-proof fixture");
    let app = hf_web::router::build_with_state(hf_web::router::AppState::new(fixture.container()));
    let operation = fixture.operation_id();

    // The persisted draft is readable through the transport and carries the
    // service-owned immutable binding rather than a presentation-derived view.
    let (status, draft) = send(
        &app,
        "GET",
        &format!("/remediation/operations/{operation}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "draft read: {draft}");
    assert_eq!(draft["status"], "draft");
    assert_eq!(draft["current_stage"], "review");
    assert_eq!(draft["verification"], serde_json::Value::Null);
    assert_eq!(
        draft["binding"]["finding_id"],
        fixture.finding_id().to_string()
    );
    assert!(
        draft["binding"]["verification_spec_sha256"]
            .as_str()
            .is_some_and(|digest| digest.len() == 64),
        "the binding carries the approved specification digest: {draft}"
    );

    // Verification cannot start before approval, and the rejected attempt does
    // not mutate the retained row.
    let (status, _) = send(
        &app,
        "POST",
        &format!("/remediation/operations/{operation}/verify"),
        Some(serde_json::json!({ "status": "verified", "verified": true })),
    )
    .await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "an unapproved operation must not start verification, got {status}"
    );
    let (_, unchanged) = send(
        &app,
        "GET",
        &format!("/remediation/operations/{operation}"),
        None,
    )
    .await;
    assert_eq!(unchanged["status"], "draft");

    // Approval is an explicit, operator-attributed transition; a body that
    // claims a terminal status cannot produce one.
    let (status, approved) = send(
        &app,
        "POST",
        &format!("/remediation/operations/{operation}/approve"),
        Some(serde_json::json!({ "operator": "henry", "status": "verified" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "approve: {approved}");
    assert_eq!(approved["status"], "approved");

    let (_, after) = send(
        &app,
        "GET",
        &format!("/remediation/operations/{operation}"),
        None,
    )
    .await;
    assert_eq!(after["status"], "approved");
    assert_eq!(
        after["verification"],
        serde_json::Value::Null,
        "approval alone never produces sandbox evidence"
    );

    // The Finding Proof Card served for the same finding still reports the fix
    // as unverified: a non-terminal operation is never a positive result.
    let (status, card) = send(
        &app,
        "GET",
        &format!("/findings/{}/proof-card", fixture.finding_id()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "proof card: {card}");
    assert_eq!(card["fix_verification"]["determination"], "not_verified");
}
