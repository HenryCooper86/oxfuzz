//! Roots-allowlist and auth-throttle regression tests for the feature routes
//! that previously reached their services without `approved_project`
//! (VULN-005/006/007/008/011a-c) and for the auth failure gate (VULN-013).

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt;

fn open_local_security(root: &std::path::Path) -> WebSecurityConfig {
    WebSecurityConfig::new(
        None,
        true,
        vec!["http://localhost:5173".to_owned()],
        vec![root.to_path_buf()],
    )
    .expect("valid test security config")
}

async fn post_json(app: axum::Router, uri: &str, body: serde_json::Value) -> StatusCode {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
    .status()
}

fn app(root: &std::path::Path) -> axum::Router {
    build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(root),
    )
}

/// One valid-shaped request body per gated feature route, with the project
/// pointing at a directory outside the approved roots. Bodies deserialize (all
/// required fields present) so a 403 can only come from the roots check.
fn gated_route_requests(outside: &std::path::Path) -> Vec<(&'static str, serde_json::Value)> {
    let script = serde_json::json!({
        "name": "responder",
        "initial_state": "idle",
        "rules": [{
            "from_state": "idle",
            "request": "read_dtc",
            "response": "ok",
            "to_state": "idle",
        }],
    });
    vec![
        (
            "/coverage/blockers",
            serde_json::json!({ "project": outside, "target": "parse", "lang": "C" }),
        ),
        (
            "/harness/tournament",
            serde_json::json!({
                "project": outside,
                "target": "parse",
                "engine": "libfuzzer",
                "lang": "C",
                "candidates": 2,
                "max_repairs": 1,
            }),
        ),
        (
            "/coverage/unreached",
            serde_json::json!({ "project": outside, "lang": "C" }),
        ),
        (
            "/corpus/concolic",
            serde_json::json!({ "project": outside, "target": "parse" }),
        ),
        (
            "/automotive/lab/simulate",
            serde_json::json!({ "project": outside, "script": script, "protocol": "can", "mode": "virtual_can", "operations": ["read_dtc"] }),
        ),
        (
            "/automotive/lab/coverage",
            serde_json::json!({ "project": outside, "protocol": "can" }),
        ),
        (
            "/automotive/lab/plan",
            serde_json::json!({ "project": outside, "protocol": "can", "mode": "virtual_can", "operations": ["read_dtc"] }),
        ),
    ]
}

#[tokio::test]
async fn feature_routes_refuse_projects_outside_the_approved_roots() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let router = app(allowed.path());
    for (uri, body) in gated_route_requests(outside.path()) {
        let status = post_json(router.clone(), uri, body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{uri} must refuse a project outside the approved roots"
        );
    }
}

#[tokio::test]
async fn feature_routes_do_not_leak_the_foreign_path_in_the_refusal() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let router = app(allowed.path());
    let (uri, body) = gated_route_requests(outside.path())
        .into_iter()
        .next()
        .unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains(
        outside
            .path()
            .to_str()
            .expect("temporary directories are valid UTF-8")
    ));
}

#[test]
fn weak_bearer_tokens_fail_startup_validation() {
    // VULN-013: the entropy floor rejects short tokens at load; anything
    // under 20 visible-ASCII characters cannot carry 128 bits of charset
    // entropy.
    let root = tempfile::tempdir().unwrap();
    for weak in ["short", "0123456789012345678"] {
        assert!(
            WebSecurityConfig::new(
                Some(weak.to_owned()),
                false,
                vec!["http://localhost:5173".to_owned()],
                vec![root.path().to_path_buf()],
            )
            .is_err(),
            "token of length {} must be rejected",
            weak.len()
        );
    }
    assert!(
        WebSecurityConfig::new(
            Some("01234567890123456789".to_owned()),
            false,
            vec!["http://localhost:5173".to_owned()],
            vec![root.path().to_path_buf()],
        )
        .is_ok(),
        "a 20-character visible-ASCII token meets the floor"
    );
}

#[tokio::test]
async fn repeated_failed_auth_attempts_are_throttled_with_429() {
    let root = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        Some("correct-horse-battery-staple".to_owned()),
        false,
        vec!["http://localhost:5173".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .unwrap();
    let router = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let mut unauthorized = 0;
    let mut throttled = 0;
    for _ in 0..12 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/system/status")
                    .header(header::AUTHORIZATION, "Bearer wrong-token-value-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        match response.status() {
            StatusCode::UNAUTHORIZED => unauthorized += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                throttled += 1;
                assert!(
                    response.headers().contains_key(header::RETRY_AFTER),
                    "throttled responses name a retry delay"
                );
            }
            status => panic!("unexpected status {status}"),
        }
    }
    assert_eq!(unauthorized + throttled, 12);
    assert!(throttled > 0, "repeated failures must engage the backoff");

    // The lockout throttles further wrong tokens, but a request carrying the
    // correct token is still admitted: the constant-time comparison runs
    // first, so an attacker's guessing can never lock out the legitimate
    // holder.
    let still_throttled = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .header(header::AUTHORIZATION, "Bearer wrong-token-value-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(still_throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    let correct = router
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .header(header::AUTHORIZATION, "Bearer correct-horse-battery-staple")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(correct.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_probes_do_not_reset_the_brute_force_window() {
    let root = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        Some("correct-horse-battery-staple".to_owned()),
        false,
        vec!["http://localhost:5173".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .unwrap();
    let router = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    // Nine failures, each interleaved with a `/health` probe: the health
    // carve-out neither checks nor records auth, so the window survives.
    for _ in 0..9 {
        let failed = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/system/status")
                    .header(header::AUTHORIZATION, "Bearer wrong-token-value-123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(failed.status(), StatusCode::UNAUTHORIZED);
        let healthy = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(healthy.status(), StatusCode::OK);
    }

    // The tenth failure still engages the lockout...
    let tenth = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .header(header::AUTHORIZATION, "Bearer wrong-token-value-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tenth.status(), StatusCode::UNAUTHORIZED);

    // ...and the next failing attempt is throttled, proving the probe did not
    // reset the window.
    let throttled = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .header(header::AUTHORIZATION, "Bearer wrong-token-value-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // The health probe stays available even while the gate is locked out.
    let healthy = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);
}
