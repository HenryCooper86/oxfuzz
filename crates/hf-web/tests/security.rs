//! Security-boundary regression tests for the REST transport.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use futures::StreamExt;
use hf_web::{
    build_with_state_and_security, validate_bind_addr, AppState, SseEvent, WebSecurityConfig,
};
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

#[tokio::test]
async fn shared_scheduler_controls_deny_foreign_and_removed_projects() {
    let fixture = hf_service::test_support::one_time_recovery_fixture(true)
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(fixture.container()).with_scheduler(scheduler.clone()),
        open_local_security(outside.path()),
    );
    let before = scheduler.max_concurrent();
    for (method, uri, body) in [
        (Method::GET, "/schedule/arm", String::new()),
        (Method::POST, "/schedule/arm", String::new()),
        (Method::DELETE, "/schedule/arm", String::new()),
        (Method::GET, "/schedule/runtime", String::new()),
        (Method::GET, "/schedule/concurrency", String::new()),
        (Method::GET, "/schedule/concurrency/limits", String::new()),
        (
            Method::POST,
            "/schedule/concurrency",
            "{\"max_concurrent\":9}".to_owned(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains(fixture.directory_path().to_str().unwrap())
        );
        assert!(!scheduler.is_armed());
        assert_eq!(scheduler.max_concurrent(), before);
    }
    scheduler.try_remove("schedule-web").await.unwrap();
    scheduler
        .acknowledge_one_time_recovery("occ-web")
        .await
        .unwrap();
    scheduler.clear_history().await.unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/schedule/arm")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(!scheduler.is_armed());
    let approved = build_with_state_and_security(
        AppState::new(fixture.container()).with_scheduler(scheduler.clone()),
        open_local_security(fixture.directory_path()),
    );
    let response = approved
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/schedule/arm")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(scheduler.is_armed());
    scheduler.stop().await;
}

#[tokio::test]
async fn recovery_routes_deny_foreign_receipts_before_acknowledgement() {
    let fixture = hf_service::test_support::one_time_recovery_fixture(true)
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let foreign = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(fixture.container()).with_scheduler(scheduler.clone()),
        open_local_security(foreign.path()),
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/schedule/recovery")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!([])
    );
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/schedule/recovery/occ-web/acknowledge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        "forbidden"
    );
    assert!(!String::from_utf8_lossy(&body).contains(fixture.directory_path().to_str().unwrap()));
    assert_eq!(
        fixture
            .container()
            .store()
            .unwrap()
            .schedule_occurrence("occ-web")
            .await
            .unwrap()
            .unwrap()
            .state,
        "running"
    );
    scheduler.stop().await;
}

#[tokio::test]
async fn scheduler_history_reads_and_clear_preserve_foreign_deleted_schedule_evidence() {
    let fixture = hf_service::test_support::scheduler_history_fixture()
        .await
        .unwrap();
    let scheduler = fixture.scheduler();
    let app = build_with_state_and_security(
        AppState::new(fixture.container()).with_scheduler(scheduler.clone()),
        open_local_security(fixture.approved_project()),
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/schedule/history?limit=1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let history: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(history[0]["execution_id"], "approved-new");
    assert!(!String::from_utf8_lossy(&body).contains("foreign campaign"));
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/schedule/history/clear")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    assert_eq!(serde_json::from_slice::<u64>(&body).unwrap(), 2);
    let remaining = scheduler.recent_executions(200).await.unwrap();
    assert_eq!(remaining.len(), 130);
    assert!(remaining
        .iter()
        .all(|view| view.execution_id.starts_with("foreign-")));
    scheduler.stop().await;
}

#[tokio::test]
async fn schedule_definitions_and_id_mutations_stay_within_approved_roots() {
    use hf_service::scheduler::{parse_trigger, CampaignParams, CampaignScheduler};
    use std::sync::Arc;

    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let state_dir = tempfile::tempdir().unwrap();
    let container = hf_service::ServiceContainer::stubbed();
    let scheduler = Arc::new(
        CampaignScheduler::try_start(
            container.clone(),
            state_dir.path().join("schedules.json"),
            None,
        )
        .await
        .unwrap(),
    );
    let mut ids = Vec::new();
    for (name, project) in [
        ("approved campaign", approved.path()),
        ("foreign campaign", outside.path()),
    ] {
        ids.push(
            scheduler
                .try_create(
                    name,
                    &CampaignParams {
                        project: project.display().to_string(),
                        duration_secs: 30,
                        ..CampaignParams::default()
                    },
                    parse_trigger("cron", "0 0 1 1 *").unwrap(),
                )
                .await
                .unwrap()
                .id,
        );
    }
    let app = build_with_state_and_security(
        AppState::new(container).with_scheduler(scheduler.clone()),
        open_local_security(approved.path()),
    );
    for (method, uri, body) in [
        (Method::GET, "/schedule".to_owned(), String::new()),
        (
            Method::POST,
            "/schedule".to_owned(),
            serde_json::json!({
                "name": "another approved campaign", "project": approved.path(),
                "trigger_kind": "cron", "trigger_value": "0 0 1 1 *", "duration_secs": 30,
            })
            .to_string(),
        ),
        (
            Method::POST,
            format!("/schedule/{}/enabled", ids[0]),
            "{\"enabled\":false}".to_owned(),
        ),
        (
            Method::DELETE,
            format!("/schedule/{}", ids[0]),
            String::new(),
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(!json.as_array().unwrap().is_empty());
        assert!(json
            .as_array()
            .unwrap()
            .iter()
            .all(|view| view["id"] != ids[1]));
        assert!(!String::from_utf8_lossy(&body).contains("foreign campaign"));
    }
    let before = std::fs::read(state_dir.path().join("schedules.json")).unwrap();
    for (method, uri, body) in [
        (
            Method::POST,
            format!("/schedule/{}/enabled", ids[1]),
            "{\"enabled\":false}",
        ),
        (Method::DELETE, format!("/schedule/{}", ids[1]), ""),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(outside.path().to_str().unwrap()));
        assert_eq!(
            std::fs::read(state_dir.path().join("schedules.json")).unwrap(),
            before
        );
    }
    assert!(
        scheduler
            .list()
            .await
            .iter()
            .find(|s| s.id == ids[1])
            .unwrap()
            .enabled
    );
    scheduler.stop().await;
}

#[tokio::test]
async fn export_requires_an_approved_project() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for (project, expected) in [
        (serde_json::Value::Null, StatusCode::BAD_REQUEST),
        (serde_json::json!(""), StatusCode::BAD_REQUEST),
        (
            serde_json::json!(outside.path().to_str().unwrap()),
            StatusCode::FORBIDDEN,
        ),
        (
            serde_json::json!(approved.path().to_str().unwrap()),
            StatusCode::OK,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/projects/export")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({ "project": project }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn project_scoped_read_routes_reject_unselected_and_outside_projects() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for uri in [
        "/runs/history",
        "/audit/auto-revert",
        "/workbench/dashboard",
        "/workbench/harnesses",
    ] {
        for (project, expected) in [
            (serde_json::Value::Null, StatusCode::BAD_REQUEST),
            (
                serde_json::json!(outside.path().to_str().unwrap()),
                StatusCode::FORBIDDEN,
            ),
            (
                serde_json::json!(approved.path().to_str().unwrap()),
                StatusCode::OK,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(uri)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            serde_json::json!({ "project": project }).to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{uri}");
        }
    }
}

#[tokio::test]
async fn artifact_reads_require_an_approved_project() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for uri in ["/crashes/all", "/corpus/all"] {
        for (project, expected) in [
            (None, StatusCode::BAD_REQUEST),
            (Some(outside.path()), StatusCode::FORBIDDEN),
            (Some(approved.path()), StatusCode::OK),
        ] {
            let uri = match project {
                Some(project) => format!("{uri}?project={}", project.display()),
                None => uri.to_owned(),
            };
            let response = app
                .clone()
                .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{uri}");
        }
    }
}

#[tokio::test]
async fn artifact_clear_requires_an_approved_project() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for (body, expected) in [
        (serde_json::json!({}), StatusCode::UNPROCESSABLE_ENTITY),
        (
            serde_json::json!({ "project": outside.path() }),
            StatusCode::FORBIDDEN,
        ),
        (
            serde_json::json!({ "project": approved.path() }),
            StatusCode::OK,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/artifacts/clear")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn run_clear_requires_an_approved_project() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for (body, expected) in [
        (serde_json::json!({}), StatusCode::UNPROCESSABLE_ENTITY),
        (
            serde_json::json!({ "project": outside.path() }),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/runs/clear")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn crash_delete_requires_an_approved_project() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for (body, expected) in [
        (
            serde_json::json!({ "crash_id": uuid::Uuid::new_v4() }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            serde_json::json!({ "project": outside.path(), "crash_id": uuid::Uuid::new_v4() }),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/crashes/delete")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[tokio::test]
async fn corpus_delete_requires_an_approved_project() {
    let approved = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );

    for (body, expected) in [
        (
            serde_json::json!({ "target_id": uuid::Uuid::new_v4(), "sha256": "digest" }),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            serde_json::json!({ "project": outside.path(), "target_id": uuid::Uuid::new_v4(), "sha256": "digest" }),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/corpus/delete-entry")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

#[cfg(feature = "patch-to-proof")]
#[tokio::test]
async fn artifact_deletes_reject_foreign_records_without_exposing_their_project() {
    let fixture = hf_service::test_support::patch_to_proof_fixture()
        .await
        .unwrap();
    let approved = tempfile::tempdir().unwrap();
    let crash = fixture
        .container()
        .store()
        .unwrap()
        .get_crash(fixture.finding_id())
        .await
        .unwrap()
        .unwrap();
    let app = build_with_state_and_security(
        AppState::new(fixture.container()),
        open_local_security(approved.path()),
    );

    for (uri, body) in [
        (
            "/crashes/delete",
            serde_json::json!({ "project": approved.path(), "crash_id": crash.id }),
        ),
        (
            "/corpus/delete-entry",
            serde_json::json!({ "project": approved.path(), "target_id": crash.target_id, "sha256": "seed" }),
        ),
    ] {
        let response = app
            .clone()
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
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&body).contains(fixture.directory_path().to_str().unwrap())
        );
    }
    assert!(fixture
        .container()
        .store()
        .unwrap()
        .get_crash(crash.id)
        .await
        .unwrap()
        .is_some());
}

#[test]
fn remote_bind_requires_a_bearer_token() {
    let loopback_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081);
    let loopback_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8081);
    let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8081);
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 8081);

    assert!(validate_bind_addr(loopback_v4, false).is_ok());
    assert!(validate_bind_addr(loopback_v6, false).is_ok());
    assert!(validate_bind_addr(wildcard, false).is_err());
    assert!(validate_bind_addr(remote, false).is_err());
    assert!(validate_bind_addr(wildcard, true).is_ok());
    assert!(validate_bind_addr(remote, true).is_ok());
}

#[test]
fn cors_origins_must_not_include_paths_or_wildcards() {
    let root = tempfile::tempdir().unwrap();
    assert!(WebSecurityConfig::new(
        None,
        true,
        vec!["https://example.com/api".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .is_err());
    assert!(WebSecurityConfig::new(
        None,
        true,
        vec!["https://*.example.com".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .is_err());
}

#[tokio::test]
async fn bearer_auth_is_fail_closed_and_never_echoes_the_token() {
    let root = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        Some("correct-horse-battery-staple".to_owned()),
        false,
        vec!["http://localhost:5173".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        unauthorized
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .unwrap(),
        "Bearer"
    );
    let body = axum::body::to_bytes(unauthorized.into_body(), 4096)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("correct-horse"));

    let wrong = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .header(header::AUTHORIZATION, "Bearer correct-horse-battery-staplf")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);

    let accepted = app
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .header(header::AUTHORIZATION, "bearer correct-horse-battery-staple")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
}

#[tokio::test]
async fn cors_preflight_allows_only_an_exact_configured_origin() {
    let root = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        Some("cors-test-token".to_owned()),
        false,
        vec!["http://localhost:5173".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let allowed = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/discover")
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), StatusCode::OK);
    assert_eq!(
        allowed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:5173"
    );

    let denied = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/discover")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        denied
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "an unlisted origin must receive no CORS grant"
    );

    let cross_origin_write = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/config/toml_to_value")
                .header(header::ORIGIN, "https://evil.example")
                .header(header::AUTHORIZATION, "Bearer cors-test-token")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"content":"enabled = true"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(cross_origin_write.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cors_preflight_allows_typed_config_patch_from_an_approved_origin() {
    let root = tempfile::tempdir().unwrap();
    let security = WebSecurityConfig::new(
        Some("cors-patch-token".to_owned()),
        false,
        vec!["http://localhost:5173".to_owned()],
        vec![root.path().to_path_buf()],
    )
    .unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::OPTIONS)
                .uri("/config/defectdojo")
                .header(header::ORIGIN, "http://localhost:5173")
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "PATCH")
                .header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    "authorization,content-type",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:5173"
    );
    assert!(response
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_METHODS)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|methods| methods.contains("PATCH")));
}

#[tokio::test]
async fn corpus_import_rejects_a_source_outside_the_approved_roots() {
    let approved = tempfile::tempdir().unwrap();
    let project = approved.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );
    let body = serde_json::json!({
        "project": project,
        "target": "parse",
        "source": outside.path(),
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/corpus/import")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn corpus_import_from_an_approved_source_returns_exact_accounting() {
    let approved = tempfile::tempdir().unwrap();
    let project = approved.path().join("project");
    let source = approved.path().join("external-corpus");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&source).unwrap();
    let target = format!("parse_web_import_{}", uuid::Uuid::new_v4().simple());
    std::fs::write(
        project.join("parse.c"),
        format!("int {target}(const unsigned char *data, unsigned long size) {{ return size && data[0]; }}"),
    )
    .unwrap();
    std::fs::write(source.join("a"), b"new").unwrap();
    std::fs::write(source.join("b"), b"new").unwrap();
    std::fs::write(source.join("empty"), b"").unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );
    let body = serde_json::json!({ "project": project, "target": target, "source": source });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/corpus/import")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(json["inspected"], 3);
    assert_eq!(json["eligible"], 2);
    assert_eq!(json["duplicates"], 1);
    assert_eq!(json["skipped"], 1);
    assert_eq!(json["added"], 1);
    assert_eq!(json["added_bytes"], 3);
    assert_eq!(
        json["before"],
        serde_json::json!({ "inputs": 0, "bytes": 0 })
    );
    assert_eq!(
        json["after"],
        serde_json::json!({ "inputs": 1, "bytes": 3 })
    );

    // Best-effort test cleanup: a missing temporary workspace needs no further action.
    let _ = std::fs::remove_dir_all(hf_service::workspace_dir(
        approved.path().join("project").as_path(),
        body["target"].as_str().unwrap(),
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn corpus_import_rejects_an_approved_root_symlink_to_an_outside_source() {
    use std::os::unix::fs::symlink;

    let approved = tempfile::tempdir().unwrap();
    let project = approved.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let linked_source = approved.path().join("linked-source");
    symlink(outside.path(), &linked_source).unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(approved.path()),
    );
    let body = serde_json::json!({
        "project": project,
        "target": "parse",
        "source": linked_source,
    });

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/corpus/import")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn project_paths_outside_the_allowlist_fail_before_service_access() {
    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(allowed.path()),
    );
    let body = serde_json::json!({
        "project": outside.path(),
        "lang": "c",
    });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/discover")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[cfg(unix)]
#[tokio::test]
async fn project_symlink_escape_is_rejected() {
    use std::os::unix::fs::symlink;

    let allowed = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let escape = allowed.path().join("escape");
    symlink(outside.path(), &escape).unwrap();

    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(allowed.path()),
    );
    let body = serde_json::json!({ "project": escape, "lang": "c" });
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/discover")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn public_system_paths_are_redacted() {
    let root = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(root.path()),
    );
    let response = app
        .oneshot(
            Request::builder()
                .uri("/system/paths")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for key in ["config_dir", "data_dir", "workspace_dir"] {
        assert_eq!(json[key], "<redacted-path>");
    }
}

#[tokio::test]
async fn typed_integration_config_routes_never_return_protected_values() {
    let root = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    std::fs::write(
        config.path().join("defectdojo.toml"),
        r#"
url = "https://dojo.example.test"
api_token = "synthetic-dojo-token"
api_token_env = "SYNTHETIC_DOJO_TOKEN_ENV"
verify_tls = true

[lifecycle]
autostart = true
compose_project = "/synthetic/private/dojo-project"
compose_files = ["/synthetic/private/compose.yml"]
"#,
    )
    .unwrap();
    std::fs::write(
        config.path().join("issue_tracker.toml"),
        r#"
provider = "github"
host = "https://github.example.test"
repo = "/synthetic/private/repo"
api_token = "synthetic-issue-token"
api_token_env = "SYNTHETIC_ISSUE_TOKEN_ENV"
labels = ["fuzzing"]
verify_tls = true
"#,
    )
    .unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed())
            .with_integration_config_dir(config.path()),
        open_local_security(root.path()),
    );

    for uri in ["/config/defectdojo", "/config/issue-tracker"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&body);
        for protected in [
            "synthetic-dojo-token",
            "SYNTHETIC_DOJO_TOKEN_ENV",
            "synthetic-issue-token",
            "SYNTHETIC_ISSUE_TOKEN_ENV",
            "/synthetic/private",
            "compose.yml",
        ] {
            assert!(!text.contains(protected), "protected config value leaked");
        }
        assert!(!text.contains("<redacted-path>"));
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let path_state = if uri == "/config/defectdojo" {
            &json["lifecycle"]["compose_project"]
        } else {
            &json["repo"]
        };
        assert_eq!(path_state["configured"], true);
        assert!(path_state["value"].is_null());
    }
}

#[tokio::test]
async fn typed_integration_patch_preserves_hidden_fields_and_validates_before_write() {
    let root = tempfile::tempdir().unwrap();
    let config = tempfile::tempdir().unwrap();
    let path = config.path().join("defectdojo.toml");
    std::fs::write(
        &path,
        r#"
url = "https://dojo.example.test"
api_token = "synthetic-dojo-token"
api_token_env = "SYNTHETIC_DOJO_TOKEN_ENV"
product_name = "old-product"

[lifecycle]
compose_files = ["/synthetic/private/compose.yml"]
"#,
    )
    .unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed())
            .with_integration_config_dir(config.path()),
        open_local_security(root.path()),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/config/defectdojo")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "product_name": {
                            "operation": "replace",
                            "value": "new-product"
                        }
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(!text.contains("synthetic-dojo-token"));
    assert!(!text.contains("SYNTHETIC_DOJO_TOKEN_ENV"));
    assert!(!text.contains("/synthetic/private"));
    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains("new-product"));
    assert!(raw.contains("synthetic-dojo-token"));
    assert!(raw.contains("SYNTHETIC_DOJO_TOKEN_ENV"));
    assert!(raw.contains("/synthetic/private/compose.yml"));

    let before_invalid = raw;
    let invalid = app
        .oneshot(
            Request::builder()
                .method(Method::PATCH)
                .uri("/config/defectdojo")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"url":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read_to_string(path).unwrap(), before_invalid);
}

#[tokio::test]
async fn generic_browser_config_write_rejects_integration_sections() {
    let root = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(root.path()),
    );

    // A raw write of `providers` would bypass the live-pool reload that the
    // typed endpoint performs, so it is rejected like the integrations.
    for name in ["defectdojo", "issue_tracker", "providers"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/config/write")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::json!({"name": name, "content": "verify_tls = true"})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn origin_host_fallback_allows_loopback_but_rejects_dns_rebinding() {
    let root = tempfile::tempdir().unwrap();
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        open_local_security(root.path()),
    );

    // A rebound page serves an Origin whose authority matches the Host
    // header, but both name an attacker-controlled host.
    let rebound = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/config/toml_to_value")
                .header(header::ORIGIN, "http://attacker.com:8081")
                .header(header::HOST, "attacker.com:8081")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"content":"enabled = true"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rebound.status(), StatusCode::FORBIDDEN);

    // Genuine same-origin browser access to the served UI stays allowed.
    let same_origin = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/config/toml_to_value")
                .header(header::ORIGIN, "http://localhost:8081")
                .header(header::HOST, "localhost:8081")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"content":"enabled = true"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(same_origin.status(), StatusCode::OK);
}

#[tokio::test]
async fn run_control_maps_preflight_and_identity_outcomes_without_inventing_ids() {
    let root = tempfile::tempdir().unwrap();
    let container = hf_service::ServiceContainer::stubbed()
        .with_store_path(root.path().join("web-run-control.db"))
        .await
        .expect("test persistence");
    let app =
        build_with_state_and_security(AppState::new(container), open_local_security(root.path()));

    let syzkaller = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/runs/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project": root.path(),
                        "target": "kernel",
                        "engine": "syzkaller",
                        "duration_secs": 60
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(syzkaller.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(syzkaller.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| error.contains("trusted local desktop")));

    let start = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/runs/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project": root.path(),
                        "target": "parse_entry",
                        "engine": "libfuzzer",
                        "duration_secs": 60
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(start.into_body(), 4096).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(body.get("run_id").is_none());
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| { error.starts_with("validation error:") }));

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/runs/not-a-uuid/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let missing_id = uuid::Uuid::new_v4();
    let missing = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/runs/{missing_id}/status"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);

    let inactive = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/runs/{missing_id}/cancel"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inactive.status(), StatusCode::NOT_FOUND);
}

#[test]
fn sse_rejects_an_oversized_event_before_enqueueing() {
    let state = AppState::new(hf_service::ServiceContainer::stubbed());
    let event = SseEvent::RunProgress {
        run_id: Some(uuid::Uuid::new_v4().to_string()),
        kind: "log".to_owned(),
        data: serde_json::json!({ "line": "x".repeat(70 * 1024) }),
    };
    assert!(state.publish_event(event).is_err());
}

#[tokio::test]
async fn lagging_sse_clients_receive_an_explicit_drop_notice() {
    let root = tempfile::tempdir().unwrap();
    let state = AppState::new(hf_service::ServiceContainer::stubbed());
    let producer = state.clone();
    let app = build_with_state_and_security(state, open_local_security(root.path()));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    for sequence in 0..300 {
        producer
            .publish_event(SseEvent::RunStatus {
                run_id: uuid::Uuid::new_v4().to_string(),
                status: format!("event-{sequence}"),
            })
            .unwrap();
    }

    let mut body = response.into_body().into_data_stream();
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), body.next())
        .await
        .expect("SSE stream should produce a lag notice")
        .expect("SSE stream should remain open")
        .expect("SSE body chunk should be readable");
    let text = String::from_utf8_lossy(&first);
    assert!(
        text.contains("event: stream:lagged"),
        "unexpected SSE: {text}"
    );
    assert!(text.contains("StreamLagged"), "unexpected SSE: {text}");
    assert!(text.contains("\"dropped\""), "unexpected SSE: {text}");
}
