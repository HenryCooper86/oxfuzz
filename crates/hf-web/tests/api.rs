//! Tests for the REST API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[test]
fn manifest_does_not_depend_on_domain_or_runtime_crates() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("read hf-web manifest");
    let forbidden = [
        "hf-core",
        "hf-runtime",
        "hf-harness",
        "hf-discovery",
        "hf-corpus",
        "hf-crash",
        "hf-agent",
    ];

    for crate_name in forbidden {
        let prefix = format!("{crate_name} =");
        assert!(
            !manifest
                .lines()
                .any(|line| line.trim_start().starts_with(&prefix)),
            "hf-web must go through hf-service, but depends directly on {crate_name}"
        );
    }
}

/// These integration tests exercise endpoints without a bearer token, so they
/// run in the explicit unauthenticated local-dev mode. Setting the same value
/// in every test (and never `HF_WEB_TOKEN`) keeps the process-global env
/// consistent regardless of test execution order. The fail-closed auth logic
/// itself is covered by the pure `auth_tests` unit tests in `router.rs`.
fn allow_open_dev_mode() {
    // SAFETY: tests in this binary only ever set this to "1" and never set
    // HF_WEB_TOKEN, so there is no conflicting concurrent mutation.
    unsafe {
        std::env::set_var("HF_WEB_TOKEN_OPTIONAL", "1");
    }
}

#[tokio::test]
async fn health_returns_ok() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn discover_returns_json() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let fixture = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
        .join("sample_c");
    let body = serde_json::json!({
        "project": fixture,
        "lang": "c"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/discover")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        json["candidates"].is_array(),
        "response should have candidates array"
    );
    assert!(
        !json["candidates"].as_array().unwrap().is_empty(),
        "fixture project should have candidates"
    );
}

#[tokio::test]
async fn policy_decisions_returns_a_json_array() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/policy/decisions?limit=5")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(
        json.is_array(),
        "policy decisions should return an array, got {json}"
    );
}

#[tokio::test]
async fn corpus_list_returns_json() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/corpus/list")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"project": ".", "target": "x"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    assert!(json.is_array(), "corpus list should return array");
}

/// POST a JSON body to `uri` and return (status, parsed-json).
async fn post_json(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
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
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn create_session_without_db_returns_null() {
    // No database in the bare test state -> create returns null, not an error.
    let (status, json) = post_json("/chat/session", serde_json::json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.is_null(), "expected null session id, got {json}");
}

#[tokio::test]
async fn chat_history_without_db_reports_persistence_error() {
    let (status, json) = post_json("/chat/history", serde_json::json!({"session_id": "s1"})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(json["error"]
        .as_str()
        .is_some_and(|error| error.contains("chat persistence")));
}

#[tokio::test]
async fn config_conversion_endpoints_round_trip_json_and_toml() {
    let (status, json) = post_json(
        "/config/toml_to_value",
        serde_json::json!({"content": "enabled = true"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["enabled"], true);

    let (status, json) = post_json(
        "/config/value_to_toml",
        serde_json::json!({"value": {"enabled": true}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json, "enabled = true\n");
}

#[tokio::test]
async fn fuzzing_config_endpoint_returns_the_service_validated_policy() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/fuzzing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let policy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(policy["enabled_engines"].is_array());
    assert!(policy["default_engine"].is_string());
    assert!(policy["default_duration_secs"].is_number());
    assert!(policy["sandbox"]["max_mem_mb"].is_number());
    assert!(policy["sandbox"]["max_cpus"].is_number());
    assert!(policy["sandbox"]["max_duration_secs"].is_number());
}

#[tokio::test]
async fn agent_and_skill_registries_have_web_crud_parity() {
    allow_open_dev_mode();
    let registry_root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", registry_root.path());
    let app = hf_web::router::build();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/agents")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    let agents: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    let mut agent = agents.first().expect("shipped agents").clone();
    agent["id"] = "web-release-agent".into();
    agent["name"] = "Web Release Agent".into();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/agents/save")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "definition": agent }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(registry_root
        .path()
        .join("agents/web-release-agent.toml")
        .is_file());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/skills")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 128 * 1024)
        .await
        .unwrap();
    let skills: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    let mut skill = skills.first().expect("shipped skills").clone();
    skill["name"] = "web-release-skill".into();
    skill["description"] = "Web registry parity".into();
    skill["body"] = "Retain release evidence.".into();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/skills/save")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "definition": skill }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(registry_root
        .path()
        .join("skills/web-release-skill/root.md")
        .is_file());

    for (uri, body) in [
        (
            "/agents/delete",
            serde_json::json!({ "id": "web-release-agent" }),
        ),
        (
            "/skills/delete",
            serde_json::json!({ "name": "web-release-skill" }),
        ),
    ] {
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
        assert_eq!(response.status(), StatusCode::OK);
    }
    assert!(!registry_root
        .path()
        .join("agents/web-release-agent.toml")
        .exists());
    assert!(!registry_root
        .path()
        .join("skills/web-release-skill")
        .exists());
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test]
async fn automotive_config_endpoint_round_trips_only_the_typed_policy() {
    allow_open_dev_mode();
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("hobot-fuzz.toml"),
        "coverage_stagnation_secs = 77\n",
    )
    .unwrap();
    let app = hf_web::router::build_with_state(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed())
            .with_integration_config_dir(directory.path()),
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/config/automotive")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let mut policy: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(policy["enabled"], false);
    assert_eq!(policy["physical_bench"]["enabled"], false);
    policy["enabled"] = serde_json::Value::Bool(true);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/automotive")
                .method("PUT")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "settings": policy }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(saved["enabled"], true);
    let raw = std::fs::read_to_string(directory.path().join("hobot-fuzz.toml")).unwrap();
    assert!(raw.contains("coverage_stagnation_secs = 77"));
    assert!(raw.contains("[automotive]"));
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test]
async fn automotive_capture_route_rejects_files_outside_the_approved_project() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let outside = directory.path().join("outside.pcap");
    std::fs::write(&outside, b"not accessible to the web route").unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()]).unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/automotive/analyze-capture")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project_root": project,
                        "protocol": "uds",
                        "capture_path": outside,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test]
async fn automotive_replay_route_is_typed_and_rejects_an_incomplete_request() {
    allow_open_dev_mode();
    let app = hf_web::router::build_with_state(hf_web::router::AppState::new(
        hf_service::ServiceContainer::stubbed(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/automotive/replay")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test]
async fn automotive_report_route_is_typed_and_rejects_an_incomplete_request() {
    allow_open_dev_mode();
    let app = hf_web::router::build_with_state(hf_web::router::AppState::new(
        hf_service::ServiceContainer::stubbed(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/automotive/report")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn system_status_returns_json_flags() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/system/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(json["docker"].is_boolean());
    assert!(json["sandbox_image"].is_boolean());
    assert!(json["libfuzzer"].is_boolean());
}

#[tokio::test]
async fn diagnostics_cost_summary_reports_the_current_web_session() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/diagnostics/cost")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["calls"], 0);
    assert_eq!(json["cost_usd"], 0.0);
    assert!(json["by_model"].is_array());
}

#[tokio::test]
async fn knowledge_search_unindexed_returns_empty_array() {
    let (status, json) = post_json(
        "/knowledge/search",
        serde_json::json!({"project": ".", "query": "anything"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.is_array(), "search should return an array");
}

#[tokio::test]
async fn knowledge_stats_unindexed_reports_not_indexed() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/knowledge/stats?project=.")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json["indexed"], false);
    assert_eq!(json["files"], 0);
    assert_eq!(json["chunks"], 0);
    assert!(json["documents"].is_number());
    assert!(
        json["retrieval_strategy"].is_string(),
        "config summary carries the active strategy"
    );
    assert!(json["chunk_max_tokens"].is_number());
}

#[tokio::test]
async fn knowledge_stats_rejects_a_path_outside_the_allowlist() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/knowledge/stats?project=/etc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn workbench_dashboard_without_db_returns_empty_summary() {
    let (status, json) = post_json(
        "/workbench/dashboard",
        serde_json::json!({"project": ".", "target": "parse_packet"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["totals"]["targets"], 0);
    assert!(json["next_actions"].is_array());
}

#[tokio::test]
async fn report_drafts_can_be_saved_listed_and_deleted() {
    let dir = tempfile::tempdir().unwrap();
    // SAFETY: this integration test owns the report-dir override for the
    // duration of the process and uses a unique temp directory.
    unsafe {
        std::env::set_var("HF_REPORTS_DIR", dir.path());
    }

    let (status, saved) = post_json(
        "/reports/save",
        serde_json::json!({
            "title": "Parser campaign",
            "project": "/tmp/project",
            "target": "parse_packet",
            "status": "Draft",
            "content": "# Parser campaign\n\nFinding details."
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = saved["id"].as_str().unwrap();
    assert_eq!(saved["title"], "Parser campaign");

    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/reports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let reports: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reports.as_array().map(Vec::len), Some(1));
    assert_eq!(reports[0]["id"], id);

    let (status, _) = post_json("/reports/delete", serde_json::json!({ "id": id })).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn schedule_list_without_scheduler_returns_empty_array() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/schedule")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(json.as_array().map(Vec::len), Some(0));
}

#[tokio::test]
async fn schedule_limits_without_scheduler_are_explicitly_unavailable() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/schedule/concurrency/limits")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let limits: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(limits["active_fuzz_campaign_limit"], 0);
    assert_eq!(limits["scheduler_workflow_dispatch_limit"], 0);
    assert_eq!(limits["effective_max_concurrent_fuzz_runs"], 0);
}

#[tokio::test]
async fn schedule_mutations_report_missing_ids() {
    allow_open_dev_mode();
    let dir = tempfile::tempdir().unwrap();
    let scheduler = std::sync::Arc::new(
        hf_service::scheduler::CampaignScheduler::try_start(
            hf_service::ServiceContainer::stubbed(),
            dir.path().join("schedules.json"),
            None,
        )
        .await
        .unwrap(),
    );
    let app = hf_web::router::build_with_state(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed())
            .with_scheduler(scheduler),
    );

    let deleted = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/schedule/missing")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NOT_FOUND);

    let enabled = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/schedule/missing/enabled")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(enabled.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn provider_thaw_maps_service_errors_to_http() {
    allow_open_dev_mode();
    // The stub container has no provider pool, so a thaw attempt must surface
    // the service's "no LLM provider configured" error as 502 Bad Gateway
    // (the stable ClassifiedError::Provider mapping), not a 404 or 500.
    let app = hf_web::router::build();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/providers/openai-main/thaw")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(
        json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("no LLM provider configured"),
        "unexpected error body: {json}"
    );
}
