//! Tests for the REST API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

#[cfg(feature = "semgrep-enrichment")]
struct RecordingSemgrepRuntime {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
    blocked: bool,
}

#[cfg(feature = "semgrep-enrichment")]
struct WorkspaceEnvGuard {
    previous: Option<std::ffi::OsString>,
}

#[cfg(feature = "semgrep-enrichment")]
impl WorkspaceEnvGuard {
    fn set(path: &std::path::Path) -> Self {
        let previous = std::env::var_os("HF_WORKSPACE_DIR");
        // SAFETY: Semgrep transport tests use one workspace setting and retain
        // this guard until both background operations reach terminal states.
        unsafe {
            std::env::set_var("HF_WORKSPACE_DIR", path);
        }
        Self { previous }
    }
}

#[cfg(feature = "semgrep-enrichment")]
impl Drop for WorkspaceEnvGuard {
    fn drop(&mut self) {
        // SAFETY: this restores the value captured by `set` after the test's
        // background operations have released their workspace leases.
        unsafe {
            if let Some(previous) = &self.previous {
                std::env::set_var("HF_WORKSPACE_DIR", previous);
            } else {
                std::env::remove_var("HF_WORKSPACE_DIR");
            }
        }
    }
}

#[cfg(feature = "semgrep-enrichment")]
impl RecordingSemgrepRuntime {
    fn blocked() -> Self {
        Self {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            blocked: true,
        }
    }

    async fn wait_until_started(&self) {
        self.started.notified().await;
    }

    fn release(&self) {
        self.release.notify_one();
    }

    async fn write_result(&self, operation_root: &std::path::Path) -> std::io::Result<()> {
        fn collect_sources(
            root: &std::path::Path,
            directory: &std::path::Path,
            paths: &mut Vec<String>,
        ) -> std::io::Result<()> {
            for entry in std::fs::read_dir(directory)? {
                let entry = entry?;
                let path = entry.path();
                if entry.file_type()?.is_dir() {
                    collect_sources(root, &path, paths)?;
                } else {
                    let relative = path.strip_prefix(root).map_err(std::io::Error::other)?;
                    paths.push(
                        relative
                            .components()
                            .map(|component| component.as_os_str().to_string_lossy())
                            .collect::<Vec<_>>()
                            .join("/"),
                    );
                }
            }
            Ok(())
        }

        let source_root = operation_root.join("source");
        let mut scanned = Vec::new();
        collect_sources(&source_root, &source_root, &mut scanned)?;
        scanned.sort();
        let output = serde_json::json!({
            "version": "1.169.0",
            "results": [],
            "errors": [],
            "paths": {
                "scanned": scanned,
                "skipped": []
            }
        });
        tokio::fs::write(
            operation_root.join("output").join("semgrep.json"),
            serde_json::to_vec(&output).map_err(std::io::Error::other)?,
        )
        .await
    }
}

#[cfg(feature = "semgrep-enrichment")]
#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for RecordingSemgrepRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        self.started.notify_one();
        if self.blocked {
            self.release.notified().await;
        }
        self.write_result(cwd)
            .await
            .map_err(|error| hf_core::error::ClassifiedError::Sandbox(error.to_string()))?;
        Ok(hf_core::runtime::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        hf_test_utils::immutable_test_image().map(Some)
    }

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        tokio::fs::write(path, content)
            .await
            .map_err(|error| hf_core::error::ClassifiedError::Sandbox(error.to_string()))
    }

    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|error| hf_core::error::ClassifiedError::Sandbox(error.to_string()))
    }
}

#[test]
fn production_manifest_does_not_depend_on_domain_or_runtime_crates() {
    let manifest = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"),
    )
    .expect("read hf-web manifest");
    let manifest = manifest
        .parse::<toml::Value>()
        .expect("parse hf-web manifest");
    let dependencies = manifest["dependencies"]
        .as_table()
        .expect("hf-web production dependencies");
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
        assert!(
            !dependencies.contains_key(crate_name),
            "hf-web production code must go through hf-service, but depends directly on {crate_name}"
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
async fn campaign_advice_returns_a_read_only_evidence_backed_proposal() {
    let (status, json) = post_json(
        "/campaign/advice",
        serde_json::json!({
            "current_engine": "LibFuzzer",
            "enabled_engines": ["LibFuzzer", "AflPlusPlus"],
            "engine_rates": [
                {"engine": "LibFuzzer", "usd_per_hour": 1.0},
                {"engine": "AflPlusPlus", "usd_per_hour": 1.0}
            ],
            "observations": [{
                "run_id": "00000000-0000-0000-0000-000000000001",
                "sequence": 1,
                "engine": "LibFuzzer",
                "duration_secs": 3600,
                "new_edges": 0,
                "crashes": 0,
                "corpus_additions": 0,
                "model_cost_usd": 0.0
            }],
            "budget": {
                "max_total_cost_usd": 10.0,
                "min_edges_per_dollar": 1.0,
                "plateau_runs": 1
            }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["action"]["kind"], "switch_engine");
    assert_eq!(json["action"]["to"], "AflPlusPlus");
    assert_eq!(json["requires_human_approval"], true);
    assert!(json["evidence"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
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
#[cfg(feature = "semgrep-enrichment")]
async fn semgrep_rest_transport_preserves_service_contract_and_status_mapping() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let _workspace_env = WorkspaceEnvGuard::set(&workspace.path().join("managed"));
    let source = root.path().join("parser.c");
    std::fs::write(
        source,
        "int parse_packet(const unsigned char *data) { return data[0]; }\n",
    )
    .unwrap();
    let runtime = std::sync::Arc::new(RecordingSemgrepRuntime::blocked());
    let container = hf_service::ServiceContainer::new(runtime.clone(), None)
        .with_store_path(root.path().join("semgrep-web.db"))
        .await
        .unwrap();
    container
        .discover(root.path(), hf_service::TargetLanguage::C)
        .await
        .unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![root.path().to_path_buf()])
            .unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(container.clone()),
        security,
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/semgrep/enrich")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project": root.path(),
                        "language": "c"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let started: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let operation_id = started["operation_id"].as_str().unwrap();
    assert_eq!(started["state"], "staging");

    runtime.wait_until_started().await;
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/semgrep/enrich/{operation_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(status.into_body(), 64 * 1024)
        .await
        .unwrap();
    let pending: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let expected_pending = container
        .semgrep_operation(uuid::Uuid::parse_str(operation_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending, serde_json::to_value(expected_pending).unwrap());
    assert_eq!(pending["state"], "scanning");
    assert!(pending["result"].is_null());

    runtime.release();
    let completed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/semgrep/enrich/{operation_id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap();
            let view: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if view["state"] == "done" && view["active"] == false {
                break view;
            }
            assert!(
                !matches!(view["state"].as_str(), Some("failed" | "cancelled")),
                "Semgrep operation did not complete successfully: {view}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Semgrep operation must complete within the test bound");
    let expected = container
        .semgrep_operation(uuid::Uuid::parse_str(operation_id).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed, serde_json::to_value(expected).unwrap());
    assert_eq!(completed["result"]["scan_id"], operation_id);
    assert_eq!(
        completed["project_root"],
        root.path()
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .as_ref()
    );
    assert_eq!(completed["result"]["overlay_state"], "current");
    assert_eq!(completed["result"]["findings"], serde_json::json!([]));
    assert_eq!(completed["result"]["candidates"][0]["semgrep_boost"], 0.0);
    assert_eq!(
        completed["result"]["candidates"][0]["base_score"],
        completed["result"]["candidates"][0]["effective_score"]
    );

    let unknown_id = uuid::Uuid::new_v4();
    let unknown = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/semgrep/enrich/{unknown_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let invalid = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/semgrep/enrich/not-a-uuid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);

    let invalid_language = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/semgrep/enrich")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project": root.path(),
                        "lang": "rust"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_language.status(), StatusCode::BAD_REQUEST);

    let outside = tempfile::tempdir().unwrap();
    let forbidden = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/semgrep/enrich")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project": outside.path(),
                        "lang": "c"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let second = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/semgrep/enrich")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project": root.path(),
                        "lang": "c"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(second.into_body(), 4096)
        .await
        .unwrap();
    let second: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let second_id = second["operation_id"].as_str().unwrap();
    runtime.wait_until_started().await;

    let accepted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/semgrep/enrich/{second_id}/cancel"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    let bytes = axum::body::to_bytes(accepted.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        "accepted"
    );
    runtime.release();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let view = container
                .semgrep_operation(uuid::Uuid::parse_str(second_id).unwrap())
                .await
                .unwrap()
                .unwrap();
            if view.state == hf_service::SemgrepOperationState::Cancelled && !view.active {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled Semgrep operation must settle within the test bound");

    let inactive = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/semgrep/enrich/{second_id}/cancel"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(inactive.status(), StatusCode::CONFLICT);

    let missing_cancel = app
        .oneshot(
            Request::builder()
                .uri(format!("/semgrep/enrich/{unknown_id}/cancel"))
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_cancel.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[cfg(not(feature = "semgrep-enrichment"))]
async fn semgrep_routes_are_absent_without_the_feature() {
    allow_open_dev_mode();
    let app = hf_web::router::build();
    for (method, uri) in [
        ("POST", "/semgrep/enrich"),
        (
            "GET",
            "/semgrep/enrich/00000000-0000-0000-0000-000000000001",
        ),
        (
            "POST",
            "/semgrep/enrich/00000000-0000-0000-0000-000000000001/cancel",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .method(method)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
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
        directory.path().join("oxfuzz.toml"),
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
    // The subsystem is enabled by default; physical bench stays off. Toggle the
    // master switch to prove the typed policy round-trips a change back out.
    assert_eq!(policy["enabled"], true);
    assert_eq!(policy["physical_bench"]["enabled"], false);
    policy["enabled"] = serde_json::Value::Bool(false);

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
    assert_eq!(saved["enabled"], false);
    let raw = std::fs::read_to_string(directory.path().join("oxfuzz.toml")).unwrap();
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
async fn automotive_import_route_analyzes_an_in_project_capture() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let capture = project.join("trace.log");
    std::fs::write(
        &capture,
        "(1.000000) can0 123#DEADBEEF\n(1.100000) can0 123#DEADBE00\n",
    )
    .unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()]).unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/automotive/import-capture")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project_root": project,
                        "format": "candump",
                        "capture_path": capture,
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["frame_count"], 2);
    assert_eq!(value["unique_ids"], 1);
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test]
async fn automotive_import_route_rejects_files_outside_the_project() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let outside = directory.path().join("outside.log");
    std::fs::write(&outside, "(1.0) can0 123#00\n").unwrap();
    let security =
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()]).unwrap();
    let app = hf_web::router::build_with_state_and_security(
        hf_web::router::AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let response = app
        .oneshot(
            Request::builder()
                .uri("/automotive/import-capture")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "project_root": project,
                        "format": "candump",
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
