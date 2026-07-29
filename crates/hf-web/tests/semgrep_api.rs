//! Isolated Semgrep REST lifecycle contract.
//!
//! This integration target intentionally contains exactly one test. Cargo runs
//! each integration target in its own process, so its `HF_WORKSPACE_DIR`
//! override cannot race with unrelated `hf-web` tests.

#![cfg(feature = "semgrep-enrichment")]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const LIFECYCLE_TIMEOUT: Duration = Duration::from_secs(10);

struct RecordingSemgrepRuntime {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl RecordingSemgrepRuntime {
    fn blocked() -> Self {
        Self {
            started: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
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

#[async_trait::async_trait]
impl hf_service::RuntimeAdapter for RecordingSemgrepRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_service::ResourceLimits,
    ) -> Result<hf_service::CommandResult, hf_service::ClassifiedError> {
        self.started.notify_one();
        self.release.notified().await;
        self.write_result(cwd)
            .await
            .map_err(|error| hf_service::ClassifiedError::Sandbox(error.to_string()))?;
        Ok(hf_service::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_service::CommandTermination::Completed,
        })
    }

    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_service::ImmutableImageReference>, hf_service::ClassifiedError> {
        hf_service::ImmutableImageReference::from_sha256_id(format!("sha256:{}", "a".repeat(64)))
            .map(Some)
    }

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), hf_service::ClassifiedError> {
        tokio::fs::write(path, content)
            .await
            .map_err(|error| hf_service::ClassifiedError::Sandbox(error.to_string()))
    }

    async fn read_file(
        &self,
        path: &std::path::Path,
    ) -> Result<String, hf_service::ClassifiedError> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|error| hf_service::ClassifiedError::Sandbox(error.to_string()))
    }
}

#[tokio::test]
async fn semgrep_rest_transport_preserves_service_contract_and_status_mapping() {
    tokio::time::timeout(LIFECYCLE_TIMEOUT, exercise_semgrep_rest_contract())
        .await
        .expect("the complete Semgrep REST lifecycle must remain bounded");
}

async fn exercise_semgrep_rest_contract() {
    let root = tempfile::tempdir().unwrap();
    let workspace = tempfile::tempdir().unwrap();
    // SAFETY: this dedicated integration-test binary contains exactly one
    // test, and Cargo executes integration binaries in separate processes.
    // No sibling test can observe or replace this process-local override.
    unsafe {
        std::env::set_var("HF_WORKSPACE_DIR", workspace.path().join("managed"));
    }
    std::fs::write(
        root.path().join("parser.c"),
        "int parse_packet(const unsigned char *data) { return data[0]; }\n",
    )
    .unwrap();
    let runtime = Arc::new(RecordingSemgrepRuntime::blocked());
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

    let availability = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/semgrep/available")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(availability.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(availability.into_body(), 32)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        true
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
    let completed = loop {
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
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
    loop {
        let view = container
            .semgrep_operation(uuid::Uuid::parse_str(second_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        if view.state == hf_service::SemgrepOperationState::Cancelled && !view.active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

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
