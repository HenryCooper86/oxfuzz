//! Isolated Harness Work Order v2 REST contract.

#![cfg(feature = "harness-work-order")]

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt as _;

const IMPORT_BODY_LIMIT: usize = 131_072;

struct ApiFixture {
    _directory: tempfile::TempDir,
    project: PathBuf,
    app: axum::Router,
}

impl ApiFixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary API fixture");
        let project = directory.path().join("private-project-root");
        std::fs::create_dir(&project).expect("create project root");
        std::fs::write(
            project.join("parser.c"),
            b"int parse_packet(const unsigned char *data, unsigned long size) {\n\
                return size == 0 ? 0 : data[0];\n\
              }\n",
        )
        .expect("write project source");

        let container = hf_service::ServiceContainer::stubbed()
            .with_store_path(directory.path().join("work-orders.db"))
            .await
            .expect("open isolated work-order store");
        let inventory = container
            .discover(
                &project,
                "c".parse().expect("canonical test target language"),
            )
            .await
            .expect("discover and retain test target");
        assert!(
            inventory
                .candidates
                .iter()
                .any(|candidate| candidate.symbol == "parse_packet"),
            "fixture source must retain the requested target"
        );

        let security = WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()])
            .expect("open local test security");
        let app = build_with_state_and_security(AppState::new(container), security);
        Self {
            _directory: directory,
            project,
            app,
        }
    }

    fn canonical_root(&self) -> String {
        std::fs::canonicalize(&self.project)
            .expect("canonical fixture root")
            .to_string_lossy()
            .into_owned()
    }
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: Body,
    json_content_type: bool,
) -> (StatusCode, Vec<u8>) {
    let mut request = Request::builder().method(method).uri(uri);
    if json_content_type {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    let response = app
        .clone()
        .oneshot(request.body(body).expect("build API request"))
        .await
        .expect("serve API request");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read API response")
        .to_vec();
    (status, bytes)
}

async fn json_request(
    app: &axum::Router,
    method: Method,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value, Vec<u8>) {
    let (status, bytes) = send(app, method, uri, Body::from(body.to_string()), true).await;
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json, bytes)
}

async fn empty_request(
    app: &axum::Router,
    method: Method,
    uri: &str,
) -> (StatusCode, serde_json::Value, Vec<u8>) {
    let (status, bytes) = send(app, method, uri, Body::empty(), false).await;
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json, bytes)
}

fn assert_root_absent(root: &str, body: &[u8]) {
    assert!(
        !String::from_utf8_lossy(body).contains(root),
        "REST body disclosed the canonical project root"
    );
}

async fn export_work_order(fixture: &ApiFixture) -> (String, Vec<u8>) {
    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-orders",
        serde_json::json!({
            "project": fixture.project,
            "target": "parse_packet",
            "lang": "c",
            "engine": "libfuzzer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "export response: {body}");
    let id = body["id"]
        .as_str()
        .expect("exported work-order id")
        .to_owned();
    assert_eq!(body["schema_version"], 2);
    assert_eq!(body["payload"]["target"]["relative_source"], "parser.c");
    assert!(body["validation_commands"][0]["argv"].is_array());
    (id, bytes)
}

#[tokio::test]
async fn every_work_order_resource_round_trips_service_owned_views() {
    let fixture = ApiFixture::new().await;
    let root = fixture.canonical_root();
    let (work_order_id, exported) = export_work_order(&fixture).await;
    assert_root_absent(&root, &exported);

    let (status, listed, bytes) =
        empty_request(&fixture.app, Method::GET, "/harness/work-orders").await;
    assert_eq!(status, StatusCode::OK, "list response: {listed}");
    assert_eq!(listed[0]["id"], work_order_id);
    assert!(listed[0]["validation_commands"][0]["argv"].is_array());
    assert_root_absent(&root, &bytes);

    let (status, fetched, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-orders/{work_order_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get response: {fetched}");
    assert_eq!(fetched["id"], work_order_id);
    assert_root_absent(&root, &bytes);

    let source = "#include <stddef.h>\n#include <stdint.h>\n\
                  int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n\
                    return size == 0 ? 0 : data[0];\n\
                  }\n";
    let (status, submission, bytes) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{work_order_id}/submissions"),
        serde_json::json!({
            "source": source,
            "origin": "human",
            "parent_submission_id": null
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "import response: {submission}");
    let submission_id = submission["id"].as_str().expect("submission id").to_owned();
    assert_eq!(submission["work_order_id"], work_order_id);
    assert_eq!(submission["source"], source);
    assert_root_absent(&root, &bytes);

    let (status, submissions, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-orders/{work_order_id}/submissions"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "submission list: {submissions}");
    assert_eq!(submissions[0]["id"], submission_id);
    assert_root_absent(&root, &bytes);

    let (status, attempt, bytes) = empty_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-order-submissions/{submission_id}/qualifications"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "qualification response: {attempt}");
    assert_eq!(attempt["submission_id"], submission_id);
    assert_eq!(attempt["status"], "compile_failed");
    let attempt_id = attempt["id"].as_str().expect("attempt id").to_owned();
    assert_root_absent(&root, &bytes);

    let (status, attempts, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-order-submissions/{submission_id}/qualifications"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "attempt list: {attempts}");
    assert_eq!(attempts[0]["id"], attempt_id);
    assert_root_absent(&root, &bytes);

    let (status, fetched_attempt, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-order-attempts/{attempt_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "attempt get: {fetched_attempt}");
    assert_eq!(fetched_attempt["id"], attempt_id);
    assert_root_absent(&root, &bytes);

    let (status, ranking, bytes) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-order-attempts/rank",
        serde_json::json!({ "attempt_ids": [attempt_id] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "ranking response: {ranking}");
    assert_eq!(ranking["attempt_ids"][0], fetched_attempt["id"]);
    assert!(ranking["winner_attempt_id"].is_null());
    assert_root_absent(&root, &bytes);

    let (status, promotion, bytes) = empty_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-order-attempts/{attempt_id}/promotion"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "promotion: {promotion}");
    assert_eq!(promotion["code"], "attempt_not_smoke_passed");
    assert_root_absent(&root, &bytes);
}

#[tokio::test]
async fn unknown_resource_ids_return_stable_codes_without_root_disclosure() {
    let fixture = ApiFixture::new().await;
    let root = fixture.canonical_root();
    let missing_order = "0".repeat(64);
    let missing_uuid = "00000000-0000-0000-0000-000000000001";

    let requests = [
        (
            Method::GET,
            format!("/harness/work-orders/{missing_order}"),
            "work_order_not_found",
        ),
        (
            Method::GET,
            format!("/harness/work-orders/{missing_order}/submissions"),
            "work_order_not_found",
        ),
        (
            Method::POST,
            format!("/harness/work-order-submissions/{missing_uuid}/qualifications"),
            "submission_not_found",
        ),
        (
            Method::GET,
            format!("/harness/work-order-submissions/{missing_uuid}/qualifications"),
            "submission_not_found",
        ),
        (
            Method::GET,
            format!("/harness/work-order-attempts/{missing_uuid}"),
            "attempt_not_found",
        ),
    ];

    for (method, uri, code) in requests {
        let (status, body, bytes) = empty_request(&fixture.app, method, &uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
        assert_eq!(body["code"], code, "{uri}: {body}");
        assert!(body["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()));
        assert_root_absent(&root, &bytes);
    }

    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{missing_order}/submissions"),
        serde_json::json!({"source": "valid source", "origin": "human"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "import: {body}");
    assert_eq!(body["code"], "work_order_not_found");
    assert_root_absent(&root, &bytes);

    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-order-attempts/rank",
        serde_json::json!({"attempt_ids": [missing_uuid]}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "rank: {body}");
    assert_eq!(body["code"], "attempt_not_found");
    assert_root_absent(&root, &bytes);

    let (status, body, bytes) = empty_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-order-attempts/{missing_uuid}/promotion"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "promotion: {body}");
    assert_eq!(body["code"], "attempt_not_found");
    assert_root_absent(&root, &bytes);
}

#[tokio::test]
async fn import_body_limit_accepts_the_exact_boundary_and_rejects_the_next_byte() {
    let fixture = ApiFixture::new().await;
    let missing_order = "0".repeat(64);
    let suffix = r#"","origin":"human","parent_submission_id":null}"#;
    let prefix = r#"{"source":""#;
    let source_len = IMPORT_BODY_LIMIT - prefix.len() - suffix.len();
    let exact = format!("{prefix}{}{suffix}", "x".repeat(source_len));
    assert_eq!(exact.len(), IMPORT_BODY_LIMIT);

    let (status, bytes) = send(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{missing_order}/submissions"),
        Body::from(exact.clone()),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let exact_body: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON error body");
    assert_eq!(exact_body["code"], "work_order_not_found");

    let (status, _) = send(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{missing_order}/submissions"),
        Body::from(format!("{exact} ")),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn public_json_requests_reject_unknown_or_authority_bearing_fields() {
    let fixture = ApiFixture::new().await;
    let (work_order_id, _) = export_work_order(&fixture).await;
    let cases = [
        (
            "/harness/work-orders".to_owned(),
            serde_json::json!({
                "project": fixture.project,
                "target": "parse_packet",
                "lang": "c",
                "engine": "libfuzzer",
                "target_id": "00000000-0000-0000-0000-000000000001"
            }),
        ),
        (
            format!("/harness/work-orders/{work_order_id}/submissions"),
            serde_json::json!({
                "source": "int LLVMFuzzerTestOneInput(void) { return 0; }",
                "origin": "human",
                "project_root": fixture.project,
                "command": ["sh", "-c", "true"]
            }),
        ),
        (
            format!("/harness/work-orders/{work_order_id}/submissions"),
            serde_json::json!({
                "source": "int LLVMFuzzerTestOneInput(void) { return 0; }",
                "origin": {"external_tool": {"tool": "author", "env": {"KEY": "value"}}}
            }),
        ),
        (
            "/harness/work-order-attempts/rank".to_owned(),
            serde_json::json!({
                "attempt_ids": ["00000000-0000-0000-0000-000000000001"],
                "approval": true
            }),
        ),
    ];

    for (uri, body) in cases {
        let (status, _, bytes) = json_request(&fixture.app, Method::POST, &uri, body).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
        assert_root_absent(&fixture.canonical_root(), &bytes);
    }

    for uri in [
        "/harness/work-order-submissions/00000000-0000-0000-0000-000000000001/qualifications",
        "/harness/work-order-attempts/00000000-0000-0000-0000-000000000001/promotion",
    ] {
        let (status, body, bytes) = json_request(
            &fixture.app,
            Method::POST,
            uri,
            serde_json::json!({"approval": true, "library_paths": [fixture.project]}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_root_absent(&fixture.canonical_root(), &bytes);
    }
}

#[tokio::test]
async fn missing_store_is_an_error_instead_of_a_successful_empty_list() {
    let root = tempfile::tempdir().expect("temporary security root");
    let security = WebSecurityConfig::new(None, true, Vec::new(), vec![root.path().to_path_buf()])
        .expect("open local test security");
    let app = build_with_state_and_security(
        AppState::new(hf_service::ServiceContainer::stubbed()),
        security,
    );

    let (status, body, bytes) = empty_request(&app, Method::GET, "/harness/work-orders").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["code"], "storage_required");
    assert!(!body.as_array().is_some_and(Vec::is_empty));
    assert_root_absent(
        std::fs::canonicalize(root.path())
            .expect("canonical security root")
            .to_string_lossy()
            .as_ref(),
        &bytes,
    );
}

#[tokio::test]
async fn validation_and_old_v1_route_have_stable_terminal_outcomes() {
    let fixture = ApiFixture::new().await;
    let (work_order_id, _) = export_work_order(&fixture).await;
    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{work_order_id}/submissions"),
        serde_json::json!({
            "source": "",
            "origin": "human",
            "parent_submission_id": null
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "source_empty");
    assert_root_absent(&fixture.canonical_root(), &bytes);

    let (status, _, _) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-order",
        serde_json::json!({
            "project": fixture.project,
            "target": "parse_packet",
            "lang": "c",
            "engine": "libfuzzer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn export_refuses_a_project_outside_the_approved_web_roots() {
    let fixture = ApiFixture::new().await;
    let outside = tempfile::tempdir().expect("outside project root");
    let outside_root = std::fs::canonicalize(outside.path())
        .expect("canonical outside root")
        .to_string_lossy()
        .into_owned();
    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-orders",
        serde_json::json!({
            "project": outside.path(),
            "target": "parse_packet",
            "lang": "c",
            "engine": "libfuzzer"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "invalid_project_path");
    assert_root_absent(&outside_root, &bytes);
    assert_root_absent(&fixture.canonical_root(), &bytes);
}
