//! Isolated Harness Work Order v2 REST contract.

#![cfg(feature = "harness-work-order")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use hf_service::{
    test_support::{
        immutable_test_image, test_chat_response, ChatRequest, ChatResponse, ChatStreamResponse,
        HarnessApprovalKind, ProviderError, ProviderId, ProviderPool, ProviderStatus, RouteRequest,
        Store,
    },
    ClassifiedError, CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter,
};
use hf_web::{build_with_state_and_security, AppState, WebSecurityConfig};
use tower::ServiceExt as _;

const IMPORT_BODY_LIMIT: usize = 131_072;
const VALID_HARNESS: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size > 0 && data[0]; }";
const APPROVING_REVIEW: &str = r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["target receives fuzz input without unsafe side effects"]}"#;

#[derive(Clone)]
enum ControlledRuntimeMode {
    Pass,
    CompileError(String),
}

struct ControlledRuntime {
    calls: AtomicUsize,
    mode: ControlledRuntimeMode,
}

impl ControlledRuntime {
    fn new(mode: ControlledRuntimeMode) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode,
        }
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for ControlledRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_service::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        if call == 0 {
            if let ControlledRuntimeMode::CompileError(message) = &self.mode {
                return Err(ClassifiedError::Sandbox(message.clone()));
            }
            std::fs::create_dir_all(cwd)
                .map_err(|error| ClassifiedError::Sandbox(error.to_string()))?;
            let binary_name = cmd
                .get(2)
                .and_then(|script| script.rsplit_once("/work/'"))
                .and_then(|(_, tail)| tail.split_once('\''))
                .map_or_else(
                    || panic!("compile command carries a staged output: {cmd:?}"),
                    |(name, _)| name,
                );
            std::fs::write(cwd.join(binary_name), b"controlled compiled harness")
                .map_err(|error| ClassifiedError::Sandbox(error.to_string()))?;
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| ClassifiedError::Sandbox(error.to_string()))?;
        }
        std::fs::write(path, content).map_err(|error| ClassifiedError::Sandbox(error.to_string()))
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        std::fs::read_to_string(path).map_err(|error| ClassifiedError::Sandbox(error.to_string()))
    }
}

struct ControlledReviewPool;

#[async_trait::async_trait]
impl ProviderPool for ControlledReviewPool {
    async fn chat_completion(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        Ok(test_chat_response(APPROVING_REVIEW))
    }

    async fn chat_completion_stream(
        &self,
        _request: &ChatRequest,
        _route: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "streaming is unused".to_owned(),
        })
    }

    fn report_error(&self, _provider_id: &ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

fn managed_workspace_root() -> PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz-work-order-web-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create controlled managed workspace");
        let canonical =
            std::fs::canonicalize(&root).expect("canonical controlled managed workspace");
        std::fs::write(
            canonical.join(".oxfuzz-workspace.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "application": "oxfuzz",
                "version": 1,
                "canonical_root": canonical,
            }))
            .expect("serialize controlled workspace manifest"),
        )
        .expect("write controlled workspace manifest");
        canonical
    });
    std::env::set_var("HF_WORKSPACE_DIR", root);
    root.clone()
}

struct ApiFixture {
    _directory: tempfile::TempDir,
    project: PathBuf,
    alternate_project: PathBuf,
    container: hf_service::ServiceContainer,
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
        let alternate_project = directory.path().join("alternate-project-root");
        std::fs::create_dir(&alternate_project).expect("create alternate project root");
        std::fs::write(
            alternate_project.join("decoder.c"),
            b"int decode_packet(const unsigned char *data, unsigned long size) {\n\
                return size == 0 ? 0 : data[0];\n\
              }\n",
        )
        .expect("write alternate project source");

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
        let alternate_inventory = container
            .discover(
                &alternate_project,
                "c".parse().expect("canonical test target language"),
            )
            .await
            .expect("discover and retain alternate test target");
        assert!(
            alternate_inventory
                .candidates
                .iter()
                .any(|candidate| candidate.symbol == "decode_packet"),
            "alternate fixture source must retain the requested target"
        );

        let security = WebSecurityConfig::new(
            None,
            true,
            Vec::new(),
            vec![project.clone(), alternate_project.clone()],
        )
        .expect("open local test security");
        let app = build_with_state_and_security(AppState::new(container.clone()), security);
        Self {
            _directory: directory,
            project,
            alternate_project,
            container,
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

struct ControlledApiFixture {
    _directory: tempfile::TempDir,
    project: PathBuf,
    managed_workspace: PathBuf,
    store: Arc<Store>,
    target_id: uuid::Uuid,
    app: axum::Router,
}

impl ControlledApiFixture {
    async fn new(mode: ControlledRuntimeMode) -> Self {
        let managed_workspace = managed_workspace_root();
        let directory = tempfile::tempdir().expect("temporary controlled API fixture");
        let project = directory.path().join("controlled-private-project");
        std::fs::create_dir(&project).expect("create controlled project");
        std::fs::write(
            project.join("parser.c"),
            b"#include <stddef.h>\n\
              int parse_packet(const unsigned char *data, size_t size) {\n\
                return size == 0 ? 0 : data[0];\n\
              }\n",
        )
        .expect("write controlled project source");
        let store = Arc::new(
            Store::connect(directory.path().join("controlled-work-orders.db"))
                .await
                .expect("open controlled work-order store"),
        );
        let container = hf_service::ServiceContainer::new(
            Arc::new(ControlledRuntime::new(mode)),
            Some(Arc::new(ControlledReviewPool)),
        )
        .with_store(Arc::clone(&store));
        let inventory = container
            .discover(&project, "c".parse().expect("controlled target language"))
            .await
            .expect("discover controlled target");
        let target_id = inventory
            .candidates
            .iter()
            .find(|candidate| candidate.symbol == "parse_packet")
            .expect("controlled target retained")
            .id;
        let security = WebSecurityConfig::new(None, true, Vec::new(), vec![project.clone()])
            .expect("controlled web security");
        let app = build_with_state_and_security(AppState::new(container), security);
        Self {
            _directory: directory,
            project,
            managed_workspace,
            store,
            target_id,
            app,
        }
    }

    fn canonical_root(&self) -> String {
        std::fs::canonicalize(&self.project)
            .expect("canonical controlled project")
            .to_string_lossy()
            .into_owned()
    }

    fn canonical_workspace(&self) -> String {
        std::fs::canonicalize(&self.managed_workspace)
            .expect("canonical controlled managed workspace")
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
    export_project_work_order(fixture, &fixture.project, "parse_packet").await
}

async fn export_project_work_order(
    fixture: &ApiFixture,
    project: &std::path::Path,
    target: &str,
) -> (String, Vec<u8>) {
    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-orders",
        serde_json::json!({
            "project": project,
            "target": target,
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
    assert_eq!(
        body["validation_commands"],
        serde_json::json!([
            {
                "step": "import",
                "argv": [
                    {"literal": "oxfuzz"},
                    {"literal": "work-order"},
                    {"literal": "import"},
                    {"literal": "--work-order"},
                    {"literal": id},
                    {"literal": "--source"},
                    {"placeholder": "source_file"}
                ],
                "approval_required": false
            },
            {
                "step": "qualify",
                "argv": [
                    {"literal": "oxfuzz"},
                    {"literal": "work-order"},
                    {"literal": "qualify"},
                    {"literal": "--submission"},
                    {"placeholder": "submission_id"}
                ],
                "approval_required": true
            },
            {
                "step": "rank",
                "argv": [
                    {"literal": "oxfuzz"},
                    {"literal": "work-order"},
                    {"literal": "rank"},
                    {"literal": "--attempt"},
                    {"placeholder": "attempt_ids"}
                ],
                "approval_required": false
            },
            {
                "step": "promote",
                "argv": [
                    {"literal": "oxfuzz"},
                    {"literal": "work-order"},
                    {"literal": "promote"},
                    {"literal": "--attempt"},
                    {"placeholder": "attempt_id"}
                ],
                "approval_required": true
            },
            {
                "step": {"run_campaign": {"duration_secs": 300}},
                "argv": [
                    {"literal": "oxfuzz"},
                    {"literal": "run"},
                    {"literal": "--target"},
                    {"literal": target},
                    {"literal": "--engine"},
                    {"literal": "libfuzzer"},
                    {"literal": "--duration-secs"},
                    {"literal": "300"}
                ],
                "approval_required": true
            },
            {
                "step": "coverage",
                "argv": [
                    {"literal": "oxfuzz"},
                    {"literal": "coverage"},
                    {"literal": "--target"},
                    {"literal": target}
                ],
                "approval_required": false
            }
        ])
    );
    (id, bytes)
}

async fn controlled_submission(
    fixture: &ControlledApiFixture,
) -> (String, String, serde_json::Value) {
    let (status, work_order, _) = json_request(
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
    assert_eq!(status, StatusCode::OK, "controlled export: {work_order}");
    let work_order_id = work_order["id"]
        .as_str()
        .expect("controlled work-order id")
        .to_owned();
    let (status, submission, _) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{work_order_id}/submissions"),
        serde_json::json!({
            "source": VALID_HARNESS,
            "origin": "human",
            "parent_submission_id": null
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "controlled import: {submission}");
    let submission_id = submission["id"]
        .as_str()
        .expect("controlled submission id")
        .to_owned();
    (work_order_id, submission_id, submission)
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
async fn successful_promotion_returns_an_explicit_path_free_promoted_view() {
    let fixture = ControlledApiFixture::new(ControlledRuntimeMode::Pass).await;
    let (_, submission_id, _) = controlled_submission(&fixture).await;
    let (status, attempt, bytes) = empty_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-order-submissions/{submission_id}/qualifications"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "controlled qualification: {attempt}"
    );
    assert_eq!(attempt["status"], "smoke_passed");
    let attempt_id = attempt["id"]
        .as_str()
        .expect("controlled attempt id")
        .to_owned();
    let harness_id = attempt["harness_id"]
        .as_str()
        .expect("controlled harness id")
        .to_owned();
    let source_sha256 = attempt["result"]["source_sha256"]
        .as_str()
        .expect("controlled source digest")
        .to_owned();
    let binary_sha256 = attempt["result"]["binary_sha256"]
        .as_str()
        .expect("controlled binary digest")
        .to_owned();
    assert_root_absent(&fixture.canonical_root(), &bytes);
    assert_root_absent(&fixture.canonical_workspace(), &bytes);

    let (status, promoted, bytes) = empty_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-order-attempts/{attempt_id}/promotion"),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "controlled promotion: {promoted}");
    assert_eq!(
        promoted,
        serde_json::json!({
            "id": harness_id,
            "target_id": fixture.target_id,
            "engine": "libfuzzer",
            "source": VALID_HARNESS,
            "language": "C",
            "status": "Promoted"
        })
    );
    assert_root_absent(&fixture.canonical_root(), &bytes);
    assert_root_absent(&fixture.canonical_workspace(), &bytes);
    let approval = fixture
        .store
        .harness_approval(
            harness_id.parse().expect("controlled harness UUID"),
            &source_sha256,
            &binary_sha256,
        )
        .await
        .expect("load REST promotion approval")
        .expect("REST promotion retained approval");
    assert_eq!(approval.harness_id.to_string(), harness_id);
    assert_eq!(approval.approval_kind, HarnessApprovalKind::CleanSmoke);
}

#[tokio::test]
async fn successful_attempt_responses_never_return_punctuation_adjacent_credentials() {
    let fixture = ControlledApiFixture::new(ControlledRuntimeMode::CompileError(
        "compile failed detail;sk-embedded-secret \
         detail;token=embedded-assignment-secret \
         detail;Bearer embedded-bearer-secret \
         detail;/Users/operator/private/source.c"
            .to_owned(),
    ))
    .await;
    let (_, submission_id, _) = controlled_submission(&fixture).await;
    let qualification_uri =
        format!("/harness/work-order-submissions/{submission_id}/qualifications");
    let (status, attempt, qualification_bytes) =
        empty_request(&fixture.app, Method::POST, &qualification_uri).await;
    assert_eq!(status, StatusCode::OK, "controlled failure: {attempt}");
    assert_eq!(attempt["status"], "compile_failed");
    let attempt_id = attempt["id"]
        .as_str()
        .expect("controlled failed attempt id")
        .to_owned();

    let (status, attempts, list_bytes) =
        empty_request(&fixture.app, Method::GET, &qualification_uri).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "controlled attempt list: {attempts}"
    );
    let (status, fetched, get_bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-order-attempts/{attempt_id}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "controlled attempt get: {fetched}");

    for body in [&qualification_bytes, &list_bytes, &get_bytes] {
        let body = String::from_utf8_lossy(body);
        for secret in [
            "embedded-secret",
            "embedded-assignment-secret",
            "embedded-bearer-secret",
            "/Users/operator",
        ] {
            assert!(
                !body.contains(secret),
                "attempt response disclosed {secret}"
            );
        }
        assert!(!body.contains(&fixture.canonical_root()));
        assert!(!body.contains(&fixture.canonical_workspace()));
    }
}

#[tokio::test]
async fn list_filter_returns_only_the_approved_project_work_orders() {
    let fixture = ApiFixture::new().await;
    let (primary_id, _) = export_work_order(&fixture).await;
    let (alternate_id, _) =
        export_project_work_order(&fixture, &fixture.alternate_project, "decode_packet").await;

    let (status, filtered, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-orders?project={}", fixture.project.display()),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "filtered list: {filtered}");
    assert_eq!(filtered.as_array().map(Vec::len), Some(1));
    assert_eq!(filtered[0]["id"], primary_id);
    assert_ne!(filtered[0]["id"], alternate_id);
    assert_root_absent(&fixture.canonical_root(), &bytes);
}

#[tokio::test]
async fn list_filter_rejects_unapproved_and_unknown_query_input_as_json() {
    let fixture = ApiFixture::new().await;
    let outside = tempfile::tempdir().expect("outside project filter");
    let outside_root = std::fs::canonicalize(outside.path())
        .expect("canonical outside filter root")
        .to_string_lossy()
        .into_owned();

    let (status, body, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        &format!("/harness/work-orders?project={outside_root}"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "outside filter: {body}");
    assert_eq!(body["code"], "invalid_project_path");
    assert_root_absent(&outside_root, &bytes);
    assert_root_absent(&fixture.canonical_root(), &bytes);

    let (status, body, bytes) = empty_request(
        &fixture.app,
        Method::GET,
        "/harness/work-orders?project_root=/tmp/unauthorized",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "unknown query: {body}");
    assert_eq!(body["code"], "invalid_request");
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| !error.is_empty()));
    assert_root_absent(&fixture.canonical_root(), &bytes);
}

#[tokio::test]
async fn malformed_path_identifiers_return_common_json_validation_errors() {
    let fixture = ApiFixture::new().await;
    let malformed_digest = "A".repeat(64);
    let malformed_uuid = "not-a-uuid";

    for uri in [
        format!("/harness/work-orders/{malformed_digest}"),
        format!("/harness/work-orders/{malformed_digest}/submissions"),
    ] {
        let (status, body, bytes) = empty_request(&fixture.app, Method::GET, &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["code"], "invalid_work_order_digest", "{uri}: {body}");
        assert_root_absent(&fixture.canonical_root(), &bytes);
    }

    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{malformed_digest}/submissions"),
        serde_json::json!({"source": "valid source", "origin": "human"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "import path: {body}");
    assert_eq!(body["code"], "invalid_work_order_digest");
    assert_root_absent(&fixture.canonical_root(), &bytes);

    let requests = [
        (
            Method::POST,
            format!("/harness/work-order-submissions/{malformed_uuid}/qualifications"),
        ),
        (
            Method::GET,
            format!("/harness/work-order-submissions/{malformed_uuid}/qualifications"),
        ),
        (
            Method::GET,
            format!("/harness/work-order-attempts/{malformed_uuid}"),
        ),
        (
            Method::POST,
            format!("/harness/work-order-attempts/{malformed_uuid}/promotion"),
        ),
    ];
    for (method, uri) in requests {
        let (status, body, bytes) = empty_request(&fixture.app, method, &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["code"], "invalid_identifier", "{uri}: {body}");
        assert_root_absent(&fixture.canonical_root(), &bytes);
    }
}

#[tokio::test]
async fn undecodable_identifier_paths_return_common_json_before_service_side_effects() {
    let fixture = ApiFixture::new().await;
    let root = fixture.canonical_root();
    let (work_order_id, _) = export_work_order(&fixture).await;
    let (status, submission, _) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{work_order_id}/submissions"),
        serde_json::json!({
            "source": "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size > 0 && data[0]; }",
            "origin": "human",
            "parent_submission_id": null
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "baseline submission: {submission}");
    let submission_id: uuid::Uuid = submission["id"]
        .as_str()
        .expect("baseline submission id")
        .parse()
        .expect("baseline submission UUID");
    let orders_before = fixture
        .container
        .list_harness_work_orders(None)
        .await
        .expect("list baseline work orders");
    let submissions_before = fixture
        .container
        .list_harness_work_order_submissions(&work_order_id)
        .await
        .expect("list baseline submissions");
    let attempts_before = fixture
        .container
        .list_harness_work_order_attempts(submission_id)
        .await
        .expect("list baseline attempts");

    let requests = [
        (Method::GET, "/harness/work-orders/%FF", None),
        (Method::GET, "/harness/work-orders/%FF/submissions", None),
        (
            Method::POST,
            "/harness/work-orders/%FF/submissions",
            Some(r#"{"source":"valid source","origin":"human"}"#),
        ),
        (
            Method::GET,
            "/harness/work-order-submissions/%FF/qualifications",
            None,
        ),
        (
            Method::POST,
            "/harness/work-order-submissions/%FF/qualifications",
            None,
        ),
        (Method::GET, "/harness/work-order-attempts/%FF", None),
        (
            Method::POST,
            "/harness/work-order-attempts/%FF/promotion",
            None,
        ),
    ];

    for (method, uri, body) in requests {
        let (status, bytes) = send(
            &fixture.app,
            method,
            uri,
            body.map_or_else(Body::empty, Body::from),
            body.is_some(),
        )
        .await;
        let response: serde_json::Value =
            serde_json::from_slice(&bytes).expect("path rejection uses common JSON");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {response}");
        assert_eq!(response["code"], "invalid_request", "{uri}: {response}");
        assert!(response["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
        assert_eq!(response.as_object().map(serde_json::Map::len), Some(2));
        assert_root_absent(&root, &bytes);
    }

    assert_eq!(
        fixture
            .container
            .list_harness_work_orders(None)
            .await
            .expect("list work orders after path rejections"),
        orders_before
    );
    assert_eq!(
        fixture
            .container
            .list_harness_work_order_submissions(&work_order_id)
            .await
            .expect("list submissions after path rejections"),
        submissions_before
    );
    assert_eq!(
        fixture
            .container
            .list_harness_work_order_attempts(submission_id)
            .await
            .expect("list attempts after path rejections"),
        attempts_before
    );
}

#[tokio::test]
async fn malformed_json_identifiers_use_route_owned_common_errors() {
    let fixture = ApiFixture::new().await;
    let (work_order_id, _) = export_work_order(&fixture).await;

    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        &format!("/harness/work-orders/{work_order_id}/submissions"),
        serde_json::json!({
            "source": "valid source",
            "origin": "human",
            "parent_submission_id": "not-a-uuid"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "parent id: {body}");
    assert_eq!(body["code"], "invalid_identifier");
    assert_root_absent(&fixture.canonical_root(), &bytes);

    let (status, body, bytes) = json_request(
        &fixture.app,
        Method::POST,
        "/harness/work-order-attempts/rank",
        serde_json::json!({"attempt_ids": ["not-a-uuid"]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "rank id: {body}");
    assert_eq!(body["code"], "invalid_identifier");
    assert_root_absent(&fixture.canonical_root(), &bytes);

    for (uri, raw_json) in [
        (
            format!("/harness/work-orders/{work_order_id}/submissions"),
            r#"{"source":"valid source","origin":"human","parent_submission_id":17}"#,
        ),
        (
            "/harness/work-order-attempts/rank".to_owned(),
            r#"{"attempt_ids":[17]}"#,
        ),
    ] {
        let (status, bytes) =
            send(&fixture.app, Method::POST, &uri, Body::from(raw_json), true).await;
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).expect("stable JSON extraction error");
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["code"], "invalid_request", "{uri}: {body}");
        assert_root_absent(&fixture.canonical_root(), &bytes);
    }
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
            "invalid_request",
        ),
        (
            format!("/harness/work-orders/{work_order_id}/submissions"),
            serde_json::json!({
                "source": "int LLVMFuzzerTestOneInput(void) { return 0; }",
                "origin": "human",
                "project_root": fixture.project,
                "command": ["sh", "-c", "true"]
            }),
            "invalid_request",
        ),
        (
            format!("/harness/work-orders/{work_order_id}/submissions"),
            serde_json::json!({
                "source": "int LLVMFuzzerTestOneInput(void) { return 0; }",
                "origin": {"external_tool": {"tool": "author", "env": {"KEY": "value"}}}
            }),
            "invalid_request",
        ),
        (
            "/harness/work-order-attempts/rank".to_owned(),
            serde_json::json!({
                "attempt_ids": ["00000000-0000-0000-0000-000000000001"],
                "approval": true
            }),
            "invalid_request",
        ),
    ];

    for (uri, request, code) in cases {
        let (status, body, bytes) = json_request(&fixture.app, Method::POST, &uri, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["code"], code, "{uri}: {body}");
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
        assert_eq!(body["code"], "invalid_request", "{uri}: {body}");
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
