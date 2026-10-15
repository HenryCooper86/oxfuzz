//! Stable-id saved report publication over HTTP.
//!
//! The REST report DTO redacts `project` to `<redacted-path>`, so a browser
//! can never supply the owning path. These regressions pin the root identity
//! flow: the report is addressed by its stable id, the server resolves the
//! saved owner from the stored draft, authorizes that resolved owner against
//! the web project policy, binds the canonical approval result into the same
//! resolved snapshot, and publishes it without re-reading the editable draft.
//!
//! The test process runs with its own isolated `HF_REPORTS_DIR` and
//! `HF_CONFIG_DIR` (the `DefectDojo` integration pointed at a process-local
//! stub) plus open-dev-mode auth, installed once before any test body runs,
//! so no real integration is ever contacted and no other test binary's
//! environment is touched.

#![cfg(feature = "change-aware")]

use std::path::PathBuf;
use std::sync::LazyLock;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use hf_service::test_support::defectdojo_stub::{CapturedImport, DefectDojoStub};
use hf_service::test_support::ChangeAwareTestFixture;
use tower::ServiceExt;
use uuid::Uuid;

struct FixtureEnv {
    stub: DefectDojoStub,
}

/// The stub integration and open-dev-mode auth for this test process.
static ENV: LazyLock<FixtureEnv> = LazyLock::new(|| {
    let stub = DefectDojoStub::start();
    let unique = format!("{}_{}", std::process::id(), Uuid::new_v4());
    let config_dir = std::env::temp_dir().join(format!("oxfuzz_web_report_config_{unique}"));
    let reports_dir = std::env::temp_dir().join(format!("oxfuzz_web_report_reports_{unique}"));
    std::fs::create_dir_all(&config_dir).expect("create isolated config dir");
    std::fs::create_dir_all(&reports_dir).expect("create isolated reports dir");
    std::fs::write(
        config_dir.join("defectdojo.toml"),
        format!("url = \"{}\"\napi_token = \"stub-token\"\n", stub.url()),
    )
    .expect("write stub defectdojo config");
    // This test binary owns these variables for the whole process and sets
    // each exactly once (lazy initialization before any test body reads
    // them), so no concurrent mutation can race the override. Auth stays in
    // the explicit unauthenticated local-dev mode the other API test binaries
    // use; `HF_WEB_TOKEN` is never set.
    std::env::set_var("HF_CONFIG_DIR", &config_dir);
    std::env::set_var("HF_REPORTS_DIR", &reports_dir);
    std::env::set_var("HF_WEB_TOKEN_OPTIONAL", "1");
    FixtureEnv { stub }
});

/// Imports captured for `product`, the requesting test's unique project name.
fn imports_for(product: &str) -> Vec<CapturedImport> {
    ENV.stub.imports_for(product)
}

/// The router for `fixture`, approving only its own project root.
fn app_for(fixture: &ChangeAwareTestFixture) -> axum::Router {
    hf_web::build_with_state_and_security(
        hf_web::router::AppState::new(fixture.container()),
        hf_web::WebSecurityConfig::new(
            None,
            true,
            Vec::new(),
            vec![fixture.project_root().to_path_buf()],
        )
        .unwrap(),
    )
}

/// The project's directory basename: the `DefectDojo` product name a push of
/// this project must carry.
fn product_name(fixture: &ChangeAwareTestFixture) -> String {
    fixture
        .project_root()
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .expect("project basename")
}

async fn response_json(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, json)
}

async fn push_report(app: &axum::Router, report_id: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/reports/{report_id}/defectdojo"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    response_json(response).await
}

// ---------------------------------------------------------------------------
// Regressions
// ---------------------------------------------------------------------------

/// Pushing a saved report by id publishes the *saved* owner and target even
/// though the listing DTO redacts the project: the browser could never have
/// supplied the real owner, and the push does not need it to.
#[tokio::test]
async fn saved_report_push_by_id_publishes_saved_owner_and_target() {
    let _env = &*ENV;
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .expect("store-backed fixture");
    let product = product_name(&fixture);
    let saved = fixture
        .container()
        .save_report_draft(
            None,
            "Parser campaign",
            &fixture.project_root().to_string_lossy(),
            Some(fixture.target_symbol()),
            "Approved",
            "# Parser campaign",
        )
        .expect("save report draft");
    let app = app_for(&fixture);

    // The DTO the browser holds redacts the owning project.
    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/reports")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let (status, reports) = response_json(listed).await;
    assert_eq!(status, StatusCode::OK);
    let mine = reports
        .as_array()
        .expect("report listing")
        .iter()
        .find(|report| report["id"] == saved.id.as_str())
        .expect("saved report is listed");
    assert_eq!(mine["project"], "<redacted-path>");

    // The push is a stable-id POST with an empty body; a payload is a client
    // bug, not something the route silently accepts.
    let rejected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/reports/{}/defectdojo", saved.id))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let (status, outcome) = push_report(&app, &saved.id).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        outcome["findings_pushed"].as_u64().unwrap_or(0) >= 1,
        "the saved owner's latest evidence was published: {outcome}"
    );

    let captured = imports_for(&product);
    assert_eq!(captured.len(), 1, "exactly one import reached DefectDojo");
    assert_eq!(captured[0].field("product_name"), Some(product.as_str()));
    assert_eq!(
        captured[0].field("test_title"),
        Some(format!("oxfuzz: {}", fixture.target_symbol()).as_str()),
        "the saved target names the DefectDojo test"
    );
}

/// A saved report owned by a project outside the approved web roots refuses
/// with a bounded policy error -- no absolute path disclosure -- and nothing
/// reaches the integration.
#[tokio::test]
async fn foreign_report_owner_refuses_without_path_disclosure() {
    let _env = &*ENV;
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .expect("store-backed fixture");
    let outside = tempfile::tempdir().unwrap();
    let foreign_product = outside
        .path()
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .expect("foreign basename");
    let saved = fixture
        .container()
        .save_report_draft(
            None,
            "Foreign campaign",
            &outside.path().to_string_lossy(),
            Some("parse_foreign"),
            "Approved",
            "# Foreign campaign",
        )
        .expect("save foreign-owned draft");
    let app = app_for(&fixture);

    let (status, error) = push_report(&app, &saved.id).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let message = error["error"].as_str().unwrap_or_default().to_owned();
    assert!(
        !message.contains(outside.path().to_string_lossy().as_ref()),
        "policy error discloses no owner path: {message}"
    );
    assert!(
        imports_for(&foreign_product).is_empty(),
        "the foreign owner never reached the integration"
    );
}

/// An unknown report id refuses before any downstream transport.
#[tokio::test]
async fn unknown_report_id_refuses_before_transport() {
    let _env = &*ENV;
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .expect("store-backed fixture");
    let product = product_name(&fixture);
    let app = app_for(&fixture);

    let (status, error) = push_report(&app, &Uuid::new_v4().to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        error["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not found"),
        "error names the missing report: {error}"
    );
    assert!(
        imports_for(&product).is_empty(),
        "no transport happened for the approved project"
    );
}

/// A saved owner spelled through a symlinked alias still publishes the
/// canonical approved directory: the handler binds the authorization
/// resolver's canonical result into the resolved snapshot it executes.
#[cfg(unix)]
#[tokio::test]
async fn aliased_saved_owner_publishes_the_canonical_approved_path() {
    let _env = &*ENV;
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .expect("store-backed fixture");
    let real_root: PathBuf = fixture.project_root().to_path_buf();
    let product = product_name(&fixture);
    let alias_parent = tempfile::tempdir().unwrap();
    let alias = alias_parent.path().join("alias-to-project");
    std::os::unix::fs::symlink(&real_root, &alias).expect("symlink the saved owner alias");
    let saved = fixture
        .container()
        .save_report_draft(
            None,
            "Aliased campaign",
            &alias.to_string_lossy(),
            Some(fixture.target_symbol()),
            "Approved",
            "# Aliased campaign",
        )
        .expect("save alias-owned draft");
    let app = app_for(&fixture);

    let (status, outcome) = push_report(&app, &saved.id).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the alias canonicalizes inside the approved root: {outcome}"
    );

    let captured = imports_for(&product);
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].field("product_name"),
        Some(product.as_str()),
        "the canonical directory names the product, not the alias"
    );
    assert!(
        imports_for("alias-to-project").is_empty(),
        "the raw alias spelling never names the published product"
    );
}
