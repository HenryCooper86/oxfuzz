//! Browser workflow routes retain service approval and project access checks.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use axum::{body::Body, http::Request, http::StatusCode, Router};
use hf_service::{
    Action, ApprovalGate, ClassifiedError, CommandResult, CommandTermination, GuardrailPolicy,
    Guardrails, ResourceLimits, RuntimeAdapter, ServiceContainer,
};
use serde_json::{json, Value};
use tower::ServiceExt;

struct CoverageRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for CoverageRuntime {
    async fn run_command(
        &self,
        _command: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(CommandResult {
            exit_code: 0,
            stdout: json!({"data": [{"functions": [
                {"name": "parse", "count": 4}, {"name": "unreached", "count": 0}
            ]}]})
            .to_string(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn write_file(&self, _: &Path, _: &str) -> Result<(), ClassifiedError> {
        panic!("coverage query must not ask the runtime to write a file")
    }

    async fn read_file(&self, _: &Path) -> Result<String, ClassifiedError> {
        panic!("coverage query must not ask the runtime to read a file")
    }
}

#[derive(Default)]
struct DenyApproval(Mutex<Vec<Action>>);

#[async_trait::async_trait]
impl ApprovalGate for DenyApproval {
    async fn request_approval(&self, action: &Action, _: &str) -> bool {
        self.0.lock().unwrap().push(action.clone());
        false
    }
}

fn project_fixture() -> (tempfile::TempDir, PathBuf) {
    static WORKSPACE: OnceLock<tempfile::TempDir> = OnceLock::new();
    WORKSPACE.get_or_init(|| {
        let workspace = tempfile::tempdir().unwrap();
        std::env::set_var("HF_WORKSPACE_DIR", workspace.path());
        workspace
    });
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().canonicalize().unwrap();
    let workspace = hf_service::workspace_dir(&project, "parse");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("harness.c"), "retained fixture source").unwrap();
    (directory, project)
}

fn router(container: ServiceContainer, project: &Path) -> Router {
    hf_web::build_with_state_and_security(
        hf_web::AppState::new(container),
        hf_web::WebSecurityConfig::new(None, true, Vec::new(), vec![project.to_path_buf()])
            .unwrap(),
    )
}

async fn post(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, body)
}

#[tokio::test]
async fn coverage_route_returns_the_service_covered_function_set() {
    let (_directory, project) = project_fixture();
    let app = router(
        ServiceContainer::new(Arc::new(CoverageRuntime), None),
        &project,
    );
    let (status, body) = post(
        &app,
        "/coverage/functions",
        json!({
            "project": project, "target": "parse"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!(["parse"]));
}

#[tokio::test]
async fn workflow_routes_reject_foreign_projects_before_service_approval() {
    let (_directory, project) = project_fixture();
    let (_foreign_directory, foreign_project) = project_fixture();
    let gate = Arc::new(DenyApproval::default());
    let container = ServiceContainer::new(Arc::new(CoverageRuntime), None)
        .with_guardrails(Guardrails::new(GuardrailPolicy::default(), gate.clone()));
    let app = router(container, &project);
    for uri in ["/coverage/functions", "/harness/promote-with-findings"] {
        let (status, body) = post(
            &app,
            uri,
            json!({
                "project": foreign_project, "target": "parse", "engine": "libfuzzer"
            }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
    }
    assert!(gate.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn workflow_routes_preserve_service_approval_denials() {
    let (_directory, project) = project_fixture();
    let gate = Arc::new(DenyApproval::default());
    let container = ServiceContainer::new(Arc::new(CoverageRuntime), None)
        .with_store_path(project.join("state.db"))
        .await
        .unwrap()
        .with_guardrails(Guardrails::new(GuardrailPolicy::default(), gate.clone()));
    let app = router(container.clone(), &project);
    let (status, body) = post(
        &app,
        "/harness/promote-with-findings",
        json!({
            "project": project, "target": "parse", "engine": "libfuzzer"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("approval declined"));
    let (status, body) = post(
        &app,
        "/coverage/functions",
        json!({
            "project": project, "target": "parse"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!([]));
    assert_eq!(
        *gate.0.lock().unwrap(),
        vec![Action::PromoteHarness, Action::RunHarness]
    );
    let decisions = container.policy_decisions(10).await.unwrap();
    for origin in ["harness_promote_with_findings", "coverage_measurement"] {
        assert!(
            decisions
                .iter()
                .any(|decision| decision.origin == origin
                    && decision.decision == "denied_by_operator")
        );
    }
}
