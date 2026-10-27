//! Explicit desktop actions must reach their service workflow with scoped consent.

use std::path::Path;
use std::sync::Arc;

use hf_service::test_support::desktop_approval::{
    in_isolated_test_process, DesktopApprovalFixture,
};
use hf_service::ServiceContainer;
#[cfg(any(
    feature = "build-doctor",
    feature = "change-aware",
    feature = "patch-to-proof"
))]
use hf_service::{ApprovalGate, GuardrailPolicy, Guardrails};
use serde_json::{json, Value};

#[cfg(any(
    feature = "build-doctor",
    feature = "change-aware",
    feature = "patch-to-proof"
))]
struct DenyStartupApproval;

#[cfg(any(
    feature = "build-doctor",
    feature = "change-aware",
    feature = "patch-to-proof"
))]
#[async_trait::async_trait]
impl ApprovalGate for DenyStartupApproval {
    async fn request_approval(&self, _: &hf_service::Action, _: &str) -> bool {
        false
    }
}

#[cfg(any(
    feature = "build-doctor",
    feature = "change-aware",
    feature = "patch-to-proof"
))]
fn with_denied_startup(service: ServiceContainer) -> ServiceContainer {
    service.with_guardrails(Guardrails::new(
        GuardrailPolicy::default(),
        Arc::new(DenyStartupApproval),
    ))
}

struct DesktopIpc {
    _app: tauri::App<tauri::test::MockRuntime>,
    window: tauri::WebviewWindow<tauri::test::MockRuntime>,
    scheduler: Arc<hf_service::scheduler::CampaignScheduler>,
}

impl DesktopIpc {
    async fn new(service: ServiceContainer, directory: &Path) -> Self {
        let scheduler = Arc::new(
            hf_service::scheduler::CampaignScheduler::try_start(
                service.clone(),
                directory.join("schedules.json"),
                None,
            )
            .await
            .expect("start isolated scheduler"),
        );
        let app = tauri::test::mock_builder()
            .manage(crate::state::AppState::new(service, Arc::clone(&scheduler)))
            .invoke_handler(tauri::generate_handler![
                crate::commands::seed_survival,
                crate::commands::corpus_prune_coverage,
                crate::commands::corpus_minimize,
                crate::commands::build_run,
                crate::commands::file_issue,
                crate::commands::push_to_defectdojo,
                crate::commands::change_publish,
                crate::commands::start_remediation_verification,
                crate::commands::harness_tournament,
                crate::commands::automotive_live_monitor,
                crate::commands::automotive_scan_uds,
            ])
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .expect("build test application");
        let window = tauri::WebviewWindowBuilder::new(&app, "main", tauri::WebviewUrl::default())
            .build()
            .expect("build test window");
        Self {
            _app: app,
            window,
            scheduler,
        }
    }

    fn invoke(&self, command: &str, body: Value) -> Result<Value, Value> {
        tauri::test::get_ipc_response(
            &self.window,
            tauri::webview::InvokeRequest {
                cmd: command.to_owned(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: self.window.url().expect("test window URL"),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: tauri::http::HeaderMap::new(),
                invoke_key: tauri::test::INVOKE_KEY.to_owned(),
            },
        )
        .map(|body| body.deserialize::<Value>().expect("JSON IPC response"))
    }
}

async fn assert_approved(service: &ServiceContainer, origin: &str, action: &str) {
    let decisions = service
        .store()
        .expect("fixture store")
        .list_guardrail_decisions(100)
        .await
        .expect("read approval audit");
    assert!(
        decisions.iter().any(|decision| {
            decision.origin == origin
                && decision.action == action
                && decision.decision == "approved"
        }),
        "missing {origin}/{action} operator approval: {decisions:?}"
    );
}

async fn corpus_fixture(engine: hf_service::EngineKind) -> DesktopApprovalFixture {
    let fixture = DesktopApprovalFixture::new(false).await;
    fixture.prepare_promoted_harness(engine).await;
    let corpus = hf_service::workspace_dir(&fixture.project, &fixture.target).join("corpus");
    std::fs::create_dir_all(&corpus).expect("create corpus");
    std::fs::write(corpus.join("seed"), b"fixture-seed").expect("write retained seed");
    fixture
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_survival_ipc_approves_only_the_explicit_measurement() {
    if in_isolated_test_process(
        "workflow_approval_tests::seed_survival_ipc_approves_only_the_explicit_measurement",
    ) {
        return;
    }
    let fixture = corpus_fixture(hf_service::EngineKind::AflPlusPlus).await;
    let ipc = DesktopIpc::new(fixture.service.clone(), fixture.directory.path()).await;
    let result = ipc.invoke(
        "seed_survival",
        json!({"project":fixture.project,"target":fixture.target}),
    );
    ipc.scheduler.stop().await;
    let result = result.expect("explicit seed measurement reaches inert showmap");
    assert_eq!(result["total"], 1);
    assert_eq!(result["not_measured"], 1);
    assert_approved(&fixture.service, "seed_survival", "run_fuzzer").await;
    let error = fixture
        .service
        .seed_survival(&fixture.project, &fixture.target)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("approval declined"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn coverage_prune_ipc_approves_the_qualified_corpus_operation() {
    if in_isolated_test_process(
        "workflow_approval_tests::coverage_prune_ipc_approves_the_qualified_corpus_operation",
    ) {
        return;
    }
    let fixture = corpus_fixture(hf_service::EngineKind::AflPlusPlus).await;
    let ipc = DesktopIpc::new(fixture.service.clone(), fixture.directory.path()).await;
    let result = ipc.invoke(
        "corpus_prune_coverage",
        json!({"project":fixture.project,"target":fixture.target}),
    );
    ipc.scheduler.stop().await;
    let result = result.expect("explicit coverage pruning reaches inert showmap");
    assert_eq!(result["before"], 1);
    assert_eq!(result["after"], 1);
    assert_approved(&fixture.service, "corpus_prune_coverage", "run_fuzzer").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn corpus_minimize_ipc_reaches_merge_and_preserves_corpus_on_empty_output() {
    if in_isolated_test_process("workflow_approval_tests::corpus_minimize_ipc_reaches_merge_and_preserves_corpus_on_empty_output") {
        return;
    }
    let fixture = corpus_fixture(hf_service::EngineKind::LibFuzzer).await;
    let ipc = DesktopIpc::new(fixture.service.clone(), fixture.directory.path()).await;
    let result = ipc.invoke(
        "corpus_minimize",
        json!({"project":fixture.project,"target":fixture.target}),
    );
    ipc.scheduler.stop().await;
    let error = result.expect_err("inert merge produces no survivor set");
    assert!(
        error
            .as_str()
            .unwrap()
            .contains("corpus minimization produced an empty survivor set"),
        "{error}"
    );
    assert_eq!(
        std::fs::read(
            hf_service::workspace_dir(&fixture.project, &fixture.target).join("corpus/seed")
        )
        .unwrap(),
        b"fixture-seed"
    );
    assert_approved(&fixture.service, "corpus_minimize", "run_fuzzer").await;
}

#[cfg(feature = "build-doctor")]
#[derive(Default)]
struct BuildDispatchRuntime {
    builds: std::sync::atomic::AtomicUsize,
}

#[cfg(feature = "build-doctor")]
#[async_trait::async_trait]
impl hf_service::RuntimeAdapter for BuildDispatchRuntime {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<hf_service::ImmutableImageReference>, hf_service::ClassifiedError> {
        Ok(Some(hf_service::test_support::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        command: &[String],
        cwd: &Path,
        _: &hf_service::ResourceLimits,
    ) -> Result<hf_service::CommandResult, hf_service::ClassifiedError> {
        if !matches!(
            command.first().map(String::as_str),
            Some("/bin/sh" | "pkg-config")
        ) {
            self.builds
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Err(hf_service::ClassifiedError::Sandbox(
                "inert build dispatch reached".to_owned(),
            ));
        }
        Ok(hf_service::CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_service::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, _: &Path, _: &str) -> Result<(), hf_service::ClassifiedError> {
        panic!("build runtime must not write files")
    }

    async fn read_file(&self, _: &Path) -> Result<String, hf_service::ClassifiedError> {
        panic!("build runtime must not read files")
    }
}

#[cfg(feature = "build-doctor")]
#[tokio::test(flavor = "multi_thread")]
async fn build_run_ipc_approves_the_reviewed_profile_and_retains_runtime_failure() {
    if in_isolated_test_process("workflow_approval_tests::build_run_ipc_approves_the_reviewed_profile_and_retains_runtime_failure") {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("CMakeLists.txt"),
        "project(fixture C)\nadd_library(parser parser.c)\n",
    )
    .unwrap();
    std::fs::write(project.join("parser.c"), "int parser(void) { return 0; }\n").unwrap();
    let runtime = Arc::new(BuildDispatchRuntime::default());
    let service = with_denied_startup(
        ServiceContainer::new(runtime.clone(), None)
            .with_store_path(directory.path().join("state.db"))
            .await
            .unwrap(),
    );
    let profile = service
        .save_build_profile(hf_service::SaveBuildProfileRequest {
            project: project.to_string_lossy().into_owned(),
            component_root: ".".to_owned(),
            build_system: hf_service::ProfileBuildSystem::CMake,
            compile_database_path: "build/compile_commands.json".to_owned(),
            cmake_definitions: std::collections::BTreeMap::new(),
            dependencies: Vec::new(),
        })
        .await
        .unwrap();
    let ipc = DesktopIpc::new(service.clone(), directory.path()).await;
    let result = ipc.invoke(
        "build_run",
        json!({"project":project,"expectedProfileSha256":profile.profile_sha256}),
    );
    ipc.scheduler.stop().await;
    let error = result.expect_err("controlled build dispatch fails inside the inert runtime");
    assert!(
        error
            .as_str()
            .unwrap()
            .contains("inert build dispatch reached"),
        "{error}"
    );
    assert_eq!(runtime.builds.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_approved(&service, "run_build_plan", "run_project_build").await;
    let history =
        serde_json::to_value(service.build_diagnosis_history(&project, 1).await.unwrap()).unwrap();
    assert_eq!(
        history[0]["diagnosis"]["terminal"]["status"],
        "runtime_failed"
    );
    assert_eq!(
        history[0]["diagnosis"]["profile"]["profile_sha256"],
        profile.profile_sha256
    );
}

#[cfg(feature = "change-aware")]
#[tokio::test(flavor = "multi_thread")]
async fn file_issue_ipc_retains_consent_and_reaches_integration_configuration() {
    if in_isolated_test_process("workflow_approval_tests::file_issue_ipc_retains_consent_and_reaches_integration_configuration") {
        return;
    }
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .unwrap();
    let service = with_denied_startup(fixture.container());
    let crash = service
        .all_crashes()
        .await
        .unwrap()
        .into_iter()
        .find(|crash| crash.run_id == fixture.head_run())
        .unwrap();
    let ipc = DesktopIpc::new(service.clone(), fixture.project_root()).await;
    let error = ipc
        .invoke(
            "file_issue",
            json!({"project":fixture.project_root(), "crashId":crash.id}),
        )
        .expect_err("unconfigured integration must refuse publication");
    ipc.scheduler.stop().await;
    assert!(
        error
            .as_str()
            .unwrap()
            .contains("issue tracker is not configured"),
        "{error}"
    );
    assert_approved(&service, "file_issue", "publish_findings").await;
}

#[cfg(feature = "change-aware")]
#[tokio::test(flavor = "multi_thread")]
async fn defectdojo_ipc_retains_consent_and_reaches_integration_configuration() {
    if in_isolated_test_process("workflow_approval_tests::defectdojo_ipc_retains_consent_and_reaches_integration_configuration") {
        return;
    }
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .unwrap();
    let service = with_denied_startup(fixture.container());
    let ipc = DesktopIpc::new(service.clone(), fixture.project_root()).await;
    let error = ipc.invoke("push_to_defectdojo", json!({"project":fixture.project_root(),"target":fixture.target_symbol(),"expectedRunId":fixture.head_run()}))
        .expect_err("unconfigured integration must refuse publication");
    ipc.scheduler.stop().await;
    assert!(
        error
            .as_str()
            .unwrap()
            .contains("DefectDojo is not configured"),
        "{error}"
    );
    assert_approved(&service, "push_to_defectdojo", "publish_findings").await;
}

#[cfg(feature = "change-aware")]
#[tokio::test(flavor = "multi_thread")]
async fn change_publication_ipc_approves_a_comparable_retained_regression() {
    if in_isolated_test_process(
        "workflow_approval_tests::change_publication_ipc_approves_a_comparable_retained_regression",
    ) {
        return;
    }
    let fixture = hf_service::test_support::change_aware_fixture()
        .await
        .unwrap();
    let service = with_denied_startup(fixture.container());
    let ipc = DesktopIpc::new(service.clone(), fixture.project_root()).await;
    let result = ipc.invoke("change_publish", json!({"baseRunId":fixture.base_run(),"headRunId":fixture.head_run(),"regressionThresholdPct":5.0,"destination":"issue_tracker"}));
    ipc.scheduler.stop().await;
    let error = result.expect_err("unconfigured integration must refuse publication");
    assert!(
        error
            .as_str()
            .unwrap()
            .contains("issue tracker is not configured"),
        "{error}"
    );
    assert_approved(
        &service,
        "publish_change_comparison",
        "publish_change_comparison",
    )
    .await;
}

#[cfg(feature = "patch-to-proof")]
#[tokio::test(flavor = "multi_thread")]
async fn remediation_ipc_preserves_the_required_durable_operation_approval() {
    if in_isolated_test_process("workflow_approval_tests::remediation_ipc_preserves_the_required_durable_operation_approval") {
        return;
    }
    let fixture = hf_service::test_support::patch_to_proof_fixture()
        .await
        .unwrap();
    let service = with_denied_startup(fixture.container());
    let ipc = DesktopIpc::new(service.clone(), fixture.directory_path()).await;
    let result = ipc.invoke(
        "start_remediation_verification",
        json!({"operationId":fixture.operation_id()}),
    );
    ipc.scheduler.stop().await;
    let error = result.expect_err("a draft operation still requires exact-scope durable approval");
    assert!(error.as_str().unwrap().contains("approved"), "{error}");
    assert_approved(&service, "verify_remediation", "verify_remediation").await;
    let operation = service
        .remediation_operation(fixture.operation_id())
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(operation).unwrap()["status"], "draft");
}

#[cfg(feature = "harness-tournament")]
#[tokio::test(flavor = "multi_thread")]
async fn tournament_ipc_retains_smoke_evidence_without_promoting_the_winner() {
    if in_isolated_test_process("workflow_approval_tests::tournament_ipc_retains_smoke_evidence_without_promoting_the_winner") {
        return;
    }
    let mut fixture = DesktopApprovalFixture::new(false).await;
    // Tournament discovers its target itself; let that scan establish its
    // deterministic id instead of the manually retained fixture target id.
    fixture.service = fixture
        .service
        .with_store_path(fixture.directory.path().join("tournament.db"))
        .await
        .unwrap();
    let ipc = DesktopIpc::new(fixture.service.clone(), fixture.directory.path()).await;
    let result = ipc.invoke("harness_tournament", json!({"project":fixture.project,"target":fixture.target,"engine":"libfuzzer","lang":"c","candidates":1,"maxRepairs":0}));
    ipc.scheduler.stop().await;
    let result = result.expect("single inert tournament candidate completes");
    assert_eq!(result["candidates"][0]["compiled"], true, "{result}");
    assert_approved(&fixture.service, "harness_smoke", "run_harness").await;
    assert!(!result["candidates"][0]["smoke"].is_null(), "{result}");
    assert_eq!(result["promoted"], false);
}

#[cfg(feature = "automotive-scapy")]
async fn assert_virtual_automotive_dispatch(command: &str, arguments: Value, operation: &str) {
    let fixture = DesktopApprovalFixture::new(false).await;
    let mut body = arguments.as_object().unwrap().clone();
    body.insert("projectRoot".to_owned(), json!(fixture.project));
    let ipc = DesktopIpc::new(fixture.service.clone(), fixture.directory.path()).await;
    let result = ipc.invoke(command, Value::Object(body));
    ipc.scheduler.stop().await;
    let error = result.expect_err("inert runtime has no automotive JSONL result");
    assert!(
        error
            .as_str()
            .unwrap()
            .contains("invalid automotive sidecar response"),
        "{error}"
    );
    assert_approved(
        &fixture.service,
        "automotive_operation",
        "automotive_virtual_can",
    )
    .await;
    let history = fixture
        .service
        .list_automotive_operations(&fixture.project, 10)
        .await
        .unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].operation, operation);
    assert_eq!(
        serde_json::to_value(&history[0]).unwrap()["status"],
        "failed"
    );
    assert!(history[0]
        .error
        .as_deref()
        .unwrap()
        .contains("invalid automotive sidecar response"));
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test(flavor = "multi_thread")]
async fn automotive_monitor_ipc_approves_virtual_can_and_retains_dispatch_failure() {
    if in_isolated_test_process("workflow_approval_tests::automotive_monitor_ipc_approves_virtual_can_and_retains_dispatch_failure") {
        return;
    }
    assert_virtual_automotive_dispatch(
        "automotive_live_monitor",
        json!({"interface":"vcan0","protocol":"can"}),
        "live_monitor",
    )
    .await;
}

#[cfg(feature = "automotive-scapy")]
#[tokio::test(flavor = "multi_thread")]
async fn automotive_scan_ipc_approves_read_only_uds_and_retains_dispatch_failure() {
    if in_isolated_test_process("workflow_approval_tests::automotive_scan_ipc_approves_read_only_uds_and_retains_dispatch_failure") {
        return;
    }
    assert_virtual_automotive_dispatch(
        "automotive_scan_uds",
        json!({"interface":"vcan0","requestIds":[0x7E0],"services":[0x3E,0x22]}),
        "scan_uds",
    )
    .await;
}
