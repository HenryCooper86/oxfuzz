//! Isolated service fixtures for desktop execution-approval tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::harness::Harness;
use hf_core::provider::{
    ChatRequest, ChatResponse, ChatStreamResponse, ProviderError, ProviderPool, ProviderStatus,
    RouteRequest,
};
use hf_core::runtime::{CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter};
use hf_core::target::{InputSurface, SourceLocation, TargetCandidate, TargetKind};
use hf_core::types::ProviderId;
use hf_guardrails::{AutoApprove, DenyAll, GuardrailPolicy, Guardrails};

use crate::{ClassifiedError, EngineKind, ServiceContainer, TargetLanguage};

const CHILD_TEST: &str = "OXFUZZ_DESKTOP_APPROVAL_CHILD";
const HARNESS: &str = "#include <stddef.h>\nint parse_packet(const unsigned char *, size_t);\nint LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) { return parse_packet(data, size); }";
const REVIEW: &str = r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["the exact source forwards fuzz input to parse_packet"]}"#;

/// Runs one test in a subprocess with private configuration and managed storage.
/// Returns `true` in the parent after its child succeeds; the child returns
/// `false` and executes the test body. No process-global settings are mutated.
///
/// # Panics
/// Panics when isolation cannot be prepared or the child test fails.
pub fn in_isolated_test_process(test_name: &str) -> bool {
    if std::env::var(CHILD_TEST).as_deref() == Ok(test_name) {
        return false;
    }
    let directory = tempfile::tempdir().expect("create isolated desktop test root");
    let config = directory.path().join("config");
    let workspace = directory.path().join("workspace");
    std::fs::create_dir(&config).expect("create isolated configuration");
    std::fs::create_dir(&workspace).expect("create isolated workspace");
    let workspace = std::fs::canonicalize(workspace).expect("canonicalize isolated workspace");
    let manifest = serde_json::json!({
        "application": "oxfuzz", "version": 1, "canonical_root": workspace,
    });
    std::fs::write(
        workspace.join(".oxfuzz-workspace.json"),
        serde_json::to_vec(&manifest).expect("serialize workspace ownership"),
    )
    .expect("write workspace ownership");
    let output = std::process::Command::new(std::env::current_exe().expect("locate test binary"))
        .args(["--exact", test_name, "--nocapture"])
        .env(CHILD_TEST, test_name)
        .env("HF_CONFIG_DIR", config)
        .env("HF_WORKSPACE_DIR", workspace)
        .output()
        .expect("start isolated desktop test");
    assert!(
        output.status.success(),
        "isolated desktop test {test_name} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    true
}

struct InertRuntime {
    known_findings: bool,
}

#[async_trait::async_trait]
impl RuntimeAdapter for InertRuntime {
    async fn resolve_image_reference(
        &self,
        _: &str,
    ) -> Result<Option<crate::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(super::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        command: &[String],
        cwd: &Path,
        _: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        if let Some((_, output)) = command
            .get(2)
            .and_then(|script| script.rsplit_once("/work/'"))
        {
            let (name, _) = output.split_once('\'').expect("quoted compile output");
            std::fs::write(cwd.join(name), b"inert desktop test binary")
                .map_err(|error| ClassifiedError::Sandbox(error.to_string()))?;
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: if self.known_findings {
                "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128\nTest unit written to crash-fixture"
            } else {
                "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128"
            }
            .to_owned(),
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

struct ApprovingReview;

#[async_trait::async_trait]
impl ProviderPool for ApprovingReview {
    async fn chat_completion(
        &self,
        _: &ChatRequest,
        _: &RouteRequest,
    ) -> Result<ChatResponse, ProviderError> {
        Ok(super::test_chat_response(REVIEW))
    }

    async fn chat_completion_stream(
        &self,
        _: &ChatRequest,
        _: &RouteRequest,
    ) -> Result<ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "review fixture does not stream".to_owned(),
        })
    }

    fn report_error(&self, _: &ProviderId, _: &ProviderError) {}
    async fn provider_statuses(&self) -> Vec<ProviderStatus> {
        Vec::new()
    }
    async fn freeze(&self, _: &ProviderId, _: String) {}
    async fn thaw(&self, _: &ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

/// Retained project and a strict startup service backed by inert dependencies.
pub struct DesktopApprovalFixture {
    /// Owns the temporary project and database.
    pub directory: tempfile::TempDir,
    /// Canonical fixture project root.
    pub project: PathBuf,
    /// File-qualified selector used by compilation, smoke, and promotion.
    pub target: String,
    /// Container whose original approval gate refuses privileged operations.
    pub service: ServiceContainer,
}

impl DesktopApprovalFixture {
    /// Creates one target and its compile context without executing a process.
    /// Call only in a process prepared by [`in_isolated_test_process`].
    ///
    /// # Panics
    /// Panics when fixture resources cannot be prepared.
    pub async fn new(known_findings: bool) -> Self {
        assert!(
            std::env::var_os(CHILD_TEST).is_some(),
            "fixture requires isolation"
        );
        let directory = tempfile::tempdir().expect("create desktop approval fixture");
        let project = directory.path().join("project");
        std::fs::create_dir(&project).expect("create project");
        let project = project.canonicalize().expect("canonicalize project");
        std::fs::write(project.join("parser.c"), "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t size) { return size > 0 && data[0]; }\n")
            .expect("write target source");
        std::fs::write(
            project.join("compile_commands.json"),
            serde_json::to_vec(&serde_json::json!([{
                "directory": project, "file": project.join("parser.c"),
                "arguments": ["cc", "-std=c11", "-c", "parser.c"],
            }]))
            .expect("serialize compile context"),
        )
        .expect("write compile context");
        let store = Arc::new(
            super::Store::connect(directory.path().join("approval.db"))
                .await
                .expect("create fixture store"),
        );
        store
            .save_inventory(
                &crate::TargetInventory {
                    project_root: project.clone(),
                    candidates: vec![TargetCandidate {
                        id: uuid::Uuid::new_v4(),
                        project_root: project.clone(),
                        language: TargetLanguage::C,
                        symbol: "parse_packet".to_owned(),
                        kind: TargetKind::Parser,
                        location: SourceLocation {
                            file: PathBuf::from("parser.c"),
                            line: 2,
                            col: 1,
                            end_line: None,
                            end_col: None,
                        },
                        signature: Some(
                            "int parse_packet(const unsigned char *, size_t)".to_owned(),
                        ),
                        input_surface: InputSurface::Bytes,
                        complexity: 4,
                        fit_score: 0.9,
                        sanitizers: Vec::new(),
                        rationale: "fixture parser".to_owned(),
                        reachable_functions: Vec::new(),
                        accumulated_complexity: 4,
                    }],
                    call_graph: std::collections::HashMap::new(),
                },
                chrono::Utc::now(),
            )
            .await
            .expect("retain fixture inventory");
        let service = ServiceContainer::new(
            Arc::new(InertRuntime { known_findings }),
            Some(Arc::new(ApprovingReview)),
        )
        .with_store(store)
        .with_guardrails(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(DenyAll),
        ));
        Self {
            directory,
            project,
            target: "parser.c::parse_packet".to_owned(),
            service,
        }
    }

    fn approving_setup_service(&self) -> ServiceContainer {
        self.service.clone().with_guardrails(Guardrails::new(
            GuardrailPolicy::default(),
            Arc::new(AutoApprove),
        ))
    }

    /// Creates an immutable work-order submission without dispatching a build.
    ///
    /// # Panics
    /// Panics when export or import fails.
    #[cfg(feature = "harness-work-order")]
    pub async fn submission(&self) -> crate::HarnessWorkOrderSubmission {
        let order = self
            .service
            .export_harness_work_order(crate::HarnessWorkOrderExportRequest {
                project: self.project.clone(),
                target: self.target.clone(),
                language: TargetLanguage::C,
                engine: EngineKind::LibFuzzer,
            })
            .await
            .expect("export fixture work order");
        self.service
            .import_harness_work_order_submission(crate::ImportHarnessWorkOrderSubmissionRequest {
                work_order_id: order.id,
                source: HARNESS.to_owned(),
                origin: crate::WorkOrderSubmissionOrigin::Human,
                parent_submission_id: None,
            })
            .await
            .expect("import fixture submission")
    }

    /// Prepares retained qualification evidence using an isolated setup clone.
    /// The original service continues to deny execution approval.
    ///
    /// # Panics
    /// Panics when the controlled qualification does not pass.
    #[cfg(feature = "harness-work-order")]
    pub async fn prepare_qualified_attempt(&self) -> crate::HarnessWorkOrderAttempt {
        let submission = self.submission().await;
        let attempt = self
            .approving_setup_service()
            .qualify_harness_work_order_submission(submission.id)
            .await
            .expect("qualify fixture submission");
        assert_eq!(
            attempt.status,
            crate::HarnessWorkOrderAttemptStatus::SmokePassed,
            "{attempt:?}"
        );
        attempt
    }

    /// Compiles and smoke-qualifies through the real service using inert output.
    ///
    /// # Panics
    /// Panics when compilation, review, or smoke cannot complete.
    pub async fn prepare_harness(&self, engine: EngineKind) -> Harness {
        let setup = self.approving_setup_service();
        setup
            .harness_compile(
                HARNESS.to_owned(),
                &self.project,
                engine,
                &self.target,
                TargetLanguage::C,
                None,
                false,
            )
            .await
            .expect("compile fixture harness");
        setup
            .harness_smoke(&self.project, &self.target, engine, TargetLanguage::C)
            .await
            .expect("review and smoke fixture harness");
        let item = setup
            .harness_review_queue(Some(&self.project), Some(&self.target))
            .await
            .expect("read qualified fixture")
            .into_iter()
            .next()
            .expect("fixture harness");
        setup
            .store()
            .unwrap()
            .get_harness(uuid::Uuid::parse_str(&item.harness_id).unwrap())
            .await
            .unwrap()
            .unwrap()
    }

    /// Prepares a promoted harness for other desktop execution tests.
    ///
    /// # Panics
    /// Panics when controlled qualification or clean promotion fails.
    pub async fn prepare_promoted_harness(&self, engine: EngineKind) -> Harness {
        self.prepare_harness(engine).await;
        self.approving_setup_service()
            .harness_promote(&self.project, &self.target, engine)
            .await
            .expect("promote fixture harness")
    }
}
