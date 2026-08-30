//! Durable qualification coverage for Harness Work Order v2 submissions.

#![cfg(feature = "harness-work-order")]

mod common;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::provider::{ProviderError, ProviderPool};
use hf_core::runtime::{CommandResult, CommandTermination, ResourceLimits, RuntimeAdapter};
use hf_core::target::{
    InputSurface, SourceLocation, TargetCandidate, TargetInventory, TargetKind, TargetLanguage,
};
use hf_service::{
    HarnessWorkOrderAttemptStage, HarnessWorkOrderAttemptStatus, HarnessWorkOrderErrorCode,
    HarnessWorkOrderExportRequest, ImportHarnessWorkOrderSubmissionRequest, ServiceContainer,
    VerdictLevel, WorkOrderSubmissionOrigin,
};
use uuid::Uuid;

const VALID_HARNESS: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size > 0 && data[0]; }";
const APPROVING_REVIEW: &str = r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["target receives fuzz input without unsafe side effects"]}"#;

#[derive(Clone)]
enum RuntimeMode {
    Pass,
    CompileError(String),
    SmokeError(String),
}

struct ControlledRuntime {
    calls: AtomicUsize,
    workspaces: Mutex<Vec<PathBuf>>,
    mode: RuntimeMode,
}

impl ControlledRuntime {
    fn new(mode: RuntimeMode) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            workspaces: Mutex::new(Vec::new()),
            mode,
        }
    }

    fn command_result(&self, cmd: &[String], cwd: &Path) -> Result<CommandResult, ClassifiedError> {
        let call = self.calls.fetch_add(1, Ordering::Relaxed);
        self.workspaces
            .lock()
            .expect("lock controlled runtime workspaces")
            .push(cwd.to_path_buf());
        if call == 0 {
            if let RuntimeMode::CompileError(message) = &self.mode {
                return Err(ClassifiedError::Sandbox(message.clone()));
            }
            std::fs::create_dir_all(cwd).expect("create controlled runtime workspace");
            let binary_name = cmd
                .get(2)
                .and_then(|script| script.rsplit_once("/work/'"))
                .and_then(|(_, tail)| tail.split_once('\''))
                .map_or_else(
                    || panic!("compile command carries a staged output: {cmd:?}"),
                    |(name, _)| name,
                );
            std::fs::write(cwd.join(binary_name), b"controlled compiled harness")
                .expect("write controlled compiled harness");
        } else if let RuntimeMode::SmokeError(message) = &self.mode {
            return Err(ClassifiedError::Sandbox(message.clone()));
        }
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for ControlledRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.command_result(cmd, cwd)
    }

    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.command_result(cmd, cwd)
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

#[derive(Clone)]
enum ReviewMode {
    Approve,
    Error(String),
}

struct ControlledReviewPool {
    calls: AtomicUsize,
    mode: ReviewMode,
}

impl ControlledReviewPool {
    fn new(mode: ReviewMode) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode,
        }
    }
}

#[async_trait::async_trait]
impl ProviderPool for ControlledReviewPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, ProviderError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        match &self.mode {
            ReviewMode::Approve => Ok(hf_test_utils::fixtures::make_chat_response(
                APPROVING_REVIEW,
            )),
            ReviewMode::Error(message) => Err(ProviderError::Other {
                message: message.clone(),
            }),
        }
    }

    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, ProviderError> {
        Err(ProviderError::Other {
            message: "streaming is unused".to_owned(),
        })
    }

    fn report_error(&self, _provider_id: &hf_core::types::ProviderId, _error: &ProviderError) {}

    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}

    async fn thaw(&self, _provider_id: &hf_core::types::ProviderId) -> Result<(), ProviderError> {
        Ok(())
    }
}

struct QualificationFixture {
    _root: tempfile::TempDir,
    project: PathBuf,
    store: Arc<hf_storage::Store>,
    service: ServiceContainer,
    runtime: Arc<ControlledRuntime>,
    review: Arc<ControlledReviewPool>,
    target_id: Uuid,
    packet: hf_service::HarnessWorkOrder,
    submission: hf_service::HarnessWorkOrderSubmission,
}

impl QualificationFixture {
    async fn new(runtime_mode: RuntimeMode, review_mode: ReviewMode, source: &str) -> Self {
        Self::new_for_target(runtime_mode, review_mode, source, "parse_packet", false).await
    }

    async fn new_for_target(
        runtime_mode: RuntimeMode,
        review_mode: ReviewMode,
        source: &str,
        target: &str,
        duplicate_symbol: bool,
    ) -> Self {
        common::install_managed_workspace("oxfuzz_work_order_qualification_it");
        let root = tempfile::tempdir().expect("create qualification root");
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).expect("create qualification project");
        std::fs::write(
            project.join("parser.c"),
            "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t size) { return size > 0 && data[0]; }\n",
        )
        .expect("write candidate source");
        if duplicate_symbol {
            std::fs::write(
                project.join("alternate.c"),
                "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t size) { return size > 1 && data[1]; }\n",
            )
            .expect("write duplicate-symbol source");
        }
        write_compile_database(&project, "WORK_ORDER=1");
        let store = Arc::new(
            hf_storage::Store::connect(root.path().join("qualification.db"))
                .await
                .expect("create qualification store"),
        );
        let mut candidates = vec![retained_target(&project)];
        if duplicate_symbol {
            candidates.push(retained_target_at(&project, "alternate.c"));
        }
        let target_file = target
            .rsplit_once("::")
            .map_or("parser.c", |(file, _)| file);
        let target_id = candidates
            .iter()
            .find(|candidate| candidate.location.file == Path::new(target_file))
            .expect("selected fixture target exists")
            .id;
        store
            .save_inventory(
                &TargetInventory {
                    project_root: candidates[0].project_root.clone(),
                    candidates,
                    call_graph: std::collections::HashMap::new(),
                },
                Utc::now(),
            )
            .await
            .expect("persist qualification target");
        let runtime = Arc::new(ControlledRuntime::new(runtime_mode));
        let review = Arc::new(ControlledReviewPool::new(review_mode));
        let service = ServiceContainer::new(runtime.clone(), Some(review.clone()))
            .with_store(Arc::clone(&store));
        let packet = service
            .export_harness_work_order(export_request_for_target(&project, target))
            .await
            .expect("export qualification packet");
        let submission = service
            .import_harness_work_order_submission(ImportHarnessWorkOrderSubmissionRequest {
                work_order_id: packet.id.clone(),
                source: source.to_owned(),
                origin: WorkOrderSubmissionOrigin::Human,
                parent_submission_id: None,
            })
            .await
            .expect("import qualification submission");
        Self {
            _root: root,
            project,
            store,
            service,
            runtime,
            review,
            target_id,
            packet,
            submission,
        }
    }

    async fn assert_no_attempt_or_dispatch(&self) {
        assert!(self
            .store
            .list_harness_work_order_attempts(self.submission.id)
            .await
            .expect("list qualification attempts")
            .is_empty());
        assert_eq!(self.runtime.calls.load(Ordering::Relaxed), 0);
        assert_eq!(self.review.calls.load(Ordering::Relaxed), 0);
    }
}

fn retained_target(project: &Path) -> TargetCandidate {
    retained_target_at(project, "parser.c")
}

fn retained_target_at(project: &Path, file: &str) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: std::fs::canonicalize(project).expect("canonicalize project"),
        language: TargetLanguage::C,
        symbol: "parse_packet".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from(file),
            line: 2,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("int parse_packet(const unsigned char *, size_t)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 4,
        fit_score: 0.9,
        sanitizers: Vec::new(),
        rationale: "parses attacker controlled packet bytes".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 4,
    }
}

fn write_compile_database(project: &Path, define: &str) {
    let database = serde_json::json!([{
        "directory": project,
        "file": project.join("parser.c"),
        "arguments": ["cc", format!("-D{define}"), "-std=c11", "-c", "parser.c"],
    }]);
    std::fs::write(
        project.join("compile_commands.json"),
        serde_json::to_vec(&database).expect("serialize compile database"),
    )
    .expect("write compile database");
}

fn export_request_for_target(project: &Path, target: &str) -> HarnessWorkOrderExportRequest {
    HarnessWorkOrderExportRequest {
        project: project.to_path_buf(),
        target: target.to_owned(),
        language: TargetLanguage::C,
        engine: EngineKind::LibFuzzer,
    }
}

async fn install_stage_audit(store: &hf_storage::Store) {
    sqlx::query(
        "CREATE TABLE qualification_stage_audit (
             sequence INTEGER PRIMARY KEY AUTOINCREMENT,
             transition TEXT NOT NULL
         )",
    )
    .execute(store.pool())
    .await
    .expect("create stage audit table");
    sqlx::query(
        "CREATE TRIGGER qualification_stage_audit_trigger
         AFTER UPDATE OF current_stage ON harness_work_order_attempts
         BEGIN
             INSERT INTO qualification_stage_audit (transition)
             VALUES (OLD.current_stage || '->' || NEW.current_stage);
         END",
    )
    .execute(store.pool())
    .await
    .expect("create stage audit trigger");
}

async fn stage_audit(store: &hf_storage::Store) -> Vec<String> {
    sqlx::query_scalar("SELECT transition FROM qualification_stage_audit ORDER BY sequence ASC")
        .fetch_all(store.pool())
        .await
        .expect("load stage audit")
}

#[tokio::test]
async fn qualification_requires_recovered_storage_before_any_dispatch() {
    let runtime = Arc::new(ControlledRuntime::new(RuntimeMode::Pass));
    let service = ServiceContainer::new(runtime.clone(), None);

    let error = service
        .qualify_harness_work_order_submission(Uuid::new_v4())
        .await
        .expect_err("qualification requires durable storage");

    assert_eq!(error.code, HarnessWorkOrderErrorCode::StorageRequired);
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn qualification_rejects_packet_digest_tampering_before_attempt_or_dispatch() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    let mut tampered = fixture.packet.clone();
    tampered.payload.target.rationale.push_str(" tampered");
    sqlx::query("DROP TRIGGER harness_work_orders_immutable")
        .execute(fixture.store.pool())
        .await
        .expect("disable immutability only for corruption fixture");
    sqlx::query("UPDATE harness_work_orders SET packet_json = ?1 WHERE id = ?2")
        .bind(serde_json::to_string(&tampered).expect("serialize tampered packet"))
        .bind(&fixture.packet.id)
        .execute(fixture.store.pool())
        .await
        .expect("inject packet corruption");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("tampered packet must fail preflight");

    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_rejects_unknown_durable_packet_fields_before_dispatch() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    let mut packet = serde_json::to_value(&fixture.packet).expect("serialize packet value");
    packet["payload"]["target"]["unrecognized_evidence"] = serde_json::json!(true);
    sqlx::query("DROP TRIGGER harness_work_orders_immutable")
        .execute(fixture.store.pool())
        .await
        .expect("disable immutability only for corruption fixture");
    sqlx::query("UPDATE harness_work_orders SET packet_json = ?1 WHERE id = ?2")
        .bind(serde_json::to_string(&packet).expect("serialize corrupt packet"))
        .bind(&fixture.packet.id)
        .execute(fixture.store.pool())
        .await
        .expect("inject unknown packet field");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("unknown durable packet fields must be rejected");

    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_rejects_submission_digest_tampering_before_attempt_or_dispatch() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    sqlx::query("DROP TRIGGER harness_work_order_submissions_immutable")
        .execute(fixture.store.pool())
        .await
        .expect("disable immutability only for corruption fixture");
    sqlx::query("UPDATE harness_work_order_submissions SET source_sha256 = ?1 WHERE id = ?2")
        .bind("0".repeat(64))
        .bind(fixture.submission.id.to_string())
        .execute(fixture.store.pool())
        .await
        .expect("inject submission corruption");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("tampered submission must fail preflight");

    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_rejects_unknown_durable_lint_fields_before_dispatch() {
    let warning_harness =
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { signal(1, 0); return size > 0 && data[0]; }";
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, warning_harness).await;
    assert!(!fixture.submission.lint.is_empty());
    sqlx::query("DROP TRIGGER harness_work_order_submissions_immutable")
        .execute(fixture.store.pool())
        .await
        .expect("disable immutability only for corruption fixture");
    sqlx::query(
        "UPDATE harness_work_order_submissions
         SET lint_json = json_set(lint_json, '$[0].unrecognized_evidence', 1)
         WHERE id = ?1",
    )
    .bind(fixture.submission.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject unknown lint field");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("unknown durable lint fields must be rejected");

    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_rejects_changed_candidate_source_before_attempt_or_dispatch() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    std::fs::write(
        fixture.project.join("parser.c"),
        "#include <stddef.h>\nint parse_packet(const unsigned char *data, size_t size) { return size > 1 && data[0]; }\n",
    )
    .expect("change candidate source");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("changed source must make the packet stale");

    assert_eq!(error.code, HarnessWorkOrderErrorCode::StaleWorkOrder);
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_rejects_changed_compile_context_before_attempt_or_dispatch() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    write_compile_database(&fixture.project, "WORK_ORDER=2");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("changed compile context must make the packet stale");

    assert_eq!(error.code, HarnessWorkOrderErrorCode::StaleWorkOrder);
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_rejects_blocking_lint_before_attempt_or_dispatch() {
    let fixture = QualificationFixture::new(
        RuntimeMode::Pass,
        ReviewMode::Approve,
        "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { abort(); }",
    )
    .await;

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("blocking lint must fail preflight");

    assert_eq!(
        error.code,
        HarnessWorkOrderErrorCode::SubmissionHasBlockingLint
    );
    fixture.assert_no_attempt_or_dispatch().await;
}

#[tokio::test]
async fn qualification_success_persists_exact_evidence_without_promotion() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    install_stage_audit(&fixture.store).await;

    let attempt = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect("qualify imported source");

    assert_eq!(attempt.status, HarnessWorkOrderAttemptStatus::SmokePassed);
    assert_eq!(
        attempt.current_stage,
        HarnessWorkOrderAttemptStage::Complete
    );
    assert_eq!(attempt.submission_id, fixture.submission.id);
    let harness_id = attempt.harness_id.expect("compiled harness id");
    let smoke_run_id = attempt.smoke_run_id.expect("smoke run id");
    let result = attempt.result.as_ref().expect("terminal result evidence");
    assert!(result.compiled);
    assert_eq!(result.smoke_verdict, Some(VerdictLevel::Pass));
    assert_eq!(result.repair_depth, 0);
    assert_eq!(result.source_sha256.as_deref().map(str::len), Some(64));
    assert_eq!(result.binary_sha256.as_deref().map(str::len), Some(64));
    assert_eq!(result.execs_per_sec, Some(128.0));
    assert_eq!(result.crashes, Some(0));
    assert!(attempt.failure_code.is_none());
    assert!(attempt.failure_message.is_none());
    assert!(attempt.ended_at.is_some());
    assert_eq!(
        stage_audit(&fixture.store).await,
        vec!["compile->review", "review->smoke", "smoke->complete"]
    );

    let retained = fixture
        .service
        .harness_work_order_attempt(attempt.id)
        .await
        .expect("read retained attempt");
    assert_eq!(retained, attempt);
    assert_eq!(
        fixture
            .service
            .list_harness_work_order_attempts(fixture.submission.id)
            .await
            .expect("list retained attempts"),
        vec![attempt.clone()]
    );
    let raw_result: String =
        sqlx::query_scalar("SELECT result_json FROM harness_work_order_attempts WHERE id = ?1")
            .bind(attempt.id.to_string())
            .fetch_one(fixture.store.pool())
            .await
            .expect("load raw result JSON");
    assert_eq!(
        raw_result,
        serde_json::to_string(result).expect("serialize public result")
    );
    let harness = fixture
        .store
        .get_harness(harness_id)
        .await
        .expect("load harness")
        .expect("qualified harness exists");
    assert_eq!(harness.status, HarnessStatus::SmokePassed);
    assert_eq!(
        harness.smoke_run.as_ref().and_then(|smoke| smoke.run_id),
        Some(smoke_run_id)
    );
    assert_eq!(fixture.runtime.calls.load(Ordering::Relaxed), 2);
    assert_eq!(fixture.review.calls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn qualification_preserves_file_qualified_target_across_every_stage() {
    let fixture = QualificationFixture::new_for_target(
        RuntimeMode::Pass,
        ReviewMode::Approve,
        VALID_HARNESS,
        "alternate.c::parse_packet",
        true,
    )
    .await;
    install_stage_audit(&fixture.store).await;

    let attempt = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect("qualify the retained duplicate-symbol target");

    assert_eq!(attempt.status, HarnessWorkOrderAttemptStatus::SmokePassed);
    assert_eq!(
        stage_audit(&fixture.store).await,
        vec!["compile->review", "review->smoke", "smoke->complete"]
    );
    let harness = fixture
        .store
        .get_harness(attempt.harness_id.expect("qualified harness id"))
        .await
        .expect("load qualified harness")
        .expect("qualified harness exists");
    assert_eq!(harness.target_id, fixture.target_id);
    let workspaces = fixture
        .runtime
        .workspaces
        .lock()
        .expect("lock controlled runtime workspaces");
    assert_eq!(workspaces.len(), 2);
    assert_eq!(workspaces[0], workspaces[1]);
}

#[tokio::test]
async fn qualification_records_nonzero_repair_depth() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    let repaired = fixture
        .service
        .import_harness_work_order_submission(ImportHarnessWorkOrderSubmissionRequest {
            work_order_id: fixture.packet.id.clone(),
            source: VALID_HARNESS.to_owned(),
            origin: WorkOrderSubmissionOrigin::Human,
            parent_submission_id: Some(fixture.submission.id),
        })
        .await
        .expect("import repaired submission");

    let attempt = fixture
        .service
        .qualify_harness_work_order_submission(repaired.id)
        .await
        .expect("qualify repaired submission");

    assert_eq!(
        attempt
            .result
            .as_ref()
            .expect("qualification result")
            .repair_depth,
        1
    );
}

#[tokio::test]
async fn qualification_step_failures_return_terminal_bounded_attempts() {
    let sensitive_detail = format!(
        "compile failed sk-standalone-secret; Authorization: Bearer bearer-secret; path=/Users/operator/private/target.c api_key=key-secret token= adjacent-credential {}\n",
        "x".repeat(6_000)
    );
    let cases = [
        (
            RuntimeMode::CompileError(sensitive_detail),
            ReviewMode::Approve,
            HarnessWorkOrderAttemptStatus::CompileFailed,
            "compile->complete",
            1,
            0,
        ),
        (
            RuntimeMode::Pass,
            ReviewMode::Error("review provider unavailable".to_owned()),
            HarnessWorkOrderAttemptStatus::ReviewFailed,
            "review->complete",
            1,
            1,
        ),
        (
            RuntimeMode::SmokeError("smoke sandbox refused execution".to_owned()),
            ReviewMode::Approve,
            HarnessWorkOrderAttemptStatus::SmokeFailed,
            "smoke->complete",
            2,
            1,
        ),
    ];

    for (runtime_mode, review_mode, status, final_transition, runtime_calls, review_calls) in cases
    {
        let fixture = QualificationFixture::new(runtime_mode, review_mode, VALID_HARNESS).await;
        install_stage_audit(&fixture.store).await;

        let attempt = fixture
            .service
            .qualify_harness_work_order_submission(fixture.submission.id)
            .await
            .expect("step failure is a terminal persisted attempt");

        assert_eq!(attempt.status, status);
        assert_eq!(
            attempt.current_stage,
            HarnessWorkOrderAttemptStage::Complete
        );
        assert!(attempt.ended_at.is_some());
        assert!(attempt
            .failure_code
            .as_ref()
            .is_some_and(|code| { !code.is_empty() && code.len() <= 128 && code.is_ascii() }));
        let message = attempt
            .failure_message
            .as_deref()
            .expect("terminal failure message");
        assert!(!message.is_empty());
        assert!(message.len() <= 4_096);
        assert!(!message.chars().any(char::is_control));
        assert!(!message.contains("sk-standalone-secret"));
        assert!(!message.contains("bearer-secret"));
        assert!(!message.contains("key-secret"));
        assert!(!message.contains("adjacent-credential"));
        assert!(!message.contains("/Users/operator"));
        assert_eq!(
            stage_audit(&fixture.store).await.last().map(String::as_str),
            Some(final_transition)
        );
        assert_eq!(fixture.runtime.calls.load(Ordering::Relaxed), runtime_calls);
        assert_eq!(fixture.review.calls.load(Ordering::Relaxed), review_calls);
        assert_eq!(
            fixture
                .service
                .harness_work_order_attempt(attempt.id)
                .await
                .expect("reload terminal attempt"),
            attempt
        );
        let durable_message: String = sqlx::query_scalar(
            "SELECT failure_message FROM harness_work_order_attempts WHERE id = ?1",
        )
        .bind(attempt.id.to_string())
        .fetch_one(fixture.store.pool())
        .await
        .expect("load durable failure message");
        assert!(!durable_message.contains("sk-standalone-secret"));
        assert!(!durable_message.contains("bearer-secret"));
        assert!(!durable_message.contains("key-secret"));
        assert!(!durable_message.contains("adjacent-credential"));
        assert!(!durable_message.contains("/Users/operator"));
    }
}

#[tokio::test]
async fn qualification_failures_retain_all_available_stage_evidence() {
    let review_fixture = QualificationFixture::new(
        RuntimeMode::Pass,
        ReviewMode::Error("controlled review failure".to_owned()),
        VALID_HARNESS,
    )
    .await;
    let review_attempt = review_fixture
        .service
        .qualify_harness_work_order_submission(review_fixture.submission.id)
        .await
        .expect("review failure is retained");
    assert_eq!(
        review_attempt.status,
        HarnessWorkOrderAttemptStatus::ReviewFailed
    );
    assert!(review_attempt.harness_id.is_some());
    assert!(review_attempt.smoke_run_id.is_none());
    let review_result = review_attempt.result.expect("review failure result");
    assert!(review_result.compiled);
    assert_eq!(
        review_result.source_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert_eq!(
        review_result.binary_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert!(review_result.smoke_verdict.is_none());
    assert!(review_result.execs_per_sec.is_none());
    assert!(review_result.crashes.is_none());

    let smoke_fixture = QualificationFixture::new(
        RuntimeMode::SmokeError("controlled smoke runtime failure".to_owned()),
        ReviewMode::Approve,
        VALID_HARNESS,
    )
    .await;
    let smoke_attempt = smoke_fixture
        .service
        .qualify_harness_work_order_submission(smoke_fixture.submission.id)
        .await
        .expect("smoke failure is retained");
    assert_eq!(
        smoke_attempt.status,
        HarnessWorkOrderAttemptStatus::SmokeFailed
    );
    assert!(smoke_attempt.harness_id.is_some());
    let smoke_run_id = smoke_attempt
        .smoke_run_id
        .expect("allocated smoke run id is retained");
    let smoke_result = smoke_attempt.result.expect("smoke failure result");
    assert!(smoke_result.compiled);
    assert_eq!(
        smoke_result.source_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert_eq!(
        smoke_result.binary_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert!(smoke_result.smoke_verdict.is_none());
    assert!(smoke_result.execs_per_sec.is_none());
    assert!(smoke_result.crashes.is_none());
    assert_eq!(
        smoke_fixture
            .store
            .get_run(smoke_run_id)
            .await
            .expect("load smoke run")
            .expect("allocated smoke run exists")
            .status,
        hf_storage::RunStatus::Failed
    );
}

async fn assert_attempt_corruption_rejected(fixture: &QualificationFixture, attempt_id: Uuid) {
    let get_error = fixture
        .service
        .harness_work_order_attempt(attempt_id)
        .await
        .expect_err("get must reject contradictory attempt evidence");
    assert_eq!(
        get_error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
    let list_error = fixture
        .service
        .list_harness_work_order_attempts(fixture.submission.id)
        .await
        .expect_err("list must reject contradictory attempt evidence");
    assert_eq!(
        list_error.code,
        HarnessWorkOrderErrorCode::InvalidWorkOrderDigest
    );
}

#[tokio::test]
async fn attempt_reads_reject_unknown_and_contradictory_durable_evidence() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    let attempt = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect("create valid attempt");
    let original_result: String =
        sqlx::query_scalar("SELECT result_json FROM harness_work_order_attempts WHERE id = ?1")
            .bind(attempt.id.to_string())
            .fetch_one(fixture.store.pool())
            .await
            .expect("load original result");
    sqlx::query("DROP TRIGGER harness_work_order_attempts_terminal_immutable")
        .execute(fixture.store.pool())
        .await
        .expect("disable terminal immutability only for corruption fixture");

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET result_json = json_set(result_json, '$.unexpected_evidence', 1)
         WHERE id = ?1",
    )
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject unknown result field");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET result_json = json_set(?1, '$.execs_per_sec', -1)
         WHERE id = ?2",
    )
    .bind(&original_result)
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject negative throughput");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET status = 'smoke_failed', result_json = ?1,
             failure_code = 'sandbox', failure_message = 'controlled failure'
         WHERE id = ?2",
    )
    .bind(&original_result)
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject failure status with successful smoke evidence");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET status = 'smoke_passed', result_json = ?1,
             failure_code = NULL, failure_message = NULL, harness_id = NULL
         WHERE id = ?2",
    )
    .bind(&original_result)
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("remove required harness id");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET harness_id = ?1, ended_at = started_at
         WHERE id = ?2",
    )
    .bind(attempt.harness_id.expect("valid harness id").to_string())
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject contradictory terminal timestamp");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET ended_at = updated_at, smoke_run_id = NULL
         WHERE id = ?1",
    )
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("remove required smoke run id");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET smoke_run_id = ?1,
             result_json = json_set(?2, '$.crashes', NULL)
         WHERE id = ?3",
    )
    .bind(
        attempt
            .smoke_run_id
            .expect("valid smoke run id")
            .to_string(),
    )
    .bind(&original_result)
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("remove required crash evidence");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query(
        "UPDATE harness_work_order_attempts
         SET result_json = json_set(?1, '$.repair_depth', ?2)
         WHERE id = ?3",
    )
    .bind(&original_result)
    .bind(hf_storage::MAX_WORK_ORDER_SUBMISSIONS)
    .bind(attempt.id.to_string())
    .execute(fixture.store.pool())
    .await
    .expect("inject out-of-range repair depth");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;

    sqlx::query("UPDATE harness_work_order_attempts SET result_json = NULL WHERE id = ?1")
        .bind(attempt.id.to_string())
        .execute(fixture.store.pool())
        .await
        .expect("remove required terminal result");
    assert_attempt_corruption_rejected(&fixture, attempt.id).await;
}

#[tokio::test]
async fn qualification_transition_storage_failure_is_not_a_stage_failure() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    sqlx::query(
        "CREATE TRIGGER reject_qualification_transition
         BEFORE UPDATE OF current_stage ON harness_work_order_attempts
         WHEN OLD.current_stage = 'compile' AND NEW.current_stage = 'review'
         BEGIN
             SELECT RAISE(ABORT, 'controlled transition failure');
         END",
    )
    .execute(fixture.store.pool())
    .await
    .expect("install controlled transition failure");

    let error = fixture
        .service
        .qualify_harness_work_order_submission(fixture.submission.id)
        .await
        .expect_err("transition storage failure must remain a service error");

    assert_eq!(error.code, HarnessWorkOrderErrorCode::StorageRequired);
    let attempts = fixture
        .store
        .list_harness_work_order_attempts(fixture.submission.id)
        .await
        .expect("load interrupted transition attempt");
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].status, HarnessWorkOrderAttemptStatus::Running);
    assert_eq!(
        attempts[0].current_stage,
        HarnessWorkOrderAttemptStage::Compile
    );
    assert!(attempts[0].failure_code.is_none());
    assert_eq!(fixture.runtime.calls.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.review.calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn interrupted_attempt_recovery_preserves_identity_and_start_time() {
    let fixture =
        QualificationFixture::new(RuntimeMode::Pass, ReviewMode::Approve, VALID_HARNESS).await;
    let started_at = Utc::now();
    let attempt_id = Uuid::new_v4();
    fixture
        .store
        .insert_harness_work_order_attempt(&hf_storage::HarnessWorkOrderAttemptRecord {
            id: attempt_id,
            submission_id: fixture.submission.id,
            status: HarnessWorkOrderAttemptStatus::Running,
            current_stage: HarnessWorkOrderAttemptStage::Compile,
            harness_id: None,
            smoke_run_id: None,
            result_json: None,
            failure_code: None,
            failure_message: None,
            started_at,
            updated_at: started_at,
            ended_at: None,
        })
        .await
        .expect("insert interrupted attempt fixture");

    assert_eq!(
        fixture
            .store
            .recover_interrupted_harness_work_order_attempts(Utc::now())
            .await
            .expect("run startup recovery"),
        1
    );
    let recovered = fixture
        .service
        .harness_work_order_attempt(attempt_id)
        .await
        .expect("read recovered attempt");

    assert_eq!(recovered.id, attempt_id);
    assert_eq!(recovered.started_at, started_at);
    assert_eq!(recovered.status, HarnessWorkOrderAttemptStatus::Interrupted);
    assert_eq!(
        recovered.current_stage,
        HarnessWorkOrderAttemptStage::Complete
    );
    assert_eq!(
        recovered.failure_code.as_deref(),
        Some("attempt_interrupted")
    );
    assert!(recovered.ended_at.is_some());
}
