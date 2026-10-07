//! Integration coverage for the persisted harness qualification lifecycle.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::harness::HarnessStatus;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;
use sha2::Digest as _;

const APPROVING_REVIEW: &str = r#"{"exercises_target":true,"safe_to_execute":true,"reasons":["target receives fuzz input without unsafe side effects"]}"#;

struct FixedReviewPool {
    response: &'static str,
    tamper_binary: Option<PathBuf>,
}

impl FixedReviewPool {
    fn new(response: &'static str) -> Self {
        Self {
            response,
            tamper_binary: None,
        }
    }

    fn tampering(response: &'static str, binary: PathBuf) -> Self {
        Self {
            response,
            tamper_binary: Some(binary),
        }
    }
}

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for FixedReviewPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        if let Some(binary) = &self.tamper_binary {
            std::fs::write(binary, b"substituted while review was in flight").unwrap();
        }
        Ok(hf_test_utils::fixtures::make_chat_response(self.response))
    }

    async fn chat_completion_stream(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatStreamResponse, hf_core::provider::ProviderError> {
        Err(hf_core::provider::ProviderError::Other {
            message: "unused".to_owned(),
        })
    }

    fn report_error(
        &self,
        _provider_id: &hf_core::types::ProviderId,
        _error: &hf_core::provider::ProviderError,
    ) {
    }

    async fn provider_statuses(&self) -> Vec<hf_core::provider::ProviderStatus> {
        Vec::new()
    }

    async fn freeze(&self, _provider_id: &hf_core::types::ProviderId, _reason: String) {}

    async fn thaw(
        &self,
        _provider_id: &hf_core::types::ProviderId,
    ) -> Result<(), hf_core::provider::ProviderError> {
        Ok(())
    }
}

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_qualification_it");
}

struct QualifyingRuntime {
    /// Entry count the double reports for the target, so a test can ask for a
    /// measured miss instead of a measured entry.
    entry_count: u64,
}

#[async_trait::async_trait]
impl RuntimeAdapter for QualifyingRuntime {
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
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        // Leave the host-side artifacts the real collection path reads, so this
        // double exercises collection instead of bypassing it.
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, self.entry_count);
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_entry"), b"mock compiled harness").unwrap();
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        // The profiling tooling names container paths, so its host targets come
        // from the mounts rather than from the working directory.
        hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(
            cmd,
            opts,
            "parse_entry",
            self.entry_count,
        );
        self.run_command_streaming(cmd, cwd, limits, cancel, on_line)
            .await
    }

    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
        _cancel: &tokio_util::sync::CancellationToken,
        _on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, hf_core::error::ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, self.entry_count);
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        path: &Path,
        content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

async fn qualified_fixture() -> (tempfile::TempDir, Arc<hf_storage::Store>, ServiceContainer) {
    qualified_fixture_with_entry_count(64).await
}

/// The same fixture, reporting `entry_count` entries of the selected target.
async fn qualified_fixture_with_entry_count(
    entry_count: u64,
) -> (tempfile::TempDir, Arc<hf_storage::Store>, ServiceContainer) {
    isolate_workspace();
    let project = tempfile::tempdir().unwrap();
    // Own the config directory: which settings are in force decides whether a
    // harness is instrumented at all, so a fixture reading the ambient config
    // changes behaviour with the developer's checkout. Collection is on here
    // because the qualification profile is what promotion reads.
    let config = project.path().join("config");
    std::env::set_var("HF_CONFIG_DIR", &config);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\ncollect_function_coverage = true\n\
         enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\", \"syzkaller\"]\n\
         default_engine = \"libfuzzer\"\ndefault_duration_secs = 60\n\
         [fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 600\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("qualification.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(
        Arc::new(QualifyingRuntime { entry_count }),
        Some(Arc::new(FixedReviewPool::new(APPROVING_REVIEW))),
    )
    .with_store(Arc::clone(&store));
    (project, store, container)
}

#[tokio::test]
async fn smoke_without_a_required_llm_review_is_refused() {
    let (project, store, _approved_container) = qualified_fixture().await;
    let container = ServiceContainer::new(Arc::new(QualifyingRuntime { entry_count: 64 }), None)
        .with_store(store);
    let source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";
    container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let error = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect_err("generated harness execution requires LLM review");
    assert!(error.to_string().contains("LLM review"), "{error}");
}

#[tokio::test]
async fn negative_llm_review_is_persisted_and_prevents_smoke_execution() {
    let (project, store, container) = qualified_fixture().await;
    let container = container.with_provider_pool(Arc::new(FixedReviewPool::new(
        r#"{"exercises_target":true,"safe_to_execute":false,"reasons":["starts an unrelated process"]}"#,
    )));
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let error = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect_err("negative review must stop execution");
    assert!(error.to_string().contains("LLM review refused"), "{error}");
    assert!(store.list_runs(None).await.unwrap().is_empty());
    let harness = store.list_all_harnesses().await.unwrap().pop().unwrap();
    let review = store
        .harness_ai_review(harness.id)
        .await
        .unwrap()
        .expect("negative decision remains auditable");
    assert_eq!(
        review.source_sha256,
        hex::encode(sha2::Sha256::digest(harness.source.as_bytes()))
    );
    assert!(review.review_json.contains("starts an unrelated process"));
}

#[tokio::test]
async fn malformed_llm_review_fails_closed_before_smoke_execution() {
    let (project, store, container) = qualified_fixture().await;
    let container = container.with_provider_pool(Arc::new(FixedReviewPool::new("approved")));
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let error = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect_err("malformed review must stop execution");
    assert!(error.to_string().contains("malformed JSON"), "{error}");
    assert!(store.list_runs(None).await.unwrap().is_empty());
    let harness = store.list_all_harnesses().await.unwrap().pop().unwrap();
    assert!(store.harness_ai_review(harness.id).await.unwrap().is_none());
}

#[tokio::test]
async fn binary_substitution_during_llm_review_is_refused_before_execution() {
    let (project, store, container) = qualified_fixture().await;
    let binary = hf_service::workspace_dir(project.path(), "parse_entry").join("fuzz_parse_entry");
    let container = container.with_provider_pool(Arc::new(FixedReviewPool::tampering(
        APPROVING_REVIEW,
        binary,
    )));
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let error = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect_err("the reviewed source must remain bound to its compiled binary");
    assert!(error.to_string().contains("binary digest"), "{error}");
    assert!(store.list_runs(None).await.unwrap().is_empty());
}

#[tokio::test]
async fn smoke_updates_the_compiled_revision_and_promotion_is_explicit() {
    let (project, store, container) = qualified_fixture().await;
    let source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

    let compiled = container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let project_root = std::fs::canonicalize(project.path()).unwrap();
    let targets = store
        .list_targets(&project_root.to_string_lossy())
        .await
        .unwrap();
    let target = targets.iter().find(|t| t.symbol == "parse_entry").unwrap();
    let before = store.list_harnesses(target.id).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].status, HarnessStatus::Compiled);
    let harness_id = before[0].id;
    assert_eq!(compiled.harness_id, harness_id);

    let premature = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await;
    assert!(
        premature.is_err(),
        "compiled-only harness must not be promoted"
    );

    let smoke = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert!(smoke.summary.passed);

    let smoked = store.get_harness(harness_id).await.unwrap().unwrap();
    assert_eq!(smoked.status, HarnessStatus::SmokePassed);
    assert!(smoked.smoke_run.as_ref().is_some_and(|run| run.passed));

    let smoke_runs = store
        .list_runs(Some(&project_root.to_string_lossy()))
        .await
        .unwrap();
    assert_eq!(smoke_runs.len(), 1);
    let smoke_config = smoke_runs[0]
        .config
        .as_ref()
        .expect("a smoke run must remain attributable to its harness and target");
    assert_eq!(smoke_config.harness_id, harness_id);
    assert_eq!(smoke_config.engine, EngineKind::LibFuzzer);
    assert_eq!(
        smoke_config.duration,
        Some(std::time::Duration::from_mins(1))
    );
    assert_eq!(smoke_runs[0].harness_rev.as_deref().map(str::len), Some(64));
    assert_eq!(smoke_runs[0].binary_rev.as_deref().map(str::len), Some(64));
    let qualification = smoked.smoke_run.as_ref().unwrap();
    assert_eq!(
        qualification.source_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert_eq!(
        qualification.binary_sha256.as_deref().map(str::len),
        Some(64)
    );
    assert_eq!(qualification.run_id, Some(smoke_runs[0].id));
    let evidence = smoke_runs[0]
        .evidence_dir
        .as_deref()
        .expect("smoke output is run-scoped");
    assert!(evidence.starts_with("runs/"));
    assert!(evidence.ends_with("/out"));

    let promoted = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();
    assert_eq!(promoted.id, harness_id);
    assert_eq!(promoted.status, HarnessStatus::Promoted);
    assert_eq!(
        store.get_harness(harness_id).await.unwrap().unwrap().status,
        HarnessStatus::Promoted
    );
}

#[tokio::test]
async fn promotion_is_refused_when_the_smoke_profile_never_entered_the_target() {
    // A measured run that never entered the target: it burned cycles without
    // fuzzing anything, which is the failure the gate exists to catch.
    let (project, _store, container) = qualified_fixture_with_entry_count(0).await;
    let source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

    container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let refused = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await;
    let error = refused.expect_err("a harness that never entered the target must not promote");
    assert!(error.to_string().contains("parse_entry"), "{error}");
}

#[tokio::test]
async fn promotion_succeeds_when_the_smoke_profile_entered_the_target() {
    let (project, _store, container) = qualified_fixture_with_entry_count(37).await;
    let source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

    container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let promoted = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .expect("positive target entry must promote");
    assert_eq!(promoted.status, HarnessStatus::Promoted);
}

/// The fixture's only run is the smoke run under qualification.
async fn sole_smoke_run(store: &hf_storage::Store, project: &Path) -> hf_storage::RunRecord {
    let project_root = std::fs::canonicalize(project).unwrap();
    let runs = store
        .list_runs(Some(&project_root.to_string_lossy()))
        .await
        .unwrap();
    assert_eq!(runs.len(), 1, "the fixture records exactly one smoke run");
    runs.into_iter().next().unwrap()
}

#[tokio::test]
async fn promotion_rejects_a_binary_changed_after_smoke_qualification() {
    let (project, _store, container) = qualified_fixture().await;
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    std::fs::write(workspace.join("fuzz_parse_entry"), b"tampered after smoke").unwrap();
    let error = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .expect_err("promotion must bind the exact smoke-tested executable");
    assert!(
        error.to_string().contains("digest"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn campaign_rejects_a_binary_changed_after_promotion() {
    let (project, _store, container) = qualified_fixture().await;
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();

    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    std::fs::write(
        workspace.join("fuzz_parse_entry"),
        b"tampered after promotion",
    )
    .unwrap();
    let error = container
        .run_fuzzer(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            60,
            None,
            &|_| {},
        )
        .await
        .expect_err("campaign must bind the exact promoted executable");
    assert!(
        error.to_string().contains("digest"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn legacy_promoted_harness_can_be_requalified_and_requires_reapproval() {
    let (project, store, container) = qualified_fixture().await;
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    let mut promoted = container
        .harness_promote(project.path(), "parse_entry", EngineKind::LibFuzzer)
        .await
        .unwrap();
    let smoke = promoted.smoke_run.as_mut().unwrap();
    smoke.source_sha256 = None;
    smoke.binary_sha256 = None;
    smoke.run_id = None;
    store.upsert_harness(&promoted).await.unwrap();

    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("legacy promoted revisions need a requalification path");

    let refreshed = store.get_harness(promoted.id).await.unwrap().unwrap();
    assert_eq!(refreshed.status, HarnessStatus::SmokePassed);
    let evidence = refreshed.smoke_run.unwrap();
    assert!(evidence.source_sha256.is_some());
    assert!(evidence.binary_sha256.is_some());
    assert!(evidence.run_id.is_some());
}

#[tokio::test]
async fn campaign_run_rejects_an_unpromoted_active_revision() {
    let (project, _store, container) = qualified_fixture().await;
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    std::fs::write(workspace.join("fuzz_parse_entry"), b"sandbox binary marker").unwrap();

    let error = container
        .run_fuzzer(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            60,
            None,
            &|_| {},
        )
        .await
        .expect_err("a compiled-only harness must not start a campaign");
    assert!(
        error.to_string().contains("promot"),
        "error should direct the operator to promotion: {error}"
    );
}

#[tokio::test]
async fn corpus_records_keep_the_persisted_rust_target_identity() {
    use chrono::Utc;
    use hf_core::target::{InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind};
    use uuid::Uuid;

    let (project, store, container) = qualified_fixture().await;
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.path().to_path_buf(),
        language: TargetLanguage::Rust,
        symbol: "parse_rust".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: project.path().join("src/lib.rs"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("fn parse_rust(data: &[u8])".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 4,
        fit_score: 0.9,
        sanitizers: vec![Sanitizer::Address],
        rationale: "persisted Rust target".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 4,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();

    assert_eq!(
        container
            .corpus_seed(project.path(), "parse_rust")
            .await
            .unwrap(),
        2
    );
    assert_eq!(store.list_corpus_entries(target.id).await.unwrap().len(), 2);
    assert!(store
        .list_corpus_entries(Uuid::nil())
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn unsupported_harness_languages_fail_before_the_compiler() {
    let (project, _store, container) = qualified_fixture().await;
    for language in [TargetLanguage::Go, TargetLanguage::Python] {
        let error = container
            .harness_compile(
                "unsupported harness".to_owned(),
                project.path(),
                EngineKind::LibFuzzer,
                "parse_entry",
                language,
            )
            .await
            .expect_err("unsupported harness language must fail closed");
        assert!(error.to_string().contains("not supported"));
    }
}

#[tokio::test]
async fn a_smoke_run_requests_a_profile_it_can_actually_retain() {
    let (project, store, container) = qualified_fixture().await;
    let source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

    container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let run = sole_smoke_run(&store, project.path()).await;
    let config = run.config.as_ref().expect("a smoke run retains its config");
    let harness = store
        .get_harness(config.harness_id)
        .await
        .unwrap()
        .expect("the smoke run names its harness");

    // Whether collection is on is deployment configuration, and this fixture
    // resolves the ambient config, so the path logic is pinned by unit tests in
    // `function_coverage::relocation_tests` instead. What is asserted here is
    // the part that must hold either way: the qualification run leaves a
    // writable directory for a profile inside its own run-scoped output.
    //
    // Producing the record itself needs the profiling toolchain, so a stub
    // runtime cannot close that link; the acceptance records cover it.
    let _ = harness;
    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    let raw = workspace
        .join(run.evidence_dir.as_deref().expect("runs are run-scoped"))
        .join("function-coverage/raw");
    assert!(
        raw.is_dir(),
        "the profile directory must exist before the run: llvm creates the file, not its parents"
    );
}

#[tokio::test]
async fn a_smoke_run_retains_the_profile_promotion_reads() {
    let (project, store, container) = qualified_fixture().await;
    let source = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

    container
        .harness_compile(
            source.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();

    // The whole point of the qualification profile: promotion reads it, and
    // before this existed nothing ever wrote one for a smoke run, so the
    // target-entry gate could not fire.
    let run = sole_smoke_run(&store, project.path()).await;

    // Localise the layer before asserting the outcome: an uninstrumented harness
    // and an unwritten profile both end as the same unavailable measurement.
    let config = run.config.as_ref().expect("a smoke run retains its config");
    let harness = store
        .get_harness(config.harness_id)
        .await
        .unwrap()
        .expect("the smoke run names its harness");
    assert!(
        harness
            .build_cmd
            .extra_flags
            .iter()
            .any(|flag| flag == "-fprofile-instr-generate"),
        "layer 1, instrumentation: {:?}",
        harness.build_cmd.extra_flags
    );
    assert!(
        config.env.iter().any(|(key, _)| key == "LLVM_PROFILE_FILE"),
        "layer 2, run does not ask for a profile: {:?}",
        config.env
    );

    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    let raw = workspace
        .join(run.evidence_dir.as_deref().expect("runs are run-scoped"))
        .join("function-coverage/raw");
    assert!(
        std::fs::read_dir(&raw)
            .map(|entries| entries.count() > 0)
            .unwrap_or(false),
        "layer 3, no raw profile reached the host at {}",
        raw.display()
    );

    let coverage = container
        .run_function_coverage(run.id)
        .await
        .expect("reading the qualification profile must not fail");
    let hf_service::RunFunctionCoverage::Available { functions, .. } = coverage else {
        panic!("a qualification run must retain the profile promotion reads: {coverage:?}");
    };
    assert!(
        functions
            .iter()
            .any(|function| function.name == "parse_entry" && function.count != "0"),
        "the retained profile must attribute entry to the selected target: {functions:?}"
    );
}
