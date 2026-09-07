//! Integration test for the harness compile-and-repair loop
//! (`ServiceContainer::harness_generate`).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

fn isolate_workspace() {
    common::install_managed_workspace("oxfuzz_repair_it");
}

/// A runtime whose compile command fails (`exit 1`) for the first
/// `fail_first` invocations, then succeeds. Lets the test drive one repair.
struct FlakyCompileRuntime {
    fail_first: usize,
    calls: AtomicUsize,
    replace_database: Option<std::path::PathBuf>,
}

#[async_trait::async_trait]
impl hf_core::runtime::RuntimeAdapter for FlakyCompileRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, hf_core::error::ClassifiedError>
    {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<hf_core::runtime::CommandResult, hf_core::error::ClassifiedError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        let exit_code = i32::from(n < self.fail_first);
        if n == 0 {
            if let Some(project) = &self.replace_database {
                std::fs::write(project.join("compile_commands.json"),serde_json::to_vec(&serde_json::json!([{"directory":project,"file":"parse.c","arguments":["cc","-DREPAIRED=1","-c","parse.c"]}])).unwrap()).unwrap();
            }
        }
        Ok(hf_core::runtime::CommandResult {
            exit_code,
            stdout: String::new(),
            stderr: if exit_code == 0 {
                String::new()
            } else {
                "harness.c:2:5: error: implicit declaration of function 'frob'".to_owned()
            },
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), hf_core::error::ClassifiedError> {
        Ok(())
    }

    async fn read_file(
        &self,
        _path: &std::path::Path,
    ) -> Result<String, hf_core::error::ClassifiedError> {
        Ok(String::new())
    }
}

/// A pool that returns a valid fenced C harness for every completion, so both
/// the initial draft and any repair yield extractable source.
struct CodeBlockPool;

#[async_trait::async_trait]
impl hf_core::provider::ProviderPool for CodeBlockPool {
    async fn chat_completion(
        &self,
        _request: &hf_core::provider::ChatRequest,
        _route: &hf_core::provider::RouteRequest,
    ) -> Result<hf_core::provider::ChatResponse, hf_core::provider::ProviderError> {
        Ok(hf_test_utils::fixtures::make_chat_response(
            "```c\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){ return 0; }\n```",
        ))
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

fn write_sample_project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("parse.c"),
        "#include <stddef.h>\n#include <stdint.h>\n\
         int parse_entry(const uint8_t *data, size_t size) {\n\
         \x20 if (size > 0 && data[0] == 'A') { return 1; }\n\
         \x20 return 0;\n}\n",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn harness_generate_repairs_a_failing_compile() {
    isolate_workspace();
    let project = write_sample_project();

    let runtime = Arc::new(FlakyCompileRuntime {
        fail_first: 1,
        calls: AtomicUsize::new(0),
        replace_database: None,
    });
    let container =
        ServiceContainer::new(runtime, Some(Arc::new(CodeBlockPool))).with_store(Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        ));

    let outcome = container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            2,
        )
        .await
        .expect("harness_generate should recover via repair");

    // First compile failed, one repair pass fixed it.
    assert_eq!(outcome.repairs_used, 1, "expected exactly one repair pass");
    assert_eq!(outcome.status, hf_core::harness::HarnessStatus::Compiled);
    assert_eq!(outcome.binary_name, "fuzz_parse_entry");
}

#[tokio::test]
async fn harness_generate_gives_up_after_max_repairs() {
    isolate_workspace();
    let project = write_sample_project();

    // Compile always fails; with max_repairs=1 that is 2 attempts, then error.
    let runtime = Arc::new(FlakyCompileRuntime {
        fail_first: usize::MAX,
        calls: AtomicUsize::new(0),
        replace_database: None,
    });
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(Arc::new(
            hf_storage::Store::connect(project.path().join("state.db"))
                .await
                .unwrap(),
        ));

    let err = container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        )
        .await;
    assert!(err.is_err(), "should fail after exhausting repairs");
    // 1 initial + 1 repair attempt = 2 compile invocations.
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 2);
    assert!(container
        .store()
        .unwrap()
        .list_all_harnesses()
        .await
        .unwrap()
        .is_empty());
    let inputs: i64 = sqlx::query_scalar("SELECT count(*) FROM harness_build_inputs")
        .fetch_one(container.store().unwrap().pool())
        .await
        .unwrap();
    assert_eq!(inputs, 0);
}

#[tokio::test]
async fn failed_compile_does_not_replace_the_active_harness_revision() {
    isolate_workspace();
    let project = write_sample_project();
    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    std::fs::create_dir_all(&workspace).unwrap();
    std::fs::write(workspace.join("harness.source"), "last known good source").unwrap();

    let runtime = Arc::new(FlakyCompileRuntime {
        fail_first: usize::MAX,
        calls: AtomicUsize::new(0),
        replace_database: None,
    });
    let container = ServiceContainer::new(runtime, None).with_store(Arc::new(
        hf_storage::Store::connect(project.path().join("state.db"))
            .await
            .unwrap(),
    ));

    let result = container
        .harness_compile(
            "regressed source".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await;

    assert!(result.is_err());
    assert_eq!(
        std::fs::read_to_string(workspace.join("harness.source")).unwrap(),
        "last known good source"
    );
}

#[tokio::test]
async fn successful_compile_commits_the_active_harness_revision() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = Arc::new(FlakyCompileRuntime {
        fail_first: 0,
        calls: AtomicUsize::new(0),
        replace_database: None,
    });
    let container = ServiceContainer::new(runtime, None).with_store(Arc::new(
        hf_storage::Store::connect(project.path().join("state.db"))
            .await
            .unwrap(),
    ));

    container
        .harness_compile(
            "new active source".to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await
        .expect("compile should succeed");

    let workspace = hf_service::workspace_dir(project.path(), "parse_entry");
    assert_eq!(
        std::fs::read_to_string(workspace.join("harness.source")).unwrap(),
        "new active source"
    );
}

#[tokio::test]
async fn new_compilation_requires_store_before_runtime_or_provider() {
    isolate_workspace();
    let project = write_sample_project();
    let runtime = Arc::new(FlakyCompileRuntime {
        fail_first: 0,
        calls: AtomicUsize::new(0),
        replace_database: None,
    });
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)));
    let compile = container
        .harness_compile(
            "new source".into(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
        )
        .await;
    assert!(compile
        .unwrap_err()
        .to_string()
        .contains("persistent service store"));
    let generated = container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            0,
        )
        .await;
    assert!(generated
        .unwrap_err()
        .to_string()
        .contains("persistent service store"));
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "build-context")]
#[tokio::test]
async fn repair_success_records_only_the_successful_attempts_fresh_database_flags() {
    use sha2::Digest;
    isolate_workspace();
    let project = write_sample_project();
    std::fs::write(project.path().join("compile_commands.json"),serde_json::to_vec(&serde_json::json!([{"directory":project.path(),"file":"parse.c","arguments":["cc","-DORIGINAL=1","-c","parse.c"]}])).unwrap()).unwrap();
    let runtime = Arc::new(FlakyCompileRuntime {
        fail_first: 1,
        calls: AtomicUsize::new(0),
        replace_database: Some(project.path().to_path_buf()),
    });
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("state.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(runtime.clone(), Some(Arc::new(CodeBlockPool)))
        .with_store(store.clone());
    let outcome = container
        .harness_generate(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
            1,
        )
        .await
        .unwrap();
    assert_eq!(outcome.repairs_used, 1);
    assert_eq!(runtime.calls.load(Ordering::SeqCst), 2);
    let harnesses = store.list_all_harnesses().await.unwrap();
    assert_eq!(harnesses.len(), 1);
    let inputs = store
        .harness_build_inputs(harnesses[0].id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        inputs.compile_flags_sha256,
        format!("{:x}", sha2::Sha256::digest(br#"["-DREPAIRED=1"]"#))
    );
    assert_eq!(
        inputs.compile_database_sha256,
        Some(format!(
            "{:x}",
            sha2::Sha256::digest(
                std::fs::read(project.path().join("compile_commands.json")).unwrap()
            )
        ))
    );
    assert_eq!(harnesses[0].build_cmd.extra_flags, vec!["-DREPAIRED=1"]);
}
