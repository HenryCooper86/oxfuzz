//! Fail-closed policy preflight for engine-backed maintenance operations.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_service::ServiceContainer;

#[derive(Default)]
struct CountingRuntime {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RuntimeAdapter for CountingRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn disabled_auxiliary_engines_fail_before_workspace_or_runtime_activity() {
    let root = tempfile::tempdir().unwrap();
    let config_dir = root.path().join("config");
    let workspace_root = root.path().join("workspace");
    std::env::set_var("HF_CONFIG_DIR", &config_dir);
    std::env::set_var("HF_WORKSPACE_DIR", &workspace_root);
    hf_service::config::write_config(
        "oxfuzz",
        r#"
[fuzzing]
enabled_engines = ["honggfuzz"]
default_engine = "honggfuzz"
default_duration_secs = 60

[fuzzing.sandbox]
max_mem_mb = 1024
max_cpus = 1
max_duration_secs = 7200
"#,
    )
    .unwrap();

    let runtime = Arc::new(CountingRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None);
    let project = root.path().join("project-that-does-not-exist");

    let coverage_error = container
        .corpus_prune_coverage(&project, "parse_afl")
        .await
        .expect_err("disabled AFL++ must fail before corpus access");
    let minimize_error = container
        .corpus_minimize(&project, "parse_libfuzzer")
        .await
        .expect_err("disabled libFuzzer must fail before corpus access");

    assert!(coverage_error.to_string().contains("afl++"));
    assert!(coverage_error.to_string().contains("disabled"));
    assert!(minimize_error.to_string().contains("libfuzzer"));
    assert!(minimize_error.to_string().contains("disabled"));
    assert_eq!(runtime.calls.load(Ordering::Relaxed), 0);
    assert!(
        !workspace_root.exists(),
        "policy rejection must precede workspace preparation"
    );
}
