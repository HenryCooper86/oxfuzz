//! Integration coverage for the deployment-wide LLM-review bypass
//! (`harness.allow_unreviewed_smoke = true`).
//!
//! Separate from `harness_review_bypass.rs` because `HF_CONFIG_DIR` is
//! process-global and this file's fixture arms the config opt-in while that
//! file's fixture must prove the default denies it.

mod common;

use std::path::Path;
use std::sync::Arc;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

const SOURCE: &str = "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }";

struct QualifyingRuntime;

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
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
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
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64);
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
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: hf_core::runtime::CommandTermination::Completed,
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        Ok(std::fs::read_to_string(path).unwrap_or_default())
    }
}

#[tokio::test]
async fn the_config_opt_in_permits_smoke_without_a_provider_or_flag() {
    common::install_managed_workspace("oxfuzz_review_bypass_config_it");
    let project = tempfile::tempdir().unwrap();
    let config = project.path().join("config");
    std::env::set_var("HF_CONFIG_DIR", &config);
    hf_service::config::write_config(
        "oxfuzz",
        "[fuzzing]\ncollect_function_coverage = true\n\
         enabled_engines = [\"libfuzzer\", \"afl++\", \"honggfuzz\", \"syzkaller\"]\n\
         default_engine = \"libfuzzer\"\ndefault_duration_secs = 60\n\
         [fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 600\n\
         [harness]\nallow_unreviewed_smoke = true\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("parse.c"),
        "#include <stddef.h>\nint parse_entry(const unsigned char *data, size_t size) { return size && data[0]; }\n",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(project.path().join("bypass.db"))
            .await
            .unwrap(),
    );
    // No provider pool: the deployment config is the only opt-in in play.
    let container =
        ServiceContainer::new(Arc::new(QualifyingRuntime), None).with_store(Arc::clone(&store));
    container
        .harness_compile(
            SOURCE.to_owned(),
            project.path(),
            EngineKind::LibFuzzer,
            "parse_entry",
            TargetLanguage::C,
            None,
        )
        .await
        .unwrap();

    let smoke = container
        .harness_smoke(
            project.path(),
            "parse_entry",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect("the deployment config opt-in permits smoke without a provider");
    assert!(smoke.summary.passed);

    let mut harnesses = store.list_all_harnesses().await.unwrap();
    let harness_id = harnesses.pop().expect("the fixture compiled a harness").id;
    let record = store
        .harness_ai_review(harness_id)
        .await
        .unwrap()
        .expect("the config bypass persists a marked review record");
    let evidence: serde_json::Value = serde_json::from_str(&record.review_json).unwrap();
    assert_eq!(evidence["verdict"], "bypassed");
    assert_eq!(evidence["reviewer"], "none");
    assert_eq!(evidence["bypass_source"], "config");

    let decisions = container.policy_decisions(20).await.unwrap();
    let audit = decisions
        .iter()
        .find(|row| row.action == "harness_llm_review_bypass")
        .expect("the config bypass is audited like the flag bypass");
    assert!(
        audit
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("allow_unreviewed_smoke")),
        "{audit:?}"
    );
}
