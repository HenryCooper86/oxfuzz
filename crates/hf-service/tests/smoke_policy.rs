//! Service-owned fuzzing policy contract for smoke qualification.

use std::path::Path;
use std::sync::{Arc, Mutex};

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

#[derive(Default)]
struct SmokePolicyRuntime {
    calls: Mutex<Vec<(Vec<String>, ResourceLimits)>>,
}

#[async_trait::async_trait]
impl RuntimeAdapter for SmokePolicyRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        std::fs::create_dir_all(cwd).unwrap();
        std::fs::write(cwd.join("fuzz_parse_policy"), b"mock compiled harness").unwrap();
        self.calls
            .lock()
            .unwrap()
            .push((cmd.to_vec(), limits.clone()));
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE cov: 12 ft: 24 corp: 2/8b exec/s: 128".to_owned(),
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

fn write_policy(max_duration_secs: u64, max_mem_mb: u64, max_cpus: u32) {
    hf_service::config::write_config(
        "hobot-fuzz",
        &format!(
            r#"
[fuzzing]
enabled_engines = ["libfuzzer"]
default_engine = "libfuzzer"
default_duration_secs = 30

[fuzzing.sandbox]
max_mem_mb = {max_mem_mb}
max_cpus = {max_cpus}
max_duration_secs = {max_duration_secs}
"#
        ),
    )
    .unwrap();
}

#[tokio::test]
async fn smoke_policy_is_enforced_before_reservation_and_drives_runtime_and_persistence() {
    let root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path().join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.path().join("workspace"));
    write_policy(30, 1024, 1);

    let project = root.path().join("project");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(
        project.join("parse.c"),
        "int parse_policy(const unsigned char *data, unsigned long size) { return size && data[0]; }",
    )
    .unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(root.path().join("policy.db"))
            .await
            .unwrap(),
    );
    let runtime = Arc::new(SmokePolicyRuntime::default());
    let container = ServiceContainer::new(runtime.clone(), None).with_store(Arc::clone(&store));
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            EngineKind::LibFuzzer,
            "parse_policy",
            TargetLanguage::C,
        )
        .await
        .unwrap();

    let rejected = container
        .harness_smoke(
            &project,
            "parse_policy",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .expect_err("the fixed 60-second smoke request must respect the policy ceiling");
    assert!(rejected.to_string().contains("60s"));
    assert!(rejected.to_string().contains("30s"));
    assert!(store.list_runs(None).await.unwrap().is_empty());
    assert_eq!(runtime.calls.lock().unwrap().len(), 1, "only compile ran");

    write_policy(120, 3584, 4);
    let summary = container
        .harness_smoke(
            &project,
            "parse_policy",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert_eq!(summary.duration_secs, 60);

    {
        let calls = runtime.calls.lock().unwrap();
        let (command, limits) = calls
            .iter()
            .find(|(command, _)| command.iter().any(|arg| arg == "-max_total_time=60"))
            .expect("smoke command uses the resolved duration");
        assert!(command.iter().any(|arg| arg == "-max_total_time=60"));
        assert_eq!(limits.max_mem_mb, 3584);
        assert_eq!(limits.max_cpus, 4);
        // The fuzzer's own budget is 60s; the sandbox wall-clock is granted
        // headroom so a non-crashing harness that runs the full budget is not
        // killed at the cap before its activity is measured.
        assert_eq!(
            limits.max_duration_secs,
            60 + hf_engine::runner::SANDBOX_TIMEOUT_HEADROOM_SECS
        );
    }

    let runs = store.list_runs(None).await.unwrap();
    assert_eq!(runs.len(), 1);
    let config = runs[0].config.as_ref().unwrap();
    assert_eq!(config.duration, Some(std::time::Duration::from_mins(1)));
    assert_eq!(config.max_mem_mb, 3584);
    assert_eq!(config.max_cpus, 4);
}
