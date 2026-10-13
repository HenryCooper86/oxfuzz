use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use super::service;
use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, CommandTermination, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use service::scheduler::CampaignParams;
use service::ServiceContainer;

fn isolate() {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    let root = ROOT.get_or_init(|| {
        let root = tempfile::tempdir().unwrap().keep();
        install_environment(&root);
        service::initialize_workspace_root().unwrap();
        root
    });
    install_environment(root);
}

fn install_environment(root: &Path) {
    std::env::set_var("HF_CONFIG_DIR", root.join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
    // Scheduler campaigns run through the env-gated dispatcher, and these
    // fixtures exercise scheduling, not the approval gate.
    std::env::set_var("HF_AUTO_APPROVE", "1");
}

pub(super) struct TestRuntime {
    pub(super) delay: Duration,
    pub(super) block: bool,
    pub(super) release: Option<Arc<tokio::sync::Notify>>,
    pub(super) panic_image: AtomicBool,
    pub(super) durations: Mutex<Vec<u64>>,
}

impl TestRuntime {
    pub(super) fn new(delay: Duration, block: bool) -> Arc<Self> {
        Arc::new(Self {
            delay,
            block,
            release: None,
            panic_image: AtomicBool::new(false),
            durations: Mutex::new(Vec::new()),
        })
    }
}

fn completed(cwd: &Path, termination: CommandTermination) -> CommandResult {
    CommandResult {
        exit_code: 0,
        stdout: "DONE exec/s: 64".to_owned(),
        stderr: String::new(),
        workspace: cwd.to_path_buf(),
        termination,
    }
}

#[async_trait::async_trait]
impl RuntimeAdapter for TestRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        assert!(
            !self.panic_image.load(Ordering::SeqCst),
            "controlled image resolver panic"
        );
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        hf_test_utils::function_coverage::satisfy_function_coverage(cmd, cwd, 64);
        Ok(completed(cwd, CommandTermination::Completed))
    }

    /// This runtime blocks until cancelled, which is the campaign shape under
    /// test. Collection dispatches profiling tooling with a token nothing
    /// cancels, so routing the tooling here would hang the run instead of
    /// failing it; the tooling is answered directly.
    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &hf_core::runtime::ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        if hf_test_utils::function_coverage::satisfy_function_coverage_with_mounts(cmd, opts, 64) {
            return Ok(completed(cwd, CommandTermination::Completed));
        }
        self.run_command_streaming(cmd, cwd, limits, cancel, on_line)
            .await
    }
    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        let duration = cmd
            .iter()
            .find_map(|arg| arg.strip_prefix("-max_total_time="))
            .expect("libFuzzer duration")
            .parse()
            .unwrap();
        self.durations.lock().unwrap().push(duration);
        on_line("#1024 DONE cov: 137 exec/s: 64");
        if self.block {
            cancel.cancelled().await;
            return Ok(completed(cwd, CommandTermination::Cancelled));
        }
        if let Some(release) = &self.release {
            release.notified().await;
        }
        if !self.delay.is_zero() {
            tokio::time::advance(self.delay).await;
        }
        Ok(completed(cwd, CommandTermination::Completed))
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

pub(super) struct Fixture {
    pub(super) root: tempfile::TempDir,
    pub(super) project: PathBuf,
    pub(super) service: ServiceContainer,
    pub(super) runtime: Arc<TestRuntime>,
}

impl Fixture {
    pub(super) async fn new(runtime: Arc<TestRuntime>) -> Self {
        isolate();
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("parse.c"), "#include <stddef.h>\nint parse_background(const unsigned char *data, size_t size) { return size && data[0]; }\n").unwrap();
        let workspace = service::workspace_dir(&project, "parse_background");
        std::fs::create_dir_all(workspace.join("corpus")).unwrap();
        std::fs::write(workspace.join("fuzz_parse_background"), b"#!/bin/true").unwrap();
        let service = ServiceContainer::new(
            runtime.clone(),
            Some(hf_test_utils::approving_harness_review_pool()),
        )
        .with_store_path(root.path().join("store.db"))
        .await
        .unwrap();
        service.harness_compile("int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(), &project, EngineKind::LibFuzzer, "parse_background", TargetLanguage::C, None,
            false,
        ).await.unwrap();
        service
            .harness_smoke(
                &project,
                "parse_background",
                EngineKind::LibFuzzer,
                TargetLanguage::C,
            )
            .await
            .unwrap();
        service
            .harness_promote(&project, "parse_background", EngineKind::LibFuzzer)
            .await
            .unwrap();
        Self {
            root,
            project,
            service,
            runtime,
        }
    }

    pub(super) fn params(&self) -> CampaignParams {
        CampaignParams {
            project: self.project.display().to_string(),
            target: Some("parse_background".into()),
            engine: "libfuzzer".into(),
            lang: "c".into(),
            duration_secs: 60,
            max_runs: Some(1),
            max_total_secs: None,
            schedule_id: String::new(),
        }
    }
}
