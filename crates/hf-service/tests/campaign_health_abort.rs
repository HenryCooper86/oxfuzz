//! Caller-drop ownership for the campaign health monitor.

#![cfg(feature = "campaign-health")]

use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::runtime::{
    CommandResult, CommandTermination, LineSink, ResourceLimits, RuntimeAdapter,
};
use hf_service::ServiceContainer;

#[derive(Default)]
struct BlockingRuntime;

#[async_trait::async_trait]
impl RuntimeAdapter for BlockingRuntime {
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<hf_core::runtime::ImmutableImageReference>, ClassifiedError> {
        Ok(Some(hf_test_utils::immutable_test_image()?))
    }

    async fn run_command(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(CommandResult {
            exit_code: 0,
            stdout: "DONE exec/s: 64".to_owned(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Completed,
        })
    }

    async fn run_command_streaming(
        &self,
        _cmd: &[String],
        cwd: &std::path::Path,
        _limits: &ResourceLimits,
        cancel: &tokio_util::sync::CancellationToken,
        _on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        cancel.cancelled().await;
        Ok(CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: cwd.to_path_buf(),
            termination: CommandTermination::Cancelled,
        })
    }

    async fn write_file(
        &self,
        _path: &std::path::Path,
        _content: &str,
    ) -> Result<(), ClassifiedError> {
        Ok(())
    }

    async fn read_file(&self, _path: &std::path::Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

#[tokio::test]
async fn aborting_the_run_caller_stops_future_health_ticks_and_repairs_the_run() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("oxfuzz.toml"),
        "[campaign_health]\nassessment_interval_secs = 1\n",
    )
    .unwrap();
    std::env::set_var("HF_CONFIG_DIR", config);

    let workspace = directory.path().join("workspace");
    std::env::set_var("HF_WORKSPACE_DIR", &workspace);
    hf_service::initialize_workspace_root().unwrap();
    let project = directory.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    let target = "abort_target";
    std::fs::write(
        project.join("target.c"),
        "int abort_target(const unsigned char *data, unsigned long size) { return size && data[0]; }\n",
    )
    .unwrap();
    let target_workspace = hf_service::workspace_dir(&project, target);
    std::fs::create_dir_all(target_workspace.join("corpus")).unwrap();
    std::fs::write(
        target_workspace.join(format!("fuzz_{target}")),
        b"fake binary",
    )
    .unwrap();

    let store = Arc::new(
        hf_storage::Store::connect(directory.path().join("abort.db"))
            .await
            .unwrap(),
    );
    let container = Arc::new(
        ServiceContainer::new(
            Arc::new(BlockingRuntime),
            Some(hf_test_utils::approving_harness_review_pool()),
        )
        .with_store(Arc::clone(&store)),
    );
    container
        .harness_compile(
            "int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(),
            &project,
            hf_core::engine::EngineKind::LibFuzzer,
            target,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_smoke(
            &project,
            target,
            hf_core::engine::EngineKind::LibFuzzer,
            hf_core::target::TargetLanguage::C,
        )
        .await
        .unwrap();
    container
        .harness_promote(&project, target, hf_core::engine::EngineKind::LibFuzzer)
        .await
        .unwrap();

    let runner = {
        let container = Arc::clone(&container);
        let project = project.clone();
        tokio::spawn(async move {
            container
                .run_fuzzer(
                    &project,
                    target,
                    hf_core::engine::EngineKind::LibFuzzer,
                    60,
                    &|_| {},
                )
                .await
        })
    };
    let run_id = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(run_id) = container.active_run_ids().into_iter().next() {
                if store.run_telemetry(run_id).await.unwrap().is_some() {
                    break run_id;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("run and initial health snapshot");

    runner.abort();
    runner.await.expect_err("caller aborts the run future");
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let run = store.get_run(run_id).await.unwrap().unwrap();
            if run.status == hf_storage::RunStatus::Failed
                && container.active_run_ids().is_empty()
                && container.live_campaign_telemetry(run_id).is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("aborted caller cleanup and durable repair");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let stopped_at = store
        .run_telemetry(run_id)
        .await
        .unwrap()
        .unwrap()
        .observed_at;
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert_eq!(
        store
            .run_telemetry(run_id)
            .await
            .unwrap()
            .unwrap()
            .observed_at,
        stopped_at,
        "an aborted caller must not leave a periodic health task ticking",
    );
}
