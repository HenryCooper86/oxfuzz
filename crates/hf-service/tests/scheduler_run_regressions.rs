//! Real scheduler/run consumers with sandbox execution replaced by a controlled runtime.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use hf_core::engine::EngineKind;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, CommandTermination, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_service::scheduler::{CampaignParams, CampaignScheduler};
use hf_service::{RunLifecycleStatus, ServiceContainer};

fn isolate() {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = tempfile::tempdir().unwrap().keep();
        std::env::set_var("HF_CONFIG_DIR", root.join("config"));
        std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
        hf_service::initialize_workspace_root().unwrap();
        root
    });
}

struct TestRuntime {
    delay: Duration,
    block: bool,
    release: Option<Arc<tokio::sync::Notify>>,
    panic_image: AtomicBool,
    durations: Mutex<Vec<u64>>,
}

impl TestRuntime {
    fn new(delay: Duration, block: bool) -> Arc<Self> {
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
        _cmd: &[String],
        cwd: &Path,
        _limits: &hf_core::runtime::ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Ok(completed(cwd, CommandTermination::Completed))
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
        tokio::time::sleep(self.delay).await;
        Ok(completed(cwd, CommandTermination::Completed))
    }
    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Ok(())
    }
    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Ok(String::new())
    }
}

struct Fixture {
    root: tempfile::TempDir,
    project: PathBuf,
    service: ServiceContainer,
    runtime: Arc<TestRuntime>,
}

impl Fixture {
    async fn new(runtime: Arc<TestRuntime>) -> Self {
        isolate();
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join("parse.c"), "#include <stddef.h>\nint parse_background(const unsigned char *data, size_t size) { return size && data[0]; }\n").unwrap();
        let workspace = hf_service::workspace_dir(&project, "parse_background");
        std::fs::create_dir_all(workspace.join("corpus")).unwrap();
        std::fs::write(workspace.join("fuzz_parse_background"), b"#!/bin/true").unwrap();
        let service = ServiceContainer::new(
            runtime.clone(),
            Some(hf_test_utils::approving_harness_review_pool()),
        )
        .with_store_path(root.path().join("store.db"))
        .await
        .unwrap();
        service.harness_compile("int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size) { return size && data[0]; }".to_owned(), &project, EngineKind::LibFuzzer, "parse_background", TargetLanguage::C).await.unwrap();
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

    fn params(&self) -> CampaignParams {
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

    async fn scheduler(&self) -> CampaignScheduler {
        CampaignScheduler::try_start(
            self.service.clone().without_provider_pool(),
            self.root.path().join("schedules.json"),
            None,
        )
        .await
        .unwrap()
    }
}

async fn wait_for_completed(scheduler: &CampaignScheduler) {
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let history = scheduler.recent_executions(10).await.unwrap();
            assert!(
                !history.iter().any(|entry| entry.status == "failed"),
                "fixture failed: {history:?}"
            );
            if history
                .iter()
                .any(|entry| entry.status == "completed" && !entry.summary.starts_with("skipped:"))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("mock campaign should complete");
}

#[test]
fn excessive_interval_is_rejected_at_user_input() {
    assert!(hf_service::scheduler::parse_trigger("interval", &u64::MAX.to_string()).is_err());
}

#[tokio::test]
async fn panicking_subscribers_do_not_hang_start_or_prevent_durable_cancellation() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, true)).await;
    let run_id = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.service.start_fuzzer(
            fixture.project.clone(),
            "parse_background".into(),
            EngineKind::LibFuzzer,
            60,
            Arc::new(|_, _| panic!("progress subscriber failed")),
            Arc::new(|_, _| panic!("status subscriber failed")),
        ),
    )
    .await
    .expect("startup resolves despite subscriber panic")
    .unwrap();
    assert!(fixture.service.cancel_run(run_id));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if fixture
                .service
                .run_control_status(run_id)
                .await
                .unwrap()
                .unwrap()
                .status
                == RunLifecycleStatus::Cancelled
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled run finalizes durably");
}

#[tokio::test]
async fn unexpected_background_panic_closes_startup_acknowledgement() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    fixture.runtime.panic_image.store(true, Ordering::SeqCst);
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        fixture.service.start_fuzzer(
            fixture.project.clone(),
            "parse_background".into(),
            EngineKind::LibFuzzer,
            60,
            Arc::new(|_, _| {}),
            Arc::new(|_, _| {}),
        ),
    )
    .await
    .expect("task failure must close the acknowledgement channel");
    assert!(result.is_err());
}

#[tokio::test]
async fn one_run_budget_completes_only_one_iteration() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    let scheduler = fixture.scheduler().await;
    scheduler
        .try_create(
            "one run",
            &fixture.params(),
            hf_service::scheduler::parse_trigger("once", "2000-01-01T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
    scheduler.arm();
    wait_for_completed(&scheduler).await;
    let views = scheduler.list_views().await.unwrap();
    scheduler.stop().await;
    assert_eq!(views[0].runs_done, 1);
    assert_eq!(fixture.runtime.durations.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn time_budget_caps_fuzzer_duration_and_stops_additional_iterations() {
    let fixture = Fixture::new(TestRuntime::new(Duration::from_millis(1100), false)).await;
    let scheduler = fixture.scheduler().await;
    let mut params = fixture.params();
    params.max_runs = None;
    params.max_total_secs = Some(2);
    scheduler
        .try_create(
            "two seconds",
            &params,
            hf_service::scheduler::parse_trigger("once", "2000-01-01T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
    scheduler.arm();
    wait_for_completed(&scheduler).await;
    scheduler.stop().await;
    assert_eq!(*fixture.runtime.durations.lock().unwrap(), vec![2, 1]);
}

#[tokio::test]
async fn overlapping_fires_cannot_spend_the_same_run_allowance() {
    let release = Arc::new(tokio::sync::Notify::new());
    let mut runtime = TestRuntime::new(Duration::ZERO, false);
    Arc::get_mut(&mut runtime).unwrap().release = Some(Arc::clone(&release));
    let fixture = Fixture::new(runtime).await;
    let scheduler = fixture.scheduler().await;
    let mut schedule = scheduler
        .try_create(
            "overlap",
            &fixture.params(),
            hf_service::scheduler::parse_trigger("interval", "1").unwrap(),
        )
        .await
        .unwrap();
    scheduler.stop().await;
    schedule.policies.concurrency_policy = Some(hf_scheduler::config::ConcurrencyPolicy::Allow);
    std::fs::write(
        fixture.root.path().join("schedules.json"),
        serde_json::to_vec(&vec![schedule]).unwrap(),
    )
    .unwrap();
    let scheduler = fixture.scheduler().await;
    scheduler.arm();
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let history = scheduler.recent_executions(10).await.unwrap();
            if history
                .iter()
                .any(|entry| entry.summary.contains("already has work in progress"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("live scheduler must attempt an overlapping fire");
    release.notify_one();
    wait_for_completed(&scheduler).await;
    let views = scheduler.list_views().await.unwrap();
    let history = scheduler.recent_executions(10).await.unwrap();
    scheduler.stop().await;
    assert_eq!(views[0].runs_done, 1);
    assert_eq!(fixture.runtime.durations.lock().unwrap().len(), 1);
    assert!(
        history
            .iter()
            .any(|entry| entry.summary.contains("already has work in progress")),
        "overlapping occurrence exercised: {history:?}"
    );
}

#[tokio::test]
async fn direct_creation_rejects_invalid_intervals_without_registering_them() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    let scheduler = fixture.scheduler().await;
    assert!(scheduler
        .try_create(
            "invalid",
            &fixture.params(),
            hf_scheduler::store::TriggerConfig::Interval {
                interval_secs: u64::MAX
            }
        )
        .await
        .is_err());
    assert!(scheduler.list().await.is_empty());
    scheduler.stop().await;
}

#[tokio::test]
async fn failed_cron_enable_restores_its_original_calendar_cursor() {
    let fixture = Fixture::new(TestRuntime::new(Duration::ZERO, false)).await;
    let scheduler = fixture.scheduler().await;
    let schedule = scheduler
        .try_create(
            "cron",
            &fixture.params(),
            hf_service::scheduler::parse_trigger("cron", "0 2 * * *").unwrap(),
        )
        .await
        .unwrap();
    scheduler
        .try_set_enabled(&schedule.id, false)
        .await
        .unwrap();
    let before = scheduler.list().await.pop().unwrap();
    let path = fixture.root.path().join("schedules.json");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(scheduler.try_set_enabled(&schedule.id, true).await.is_err());
    let after = scheduler.list().await.pop().unwrap();
    scheduler.stop().await;
    assert!(!after.enabled);
    assert_eq!(after.last_fire, before.last_fire);
}

#[tokio::test]
async fn one_second_allowance_can_launch_a_one_second_run() {
    let fixture = Fixture::new(TestRuntime::new(Duration::from_millis(1100), false)).await;
    let scheduler = fixture.scheduler().await;
    let mut params = fixture.params();
    params.max_runs = None;
    params.max_total_secs = Some(1);
    scheduler
        .try_create(
            "one second",
            &params,
            hf_service::scheduler::parse_trigger("once", "2000-01-01T00:00:00Z").unwrap(),
        )
        .await
        .unwrap();
    scheduler.arm();
    wait_for_completed(&scheduler).await;
    scheduler.stop().await;
    assert_eq!(*fixture.runtime.durations.lock().unwrap(), vec![1]);
}
