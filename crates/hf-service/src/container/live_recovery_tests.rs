//! Approved userspace campaign interrupted after durable service admission.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use hf_core::engine::EngineKind;
use hf_core::runtime::{ResourceLimits, RuntimeAdapter};
use hf_core::target::TargetLanguage;
use hf_runtime::docker::DockerRuntime;
use hf_runtime::owned_containers::OwnedContainerRegistry;
use hf_runtime::RuntimeConfig;
use hf_storage::{RunStatus, Store};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{provider_pool_from_config, workspace, ServiceContainer};
use crate::recovery::{reconcile_interrupted_run_statuses, RunJournal};

const TARGET: &str = include_str!("../../../../examples/qualification/parser.c");
const HARNESS: &str = include_str!("../../../../examples/qualification/harness.c");
const APPROVAL: &str = "OXFUZZ_LIVE_APPROVAL_SHA256";
const EVIDENCE_ROOT: &str = "OXFUZZ_LIVE_EVIDENCE_ROOT";
const CHILD_ROOT: &str = "OXFUZZ_A3_SERVICE_CHILD_ROOT";

fn approved_sources() {
    let mut hash = Sha256::new();
    hash.update(TARGET.as_bytes());
    hash.update(b"\0");
    hash.update(HARNESS.as_bytes());
    let approved = std::env::var(APPROVAL).expect("exact source approval is required");
    assert_eq!(approved, format!("{:x}", hash.finalize()));
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(None) => {
                if let Err(error) = self.0.kill() {
                    eprintln!("could not kill owned qualification child: {error}");
                }
            }
            Ok(Some(_)) => {}
            Err(error) => eprintln!("could not inspect owned qualification child: {error}"),
        }
        if let Err(error) = self.0.wait() {
            eprintln!("could not reap owned qualification child: {error}");
        }
    }
}

async fn run_containers(workspace_digest: &str, include_stopped: bool) -> BTreeSet<String> {
    let mut command = tokio::process::Command::new(hf_runtime::docker_bin());
    command.arg("ps");
    if include_stopped {
        command.arg("-a");
    }
    command
        .args([
            "--format",
            "{{.Names}}",
            "--filter",
            &format!("label=org.oxfuzz.workspace-sha256={workspace_digest}"),
        ])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("bounded Docker inventory")
        .expect("Docker inventory");
    assert!(output.status.success(), "Docker inventory failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn short_limits() -> ResourceLimits {
    ResourceLimits {
        max_mem_mb: 256,
        max_cpus: 1,
        max_duration_secs: 10,
        env: HashMap::new(),
        ptrace: false,
    }
}

#[tokio::test]
#[ignore = "requires approved sources, configured provider, Docker, and sandbox image"]
async fn approved_campaign_survives_service_process_loss() {
    approved_sources();
    assert!(hf_runtime::docker_daemon_ready());
    let parent = PathBuf::from(std::env::var(EVIDENCE_ROOT).expect("private evidence root"));
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent.join(format!("a3-service-{}", Uuid::new_v4()));
    let workspace_root = root.join("workspace");
    std::fs::create_dir_all(&workspace_root).unwrap();
    let registry = OwnedContainerRegistry::new(&workspace_root).unwrap();
    let child_log = File::create(root.join("child.log")).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "container::live_recovery_tests::live_campaign_child",
                "--nocapture",
            ])
            .env(CHILD_ROOT, &root)
            .stdout(Stdio::from(child_log.try_clone().unwrap()))
            .stderr(Stdio::from(child_log))
            .spawn()
            .unwrap(),
    );
    let marker = root.join("admitted-run-id");
    let container_name = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "live campaign child exited early"
            );
            if marker.exists() {
                let running = run_containers(registry.workspace_digest(), false).await;
                if let Some(name) = registry
                    .pending_names()
                    .unwrap()
                    .into_iter()
                    .find(|name| running.contains(name))
                {
                    return name;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("admitted campaign never entered its owned sandbox");
    child.0.kill().unwrap();
    child.0.wait().unwrap();

    let run_id = Uuid::parse_str(std::fs::read_to_string(&marker).unwrap().trim()).unwrap();
    let journal = RunJournal::open(root.join("run_journal.jsonl"));
    assert!(journal.durability_error().is_none());
    assert_eq!(journal.interrupted().len(), 1);
    assert_eq!(journal.interrupted()[0].run_id, run_id.to_string());
    let store = Arc::new(Store::connect(root.join("qualification.db")).await.unwrap());
    assert_eq!(
        store.get_run(run_id).await.unwrap().unwrap().status,
        RunStatus::Running
    );
    assert_eq!(
        reconcile_interrupted_run_statuses(&store, &journal)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.get_run(run_id).await.unwrap().unwrap().status,
        RunStatus::Failed
    );

    let runtime = Arc::new(DockerRuntime::new(
        RuntimeConfig::default(),
        &workspace_root,
    ));
    runtime
        .run_command(&["true".to_owned()], &workspace_root, &short_limits())
        .await
        .expect("fresh runtime reconciles and admits a harmless command");
    assert!(registry.pending_names().unwrap().is_empty());
    assert!(!run_containers(registry.workspace_digest(), true)
        .await
        .contains(&container_name));

    let pool = provider_pool_from_config().expect("configured review provider");
    std::env::set_var("HF_CONFIG_DIR", root.join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", &workspace_root);
    let mut service = ServiceContainer::new(runtime, Some(pool)).with_store(store);
    service.run_journal = Arc::new(journal);
    let project = root.join("libfuzzer");
    let resumed = service
        .run_fuzzer(
            &project,
            "qualification_parse",
            EngineKind::LibFuzzer,
            10,
            &|_| {},
        )
        .await
        .expect("fresh service admits a distinct approved campaign");
    assert_ne!(resumed.run_id, run_id);
    assert!(registry.pending_names().unwrap().is_empty());
    assert!(run_containers(registry.workspace_digest(), true)
        .await
        .is_empty());
    std::fs::write(
        root.join("recovery.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "interrupted_run_id": run_id,
            "new_run_id": resumed.run_id,
            "owned_container_name": container_name,
            "cleanup": "verified",
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "helper for approved_campaign_survives_service_process_loss"]
async fn live_campaign_child() {
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        return;
    };
    approved_sources();
    let root = Path::new(&root);
    let pool = provider_pool_from_config().expect("configured review provider");
    std::env::set_var("HF_CONFIG_DIR", root.join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
    workspace::initialize_workspace_root().unwrap();
    crate::config::write_config("oxfuzz", "[fuzzing]\ncollect_function_coverage = true\nenabled_engines = [\"libfuzzer\"]\ndefault_engine = \"libfuzzer\"\ndefault_duration_secs = 120\n[fuzzing.sandbox]\nmax_mem_mb = 2048\nmax_cpus = 1\nmax_duration_secs = 120\n").unwrap();
    let runtime = Arc::new(DockerRuntime::new(
        RuntimeConfig::default(),
        &root.join("workspace"),
    ));
    let store = Arc::new(Store::connect(root.join("qualification.db")).await.unwrap());
    let mut service = ServiceContainer::new(runtime, Some(pool)).with_store(store);
    service.run_journal = Arc::new(RunJournal::open(root.join("run_journal.jsonl")));
    let project = root.join("libfuzzer");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("parser.c"), TARGET).unwrap();
    service
        .harness_compile(
            HARNESS.to_owned(),
            &project,
            EngineKind::LibFuzzer,
            "qualification_parse",
            TargetLanguage::C,
        )
        .await
        .unwrap();
    let target_workspace = workspace::workspace_dir(&project, "qualification_parse");
    std::fs::create_dir_all(target_workspace.join("corpus")).unwrap();
    std::fs::write(target_workspace.join("corpus/seed"), b"OX\0\xff").unwrap();
    let smoke = service
        .harness_smoke(
            &project,
            "qualification_parse",
            EngineKind::LibFuzzer,
            TargetLanguage::C,
        )
        .await
        .unwrap();
    assert_eq!(smoke.verdict.level, crate::verification::VerdictLevel::Pass);
    service
        .harness_promote(&project, "qualification_parse", EngineKind::LibFuzzer)
        .await
        .unwrap();
    service
        .run_fuzzer_observed(
            &project,
            "qualification_parse",
            EngineKind::LibFuzzer,
            120,
            &|_| {},
            &|id| {
                let mut marker = File::create(root.join("admitted-run-id")).unwrap();
                write!(marker, "{id}").unwrap();
                marker.sync_all().unwrap();
            },
        )
        .await
        .expect("parent must terminate the live service before the campaign completes");
    panic!("campaign completed before process-loss injection");
}
