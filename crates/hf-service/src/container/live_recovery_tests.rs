//! Approved userspace campaign interrupted after durable service admission.

use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use hf_core::engine::EngineKind;
use hf_core::engine::FuzzRunConfig;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::runtime::{ResourceLimits, RuntimeAdapter};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_runtime::docker::DockerRuntime;
use hf_runtime::owned_containers::OwnedContainerRegistry;
use hf_runtime::RuntimeConfig;
use hf_storage::{RunRecord, RunStatus, Store};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{provider_pool_from_config, workspace, ServiceContainer};
use crate::recovery::{reconcile_interrupted_run_statuses, RunJournal};

const TARGET: &str = include_str!("../../../../examples/qualification/parser.c");
const HARNESS: &str = include_str!("../../../../examples/qualification/harness.c");
const APPROVAL: &str = "OXFUZZ_LIVE_APPROVAL_SHA256";
const EVIDENCE_ROOT: &str = "OXFUZZ_LIVE_EVIDENCE_ROOT";
const CHILD_ROOT: &str = "OXFUZZ_A3_SERVICE_CHILD_ROOT";
const CLOSEOUT_PAUSE_STEP: &str = "OXFUZZ_A3_CLOSEOUT_PAUSE_STEP";

pub(super) fn pause_after_closeout_record(step: crate::run_closeout::CloseoutStep) {
    if std::env::var(CLOSEOUT_PAUSE_STEP).ok().as_deref() != Some(format!("{step:?}").as_str()) {
        return;
    }
    let root = PathBuf::from(std::env::var(CHILD_ROOT).expect("closeout child root"));
    let mut marker = File::create(root.join("closeout-paused")).unwrap();
    write!(marker, "{step:?}").unwrap();
    marker.sync_all().unwrap();
    loop {
        std::thread::park();
    }
}

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

#[tokio::test]
#[ignore = "terminates an owned disposable closeout process"]
async fn persisted_closeout_step_survives_process_loss() {
    let parent = PathBuf::from(std::env::var(EVIDENCE_ROOT).expect("private evidence root"));
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent.join(format!("a3-closeout-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let child_log = File::create(root.join("child.log")).unwrap();
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "container::live_recovery_tests::closeout_child",
                "--nocapture",
            ])
            .env(CHILD_ROOT, &root)
            .env(CLOSEOUT_PAUSE_STEP, "Triage")
            .stdout(Stdio::from(child_log.try_clone().unwrap()))
            .stderr(Stdio::from(child_log))
            .spawn()
            .unwrap(),
    );
    let marker = root.join("closeout-paused");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "closeout child exited early"
            );
            if marker.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("closeout did not pause after its first durable step");
    assert_eq!(std::fs::read_to_string(marker).unwrap(), "Triage");
    child.0.kill().unwrap();
    child.0.wait().unwrap();

    let run_id =
        Uuid::parse_str(std::fs::read_to_string(root.join("run-id")).unwrap().trim()).unwrap();
    let store = Arc::new(Store::connect(root.join("closeout.db")).await.unwrap());
    let before = store.closeout_steps(run_id).await.unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].0, "Triage");
    assert_eq!(before[0].1, "completed");

    let service =
        ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store.clone());
    let report = service.close_out_run(run_id).await.unwrap();
    assert_eq!(
        report.resumed_at,
        Some(crate::run_closeout::CloseoutStep::Minimize)
    );
    assert_eq!(store.closeout_steps(run_id).await.unwrap()[0], before[0]);
    assert_eq!(
        report.steps.len(),
        crate::run_closeout::closeout_ladder().len()
    );
    std::fs::write(
        root.join("recovery.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "run_id": run_id,
            "durable_first_step": before[0],
            "resumed_at": "Minimize",
            "retained_steps": report.steps.len(),
        }))
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
#[ignore = "helper for persisted_closeout_step_survives_process_loss"]
async fn closeout_child() {
    let Ok(root) = std::env::var(CHILD_ROOT) else {
        return;
    };
    let root = Path::new(&root);
    let project = root.join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.join("config"));
    std::env::set_var("HF_WORKSPACE_DIR", root.join("workspace"));
    workspace::initialize_workspace_root().unwrap();
    let target_workspace = workspace::workspace_dir(&project, "qualification_parse");
    std::fs::create_dir_all(target_workspace.join("out")).unwrap();
    std::fs::write(
        target_workspace.join("fuzz_qualification_parse"),
        b"unused fixture",
    )
    .unwrap();
    let store = Arc::new(Store::connect(root.join("closeout.db")).await.unwrap());
    let run_id = seed_terminal_closeout_run(&store, &project).await;
    let mut marker = File::create(root.join("run-id")).unwrap();
    write!(marker, "{run_id}").unwrap();
    marker.sync_all().unwrap();
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None).with_store(store);
    service.close_out_run(run_id).await.unwrap();
    panic!("closeout finished before process-loss injection");
}

async fn seed_terminal_closeout_run(store: &Store, project: &Path) -> Uuid {
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.to_path_buf(),
        language: TargetLanguage::C,
        symbol: "qualification_parse".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("parser.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: "disposable process-loss probe".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }"
            .to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: Vec::new(),
            output: PathBuf::from("fuzz"),
            extra_flags: Vec::new(),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::SmokePassed,
        smoke_run: None,
    };
    store.upsert_harness(&harness).await.unwrap();
    let mut run = RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(FuzzRunConfig {
            harness_id: harness.id,
            engine: EngineKind::LibFuzzer,
            duration: None,
            max_mem_mb: 256,
            max_cpus: 1,
            seed_corpus: None,
            sanitizer: Sanitizer::Address,
            env: Vec::new(),
            extra_args: Vec::new(),
            seed: None,
            replay_of: None,
            input_manifest_sha256: None,
        }),
        Utc::now(),
    );
    run.status = RunStatus::Done;
    store.insert_run(&run).await.unwrap();
    run.id
}
