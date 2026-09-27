//! Explicit live checks of Docker isolation for harmless sandbox commands.

use std::collections::{BTreeSet, HashMap};
use std::process::{Command, Stdio};

use hf_core::runtime::{
    CommandTermination, ResourceLimits, RuntimeAdapter, SandboxMount, SandboxOptions,
};
use hf_runtime::config::RuntimeConfig;
use hf_runtime::docker::DockerRuntime;
use hf_runtime::owned_containers::OwnedContainerRegistry;

fn run_containers(workspace_digest: &str) -> BTreeSet<String> {
    let output = Command::new(hf_runtime::docker_bin())
        .args([
            "ps",
            "-a",
            "--format",
            "{{.Names}}",
            "--filter",
            &format!("label=org.oxfuzz.workspace-sha256={workspace_digest}"),
        ])
        .output()
        .expect("Docker inventory");
    assert!(output.status.success(), "Docker inventory failed");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn limits(seconds: u64) -> ResourceLimits {
    ResourceLimits {
        max_mem_mb: 256,
        max_cpus: 1,
        max_duration_secs: seconds,
        env: HashMap::new(),
        ptrace: false,
    }
}

fn workspace_label(name: &str) -> Option<String> {
    let output = Command::new(hf_runtime::docker_bin())
        .args([
            "inspect",
            "--format",
            "{{index .Config.Labels \"org.oxfuzz.workspace-sha256\"}}",
            name,
        ])
        .output()
        .unwrap();
    output
        .status
        .success()
        .then(|| String::from_utf8(output.stdout).unwrap().trim().to_owned())
}

fn cleanup_inventory(root: &std::path::Path) {
    let registry = OwnedContainerRegistry::new(root).unwrap();
    assert!(registry.pending_names().unwrap().is_empty());
    let directory = root
        .parent()
        .unwrap()
        .join(format!(".oxfuzz-runtime-{}", registry.workspace_digest()));
    std::fs::remove_dir(directory).unwrap();
}

#[tokio::test]
#[ignore = "requires the pinned Docker image and disposable host workspace"]
async fn live_sandbox_denies_network_and_input_writes_but_retains_bounded_output() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("output");
    std::fs::create_dir(&output).unwrap();
    std::fs::write(root.path().join("input.txt"), "retained input").unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), root.path());
    let options = SandboxOptions {
        workspace_read_only: true,
        extra_mounts: vec![SandboxMount::writable(output.clone(), "/work/output")],
        ..SandboxOptions::default()
    };
    let command = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "test ! -e /sys/class/net/eth0 && test \"$(cat /sys/fs/cgroup/memory.max)\" = 268435456 && test \"$(cat /sys/fs/cgroup/cpu.max)\" = '100000 100000' && test \"$(cat /work/input.txt)\" = 'retained input' && if (printf forbidden > /work/input.txt) 2>/dev/null; then exit 11; fi && printf accepted > /work/output/result.txt".to_owned(),
    ];
    let result = runtime
        .run_command_opts(&command, root.path(), &limits(10), &options)
        .await
        .unwrap();
    assert_eq!(result.termination, CommandTermination::Completed);
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    assert_eq!(
        std::fs::read_to_string(root.path().join("input.txt")).unwrap(),
        "retained input"
    );
    assert_eq!(
        std::fs::read_to_string(output.join("result.txt")).unwrap(),
        "accepted"
    );
    cleanup_inventory(root.path());
}

#[tokio::test]
#[ignore = "requires the pinned Docker image and disposable host workspace"]
async fn live_timeout_waits_for_owned_container_cleanup() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    let before = run_containers(registry.workspace_digest());
    let runtime = DockerRuntime::new(RuntimeConfig::default(), root.path());
    let command = vec!["sleep".to_owned(), "30".to_owned()];
    let result = runtime
        .run_command(&command, root.path(), &limits(1))
        .await
        .unwrap();
    assert_eq!(result.termination, CommandTermination::TimedOut);
    let after = run_containers(registry.workspace_digest());
    assert!(
        after.difference(&before).next().is_none(),
        "owned container remains: {after:?}"
    );
    cleanup_inventory(root.path());
}

#[tokio::test]
#[ignore = "requires the pinned Docker image and disposable host workspace"]
async fn live_run_registers_and_labels_its_owned_container() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    let before = run_containers(registry.workspace_digest());
    let runtime = DockerRuntime::new(RuntimeConfig::default(), root.path());
    let workspace = root.path().to_path_buf();
    let task = tokio::spawn(async move {
        runtime
            .run_command(
                &["sleep".to_owned(), "5".to_owned()],
                &workspace,
                &limits(10),
            )
            .await
    });
    let owned = tokio::time::timeout(std::time::Duration::from_secs(4), async {
        loop {
            if let Some(name) = run_containers(registry.workspace_digest())
                .difference(&before)
                .next()
                .cloned()
            {
                return name;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("owned container starts");
    let pending = registry.pending_names().unwrap();
    let label = workspace_label(&owned);
    let result = task.await.unwrap().unwrap();
    assert_eq!(result.termination, CommandTermination::Completed);
    assert_eq!(result.exit_code, 0);
    assert_eq!(pending, vec![owned]);
    assert_eq!(label.as_deref(), Some(registry.workspace_digest()));
    assert!(registry.pending_names().unwrap().is_empty());
    cleanup_inventory(root.path());
}

#[tokio::test]
#[ignore = "requires the pinned Docker image and disposable host workspace"]
async fn live_target_cannot_read_runtime_ownership_records() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), root.path());
    let command = vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "test ! -e /work/.oxfuzz/runtime-containers".to_owned(),
    ];
    let result = runtime
        .run_command(&command, root.path(), &limits(10))
        .await
        .unwrap();
    assert_eq!(result.termination, CommandTermination::Completed);
    assert_eq!(
        result.exit_code, 0,
        "runtime inventory was visible inside the sandbox"
    );
    cleanup_inventory(root.path());
}

#[tokio::test]
#[ignore = "requires Docker and terminates only its own disposable helper process"]
async fn live_fresh_runtime_removes_a_container_left_by_process_termination() {
    assert!(hf_runtime::docker_daemon_ready());
    let root = tempfile::tempdir().unwrap();
    let registry = OwnedContainerRegistry::new(root.path()).unwrap();
    let mut helper = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "live_owned_container_helper",
            "--nocapture",
        ])
        .env("OXFUZZ_A3_HELPER_ROOT", root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let owned = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(name) = registry
                .pending_names()
                .unwrap()
                .into_iter()
                .find(|name| run_containers(registry.workspace_digest()).contains(name))
            {
                return name;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await;
    if helper.try_wait().unwrap().is_none() {
        helper.kill().unwrap();
    }
    helper.wait().unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), root.path());
    let recovered = runtime
        .run_command(&["true".to_owned()], root.path(), &limits(10))
        .await;
    let pending = registry.pending_names().unwrap();
    let still_running = owned
        .as_ref()
        .ok()
        .is_some_and(|name| run_containers(registry.workspace_digest()).contains(name));
    for name in &pending {
        if workspace_label(name).as_deref() == Some(registry.workspace_digest()) {
            let output = Command::new(hf_runtime::docker_bin())
                .args(["rm", "-f", name])
                .output()
                .unwrap();
            assert!(output.status.success());
        }
    }
    assert!(owned.is_ok(), "helper never started an owned container");
    assert!(
        recovered.is_ok(),
        "fresh runtime did not reconcile: {recovered:?}"
    );
    assert!(pending.is_empty(), "owned records remain: {pending:?}");
    assert!(!still_running, "owned container remains after recovery");
    cleanup_inventory(root.path());
}

#[tokio::test]
#[ignore = "helper for live_fresh_runtime_removes_a_container_left_by_process_termination"]
async fn live_owned_container_helper() {
    let Ok(root) = std::env::var("OXFUZZ_A3_HELPER_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let runtime = DockerRuntime::new(RuntimeConfig::default(), &root);
    runtime
        .run_command(&["sleep".to_owned(), "30".to_owned()], &root, &limits(40))
        .await
        .unwrap();
}
