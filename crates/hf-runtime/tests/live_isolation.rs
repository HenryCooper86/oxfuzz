//! Explicit live checks of Docker isolation for harmless sandbox commands.

use std::collections::{BTreeSet, HashMap};
use std::process::Command;

use hf_core::runtime::{
    CommandTermination, ResourceLimits, RuntimeAdapter, SandboxMount, SandboxOptions,
};
use hf_runtime::config::RuntimeConfig;
use hf_runtime::docker::DockerRuntime;

fn run_containers() -> BTreeSet<String> {
    let output = Command::new(hf_runtime::docker_bin())
        .args([
            "ps",
            "-a",
            "--format",
            "{{.Names}}",
            "--filter",
            "name=hf-run-",
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
}

#[tokio::test]
#[ignore = "requires the pinned Docker image and disposable host workspace"]
async fn live_timeout_waits_for_owned_container_cleanup() {
    assert!(hf_runtime::docker_daemon_ready());
    let before = run_containers();
    let root = tempfile::tempdir().unwrap();
    let runtime = DockerRuntime::new(RuntimeConfig::default(), root.path());
    let command = vec!["sleep".to_owned(), "30".to_owned()];
    let result = runtime
        .run_command(&command, root.path(), &limits(1))
        .await
        .unwrap();
    assert_eq!(result.termination, CommandTermination::TimedOut);
    let after = run_containers();
    assert!(
        after.difference(&before).next().is_none(),
        "owned container remains: {after:?}"
    );
}
