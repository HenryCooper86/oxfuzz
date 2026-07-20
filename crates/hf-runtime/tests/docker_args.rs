//! Unit tests for Docker command construction.
//!
//! These do NOT require a Docker daemon; they verify the pure logic that
//! builds container exec arguments from a `RuntimeConfig` and per-call limits.

use hf_core::runtime::ResourceLimits;
use hf_runtime::config::RuntimeConfig;
use std::collections::HashMap;

/// Per-call limits with the given memory/cpu and otherwise inert values.
fn limits(max_mem_mb: u64, max_cpus: u32) -> ResourceLimits {
    ResourceLimits {
        max_mem_mb,
        max_cpus,
        max_duration_secs: 60,
        env: HashMap::new(),
        ptrace: false,
    }
}

fn cfg_with(default_limits: ResourceLimits) -> RuntimeConfig {
    RuntimeConfig {
        image: "oxfuzz/fuzz-sandbox:0.1.0".to_owned(),
        container_workspace: "/work".to_owned(),
        default_limits,
        max_pids: 512,
    }
}

#[test]
fn build_exec_args_includes_image_and_command() {
    let cfg = cfg_with(limits(4096, 2));
    let args = hf_runtime::docker::build_exec_args(
        &cfg,
        &limits(4096, 2),
        &["clang".to_owned(), "--version".to_owned()],
    );
    let joined = args.join(" ");
    assert!(joined.contains("oxfuzz/fuzz-sandbox:0.1.0"));
    assert!(joined.contains("clang"));
    assert!(joined.contains("--version"));
}

#[test]
fn build_exec_args_uses_per_call_memory_and_cpu_over_defaults() {
    // The config default is generous; the per-call limit is tighter and must
    // win -- previously the per-call limit was silently ignored.
    let cfg = cfg_with(limits(8192, 8));
    let args = hf_runtime::docker::build_exec_args(&cfg, &limits(1024, 1), &["echo".to_owned()]);
    let joined = args.join(" ");
    assert!(
        joined.contains("--memory=1024m"),
        "per-call memory not applied: {joined}"
    );
    // Swap is pinned to the memory ceiling so Docker cannot default it to 2x.
    assert!(
        joined.contains("--memory-swap=1024m"),
        "swap not pinned to the memory ceiling: {joined}"
    );
    assert!(
        joined.contains("--cpus=1"),
        "per-call cpu not applied: {joined}"
    );
    assert!(
        !joined.contains("--memory=8192m"),
        "default memory leaked over per-call limit: {joined}"
    );
}

#[test]
fn build_exec_args_passes_per_call_env_to_container() {
    // Per-call env must reach the container as `--env` flags (not the host CLI
    // process), overlaid on any config-wide default env.
    let mut default_env = HashMap::new();
    default_env.insert("BASE_OPT".to_owned(), "1".to_owned());
    let cfg = cfg_with(ResourceLimits {
        env: default_env,
        ..limits(4096, 2)
    });

    let mut call_env = HashMap::new();
    call_env.insert("ASAN_OPTIONS".to_owned(), "detect_leaks=0".to_owned());
    let per_call = ResourceLimits {
        env: call_env,
        ..limits(4096, 2)
    };

    let args = hf_runtime::docker::build_exec_args(&cfg, &per_call, &["x".to_owned()]);
    let joined = args.join(" ");
    assert!(
        joined.contains("--env=ASAN_OPTIONS=detect_leaks=0"),
        "per-call env not passed to container: {joined}"
    );
    assert!(
        joined.contains("--env=BASE_OPT=1"),
        "config default env dropped: {joined}"
    );
}

#[test]
fn build_exec_args_per_call_env_overrides_default() {
    let mut default_env = HashMap::new();
    default_env.insert("OPT".to_owned(), "default".to_owned());
    let cfg = cfg_with(ResourceLimits {
        env: default_env,
        ..limits(4096, 2)
    });
    let mut call_env = HashMap::new();
    call_env.insert("OPT".to_owned(), "override".to_owned());
    let per_call = ResourceLimits {
        env: call_env,
        ..limits(4096, 2)
    };
    let args = hf_runtime::docker::build_exec_args(&cfg, &per_call, &["x".to_owned()]);
    let joined = args.join(" ");
    assert!(
        joined.contains("--env=OPT=override"),
        "override missing: {joined}"
    );
    assert!(
        !joined.contains("--env=OPT=default"),
        "default not overridden: {joined}"
    );
}

#[test]
fn build_exec_args_mounts_workspace() {
    let cfg = cfg_with(limits(1024, 1));
    let args = hf_runtime::docker::build_exec_args(&cfg, &limits(1024, 1), &["ls".to_owned()]);
    let joined = args.join(" ");
    assert!(joined.contains("-v"), "missing volume flag: {joined}");
    assert!(joined.contains(":/work"), "missing mount target: {joined}");
}

#[test]
fn build_exec_args_adds_ptrace_caps_when_requested() {
    let cfg = cfg_with(limits(2048, 1));
    let with_ptrace = ResourceLimits {
        ptrace: true,
        ..limits(2048, 1)
    };
    let with = hf_runtime::docker::build_exec_args(&cfg, &with_ptrace, &["x".to_owned()]);
    let joined = with.join(" ");
    assert!(
        joined.contains("--cap-add=SYS_PTRACE"),
        "missing SYS_PTRACE: {joined}"
    );
    assert!(
        joined.contains("seccomp=unconfined"),
        "missing seccomp: {joined}"
    );

    let without = hf_runtime::docker::build_exec_args(&cfg, &limits(2048, 1), &["x".to_owned()]);
    assert!(
        !without.join(" ").contains("SYS_PTRACE"),
        "ptrace caps leaked when not requested"
    );
}

#[test]
fn build_exec_args_with_syzkaller_profile() {
    use hf_core::runtime::{SandboxMount, SandboxOptions};
    let cfg = cfg_with(limits(4096, 4));
    let opts = SandboxOptions {
        extra_mounts: vec![
            SandboxMount::read_only("/host/inputs".into(), "/syzbench/inputs"),
            SandboxMount::writable("/host/scratch".into(), "/syzbench/scratch"),
            SandboxMount::writable("/host/workdir".into(), "/syzbench/workdir"),
        ],
        image: None,
        platform: Some("linux/amd64".to_owned()),
        network_mode: hf_core::runtime::SandboxNetworkMode::None,
        workdir: Some("/syzbench".to_owned()),
        relax_hardening: false,
        capabilities: Vec::new(),
        stdin: None,
        devices: vec!["/dev/kvm".to_owned()],
        workspace_read_only: true,
        max_file_size_bytes: None,
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(4096, 4),
        &[
            "syz-manager".to_owned(),
            "-config=/syzbench/inputs/manager.cfg".to_owned(),
        ],
        &opts,
    );
    let joined = args.join(" ");
    // Platform, staged mounts, a custom workdir, and device passthrough present.
    assert!(joined.contains("--platform linux/amd64"), "{joined}");
    assert!(joined.contains("--device=/dev/kvm"), "{joined}");
    assert!(
        joined.contains("--mount type=bind,source=/host/inputs,target=/syzbench/inputs,readonly"),
        "{joined}"
    );
    assert!(
        joined.contains("--mount type=bind,source=/host/scratch,target=/syzbench/scratch"),
        "{joined}"
    );
    assert!(joined.contains("-w /syzbench"), "{joined}");
    assert!(
        joined.contains("--mount type=bind,source=/host/workdir,target=/syzbench/workdir"),
        "{joined}"
    );
    assert!(joined.contains("/work:ro"), "{joined}");
    // qemu runs inside the normal network and privilege boundary.
    assert!(
        joined.contains("--network=none"),
        "network should be disabled: {joined}"
    );
    assert!(
        joined.contains("--cap-drop=ALL"),
        "capabilities should be dropped: {joined}"
    );
    assert!(
        joined.contains("no-new-privileges"),
        "privilege escalation should be disabled: {joined}"
    );
    // Process limits remain part of the hardened profile.
    assert!(joined.contains("--pids-limit=512"), "{joined}");
}

#[test]
fn build_exec_args_supports_read_only_workspace_with_writable_run_mounts() {
    use hf_core::runtime::{SandboxMount, SandboxOptions};

    let cfg = cfg_with(limits(2048, 1));
    let opts = SandboxOptions {
        extra_mounts: vec![
            SandboxMount::writable("/host/corpus".into(), "/work/corpus"),
            SandboxMount::writable("/host/run-out".into(), "/work/runs/run-id/out"),
        ],
        workspace_read_only: true,
        ..SandboxOptions::default()
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(2048, 1),
        &["fuzz_bin".to_owned()],
        &opts,
    );
    let joined = args.join(" ");

    assert!(
        joined.contains("/tmp/oxfuzz_workspace:/work:ro"),
        "primary workspace must be immutable: {joined}"
    );
    assert!(
        joined.contains("type=bind,source=/host/corpus,target=/work/corpus"),
        "{joined}"
    );
    assert!(
        joined.contains("type=bind,source=/host/run-out,target=/work/runs/run-id/out"),
        "{joined}"
    );
}

#[test]
fn build_exec_args_applies_a_per_file_write_limit() {
    let cfg = cfg_with(limits(2048, 1));
    let opts = hf_core::runtime::SandboxOptions {
        max_file_size_bytes: Some(64 * 1024 * 1024),
        ..hf_core::runtime::SandboxOptions::default()
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(2048, 1),
        &["fuzz_bin".to_owned()],
        &opts,
    );

    assert!(
        args.iter()
            .any(|arg| arg == "--ulimit=fsize=67108864:67108864"),
        "missing per-file output limit: {}",
        args.join(" ")
    );
}

#[test]
fn build_exec_args_applies_hardening_baseline() {
    let cfg = RuntimeConfig::default();
    let args = hf_runtime::docker::build_exec_args(&cfg, &limits(2048, 1), &["x".to_owned()]);
    let joined = args.join(" ");
    assert!(
        joined.contains("--network=none"),
        "missing network isolation"
    );
    assert!(joined.contains("--cap-drop=ALL"), "missing cap-drop");
    assert!(
        joined.contains("no-new-privileges"),
        "missing no-new-privileges"
    );
    assert!(joined.contains("--pids-limit=512"), "missing pids-limit");
    assert!(
        joined.contains("--memory-swap=2048m"),
        "swap must be pinned to memory to forbid swap-backed overcommit: {joined}"
    );
    assert!(
        !joined.contains("seccomp=unconfined"),
        "seccomp weakened on a normal run"
    );
}

#[test]
fn automotive_virtual_can_profile_keeps_network_isolated_and_adds_only_can_capabilities() {
    use hf_core::runtime::{SandboxCapability, SandboxNetworkMode, SandboxOptions};

    let cfg = RuntimeConfig::default();
    let options = SandboxOptions {
        network_mode: SandboxNetworkMode::None,
        capabilities: vec![SandboxCapability::NetAdmin, SandboxCapability::NetRaw],
        ..SandboxOptions::default()
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(512, 1),
        &[
            "python3".to_owned(),
            "-m".to_owned(),
            "hf_scapy_automotive".to_owned(),
        ],
        &options,
    );
    let joined = args.join(" ");

    assert!(joined.contains("--network=none"), "{joined}");
    assert!(joined.contains("--cap-drop=ALL"), "{joined}");
    assert!(joined.contains("--cap-add=NET_ADMIN"), "{joined}");
    assert!(joined.contains("--cap-add=NET_RAW"), "{joined}");
    assert!(!joined.contains("--privileged"), "{joined}");
}

#[test]
fn physical_can_profile_uses_an_explicit_host_network_without_relaxing_hardening() {
    use hf_core::runtime::{SandboxCapability, SandboxNetworkMode, SandboxOptions};

    let cfg = RuntimeConfig::default();
    let options = SandboxOptions {
        network_mode: SandboxNetworkMode::Host,
        capabilities: vec![SandboxCapability::NetRaw],
        ..SandboxOptions::default()
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(512, 1),
        &[
            "python3".to_owned(),
            "-m".to_owned(),
            "hf_scapy_automotive".to_owned(),
        ],
        &options,
    );
    let joined = args.join(" ");

    assert!(joined.contains("--network=host"), "{joined}");
    assert!(!joined.contains("--network=none"), "{joined}");
    assert!(joined.contains("--cap-drop=ALL"), "{joined}");
    assert!(joined.contains("no-new-privileges"), "{joined}");
    assert!(joined.contains("--cap-add=NET_RAW"), "{joined}");
    assert!(!joined.contains("--cap-add=NET_ADMIN"), "{joined}");
}

#[test]
fn sandbox_stdin_enables_interactive_docker_without_leaking_payload_into_arguments() {
    use hf_core::runtime::SandboxOptions;

    let cfg = RuntimeConfig::default();
    let secret_marker = "synthetic-request-not-for-command-line";
    let options = SandboxOptions {
        stdin: Some(format!(r#"{{"payload":"{secret_marker}"}}\n"#).into_bytes()),
        ..SandboxOptions::default()
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(512, 1),
        &["python3".to_owned(), "-m".to_owned(), "sidecar".to_owned()],
        &options,
    );

    assert!(args.iter().any(|argument| argument == "-i"));
    assert!(!args.join(" ").contains(secret_marker));
}

#[test]
fn specialized_sandbox_profile_can_select_a_pinned_sidecar_image() {
    use hf_core::runtime::SandboxOptions;

    let cfg = RuntimeConfig::default();
    let options = SandboxOptions {
        image: Some("oxfuzz/scapy-automotive:2.7.0".to_owned()),
        ..SandboxOptions::default()
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(512, 1),
        &["python3".to_owned(), "-m".to_owned(), "sidecar".to_owned()],
        &options,
    );
    let joined = args.join(" ");

    assert!(joined.contains("oxfuzz/scapy-automotive:2.7.0"));
    assert!(!joined.contains("oxfuzz/fuzz-sandbox:0.1.0"));
}
