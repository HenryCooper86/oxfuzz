//! Unit tests for Docker command construction.
//!
//! These do NOT require a Docker daemon; they verify the pure logic that
//! builds container exec arguments from a `RuntimeConfig` and per-call limits.

use hf_core::runtime::ResourceLimits;
use hf_runtime::config::{RuntimeBackend, RuntimeConfig};
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
        backend: RuntimeBackend::Docker,
        image: "hobot/fuzz-sandbox:latest".to_owned(),
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
    assert!(joined.contains("hobot/fuzz-sandbox:latest"));
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
    use hf_core::runtime::SandboxOptions;
    let cfg = cfg_with(limits(4096, 4));
    let opts = SandboxOptions {
        extra_mounts: vec![
            "/host/kernel:/syzbench/kernel:ro".to_owned(),
            "/host/rootfs.img:/syzbench/rootfs.img".to_owned(),
        ],
        platform: Some("linux/amd64".to_owned()),
        network_enabled: true,
        workdir: Some("/syzbench".to_owned()),
        relax_hardening: true,
    };
    let args = hf_runtime::docker::build_exec_args_with(
        &cfg,
        &limits(4096, 4),
        &["bash".to_owned(), "-c".to_owned(), "syz-manager".to_owned()],
        &opts,
    );
    let joined = args.join(" ");
    // Platform, custom mounts, and a custom workdir are present.
    assert!(joined.contains("--platform linux/amd64"), "{joined}");
    assert!(
        joined.contains("-v /host/kernel:/syzbench/kernel:ro"),
        "{joined}"
    );
    assert!(
        joined.contains("-v /host/rootfs.img:/syzbench/rootfs.img"),
        "{joined}"
    );
    assert!(joined.contains("-w /syzbench"), "{joined}");
    // Network is enabled and the qemu-incompatible hardening is relaxed.
    assert!(
        !joined.contains("--network=none"),
        "network should be enabled: {joined}"
    );
    assert!(
        !joined.contains("--cap-drop=ALL"),
        "hardening should be relaxed: {joined}"
    );
    assert!(
        !joined.contains("no-new-privileges"),
        "hardening should be relaxed: {joined}"
    );
    // pids-limit is still applied even when hardening is relaxed.
    assert!(joined.contains("--pids-limit=512"), "{joined}");
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
        !joined.contains("seccomp=unconfined"),
        "seccomp weakened on a normal run"
    );
}
