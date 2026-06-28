//! Unit tests for Docker command construction.
//!
//! These do NOT require a Docker daemon; they verify the pure logic that
//! builds container exec arguments from a `RuntimeConfig`.

use hf_core::runtime::ResourceLimits;
use hf_runtime::config::{RuntimeBackend, RuntimeConfig};
use std::collections::HashMap;
use std::time::Duration;

#[test]
fn build_exec_args_includes_image_and_command() {
    let cfg = RuntimeConfig {
        backend: RuntimeBackend::Docker,
        image: "hobot/fuzz-sandbox:latest".to_owned(),
        container_workspace: "/work".to_owned(),
        default_limits: ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 7200,
            env: HashMap::new(),
            ptrace: false,
        },
        max_pids: 512,
    };
    let args = hf_runtime::docker::build_exec_args(
        &cfg,
        &["clang".to_owned(), "--version".to_owned()],
        Duration::from_mins(1),
        false,
    );
    // Must contain the image and the command tokens.
    let joined = args.join(" ");
    assert!(joined.contains("hobot/fuzz-sandbox:latest"));
    assert!(joined.contains("clang"));
    assert!(joined.contains("--version"));
}

#[test]
fn build_exec_args_applies_memory_and_cpu_limits() {
    let cfg = RuntimeConfig {
        backend: RuntimeBackend::Docker,
        image: "img".to_owned(),
        container_workspace: "/work".to_owned(),
        default_limits: ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 4,
            max_duration_secs: 3600,
            env: HashMap::new(),
            ptrace: false,
        },
        max_pids: 512,
    };
    let args = hf_runtime::docker::build_exec_args(
        &cfg,
        &["echo".to_owned(), "hi".to_owned()],
        Duration::from_secs(30),
        false,
    );
    let joined = args.join(" ");
    assert!(
        joined.contains("--memory=2048m"),
        "missing memory limit: {joined}"
    );
    assert!(joined.contains("--cpus=4"), "missing cpu limit: {joined}");
}

#[test]
fn build_exec_args_mounts_workspace() {
    let cfg = RuntimeConfig {
        backend: RuntimeBackend::Docker,
        image: "img".to_owned(),
        container_workspace: "/work".to_owned(),
        default_limits: ResourceLimits {
            max_mem_mb: 1024,
            max_cpus: 1,
            max_duration_secs: 60,
            env: HashMap::new(),
            ptrace: false,
        },
        max_pids: 512,
    };
    let args = hf_runtime::docker::build_exec_args(
        &cfg,
        &["ls".to_owned()],
        Duration::from_secs(10),
        false,
    );
    let joined = args.join(" ");
    assert!(joined.contains("-v"), "missing volume flag: {joined}");
    assert!(joined.contains(":/work"), "missing mount target: {joined}");
}

#[test]
fn build_exec_args_adds_ptrace_caps_when_requested() {
    let cfg = RuntimeConfig {
        backend: RuntimeBackend::Docker,
        image: "img".to_owned(),
        container_workspace: "/work".to_owned(),
        default_limits: ResourceLimits {
            max_mem_mb: 2048,
            max_cpus: 1,
            max_duration_secs: 60,
            env: HashMap::new(),
            ptrace: false,
        },
        max_pids: 512,
    };
    let with =
        hf_runtime::docker::build_exec_args(&cfg, &["x".to_owned()], Duration::from_secs(5), true);
    let joined = with.join(" ");
    assert!(
        joined.contains("--cap-add=SYS_PTRACE"),
        "missing SYS_PTRACE: {joined}"
    );
    assert!(
        joined.contains("seccomp=unconfined"),
        "missing seccomp: {joined}"
    );

    let without =
        hf_runtime::docker::build_exec_args(&cfg, &["x".to_owned()], Duration::from_secs(5), false);
    assert!(
        !without.join(" ").contains("SYS_PTRACE"),
        "ptrace caps leaked when not requested"
    );
}

#[test]
fn build_exec_args_applies_hardening_baseline() {
    let cfg = RuntimeConfig::default();
    let args =
        hf_runtime::docker::build_exec_args(&cfg, &["x".to_owned()], Duration::from_secs(5), false);
    let joined = args.join(" ");
    assert!(joined.contains("--network=none"), "missing network isolation");
    assert!(joined.contains("--cap-drop=ALL"), "missing cap-drop");
    assert!(joined.contains("no-new-privileges"), "missing no-new-privileges");
    assert!(joined.contains("--pids-limit=512"), "missing pids-limit");
    // Baseline (non-triage) must NOT weaken seccomp.
    assert!(
        !joined.contains("seccomp=unconfined"),
        "seccomp weakened on a normal run"
    );
}
