//! Docker runtime: builds and runs commands inside a Docker container.
//!
//! The `DockerRuntime` adapter implements `RuntimeAdapter` by creating a
//! container from the configured image, mounting a host workspace directory,
//! exec'ing the command, and capturing stdout/stderr.
//!
//! `build_exec_args` is a pure function that constructs the `docker run`
//! argument list from a `RuntimeConfig`; it is unit-tested without a daemon.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::config::RuntimeConfig;

/// Build the `docker run` argument list for a command.
///
/// This is a pure function with no side effects, making it testable without
/// a Docker daemon.
#[must_use]
pub fn build_exec_args(cfg: &RuntimeConfig, command: &[String], timeout: Duration) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        format!("--memory={}m", cfg.default_limits.max_mem_mb),
        format!("--cpus={}", cfg.default_limits.max_cpus),
    ];

    // Timeout: pass as env var so the entrypoint can enforce it, plus a
    // label for tooling. The actual kill is done by tokio::time::timeout in
    // `DockerRuntime::run_command`.
    args.push(format!("--label=hf_timeout_secs={}", timeout.as_secs()));

    // Environment variables from the default limits.
    for (k, v) in &cfg.default_limits.env {
        args.push(format!("--env={k}={v}"));
    }

    // Workspace mount: host path -> container_workspace.
    // We use a placeholder host path here; `DockerRuntime::run_command`
    // substitutes the real cwd.
    let host_workspace = "/tmp/hobot_fuzz_workspace";
    args.push("-v".to_owned());
    args.push(format!("{host_workspace}:{}", cfg.container_workspace));

    // Working directory inside the container.
    args.push("-w".to_owned());
    args.push(cfg.container_workspace.clone());

    // Network disabled for fuzz runs by default.
    args.push("--network=none".to_owned());

    // Image.
    args.push(cfg.image.clone());

    // The command itself.
    args.extend_from_slice(command);
    args
}

/// A Docker-based sandbox runtime.
///
/// Uses `bollard` to communicate with the Docker daemon. All commands run
/// inside a container created from `RuntimeConfig::image`.
pub struct DockerRuntime {
    cfg: RuntimeConfig,
    #[allow(dead_code)]
    host_workspace: std::path::PathBuf,
}

impl DockerRuntime {
    /// Create a new `DockerRuntime`.
    ///
    /// `host_workspace` is the host directory mounted into the container at
    /// `cfg.container_workspace`.
    #[must_use]
    pub fn new(cfg: RuntimeConfig, host_workspace: &Path) -> Self {
        Self {
            cfg,
            host_workspace: host_workspace.to_path_buf(),
        }
    }
}

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};

#[async_trait]
impl RuntimeAdapter for DockerRuntime {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        use tokio::process::Command;

        let timeout = Duration::from_secs(limits.max_duration_secs);
        let mut args = build_exec_args(&self.cfg, cmd, timeout);
        // Replace the placeholder host workspace with the real cwd.
        let placeholder = "/tmp/hobot_fuzz_workspace";
        for a in &mut args {
            if a == &format!("{placeholder}:{}", self.cfg.container_workspace) {
                *a = format!("{}:{}", cwd.display(), self.cfg.container_workspace);
            }
        }

        let mut docker = Command::new(crate::docker_bin());
        docker.args(&args);
        for (k, v) in &limits.env {
            docker.env(k, v);
        }

        let output = tokio::time::timeout(timeout, docker.output())
            .await
            .map_err(|_| ClassifiedError::Sandbox("command timed out".to_owned()))?
            .map_err(|e| ClassifiedError::Sandbox(format!("docker run: {e}")))?;

        Ok(CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            workspace: cwd.to_path_buf(),
        })
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        // Write on the host within the workspace; the container mounts it.
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ClassifiedError::Sandbox(format!("mkdir: {e}")))?;
        }
        tokio::fs::write(path, content)
            .await
            .map_err(|e| ClassifiedError::Sandbox(format!("write: {e}")))?;
        Ok(())
    }

    async fn read_file(&self, path: &Path) -> Result<String, ClassifiedError> {
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| ClassifiedError::Sandbox(format!("read: {e}")))
    }
}

// HashMap is referenced in ResourceLimits env; silence unused import in
// minimal builds.
#[allow(dead_code)]
fn _ensure_hashmap_used(_m: &HashMap<String, String>) {}
