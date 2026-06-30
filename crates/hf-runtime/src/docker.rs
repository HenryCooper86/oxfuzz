//! Docker runtime: builds and runs commands inside a Docker container.
//!
//! The `DockerRuntime` adapter implements `RuntimeAdapter` by creating a
//! container from the configured image, mounting a host workspace directory,
//! exec'ing the command, and capturing stdout/stderr.
//!
//! `build_exec_args` is a pure function that constructs the `docker run`
//! argument list from a `RuntimeConfig`; it is unit-tested without a daemon.

use std::path::Path;
use std::time::Duration;

use crate::config::RuntimeConfig;

/// Build the `docker run` argument list for a command.
///
/// This is a pure function with no side effects, making it testable without
/// a Docker daemon. Memory, CPU, duration, ptrace, and environment all come
/// from the per-call [`ResourceLimits`] so a caller can tighten the sandbox for
/// an individual run; `cfg` supplies the image, workspace, pids cap, and any
/// config-wide default environment.
#[must_use]
pub fn build_exec_args(
    cfg: &RuntimeConfig,
    limits: &hf_core::runtime::ResourceLimits,
    command: &[String],
) -> Vec<String> {
    build_exec_args_with(
        cfg,
        limits,
        command,
        &hf_core::runtime::SandboxOptions::default(),
    )
}

/// Build the `docker run` argument list, applying
/// [`SandboxOptions`](hf_core::runtime::SandboxOptions).
///
/// With its default this is identical to the hardened
/// harness/fuzz profile. Options relax or extend it for specialized runs
/// (syzkaller): extra bind mounts, a target platform, container networking, a
/// custom working directory, and a relaxed capability profile for qemu.
#[must_use]
pub fn build_exec_args_with(
    cfg: &RuntimeConfig,
    limits: &hf_core::runtime::ResourceLimits,
    command: &[String],
    opts: &hf_core::runtime::SandboxOptions,
) -> Vec<String> {
    let mut args = vec![
        "run".to_owned(),
        "--rm".to_owned(),
        format!("--memory={}m", limits.max_mem_mb),
        format!("--cpus={}", limits.max_cpus),
    ];

    // Target platform for the image (e.g. an arm64 host running a linux/amd64
    // syzkaller image under emulation).
    if let Some(platform) = &opts.platform {
        args.push("--platform".to_owned());
        args.push(platform.clone());
    }

    // Timeout: pass as a label for tooling. The actual kill is done by
    // tokio::time::timeout / the streaming deadline in `DockerRuntime`.
    args.push(format!(
        "--label=hf_timeout_secs={}",
        limits.max_duration_secs
    ));

    // Effective container environment: config-wide defaults overlaid with this
    // call's overrides. These must be `--env` flags so they reach the container;
    // setting them on the host docker CLI process (`Command::env`) would not.
    // BTreeMap keeps the flag order deterministic for tests/reproducibility.
    let mut env: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for (k, v) in &cfg.default_limits.env {
        env.insert(k.as_str(), v.as_str());
    }
    for (k, v) in &limits.env {
        env.insert(k.as_str(), v.as_str());
    }
    for (k, v) in env {
        args.push(format!("--env={k}={v}"));
    }

    // Workspace mount: host path -> container_workspace.
    // We use a placeholder host path here; `DockerRuntime::run_command`
    // substitutes the real cwd.
    let host_workspace = "/tmp/hobot_fuzz_workspace";
    args.push("-v".to_owned());
    args.push(format!("{host_workspace}:{}", cfg.container_workspace));

    // Additional bind mounts (e.g. syzkaller's kernel image / rootfs / config).
    for mount in &opts.extra_mounts {
        args.push("-v".to_owned());
        args.push(mount.clone());
    }

    // Working directory inside the container.
    args.push("-w".to_owned());
    args.push(
        opts.workdir
            .clone()
            .unwrap_or_else(|| cfg.container_workspace.clone()),
    );

    // Network: disabled for fuzz runs by default; enabled only when a run needs
    // it (syzkaller's managed VM).
    if !opts.network_enabled {
        args.push("--network=none".to_owned());
    }

    // Hardening: drop all Linux capabilities by default (re-added per-run only
    // when needed), forbid privilege escalation, and cap process count to blunt
    // fork bombs from a malicious harness. The container is also network-
    // isolated, resource-limited, and ephemeral. qemu-based runs cannot operate
    // under this profile, so it can be relaxed per-run.
    if !opts.relax_hardening {
        args.push("--cap-drop=ALL".to_owned());
        args.push("--security-opt".to_owned());
        args.push("no-new-privileges".to_owned());
    }
    args.push(format!("--pids-limit={}", cfg.max_pids));

    // CASR's crash analysis uses ptrace, which needs SYS_PTRACE and an
    // unconfined seccomp profile. Granted per-call (triage only); even then the
    // baseline cap-drop=ALL means only SYS_PTRACE is added back.
    if limits.ptrace {
        args.push("--cap-add=SYS_PTRACE".to_owned());
        args.push("--security-opt".to_owned());
        args.push("seccomp=unconfined".to_owned());
    }

    // Image.
    args.push(cfg.image.clone());

    // The command itself.
    args.extend_from_slice(command);
    args
}

/// A Docker-based sandbox runtime.
///
/// Shells out to the `docker` CLI (see [`crate::docker_bin`]) to run each
/// command inside a `--rm` container created from `RuntimeConfig::image`.
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

    /// Build the final `docker run` args for a streaming run: substitute the
    /// real `cwd` into the workspace mount and give the container a unique name
    /// (so a deadline/cancel can `docker kill` it). Returns the args and name.
    fn prepare_stream_args(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
    ) -> (Vec<String>, String) {
        let mut args = build_exec_args_with(&self.cfg, limits, cmd, opts);
        let placeholder = "/tmp/hobot_fuzz_workspace";
        for a in &mut args {
            if a == &format!("{placeholder}:{}", self.cfg.container_workspace) {
                *a = format!("{}:{}", cwd.display(), self.cfg.container_workspace);
            }
        }
        // `args[0]` is "run"; the name must precede the image/command.
        let container_name = format!("hf-run-{}", uuid::Uuid::new_v4());
        args.insert(1, format!("--name={container_name}"));
        (args, container_name)
    }

    /// Spawn `docker run` with `args` and stream stdout/stderr line-by-line to
    /// `on_line`, honoring the wall-clock `timeout` and `cancel`. On either a
    /// deadline or a cancel, `docker kill`s the named container (killing the
    /// client process alone leaves the container running). Shared by the plain
    /// and options-bearing streaming entry points.
    async fn stream_docker_run(
        &self,
        args: &[String],
        container_name: &str,
        timeout: Duration,
        cwd: &Path,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        use std::process::Stdio;
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::process::Command;

        enum Stop {
            Completed,
            Killed,
        }

        let mut docker = Command::new(crate::docker_bin());
        docker
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = docker
            .spawn()
            .map_err(|e| ClassifiedError::Sandbox(format!("docker spawn: {e}")))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ClassifiedError::Sandbox("no stdout pipe".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ClassifiedError::Sandbox("no stderr pipe".to_owned()))?;

        let mut out_lines = BufReader::new(stdout).lines();
        let mut err_lines = BufReader::new(stderr).lines();
        let mut stdout_buf = String::new();
        let mut stderr_buf = String::new();
        let mut out_done = false;
        let mut err_done = false;

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        // Read both pipes line-by-line as the command runs. libFuzzer writes its
        // progress to stderr (unbuffered in C), so this surfaces live activity.
        let stop = loop {
            if out_done && err_done {
                break Stop::Completed;
            }
            tokio::select! {
                () = &mut deadline => break Stop::Killed,
                () = cancel.cancelled() => break Stop::Killed,
                line = out_lines.next_line(), if !out_done => match line {
                    Ok(Some(l)) => {
                        on_line(l.as_str());
                        stdout_buf.push_str(&l);
                        stdout_buf.push('\n');
                    }
                    _ => out_done = true,
                },
                line = err_lines.next_line(), if !err_done => match line {
                    Ok(Some(l)) => {
                        on_line(l.as_str());
                        stderr_buf.push_str(&l);
                        stderr_buf.push('\n');
                    }
                    _ => err_done = true,
                },
            }
        };

        let exit_code = match stop {
            Stop::Completed => child.wait().await.map_or(-1, |s| s.code().unwrap_or(0)),
            Stop::Killed => {
                let kill = Command::new(crate::docker_bin())
                    .arg("kill")
                    .arg(container_name)
                    .output()
                    .await;
                if let Err(e) = kill {
                    tracing::warn!(container = %container_name, error = %e, "failed to kill stopped container");
                }
                let _ = child.start_kill();
                let _ = child.wait().await;
                0
            }
        };

        Ok(CommandResult {
            exit_code,
            stdout: stdout_buf,
            stderr: stderr_buf,
            workspace: cwd.to_path_buf(),
        })
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
        let mut args = build_exec_args(&self.cfg, limits, cmd);
        // Replace the placeholder host workspace with the real cwd.
        let placeholder = "/tmp/hobot_fuzz_workspace";
        for a in &mut args {
            if a == &format!("{placeholder}:{}", self.cfg.container_workspace) {
                *a = format!("{}:{}", cwd.display(), self.cfg.container_workspace);
            }
        }

        // Give the container a unique name so that on timeout we can explicitly
        // `docker kill` it. `args[0]` is "run"; the name flag must precede the
        // image/command, so insert it right after the subcommand.
        let container_name = format!("hf-run-{}", uuid::Uuid::new_v4());
        args.insert(1, format!("--name={container_name}"));

        let mut docker = Command::new(crate::docker_bin());
        // `kill_on_drop` reaps the `docker run` client if this future is
        // dropped; the explicit `docker kill` below stops the container itself
        // (killing the client alone leaves the container running).
        docker.args(&args).kill_on_drop(true);

        let Ok(run_result) = tokio::time::timeout(timeout, docker.output()).await else {
            // Timed out: tear down the container so it does not leak. Run the
            // kill synchronously (best effort) before returning the error.
            let kill = Command::new(crate::docker_bin())
                .arg("kill")
                .arg(&container_name)
                .output()
                .await;
            if let Err(e) = kill {
                tracing::warn!(container = %container_name, error = %e, "failed to kill timed-out container");
            }
            return Err(ClassifiedError::Sandbox("command timed out".to_owned()));
        };
        let output =
            run_result.map_err(|e| ClassifiedError::Sandbox(format!("docker run: {e}")))?;

        Ok(CommandResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            workspace: cwd.to_path_buf(),
        })
    }

    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_streaming_opts(
            cmd,
            cwd,
            limits,
            &hf_core::runtime::SandboxOptions::default(),
            cancel,
            on_line,
        )
        .await
    }

    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &hf_core::runtime::LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        // A run cancelled before it starts launches no container.
        if cancel.is_cancelled() {
            return Ok(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
            });
        }

        let timeout = Duration::from_secs(limits.max_duration_secs);
        let (args, container_name) = self.prepare_stream_args(cmd, cwd, limits, opts);
        self.stream_docker_run(&args, &container_name, timeout, cwd, cancel, on_line)
            .await
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
