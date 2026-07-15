//! Docker runtime: builds and runs commands inside a Docker container.
//!
//! The `DockerRuntime` adapter implements `RuntimeAdapter` by creating a
//! container from the configured image, mounting a host workspace directory,
//! exec'ing the command, and capturing stdout/stderr.
//!
//! `build_exec_args` is a pure function that constructs the `docker run`
//! argument list from a `RuntimeConfig`; it is unit-tested without a daemon.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use crate::config::RuntimeConfig;

/// Outcome of reading one line from a streamed pipe.
enum LineRead {
    /// A decoded line to forward.
    Line(String),
    /// An unreadable line (non-UTF-8 or a transient interruption): drop it but
    /// keep reading the pipe.
    Skip,
    /// End of the stream (clean EOF or a hard read error).
    Eof,
}

/// Classify one `next_line()` result. A fuzzed target can emit raw bytes on
/// stdout/stderr; `tokio`'s line reader surfaces those as `InvalidData`. Folding
/// that into EOF (as a bare `_ => done`) would stop reading the pipe for the
/// rest of the campaign and silently drop later crash/coverage lines, so a
/// non-UTF-8 or interrupted read is skipped rather than treated as the end.
fn classify_line_read(line: std::io::Result<Option<String>>) -> LineRead {
    match line {
        Ok(Some(l)) => LineRead::Line(l),
        Err(e)
            if e.kind() == std::io::ErrorKind::InvalidData
                || e.kind() == std::io::ErrorKind::Interrupted =>
        {
            LineRead::Skip
        }
        // A clean EOF or a hard read error (e.g. a broken pipe) both end it.
        Ok(None) | Err(_) => LineRead::Eof,
    }
}

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

    // Host device passthrough (e.g. `/dev/kvm` for hardware-accelerated qemu).
    for device in &opts.devices {
        args.push(format!("--device={device}"));
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
    host_workspace: PathBuf,
}

impl DockerRuntime {
    /// Create a new `DockerRuntime`.
    ///
    /// `host_workspace` is the host directory mounted into the container at
    /// `cfg.container_workspace`.
    #[must_use]
    pub fn new(cfg: RuntimeConfig, host_workspace: &Path) -> Self {
        let host_workspace = if host_workspace.is_absolute() {
            host_workspace.to_path_buf()
        } else {
            std::env::current_dir().map_or_else(
                |_| host_workspace.to_path_buf(),
                |current| current.join(host_workspace),
            )
        };
        Self {
            cfg,
            host_workspace,
        }
    }

    /// Resolve the configured workspace root through the host filesystem.
    fn canonical_workspace_root(&self) -> Result<PathBuf, ClassifiedError> {
        std::fs::canonicalize(&self.host_workspace).map_err(|e| {
            ClassifiedError::Sandbox(format!(
                "approved workspace {} is unavailable: {e}",
                self.host_workspace.display()
            ))
        })
    }

    /// Convert a caller path to an absolute path without resolving symlinks.
    fn absolute_path(path: &Path) -> Result<PathBuf, ClassifiedError> {
        if path.components().any(|part| part == Component::ParentDir) {
            return Err(ClassifiedError::Sandbox(format!(
                "workspace path contains parent traversal: {}",
                path.display()
            )));
        }
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|e| ClassifiedError::Sandbox(format!("resolve current directory: {e}")))
    }

    /// Prove that an existing host path resolves inside the approved workspace.
    fn confined_existing_path(&self, path: &Path) -> Result<PathBuf, ClassifiedError> {
        let absolute = Self::absolute_path(path)?;
        let root = self.canonical_workspace_root()?;
        let resolved = std::fs::canonicalize(&absolute).map_err(|e| {
            ClassifiedError::Sandbox(format!(
                "workspace path {} is unavailable: {e}",
                absolute.display()
            ))
        })?;
        if resolved == root || resolved.starts_with(&root) {
            Ok(resolved)
        } else {
            Err(ClassifiedError::Sandbox(format!(
                "workspace path {} resolves outside approved root {}",
                absolute.display(),
                root.display()
            )))
        }
    }

    /// Prove that a possibly-missing write path is inside the approved root.
    ///
    /// The nearest existing ancestor is canonicalized so a symlinked directory
    /// cannot redirect a later `create_dir_all` or file write outside the root.
    fn confined_write_path(&self, path: &Path) -> Result<PathBuf, ClassifiedError> {
        let absolute = Self::absolute_path(path)?;
        let root = self.canonical_workspace_root()?;
        let mut ancestor = absolute.as_path();
        loop {
            match std::fs::symlink_metadata(ancestor) {
                Ok(_) => break,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    ancestor = ancestor.parent().ok_or_else(|| {
                        ClassifiedError::Sandbox(format!(
                            "workspace path has no existing ancestor: {}",
                            absolute.display()
                        ))
                    })?;
                }
                Err(error) => {
                    return Err(ClassifiedError::Sandbox(format!(
                        "inspect workspace ancestor {}: {error}",
                        ancestor.display()
                    )));
                }
            }
        }
        let resolved_ancestor = std::fs::canonicalize(ancestor).map_err(|e| {
            ClassifiedError::Sandbox(format!(
                "workspace ancestor {} is unavailable: {e}",
                ancestor.display()
            ))
        })?;
        if resolved_ancestor == root || resolved_ancestor.starts_with(&root) {
            Ok(absolute)
        } else {
            Err(ClassifiedError::Sandbox(format!(
                "workspace path {} resolves outside approved root {}",
                absolute.display(),
                root.display()
            )))
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
                line = out_lines.next_line(), if !out_done => match classify_line_read(line) {
                    LineRead::Line(l) => {
                        on_line(l.as_str());
                        stdout_buf.push_str(&l);
                        stdout_buf.push('\n');
                    }
                    LineRead::Skip => {}
                    LineRead::Eof => out_done = true,
                },
                line = err_lines.next_line(), if !err_done => match classify_line_read(line) {
                    LineRead::Line(l) => {
                        on_line(l.as_str());
                        stderr_buf.push_str(&l);
                        stderr_buf.push('\n');
                    }
                    LineRead::Skip => {}
                    LineRead::Eof => err_done = true,
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

        let cwd = self.confined_existing_path(cwd)?;
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
            workspace: cwd,
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
        let cwd = self.confined_existing_path(cwd)?;
        // A run cancelled before it starts launches no container.
        if cancel.is_cancelled() {
            return Ok(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd,
            });
        }

        let timeout = Duration::from_secs(limits.max_duration_secs);
        let (args, container_name) = self.prepare_stream_args(cmd, &cwd, limits, opts);
        self.stream_docker_run(&args, &container_name, timeout, &cwd, cancel, on_line)
            .await
    }

    async fn write_file(&self, path: &Path, content: &str) -> Result<(), ClassifiedError> {
        // Write on the host within the workspace; the container mounts it.
        let path = self.confined_write_path(path)?;
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
        let path = self.confined_existing_path(path)?;
        tokio::fs::read_to_string(path)
            .await
            .map_err(|e| ClassifiedError::Sandbox(format!("read: {e}")))
    }
}

#[cfg(test)]
mod line_read_tests {
    use super::{classify_line_read, LineRead};
    use std::io::{Error, ErrorKind};

    #[test]
    fn decoded_line_is_forwarded() {
        assert!(matches!(
            classify_line_read(Ok(Some("crash-0".to_owned()))),
            LineRead::Line(l) if l == "crash-0"
        ));
    }

    #[test]
    fn clean_eof_ends_the_stream() {
        assert!(matches!(classify_line_read(Ok(None)), LineRead::Eof));
    }

    #[test]
    fn non_utf8_line_is_skipped_not_ended() {
        // A raw byte on the fuzzer's output must not stop capture, or later
        // crash/coverage lines would be lost.
        let err = Err(Error::new(
            ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        ));
        assert!(matches!(classify_line_read(err), LineRead::Skip));
    }

    #[test]
    fn hard_read_error_ends_the_stream() {
        let err = Err(Error::new(ErrorKind::BrokenPipe, "pipe closed"));
        assert!(matches!(classify_line_read(err), LineRead::Eof));
    }
}
