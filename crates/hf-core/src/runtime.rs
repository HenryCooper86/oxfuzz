//! Runtime sandbox adapter.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::ClassifiedError;

/// Resource limits for a sandboxed command.
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub max_duration_secs: u64,
    pub env: HashMap<String, String>,
    /// Grant `SYS_PTRACE` + unconfined seccomp for this run. Needed by CASR's
    /// ptrace-based crash analysis; off by default since it weakens isolation.
    pub ptrace: bool,
}

/// How a started sandboxed command reached its terminal state.
///
/// An exit code is meaningful only for [`CommandTermination::Completed`]. A
/// deadline or explicit cancellation may force the container and Docker client
/// to exit with implementation-specific statuses, so callers must inspect this
/// value first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandTermination {
    /// The process exited without runtime intervention.
    Completed,
    /// The sandbox wall-clock limit expired and the process was terminated.
    TimedOut,
    /// The caller requested cancellation and the process was terminated.
    Cancelled,
}

/// Result of a sandboxed command execution.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub workspace: PathBuf,
    /// The authoritative reason execution stopped.
    pub termination: CommandTermination,
}

impl CommandResult {
    /// Return this result only when the process exited without runtime
    /// intervention.
    ///
    /// # Errors
    /// Returns a sandbox error for timeout or cancellation because the exit code
    /// is not authoritative in either case.
    pub fn require_completed(self, operation: &str) -> Result<Self, ClassifiedError> {
        match self.termination {
            CommandTermination::Completed => Ok(self),
            CommandTermination::TimedOut => {
                Err(ClassifiedError::Sandbox(format!("{operation} timed out")))
            }
            CommandTermination::Cancelled => Err(ClassifiedError::Sandbox(format!(
                "{operation} was cancelled"
            ))),
        }
    }
}

/// A callback invoked with each output line as a streamed command runs.
pub type LineSink<'a> = dyn Fn(&str) + Send + Sync + 'a;

/// One explicit bind mount granted to a sandboxed command.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SandboxMount {
    /// Host path. The runtime canonicalizes it and requires it to remain below
    /// the approved workspace root immediately before launch.
    pub host_path: PathBuf,
    /// Absolute path exposed inside the container.
    pub container_path: String,
    /// Whether the container receives a read-only view of this path.
    pub read_only: bool,
}

impl SandboxMount {
    /// Construct a writable bind mount.
    #[must_use]
    pub fn writable(host_path: PathBuf, container_path: impl Into<String>) -> Self {
        Self {
            host_path,
            container_path: container_path.into(),
            read_only: false,
        }
    }

    /// Construct a read-only bind mount.
    #[must_use]
    pub fn read_only(host_path: PathBuf, container_path: impl Into<String>) -> Self {
        Self {
            host_path,
            container_path: container_path.into(),
            read_only: true,
        }
    }
}

/// Extra container options for specialized runs that need more than the default
/// hardened harness/fuzz profile.
///
/// The harness/fuzz path leaves this at [`SandboxOptions::default`], which is
/// equivalent to the historical behavior: network-isolated, all capabilities
/// dropped, workspace mounted at the config's `container_workspace`. Syzkaller
/// kernel fuzzing uses service-staged bind mounts, a target `platform`, and an
/// optional `/dev/kvm` device while retaining that hardened baseline. These
/// options remain in the runtime boundary rather than letting a presentation
/// layer shell out to `docker`.
#[derive(Debug, Clone, Default)]
pub struct SandboxOptions {
    /// Additional canonicalized Docker bind mounts. Empty by default.
    pub extra_mounts: Vec<SandboxMount>,
    /// Target platform for the image (e.g. `"linux/amd64"`); maps to `--platform`.
    pub platform: Option<String>,
    /// Enable container networking. When `false` the run is `--network=none`.
    pub network_enabled: bool,
    /// Override the in-container working directory (defaults to the config's
    /// `container_workspace`).
    pub workdir: Option<String>,
    /// Skip the `cap-drop=ALL` / `no-new-privileges` baseline. Specialized
    /// callers must justify this independently; syzkaller leaves it `false`.
    pub relax_hardening: bool,
    /// Host device nodes to pass through with `--device`, e.g. `"/dev/kvm"` so
    /// an in-container qemu can use hardware virtualization. Empty by default.
    pub devices: Vec<String>,
    /// Mount the primary workspace read-only. Fuzzer execution enables this and
    /// overlays only its service-owned corpus/output directories as writable
    /// extra mounts; build flows leave it disabled.
    pub workspace_read_only: bool,
    /// Optional per-file write ceiling enforced by the container runtime.
    /// Service-level aggregate monitoring complements this limit.
    pub max_file_size_bytes: Option<u64>,
}

/// A sandboxed runtime for building harnesses and running fuzzers.
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError>;

    /// Run a non-streaming command with an explicit sandbox mount/profile.
    /// Adapters without specialized profile support may delegate to
    /// [`run_command`](Self::run_command).
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the command cannot be started or contained.
    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &ResourceLimits,
        _opts: &SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command(cmd, cwd, limits).await
    }

    /// Run a command, delivering each stdout/stderr line to `on_line` as it
    /// arrives, for live progress.
    ///
    /// The run is cooperatively cancellable: when `cancel` fires, an adapter
    /// that supports it tears down the in-flight command and returns whatever
    /// output it had streamed so far. The default implementation runs the
    /// command to completion and replays the captured output line-by-line (no
    /// live streaming, no mid-run cancellation); adapters that can stream
    /// (e.g. Docker) override this.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the command fails to run.
    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &ResourceLimits,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        // A run cancelled before it starts does no work.
        if cancel.is_cancelled() {
            return Ok(CommandResult {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
                workspace: cwd.to_path_buf(),
                termination: CommandTermination::Cancelled,
            });
        }
        let result = self.run_command(cmd, cwd, limits).await?;
        for line in result.stdout.lines().chain(result.stderr.lines()) {
            on_line(line);
        }
        Ok(result)
    }

    /// Like [`run_command_streaming`](Self::run_command_streaming) but with
    /// extra container options (custom mounts, platform, network, relaxed
    /// hardening) for specialized runs such as syzkaller.
    ///
    /// The default implementation ignores `opts` and delegates to
    /// `run_command_streaming`, so adapters that cannot honor the options
    /// (stubs, the native runtime) degrade gracefully; the Docker runtime
    /// overrides this to apply them.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the command fails to run.
    async fn run_command_streaming_opts(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &ResourceLimits,
        _opts: &SandboxOptions,
        cancel: &tokio_util::sync::CancellationToken,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_streaming(cmd, cwd, limits, cancel, on_line)
            .await
    }

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), ClassifiedError>;
    async fn read_file(&self, path: &std::path::Path) -> Result<String, ClassifiedError>;
}

#[cfg(test)]
mod tests {
    use super::{CommandResult, CommandTermination};

    #[test]
    fn command_result_requires_an_explicit_terminal_outcome() {
        let result = CommandResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
            workspace: std::path::PathBuf::from("/work"),
            termination: CommandTermination::TimedOut,
        };

        assert_eq!(result.termination, CommandTermination::TimedOut);
        assert!(result.require_completed("test command").is_err());
    }
}
