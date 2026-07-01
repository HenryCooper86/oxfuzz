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

/// Result of a sandboxed command execution.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub workspace: PathBuf,
}

/// A callback invoked with each output line as a streamed command runs.
pub type LineSink<'a> = dyn Fn(&str) + Send + Sync + 'a;

/// Extra container options for specialized runs that need more than the default
/// hardened harness/fuzz profile.
///
/// The harness/fuzz path leaves this at [`SandboxOptions::default`], which is
/// equivalent to the historical behavior: network-isolated, all capabilities
/// dropped, workspace mounted at the config's `container_workspace`. Syzkaller
/// kernel fuzzing needs custom bind mounts (kernel image, rootfs, config), a
/// target `platform`, network access for the managed VM, and a relaxed
/// capability profile for qemu -- expressed here rather than by shelling out to
/// `docker` from a presentation layer.
#[derive(Debug, Clone, Default)]
pub struct SandboxOptions {
    /// Additional raw `-v` bind-mount specs, e.g. `"/host/path:/in/container:ro"`.
    pub extra_mounts: Vec<String>,
    /// Target platform for the image (e.g. `"linux/amd64"`); maps to `--platform`.
    pub platform: Option<String>,
    /// Enable container networking. When `false` the run is `--network=none`.
    pub network_enabled: bool,
    /// Override the in-container working directory (defaults to the config's
    /// `container_workspace`).
    pub workdir: Option<String>,
    /// Skip the `cap-drop=ALL` / `no-new-privileges` baseline. Required for
    /// qemu-based syzkaller runs; leave `false` for everything else.
    pub relax_hardening: bool,
    /// Host device nodes to pass through with `--device`, e.g. `"/dev/kvm"` so
    /// an in-container qemu can use hardware virtualization. Empty by default.
    pub devices: Vec<String>,
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
