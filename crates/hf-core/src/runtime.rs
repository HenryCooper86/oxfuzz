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

/// A runtime image pinned by its exact Docker-compatible content ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImmutableImageReference {
    reference: String,
    sha256: String,
}

impl ImmutableImageReference {
    /// Validate and retain a `sha256:<64 lowercase hex>` image ID.
    ///
    /// # Errors
    /// Returns a sandbox error when `reference` is mutable or malformed.
    pub fn from_sha256_id(reference: impl Into<String>) -> Result<Self, ClassifiedError> {
        let reference = reference.into();
        let Some(sha256) = reference.strip_prefix("sha256:") else {
            return Err(ClassifiedError::Sandbox(
                "runtime image identity is not content-addressed".to_owned(),
            ));
        };
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ClassifiedError::Sandbox(
                "runtime image identity has an invalid SHA-256 digest".to_owned(),
            ));
        }
        Ok(Self {
            sha256: sha256.to_owned(),
            reference,
        })
    }

    /// Exact reference passed to the runtime command.
    #[must_use]
    pub fn reference(&self) -> &str {
        &self.reference
    }

    /// Lowercase SHA-256 identity persisted as provenance.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

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

/// Network namespace exposed to a sandboxed command.
///
/// The default is [`Self::None`]. Automotive physical-bench operations are the
/// only current consumer of [`Self::Host`], and the service must approve that
/// exceptional profile before it reaches the runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SandboxNetworkMode {
    /// No container network devices other than loopback (`--network=none`).
    #[default]
    None,
    /// Docker's isolated bridge network.
    Bridge,
    /// The host network namespace (`--network=host`).
    Host,
}

/// A Linux capability that may be added back after the sandbox drops all
/// capabilities.
///
/// This deliberately small enum prevents presentation or domain code from
/// passing arbitrary capability strings to Docker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SandboxCapability {
    /// Create and configure an isolated virtual network device such as vcan.
    NetAdmin,
    /// Open raw packet or CAN sockets.
    NetRaw,
}

impl SandboxCapability {
    /// Docker capability name.
    #[must_use]
    pub const fn as_docker_name(self) -> &'static str {
        match self {
            Self::NetAdmin => "NET_ADMIN",
            Self::NetRaw => "NET_RAW",
        }
    }
}

/// Render a relative host path with `/` separators regardless of the host.
///
/// `Path::display` keeps `\` on Windows, which is wrong everywhere the string
/// leaves the host's path rules: the Linux sandbox reads it as part of a file
/// name rather than as a separator, and durable records or SARIF URIs built
/// from it stop meaning the same path on another machine. `path` must already
/// be relative; callers compose the result onto a POSIX base such as `/work`.
#[must_use]
pub fn posix_relative(path: &std::path::Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether `value` is the fixed sandbox workspace or one canonical descendant.
///
/// This accepts only POSIX spellings that cannot escape `/work`: components
/// must be non-empty normal names, so dot segments, duplicate separators,
/// trailing separators, and backslashes are rejected before a path API can
/// normalize them.
#[must_use]
pub fn is_fixed_sandbox_include_path(value: &str) -> bool {
    if value == "/work" {
        return true;
    }
    let Some(descendant) = value.strip_prefix("/work/") else {
        return false;
    };
    !descendant.is_empty()
        && !value.contains('\\')
        && descendant.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && !component.chars().any(char::is_control)
        })
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
    /// Optional pinned image selected by a service-owned specialized adapter.
    /// The runtime validates its syntax and rejects unpinned `latest` values.
    pub image: Option<String>,
    /// Target platform for the image (e.g. `"linux/amd64"`); maps to `--platform`.
    pub platform: Option<String>,
    /// Network namespace exposed to the container. Defaults to no network.
    pub network_mode: SandboxNetworkMode,
    /// Override the in-container working directory (defaults to the config's
    /// `container_workspace`).
    pub workdir: Option<String>,
    /// Skip the `cap-drop=ALL` / `no-new-privileges` baseline. Specialized
    /// callers must justify this independently; syzkaller leaves it `false`.
    pub relax_hardening: bool,
    /// Minimal capabilities added back after `--cap-drop=ALL`.
    pub capabilities: Vec<SandboxCapability>,
    /// Optional bytes delivered to the container process over stdin. The
    /// runtime applies a hard size ceiling and never places these bytes in the
    /// Docker argument list.
    pub stdin: Option<Vec<u8>>,
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
    /// Optional process-count ceiling for a specialized profile. The runtime
    /// accepts only values that tighten the configured sandbox limit.
    pub max_pids: Option<u32>,
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

    /// Whether `image` is available to run (loaded locally).
    ///
    /// Defaults to `true` so adapters without an image concept (native/stub) and
    /// test doubles never block execution. The Docker adapter overrides this to
    /// actually check, letting callers fail fast with an actionable message when
    /// an optional image (e.g. the automotive sidecar) has not been built, rather
    /// than surfacing a raw "no such image" from the run.
    async fn image_present(&self, _image: &str) -> bool {
        true
    }

    /// Resolve a configured image name to the immutable reference that the
    /// runtime will execute.
    ///
    /// Adapters without an image concept return `None`. Proof-carrying callers
    /// fail closed on that result. Container runtimes must return a validated
    /// content-addressed reference and fail when the image cannot be resolved.
    async fn resolve_image_reference(
        &self,
        _image: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        Ok(None)
    }

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
    use super::{
        is_fixed_sandbox_include_path, posix_relative, CommandResult, CommandTermination,
        ImmutableImageReference,
    };

    #[test]
    fn fixed_sandbox_include_paths_require_canonical_work_descendants() {
        for accepted in ["/work", "/work/include", "/work/a/b"] {
            assert!(
                is_fixed_sandbox_include_path(accepted),
                "must accept {accepted}"
            );
        }
        for rejected in [
            "/work/../etc",
            "/work/./include",
            "/work//include",
            "/work/include/",
            "/work\\include",
            "/workx/include",
            "/work/",
        ] {
            assert!(
                !is_fixed_sandbox_include_path(rejected),
                "must reject {rejected}"
            );
        }
    }

    #[test]
    fn posix_relative_joins_components_with_forward_slashes() {
        // Built with Path::join so the host's native separator is exercised:
        // on Windows this is `corpus\c` and must still render as `corpus/c`.
        let path = std::path::PathBuf::from("corpus").join("c");
        assert_eq!(posix_relative(&path), "corpus/c");
        assert_eq!(posix_relative(std::path::Path::new("single")), "single");
    }

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

    #[test]
    fn immutable_image_reference_requires_a_lowercase_sha256_id() {
        let valid = format!("sha256:{}", "a".repeat(64));
        let identity = ImmutableImageReference::from_sha256_id(valid.clone()).unwrap();
        assert_eq!(identity.reference(), valid);
        assert_eq!(identity.sha256(), "a".repeat(64));

        assert!(ImmutableImageReference::from_sha256_id("repo/image:1.0").is_err());
        assert!(
            ImmutableImageReference::from_sha256_id(format!("sha256:{}", "A".repeat(64))).is_err()
        );
    }
}
