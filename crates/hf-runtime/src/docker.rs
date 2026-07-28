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

/// Maximum bytes retained independently for stdout and stderr.
const MAX_CAPTURED_OUTPUT_BYTES: usize = 1024 * 1024;
/// Maximum bytes retained for one streamed line before discarding until `\n`.
const MAX_STREAM_LINE_BYTES: usize = 64 * 1024;
const OUTPUT_TRUNCATION_MARKER: &str = "\n[output truncated]\n";
const LINE_TRUNCATION_MARKER: &str = " [line truncated]";
const PIPE_CHUNK_BYTES: usize = 8 * 1024;
const MAX_STDIN_BYTES: usize = 4 * 1024 * 1024;
const CONTAINER_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

fn valid_pinned_image_reference(image: &str) -> bool {
    if image.is_empty()
        || image.len() > 256
        // The reference is emitted verbatim into the `docker run` argv; a
        // leading `-` would be parsed as a docker CLI flag instead of an
        // image, voiding the pinned-image guarantee.
        || image.starts_with('-')
        || !image.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'@')
        })
    {
        return false;
    }
    if let Some((name, digest)) = image.rsplit_once("@sha256:") {
        return !name.is_empty()
            && digest.len() == 64
            && digest.bytes().all(|byte| byte.is_ascii_hexdigit());
    }
    image.rsplit_once(':').is_some_and(|(name, tag)| {
        !name.is_empty() && !tag.is_empty() && tag != "latest" && !tag.contains('/')
    })
}

/// Best-effort cleanup when an in-flight runtime future is dropped or aborted.
/// The Docker CLI child has `kill_on_drop`, but killing that client alone does
/// not stop the named container it launched.
struct ContainerCleanupGuard {
    name: String,
    armed: bool,
}

impl ContainerCleanupGuard {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ContainerCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = std::process::Command::new(crate::docker_bin())
            .args(["rm", "-f", &self.name])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
}

/// A byte buffer that retains a fixed prefix and records discarded output.
struct BoundedOutput {
    head: Vec<u8>,
    tail: Vec<u8>,
    limit: usize,
    received: usize,
    truncated: bool,
}

impl BoundedOutput {
    fn new(limit: usize) -> Self {
        Self {
            head: Vec::with_capacity(limit.min(PIPE_CHUNK_BYTES)),
            tail: Vec::with_capacity(limit.min(PIPE_CHUNK_BYTES)),
            limit,
            received: 0,
            truncated: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) {
        self.received = self.received.saturating_add(bytes.len());
        let data_limit = self.limit.saturating_sub(OUTPUT_TRUNCATION_MARKER.len());
        let head_limit = data_limit / 2;
        let tail_limit = data_limit.saturating_sub(head_limit);
        let head_keep = head_limit.saturating_sub(self.head.len()).min(bytes.len());
        self.head.extend_from_slice(&bytes[..head_keep]);
        let remaining = &bytes[head_keep..];

        if !remaining.is_empty() && tail_limit > 0 {
            if remaining.len() >= tail_limit {
                self.tail.clear();
                self.tail
                    .extend_from_slice(&remaining[remaining.len() - tail_limit..]);
            } else {
                let overflow = self
                    .tail
                    .len()
                    .saturating_add(remaining.len())
                    .saturating_sub(tail_limit);
                if overflow > 0 {
                    self.tail.drain(..overflow.min(self.tail.len()));
                }
                self.tail.extend_from_slice(remaining);
            }
        }
        self.truncated = self.received > data_limit;
    }

    fn finish(self) -> String {
        let mut bytes = self.head;
        if self.truncated {
            bytes.extend_from_slice(OUTPUT_TRUNCATION_MARKER.as_bytes());
        }
        bytes.extend_from_slice(&self.tail);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

/// Bounded output capture plus chunk-to-line framing for live callbacks.
struct StreamOutput {
    captured: BoundedOutput,
    pending_line: Vec<u8>,
    max_line_bytes: usize,
    line_truncated: bool,
}

impl StreamOutput {
    fn new(capture_limit: usize, max_line_bytes: usize) -> Self {
        Self {
            captured: BoundedOutput::new(capture_limit),
            pending_line: Vec::with_capacity(max_line_bytes.min(PIPE_CHUNK_BYTES)),
            max_line_bytes,
            line_truncated: false,
        }
    }

    fn push(&mut self, bytes: &[u8], on_line: &mut dyn FnMut(&str)) {
        self.captured.push(bytes);
        let mut remaining = bytes;
        while let Some(newline) = remaining.iter().position(|byte| *byte == b'\n') {
            self.push_line_part(&remaining[..newline]);
            self.emit_line(on_line);
            remaining = &remaining[newline + 1..];
        }
        self.push_line_part(remaining);
    }

    fn push_line_part(&mut self, bytes: &[u8]) {
        let available = self.max_line_bytes.saturating_sub(self.pending_line.len());
        let keep = available.min(bytes.len());
        self.pending_line.extend_from_slice(&bytes[..keep]);
        self.line_truncated |= keep < bytes.len();
    }

    fn emit_line(&mut self, on_line: &mut dyn FnMut(&str)) {
        if self.pending_line.last() == Some(&b'\r') {
            self.pending_line.pop();
        }
        let mut line = String::from_utf8_lossy(&self.pending_line).into_owned();
        if self.line_truncated {
            line.push_str(LINE_TRUNCATION_MARKER);
        }
        on_line(&line);
        self.pending_line.clear();
        self.line_truncated = false;
    }

    fn finish(mut self, on_line: &mut dyn FnMut(&str)) -> String {
        if !self.pending_line.is_empty() || self.line_truncated {
            self.emit_line(on_line);
        }
        self.captured.finish()
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
/// (syzkaller): extra bind mounts, a target platform, an optional device, and a
/// custom working directory. The syzkaller service profile keeps network and
/// capability hardening enabled.
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
        // Pin swap to the memory ceiling so Docker does not default `--memory-swap`
        // to 2x memory (which would silently grant a malicious harness extra
        // swap-backed memory beyond the intended cap).
        format!("--memory-swap={}m", limits.max_mem_mb),
        format!("--cpus={}", limits.max_cpus),
    ];

    if opts.stdin.is_some() {
        args.push("-i".to_owned());
    }

    if let Some(bytes) = opts.max_file_size_bytes {
        args.push(format!("--ulimit=fsize={bytes}:{bytes}"));
    }

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
    let host_workspace = "/tmp/oxfuzz_workspace";
    args.push("-v".to_owned());
    let read_only = if opts.workspace_read_only { ":ro" } else { "" };
    args.push(format!(
        "{host_workspace}:{}{read_only}",
        cfg.container_workspace
    ));

    // Additional structured bind mounts. Runtime execution canonicalizes every
    // source under the approved workspace before this argument list is used.
    for mount in &opts.extra_mounts {
        args.push("--mount".to_owned());
        args.push(format!(
            "type=bind,source={},target={}{}",
            mount.host_path.display(),
            mount.container_path,
            if mount.read_only { ",readonly" } else { "" }
        ));
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

    // Network access is explicit. qemu user networking for syzkaller operates
    // inside the default `none` boundary and does not require a Docker network.
    match opts.network_mode {
        hf_core::runtime::SandboxNetworkMode::None => {
            args.push("--network=none".to_owned());
        }
        hf_core::runtime::SandboxNetworkMode::Bridge => {
            args.push("--network=bridge".to_owned());
        }
        hf_core::runtime::SandboxNetworkMode::Host => {
            args.push("--network=host".to_owned());
        }
    }

    // Hardening: drop all Linux capabilities by default (re-added per-run only
    // when needed), forbid privilege escalation, and cap process count to blunt
    // fork bombs from a malicious harness. The container is also network-
    // isolated, resource-limited, and ephemeral. Any relaxation remains an
    // explicit exceptional option; the qemu-based syzkaller profile keeps it.
    if !opts.relax_hardening {
        args.push("--cap-drop=ALL".to_owned());
        args.push("--security-opt".to_owned());
        args.push("no-new-privileges".to_owned());
    }
    let capabilities = opts
        .capabilities
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    for capability in capabilities {
        args.push(format!("--cap-add={}", capability.as_docker_name()));
    }
    args.push(format!(
        "--pids-limit={}",
        opts.max_pids.unwrap_or(cfg.max_pids)
    ));

    // CASR's crash analysis uses ptrace, which needs SYS_PTRACE and an
    // unconfined seccomp profile. Granted per-call (triage only); even then the
    // baseline cap-drop=ALL means only SYS_PTRACE is added back.
    if limits.ptrace {
        args.push("--cap-add=SYS_PTRACE".to_owned());
        args.push("--security-opt".to_owned());
        args.push("seccomp=unconfined".to_owned());
    }

    // Image.
    args.push(opts.image.clone().unwrap_or_else(|| cfg.image.clone()));

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

    /// Canonicalize and validate every extra bind mount before Docker sees it.
    ///
    /// # Errors
    /// Returns a sandbox error when a source escapes the approved workspace,
    /// is not a regular file/directory, or the container target is unsafe.
    pub fn validate_sandbox_options(
        &self,
        opts: &hf_core::runtime::SandboxOptions,
    ) -> Result<hf_core::runtime::SandboxOptions, ClassifiedError> {
        if let Some(max_pids) = opts.max_pids {
            if max_pids == 0 || max_pids > self.cfg.max_pids {
                return Err(ClassifiedError::Sandbox(format!(
                    "sandbox PID limit must be between 1 and {}",
                    self.cfg.max_pids
                )));
            }
        }
        if opts
            .image
            .as_deref()
            .is_some_and(|image| !valid_pinned_image_reference(image))
        {
            return Err(ClassifiedError::Sandbox(
                "sandbox image override must be a pinned, safe image reference".to_owned(),
            ));
        }
        if opts
            .stdin
            .as_ref()
            .is_some_and(|stdin| stdin.len() > MAX_STDIN_BYTES)
        {
            return Err(ClassifiedError::Sandbox(format!(
                "sandbox stdin exceeds the {MAX_STDIN_BYTES}-byte limit"
            )));
        }
        let mut validated = opts.clone();
        for mount in &mut validated.extra_mounts {
            let container_path = Path::new(&mount.container_path);
            if mount.container_path.contains(',')
                || mount.container_path.contains('\0')
                || !container_path.is_absolute()
                || !container_path
                    .components()
                    .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
            {
                return Err(ClassifiedError::Sandbox(format!(
                    "invalid container mount target: {}",
                    mount.container_path
                )));
            }
            if mount.host_path.to_string_lossy().contains(',') {
                return Err(ClassifiedError::Sandbox(format!(
                    "host mount path contains an unsupported comma: {}",
                    mount.host_path.display()
                )));
            }
            let resolved = self.confined_existing_path(&mount.host_path)?;
            let metadata = std::fs::metadata(&resolved).map_err(|e| {
                ClassifiedError::Sandbox(format!(
                    "inspect mount source {}: {e}",
                    resolved.display()
                ))
            })?;
            if !(metadata.is_file() || metadata.is_dir())
                || (!mount.read_only && !metadata.is_dir())
            {
                return Err(ClassifiedError::Sandbox(format!(
                    "mount source must be a regular {}: {}",
                    if mount.read_only {
                        "file or directory"
                    } else {
                        "directory"
                    },
                    resolved.display()
                )));
            }
            // Re-check the RESOLVED path: `confined_existing_path` follows
            // symlinks, so a benign-looking source may canonicalize to a path
            // whose name embeds a comma (or NUL). Because the resolved path is
            // what gets emitted verbatim as the comma-delimited
            // `--mount type=bind,source=...` value, an unchecked comma there
            // would inject arbitrary mount options.
            let resolved_str = resolved.to_string_lossy();
            if resolved_str.contains(',') || resolved_str.contains('\0') {
                return Err(ClassifiedError::Sandbox(format!(
                    "resolved host mount path contains an unsupported delimiter: {}",
                    resolved.display()
                )));
            }
            mount.host_path = resolved;
        }
        Ok(validated)
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
    ) -> Result<(Vec<String>, String), ClassifiedError> {
        // The workspace mount uses `-v` short syntax, which Docker splits on
        // `:` into source/target/mode. A colon in the resolved host cwd would
        // corrupt that split (redirecting the mount target or mode), so reject
        // it before substituting the real path into the mount argument.
        if cwd.to_string_lossy().contains(':') {
            return Err(ClassifiedError::Sandbox(format!(
                "workspace path contains an unsupported ':' delimiter: {}",
                cwd.display()
            )));
        }
        let mut args = build_exec_args_with(&self.cfg, limits, cmd, opts);
        let placeholder = "/tmp/oxfuzz_workspace";
        let placeholder_mount = format!(
            "{placeholder}:{}{}",
            self.cfg.container_workspace,
            if opts.workspace_read_only { ":ro" } else { "" }
        );
        for a in &mut args {
            if a == &placeholder_mount {
                *a = format!(
                    "{}:{}{}",
                    cwd.display(),
                    self.cfg.container_workspace,
                    if opts.workspace_read_only { ":ro" } else { "" }
                );
            }
        }
        // `args[0]` is "run"; the name must precede the image/command.
        let container_name = format!("hf-run-{}", uuid::Uuid::new_v4());
        args.insert(1, format!("--name={container_name}"));
        Ok((args, container_name))
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
        stdin: Option<&[u8]>,
    ) -> Result<CommandResult, ClassifiedError> {
        use std::process::Stdio;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::process::Command;

        enum Stop {
            Completed,
            TimedOut,
            Cancelled,
            Failed(String),
        }

        let mut docker = Command::new(crate::docker_bin());
        docker
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = docker
            .spawn()
            .map_err(|e| ClassifiedError::Sandbox(format!("docker spawn: {e}")))?;
        let child_stdin = if stdin.is_some() {
            Some(
                child
                    .stdin
                    .take()
                    .ok_or_else(|| ClassifiedError::Sandbox("no stdin pipe".to_owned()))?,
            )
        } else {
            None
        };
        let mut cleanup = ContainerCleanupGuard::new(container_name);
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| ClassifiedError::Sandbox("no stdout pipe".to_owned()))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| ClassifiedError::Sandbox("no stderr pipe".to_owned()))?;

        let mut out_chunk = [0_u8; PIPE_CHUNK_BYTES];
        let mut err_chunk = [0_u8; PIPE_CHUNK_BYTES];
        let mut stdout_buf = StreamOutput::new(MAX_CAPTURED_OUTPUT_BYTES, MAX_STREAM_LINE_BYTES);
        let mut stderr_buf = StreamOutput::new(MAX_CAPTURED_OUTPUT_BYTES, MAX_STREAM_LINE_BYTES);
        let mut out_done = false;
        let mut err_done = false;
        let mut stdin_done = false;
        let stdin_payload = stdin.map(<[u8]>::to_vec);
        let stdin_writer = async move {
            if let (Some(mut child_stdin), Some(input)) = (child_stdin, stdin_payload) {
                child_stdin.write_all(&input).await?;
                child_stdin.shutdown().await?;
            }
            Ok::<(), std::io::Error>(())
        };
        tokio::pin!(stdin_writer);

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);

        // Read both pipes line-by-line as the command runs. libFuzzer writes its
        // progress to stderr (unbuffered in C), so this surfaces live activity.
        let stop = loop {
            if out_done && err_done && stdin_done {
                break Stop::Completed;
            }
            tokio::select! {
                () = cancel.cancelled() => break Stop::Cancelled,
                () = &mut deadline => break Stop::TimedOut,
                written = &mut stdin_writer, if !stdin_done => match written {
                    Ok(()) => stdin_done = true,
                    // EPIPE means the container exited (crash, bad image)
                    // before consuming stdin. That is not a pipe failure: the
                    // container's exit closes stdout/stderr, so the real error
                    // output (e.g. "pull access denied") and the exit code
                    // surface through the normal Completed path. Failing here
                    // would discard the captured output that explains why.
                    Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                        stdin_done = true;
                    }
                    Err(error) => break Stop::Failed(format!("write docker stdin: {error}")),
                },
                read = stdout.read(&mut out_chunk), if !out_done => match read {
                    Ok(0) => out_done = true,
                    Ok(read) => stdout_buf.push(&out_chunk[..read], &mut |line| on_line(line)),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => break Stop::Failed(format!("read docker stdout: {error}")),
                },
                read = stderr.read(&mut err_chunk), if !err_done => match read {
                    Ok(0) => err_done = true,
                    Ok(read) => stderr_buf.push(&err_chunk[..read], &mut |line| on_line(line)),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => break Stop::Failed(format!("read docker stderr: {error}")),
                },
            }
        };

        let forced_termination = match &stop {
            Stop::TimedOut => Some(hf_core::runtime::CommandTermination::TimedOut),
            Stop::Cancelled => Some(hf_core::runtime::CommandTermination::Cancelled),
            Stop::Completed | Stop::Failed(_) => None,
        };
        let pipe_failure = match &stop {
            Stop::Failed(error) => Some(error.clone()),
            Stop::Completed | Stop::TimedOut | Stop::Cancelled => None,
        };
        let (exit_code, termination) = match stop {
            Stop::Completed => {
                let status = tokio::time::timeout(CONTAINER_TEARDOWN_TIMEOUT, child.wait())
                    .await
                    .map_err(|_| {
                        ClassifiedError::Sandbox(format!(
                            "docker client did not exit after output closed for {container_name}"
                        ))
                    })?
                    .map_err(|e| ClassifiedError::Sandbox(format!("wait for docker: {e}")))?;
                cleanup.disarm();
                (
                    status.code().unwrap_or(-1),
                    hf_core::runtime::CommandTermination::Completed,
                )
            }
            Stop::TimedOut | Stop::Cancelled | Stop::Failed(_) => {
                let kill = tokio::time::timeout(
                    CONTAINER_TEARDOWN_TIMEOUT,
                    Command::new(crate::docker_bin())
                        .arg("kill")
                        .arg(container_name)
                        .output(),
                )
                .await
                .map_err(|_| {
                    ClassifiedError::Sandbox(format!(
                        "timed out killing stopped container {container_name}"
                    ))
                })?
                .map_err(|e| {
                    ClassifiedError::Sandbox(format!(
                        "failed to kill stopped container {container_name}: {e}"
                    ))
                })?;
                if !kill.status.success() && child.try_wait().ok().flatten().is_none() {
                    return Err(ClassifiedError::Sandbox(format!(
                        "failed to kill stopped container {container_name}: {}",
                        String::from_utf8_lossy(&kill.stderr).trim()
                    )));
                }
                let _ = child.start_kill();
                tokio::time::timeout(CONTAINER_TEARDOWN_TIMEOUT, child.wait())
                    .await
                    .map_err(|_| {
                        ClassifiedError::Sandbox(format!(
                            "docker client did not stop for container {container_name}"
                        ))
                    })?
                    .map_err(|e| ClassifiedError::Sandbox(format!("wait for docker: {e}")))?;
                cleanup.disarm();
                if let Some(error) = pipe_failure {
                    return Err(ClassifiedError::Sandbox(error));
                }
                (
                    -1,
                    forced_termination.expect("forced stop has a termination"),
                )
            }
        };
        let mut forward = |line: &str| on_line(line);
        let stdout = stdout_buf.finish(&mut forward);
        let stderr = stderr_buf.finish(&mut forward);

        Ok(CommandResult {
            exit_code,
            stdout,
            stderr,
            workspace: cwd.to_path_buf(),
            termination,
        })
    }
}

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ImmutableImageReference, ResourceLimits, RuntimeAdapter};

#[async_trait]
impl RuntimeAdapter for DockerRuntime {
    async fn image_present(&self, image: &str) -> bool {
        // The presence probe is a blocking, bounded `docker image inspect`; run
        // it off the async runtime so it never stalls a worker thread.
        let image = image.to_owned();
        tokio::task::spawn_blocking(move || crate::config::image_present(&image))
            .await
            .unwrap_or(false)
    }

    async fn resolve_image_reference(
        &self,
        image: &str,
    ) -> Result<Option<ImmutableImageReference>, ClassifiedError> {
        let image = image.to_owned();
        let display = image.clone();
        tokio::task::spawn_blocking(move || crate::config::image_id(&image))
            .await
            .map_err(|error| {
                ClassifiedError::Sandbox(format!("resolve sandbox image identity: {error}"))
            })?
            .ok_or_else(|| {
                ClassifiedError::Sandbox(format!(
                    "sandbox image {display} is unavailable or has no immutable image ID"
                ))
            })
            .and_then(ImmutableImageReference::from_sha256_id)
            .map(Some)
    }

    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        self.run_command_opts(
            cmd,
            cwd,
            limits,
            &hf_core::runtime::SandboxOptions::default(),
        )
        .await
    }

    async fn run_command_opts(
        &self,
        cmd: &[String],
        cwd: &Path,
        limits: &ResourceLimits,
        opts: &hf_core::runtime::SandboxOptions,
    ) -> Result<CommandResult, ClassifiedError> {
        let cancel = tokio_util::sync::CancellationToken::new();
        self.run_command_streaming_opts(cmd, cwd, limits, opts, &cancel, &|_| {})
            .await
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
                termination: hf_core::runtime::CommandTermination::Cancelled,
            });
        }

        let opts = self.validate_sandbox_options(opts)?;
        let timeout = Duration::from_secs(limits.max_duration_secs);
        let (args, container_name) = self.prepare_stream_args(cmd, &cwd, limits, &opts)?;
        Box::pin(self.stream_docker_run(
            &args,
            &container_name,
            timeout,
            &cwd,
            cancel,
            on_line,
            opts.stdin.as_deref(),
        ))
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
mod prepare_args_tests {
    use super::DockerRuntime;
    use crate::config::RuntimeConfig;
    use hf_core::runtime::{ResourceLimits, SandboxOptions};
    use std::path::Path;

    fn limits() -> ResourceLimits {
        ResourceLimits {
            max_mem_mb: 512,
            max_cpus: 1,
            max_duration_secs: 60,
            env: std::collections::HashMap::new(),
            ptrace: false,
        }
    }

    #[test]
    fn prepare_stream_args_rejects_a_colon_in_the_resolved_workspace_path() {
        // A `:` in the resolved cwd would corrupt the `-v source:target:mode`
        // short syntax, so the workspace mount must refuse it up front.
        let runtime = DockerRuntime::new(RuntimeConfig::default(), Path::new("/tmp/ws"));
        let cmd = vec!["echo".to_owned()];
        let opts = SandboxOptions::default();

        let rejected = runtime.prepare_stream_args(&cmd, Path::new("/work/a:b"), &limits(), &opts);
        assert!(
            rejected.is_err(),
            "a colon in the workspace path must be rejected"
        );

        let accepted =
            runtime.prepare_stream_args(&cmd, Path::new("/work/clean"), &limits(), &opts);
        let (args, _name) = accepted.expect("a clean workspace path must build args");
        assert!(
            args.join(" ").contains("/work/clean:/work"),
            "clean workspace path must be mounted: {}",
            args.join(" ")
        );
    }
}

#[cfg(test)]
mod line_read_tests {
    use super::{BoundedOutput, StreamOutput, OUTPUT_TRUNCATION_MARKER};

    #[test]
    fn retained_output_is_bounded_and_marks_truncation() {
        let mut output = BoundedOutput::new(40);
        output.push(b"head-1234567890");
        output.push(b"middle-that-is-discarded");
        output.push(b"tail-abcdefghij");

        let rendered = output.finish();
        assert!(rendered.len() <= 40);
        assert!(rendered.starts_with("head-"));
        assert!(rendered.contains(OUTPUT_TRUNCATION_MARKER));
        assert!(rendered.ends_with("fghij"));
        assert!(!rendered.contains("discarded"));
    }

    #[test]
    fn streamed_unterminated_lines_are_bounded() {
        let mut output = StreamOutput::new(64, 8);
        let mut lines = Vec::new();
        output.push(b"abcdefghijklmnop\nnext\n", &mut |line| {
            lines.push(line.to_owned());
        });

        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("abcdefgh"));
        assert!(lines[0].contains("truncated"));
        assert_eq!(lines[1], "next");
    }
}

#[cfg(test)]
mod pinned_image_tests {
    use super::valid_pinned_image_reference;

    #[test]
    fn pinned_image_reference_rejects_flag_injection() {
        // The reference is later emitted verbatim into the `docker run` argv,
        // so a leading `-` would be parsed as a docker CLI flag, voiding the
        // pinned-image guarantee.
        assert!(!valid_pinned_image_reference("-w/tmp:x"));
        assert!(!valid_pinned_image_reference("-evil"));
        // A tag or digest without a name component is not a usable reference.
        assert!(!valid_pinned_image_reference(":1.2.3"));
        assert!(!valid_pinned_image_reference(
            "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
    }

    #[test]
    fn pinned_image_reference_accepts_pinned_tags_and_digests() {
        assert!(valid_pinned_image_reference("repo/name:1.2.3"));
        assert!(valid_pinned_image_reference("name:2.7.0"));
        assert!(valid_pinned_image_reference(
            "repo/name@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(valid_pinned_image_reference(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!valid_pinned_image_reference("repo/name:latest"));
        assert!(!valid_pinned_image_reference("repo/name"));
    }
}
