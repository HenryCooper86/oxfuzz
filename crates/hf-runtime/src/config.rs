//! Runtime configuration.

use hf_core::engine::EngineKind;
use hf_core::runtime::ResourceLimits;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;

/// The sandbox image used for all isolated builds and fuzz runs.
///
/// Single source of truth -- referenced by `hf-service`, `hf-cli`, and
/// `hf-gui` so the tag never drifts across presentation layers.
pub const SANDBOX_IMAGE: &str = "oxfuzz/fuzz-sandbox:0.1.0";

/// Configuration for the production Docker sandbox runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub image: String,
    pub container_workspace: String,
    pub default_limits: ResourceLimits,
    /// Max process count inside the sandbox (`--pids-limit`), to blunt fork
    /// bombs. Generous enough for parallel compile + multi-threaded fuzzers.
    pub max_pids: u32,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            image: SANDBOX_IMAGE.to_owned(),
            container_workspace: "/work".to_owned(),
            default_limits: ResourceLimits {
                max_mem_mb: 4096,
                max_cpus: 2,
                max_duration_secs: 7200,
                env: HashMap::new(),
                ptrace: false,
            },
            max_pids: 512,
        }
    }
}

// ---------------------------------------------------------------------------
// Docker CLI discovery (shared by CLI, GUI, and service layer)
// ---------------------------------------------------------------------------

/// Check whether a binary exists and responds to `--version`.
fn which(bin: &str) -> bool {
    crate::process_env::scrubbed_command(bin)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Resolve the `docker` executable path.
///
/// A `.app` launched from Finder (macOS) does not inherit the user's shell
/// `PATH`, so a bare `docker` lookup fails even when `OrbStack` or Docker
/// Desktop is installed. Probe the bare name first (honours an inherited
/// PATH and user overrides), then the well-known install locations, and
/// cache the result. Falls back to `"docker"` so a PATH-equipped launch
/// (e.g. from a terminal) still works.
///
/// Shared by `hf-cli`, `hf-gui`, and `hf-service` so the PATH-probing logic
/// never drifts between presentation layers.
#[must_use]
pub fn docker_bin() -> &'static str {
    static DOCKER_BIN: OnceLock<String> = OnceLock::new();
    DOCKER_BIN.get_or_init(|| {
        if which("docker") {
            return "docker".to_string();
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(PathBuf::from(&home).join(".orbstack/bin/docker"));
        }
        candidates.push(PathBuf::from("/usr/local/bin/docker"));
        candidates.push(PathBuf::from("/opt/homebrew/bin/docker"));
        candidates.push(PathBuf::from(
            "/Applications/Docker.app/Contents/Resources/bin/docker",
        ));
        for c in candidates {
            if c.is_file() && which(&c.to_string_lossy()) {
                return c.to_string_lossy().into_owned();
            }
        }
        "docker".to_string()
    })
}

/// Whether the `docker` CLI is installed (says nothing about the daemon).
#[must_use]
pub fn docker_cli_present() -> bool {
    which(docker_bin())
}

/// Resolve a tool executable by name, tolerating a stripped `PATH`.
///
/// A `.app` launched from Finder (macOS) does not inherit the shell `PATH`, so a
/// bare tool name (e.g. `pandoc`, `xelatex`) is invisible even when installed.
/// Probe the bare name first (honours an inherited PATH and user overrides),
/// then the well-known Homebrew / system / TeX install locations. Falls back to
/// the bare name so a PATH-equipped launch still works. Not cached: callers hold
/// the result for one operation and the set of installed tools can change.
#[must_use]
pub fn resolve_bin(name: &str) -> String {
    if which(name) {
        return name.to_owned();
    }
    let dirs = [
        "/opt/homebrew/bin",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/Library/TeX/texbin",
    ];
    for dir in dirs {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.is_file() && which(&candidate.to_string_lossy()) {
            return candidate.to_string_lossy().into_owned();
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        let candidate = PathBuf::from(&home).join(".local/bin").join(name);
        if candidate.is_file() && which(&candidate.to_string_lossy()) {
            return candidate.to_string_lossy().into_owned();
        }
    }
    name.to_owned()
}

/// Cap for one Docker probe command. A wedged daemon (e.g. Docker Desktop
/// stuck starting) makes `docker` invocations block indefinitely; without a
/// bound, every readiness probe -- and any UI or test polling it -- would hang
/// with it. Ten seconds is generous for a local daemon round-trip.
const DOCKER_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `cmd` to completion, returning its output, or `None` when it cannot be
/// spawned or exceeds `timeout` (the child is killed and reaped). Readiness
/// probes use this so a wedged daemon surfaces as "not ready" instead of an
/// unbounded hang.
fn run_bounded(cmd: std::process::Command, timeout: Duration) -> Option<std::process::Output> {
    let deadline = std::time::Instant::now() + timeout;
    let worker = match std::thread::Builder::new()
        .name("hf-readiness-probe".to_owned())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    tracing::warn!(%error, "Cannot initialize readiness probe worker");
                    return None;
                }
            };
            runtime.block_on(capture_probe(cmd, deadline))
        }) {
        Ok(worker) => worker,
        Err(error) => {
            tracing::warn!(%error, "Cannot start readiness probe worker");
            return None;
        }
    };
    if let Ok(output) = worker.join() {
        output
    } else {
        tracing::warn!("Readiness probe worker panicked");
        None
    }
}

async fn capture_probe(
    cmd: std::process::Command,
    deadline: std::time::Instant,
) -> Option<std::process::Output> {
    use tokio::io::AsyncReadExt;
    if std::time::Instant::now() >= deadline {
        return None;
    }
    let mut cmd = cmd;
    #[cfg(windows)]
    let pipe = match windows_probe_stdout(&mut cmd) {
        Ok(pipe) => pipe,
        Err(error) => {
            tracing::warn!(%error, "Cannot initialize readiness probe stdout");
            return None;
        }
    };
    #[cfg(not(windows))]
    cmd.stdout(std::process::Stdio::piped());
    let mut child = match tokio::process::Command::from(cmd)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            tracing::debug!(%error, "Cannot spawn readiness probe");
            return None;
        }
    };
    let capture = async {
        let mut stdout = Vec::new();
        #[cfg(windows)]
        let mut pipe = pipe;
        #[cfg(not(windows))]
        let mut pipe = child.stdout.take();
        let read = async {
            #[cfg(windows)]
            pipe.connect().await?;
            #[cfg(not(windows))]
            let pipe = pipe
                .as_mut()
                .ok_or_else(|| std::io::Error::other("Readiness probe stdout pipe is missing"))?;
            pipe.read_to_end(&mut stdout).await?;
            Ok::<_, std::io::Error>(stdout)
        };
        tokio::try_join!(child.wait(), read)
    };
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), capture).await {
        Ok(Ok((status, stdout))) => {
            return Some(std::process::Output {
                status,
                stdout,
                stderr: Vec::new(),
            });
        }
        Ok(Err(error)) => tracing::warn!(%error, "Cannot capture readiness probe output"),
        Err(_) => tracing::debug!("Readiness probe exceeded its deadline"),
    }
    // The cancelled capture has closed stdout. A reaped child has no process id;
    // otherwise kill() waits for the owned CLI child before this worker returns.
    if child.id().is_some() {
        if let Err(error) = child.kill().await {
            tracing::warn!(%error, "Cannot kill readiness probe child");
            if let Err(error) = child.wait().await {
                tracing::warn!(%error, "Cannot reap readiness probe child");
            }
        }
    }
    None
}

#[cfg(windows)]
fn windows_probe_stdout(
    command: &mut std::process::Command,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let name = format!(r"\\.\pipe\oxfuzz-readiness-{}", uuid::Uuid::new_v4());
    let pipe = ServerOptions::new()
        .access_outbound(false)
        .first_pipe_instance(true)
        .max_instances(1)
        .reject_remote_clients(true)
        .create(&name)?;
    let writer = std::fs::OpenOptions::new().write(true).open(&name)?;
    command.stdout(writer);
    Ok(pipe)
}

/// Whether the Docker daemon is actually reachable. `docker info` only
/// succeeds when a daemon is up, so this is a true readiness check (unlike
/// `docker --version`, which only proves the CLI exists). Bounded by
/// `DOCKER_PROBE_TIMEOUT`: a wedged daemon reports not-ready.
#[must_use]
pub fn docker_daemon_ready() -> bool {
    let mut command = crate::process_env::scrubbed_command(docker_bin());
    command.args(["info", "--format", "{{.ServerVersion}}"]);
    run_bounded(command, DOCKER_PROBE_TIMEOUT).is_some_and(|o| o.status.success())
}

/// Whether the sandbox image is loaded locally.
#[must_use]
pub fn sandbox_image_present() -> bool {
    image_present(SANDBOX_IMAGE)
}

/// Whether a specific Docker image is loaded locally. Bounded like the other
/// Docker probes so a wedged daemon surfaces as "not present" rather than an
/// unbounded hang. `image` is passed as a separate argv (never a shell), and
/// callers pass a validated pinned reference.
#[must_use]
pub fn image_present(image: &str) -> bool {
    let mut command = crate::process_env::scrubbed_command(docker_bin());
    command.args(["image", "inspect", image]);
    run_bounded(command, DOCKER_PROBE_TIMEOUT).is_some_and(|o| o.status.success())
}

/// The architecture the loaded sandbox image was built for ("amd64"/"arm64"),
/// or `None` when the image is absent.
#[must_use]
pub fn sandbox_image_arch() -> Option<String> {
    let mut command = crate::process_env::scrubbed_command(docker_bin());
    command.args([
        "image",
        "inspect",
        "--format",
        "{{.Architecture}}",
        SANDBOX_IMAGE,
    ]);
    let out = run_bounded(command, DOCKER_PROBE_TIMEOUT)?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Which fuzzing-engine toolchains are actually present in the loaded sandbox
/// image. Engines run inside the image, so this -- not the host -- determines
/// what can run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SandboxEngines {
    available: [bool; 4],
}

impl SandboxEngines {
    /// Whether the sandbox contains the toolchain required by `engine`.
    #[must_use]
    pub const fn supports(self, engine: EngineKind) -> bool {
        self.available[match engine {
            EngineKind::LibFuzzer => 0,
            EngineKind::AflPlusPlus => 1,
            EngineKind::Honggfuzz => 2,
            EngineKind::Syzkaller => 3,
        }]
    }
}

/// The content-addressed `docker image inspect --format {{.Id}}` identity of a
/// loaded image. Reject malformed output so callers never mistake a mutable
/// name for immutable provenance.
pub(crate) fn image_id(image: &str) -> Option<String> {
    let mut command = crate::process_env::scrubbed_command(docker_bin());
    command.args(["image", "inspect", "--format", "{{.Id}}", image]);
    let out = run_bounded(command, DOCKER_PROBE_TIMEOUT)?;
    if !out.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_ascii_lowercase();
    let digest = id.strip_prefix("sha256:")?;
    (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(id)
}

/// The loaded sandbox image identity used to invalidate the engine-probe cache
/// when the image is rebuilt under the same configured tag.
fn sandbox_image_id() -> Option<String> {
    image_id(SANDBOX_IMAGE)
}

/// Map the probe script's stdout (one present-binary name per line) to the
/// per-engine availability. Each engine maps to the binary its adapter invokes
/// inside the sandbox: libFuzzer compiles/runs via `clang`; AFL++ -> `afl-fuzz`;
/// honggfuzz -> `honggfuzz`; syzkaller -> `syz-manager`.
fn engines_from_probe_output(found: &str) -> SandboxEngines {
    let has = |bin: &str| found.lines().any(|l| l.trim() == bin);
    SandboxEngines {
        available: [
            has("clang"),
            has("afl-fuzz"),
            has("honggfuzz"),
            has("syz-manager"),
        ],
    }
}

/// Run a one-shot container that reports which engine binaries exist in the
/// image. All-false if the run fails.
fn probe_sandbox_engines() -> SandboxEngines {
    let mut command = crate::process_env::scrubbed_command(docker_bin());
    command.args([
        "run",
        "--rm",
        "--entrypoint",
        "sh",
        SANDBOX_IMAGE,
        "-c",
        "for b in clang afl-fuzz honggfuzz syz-manager; do \
             command -v \"$b\" >/dev/null 2>&1 && echo \"$b\"; done",
    ]);
    let out = run_bounded(command, DOCKER_PROBE_TIMEOUT);
    match out {
        Some(out) if out.status.success() => {
            engines_from_probe_output(&String::from_utf8_lossy(&out.stdout))
        }
        _ => SandboxEngines::default(),
    }
}

/// Engine-probe cache, keyed by sandbox image id so a rebuild re-probes.
static ENGINE_PROBE_CACHE: std::sync::Mutex<Option<(String, SandboxEngines)>> =
    std::sync::Mutex::new(None);

/// Probe the loaded sandbox image for each engine's toolchain, reflecting what
/// can really run rather than assuming the image bundles every engine. Returns
/// all-false when the image is absent or Docker is unreachable.
///
/// The probe runs a container, so the result is cached and only re-run when the
/// image id changes -- callers may invoke this on a poll without spawning a
/// container each time.
#[must_use]
pub fn sandbox_engine_probe() -> SandboxEngines {
    let Some(id) = sandbox_image_id() else {
        return SandboxEngines::default();
    };
    if let Ok(cache) = ENGINE_PROBE_CACHE.lock() {
        if let Some((cached_id, engines)) = cache.as_ref() {
            if *cached_id == id {
                return *engines;
            }
        }
    }
    let engines = probe_sandbox_engines();
    if let Ok(mut cache) = ENGINE_PROBE_CACHE.lock() {
        *cache = Some((id, engines));
    }
    engines
}

// ---------------------------------------------------------------------------
// Platform normalisation helpers (shared by GUI and service layer)
// ---------------------------------------------------------------------------

/// The host's native Docker platform, e.g. "linux/arm64".
#[must_use]
pub fn host_platform() -> String {
    if std::env::consts::ARCH == "x86_64" {
        "linux/amd64".to_string()
    } else {
        "linux/arm64".to_string()
    }
}

/// Normalize a UI architecture string to a Docker `--platform` value. Accepts
/// "linux/amd64", "amd64", "x86", "`x86_64`", "linux/arm64", "arm64", ...
#[must_use]
pub fn norm_platform(arch: &str) -> String {
    let a = arch.to_ascii_lowercase();
    if a.contains("amd64") || a.contains("x86") || a.contains("intel") {
        "linux/amd64".to_string()
    } else {
        "linux/arm64".to_string()
    }
}

/// The short arch ("amd64"/"arm64") of a `linux/<arch>` platform string.
#[must_use]
pub fn platform_short(platform: &str) -> &str {
    platform.rsplit('/').next().unwrap_or("arm64")
}

/// Whether the host can build and run containers for `platform` (a
/// `linux/<arch>` value).
///
/// Always true for the host's native platform. A non-native platform requires
/// Docker to emulate the foreign arch via `qemu-user` + `binfmt_misc`:
/// macOS/Windows (`OrbStack` / Docker Desktop) register this automatically
/// inside their managed VM, but a bare Linux `docker` install does not. So on
/// Linux we
/// probe `/proc/sys/fs/binfmt_misc` for the matching qemu handler. When this
/// returns false a cross-arch build fails with an opaque "exec format error";
/// callers should surface a clear "register qemu-user/binfmt" hint instead.
#[must_use]
pub fn can_run_platform(platform: &str) -> bool {
    if norm_platform(platform) == host_platform() {
        return true;
    }
    #[cfg(not(target_os = "linux"))]
    {
        // The managed container VM (OrbStack / Docker Desktop) emulates it.
        true
    }
    #[cfg(target_os = "linux")]
    {
        let handler = if platform_short(platform) == "amd64" {
            "qemu-x86_64"
        } else {
            "qemu-aarch64"
        };
        std::path::Path::new("/proc/sys/fs/binfmt_misc")
            .join(handler)
            .exists()
    }
}

#[cfg(test)]
mod tests {
    use super::{engines_from_probe_output, run_bounded, SandboxEngines, SANDBOX_IMAGE};
    use hf_core::engine::EngineKind;
    use std::time::{Duration, Instant};

    // `run_bounded` is platform-agnostic, so these tests drive it with the
    // host's own shell rather than hardcoding /bin paths that do not exist on
    // Windows. Gating them to unix instead would leave the timeout wrapper
    // untested on the platform whose process handling differs most.
    #[cfg(unix)]
    fn shell_command(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[cfg(windows)]
    fn shell_command(script: &str) -> std::process::Command {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", script]);
        command
    }

    /// A command that outlives any timeout under test without needing a
    /// console (Windows `timeout` fails when stdin is redirected).
    #[cfg(unix)]
    fn long_running_command() -> std::process::Command {
        let mut command = std::process::Command::new("/bin/sleep");
        command.arg("30");
        command
    }

    #[cfg(windows)]
    fn long_running_command() -> std::process::Command {
        let mut command = std::process::Command::new("ping");
        command.args(["-n", "31", "127.0.0.1"]);
        command
    }

    #[test]
    fn run_bounded_captures_stdout_and_success() {
        let out = run_bounded(shell_command("echo ready"), Duration::from_secs(5))
            .expect("fast command completes");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ready");
    }

    #[test]
    fn run_bounded_reports_a_failing_exit() {
        let out = run_bounded(shell_command("exit 1"), Duration::from_secs(5))
            .expect("failed command still returns its output");
        assert!(!out.status.success());
    }

    #[test]
    fn run_bounded_kills_a_wedged_command_instead_of_hanging() {
        let start = Instant::now();
        let out = run_bounded(long_running_command(), Duration::from_millis(200));
        assert!(out.is_none(), "a wedged command yields no output");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the probe returns promptly after the timeout, not after the command"
        );
    }

    #[test]
    fn run_bounded_missing_binary_is_none() {
        assert!(run_bounded(
            std::process::Command::new("definitely-not-a-real-binary-hf"),
            Duration::from_secs(1),
        )
        .is_none());
    }

    fn pipe_fixture_command(root: &std::path::Path, role: &str) -> std::process::Command {
        let mut command =
            crate::process_env::scrubbed_command(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--ignored",
                "--exact",
                "config::tests::probe_pipe_fixture",
                "--nocapture",
            ])
            .env("HF_PROBE_FIXTURE_ROOT", root)
            .env("HF_PROBE_FIXTURE_ROLE", role);
        command
    }

    fn wait_for_marker(path: &std::path::Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if path.is_file() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    #[ignore = "subprocess fixture; selected exactly by the deadline regression"]
    fn probe_pipe_fixture() {
        let root = std::path::PathBuf::from(
            std::env::var_os("HF_PROBE_FIXTURE_ROOT").expect("owned fixture directory"),
        );
        match std::env::var("HF_PROBE_FIXTURE_ROLE")
            .expect("fixture role")
            .as_str()
        {
            "parent" => {
                let holder = pipe_fixture_command(&root, "holder")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("start pipe holder");
                // The holder deliberately outlives this parent. Its bounded lifetime
                // and owned stop/done markers let the calling test await cleanup.
                drop(holder);
                assert!(wait_for_marker(&root.join("ready")), "holder started");
                std::process::exit(0);
            }
            "holder" => {
                std::fs::write(root.join("ready"), b"ready").expect("ready marker");
                let deadline = Instant::now() + Duration::from_secs(5);
                while !root.join("stop").is_file() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
                std::fs::write(root.join("done"), b"done").expect("done marker");
                std::process::exit(0);
            }
            "output" => {
                use std::io::Write;
                let mut stdout = std::io::stdout().lock();
                stdout
                    .write_all(&vec![b'x'; 256 * 1024])
                    .expect("large probe output");
                stdout.flush().expect("flush output");
                std::process::exit(0);
            }
            role => panic!("unknown fixture role: {role}"),
        }
    }

    #[tokio::test]
    async fn run_bounded_times_out_when_descendant_retains_stdout() {
        let root = tempfile::tempdir().expect("owned fixture directory");
        let start = Instant::now();
        let out = run_bounded(
            pipe_fixture_command(root.path(), "parent"),
            Duration::from_secs(2),
        );
        let elapsed = start.elapsed();
        std::fs::write(root.path().join("stop"), b"stop").expect("stop pipe holder");
        let stopped = wait_for_marker(&root.path().join("done"));
        assert!(
            root.path().join("ready").is_file(),
            "holder actually started"
        );
        assert!(stopped, "fixture holder acknowledged cleanup");
        assert!(
            out.is_none(),
            "stdout must finish within the probe deadline"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "probe returned before the holder's fallback exit"
        );
    }

    #[test]
    fn run_bounded_drains_stdout_while_child_is_running() {
        let root = tempfile::tempdir().expect("owned fixture directory");
        let out = run_bounded(
            pipe_fixture_command(root.path(), "output"),
            Duration::from_secs(2),
        )
        .expect("output larger than the pipe buffer completes");
        assert!(out.status.success());
        assert!(out.stdout.ends_with(&vec![b'x'; 256 * 1024]));
    }

    #[test]
    fn probe_output_maps_present_binaries_to_engines() {
        // The image bundles the binaries required by every active engine.
        let out = "clang\nafl-fuzz\nhonggfuzz\nsyz-manager\n";
        let engines = engines_from_probe_output(out);
        assert!(engines.supports(EngineKind::LibFuzzer));
        assert!(engines.supports(EngineKind::AflPlusPlus));
        assert!(engines.supports(EngineKind::Honggfuzz));
        assert!(engines.supports(EngineKind::Syzkaller));
    }

    #[test]
    fn probe_output_empty_is_all_false() {
        assert_eq!(engines_from_probe_output(""), SandboxEngines::default());
    }

    #[test]
    fn python_alone_does_not_mark_an_engine_ready() {
        let engines = engines_from_probe_output("python3\n");
        assert!(EngineKind::ALL
            .into_iter()
            .all(|engine| !engines.supports(engine)));
    }

    #[test]
    fn production_sandbox_image_is_version_pinned() {
        assert!(!SANDBOX_IMAGE.ends_with(":latest"));
        assert_eq!(SANDBOX_IMAGE, "oxfuzz/fuzz-sandbox:0.1.0");
    }
}
