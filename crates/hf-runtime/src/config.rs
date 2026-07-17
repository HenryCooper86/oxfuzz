//! Runtime configuration.

use hf_core::engine::EngineKind;
use hf_core::runtime::ResourceLimits;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

/// The sandbox image used for all isolated builds and fuzz runs.
///
/// Single source of truth -- referenced by `hf-service`, `hf-cli`, and
/// `hf-gui` so the tag never drifts across presentation layers.
pub const SANDBOX_IMAGE: &str = "hobot/fuzz-sandbox:0.1.0";

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
    std::process::Command::new(bin)
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

/// Whether the Docker daemon is actually reachable. `docker info` only
/// succeeds when a daemon is up, so this is a true readiness check (unlike
/// `docker --version`, which only proves the CLI exists).
#[must_use]
pub fn docker_daemon_ready() -> bool {
    std::process::Command::new(docker_bin())
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Whether the sandbox image is loaded locally.
#[must_use]
pub fn sandbox_image_present() -> bool {
    std::process::Command::new(docker_bin())
        .args(["image", "inspect", SANDBOX_IMAGE])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// The architecture the loaded sandbox image was built for ("amd64"/"arm64"),
/// or `None` when the image is absent.
#[must_use]
pub fn sandbox_image_arch() -> Option<String> {
    let out = std::process::Command::new(docker_bin())
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Architecture}}",
            SANDBOX_IMAGE,
        ])
        .output()
        .ok()?;
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
    available: [bool; 5],
}

impl SandboxEngines {
    /// Whether the sandbox contains the toolchain required by `engine`.
    #[must_use]
    pub const fn supports(self, engine: EngineKind) -> bool {
        self.available[match engine {
            EngineKind::LibFuzzer => 0,
            EngineKind::AflPlusPlus => 1,
            EngineKind::Honggfuzz => 2,
            EngineKind::ClusterFuzzLite => 3,
            EngineKind::Syzkaller => 4,
        }]
    }
}

/// The `docker image inspect --format {{.Id}}` of the loaded sandbox image, used
/// to invalidate the engine-probe cache when the image is rebuilt.
fn sandbox_image_id() -> Option<String> {
    let out = std::process::Command::new(docker_bin())
        .args(["image", "inspect", "--format", "{{.Id}}", SANDBOX_IMAGE])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let id = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!id.is_empty()).then_some(id)
}

/// Map the probe script's stdout (one present-binary name per line) to the
/// per-engine availability. Each engine maps to the binary its adapter invokes
/// inside the sandbox: libFuzzer compiles/runs via `clang`; AFL++ -> `afl-fuzz`;
/// honggfuzz -> `honggfuzz`; syzkaller -> `syz-manager`; `ClusterFuzzLite` shells
/// `python3 infra/helper.py`, so it needs `python3` (the helper itself comes
/// from the project, not the image).
fn engines_from_probe_output(found: &str) -> SandboxEngines {
    let has = |bin: &str| found.lines().any(|l| l.trim() == bin);
    SandboxEngines {
        available: [
            has("clang"),
            has("afl-fuzz"),
            has("honggfuzz"),
            has("python3"),
            has("syz-manager"),
        ],
    }
}

/// Run a one-shot container that reports which engine binaries exist in the
/// image. All-false if the run fails.
fn probe_sandbox_engines() -> SandboxEngines {
    let out = std::process::Command::new(docker_bin())
        .args([
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            SANDBOX_IMAGE,
            "-c",
            "for b in clang afl-fuzz honggfuzz syz-manager python3; do \
             command -v \"$b\" >/dev/null 2>&1 && echo \"$b\"; done",
        ])
        .output();
    match out {
        Ok(out) if out.status.success() => {
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
    use super::{engines_from_probe_output, SandboxEngines, SANDBOX_IMAGE};
    use hf_core::engine::EngineKind;

    #[test]
    fn probe_output_maps_present_binaries_to_engines() {
        // The image bundles clang/afl-fuzz/honggfuzz/syz-manager but not python3.
        let out = "clang\nafl-fuzz\nhonggfuzz\nsyz-manager\n";
        let engines = engines_from_probe_output(out);
        assert!(engines.supports(EngineKind::LibFuzzer));
        assert!(engines.supports(EngineKind::AflPlusPlus));
        assert!(engines.supports(EngineKind::Honggfuzz));
        assert!(!engines.supports(EngineKind::ClusterFuzzLite));
        assert!(engines.supports(EngineKind::Syzkaller));
    }

    #[test]
    fn probe_output_empty_is_all_false() {
        assert_eq!(engines_from_probe_output(""), SandboxEngines::default());
    }

    #[test]
    fn probe_output_clusterfuzzlite_needs_python3() {
        let out = "clang\npython3\n";
        let e = engines_from_probe_output(out);
        assert!(e.supports(EngineKind::LibFuzzer));
        assert!(e.supports(EngineKind::ClusterFuzzLite));
        assert!(!e.supports(EngineKind::AflPlusPlus));
        assert!(!e.supports(EngineKind::Honggfuzz));
        assert!(!e.supports(EngineKind::Syzkaller));
    }

    #[test]
    fn production_sandbox_image_is_version_pinned() {
        assert!(!SANDBOX_IMAGE.ends_with(":latest"));
        assert_eq!(SANDBOX_IMAGE, "hobot/fuzz-sandbox:0.1.0");
    }
}
