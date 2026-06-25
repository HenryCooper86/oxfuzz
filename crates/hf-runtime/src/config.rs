//! Runtime configuration.

use hf_core::runtime::ResourceLimits;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

/// The sandbox image used for all isolated builds and fuzz runs.
///
/// Single source of truth -- referenced by `hf-service`, `hf-cli`, and
/// `hf-gui` so the tag never drifts across presentation layers.
pub const SANDBOX_IMAGE: &str = "hobot/fuzz-sandbox:latest";

/// Which backend the runtime uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeBackend {
    Docker,
    Native,
}

/// Configuration for the sandbox runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub backend: RuntimeBackend,
    pub image: String,
    pub container_workspace: String,
    pub default_limits: ResourceLimits,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend: RuntimeBackend::Docker,
            image: SANDBOX_IMAGE.to_owned(),
            container_workspace: "/work".to_owned(),
            default_limits: ResourceLimits {
                max_mem_mb: 4096,
                max_cpus: 2,
                max_duration_secs: 7200,
                env: HashMap::new(),
            },
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
