//! hf-runtime: Sandboxed runtime for harness builds and fuzz runs.
//!
//! Implements `RuntimeAdapter` from `hf-core`. Two backends:
//! - `DockerRuntime` (default, isolation by shelling out to the `docker` CLI).
//! - `StubRuntime` (development only, returns errors).
//!
//! See `docs/design/runtime-design.md` (to be written) and
//! `AGENTS.md` section 2.12 (Fuzzing Safety First).

pub mod adapter;
pub mod config;
pub mod docker;

pub use adapter::StubRuntime;
pub use config::{
    docker_bin, docker_cli_present, docker_daemon_ready, host_platform, norm_platform,
    platform_short, sandbox_engine_probe, sandbox_image_arch, sandbox_image_present, RuntimeBackend,
    RuntimeConfig, SandboxEngines, SANDBOX_IMAGE,
};
