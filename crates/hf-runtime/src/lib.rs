//! hf-runtime: Sandboxed runtime for harness builds and fuzz runs.
//!
//! Implements `RuntimeAdapter` from `hf-core` with a production
//! `DockerRuntime`; `StubRuntime` is a non-executing test/presentation double.
//!
//! See `docs/design/runtime-design.md` and `AGENTS.md` section 2.12
//! (Fuzzing Safety First).

pub mod adapter;
pub mod config;
pub mod docker;
pub mod process_env;

pub use adapter::StubRuntime;
pub use config::{
    can_run_platform, docker_bin, docker_cli_present, docker_daemon_ready, host_platform,
    image_present, norm_platform, platform_short, resolve_bin, sandbox_engine_probe,
    sandbox_image_arch, sandbox_image_present, RuntimeConfig, SandboxEngines, SANDBOX_IMAGE,
};
pub use process_env::{
    is_sensitive_name, scrub, scrubbed_command, scrubbed_parent_env, scrubbed_tokio_command,
    HARNESS_NAME_PREFIX, SENSITIVE_NAME_FRAGMENTS,
};
