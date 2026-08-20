//! Runtime adapter stub.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use std::path::Path;

/// A non-executing [`RuntimeAdapter`]: every method returns
/// [`ClassifiedError::Sandbox`] rather than doing anything.
///
/// This is what `runtime_from_env` installs when the Docker daemon is not
/// reachable, and refusing is the point. A harness build or fuzz run is
/// untrusted code (AGENTS.md 2.5 / 2.12), so with no sandbox available the
/// only safe answer is to fail the operation -- never to fall back to running
/// it on the host. Tests and presentation layers use it for the same reason:
/// they can construct a service without any risk of execution.
///
/// Production execution goes through
/// [`DockerRuntime`](crate::docker::DockerRuntime).
pub struct StubRuntime;

#[async_trait]
impl RuntimeAdapter for StubRuntime {
    async fn run_command(
        &self,
        _cmd: &[String],
        _cwd: &Path,
        _limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError> {
        Err(ClassifiedError::Sandbox(
            "stub runtime: not implemented".to_owned(),
        ))
    }

    async fn write_file(&self, _path: &Path, _content: &str) -> Result<(), ClassifiedError> {
        Err(ClassifiedError::Sandbox(
            "stub runtime: not implemented".to_owned(),
        ))
    }

    async fn read_file(&self, _path: &Path) -> Result<String, ClassifiedError> {
        Err(ClassifiedError::Sandbox(
            "stub runtime: not implemented".to_owned(),
        ))
    }
}
