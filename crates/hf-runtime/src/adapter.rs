//! Runtime adapter stub.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::runtime::{CommandResult, ResourceLimits, RuntimeAdapter};
use std::path::Path;

/// A stub runtime that executes commands on the host (development only).
///
/// Production uses [`DockerRuntime`](crate::docker::DockerRuntime).
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
