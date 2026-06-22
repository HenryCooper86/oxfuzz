//! Runtime sandbox adapter.

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::ClassifiedError;

/// Resource limits for a sandboxed command.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub max_duration_secs: u64,
    pub env: HashMap<String, String>,
}

/// Result of a sandboxed command execution.
#[derive(Debug, Clone)]
pub struct CommandResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub workspace: PathBuf,
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

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), ClassifiedError>;
    async fn read_file(&self, path: &std::path::Path) -> Result<String, ClassifiedError>;
}
