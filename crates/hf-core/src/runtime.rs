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

/// A callback invoked with each output line as a streamed command runs.
pub type LineSink<'a> = dyn Fn(&str) + Send + Sync + 'a;

/// A sandboxed runtime for building harnesses and running fuzzers.
#[async_trait]
pub trait RuntimeAdapter: Send + Sync {
    async fn run_command(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &ResourceLimits,
    ) -> Result<CommandResult, ClassifiedError>;

    /// Run a command, delivering each stdout/stderr line to `on_line` as it
    /// arrives, for live progress.
    ///
    /// The default implementation runs the command to completion and replays
    /// the captured output line-by-line (no live streaming); adapters that can
    /// stream (e.g. Docker) override this.
    ///
    /// # Errors
    /// Returns `ClassifiedError` if the command fails to run.
    async fn run_command_streaming(
        &self,
        cmd: &[String],
        cwd: &std::path::Path,
        limits: &ResourceLimits,
        on_line: &LineSink<'_>,
    ) -> Result<CommandResult, ClassifiedError> {
        let result = self.run_command(cmd, cwd, limits).await?;
        for line in result.stdout.lines().chain(result.stderr.lines()) {
            on_line(line);
        }
        Ok(result)
    }

    async fn write_file(
        &self,
        path: &std::path::Path,
        content: &str,
    ) -> Result<(), ClassifiedError>;
    async fn read_file(&self, path: &std::path::Path) -> Result<String, ClassifiedError>;
}
