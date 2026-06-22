//! `ShellExec` tool stub.

use async_trait::async_trait;
use hf_core::error::ClassifiedError;
use hf_core::tool::{Tool, ToolContext, ToolOutput};
use serde_json::{json, Value};

/// Execute a shell command inside the sandbox.
pub struct ShellExec;

#[async_trait]
impl Tool for ShellExec {
    fn name(&self) -> &str {
        "ShellExec"
    }

    fn schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "command": { "type": "string" },
                "cwd": { "type": "string" }
            },
            "required": ["command"]
        })
    }

    async fn call(&self, _args: Value, _ctx: &ToolContext) -> Result<ToolOutput, ClassifiedError> {
        Err(ClassifiedError::Internal(
            "ShellExec: not implemented".to_owned(),
        ))
    }
}
