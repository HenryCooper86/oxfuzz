//! Read-only code-inspection tools for the agent, backed by the `hf-tools`
//! registry + executor (JSON-schema validation + hooks middleware).
//!
//! These let the fuzzing agent read and search a target's source while it
//! reasons about what to fuzz, complementing the fuzzing-domain tools
//! (`discover`/`harness`/`run`/`triage`) dispatched through `hf-service`.
//! They are read-only, so they bypass the per-agent tool allowlist.

use std::sync::Arc;

use hf_core::tool::{Tool, ToolDefinition, ToolInput};
use hf_core::types::{SessionId, ToolName};
use hf_tools::builtin::{file_read, glob, grep, tool_search};
use hf_tools::config::ToolRegistryConfig;
use hf_tools::executor::ToolExecutor;
use hf_tools::registry::ToolRegistryImpl;

/// Names of the read-only inspection tools (exempt from the allowlist).
pub const INSPECTION_TOOLS: &[&str] = &["FileRead", "Glob", "Grep", "ToolSearch"];

/// A one-line catalog entry per inspection tool, appended to the system prompt.
pub const INSPECTION_CATALOG: &str = "\
- FileRead: read a source file. args: {\"path\":\"...\"}\n\
- Glob: list files matching a glob. args: {\"pattern\":\"**/*.c\"}\n\
- Grep: search file contents by regex. args: {\"pattern\":\"...\"}\n\
- ToolSearch: find available tools by keyword. args: {\"query\":\"...\"}";

/// Build the inspection-tool registry (read-only file/search tools).
pub async fn build_inspection_registry() -> Arc<ToolRegistryImpl> {
    let registry = ToolRegistryImpl::new(ToolRegistryConfig::default());
    let tools: Vec<(Arc<dyn Tool>, ToolDefinition)> = vec![
        (
            Arc::new(file_read::FileReadTool::new()),
            file_read::FileReadTool::tool_definition(),
        ),
        (
            Arc::new(glob::GlobTool::new()),
            glob::GlobTool::tool_definition(),
        ),
        (
            Arc::new(grep::GrepTool::new()),
            grep::GrepTool::tool_definition(),
        ),
        (
            Arc::new(tool_search::ToolSearchTool::new()),
            tool_search::ToolSearchTool::tool_definition(),
        ),
    ];
    for (tool, def) in tools {
        if let Err(e) = registry.register_tool(tool, def).await {
            tracing::warn!(error = %e, "failed to register inspection tool");
        }
    }
    Arc::new(registry)
}

/// Execute an inspection tool through the registry executor, returning the
/// tool output (or error) rendered as a JSON string for the agent transcript.
pub async fn dispatch_inspection(
    registry: &ToolRegistryImpl,
    name: &str,
    args: &serde_json::Value,
    working_dir: Option<&str>,
) -> String {
    let tool_name = ToolName::from_string(name);
    let input = ToolInput {
        call_id: uuid::Uuid::new_v4().to_string(),
        name: tool_name.clone(),
        arguments: args.clone(),
        session_id: SessionId::new(),
        working_dir: working_dir.map(str::to_owned),
        additional_read_dirs: Vec::new(),
        command_runner: None,
    };
    let mut executor = ToolExecutor::new();
    match executor.execute(registry, &tool_name, input).await {
        Ok(out) => out.content.to_string(),
        Err(e) => format!("{{\"error\":\"{e}\"}}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registry_executes_file_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.c");
        std::fs::write(&path, "int parse_value(const char *s) { return 0; }").unwrap();

        let registry = build_inspection_registry().await;
        let args = serde_json::json!({ "path": path.to_str().unwrap() });
        let out = dispatch_inspection(&registry, "FileRead", &args, dir.path().to_str()).await;

        assert!(
            out.contains("parse_value"),
            "FileRead should return the file contents; got: {out}"
        );
    }

    #[tokio::test]
    async fn registry_registers_all_inspection_tools() {
        let registry = build_inspection_registry().await;
        assert_eq!(registry.len().await, INSPECTION_TOOLS.len());
    }
}
