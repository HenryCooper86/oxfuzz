//! Built-in tools shipped with the agent.
//!
//! These are core tools implemented in Rust, registered at startup. The
//! browser (`WebFetch`/`Browser`) and `KnowledgeSearch` tools from y-agent are
//! omitted here until the browser/knowledge subsystems are ported.

mod path_utils;

pub mod file_edit;
pub mod file_read;
pub mod file_write;
pub mod glob;
pub mod grep;

pub mod loop_tool;
pub mod plan;
pub mod shell_exec;
pub mod task;
pub mod tool_search;
pub mod user_interaction;

pub mod workflow;

use crate::registry::ToolRegistryImpl;
use std::sync::Arc;

/// Register all built-in tools into the given registry.
///
/// Called during service wiring to populate the tool registry with the
/// standard set of tools the agent can use.
pub async fn register_builtin_tools(registry: &ToolRegistryImpl) {
    let tools: Vec<(Arc<dyn hf_core::tool::Tool>, hf_core::tool::ToolDefinition)> = vec![
        (
            Arc::new(file_read::FileReadTool::new()),
            file_read::FileReadTool::tool_definition(),
        ),
        (
            Arc::new(file_write::FileWriteTool::new()),
            file_write::FileWriteTool::tool_definition(),
        ),
        (
            Arc::new(file_edit::FileEditTool::new()),
            file_edit::FileEditTool::tool_definition(),
        ),
        (
            Arc::new(shell_exec::ShellExecTool::new()),
            shell_exec::ShellExecTool::tool_definition(),
        ),
        (
            Arc::new(task::TaskTool::new()),
            task::TaskTool::tool_definition(),
        ),
        (
            Arc::new(user_interaction::AskUserTool::new()),
            user_interaction::AskUserTool::tool_definition(),
        ),
        (
            Arc::new(tool_search::ToolSearchTool::new()),
            tool_search::ToolSearchTool::tool_definition(),
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
            Arc::new(workflow::WorkflowCreateTool::new()),
            workflow::WorkflowCreateTool::tool_definition(),
        ),
        (
            Arc::new(workflow::WorkflowListTool::new()),
            workflow::WorkflowListTool::tool_definition(),
        ),
        (
            Arc::new(workflow::ScheduleCreateTool::new()),
            workflow::ScheduleCreateTool::tool_definition(),
        ),
        (
            Arc::new(workflow::WorkflowGetTool::new()),
            workflow::WorkflowGetTool::tool_definition(),
        ),
        (
            Arc::new(workflow::WorkflowUpdateTool::new()),
            workflow::WorkflowUpdateTool::tool_definition(),
        ),
        (
            Arc::new(workflow::WorkflowDeleteTool::new()),
            workflow::WorkflowDeleteTool::tool_definition(),
        ),
        (
            Arc::new(workflow::WorkflowValidateTool::new()),
            workflow::WorkflowValidateTool::tool_definition(),
        ),
        (
            Arc::new(workflow::ScheduleListTool::new()),
            workflow::ScheduleListTool::tool_definition(),
        ),
        (
            Arc::new(workflow::SchedulePauseTool::new()),
            workflow::SchedulePauseTool::tool_definition(),
        ),
        (
            Arc::new(workflow::ScheduleResumeTool::new()),
            workflow::ScheduleResumeTool::tool_definition(),
        ),
        (
            Arc::new(workflow::ScheduleDeleteTool::new()),
            workflow::ScheduleDeleteTool::tool_definition(),
        ),
        (
            Arc::new(plan::PlanTool::new()),
            plan::PlanTool::tool_definition(),
        ),
        (
            Arc::new(loop_tool::LoopTool::new()),
            loop_tool::LoopTool::tool_definition(),
        ),
    ];

    for (tool, def) in tools {
        if let Err(e) = registry.register_tool(tool, def).await {
            tracing::warn!(error = %e, "failed to register built-in tool");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ToolRegistryConfig;
    use hf_core::tool::ToolRegistry;

    #[tokio::test]
    async fn test_register_builtin_tools_populates_registry() {
        let registry = ToolRegistryImpl::new(ToolRegistryConfig::default());
        register_builtin_tools(&registry).await;
        // 9 core/file/shell + 11 workflow/schedule + 1 plan + 1 loop = 22
        assert_eq!(registry.len().await, 22);
    }

    #[tokio::test]
    async fn test_registered_tools_appear_in_index() {
        let registry = ToolRegistryImpl::new(ToolRegistryConfig::default());
        register_builtin_tools(&registry).await;
        let index = registry.tool_index().await;
        let names: Vec<&str> = index.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"FileRead"));
        assert!(names.contains(&"FileWrite"));
        assert!(names.contains(&"FileEdit"));
        assert!(names.contains(&"ShellExec"));
        assert!(names.contains(&"ToolSearch"));
        assert!(names.contains(&"Glob"));
        assert!(names.contains(&"Grep"));
        assert!(names.contains(&"Task"));
    }
}
