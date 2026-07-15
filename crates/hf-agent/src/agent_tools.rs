//! Read-only code-inspection tools for the agent, backed by the `hf-tools`
//! registry + executor (JSON-schema validation + registered-tool dispatch).
//!
//! These let the fuzzing agent read and search a target's source while it
//! reasons about what to fuzz, complementing the fuzzing-domain tools
//! (`discover`/`harness`/`run`/`triage`) dispatched through `hf-service`.
//! They are read-only, so they bypass the per-agent tool allowlist.

use std::sync::Arc;

use hf_core::exec::RuntimeCapability;
use hf_core::tool::{
    Tool, ToolCategory, ToolDefinition, ToolError, ToolInput, ToolOutput, ToolType,
};
use hf_core::types::{SessionId, ToolName};
use hf_tools::builtin::{file_read, glob, grep};
use hf_tools::config::ToolRegistryConfig;
use hf_tools::executor::ToolExecutor;
use hf_tools::registry::ToolRegistryImpl;

/// Names of the read-only inspection tools (exempt from the allowlist).
pub const INSPECTION_TOOLS: &[&str] = &["FileRead", "Glob", "Grep", "KnowledgeSearch"];

/// Build a well-formed `{"error": "..."}` tool result.
///
/// Tool errors routinely contain quotes, backslashes, and newlines (compiler
/// diagnostics, Windows paths, validation messages quoting the bad token).
/// Interpolating them into a hand-built JSON string produces invalid JSON,
/// which the model then cannot parse -- crippling `ReAct` self-correction on
/// exactly the errors it most needs to read. Serialize instead of formatting.
#[must_use]
pub(crate) fn error_json(message: impl std::fmt::Display) -> String {
    serde_json::json!({ "error": message.to_string() }).to_string()
}

/// A one-line catalog entry per inspection tool, appended to the system prompt.
pub const INSPECTION_CATALOG: &str = "\
- FileRead: read a source file. args: {\"path\":\"...\"}\n\
- Glob: list files matching a glob. args: {\"pattern\":\"**/*.c\"}\n\
- Grep: search file contents by regex. args: {\"pattern\":\"...\"}\n\
- KnowledgeSearch: BM25 search the project's source for symbols/patterns. args: {\"query\":\"...\"}";

/// Build the inspection-tool registry (read-only file/search tools).
pub async fn build_inspection_registry(
    backend: Arc<dyn crate::AgentBackend>,
) -> Arc<ToolRegistryImpl> {
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
            Arc::new(KnowledgeSearchTool::new(backend)),
            KnowledgeSearchTool::tool_definition(),
        ),
    ];
    for (tool, def) in tools {
        if let Err(e) = registry.register_tool(tool, def).await {
            tracing::warn!(error = %e, "failed to register inspection tool");
        }
    }
    Arc::new(registry)
}

/// A `KnowledgeSearch` tool backed by `hf-service::knowledge`: BM25 search over
/// the active project's source, lazily indexing it on first use. The project
/// root comes from `ToolInput::working_dir`, which the agent sets to its
/// project path.
struct KnowledgeSearchTool {
    definition: ToolDefinition,
    backend: Arc<dyn crate::AgentBackend>,
}

impl KnowledgeSearchTool {
    fn tool_definition() -> ToolDefinition {
        ToolDefinition {
            name: ToolName::from_string("KnowledgeSearch"),
            description: "Search the active project's source code by keyword (BM25). Use this to \
                 locate functions, patterns, or symbols across the whole codebase before reading \
                 specific files."
                .to_owned(),
            help: None,
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Keywords to search for." },
                    "limit": { "type": "integer", "description": "Max results (default 10)." }
                },
                "required": ["query"]
            }),
            result_schema: None,
            category: ToolCategory::Search,
            tool_type: ToolType::BuiltIn,
            capabilities: RuntimeCapability::default(),
            is_dangerous: false,
        }
    }

    fn new(backend: Arc<dyn crate::AgentBackend>) -> Self {
        Self {
            definition: Self::tool_definition(),
            backend,
        }
    }
}

#[async_trait::async_trait]
impl Tool for KnowledgeSearchTool {
    async fn execute(&self, input: ToolInput) -> Result<ToolOutput, ToolError> {
        let query = input
            .arguments
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_owned();
        if query.is_empty() {
            return Err(ToolError::ValidationError {
                message: "query is required".to_owned(),
            });
        }
        let Some(dir) = input.working_dir.as_deref() else {
            return Err(ToolError::Other {
                message: "no active project to search".to_owned(),
            });
        };
        let project = std::path::PathBuf::from(dir);
        let limit = input
            .arguments
            .get("limit")
            .and_then(serde_json::Value::as_u64)
            .map_or(10, |n| n as usize);

        let hits = self
            .backend
            .knowledge_search(&project, &query, limit)
            .await
            .map_err(|error| ToolError::Other {
                message: error.to_string(),
            })?;
        Ok(ToolOutput {
            success: true,
            content: hits,
            warnings: Vec::new(),
            metadata: serde_json::Value::Null,
        })
    }

    fn definition(&self) -> &ToolDefinition {
        &self.definition
    }
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
        Err(e) => error_json(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestBackend;

    #[async_trait::async_trait]
    impl crate::AgentBackend for TestBackend {
        fn provider_pool(&self) -> Option<Arc<dyn hf_core::provider::ProviderPool>> {
            None
        }

        async fn record_usage(
            &self,
            _operation: &str,
            _model: &str,
            _usage: &hf_core::types::TokenUsage,
        ) {
        }

        async fn approve_tool(&self, _tool: &str, _agent: &str) -> bool {
            true
        }

        async fn dispatch_tool(
            &self,
            _project: &std::path::Path,
            _name: &str,
            _args: &serde_json::Value,
        ) -> Result<String, hf_core::error::ClassifiedError> {
            Ok("{}".to_owned())
        }

        async fn knowledge_search(
            &self,
            project: &std::path::Path,
            query: &str,
            _limit: usize,
        ) -> Result<serde_json::Value, hf_core::error::ClassifiedError> {
            let mut hits = Vec::new();
            for entry in std::fs::read_dir(project)
                .map_err(|error| hf_core::error::ClassifiedError::Internal(error.to_string()))?
                .flatten()
            {
                let path = entry.path();
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                if content.contains(query) {
                    hits.push(serde_json::json!({
                        "path": path,
                        "content": content,
                    }));
                }
            }
            Ok(serde_json::Value::Array(hits))
        }

        fn skills_dir(&self) -> std::path::PathBuf {
            std::path::PathBuf::from("skills")
        }
    }

    fn test_backend() -> Arc<dyn crate::AgentBackend> {
        Arc::new(TestBackend)
    }

    #[test]
    fn error_json_escapes_special_characters() {
        // A realistic compiler diagnostic: quotes, a backslash path, a newline.
        let msg = "expected ';', found \"}\"\n  at C:\\src\\a.c";
        let out = error_json(msg);
        // Must be valid JSON that round-trips to the original message.
        let parsed: serde_json::Value =
            serde_json::from_str(&out).expect("error_json must be valid JSON");
        assert_eq!(parsed["error"], serde_json::Value::String(msg.to_owned()));
    }

    #[tokio::test]
    async fn registry_executes_file_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.c");
        std::fs::write(&path, "int parse_value(const char *s) { return 0; }").unwrap();

        let registry = build_inspection_registry(test_backend()).await;
        let args = serde_json::json!({ "path": path.to_str().unwrap() });
        let out = dispatch_inspection(&registry, "FileRead", &args, dir.path().to_str()).await;

        assert!(
            out.contains("parse_value"),
            "FileRead should return the file contents; got: {out}"
        );
    }

    #[tokio::test]
    async fn registry_registers_all_inspection_tools() {
        let registry = build_inspection_registry(test_backend()).await;
        assert_eq!(registry.len().await, INSPECTION_TOOLS.len());

        let advertised = INSPECTION_CATALOG
            .lines()
            .filter_map(|line| line.strip_prefix("- "))
            .filter_map(|line| line.split_once(':').map(|(name, _)| name))
            .collect::<Vec<_>>();
        assert_eq!(advertised, INSPECTION_TOOLS);
        for name in advertised {
            assert!(
                registry
                    .get_tool(&ToolName::from_string(name))
                    .await
                    .is_some(),
                "advertised inspection tool {name} has no executable registry entry"
            );
        }
    }

    #[tokio::test]
    async fn active_inspection_surface_does_not_advertise_tool_search() {
        let registry = build_inspection_registry(test_backend()).await;

        assert!(!INSPECTION_TOOLS.contains(&"ToolSearch"));
        assert!(!INSPECTION_CATALOG.contains("ToolSearch"));
        assert!(registry
            .get_tool(&ToolName::from_string("ToolSearch"))
            .await
            .is_none());
    }

    #[tokio::test]
    async fn knowledge_search_indexes_and_finds_symbols() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("chunk.c"),
            "int copy_chunk(const unsigned char *data, unsigned long len) { return 0; }",
        )
        .unwrap();

        let registry = build_inspection_registry(test_backend()).await;
        let args = serde_json::json!({ "query": "copy_chunk" });
        // working_dir carries the project root, exactly as the agent passes it.
        let out =
            dispatch_inspection(&registry, "KnowledgeSearch", &args, dir.path().to_str()).await;

        assert!(
            out.contains("copy_chunk") && out.contains("chunk.c"),
            "KnowledgeSearch should lazily index and return matching source; got: {out}"
        );
    }
}
