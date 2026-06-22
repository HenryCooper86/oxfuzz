//! Tool registry traits.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::error::ClassifiedError;

/// Context passed to every tool invocation.
#[derive(Debug, Clone)]
pub struct ToolContext {
    pub run_id: crate::types::Id,
    pub workspace: std::path::PathBuf,
    pub user_approved: bool,
}

/// Output of a tool invocation.
#[derive(Debug, Clone)]
pub struct ToolOutput {
    pub content: String,
    pub structured: Option<Value>,
}

/// A tool the agent can call.
#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn schema(&self) -> Value;
    async fn call(&self, args: Value, ctx: &ToolContext) -> Result<ToolOutput, ClassifiedError>;
}

/// A registry of tools.
#[async_trait]
pub trait ToolRegistry: Send + Sync {
    async fn get(&self, name: &str) -> Option<Box<dyn Tool>>;
    async fn list(&self) -> Vec<String>;
    async fn call(
        &self,
        name: &str,
        args: Value,
        ctx: &ToolContext,
    ) -> Result<ToolOutput, ClassifiedError>;
}

/// A simple in-memory tool registry (for testing).
#[derive(Default)]
pub struct InMemoryToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl InMemoryToolRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name().to_owned(), tool);
    }
}

#[async_trait]
impl ToolRegistry for InMemoryToolRegistry {
    async fn get(&self, _name: &str) -> Option<Box<dyn Tool>> {
        // Generic `Box<dyn Tool>` cannot be cloned without a `Clone` super-trait;
        // callers should use `call` directly. This stub returns `None`.
        None
    }

    async fn list(&self) -> Vec<String> {
        self.tools.keys().cloned().collect()
    }

    async fn call(
        &self,
        name: &str,
        _args: Value,
        _ctx: &ToolContext,
    ) -> Result<ToolOutput, ClassifiedError> {
        Err(ClassifiedError::Internal(format!(
            "tool '{name}' not callable in stub registry"
        )))
    }
}
