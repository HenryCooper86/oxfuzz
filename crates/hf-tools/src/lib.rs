//! `hobot_fuzz` tool registry, JSON Schema validation, and execution support.
//!
//! This crate provides the reusable tool-management infrastructure for the
//! agent:
//!
//! - [`ToolRegistryImpl`] — manages tool registration, lookup, and search
//! - [`ToolIndex`] — compact entries for LLM context (name+description only)
//! - [`ToolActivationSet`] — LRU cache of active tools (ceiling: 20)
//! - [`JsonSchemaValidator`] — parameter validation with compiled schema cache
//! - [`ToolExecutor`] — validates + runs tools through middleware chain
//! - [`DynamicToolManager`] — CRUD lifecycle for agent-created tools
//! - [`RateLimiter`] — per-tool token-bucket rate limiting
//! - [`ResultFormatter`] — formats tool output for LLM consumption
//! - [`builtin::file_read`], [`builtin::glob`], and [`builtin::grep`] — the
//!   project-scoped, read-only inspection tools used by the active agent
//!
//! # Executable surface
//!
//! A registry starts empty. Its owner must register each executable tool
//! explicitly and advertise only those entries. `hf-agent` registers the
//! three inspection tools above plus its service-backed `KnowledgeSearch`.
//! Shell execution, file mutation, delegation, workflow mutation, and fuzzing
//! actions are not generic built-ins; those operations remain behind the
//! service's guardrail, approval, and sandbox boundaries.

pub mod activation;
pub mod builtin;
pub mod config;
pub mod dynamic;
pub mod error;
pub mod executor;
pub mod formatter;
pub mod index;
pub mod mcp_integration;
pub mod mcp_toml;
pub mod parser;
pub mod rate_limiter;
pub mod registry;
pub mod taxonomy;
pub mod validator;

// Re-export primary types.
pub use activation::ToolActivationSet;
pub use config::ToolRegistryConfig;
pub use dynamic::{DynamicToolDef, DynamicToolKind, DynamicToolManager};
pub use error::ToolRegistryError;
pub use executor::ToolExecutor;
pub use formatter::{FormattedResult, FormatterConfig, ResultFormat, ResultFormatter};
pub use index::ToolIndex;
pub use mcp_integration::McpServerConfig;
pub use parser::{
    format_tool_result, parse_tool_calls, strip_tool_call_blocks, ParseResult, ParsedToolCall,
};
pub use rate_limiter::{RateLimitConfig, RateLimitResult, RateLimiter};
pub use registry::ToolRegistryImpl;
pub use taxonomy::ToolTaxonomy;
pub use validator::JsonSchemaValidator;
