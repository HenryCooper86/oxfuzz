//! `oxfuzz` tool registry, JSON Schema validation, and execution support.
//!
//! This crate provides the reusable tool-management infrastructure for the
//! agent:
//!
//! - [`ToolRegistryImpl`] — manages tool registration, lookup, and search
//! - [`ToolIndex`] — compact entries for LLM context (name+description only)
//! - [`JsonSchemaValidator`] — parameter validation with compiled schema cache
//! - [`ToolExecutor`] — validates and executes registered tools
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

pub mod builtin;
pub mod config;
pub mod error;
pub mod executor;
pub mod index;
pub mod registry;
pub mod validator;

// Re-export primary types.
pub use config::ToolRegistryConfig;
pub use error::ToolRegistryError;
pub use executor::ToolExecutor;
pub use index::ToolIndex;
pub use registry::ToolRegistryImpl;
pub use validator::JsonSchemaValidator;
