//! Read-only inspection tools shipped with `oxfuzz`.
//!
//! The active agent explicitly registers these three tools and adds its
//! service-backed `KnowledgeSearch` implementation. Mutating files, executing
//! commands, delegating agents, and changing workflows are service-owned
//! operations; they are deliberately not exposed as generic built-in tools.

mod path_utils;

pub mod file_read;
pub mod glob;
pub mod grep;
