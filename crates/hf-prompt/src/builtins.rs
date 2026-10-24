//! Compile-time prompt sections embedded from `config/prompts/*.txt`.
//!
//! These are the fixed sections of the agent system prompt assembled by
//! [`crate::agent`]. There is no runtime override mechanism: the prompts are
//! compile-time constants of the binary, and no loader reads a user prompts
//! directory.

/// The invariant identity section of the agent system prompt.
pub(crate) const PROMPT_IDENTITY: &str = include_str!("../../../config/prompts/core_identity.txt");

/// The invariant security section of the agent system prompt.
pub(crate) const PROMPT_SECURITY: &str = include_str!("../../../config/prompts/core_security.txt");

/// The tool-catalog protocol section of the agent system prompt.
pub(crate) const PROMPT_TOOL_PROTOCOL: &str =
    include_str!("../../../config/prompts/core_tool_protocol.txt");
