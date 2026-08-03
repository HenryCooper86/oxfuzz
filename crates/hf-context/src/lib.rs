//! hf-context: message-history context assembly, compaction, and intra-turn
//! pruning.
//!
//! This crate provides the token-budget machinery the agent reason/act loop
//! uses to keep a flat `Vec<Message>` conversation within the model's context
//! window:
//!
//! - [`assemble`] / [`prune_tool_results_by_age`] / [`cap_fresh_tool_result`] —
//!   budget-aware trimming of the working history ([`simple`]).
//! - [`CompactionEngine`] — summarizes older turns to reclaim space
//!   ([`compaction`]).
//! - [`pruning::IntraTurnPruner`] — removes dead tool-call branches within a
//!   turn ([`pruning`]).

pub mod compaction;
pub mod pruning;
pub mod simple;
pub mod token_utils;

pub use compaction::{
    CompactionConfig, CompactionEngine, CompactionLlm, CompactionResult, CompactionStrategy,
    IdentifierPolicy,
};
pub use simple::{
    assemble, cap_fresh_tool_result, estimate_tokens, prune_tool_results_by_age, total_tokens,
    DEFAULT_BUDGET_TOKENS,
};
