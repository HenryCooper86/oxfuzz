//! Context pruning: intra-turn dead-branch removal for attention quality.
//!
//! [`IntraTurnPruner`] removes failed and empty tool-call branches from the
//! working history within a single turn (zero LLM cost), keeping model
//! attention on the live path. This is the pruning path wired into the agent
//! reason/act loop.

pub mod config;
pub mod intra_turn;
pub mod patterns;

pub use config::IntraTurnPruningConfig;
pub use intra_turn::{IntraTurnPruner, IntraTurnPruningReport};
