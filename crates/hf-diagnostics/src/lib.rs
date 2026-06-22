//! hf-diagnostics: Cost intelligence and run replay.
//!
//! See `docs/design/` and AGENTS.md section on observability.

pub mod cost;
pub mod journal;

pub use cost::{CostSummary, CostTracker, ProviderCost};
pub use journal::{RunEvent, RunJournal};
