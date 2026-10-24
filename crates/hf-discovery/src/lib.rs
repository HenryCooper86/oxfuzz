//! hf-discovery: Target discovery for fuzzing.
//!
//! See `docs/design/target-discovery-design.md`.

#[cfg(feature = "ai-target-ranking")]
pub mod ai_ranking;
#[cfg(feature = "build-context")]
pub mod build_context;
pub mod enrichment;
mod reachability;
pub mod scanner;
#[cfg(feature = "semgrep-enrichment")]
pub mod semgrep;

pub use scanner::{discover, discover_with_signals, discoverable_source_files};

#[cfg(feature = "clang-analysis")]
pub mod clang_analysis;
