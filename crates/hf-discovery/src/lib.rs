//! hf-discovery: Target discovery for fuzzing.
//!
//! See `docs/design/target-discovery-design.md`.

#[cfg(feature = "build-context")]
pub mod build_context;
pub mod ranking;
mod reachability;
pub mod scanner;
#[cfg(feature = "semgrep-enrichment")]
pub mod semgrep;

pub use ranking::rank;
pub use scanner::{discover, discoverable_source_files};
