//! hf-discovery: Target discovery for fuzzing.
//!
//! See `docs/design/target-discovery-design.md`.

pub mod ranking;
mod reachability;
pub mod scanner;
#[cfg(feature = "semgrep-enrichment")]
pub mod semgrep;

pub use ranking::rank;
pub use scanner::{discover, discoverable_source_files};
