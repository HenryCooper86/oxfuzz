//! hf-discovery: Target discovery for fuzzing.
//!
//! See `docs/design/target-discovery-design.md`.

pub mod ranking;
pub mod scanner;

pub use ranking::rank;
pub use scanner::discover;
