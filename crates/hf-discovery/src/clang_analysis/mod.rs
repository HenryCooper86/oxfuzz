//! Strict semantic evidence normalization and advisory graph queries.
mod graph;
mod normalize;
pub use graph::{associate_target, reachable_functions, target_context};
pub use normalize::normalize_index;

/// Invalid or unsupported analyzer evidence.
#[derive(Debug, thiserror::Error)]
#[error("invalid Clang analysis: {0}")]
pub struct ClangAnalysisError(pub String);
