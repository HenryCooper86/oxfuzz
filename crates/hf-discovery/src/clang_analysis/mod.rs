//! Strict semantic evidence normalization and advisory graph queries.
mod exploration;
mod graph;
mod normalize;
pub use graph::{associate_target, selected_roots, target_context};
pub use normalize::normalize_index;

/// Invalid or unsupported analyzer evidence.
#[derive(Debug, thiserror::Error)]
#[error("invalid Clang analysis: {0}")]
pub struct ClangAnalysisError(pub String);
