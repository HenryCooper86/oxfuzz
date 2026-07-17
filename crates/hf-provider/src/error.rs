//! Crate-level error types for y-provider.

/// Errors from the provider pool layer.
///
/// These are distinct from `hf_core::provider::ProviderError` which represents
/// individual provider failures. `ProviderPoolError` represents pool-level
/// issues (config, routing decisions, pool management).
#[derive(Debug, thiserror::Error)]
pub enum ProviderPoolError {
    #[error("provider pool configuration error: {message}")]
    Config { message: String },

    #[error("duplicate provider id: {id}")]
    DuplicateProvider { id: String },
}
