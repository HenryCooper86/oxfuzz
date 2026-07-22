//! hf-test-utils: shared test fixtures, mock providers/storage. Ported from
//! y-agent's y-test-utils (`mock_runtime` deferred until the tool runtime lands).

pub mod assert_helpers;
pub mod fixtures;
pub mod mock_provider;
pub mod mock_storage;

/// Stable content-addressed image identity for runtime test doubles that
/// exercise proof-carrying smoke or campaign paths.
///
/// # Errors
/// Returns an error if the static fixture stops satisfying the production
/// immutable-image validator.
pub fn immutable_test_image(
) -> Result<hf_core::runtime::ImmutableImageReference, hf_core::error::ClassifiedError> {
    hf_core::runtime::ImmutableImageReference::from_sha256_id(format!("sha256:{}", "a".repeat(64)))
}
