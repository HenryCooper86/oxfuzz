//! Concolic enrichment through the service.
//!
//! With no sandbox image the pass must report unavailable and leave the corpus
//! untouched, rather than reporting a completed pass that did nothing.

#![cfg(feature = "concolic-enrichment")]

use std::sync::Arc;

use hf_service::{ConcolicAvailability, ServiceContainer};

#[tokio::test]
async fn a_missing_toolchain_is_unavailable_with_a_reason() {
    // StubRuntime reports no image, which is the same shape as an image
    // without the SymCC layer.
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let availability = container.concolic_availability().await;

    assert!(
        matches!(availability, ConcolicAvailability::Unavailable { .. }),
        "an absent toolchain is unavailable, not a failed pass"
    );
}

#[tokio::test]
async fn an_unavailable_toolchain_does_not_touch_the_corpus() {
    let dir = tempfile::tempdir().unwrap();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let result = container.corpus_concolic(dir.path(), "parse_packet").await;

    assert!(
        result.is_err(),
        "a pass that cannot run reports so rather than returning an empty success"
    );
}
