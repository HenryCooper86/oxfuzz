//! Concolic enrichment through the service.
//!
//! With no sandbox image the pass must report unavailable and leave the corpus
//! untouched, rather than reporting a completed pass that did nothing.

#![cfg(feature = "concolic-enrichment")]

use std::path::Path;
use std::sync::Arc;

use hf_service::{ConcolicAvailability, ServiceContainer};
use uuid::Uuid;

/// A dedicated workspace root for this test file only, isolated from every
/// other integration test binary (each `tests/*.rs` file is its own process).
///
/// Every test calls this first: the availability probe prepares and then runs
/// in the approved workspace root, so an unset override would have these tests
/// touching the real per-user application directory.
fn workspace_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!(
            "oxfuzz_concolic_service_{}_{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::env::set_var("HF_WORKSPACE_DIR", &root);
        hf_service::initialize_workspace_root().unwrap();
        root
    })
}

#[tokio::test]
async fn a_missing_toolchain_is_unavailable_with_a_reason() {
    // StubRuntime fails every command, which is the same shape as an image
    // without the SymCC layer.
    workspace_root();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let availability = container.concolic_availability().await;

    assert!(
        matches!(availability, ConcolicAvailability::Unavailable { .. }),
        "an absent toolchain is unavailable, not a failed pass"
    );
}

#[tokio::test]
async fn an_unavailable_toolchain_does_not_touch_the_corpus() {
    workspace_root();
    let project = tempfile::tempdir().unwrap();
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let result = container
        .corpus_concolic(project.path(), "parse_packet")
        .await;

    assert!(
        result.is_err(),
        "a pass that cannot run reports so rather than returning an empty success"
    );
}
