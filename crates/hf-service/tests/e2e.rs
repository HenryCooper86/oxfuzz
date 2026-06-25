//! End-to-end (Docker-free) smoke test of the discovery -> persistence path:
//! discover targets in a fixture C project through the `ServiceContainer`, then
//! confirm they were persisted and can be reloaded from the store.

use std::sync::Arc;

use hf_core::target::TargetLanguage;
use hf_service::ServiceContainer;

const FIXTURE: &str = r"
#include <stddef.h>
#include <stdint.h>

// A parser-shaped function: a byte buffer + length is an obvious fuzz target.
int parse_value(const uint8_t *data, size_t len) {
    if (len >= 4 && data[0] == 'F' && data[1] == 'U' && data[2] == 'Z' && data[3] == 'Z') {
        return 1;
    }
    return 0;
}

int helper_add(int a, int b) { return a + b; }
";

#[tokio::test]
async fn discover_persists_and_reloads() {
    let proj = tempfile::tempdir().unwrap();
    std::fs::write(proj.path().join("parser.c"), FIXTURE).unwrap();

    let db = tempfile::tempdir().unwrap();
    let store = Arc::new(
        hf_storage::Store::connect(db.path().join("e2e.db"))
            .await
            .unwrap(),
    );
    let container = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None)
        .with_store(Arc::clone(&store));

    // Discover (this also persists the inventory via the store).
    let inv = container
        .discover(proj.path(), TargetLanguage::C)
        .await
        .unwrap();
    assert!(
        !inv.candidates.is_empty(),
        "expected at least one fuzzing target in the fixture"
    );
    assert!(
        inv.candidates.iter().any(|c| c.symbol == "parse_value"),
        "expected parse_value to be discovered"
    );

    // Reload from persistence and confirm the round-trip. Key off the
    // candidate's own project_root (the scanner may canonicalize the path,
    // e.g. /var -> /private/var on macOS).
    let key = inv.candidates[0].project_root.to_string_lossy().to_string();
    let reloaded = store.list_targets(&key).await.unwrap();
    assert_eq!(
        reloaded.len(),
        inv.candidates.len(),
        "persisted target count should match the discovered inventory"
    );
    assert!(reloaded.iter().any(|c| c.symbol == "parse_value"));
}
