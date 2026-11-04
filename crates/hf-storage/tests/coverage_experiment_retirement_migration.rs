//! Migration 0051 drops the retired coverage-experiment tables, so their
//! `ON DELETE RESTRICT` references can no longer block deleting a run.

#[tokio::test]
async fn drops_every_coverage_experiment_object() {
    let dir = tempfile::tempdir().unwrap();
    let store = hf_storage::Store::connect(dir.path().join("store.db"))
        .await
        .unwrap();
    let remaining: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE name LIKE '%coverage_experiment%' ORDER BY name",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert!(remaining.is_empty(), "left behind: {remaining:?}");
}
