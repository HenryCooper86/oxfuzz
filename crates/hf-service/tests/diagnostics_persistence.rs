//! Diagnostics cost/usage must survive a "restart": a fresh recorder built on
//! the same database sees the cost recorded by an earlier one.

use std::collections::HashMap;
use std::sync::Arc;

use hf_core::types::TokenUsage;
use hf_diagnostics::SqliteTraceStore;
use hf_service::diagnostics::DiagnosticsRecorder;
use hf_storage::Store;

fn usage(input: u32, output: u32) -> TokenUsage {
    TokenUsage {
        input_tokens: input,
        output_tokens: output,
        ..TokenUsage::default()
    }
}

#[tokio::test]
async fn cost_persists_across_recorder_instances() {
    let dir = tempfile::tempdir().unwrap();
    // Store::connect runs migrations, creating the diag_* tables (0003).
    let store = Store::connect(dir.path().join("hf.db"))
        .await
        .expect("connect");

    let mut costs = HashMap::new();
    costs.insert("gpt".to_owned(), (1.0, 2.0)); // $1/1k in, $2/1k out

    // Session 1: record two LLM calls, then drop the recorder (simulating quit).
    let rec1 = DiagnosticsRecorder::with_store(
        costs.clone(),
        Arc::new(SqliteTraceStore::new(store.pool().clone())),
    );
    rec1.record("harness_draft", "gpt", &usage(1000, 500)).await; // 1.0 + 1.0 = 2.0
    rec1.record("chat", "gpt", &usage(2000, 1000)).await; // 2.0 + 2.0 = 4.0
    drop(rec1);

    // Session 2: a brand-new recorder on the same DB == a restart.
    let rec2 = DiagnosticsRecorder::with_store(
        costs,
        Arc::new(SqliteTraceStore::new(store.pool().clone())),
    );
    let summary = rec2.summary().await;

    assert_eq!(summary.calls, 2, "both calls should persist");
    assert_eq!(summary.input_tokens, 3000);
    assert_eq!(summary.output_tokens, 1500);
    assert!(
        (summary.cost_usd - 6.0).abs() < 1e-9,
        "cumulative cost was {}",
        summary.cost_usd
    );
    assert_eq!(summary.by_model.len(), 1);
    assert_eq!(summary.by_model[0].model, "gpt");
}
