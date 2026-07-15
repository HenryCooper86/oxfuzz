//! Persistent diagnostics retain historical traces without mixing their cost
//! into the current service session.

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
async fn session_summary_excludes_calls_from_older_recorder_instances() {
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

    // Session 2: a brand-new recorder on the same DB == a restart. Its summary
    // must remain session-scoped even though the earlier traces still exist.
    let rec2 = DiagnosticsRecorder::with_store(
        costs,
        Arc::new(SqliteTraceStore::new(store.pool().clone())),
    );
    rec2.record("triage", "gpt", &usage(500, 250)).await; // 0.5 + 0.5 = 1.0
    let persisted_trace_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM diag_traces")
        .fetch_one(store.pool())
        .await
        .expect("count retained traces");
    assert_eq!(persisted_trace_count, 3, "history remains available");
    let summary = rec2.summary().await.expect("current session summary");

    assert_eq!(summary.calls, 1, "older sessions must be excluded");
    assert_eq!(summary.input_tokens, 500);
    assert_eq!(summary.output_tokens, 250);
    assert!(
        (summary.cost_usd - 1.0).abs() < 1e-9,
        "session cost was {}",
        summary.cost_usd
    );
    assert_eq!(summary.by_model.len(), 1);
    assert_eq!(summary.by_model[0].model, "gpt");
}

#[tokio::test]
async fn session_summary_surfaces_trace_store_failures() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(dir.path().join("hf.db"))
        .await
        .expect("connect");
    let recorder = DiagnosticsRecorder::with_store(
        HashMap::new(),
        Arc::new(SqliteTraceStore::new(store.pool().clone())),
    );

    sqlx::query("DROP TABLE diag_traces")
        .execute(store.pool())
        .await
        .expect("break diagnostics store");

    let error = recorder
        .summary()
        .await
        .expect_err("a broken store must not look like zero calls");
    assert!(error.to_string().contains("list_traces_by_session"));
}
