use hf_storage::{RunEdgeSetRecord, RunRecord, Store};
use uuid::Uuid;

fn edge_map(edges: &[u64]) -> Vec<u8> {
    let mut map = vec![0_u8; hf_core::coverage::EDGE_SET_BYTES];
    for edge in edges {
        let index = usize::try_from(*edge).unwrap();
        map[index / 8] |= 1 << (index % 8);
    }
    map
}

async fn afl_run(store: &Store) -> RunRecord {
    let mut run = RunRecord::new(
        "/project",
        hf_core::engine::EngineKind::AflPlusPlus,
        None,
        chrono::Utc::now(),
    );
    run.binary_rev = Some("a".repeat(64));
    run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "b".repeat(64)));
    store.insert_run(&run).await.unwrap();
    run
}

fn record(run: &RunRecord, edges: &[u64], inputs: u64) -> RunEdgeSetRecord {
    RunEdgeSetRecord {
        run_id: run.id,
        binary_sha256: run.binary_rev.clone().unwrap(),
        sandbox_rev: run.sandbox_rev.clone().unwrap(),
        inputs,
        edge_count: edges.len() as u64,
        edge_map: edge_map(edges),
        collected_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn edge_set_evidence_is_owned_by_the_exact_run_and_cannot_be_replaced() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("edges.db"))
        .await
        .unwrap();
    let run = afl_run(&store).await;
    let evidence = record(&run, &[1, 42, 65_535], 7);

    let mut wrong = evidence.clone();
    wrong.run_id = Uuid::new_v4();
    assert!(store.record_run_edge_set(&wrong).await.is_err());
    wrong = evidence.clone();
    wrong.binary_sha256 = "c".repeat(64);
    assert!(store.record_run_edge_set(&wrong).await.is_err());
    wrong = evidence.clone();
    wrong.sandbox_rev = format!("docker-image-id-sha256:{}", "d".repeat(64));
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    store.record_run_edge_set(&evidence).await.unwrap();
    // An identical retry preserves the original evidence.
    store.record_run_edge_set(&evidence).await.unwrap();
    // Different evidence for the same run is rejected, never replaced.
    wrong = evidence.clone();
    wrong.edge_count = 1;
    wrong.edge_map = edge_map(&[1]);
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    assert_eq!(
        store.run_edge_set(run.id).await.unwrap(),
        Some(evidence.clone())
    );
    // Another run has no set yet: absence is explicit, not an empty map.
    let other = afl_run(&store).await;
    assert_eq!(store.run_edge_set(other.id).await.unwrap(), None);
}

#[tokio::test]
async fn edge_set_validation_rejects_malformed_and_inconsistent_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("edges.db"))
        .await
        .unwrap();
    let run = afl_run(&store).await;
    let evidence = record(&run, &[9], 3);

    let mut wrong = evidence.clone();
    wrong.edge_map.truncate(65_535);
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    let mut wrong = evidence.clone();
    wrong.edge_count = 2; // popcount says 1
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    let mut wrong = evidence.clone();
    wrong.inputs = 0;
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    let mut wrong = evidence.clone();
    wrong.binary_sha256 = "not-a-digest".to_owned();
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    let mut wrong = evidence.clone();
    wrong.sandbox_rev = "oxfuzz/fuzz-sandbox:latest".to_owned();
    assert!(store.record_run_edge_set(&wrong).await.is_err());

    assert!(store.run_edge_set(run.id).await.unwrap().is_none());
}
