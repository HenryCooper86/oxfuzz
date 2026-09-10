//! Compare retained metadata without executing a provider, harness or engine.
use chrono::Utc;
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_service::ServiceContainer;
use hf_storage::{RunKind, RunRecord, RunStatus, Store};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

async fn fixture(project: &std::path::Path) -> (ServiceContainer, Arc<Store>, RunRecord) {
    let store = Arc::new(Store::connect(project.join("records.db")).await.unwrap());
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.into(),
        symbol: "parse".into(),
        language: TargetLanguage::C,
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: project.join("parser.c"),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 1.0,
        sanitizers: vec![Sanitizer::Address],
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 1,
    };
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "retained metadata fixture".into(),
        language: TargetLanguage::C,
        status: HarnessStatus::Draft,
        sanitizer: Sanitizer::Address,
        smoke_run: None,
        build_cmd: BuildCommand {
            compiler: "clang".into(),
            args: Vec::new(),
            output: "unused".into(),
            extra_flags: Vec::new(),
        },
    };
    store.upsert_harness(&harness).await.unwrap();
    let config = FuzzRunConfig {
        harness_id: harness.id,
        engine: EngineKind::LibFuzzer,
        duration: Some(Duration::from_secs(10)),
        max_mem_mb: 1024,
        max_cpus: 1,
        seed_corpus: Some(project.join("corpus")),
        sanitizer: Sanitizer::Address,
        env: Vec::new(),
        extra_args: Vec::new(),
        seed: Some(1),
        replay_of: None,
    };
    let mut run = RunRecord::new(
        project.to_string_lossy(),
        EngineKind::LibFuzzer,
        Some(config),
        Utc::now(),
    );
    run.status = RunStatus::Done;
    run.ended_at = Some(Utc::now());
    run.edges = Some((1_u64 << 53) + 9);
    run.harness_rev = Some("a".repeat(64));
    run.binary_rev = Some("b".repeat(64));
    run.context_rev = Some("c".repeat(64));
    store.insert_run(&run).await.unwrap();
    (
        ServiceContainer::stubbed().with_store(Arc::clone(&store)),
        store,
        run,
    )
}

#[tokio::test]
async fn edge_delta_requires_retained_matching_setup_and_exact_executable() {
    let root = tempfile::tempdir().unwrap();
    let (service, store, baseline) = fixture(root.path()).await;
    let mut result = baseline.clone();
    result.id = Uuid::new_v4();
    result.edges = Some((1_u64 << 53) + 2);
    store.insert_run(&result).await.unwrap();
    let assessment = service
        .run_comparison(baseline.id, result.id)
        .await
        .unwrap();
    assert!(assessment.comparable);
    assert_eq!(assessment.edge_delta.as_deref(), Some("-7"));
    assert_eq!(assessment.baseline_id, baseline.id.to_string());
    assert_eq!(assessment.result_id, result.id.to_string());
    result.id = Uuid::new_v4();
    result.binary_rev = Some("d".repeat(64));
    store.insert_run(&result).await.unwrap();
    let changed = service
        .run_comparison(baseline.id, result.id)
        .await
        .unwrap();
    assert!(!changed.comparable);
    assert_eq!(changed.setup_matches, Some(true));
    assert_eq!(changed.binary_changed, Some(true));
    assert_eq!(changed.edge_delta, None);
    assert_eq!(
        serde_json::to_value(changed).unwrap()["reason"],
        "different_executable"
    );
    result.id = Uuid::new_v4();
    result.context_rev = Some("e".repeat(64));
    store.insert_run(&result).await.unwrap();
    assert_eq!(
        serde_json::to_value(
            service
                .run_comparison(baseline.id, result.id)
                .await
                .unwrap()
        )
        .unwrap()["reason"],
        "different_setup"
    );
}

#[tokio::test]
async fn missing_or_unfinished_evidence_explains_why_comparison_is_unavailable() {
    let root = tempfile::tempdir().unwrap();
    let (service, store, baseline) = fixture(root.path()).await;
    for (kind, context, binary, edges, expected) in [
        (
            RunKind::Smoke,
            Some("c".repeat(64)),
            Some("b".repeat(64)),
            Some(10),
            "unfinished_campaign",
        ),
        (
            RunKind::Campaign,
            None,
            Some("b".repeat(64)),
            Some(10),
            "missing_setup",
        ),
        (
            RunKind::Campaign,
            Some("c".repeat(64)),
            Some(String::new()),
            Some(10),
            "missing_executable",
        ),
        (
            RunKind::Campaign,
            Some("c".repeat(64)),
            Some("b".repeat(64)),
            None,
            "missing_coverage",
        ),
    ] {
        let mut result = baseline.clone();
        result.id = Uuid::new_v4();
        result.kind = kind;
        result.context_rev = context;
        result.binary_rev = binary;
        result.edges = edges;
        store.insert_run(&result).await.unwrap();
        let assessment = service
            .run_comparison(baseline.id, result.id)
            .await
            .unwrap();
        assert!(!assessment.comparable);
        assert!(assessment.edge_delta.is_none());
        assert_eq!(
            serde_json::to_value(assessment).unwrap()["reason"],
            expected
        );
    }
    assert!(service
        .run_comparison(baseline.id, baseline.id)
        .await
        .is_err());
    assert!(service
        .run_comparison(baseline.id, Uuid::new_v4())
        .await
        .is_err());
}

#[tokio::test]
async fn retained_runs_from_different_projects_cannot_be_compared() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let (service, store, baseline) = fixture(root.path()).await;
    let mut foreign = baseline.clone();
    foreign.id = Uuid::new_v4();
    foreign.project_root = outside.path().to_string_lossy().into_owned();
    store.insert_run(&foreign).await.unwrap();
    for (first, second) in [(baseline.id, foreign.id), (foreign.id, baseline.id)] {
        let error = service.run_comparison(first, second).await.unwrap_err();
        assert!(error.to_string().contains("same project"));
    }
}
