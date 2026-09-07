//! Durable experiment storage behavior; no runtime or filesystem evidence reads.
use hf_storage::Store;
use uuid::Uuid;

#[tokio::test]
async fn absent_experiment_owner_is_none_and_list_limit_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("experiments.db"))
        .await
        .unwrap();
    assert!(store
        .coverage_experiment_owner(Uuid::new_v4())
        .await
        .unwrap()
        .is_none());
    assert!(store
        .list_coverage_experiments("/project", None, 0, None)
        .await
        .is_err());
}

#[test]
fn phase6_input_encoding_keeps_nulls_and_field_order() {
    let bytes = hf_storage::harness_build_input_digest_bytes(None, None, "flags", "image").unwrap();
    assert_eq!(bytes, br#"{"schema_version":1,"profile_sha256":null,"compile_database_sha256":null,"compile_flags_sha256":"flags","sandbox_image_id":"image"}"#);
    assert_eq!(
        hf_storage::harness_build_input_sha256(None, None, "flags", "image").unwrap(),
        "409cba9078bf100882ba6aa825f5d50b2942ce2ebd2ae8ae9fcf287f0ded222c"
    );
}

use chrono::{DateTime, Duration, Utc};
use hf_core::engine::{EngineKind, FuzzRunConfig};
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_storage::*;
use std::{path::PathBuf, time::Duration as StdDuration};

fn time() -> DateTime<Utc> {
    "2026-09-01T00:00:00.000000000Z".parse().unwrap()
}
async fn fixture(store: &Store, project: &str, start: DateTime<Utc>) -> RunRecord {
    let target = TargetCandidate {
        id: Uuid::new_v4(),
        project_root: project.into(),
        language: TargetLanguage::C,
        symbol: "parse_value".into(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: "parser.c".into(),
            line: 1,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: None,
        input_surface: InputSurface::Bytes,
        complexity: 1,
        fit_score: 0.8,
        sanitizers: vec![Sanitizer::Address],
        rationale: "parser".into(),
        reachable_functions: vec![],
        accumulated_complexity: 0,
    };
    store.upsert_target(&target, start).await.unwrap();
    let harness = Harness {
        id: Uuid::new_v4(),
        target_id: target.id,
        engine: EngineKind::LibFuzzer,
        source: "abc".into(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".into(),
            args: vec![],
            output: "parser".into(),
            extra_flags: vec![],
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    };
    store.upsert_harness(&harness).await.unwrap();
    let config = FuzzRunConfig {
        harness_id: harness.id,
        engine: harness.engine,
        duration: Some(StdDuration::from_secs(60)),
        max_mem_mb: 1024,
        max_cpus: 1,
        seed_corpus: Some(PathBuf::from("/corpus")),
        sanitizer: harness.sanitizer,
        env: vec![("A".into(), "secret".into()), ("A".into(), "second".into())],
        extra_args: vec![String::new(), "-x".into()],
        seed: Some(u64::MAX),
        replay_of: None,
    };
    let mut run = RunRecord::new(project, harness.engine, Some(config), start);
    run.status = RunStatus::Done;
    run.ended_at = Some(start + Duration::seconds(60));
    run.harness_rev =
        Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into());
    run.binary_rev = Some("b".repeat(64));
    run.source_rev = Some("c".repeat(64));
    run.corpus_rev = Some("d".repeat(64));
    run.sandbox_rev = Some(format!("docker-image-id-sha256:{}", "e".repeat(64)));
    run.edges = Some(0);
    store.insert_run(&run).await.unwrap();
    run
}
async fn proposal(store: &Store, run: &RunRecord) -> CoverageExperimentRecord {
    let baseline = store
        .coverage_experiment_run_evidence(run.id)
        .await
        .unwrap();
    CoverageExperimentRecord {
        id: Uuid::new_v4(),
        schema_version: 1,
        project_root: baseline.project_root.clone(),
        target_id: baseline.target_id,
        target_symbol: baseline.target_symbol.clone(),
        baseline_run_id: run.id,
        kind: CoverageExperimentKind::GrowCorpus,
        goal_function: "parse_value".into(),
        hypothesis: "More seeds reach the parser".into(),
        duration_secs: 60,
        baseline,
        status: CoverageExperimentStatus::Prepared,
        result: None,
        cancellation_reason: None,
        created_at: time() + Duration::seconds(120),
        updated_at: time() + Duration::seconds(120),
        ended_at: None,
    }
}
async fn result(store: &Store, base: &RunRecord) -> CoverageExperimentResultEvidenceV1 {
    let mut later = base.clone();
    later.id = Uuid::new_v4();
    later.started_at = time() + Duration::seconds(180);
    later.ended_at = Some(time() + Duration::seconds(240));
    later.status = RunStatus::Failed;
    store.insert_run(&later).await.unwrap();
    CoverageExperimentResultEvidenceV1 {
        schema_version: 1,
        run: store
            .coverage_experiment_run_evidence(later.id)
            .await
            .unwrap(),
        input_change: CoverageExperimentInputChange::NoObservedInputChange,
        build_comparison: CoverageExperimentBuildComparison::UnavailableLegacy,
        edge_comparison: CoverageExperimentEdgeComparison::Unavailable {
            reason_code: CoverageExperimentEdgeUnavailableReason::LegacyBuildInputsUnavailable,
        },
        target_entry: CoverageExperimentTargetEntry::Unavailable {
            reason_code: CoverageExperimentTargetEntryReason::NoExactRunScopedFunctionCoverage,
        },
        limitations: vec![
            CoverageExperimentLimitation::AggregateEdgesNotFunctionEntry,
            CoverageExperimentLimitation::LegacyBuildInputsUnavailable,
            CoverageExperimentLimitation::NoObservedInputChange,
            CoverageExperimentLimitation::ResultFailed,
        ],
    }
}
async fn database() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::connect(&dir.path().join("experiments.db"))
        .await
        .unwrap();
    (store, dir)
}
#[tokio::test]
async fn prepared_reconnect_exact_retry_and_scoped_keyset_history() {
    let (store, dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let first = proposal(&store, &run).await;
    store.insert_coverage_experiment(&first).await.unwrap();
    store.insert_coverage_experiment(&first).await.unwrap();
    let mut changed = first.clone();
    changed.hypothesis = "different".into();
    assert!(matches!(
        store.insert_coverage_experiment(&changed).await,
        Err(StorageError::CoverageExperimentConflict { .. })
    ));
    let mut second = first.clone();
    second.id = Uuid::new_v4();
    store.insert_coverage_experiment(&second).await.unwrap();
    let page = store
        .list_coverage_experiments("/project", Some(first.target_id), 1, None)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].id, first.id.max(second.id));
    let next = store
        .list_coverage_experiments("/project", None, 1, page.next_cursor)
        .await
        .unwrap();
    assert_eq!(next.items[0].id, first.id.min(second.id));
    assert!(next.next_cursor.is_none());
    assert!(store
        .list_coverage_experiments(
            "/other",
            None,
            1,
            Some(CoverageExperimentCursor {
                created_at: first.created_at,
                id: first.id
            })
        )
        .await
        .is_err());
    store.pool().close().await;
    let reopened = Store::connect(&dir.path().join("experiments.db"))
        .await
        .unwrap();
    assert_eq!(
        reopened.coverage_experiment(first.id).await.unwrap(),
        Some(first)
    );
}
#[tokio::test]
async fn snapshots_cannot_commit_after_source_changes_and_terminal_retries_preserve_history() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    let mut forged = p.clone();
    forged.baseline.engine_env.reverse();
    assert!(matches!(
        store.insert_coverage_experiment(&forged).await,
        Err(StorageError::CoverageExperimentSourceChanged { .. })
    ));
    store.insert_coverage_experiment(&p).await.unwrap();
    let r = result(&store, &run).await;
    let end = time() + Duration::seconds(300);
    let saved = store
        .complete_coverage_experiment(p.id, &r, end)
        .await
        .unwrap();
    store.set_run_stats(r.run.run_id, 42, 1.0, 0).await.unwrap();
    assert_eq!(
        store
            .complete_coverage_experiment(p.id, &r, end + Duration::seconds(1))
            .await
            .unwrap(),
        saved
    );
    let mut different = r.clone();
    different.run.edges = Some(42);
    assert!(matches!(
        store
            .complete_coverage_experiment(p.id, &different, end)
            .await,
        Err(StorageError::CoverageExperimentConflict { .. })
    ));
    assert!(matches!(
        store.cancel_coverage_experiment(p.id, "cancel", end).await,
        Err(StorageError::CoverageExperimentConflict { .. })
    ));
}
#[tokio::test]
async fn complete_and_cancel_writers_have_one_winner() {
    let (store, dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let r = result(&store, &run).await;
    let other = Store::connect(&dir.path().join("experiments.db"))
        .await
        .unwrap();
    let end = time() + Duration::seconds(300);
    let (complete, cancel) = tokio::join!(
        store.complete_coverage_experiment(p.id, &r, end),
        other.cancel_coverage_experiment(p.id, "cancel", end)
    );
    assert_ne!(complete.is_ok(), cancel.is_ok());
    let loser = if let Err(error) = complete {
        error
    } else {
        cancel.unwrap_err()
    };
    assert!(matches!(
        loser,
        StorageError::CoverageExperimentConflict { .. }
    ));
}
#[tokio::test]
async fn cancellation_and_reference_retention_survive_cleanup_failures() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let end = time() + Duration::seconds(300);
    let cancelled = store
        .cancel_coverage_experiment(p.id, "Hypothesis withdrawn", end)
        .await
        .unwrap();
    assert_eq!(
        store
            .cancel_coverage_experiment(p.id, "Hypothesis withdrawn", time())
            .await
            .unwrap(),
        cancelled
    );
    let reference = store
        .coverage_experiment_run_reference(run.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reference.experiment_id, p.id);
    assert_eq!(reference.role, CoverageExperimentRunRole::Baseline);
    for error in [
        store.delete_run(&run.id.to_string()).await.unwrap_err(),
        store.clear_all_runs().await.unwrap_err(),
    ] {
        assert!(
            matches!(error, StorageError::RunRetainedByExperiment { run_id, experiment_id, role: CoverageExperimentRunRole::Baseline } if run_id == run.id && experiment_id == p.id)
        );
    }
    assert!(sqlx::query("DELETE FROM runs WHERE id = ?")
        .bind(run.id.to_string())
        .execute(store.pool())
        .await
        .is_err());
    let other = fixture(&store, "/other", time()).await;
    let other_p = proposal(&store, &other).await;
    store.insert_coverage_experiment(&other_p).await.unwrap();
    store.delete_project("/project").await.unwrap();
    assert!(store.coverage_experiment(p.id).await.unwrap().is_none());
    assert!(store.get_run(run.id).await.unwrap().is_none());
    assert!(store
        .coverage_experiment(other_p.id)
        .await
        .unwrap()
        .is_some());
    store.clear_knowledge().await.unwrap();
    assert!(store.get_run(other.id).await.unwrap().is_none());
}
#[tokio::test]
async fn validation_rejects_bad_bounds_chronology_and_foreign_json() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    let mut bad = p.clone();
    bad.hypothesis = " ".into();
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    bad = p.clone();
    bad.baseline.harness_rev = "a".repeat(63);
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    bad = p.clone();
    bad.created_at = time();
    bad.updated_at = time();
    assert!(matches!(
        store.insert_coverage_experiment(&bad).await,
        Err(StorageError::CoverageExperimentInvalidChronology)
    ));
    store.insert_coverage_experiment(&p).await.unwrap();
    let r = result(&store, &run).await;
    assert!(matches!(
        store.complete_coverage_experiment(p.id, &r, time()).await,
        Err(StorageError::CoverageExperimentInvalidChronology)
    ));
    sqlx::query("DROP TRIGGER coverage_experiments_immutable_proposal")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_terminal_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE coverage_experiments SET baseline_evidence_json = json_remove(baseline_evidence_json, '$.seed') WHERE id = ?").bind(p.id.to_string()).execute(store.pool()).await.unwrap();
    assert!(store.coverage_experiment(p.id).await.is_err());
    assert!(store
        .list_coverage_experiments("/project", None, 10, None)
        .await
        .is_err());
    assert_eq!(
        store
            .coverage_experiment_owner(p.id)
            .await
            .unwrap()
            .unwrap()
            .target_id,
        p.target_id
    );
}

#[tokio::test]
async fn canonical_project_path_can_retain_a_space_in_the_last_component() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project ", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    assert_eq!(
        store
            .coverage_experiment_owner(p.id)
            .await
            .unwrap()
            .unwrap()
            .project_root,
        "/project "
    );
}
#[tokio::test]
async fn inconsistent_comparison_tags_are_rejected_before_terminal_commit() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let r = result(&store, &run).await;
    let end = time() + Duration::seconds(300);
    let mut bad = r.clone();
    bad.build_comparison = CoverageExperimentBuildComparison::Matched;
    assert!(store
        .complete_coverage_experiment(p.id, &bad, end)
        .await
        .is_err());
    bad = r.clone();
    bad.input_change = CoverageExperimentInputChange::HarnessSourceChanged;
    assert!(store
        .complete_coverage_experiment(p.id, &bad, end)
        .await
        .is_err());
    bad = r.clone();
    bad.edge_comparison = CoverageExperimentEdgeComparison::Observed {
        baseline_edges: 0,
        result_edges: 0,
        delta: 0,
    };
    assert!(store
        .complete_coverage_experiment(p.id, &bad, end)
        .await
        .is_err());
    bad = r.clone();
    bad.edge_comparison = CoverageExperimentEdgeComparison::Unavailable {
        reason_code: CoverageExperimentEdgeUnavailableReason::ResultEdgesUnavailable,
    };
    assert!(store
        .complete_coverage_experiment(p.id, &bad, end)
        .await
        .is_err());
    assert_eq!(
        store
            .coverage_experiment(p.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        CoverageExperimentStatus::Prepared
    );
}
#[tokio::test]
async fn changed_result_source_is_refused_without_modifying_prepared_proposal() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let r = result(&store, &run).await;
    store.set_run_stats(r.run.run_id, 1, 2.0, 0).await.unwrap();
    assert!(
        matches!(store.complete_coverage_experiment(p.id, &r, time() + Duration::seconds(300)).await, Err(StorageError::CoverageExperimentSourceChanged { run_id }) if run_id == r.run.run_id)
    );
    assert_eq!(store.coverage_experiment(p.id).await.unwrap(), Some(p));
}
async fn inputs(store: &Store, run: &RunRecord) -> HarnessBuildInputsRecord {
    let mut record = HarnessBuildInputsRecord {
        harness_id: run.config.as_ref().unwrap().harness_id,
        project_root: run.project_root.clone(),
        profile_sha256: None,
        compile_database_sha256: None,
        compile_flags_sha256: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
            .into(),
        sandbox_image_id: format!("sha256:{}", "e".repeat(64)),
        build_input_sha256: String::new(),
        created_at: time() - Duration::seconds(1),
    };
    record.build_input_sha256 = harness_build_input_sha256(
        None,
        None,
        &record.compile_flags_sha256,
        &record.sandbox_image_id,
    )
    .unwrap();
    store.set_harness_build_inputs(&record).await.unwrap();
    record
}
#[tokio::test]
async fn captured_build_metadata_is_exact_and_bad_digest_or_late_capture_is_refused() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let saved = inputs(&store, &run).await;
    let p = proposal(&store, &run).await;
    assert_eq!(p.baseline.build_inputs, Some(saved.clone()));
    assert_eq!(p.baseline.seed, Some(u64::MAX));
    assert_eq!(p.baseline.engine_args, ["", "-x"]);
    store.insert_coverage_experiment(&p).await.unwrap();
    let json: String =
        sqlx::query_scalar("SELECT baseline_evidence_json FROM coverage_experiments WHERE id = ?")
            .bind(p.id.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(json.contains("2026-09-01T00:00:00.000000000Z"));
    assert!(json.contains("2026-08-31T23:59:59.000000000Z"));
    let mut forged = p.clone();
    forged.id = Uuid::new_v4();
    forged
        .baseline
        .build_inputs
        .as_mut()
        .unwrap()
        .build_input_sha256 = "f".repeat(64);
    assert!(store.insert_coverage_experiment(&forged).await.is_err());
    forged = p.clone();
    forged.id = Uuid::new_v4();
    forged.baseline.build_inputs.as_mut().unwrap().created_at = time() + Duration::seconds(1);
    assert!(matches!(
        store.insert_coverage_experiment(&forged).await,
        Err(StorageError::CoverageExperimentInvalidChronology)
    ));
    sqlx::query("DELETE FROM harnesses WHERE id = ?")
        .bind(saved.harness_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(store.coverage_experiment(p.id).await.unwrap(), Some(p));
}
#[tokio::test]
async fn matching_captured_builds_keep_zero_baseline_signed_delta() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    inputs(&store, &run).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let mut r = result(&store, &run).await;
    store.set_run_stats(r.run.run_id, 7, 0.0, 0).await.unwrap();
    r.run = store
        .coverage_experiment_run_evidence(r.run.run_id)
        .await
        .unwrap();
    r.build_comparison = CoverageExperimentBuildComparison::Matched;
    r.edge_comparison = CoverageExperimentEdgeComparison::Observed {
        baseline_edges: 0,
        result_edges: 7,
        delta: 7,
    };
    r.limitations
        .retain(|l| *l != CoverageExperimentLimitation::LegacyBuildInputsUnavailable);
    let saved = store
        .complete_coverage_experiment(p.id, &r, time() + Duration::seconds(300))
        .await
        .unwrap();
    assert_eq!(saved.result.unwrap().edge_comparison, r.edge_comparison);
    let reference = store
        .coverage_experiment_run_reference(r.run.run_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reference.role, CoverageExperimentRunRole::Result);
    assert!(matches!(
        store.delete_run(&r.run.run_id.to_string()).await,
        Err(StorageError::RunRetainedByExperiment {
            role: CoverageExperimentRunRole::Result,
            ..
        })
    ));
}
#[tokio::test]
async fn damaged_evidence_is_never_absence_but_owner_projection_still_works() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_immutable_proposal")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_terminal_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    let json: String =
        sqlx::query_scalar("SELECT baseline_evidence_json FROM coverage_experiments")
            .fetch_one(store.pool())
            .await
            .unwrap();
    let original: serde_json::Value = serde_json::from_str(&json).unwrap();
    let mut mutations = Vec::new();
    for (key, value) in [
        ("schema_version", serde_json::json!(2)),
        ("engine", serde_json::json!("LibFuzzer")),
        ("started_at", serde_json::json!("2026-09-01T00:00:00+00:00")),
        ("source_rev", serde_json::json!("C".repeat(64))),
        ("sandbox_rev", serde_json::json!("e".repeat(64))),
        ("edges", serde_json::json!(-1)),
        ("unknown", serde_json::json!(null)),
    ] {
        let mut value_copy = original.clone();
        value_copy[key] = value;
        mutations.push(value_copy.to_string());
    }
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("build_inputs");
    mutations.push(missing.to_string());
    mutations.push(json.replacen('{', "{\"seed\":null,", 1));
    // Bypass SQL checks on this single connection to represent damaged durable media.
    let mut tx = store.pool().begin().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *tx)
        .await
        .unwrap();
    for corrupt in mutations {
        sqlx::query("UPDATE coverage_experiments SET baseline_evidence_json = ?")
            .bind(&corrupt)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(store.coverage_experiment(p.id).await.is_err());
        assert!(store
            .coverage_experiment_owner(p.id)
            .await
            .unwrap()
            .is_some());
        tx = store.pool().begin().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn schema_rejects_replacement_proposal_edits_and_invalid_scalar_formats() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    assert!(sqlx::query(
        "INSERT OR REPLACE INTO coverage_experiments SELECT * FROM coverage_experiments"
    )
    .execute(store.pool())
    .await
    .is_err());
    assert!(
        sqlx::query("UPDATE coverage_experiments SET hypothesis = 'different'")
            .execute(store.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE coverage_experiments SET status = 'prepared'")
            .execute(store.pool())
            .await
            .is_err()
    );
    sqlx::query("DROP TRIGGER coverage_experiments_immutable_proposal")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_terminal_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    for assignment in [
        "duration_secs = 0",
        "duration_secs = 604801",
        "target_symbol = ' '",
        "hypothesis = char(0)",
        "schema_version = 2",
        "created_at = '2026-02-30T00:00:00.000000000Z'",
        "created_at = '2026-09-01T00:00:00Z'",
        "id = '00000000-0000-0000-0000-000000000000'",
        "result_evidence_json = '{}'",
        "status = 'completed'",
    ] {
        assert!(
            sqlx::query(&format!("UPDATE coverage_experiments SET {assignment}"))
                .execute(store.pool())
                .await
                .is_err(),
            "accepted {assignment}"
        );
    }
}
#[tokio::test]
async fn run_retention_preserves_crashes_and_explicit_cleanup_preserves_configuration() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    sqlx::query("INSERT INTO crashes (id, run_id, target_id, stack_signature, kind, summary, minimized, data_json) VALUES (?, ?, ?, 'sig', 'unknown', 'fixture', 0, '{}')").bind(Uuid::new_v4().to_string()).bind(run.id.to_string()).bind(p.target_id.to_string()).execute(store.pool()).await.unwrap();
    store
        .set_project_auto_revert(
            "/project",
            ProjectAutoRevert {
                enabled: true,
                threshold_pct: 10.0,
                notify_only: true,
            },
        )
        .await
        .unwrap();
    assert!(store.delete_run(&run.id.to_string()).await.is_err());
    assert!(store.clear_all_runs().await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crashes")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
    store.clear_knowledge().await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM crashes")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(store
        .project_auto_revert("/project")
        .await
        .unwrap()
        .is_some());
}
#[tokio::test]
async fn negative_source_edges_and_duplicate_config_keys_fail_strict_snapshot_read() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    sqlx::query("UPDATE runs SET edges = -1")
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store
        .coverage_experiment_run_evidence(run.id)
        .await
        .is_err());
    sqlx::query(
        "UPDATE runs SET edges = 0, config_json = replace(config_json, '{', '{\"seed\":null,')",
    )
    .execute(store.pool())
    .await
    .unwrap();
    assert!(store
        .coverage_experiment_run_evidence(run.id)
        .await
        .is_err());
}

#[tokio::test]
async fn calendar_checks_do_not_accept_invalid_days_at_the_maximum_year() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_immutable_proposal")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_terminal_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    for timestamp in [
        "9999-12-99T00:00:00.000000000Z",
        "2026-02-30T00:00:00.000000000Z",
        "2026-01-01T00:00:60.000000000Z",
        "0000-01-01T00:00:00.000000000Z",
    ] {
        assert!(
            sqlx::query("UPDATE coverage_experiments SET created_at = ?1, updated_at = ?1")
                .bind(timestamp)
                .execute(store.pool())
                .await
                .is_err(),
            "accepted {timestamp}"
        );
    }
}
#[tokio::test]
async fn legacy_baseline_and_captured_result_retain_mixed_input_evidence() {
    let (store, _dir) = database().await;
    let base = fixture(&store, "/project", time()).await;
    let mut p = proposal(&store, &base).await;
    p.kind = CoverageExperimentKind::RefineHarness;
    store.insert_coverage_experiment(&p).await.unwrap();
    // Capture inputs after the legacy proposal; its retained null stays immutable.
    inputs(&store, &base).await;
    let r = result(&store, &base).await;
    assert!(p.baseline.build_inputs.is_none());
    assert!(r.run.build_inputs.is_some());
    let saved = store
        .complete_coverage_experiment(p.id, &r, time() + Duration::seconds(300))
        .await
        .unwrap();
    assert!(saved.baseline.build_inputs.is_none());
    assert!(saved.result.unwrap().run.build_inputs.is_some());
}
#[tokio::test]
async fn failed_and_cancelled_campaigns_remain_eligible_but_active_and_smoke_runs_do_not() {
    let (store, _dir) = database().await;
    let mut run = fixture(&store, "/project", time()).await;
    for status in [RunStatus::Failed, RunStatus::Cancelled] {
        store
            .set_run_status(run.id, status, run.ended_at)
            .await
            .unwrap();
        let p = proposal(&store, &run).await;
        assert_eq!(p.baseline.status, status);
        store.insert_coverage_experiment(&p).await.unwrap();
    }
    store
        .set_run_status(run.id, RunStatus::Running, run.ended_at)
        .await
        .unwrap();
    assert!(store
        .coverage_experiment_run_evidence(run.id)
        .await
        .is_err());
    run.id = Uuid::new_v4();
    run.kind = RunKind::Smoke;
    store.insert_run(&run).await.unwrap();
    assert!(store
        .coverage_experiment_run_evidence(run.id)
        .await
        .is_err());
}
#[tokio::test]
async fn envelope_and_per_field_limits_reject_without_truncation() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    let mut bad = p.clone();
    bad.baseline.engine_args = vec!["x".repeat(4097)];
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    let mut bad = p.clone();
    bad.baseline.engine_env = (0..17).map(|_| ("A".into(), "x".repeat(4096))).collect();
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    bad = p.clone();
    bad.baseline.engine_args = vec![String::new(); 129];
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    bad = p.clone();
    bad.baseline.engine_env = vec![("A".into(), "secret\0value".into())];
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    bad = p.clone();
    bad.hypothesis = "x\rhidden".into();
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    bad = p.clone();
    bad.baseline.edges = Some(u64::MAX);
    assert!(store.insert_coverage_experiment(&bad).await.is_err());
    assert!(store
        .list_coverage_experiments("/project", None, 101, None)
        .await
        .is_err());
    store.insert_coverage_experiment(&p).await.unwrap();
    assert!(store
        .cancel_coverage_experiment(p.id, "\t", p.created_at)
        .await
        .is_err());
    assert!(store
        .cancel_coverage_experiment(p.id, "x\u{7f}", p.created_at)
        .await
        .is_err());
}
#[tokio::test]
async fn unexpected_cross_project_run_reference_rolls_back_project_cleanup() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_immutable_proposal")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_terminal_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE coverage_experiments SET project_root = '/foreign', baseline_evidence_json = json_set(baseline_evidence_json, '$.project_root', '/foreign')").execute(store.pool()).await.unwrap();
    assert!(store.delete_project("/project").await.is_err());
    assert!(store.get_run(run.id).await.unwrap().is_some());
    assert!(store
        .get_harness(run.config.unwrap().harness_id)
        .await
        .unwrap()
        .is_some());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM coverage_experiments")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
}
#[tokio::test]
async fn differing_complete_writers_have_one_immutable_result() {
    let (store, dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let first = result(&store, &run).await;
    let second = result(&store, &run).await;
    let other = Store::connect(&dir.path().join("experiments.db"))
        .await
        .unwrap();
    let end = time() + Duration::seconds(300);
    let (a, b) = tokio::join!(
        store.complete_coverage_experiment(p.id, &first, end),
        other.complete_coverage_experiment(p.id, &second, end)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let saved = store.coverage_experiment(p.id).await.unwrap().unwrap();
    assert!(
        matches!(saved.result.as_ref().unwrap().run.run_id, id if id == first.run.run_id || id == second.run.run_id)
    );
    assert!(
        sqlx::query("UPDATE coverage_experiments SET updated_at = ended_at")
            .execute(store.pool())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_uuid_variant_is_rejected_on_durable_reads() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let p = proposal(&store, &run).await;
    store.insert_coverage_experiment(&p).await.unwrap();
    let invalid_id: Uuid = "11111111-1111-4111-0111-111111111111".parse().unwrap();
    let mut tx = store.pool().begin().await.unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_immutable_proposal")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER coverage_experiments_terminal_immutable")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE coverage_experiments SET id = ?")
        .bind(invalid_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(store.coverage_experiment(invalid_id).await.is_err());
}

#[tokio::test]
async fn source_uuid_spelling_is_not_silently_normalized() {
    let (store, _dir) = database().await;
    let run = fixture(&store, "/project", time()).await;
    let config_id = run.config.as_ref().unwrap().harness_id;
    sqlx::query("UPDATE runs SET config_json = json_set(config_json, '$.harness_id', ?)")
        .bind(config_id.simple().to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store
        .coverage_experiment_run_evidence(run.id)
        .await
        .is_err());
}
