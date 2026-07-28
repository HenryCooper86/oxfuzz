//! Integration tests for the `SQLite` [`Store`].

use std::path::PathBuf;

use chrono::{Duration, Utc};
use hf_core::corpus::{CorpusEntry, CorpusSource};
use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::EngineKind;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_storage::{
    AutoRevertEvent, AutomotiveOperationRecord, AutomotiveOperationStatus,
    AutomotiveStateCorpusRecord, GuardrailDecisionRecord, HarnessApprovalKind, ProjectAutoRevert,
    RunKind, RunRecord, RunStatus, SemgrepFindingRecord, SemgrepFindingSeverity,
    SemgrepPublication, SemgrepRunRecord, SemgrepRunStatus, SemgrepTargetScoreRecord, StorageError,
    Store,
};
use uuid::Uuid;

async fn temp_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let store = Store::connect(&path).await.expect("connect");
    (store, dir)
}

fn semgrep_staging_run(project_root: &str, started_at: chrono::DateTime<Utc>) -> SemgrepRunRecord {
    SemgrepRunRecord {
        id: Uuid::new_v4(),
        project_root: project_root.to_owned(),
        language: "c".to_owned(),
        source_sha256: None,
        sandbox_image: "oxfuzz-semgrep:1.169.0".to_owned(),
        sandbox_image_sha256: "11".repeat(32),
        semgrep_version: "1.169.0".to_owned(),
        rules_commit: "4d66ecf30bfb1809a984085f2c86a8c3915bfc71".to_owned(),
        rules_tree_sha256: "22".repeat(32),
        command_schema_version: 1,
        status: SemgrepRunStatus::Staging,
        started_at,
        ended_at: None,
        output_sha256: None,
        finding_count: None,
        matched_candidate_count: None,
        duration_ms: None,
        failure_code: None,
        failure_message: None,
    }
}

fn semgrep_publication(
    mut run: SemgrepRunRecord,
    finding_count: usize,
    score_count: usize,
) -> SemgrepPublication {
    run.status = SemgrepRunStatus::Done;
    run.source_sha256 = Some("33".repeat(32));
    run.ended_at = Some(run.started_at + Duration::milliseconds(250));
    run.output_sha256 = Some("44".repeat(32));
    run.finding_count = Some(u32::try_from(finding_count).unwrap());
    run.matched_candidate_count = Some(u32::try_from(score_count).unwrap());
    run.duration_ms = Some(250);
    let findings = (0..finding_count)
        .map(|index| SemgrepFindingRecord {
            scan_id: run.id,
            fingerprint: format!("{index:064x}"),
            rule_id: format!("raptor.rule-{index}"),
            severity: SemgrepFindingSeverity::Warning,
            message: format!("advisory finding {index}"),
            relative_file: format!("src/parser-{index}.c"),
            start_line: u32::try_from(index + 1).unwrap(),
            start_col: 1,
            end_line: u32::try_from(index + 1).unwrap(),
            end_col: 5,
            target_id: (index < score_count).then(Uuid::new_v4),
            nominal_weight: 0.05,
        })
        .collect();
    let mut scores = (0..score_count)
        .map(|index| SemgrepTargetScoreRecord {
            scan_id: run.id,
            target_id: Uuid::new_v4(),
            base_score: 0.6,
            boost: 0.05,
            effective_score: 0.65,
            matched_rule_count: u32::try_from(index + 1).unwrap(),
        })
        .collect::<Vec<_>>();
    scores.sort_by_key(|score| score.target_id);
    SemgrepPublication {
        run,
        findings,
        scores,
    }
}

async fn advance_semgrep_to_persisting(store: &Store, run: &mut SemgrepRunRecord) {
    store.insert_semgrep_run(run).await.unwrap();
    store
        .set_semgrep_phase(
            run.id,
            SemgrepRunStatus::Staging,
            SemgrepRunStatus::Scanning,
            Some(&"33".repeat(32)),
        )
        .await
        .unwrap();
    store
        .set_semgrep_phase(
            run.id,
            SemgrepRunStatus::Scanning,
            SemgrepRunStatus::Validating,
            None,
        )
        .await
        .unwrap();
    store
        .set_semgrep_phase(
            run.id,
            SemgrepRunStatus::Validating,
            SemgrepRunStatus::Persisting,
            None,
        )
        .await
        .unwrap();
    run.status = SemgrepRunStatus::Persisting;
    run.source_sha256 = Some("33".repeat(32));
}

#[tokio::test]
async fn semgrep_phase_compare_and_set_and_active_project_index_are_enforced() {
    let (store, _dir) = temp_store().await;
    let started_at = Utc::now();
    let mut run = semgrep_staging_run("/projects/parser", started_at);
    store.insert_semgrep_run(&run).await.unwrap();
    assert_eq!(store.semgrep_run(run.id).await.unwrap(), Some(run.clone()));

    let invalid = store
        .set_semgrep_phase(
            run.id,
            SemgrepRunStatus::Scanning,
            SemgrepRunStatus::Validating,
            None,
        )
        .await;
    assert!(matches!(invalid, Err(StorageError::NotFound(_))));
    store
        .set_semgrep_phase(
            run.id,
            SemgrepRunStatus::Staging,
            SemgrepRunStatus::Scanning,
            Some(&"33".repeat(32)),
        )
        .await
        .unwrap();
    run.status = SemgrepRunStatus::Scanning;
    run.source_sha256 = Some("33".repeat(32));
    assert_eq!(store.semgrep_run(run.id).await.unwrap(), Some(run));

    let duplicate = semgrep_staging_run("/projects/parser", started_at + Duration::seconds(1));
    assert!(matches!(
        store.insert_semgrep_run(&duplicate).await,
        Err(StorageError::Db(_))
    ));
}

#[tokio::test]
async fn semgrep_publication_persists_complete_overlay_and_latest_done_run() {
    let (store, _dir) = temp_store().await;
    let mut older = semgrep_staging_run("/projects/parser", Utc::now());
    advance_semgrep_to_persisting(&store, &mut older).await;
    let older_publication = semgrep_publication(older, 2, 1);
    store.publish_semgrep_run(&older_publication).await.unwrap();
    assert_eq!(
        store
            .semgrep_publication(older_publication.run.id)
            .await
            .unwrap(),
        Some(older_publication.clone())
    );

    let persisted = store
        .semgrep_run(older_publication.run.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(persisted.status, SemgrepRunStatus::Done);
    assert_eq!(persisted.source_sha256, Some("33".repeat(32)));
    assert_eq!(persisted.output_sha256, Some("44".repeat(32)));
    assert_eq!(persisted.finding_count, Some(2));
    assert_eq!(persisted.matched_candidate_count, Some(1));
    assert_eq!(persisted.duration_ms, Some(250));

    let mut newer = semgrep_staging_run("/projects/parser", Utc::now() + Duration::seconds(10));
    advance_semgrep_to_persisting(&store, &mut newer).await;
    let newer_publication = semgrep_publication(newer, 1, 1);
    store.publish_semgrep_run(&newer_publication).await.unwrap();
    assert_eq!(
        store
            .latest_semgrep_publication("/projects/parser", "c")
            .await
            .unwrap(),
        Some(newer_publication)
    );
    assert!(store
        .latest_semgrep_publication("/projects/parser", "cpp")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn semgrep_publication_rolls_back_every_child_when_second_finding_fails() {
    let (store, _dir) = temp_store().await;
    let mut run = semgrep_staging_run("/projects/parser", Utc::now());
    advance_semgrep_to_persisting(&store, &mut run).await;
    sqlx::query(
        "CREATE TRIGGER reject_second_semgrep_finding
         BEFORE INSERT ON semgrep_findings
         WHEN NEW.rule_id = 'raptor.rule-1'
         BEGIN
             SELECT RAISE(ABORT, 'injected second finding failure');
         END",
    )
    .execute(store.pool())
    .await
    .unwrap();
    let publication = semgrep_publication(run, 2, 1);

    assert!(matches!(
        store.publish_semgrep_run(&publication).await,
        Err(StorageError::Db(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM semgrep_findings WHERE scan_id = ?1")
            .bind(publication.run.id.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM semgrep_target_scores WHERE scan_id = ?1"
        )
        .bind(publication.run.id.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
    assert_eq!(
        store
            .semgrep_run(publication.run.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        SemgrepRunStatus::Persisting
    );
}

#[tokio::test]
async fn semgrep_publication_rejects_changed_parent_identity() {
    let (store, _dir) = temp_store().await;
    let mut run = semgrep_staging_run("/projects/parser", Utc::now());
    advance_semgrep_to_persisting(&store, &mut run).await;
    let mut publication = semgrep_publication(run, 1, 1);
    publication.run.project_root = "/projects/substituted".to_owned();

    assert!(matches!(
        store.publish_semgrep_run(&publication).await,
        Err(StorageError::InvalidData(_))
    ));
    assert_eq!(
        store
            .semgrep_run(publication.run.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        SemgrepRunStatus::Persisting
    );
}

#[tokio::test]
async fn semgrep_failure_rejects_an_end_time_before_admission() {
    let (store, _dir) = temp_store().await;
    let started_at = Utc::now();
    let run = semgrep_staging_run("/projects/parser", started_at);
    store.insert_semgrep_run(&run).await.unwrap();

    assert!(matches!(
        store
            .fail_semgrep_run(
                run.id,
                SemgrepRunStatus::Failed,
                "failure",
                "invalid terminal timestamp",
                started_at - Duration::milliseconds(1),
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));
    assert_eq!(
        store.semgrep_run(run.id).await.unwrap().unwrap().status,
        SemgrepRunStatus::Staging
    );
}

#[tokio::test]
async fn semgrep_failure_cancellation_and_compensation_remove_children() {
    let (store, _dir) = temp_store().await;
    let mut published = semgrep_staging_run("/projects/published", Utc::now());
    advance_semgrep_to_persisting(&store, &mut published).await;
    let publication = semgrep_publication(published, 2, 2);
    store.publish_semgrep_run(&publication).await.unwrap();
    store
        .compensate_semgrep_publication(
            publication.run.id,
            "journal_commit_failed",
            "terminal journal record could not be written",
            Utc::now(),
        )
        .await
        .unwrap();
    let compensated = store
        .semgrep_publication(publication.run.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(compensated.run.status, SemgrepRunStatus::Failed);
    assert!(compensated.findings.is_empty());
    assert!(compensated.scores.is_empty());

    for (project, status) in [
        ("/projects/failed", SemgrepRunStatus::Failed),
        ("/projects/cancelled", SemgrepRunStatus::Cancelled),
    ] {
        let mut run = semgrep_staging_run(project, Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        sqlx::query(
            "INSERT INTO semgrep_findings
                (scan_id, fingerprint, rule_id, severity, message, relative_file,
                 start_line, start_col, end_line, end_col, target_id, nominal_weight)
             VALUES (?1, ?2, 'raptor.injected', 'info', 'partial child', 'src/partial.c',
                     1, 1, 1, 2, NULL, 0.01)",
        )
        .bind(run.id.to_string())
        .bind("55".repeat(32))
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO semgrep_target_scores
                (scan_id, target_id, base_score, boost, effective_score, matched_rule_count)
             VALUES (?1, ?2, 0.5, 0.0, 0.5, 0)",
        )
        .bind(run.id.to_string())
        .bind(Uuid::new_v4().to_string())
        .execute(store.pool())
        .await
        .unwrap();
        store
            .fail_semgrep_run(
                run.id,
                status,
                "operator",
                "operation terminated",
                Utc::now(),
            )
            .await
            .unwrap();
        let terminal = store.semgrep_publication(run.id).await.unwrap().unwrap();
        assert_eq!(terminal.run.status, status);
        assert!(terminal.findings.is_empty());
        assert!(terminal.scores.is_empty());
    }
    assert!(matches!(
        store
            .fail_semgrep_run(
                Uuid::new_v4(),
                SemgrepRunStatus::Done,
                "invalid",
                "done is not a failure state",
                Utc::now(),
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));
}

#[tokio::test]
async fn semgrep_records_follow_project_and_knowledge_cleanup() {
    let (store, _dir) = temp_store().await;
    for project in ["/projects/delete", "/projects/keep"] {
        let mut run = semgrep_staging_run(project, Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        let publication = semgrep_publication(run, 1, 1);
        store.publish_semgrep_run(&publication).await.unwrap();
    }

    store.delete_project("/projects/delete").await.unwrap();
    assert!(store
        .latest_semgrep_publication("/projects/delete", "c")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .latest_semgrep_publication("/projects/keep", "c")
        .await
        .unwrap()
        .is_some());

    store.clear_knowledge().await.unwrap();
    assert!(store
        .latest_semgrep_publication("/projects/keep", "c")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn semgrep_typed_reads_reject_malformed_persisted_fields() {
    let malformed_run_fields = [
        ("id", "'not-a-uuid'"),
        ("status", "'unknown'"),
        ("started_at", "'not-a-timestamp'"),
        ("source_sha256", "'short'"),
        ("finding_count", "-1"),
    ];
    for (column, value) in malformed_run_fields {
        let (store, _dir) = temp_store().await;
        let mut run = semgrep_staging_run("/projects/malformed", Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        let publication = if column == "id" {
            semgrep_publication(run, 0, 0)
        } else {
            semgrep_publication(run, 1, 1)
        };
        store.publish_semgrep_run(&publication).await.unwrap();
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(&format!(
            "UPDATE semgrep_enrichment_runs SET {column} = {value} WHERE id = ?1"
        ))
        .bind(publication.run.id.to_string())
        .execute(&mut *connection)
        .await
        .unwrap();
        drop(connection);
        let result = if column == "id" {
            let malformed_id =
                sqlx::query_scalar::<_, String>("SELECT id FROM semgrep_enrichment_runs")
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            let row = sqlx::query("SELECT id FROM semgrep_enrichment_runs WHERE id = ?1")
                .bind(malformed_id)
                .fetch_one(store.pool())
                .await
                .unwrap();
            assert_eq!(sqlx::Row::get::<String, _>(&row, "id"), "not-a-uuid");
            store
                .latest_semgrep_publication("/projects/malformed", "c")
                .await
        } else {
            store.semgrep_publication(publication.run.id).await
        };
        assert!(
            matches!(
                result,
                Err(StorageError::InvalidData(_)
                    | StorageError::Timestamp(_)
                    | StorageError::Serde(_))
            ),
            "{column} unexpectedly decoded"
        );
    }

    let malformed_finding_fields = [
        ("severity", "'unknown'"),
        ("start_line", "0"),
        ("nominal_weight", "0.02"),
        ("target_id", "'not-a-uuid'"),
    ];
    for (column, value) in malformed_finding_fields {
        let (store, _dir) = temp_store().await;
        let mut run = semgrep_staging_run("/projects/malformed-finding", Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        let publication = semgrep_publication(run, 1, 1);
        store.publish_semgrep_run(&publication).await.unwrap();
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(&format!(
            "UPDATE semgrep_findings SET {column} = {value} WHERE scan_id = ?1"
        ))
        .bind(publication.run.id.to_string())
        .execute(&mut *connection)
        .await
        .unwrap();
        drop(connection);
        assert!(
            matches!(
                store.semgrep_publication(publication.run.id).await,
                Err(StorageError::InvalidData(_) | StorageError::Serde(_))
            ),
            "{column} unexpectedly decoded"
        );
    }

    let malformed_score_fields = [
        ("target_id", "'not-a-uuid'"),
        ("base_score", "1.5"),
        ("matched_rule_count", "-1"),
    ];
    for (column, value) in malformed_score_fields {
        let (store, _dir) = temp_store().await;
        let mut run = semgrep_staging_run("/projects/malformed-score", Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        let publication = semgrep_publication(run, 1, 1);
        store.publish_semgrep_run(&publication).await.unwrap();
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(&format!(
            "UPDATE semgrep_target_scores SET {column} = {value} WHERE scan_id = ?1"
        ))
        .bind(publication.run.id.to_string())
        .execute(&mut *connection)
        .await
        .unwrap();
        drop(connection);
        assert!(
            matches!(
                store.semgrep_publication(publication.run.id).await,
                Err(StorageError::InvalidData(_))
            ),
            "{column} unexpectedly decoded"
        );
    }
}

#[tokio::test]
async fn automotive_operation_evidence_round_trips_and_updates_terminal_state() {
    let (store, _dir) = temp_store().await;
    let id = Uuid::new_v4();
    let started_at = Utc::now();
    let operation = AutomotiveOperationRecord {
        id,
        project_root: "/projects/vehicle-parser".to_owned(),
        operation: "analyze_pcap".to_owned(),
        mode: "offline_pcap".to_owned(),
        protocol: Some("uds".to_owned()),
        status: AutomotiveOperationStatus::Running,
        started_at,
        ended_at: None,
        request_hash: "request-sha256".to_owned(),
        transcript_hash: None,
        artifact_dir: "automotive/operation-id".to_owned(),
        approval_json: None,
        result_json: None,
        error: None,
    };

    store.insert_automotive_operation(&operation).await.unwrap();
    assert_eq!(
        store.automotive_operation(id).await.unwrap(),
        Some(operation.clone())
    );

    let ended_at = Utc::now();
    store
        .complete_automotive_operation(
            id,
            AutomotiveOperationStatus::Done,
            ended_at,
            Some("transcript-sha256"),
            Some(r#"{"state_findings":["session:extended"]}"#),
            None,
        )
        .await
        .unwrap();

    let completed = store
        .automotive_operation(id)
        .await
        .unwrap()
        .expect("persisted operation");
    assert_eq!(completed.status, AutomotiveOperationStatus::Done);
    assert_eq!(completed.ended_at, Some(ended_at));
    assert_eq!(
        completed.transcript_hash.as_deref(),
        Some("transcript-sha256")
    );
    assert!(completed
        .result_json
        .as_deref()
        .is_some_and(|value| value.contains("state_findings")));
}

#[tokio::test]
async fn automotive_operation_completion_rejects_non_terminal_status() {
    let (store, _dir) = temp_store().await;
    let error = store
        .complete_automotive_operation(
            Uuid::new_v4(),
            AutomotiveOperationStatus::Running,
            Utc::now(),
            None,
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, StorageError::InvalidData(_)));
}

#[tokio::test]
async fn automotive_state_corpus_is_idempotent_and_project_scoped() {
    let (store, _dir) = temp_store().await;
    let source_operation_id = Uuid::new_v4();
    let started_at = Utc::now();
    store
        .insert_automotive_operation(&AutomotiveOperationRecord {
            id: source_operation_id,
            project_root: "/projects/vehicle-parser".to_owned(),
            operation: "analyze_capture".to_owned(),
            mode: "offline_pcap".to_owned(),
            protocol: Some("uds".to_owned()),
            status: AutomotiveOperationStatus::Running,
            started_at,
            ended_at: None,
            request_hash: "11".repeat(32),
            transcript_hash: None,
            artifact_dir: "projects/vehicle/.service/automotive/source".to_owned(),
            approval_json: None,
            result_json: None,
            error: None,
        })
        .await
        .unwrap();
    let transcript_hash = "22".repeat(32);
    store
        .complete_automotive_operation(
            source_operation_id,
            AutomotiveOperationStatus::Done,
            Utc::now(),
            Some(&transcript_hash),
            Some(r#"{"result":"capture_analysis"}"#),
            None,
        )
        .await
        .unwrap();

    let created_at = Utc::now();
    let record = AutomotiveStateCorpusRecord {
        project_root: "/projects/vehicle-parser".to_owned(),
        protocol: "uds".to_owned(),
        state_digest: "33".repeat(32),
        artifact_sha256: "44".repeat(32),
        source_operation_id,
        artifact_path: "projects/vehicle/.service/automotive/state-corpus/uds/state/artifact"
            .to_owned(),
        created_at,
    };

    let inserted = store.record_automotive_state_corpus(&record).await.unwrap();
    assert_eq!(inserted, record);
    assert_eq!(
        store
            .automotive_state_corpus_entry(
                &record.project_root,
                &record.protocol,
                &record.state_digest,
                &record.artifact_sha256,
            )
            .await
            .unwrap(),
        Some(record.clone())
    );

    let duplicate = AutomotiveStateCorpusRecord {
        artifact_path: "must/not/replace/the/original".to_owned(),
        created_at: Utc::now(),
        ..record.clone()
    };
    assert_eq!(
        store
            .record_automotive_state_corpus(&duplicate)
            .await
            .unwrap(),
        record
    );

    let listed = store
        .automotive_state_corpus("/projects/vehicle-parser", 20)
        .await
        .unwrap();
    assert_eq!(listed, vec![record]);
    assert!(store
        .automotive_state_corpus("/projects/another-vehicle", 20)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn automotive_state_corpus_rejects_noncompleted_or_mismatched_sources() {
    let (store, _dir) = temp_store().await;
    let source_operation_id = Uuid::new_v4();
    store
        .insert_automotive_operation(&AutomotiveOperationRecord {
            id: source_operation_id,
            project_root: "/projects/vehicle-parser".to_owned(),
            operation: "analyze_capture".to_owned(),
            mode: "offline_pcap".to_owned(),
            protocol: Some("uds".to_owned()),
            status: AutomotiveOperationStatus::Running,
            started_at: Utc::now(),
            ended_at: None,
            request_hash: "11".repeat(32),
            transcript_hash: None,
            artifact_dir: "projects/vehicle/.service/automotive/source".to_owned(),
            approval_json: None,
            result_json: None,
            error: None,
        })
        .await
        .unwrap();
    let record = AutomotiveStateCorpusRecord {
        project_root: "/projects/vehicle-parser".to_owned(),
        protocol: "uds".to_owned(),
        state_digest: "33".repeat(32),
        artifact_sha256: "44".repeat(32),
        source_operation_id,
        artifact_path: "projects/vehicle/.service/automotive/state-corpus/uds/state/artifact"
            .to_owned(),
        created_at: Utc::now(),
    };

    assert!(matches!(
        store.record_automotive_state_corpus(&record).await,
        Err(StorageError::InvalidData(_))
    ));

    store
        .complete_automotive_operation(
            source_operation_id,
            AutomotiveOperationStatus::Done,
            Utc::now(),
            None,
            Some(r#"{"result":"capture_analysis"}"#),
            None,
        )
        .await
        .unwrap();
    let wrong_project = AutomotiveStateCorpusRecord {
        project_root: "/projects/another".to_owned(),
        ..record.clone()
    };
    assert!(matches!(
        store.record_automotive_state_corpus(&wrong_project).await,
        Err(StorageError::InvalidData(_))
    ));
    let wrong_protocol = AutomotiveStateCorpusRecord {
        protocol: "can".to_owned(),
        ..record
    };
    assert!(matches!(
        store.record_automotive_state_corpus(&wrong_protocol).await,
        Err(StorageError::InvalidData(_))
    ));
}

#[test]
fn applied_run_revision_migration_remains_byte_for_byte_immutable() {
    // sqlx stores a checksum for every applied migration. Editing an old SQL
    // file, including its comments, prevents existing databases from opening.
    assert_eq!(
        include_str!("../migrations/0009_run_harness_rev.sql"),
        "-- Record which harness revision a run used, as a short content hash of the\n\
         -- harness source. Lets run history tie a coverage jump to the harness change\n\
         -- that produced it. Nullable; forward-only.\n\
         ALTER TABLE runs ADD COLUMN harness_rev TEXT;\n"
    );
}

#[tokio::test]
async fn database_standard_has_exact_migrated_table_and_column_parity() {
    let (store, _dir) = temp_store().await;
    let standard = include_str!("../../../docs/standards/DATABASE_SCHEMA.md");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_schema
         WHERE type = 'table'
           AND name NOT LIKE 'sqlite_%'
           AND name <> '_sqlx_migrations'
         ORDER BY name",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();

    let mut documented_tables = standard
        .lines()
        .filter_map(|line| {
            line.strip_prefix("### `")
                .or_else(|| line.strip_prefix("#### `"))
        })
        .filter_map(|line| line.strip_suffix('`'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    documented_tables.sort();
    assert_eq!(documented_tables, tables, "documented table set drifted");

    for table in tables {
        let level_three_heading = format!("### `{table}`");
        let level_four_heading = format!("#### `{table}`");
        let (heading, section_start) = standard
            .find(&level_three_heading)
            .map(|start| (level_three_heading, start))
            .or_else(|| {
                standard
                    .find(&level_four_heading)
                    .map(|start| (level_four_heading, start))
            })
            .expect("documented table heading");
        let after_heading = &standard[section_start + heading.len()..];
        let next_h2 = after_heading.find("\n## ");
        let next_h3_or_h4 = after_heading.find("\n###");
        let section_end = match (next_h2, next_h3_or_h4) {
            (Some(h2), Some(h3)) => h2.min(h3),
            (Some(end), None) | (None, Some(end)) => end,
            (None, None) => after_heading.len(),
        };
        let documented_columns = after_heading[..section_end]
            .lines()
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|line| line.split_once("` |").map(|(name, _)| name.to_owned()))
            .collect::<Vec<_>>();
        let migrated_columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info(?1) ORDER BY cid")
                .bind(&table)
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert_eq!(
            documented_columns, migrated_columns,
            "documented columns drifted for {table}"
        );
    }
}

fn sample_target(project: &str) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: PathBuf::from(project),
        language: TargetLanguage::C,
        symbol: "parse_value".to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: PathBuf::from("src/json.c"),
            line: 12,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some("int parse_value(const char*)".to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 7,
        fit_score: 0.82,
        sanitizers: vec![Sanitizer::Address],
        rationale: "hot parser path".to_owned(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 0,
    }
}

#[tokio::test]
async fn project_auto_revert_override_upserts_and_clears() {
    let (store, _dir) = temp_store().await;
    let project = "/home/user/proj-a";

    // No override initially -> None (inherit global).
    assert_eq!(store.project_auto_revert(project).await.unwrap(), None);

    // Set an override and read it back verbatim.
    let over = ProjectAutoRevert {
        enabled: true,
        threshold_pct: 42.5,
        notify_only: true,
    };
    store.set_project_auto_revert(project, over).await.unwrap();
    assert_eq!(
        store.project_auto_revert(project).await.unwrap(),
        Some(over)
    );

    // Upsert replaces the row rather than duplicating it.
    let updated = ProjectAutoRevert {
        enabled: false,
        threshold_pct: 10.0,
        notify_only: false,
    };
    store
        .set_project_auto_revert(project, updated)
        .await
        .unwrap();
    assert_eq!(
        store.project_auto_revert(project).await.unwrap(),
        Some(updated)
    );

    // A different project is independent.
    assert_eq!(
        store
            .project_auto_revert("/home/user/proj-b")
            .await
            .unwrap(),
        None
    );

    // Clearing removes the override (back to inherit).
    store.clear_project_auto_revert(project).await.unwrap();
    assert_eq!(store.project_auto_revert(project).await.unwrap(), None);
}

#[tokio::test]
async fn all_project_auto_reverts_lists_only_overridden_projects() {
    let (store, _dir) = temp_store().await;
    assert!(store.all_project_auto_reverts().await.unwrap().is_empty());

    let a = ProjectAutoRevert {
        enabled: true,
        threshold_pct: 25.0,
        notify_only: false,
    };
    let b = ProjectAutoRevert {
        enabled: false,
        threshold_pct: 15.0,
        notify_only: true,
    };
    store.set_project_auto_revert("/p/a", a).await.unwrap();
    store.set_project_auto_revert("/p/b", b).await.unwrap();

    let all: std::collections::HashMap<String, ProjectAutoRevert> = store
        .all_project_auto_reverts()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(all.len(), 2);
    assert_eq!(all.get("/p/a"), Some(&a));
    assert_eq!(all.get("/p/b"), Some(&b));

    // Cleared projects drop out of the listing.
    store.clear_project_auto_revert("/p/a").await.unwrap();
    let all = store.all_project_auto_reverts().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, "/p/b");
}

#[tokio::test]
async fn auto_revert_events_record_list_scope_and_order() {
    let (store, _dir) = temp_store().await;
    assert!(store
        .list_auto_revert_events(None, 50)
        .await
        .unwrap()
        .is_empty());

    let mk = |id: &str, ts: &str, project: &str, reverted: bool| AutoRevertEvent {
        id: id.to_owned(),
        ts: ts.to_owned(),
        project_root: project.to_owned(),
        target: "parse".to_owned(),
        run_id: "run-1".to_owned(),
        from_rev: "aaaaaaaaaaaa".to_owned(),
        to_rev: "bbbbbbbbbbbb".to_owned(),
        previous_edges: 1000,
        regressed_edges: 700,
        drop_pct: 30.0,
        reverted,
    };
    store
        .record_auto_revert_event(&mk("e1", "2026-07-01T10:00:00Z", "/p/a", true))
        .await
        .unwrap();
    store
        .record_auto_revert_event(&mk("e2", "2026-07-02T10:00:00Z", "/p/a", false))
        .await
        .unwrap();
    store
        .record_auto_revert_event(&mk("e3", "2026-07-03T10:00:00Z", "/p/b", true))
        .await
        .unwrap();

    // Newest first, across all projects.
    let all = store.list_auto_revert_events(None, 50).await.unwrap();
    assert_eq!(
        all.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["e3", "e2", "e1"]
    );

    // Scoped to one project.
    let a = store
        .list_auto_revert_events(Some("/p/a"), 50)
        .await
        .unwrap();
    assert_eq!(
        a.iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        ["e2", "e1"]
    );
    assert!(!a[0].reverted, "e2 was notify-only");

    // Limit caps the rows.
    assert_eq!(
        store.list_auto_revert_events(None, 1).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn append_message_assigns_monotonic_seq_and_orders_history() {
    let (store, _dir) = temp_store().await;
    let session = store.create_session(None, Utc::now()).await.unwrap();

    store
        .append_message(session, "user", "first", Utc::now())
        .await
        .unwrap();
    store
        .append_message(session, "assistant", "second", Utc::now())
        .await
        .unwrap();
    store
        .append_message(session, "user", "third", Utc::now())
        .await
        .unwrap();

    let history = store.session_history(session).await.unwrap();
    assert_eq!(
        history,
        vec![
            ("user".to_owned(), "first".to_owned()),
            ("assistant".to_owned(), "second".to_owned()),
            ("user".to_owned(), "third".to_owned()),
        ]
    );
}

#[tokio::test]
async fn concurrent_appends_get_distinct_seqs() {
    // The atomic INSERT...SELECT must not assign duplicate seq under concurrency.
    let (store, _dir) = temp_store().await;
    let store = std::sync::Arc::new(store);
    let session = store.create_session(None, Utc::now()).await.unwrap();

    let mut handles = Vec::new();
    for i in 0..20 {
        let s = std::sync::Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            s.append_message(session, "user", &format!("m{i}"), Utc::now())
                .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    // Every append got a distinct, gapless seq 0..20 (no collision, none lost).
    let seqs: Vec<i64> =
        sqlx::query_scalar("SELECT seq FROM messages WHERE session_id = ?1 ORDER BY seq ASC")
            .bind(session.to_string())
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(
        seqs,
        (0..20).collect::<Vec<i64>>(),
        "seqs must be distinct 0..20"
    );
}

#[tokio::test]
async fn dedupe_crashes_collapses_same_run_and_signature() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let target = Uuid::new_v4();
    let mk = |sig: &str| Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id: target,
        input_path: PathBuf::from("out/crash"),
        stack_signature: sig.to_owned(),
        kind: CrashKind::Asan,
        summary: "boom".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };
    // Two rows share a signature (legacy duplicate); one distinct signature;
    // two empty-signature rows that must NOT be collapsed.
    for c in [mk("S"), mk("S"), mk("T"), mk(""), mk("")] {
        store.upsert_crash(&c).await.unwrap();
    }
    assert_eq!(store.list_crashes_by_run(run.id).await.unwrap().len(), 5);

    store.dedupe_crashes().await.unwrap();

    // "S" collapses to 1, "T" stays, both empty-sig rows stay -> 4.
    let remaining = store.list_crashes_by_run(run.id).await.unwrap();
    assert_eq!(remaining.len(), 4, "got {:?}", remaining.len());
    assert_eq!(
        remaining
            .iter()
            .filter(|c| c.stack_signature == "S")
            .count(),
        1
    );
    assert_eq!(
        remaining
            .iter()
            .filter(|c| c.stack_signature.is_empty())
            .count(),
        2
    );

    // Idempotent: a second pass removes nothing.
    store.dedupe_crashes().await.unwrap();
    assert_eq!(store.list_crashes_by_run(run.id).await.unwrap().len(), 4);
}

#[tokio::test]
async fn list_all_crashes_is_newest_first_by_insertion_order() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let target_id = Uuid::new_v4();
    let crash = |id: &str, summary: &str| Crash {
        id: Uuid::parse_str(id).unwrap(),
        run_id: run.id,
        target_id,
        input_path: PathBuf::from(format!("out/{summary}")),
        stack_signature: summary.to_owned(),
        kind: CrashKind::Asan,
        summary: summary.to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };

    // IDs deliberately sort in the opposite order from insertion. `Crash`
    // has no creation timestamp, so SQLite row insertion order is the only
    // persisted definition of "newest" available to this API.
    let oldest = crash("ffffffff-ffff-4fff-8fff-ffffffffffff", "oldest");
    let middle = crash("88888888-8888-4888-8888-888888888888", "middle");
    let newest = crash("00000000-0000-4000-8000-000000000000", "newest");
    for item in [&oldest, &middle, &newest] {
        store.upsert_crash(item).await.unwrap();
    }

    let listed = store.list_all_crashes().await.unwrap();
    assert_eq!(
        listed.iter().map(|item| item.id).collect::<Vec<_>>(),
        [newest.id, middle.id, oldest.id]
    );

    // Re-triaging an existing crash must NOT reorder it: the upsert updates in
    // place (ON CONFLICT DO UPDATE) rather than delete+reinsert, so the oldest
    // crash does not jump to the top just because it was re-processed.
    store
        .upsert_crash(&Crash {
            summary: "oldest-retriaged".to_owned(),
            ..oldest.clone()
        })
        .await
        .unwrap();
    let relisted = store.list_all_crashes().await.unwrap();
    assert_eq!(
        relisted.iter().map(|item| item.id).collect::<Vec<_>>(),
        [newest.id, middle.id, oldest.id],
        "re-triage must preserve first-seen ordering"
    );
}

#[tokio::test]
async fn upsert_target_keeps_one_row_per_project_symbol_file() {
    let (store, _dir) = temp_store().await;
    let project = "/home/user/proj-unique";

    // Two discoveries of the same symbol in the same file under the same
    // project arrive with different scanner UUIDs. Identity is (project,
    // symbol, file), so exactly one row must survive, and it must keep the
    // first stable id.
    let first = sample_target(project);
    let mut second = sample_target(project);
    second.id = Uuid::new_v4();
    assert_ne!(first.id, second.id);

    store.upsert_target(&first, Utc::now()).await.unwrap();
    store.upsert_target(&second, Utc::now()).await.unwrap();

    let targets = store.list_targets(project).await.unwrap();
    assert_eq!(targets.len(), 1, "one row per (project, symbol, file)");
    assert_eq!(targets[0].id, first.id, "stable id is preserved");
}

#[tokio::test]
async fn upsert_target_distinguishes_same_symbol_in_different_files() {
    let (store, _dir) = temp_store().await;
    let project = "/proj";

    // Two same-named functions in different files of one project are distinct
    // persisted targets, each with its own stable id.
    let mut in_a = sample_target(project);
    in_a.location.file = PathBuf::from("/proj/src/a.c");
    let mut in_b = sample_target(project);
    in_b.id = Uuid::new_v4();
    in_b.location.file = PathBuf::from("/proj/src/b.c");

    store.upsert_target(&in_a, Utc::now()).await.unwrap();
    store.upsert_target(&in_b, Utc::now()).await.unwrap();
    assert_eq!(store.list_targets(project).await.unwrap().len(), 2);

    // Rediscovering the definition in src/a.c re-homes onto that file's row
    // only; the src/b.c row is untouched.
    let mut rediscovered = sample_target(project);
    rediscovered.id = Uuid::new_v4();
    rediscovered.location.file = PathBuf::from("/proj/src/a.c");
    store
        .upsert_target(&rediscovered, Utc::now())
        .await
        .unwrap();
    let targets = store.list_targets(project).await.unwrap();
    assert_eq!(targets.len(), 2, "no duplicates and no cross-file collapse");
    assert!(
        targets.iter().any(|t| t.id == in_a.id),
        "the src/a.c row keeps its stable id"
    );
    assert!(
        targets.iter().any(|t| t.id == in_b.id),
        "the src/b.c row keeps its stable id"
    );
}

#[tokio::test]
async fn legacy_row_without_file_survives_and_rescan_adds_a_file_scoped_row() {
    let (store, _dir) = temp_store().await;
    let project = "/proj";

    // Simulate a legacy row whose file could not be backfilled: migration 0019
    // leaves such rows valid with file = ''.
    let legacy = sample_target(project);
    sqlx::query(
        "INSERT INTO targets
            (id, project_root, symbol, language, fit_score, rationale, discovered_at, data_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(legacy.id.to_string())
    .bind(project)
    .bind(&legacy.symbol)
    .bind("c")
    .bind(legacy.fit_score)
    .bind(&legacy.rationale)
    .bind(Utc::now().to_rfc3339())
    .bind(serde_json::to_string(&legacy).unwrap())
    .execute(store.pool())
    .await
    .unwrap();

    // A rescan upserts against the file-scoped key; it cannot re-home onto the
    // file-less row, so a second row appears while the legacy row is kept.
    let mut scanned = sample_target(project);
    scanned.id = Uuid::new_v4();
    store.upsert_target(&scanned, Utc::now()).await.unwrap();

    let targets = store.list_targets(project).await.unwrap();
    assert_eq!(targets.len(), 2, "legacy row and file-scoped row coexist");
    assert!(targets.iter().any(|t| t.id == legacy.id));
    assert!(targets.iter().any(|t| t.id == scanned.id));
}

#[tokio::test]
async fn migration_0019_backfills_relative_file_and_preserves_identity_on_rescan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let opts = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(opts)
        .await
        .unwrap();

    // Bring the database to its pre-0019 shape, then seed a legacy row exactly
    // as a pre-0019 database holds it: no file column, the scanner's absolute
    // location.file carried inside data_json.
    let mut pre_0019 = sqlx::migrate!();
    pre_0019.migrations.to_mut().retain(|m| m.version <= 18);
    pre_0019.run(&pool).await.unwrap();
    let mut legacy = sample_target("/proj");
    legacy.location.file = PathBuf::from("/proj/src/a.c");
    sqlx::query(
        "INSERT INTO targets
            (id, project_root, symbol, language, fit_score, rationale, discovered_at, data_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(legacy.id.to_string())
    .bind("/proj")
    .bind(&legacy.symbol)
    .bind("c")
    .bind(legacy.fit_score)
    .bind(&legacy.rationale)
    .bind(Utc::now().to_rfc3339())
    .bind(serde_json::to_string(&legacy).unwrap())
    .execute(&pool)
    .await
    .unwrap();

    // Applying 0019 backfills the root-relative file from data_json and swaps
    // the unique index for the file-scoped one.
    sqlx::migrate!().run(&pool).await.unwrap();
    let file: String = sqlx::query_scalar("SELECT file FROM targets WHERE id = ?1")
        .bind(legacy.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(file, "src/a.c", "file is relativized against project_root");
    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'targets'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(indexes
        .iter()
        .any(|i| i == "idx_targets_project_symbol_file"));
    assert!(!indexes.iter().any(|i| i == "idx_targets_project_symbol"));
    pool.close().await;

    // Rescanning re-homes onto the backfilled row, keeping the legacy id, and
    // the second definition of the same symbol becomes a distinct new row.
    let store = Store::connect(&path).await.unwrap();
    let mut rescan_a = sample_target("/proj");
    rescan_a.id = Uuid::new_v4();
    rescan_a.location.file = PathBuf::from("/proj/src/a.c");
    store.upsert_target(&rescan_a, Utc::now()).await.unwrap();
    let mut scanned_b = sample_target("/proj");
    scanned_b.id = Uuid::new_v4();
    scanned_b.location.file = PathBuf::from("/proj/src/b.c");
    store.upsert_target(&scanned_b, Utc::now()).await.unwrap();

    let targets = store.list_targets("/proj").await.unwrap();
    assert_eq!(targets.len(), 2);
    assert!(
        targets.iter().any(|t| t.id == legacy.id),
        "the surviving row keeps its pre-migration id"
    );
    assert!(
        targets.iter().any(|t| t.id == scanned_b.id),
        "the second definition gets its own row"
    );
}

#[tokio::test]
async fn consume_automotive_approval_is_single_use_and_atomic() {
    let (store, _dir) = temp_store().await;
    let op = Uuid::new_v4();
    let scope = "aa".repeat(32);

    // First claim of an approval id succeeds.
    assert!(store
        .consume_automotive_approval("approval-1", &scope, op, "/proj", Utc::now())
        .await
        .unwrap());
    // A second claim of the SAME id is rejected -- single-use.
    assert!(!store
        .consume_automotive_approval("approval-1", &scope, Uuid::new_v4(), "/proj", Utc::now())
        .await
        .unwrap());
    // A distinct approval id is independent and succeeds.
    assert!(store
        .consume_automotive_approval("approval-2", &scope, Uuid::new_v4(), "/proj", Utc::now())
        .await
        .unwrap());
    // An empty id is rejected as invalid data, not silently consumed.
    assert!(store
        .consume_automotive_approval("", &scope, op, "/proj", Utc::now())
        .await
        .is_err());
}

#[tokio::test]
async fn delete_project_clears_consumed_approvals() {
    let (store, _dir) = temp_store().await;
    let project = "/projects/vehicle-approvals";
    store
        .consume_automotive_approval(
            "approval-x",
            &"bb".repeat(32),
            Uuid::new_v4(),
            project,
            Utc::now(),
        )
        .await
        .unwrap();

    store.delete_project(project).await.unwrap();

    // After deletion the ledger no longer holds the id, so it could be claimed
    // again (safe: a real approval that old is long past its freshness window).
    assert!(store
        .consume_automotive_approval(
            "approval-x",
            &"bb".repeat(32),
            Uuid::new_v4(),
            project,
            Utc::now()
        )
        .await
        .unwrap());
}

#[tokio::test]
async fn delete_project_removes_automotive_evidence() {
    let (store, _dir) = temp_store().await;
    let project = "/projects/vehicle-evidence";
    let op = AutomotiveOperationRecord {
        id: Uuid::new_v4(),
        project_root: project.to_owned(),
        operation: "analyze_pcap".to_owned(),
        mode: "offline_pcap".to_owned(),
        protocol: Some("uds".to_owned()),
        status: AutomotiveOperationStatus::Running,
        started_at: Utc::now(),
        ended_at: None,
        request_hash: "req".to_owned(),
        transcript_hash: None,
        artifact_dir: "automotive/op".to_owned(),
        approval_json: None,
        result_json: None,
        error: None,
    };
    store.insert_automotive_operation(&op).await.unwrap();
    assert_eq!(
        store
            .automotive_operations(project, 100)
            .await
            .unwrap()
            .len(),
        1
    );

    store.delete_project(project).await.unwrap();
    assert!(
        store
            .automotive_operations(project, 100)
            .await
            .unwrap()
            .is_empty(),
        "deleting a project must not leave stale automotive evidence"
    );
}

#[tokio::test]
async fn crash_batch_persistence_is_atomic() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let target_id = Uuid::new_v4();
    let crash = |summary: &str| Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id,
        input_path: PathBuf::from(format!("out/{summary}")),
        stack_signature: summary.to_owned(),
        kind: CrashKind::Asan,
        summary: summary.to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };
    sqlx::query(
        "CREATE TRIGGER reject_crash_batch
         BEFORE INSERT ON crashes
         WHEN NEW.summary = 'reject'
         BEGIN
           SELECT RAISE(ABORT, 'rejected crash');
         END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let error = store
        .upsert_crashes(&[crash("accepted"), crash("reject")])
        .await
        .expect_err("one failed crash must roll back the entire triage batch");

    assert!(matches!(error, StorageError::Db(_)));
    assert!(store.list_crashes_by_run(run.id).await.unwrap().is_empty());
}

fn sample_harness(target_id: Uuid) -> Harness {
    Harness {
        id: Uuid::new_v4(),
        target_id,
        engine: EngineKind::LibFuzzer,
        source: "int LLVMFuzzerTestOneInput(...) { return 0; }".to_owned(),
        language: TargetLanguage::C,
        build_cmd: BuildCommand {
            compiler: "clang".to_owned(),
            args: vec!["-fsanitize=fuzzer,address".to_owned()],
            output: PathBuf::from("fuzz_parse_value"),
        },
        sanitizer: Sanitizer::Address,
        status: HarnessStatus::Draft,
        smoke_run: None,
    }
}

#[tokio::test]
async fn run_roundtrip_and_status_update() {
    let (store, _dir) = temp_store().await;
    let mut run = RunRecord::new("/proj", EngineKind::AflPlusPlus, None, Utc::now());
    run.source_rev = Some("a".repeat(64));
    run.corpus_rev = Some("b".repeat(64));
    run.sandbox_rev = Some("c".repeat(64));
    let id = run.id;
    store.insert_run(&run).await.unwrap();

    let fetched = store.get_run(id).await.unwrap().expect("run exists");
    assert_eq!(fetched.id, id);
    assert_eq!(fetched.status, RunStatus::Pending);
    assert_eq!(fetched.kind, RunKind::Campaign);
    assert_eq!(fetched.engine, EngineKind::AflPlusPlus);
    assert_eq!(fetched.source_rev, Some("a".repeat(64)));
    assert_eq!(fetched.corpus_rev, Some("b".repeat(64)));
    assert_eq!(fetched.sandbox_rev, Some("c".repeat(64)));

    let ended = Utc::now();
    store
        .set_run_status(id, RunStatus::Done, Some(ended))
        .await
        .unwrap();
    let after = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(after.status, RunStatus::Done);
    assert!(after.ended_at.is_some());

    let listed = store.list_runs(Some("/proj")).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(store.list_runs(Some("/other")).await.unwrap().is_empty());
}

#[tokio::test]
async fn target_and_harness_roundtrip() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    let target_id = target.id;
    store.upsert_target(&target, Utc::now()).await.unwrap();

    // Idempotent upsert: replacing the same id keeps a single row.
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let targets = store.list_targets("/proj").await.unwrap();
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].symbol, "parse_value");

    let harness = sample_harness(target_id);
    let hid = harness.id;
    store.upsert_harness(&harness).await.unwrap();
    let got = store.get_harness(hid).await.unwrap().unwrap();
    assert_eq!(got.target_id, target_id);
    assert_eq!(store.list_harnesses(target_id).await.unwrap().len(), 1);
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);
}

#[tokio::test]
async fn harness_promotion_and_digest_bound_approval_are_atomic_and_idempotent() {
    let (store, _dir) = temp_store().await;
    let mut harness = sample_harness(Uuid::new_v4());
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Promoted;
    let approved_at = Utc::now();

    let approval = store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            approved_at,
        )
        .await
        .expect("atomic promotion");
    assert_eq!(approval.harness_id, harness.id);
    assert_eq!(approval.source_sha256, "a".repeat(64));
    assert_eq!(approval.binary_sha256, "b".repeat(64));
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::Promoted
    );
    assert_eq!(
        store
            .harness_approval(harness.id, &"a".repeat(64), &"b".repeat(64))
            .await
            .unwrap(),
        Some(approval.clone())
    );

    let retried = store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect("idempotent promotion");
    assert_eq!(retried, approval);
}

#[tokio::test]
async fn rejected_approval_rolls_back_the_promoted_harness_state() {
    let (store, _dir) = temp_store().await;
    let mut harness = sample_harness(Uuid::new_v4());
    harness.status = HarnessStatus::SmokePassed;
    store.upsert_harness(&harness).await.unwrap();
    sqlx::query(
        "CREATE TRIGGER reject_harness_approval
         BEFORE INSERT ON harness_approvals
         BEGIN
           SELECT RAISE(ABORT, 'rejected approval');
         END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    harness.status = HarnessStatus::Promoted;
    let error = store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"c".repeat(64),
            &"d".repeat(64),
            Utc::now(),
        )
        .await
        .expect_err("approval failure must abort the transaction");

    assert!(matches!(error, StorageError::Db(_)));
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );
}

#[tokio::test]
async fn rediscovering_a_symbol_does_not_accumulate_duplicates() {
    let (store, _dir) = temp_store().await;

    // Each discovery pass assigns a fresh id to the same symbol (as the scanner
    // does). The store must keep one stable row per (project, symbol, file),
    // not pile up or invalidate harness/corpus/crash foreign-key attribution.
    let stable_id = sample_target("/proj").id;
    for _ in 0..5 {
        let mut t = sample_target("/proj");
        t.id = stable_id;
        store.upsert_target(&t, Utc::now()).await.unwrap();
    }
    let harness = sample_harness(stable_id);
    store.upsert_harness(&harness).await.unwrap();
    let mut rediscovered = sample_target("/proj");
    rediscovered.id = Uuid::new_v4();
    store
        .upsert_target(&rediscovered, Utc::now())
        .await
        .unwrap();
    let targets = store.list_targets("/proj").await.unwrap();
    assert_eq!(targets.len(), 1, "same symbol must collapse to one row");
    assert_eq!(targets[0].symbol, "parse_value");
    assert_eq!(
        targets[0].id, stable_id,
        "target identity must remain stable"
    );
    assert_eq!(
        store.list_harnesses(stable_id).await.unwrap().len(),
        1,
        "rediscovery must not orphan the target's harnesses"
    );

    // A different symbol in the same project is kept separately.
    let mut other = sample_target("/proj");
    other.id = Uuid::new_v4();
    other.symbol = "parse_header".to_owned();
    store.upsert_target(&other, Utc::now()).await.unwrap();
    assert_eq!(store.list_targets("/proj").await.unwrap().len(), 2);
}

#[tokio::test]
async fn clear_knowledge_empties_all_domain_tables() {
    let (store, _dir) = temp_store().await;

    // Seed one of every domain record, linked as they would be in practice.
    let target = sample_target("/proj");
    let target_id = target.id;
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store
        .upsert_harness(&sample_harness(target_id))
        .await
        .unwrap();
    let entry = CorpusEntry {
        path: PathBuf::from("corpus/seed_1"),
        sha256: "abc123".to_owned(),
        size: 42,
        source: CorpusSource::Seed,
        coverage_hash: None,
    };
    store.upsert_corpus_entry(target_id, &entry).await.unwrap();
    let run = RunRecord::new("/proj".to_owned(), EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id: run.id,
        target_id,
        input_path: PathBuf::from("out/crash-1"),
        stack_signature: "sig".to_owned(),
        kind: CrashKind::Asan,
        summary: "boom".to_owned(),
        minimized: false,
        bug_report: None,
        casr: None,
    };
    store.upsert_crash(&crash).await.unwrap();

    store.clear_knowledge().await.unwrap();

    // Every table is emptied -- no orphaned harnesses or corpus left behind.
    assert!(store.list_targets("/proj").await.unwrap().is_empty());
    assert!(store.list_runs(Some("/proj")).await.unwrap().is_empty());
    assert!(store.list_crashes_by_run(run.id).await.unwrap().is_empty());
    assert!(store.list_all_harnesses().await.unwrap().is_empty());
    assert!(store.list_all_corpus_entries().await.unwrap().is_empty());
}

#[tokio::test]
async fn delete_project_cascades_and_isolates_other_projects() {
    let (store, _dir) = temp_store().await;

    // Seed two projects with a full record set each.
    let seed = |root: &'static str| {
        let store = &store;
        async move {
            let mut target = sample_target(root);
            target.id = Uuid::new_v4();
            let target_id = target.id;
            store.upsert_target(&target, Utc::now()).await.unwrap();
            store
                .upsert_harness(&sample_harness(target_id))
                .await
                .unwrap();
            let entry = CorpusEntry {
                path: PathBuf::from("corpus/seed"),
                sha256: "sha".to_owned(),
                size: 10,
                source: CorpusSource::Seed,
                coverage_hash: None,
            };
            store.upsert_corpus_entry(target_id, &entry).await.unwrap();
            let run = RunRecord::new(root.to_owned(), EngineKind::LibFuzzer, None, Utc::now());
            let run_id = run.id;
            store.insert_run(&run).await.unwrap();
            store
                .upsert_crash(&Crash {
                    id: Uuid::new_v4(),
                    run_id,
                    target_id,
                    input_path: PathBuf::from("out/crash"),
                    stack_signature: "sig".to_owned(),
                    kind: CrashKind::Asan,
                    summary: "boom".to_owned(),
                    minimized: false,
                    bug_report: None,
                    casr: None,
                })
                .await
                .unwrap();
            (target_id, run_id)
        }
    };
    let (_gone_target, gone_run) = seed("/gone").await;
    let (kept_target, kept_run) = seed("/kept").await;

    // Both projects also carry a policy override and an audit event.
    let over = ProjectAutoRevert {
        enabled: true,
        threshold_pct: 20.0,
        notify_only: false,
    };
    store.set_project_auto_revert("/gone", over).await.unwrap();
    store.set_project_auto_revert("/kept", over).await.unwrap();
    let ev = |project: &str| AutoRevertEvent {
        id: Uuid::new_v4().to_string(),
        ts: "2026-07-09T10:00:00Z".to_owned(),
        project_root: project.to_owned(),
        target: "parse".to_owned(),
        run_id: "run".to_owned(),
        from_rev: "aaaaaaaaaaaa".to_owned(),
        to_rev: "bbbbbbbbbbbb".to_owned(),
        previous_edges: 1000,
        regressed_edges: 700,
        drop_pct: 30.0,
        reverted: true,
    };
    store.record_auto_revert_event(&ev("/gone")).await.unwrap();
    store.record_auto_revert_event(&ev("/kept")).await.unwrap();

    store.delete_project("/gone").await.unwrap();

    // The deleted project is gone across every table.
    assert!(store.list_targets("/gone").await.unwrap().is_empty());
    assert!(store.list_runs(Some("/gone")).await.unwrap().is_empty());
    assert!(store
        .list_crashes_by_run(gone_run)
        .await
        .unwrap()
        .is_empty());
    // Its policy override and audit events are cascaded too.
    assert_eq!(store.project_auto_revert("/gone").await.unwrap(), None);
    assert!(store
        .list_auto_revert_events(Some("/gone"), 50)
        .await
        .unwrap()
        .is_empty());

    // The other project is fully intact.
    assert_eq!(store.list_targets("/kept").await.unwrap().len(), 1);
    assert_eq!(store.list_runs(Some("/kept")).await.unwrap().len(), 1);
    assert_eq!(store.list_harnesses(kept_target).await.unwrap().len(), 1);
    assert_eq!(
        store.list_corpus_entries(kept_target).await.unwrap().len(),
        1
    );
    assert_eq!(store.list_crashes_by_run(kept_run).await.unwrap().len(), 1);
    assert_eq!(
        store.project_auto_revert("/kept").await.unwrap(),
        Some(over)
    );
    assert_eq!(
        store
            .list_auto_revert_events(Some("/kept"), 50)
            .await
            .unwrap()
            .len(),
        1
    );
    // No orphaned children survive the delete.
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);
    assert_eq!(store.list_all_corpus_entries().await.unwrap().len(), 1);
}

#[tokio::test]
async fn delete_orphans_removes_dangling_children_keeps_valid() {
    let (store, _dir) = temp_store().await;

    // A valid target with a linked harness/corpus.
    let target = sample_target("/proj");
    let valid_target = target.id;
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store
        .upsert_harness(&sample_harness(valid_target))
        .await
        .unwrap();

    // An orphaned harness/corpus/crash pointing at a target that never existed
    // (as older partial clears left behind -- these render as "unknown").
    let ghost = Uuid::new_v4();
    store.upsert_harness(&sample_harness(ghost)).await.unwrap();
    store
        .upsert_corpus_entry(
            ghost,
            &CorpusEntry {
                path: PathBuf::from("c"),
                sha256: "x".to_owned(),
                size: 1,
                source: CorpusSource::Seed,
                coverage_hash: None,
            },
        )
        .await
        .unwrap();
    let run_id = Uuid::new_v4();
    store
        .upsert_crash(&Crash {
            id: Uuid::new_v4(),
            run_id,
            target_id: ghost,
            input_path: PathBuf::from("out/crash"),
            stack_signature: "sig".to_owned(),
            kind: CrashKind::Asan,
            summary: "boom".to_owned(),
            minimized: false,
            bug_report: None,
            casr: None,
        })
        .await
        .unwrap();

    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 2);

    store.delete_orphans().await.unwrap();

    // The valid harness survives; the ghosts are purged.
    assert_eq!(store.list_all_harnesses().await.unwrap().len(), 1);
    assert_eq!(store.list_harnesses(valid_target).await.unwrap().len(), 1);
    assert!(store.list_all_corpus_entries().await.unwrap().is_empty());
    assert!(store.list_crashes_by_run(run_id).await.unwrap().is_empty());
}

#[tokio::test]
async fn crash_and_corpus_roundtrip() {
    let (store, _dir) = temp_store().await;
    let run_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let crash = Crash {
        id: Uuid::new_v4(),
        run_id,
        target_id,
        input_path: PathBuf::from("out/crash-abc"),
        stack_signature: "deadbeef".to_owned(),
        kind: CrashKind::Asan,
        summary: "heap-buffer-overflow".to_owned(),
        minimized: true,
        bug_report: None,
        casr: None,
    };
    store.upsert_crash(&crash).await.unwrap();
    let crashes = store.list_crashes_by_run(run_id).await.unwrap();
    assert_eq!(crashes.len(), 1);
    assert_eq!(crashes[0].kind, CrashKind::Asan);
    assert!(crashes[0].minimized);

    let entry = CorpusEntry {
        path: PathBuf::from("corpus/seed_1"),
        sha256: "abc123".to_owned(),
        size: 42,
        source: CorpusSource::Seed,
        coverage_hash: None,
    };
    store.upsert_corpus_entry(target_id, &entry).await.unwrap();
    // Same (target, sha) upserts in place rather than duplicating.
    store.upsert_corpus_entry(target_id, &entry).await.unwrap();
    let entries = store.list_corpus_entries(target_id).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, 42);
}

#[tokio::test]
async fn corpus_replacement_is_exact_and_preserves_richer_metadata() {
    let (store, _dir) = temp_store().await;
    let target_id = Uuid::new_v4();
    let stale = CorpusEntry {
        path: PathBuf::from("corpus/stale"),
        sha256: "stale".to_owned(),
        size: 5,
        source: CorpusSource::Fuzzer,
        coverage_hash: Some("old-coverage".to_owned()),
    };
    let retained = CorpusEntry {
        path: PathBuf::from("corpus/original"),
        sha256: "retained".to_owned(),
        size: 8,
        source: CorpusSource::Seed,
        coverage_hash: Some("coverage".to_owned()),
    };
    store.upsert_corpus_entry(target_id, &stale).await.unwrap();
    store
        .upsert_corpus_entry(target_id, &retained)
        .await
        .unwrap();

    let rediscovered = CorpusEntry {
        path: PathBuf::from("corpus/current"),
        sha256: retained.sha256.clone(),
        size: retained.size,
        source: CorpusSource::Manual,
        coverage_hash: None,
    };
    store
        .replace_corpus_entries(target_id, &[rediscovered])
        .await
        .unwrap();

    let entries = store.list_corpus_entries(target_id).await.unwrap();
    assert_eq!(entries.len(), 1, "stale rows must be removed");
    assert_eq!(entries[0].path, PathBuf::from("corpus/current"));
    assert_eq!(entries[0].source, CorpusSource::Seed);
    assert_eq!(entries[0].coverage_hash.as_deref(), Some("coverage"));
}

#[tokio::test]
async fn corpus_deletion_is_scoped_to_the_owning_target() {
    let (store, _dir) = temp_store().await;
    let first_target = Uuid::new_v4();
    let second_target = Uuid::new_v4();
    let entry = CorpusEntry {
        path: PathBuf::from("corpus/shared"),
        sha256: "same-content".to_owned(),
        size: 12,
        source: CorpusSource::Manual,
        coverage_hash: None,
    };
    store
        .upsert_corpus_entry(first_target, &entry)
        .await
        .unwrap();
    store
        .upsert_corpus_entry(second_target, &entry)
        .await
        .unwrap();

    store
        .delete_corpus_entry(first_target, &entry.sha256)
        .await
        .unwrap();

    assert!(store
        .list_corpus_entries(first_target)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store
            .list_corpus_entries(second_target)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn schedule_executions_round_trip_and_latest_fire() {
    let (store, _dir) = temp_store().await;

    store
        .upsert_schedule_execution(
            "e1",
            "s1",
            "2026-07-01T01:00:00+00:00",
            "completed",
            r#"{"k":1}"#,
        )
        .await
        .unwrap();
    store
        .upsert_schedule_execution(
            "e2",
            "s1",
            "2026-07-01T02:00:00+00:00",
            "failed",
            r#"{"k":2}"#,
        )
        .await
        .unwrap();

    let recent = store.list_schedule_executions(10).await.unwrap();
    assert_eq!(recent.len(), 2);
    // Newest first.
    assert_eq!(recent[0], r#"{"k":2}"#);

    let fires: std::collections::HashMap<String, String> = store
        .latest_schedule_fires()
        .await
        .unwrap()
        .into_iter()
        .collect();
    assert_eq!(fires.get("s1").unwrap(), "2026-07-01T02:00:00+00:00");

    // Upsert replaces by id (no duplicate).
    store
        .upsert_schedule_execution(
            "e2",
            "s1",
            "2026-07-01T02:00:00+00:00",
            "completed",
            r#"{"k":3}"#,
        )
        .await
        .unwrap();
    assert_eq!(store.list_schedule_executions(10).await.unwrap().len(), 2);
}

#[tokio::test]
async fn pruning_schedule_executions_is_scoped_deterministic_and_supports_zero() {
    let (store, _dir) = temp_store().await;
    for (id, schedule, triggered_at) in [
        ("a-old", "schedule-a", "2026-07-01T01:00:00+00:00"),
        ("a-tie-1", "schedule-a", "2026-07-01T02:00:00+00:00"),
        ("a-tie-2", "schedule-a", "2026-07-01T02:00:00+00:00"),
        ("b-only", "schedule-b", "2026-06-01T01:00:00+00:00"),
    ] {
        store
            .upsert_schedule_execution(id, schedule, triggered_at, "completed", "{}")
            .await
            .unwrap();
    }

    assert_eq!(
        store
            .prune_schedule_executions("schedule-a", 2)
            .await
            .unwrap(),
        1
    );
    let remaining_a: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM schedule_executions
         WHERE schedule_id = ?1 ORDER BY triggered_at DESC, id DESC",
    )
    .bind("schedule-a")
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(remaining_a, ["a-tie-2", "a-tie-1"]);
    let remaining_b: Vec<String> =
        sqlx::query_scalar("SELECT id FROM schedule_executions WHERE schedule_id = 'schedule-b'")
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(remaining_b, ["b-only"]);

    assert_eq!(
        store
            .prune_schedule_executions("schedule-a", 0)
            .await
            .unwrap(),
        2
    );
    let remaining_a: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-a'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(remaining_a, 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-b'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn counting_schedule_starts_is_scoped_inclusive_and_excludes_skips() {
    let (store, _dir) = temp_store().await;
    for (id, schedule, triggered_at, started_at, status) in [
        (
            "a-trigger-after-started-before-1",
            "schedule-a",
            "2026-07-01T02:00:00+00:00",
            Some("2026-07-01T00:30:00+00:00"),
            "completed",
        ),
        (
            "a-trigger-after-started-before-2",
            "schedule-a",
            "2026-07-01T03:00:00+00:00",
            Some("2026-07-01T00:45:00+00:00"),
            "failed",
        ),
        (
            "a-trigger-before-started-at-cutoff",
            "schedule-a",
            "2026-07-01T00:00:00+00:00",
            Some("2026-07-01T01:00:00+00:00"),
            "failed",
        ),
        (
            "a-after",
            "schedule-a",
            "2026-07-01T01:30:00+00:00",
            Some("2026-07-01T01:30:00+00:00"),
            "running",
        ),
        (
            "a-skipped",
            "schedule-a",
            "2026-07-01T01:45:00+00:00",
            Some("2026-07-01T01:45:00+00:00"),
            "skipped",
        ),
        (
            "a-pending",
            "schedule-a",
            "2026-07-01T01:50:00+00:00",
            Some("2026-07-01T01:50:00Z"),
            "pending",
        ),
        (
            "b-after",
            "schedule-b",
            "2026-07-01T01:30:00+00:00",
            Some("2026-07-01T01:30:00+00:00"),
            "completed",
        ),
    ] {
        let data = serde_json::json!({ "started_at": started_at }).to_string();
        store
            .upsert_schedule_execution(id, schedule, triggered_at, status, &data)
            .await
            .unwrap();
    }
    store
        .upsert_schedule_execution(
            "a-invalid-json",
            "schedule-a",
            "2026-07-01T02:00:00+00:00",
            "completed",
            "not-json",
        )
        .await
        .unwrap();

    assert_eq!(
        store
            .count_schedule_executions_since("schedule-a", "2026-07-01T01:00:00+00:00")
            .await
            .unwrap(),
        2,
        "started_at drives the inclusive cutoff; skipped rows and other schedules do not count"
    );
    assert_eq!(
        store
            .count_schedule_executions_since("schedule-b", "2026-07-01T01:00:00+00:00")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn pruning_preserves_running_and_recent_started_executions() {
    let (store, _dir) = temp_store().await;
    let recent_start = (Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    for (id, schedule, status, started_at) in [
        (
            "old-running",
            "schedule-a",
            "running",
            Some("2020-01-01T00:00:00+00:00"),
        ),
        ("old-pending", "schedule-a", "pending", None),
        (
            "recent-completed",
            "schedule-a",
            "completed",
            Some(recent_start.as_str()),
        ),
        (
            "old-completed",
            "schedule-a",
            "completed",
            Some("2020-01-01T00:00:00+00:00"),
        ),
        (
            "other-old-completed",
            "schedule-b",
            "completed",
            Some("2020-01-01T00:00:00+00:00"),
        ),
    ] {
        let data = serde_json::json!({ "started_at": started_at }).to_string();
        store
            .upsert_schedule_execution(id, schedule, "2020-01-01T00:00:00+00:00", status, &data)
            .await
            .unwrap();
    }

    assert_eq!(
        store
            .prune_schedule_executions("schedule-a", 0)
            .await
            .unwrap(),
        1,
        "only old terminal history is safe to remove"
    );
    let remaining_a: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM schedule_executions WHERE schedule_id = 'schedule-a' ORDER BY id",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        remaining_a,
        ["old-pending", "old-running", "recent-completed"]
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-b'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1,
        "pruning must remain schedule-scoped"
    );
}

#[tokio::test]
async fn chat_checkpoints_survive_a_reconnect() {
    use hf_core::session::{ChatCheckpoint, ChatCheckpointStore};
    use hf_core::types::SessionId;
    use hf_storage::SqliteChatCheckpointStore;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cp.db");
    let session = SessionId("s-1".to_owned());

    let cp = |id: &str, turn: u32| ChatCheckpoint {
        checkpoint_id: id.to_owned(),
        session_id: session.clone(),
        turn_number: turn,
        message_count_before: turn * 2,
        journal_scope_id: format!("scope-{turn}"),
        invalidated: false,
        created_at: Utc::now(),
    };

    // Persist two checkpoints, then drop the store (simulating app exit).
    {
        let store = Store::connect(&path).await.expect("connect");
        let cps = SqliteChatCheckpointStore::new(store.pool().clone());
        cps.save(&cp("cp-1", 1)).await.unwrap();
        cps.save(&cp("cp-2", 2)).await.unwrap();
    }

    // Reconnect (simulating a restart) -- the checkpoints must still be there,
    // which is exactly what the in-memory store lost (making rollback a no-op).
    let store = Store::connect(&path).await.expect("reconnect");
    let cps = SqliteChatCheckpointStore::new(store.pool().clone());

    let all = cps.list_by_session(&session).await.unwrap();
    assert_eq!(all.len(), 2, "checkpoints must persist across a restart");
    // list_by_session is turn_number DESC.
    assert_eq!(all[0].turn_number, 2);

    let latest = cps.latest(&session).await.unwrap().expect("a latest");
    assert_eq!(latest.checkpoint_id, "cp-2");

    let loaded = cps.load("cp-1").await.unwrap();
    assert_eq!(loaded.message_count_before, 2);

    // Rolling back past turn 1 invalidates every later checkpoint.
    let invalidated = cps.invalidate_after(&session, 1).await.unwrap();
    assert_eq!(invalidated, 1);
    assert_eq!(
        cps.latest(&session).await.unwrap().map(|c| c.checkpoint_id),
        Some("cp-1".to_owned()),
        "the latest non-invalidated checkpoint is now cp-1"
    );
}

#[tokio::test]
async fn reopening_a_store_self_heals_orphaned_children() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("heal.db");

    // First connection: a valid target+harness, plus an orphaned harness whose
    // target never existed (as an older partial clear would have left behind).
    {
        let store = Store::connect(&path).await.unwrap();
        let target = sample_target("/proj");
        let valid = target.id;
        store.upsert_target(&target, Utc::now()).await.unwrap();
        store.upsert_harness(&sample_harness(valid)).await.unwrap();
        store
            .upsert_harness(&sample_harness(Uuid::new_v4()))
            .await
            .unwrap();
        assert_eq!(store.list_all_harnesses().await.unwrap().len(), 2);
    }

    // Reconnecting runs the on-open cleanup, dropping the orphan.
    let store = Store::connect(&path).await.unwrap();
    let remaining = store.list_all_harnesses().await.unwrap();
    assert_eq!(remaining.len(), 1);
}

#[tokio::test]
async fn set_run_stats_persists_edges_and_execs() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();

    // Fresh run has no stats yet.
    assert!(store.get_run(id).await.unwrap().unwrap().edges.is_none());

    store.set_run_stats(id, 142, 3800.0, 5).await.unwrap();

    let got = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(got.edges, Some(142));
    assert_eq!(got.execs, Some(3800.0));
    assert_eq!(got.crash_count, Some(5));
    // Round-trips through list_runs too.
    let listed = store.list_runs(Some("/proj")).await.unwrap();
    assert_eq!(listed[0].edges, Some(142));
}

#[tokio::test]
async fn run_samples_roundtrip() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();
    assert!(store.run_samples(id).await.unwrap().is_none());

    let json = r#"[{"t":0.0,"edges":3,"execs":100.0},{"t":5.0,"edges":9,"execs":250.0}]"#;
    store.set_run_samples(id, json).await.unwrap();
    assert_eq!(store.run_samples(id).await.unwrap().as_deref(), Some(json));
}

#[tokio::test]
async fn run_harness_rev_roundtrips() {
    let (store, _dir) = temp_store().await;
    let mut run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    run.harness_rev = Some("a".repeat(64));
    run.binary_rev = Some("b".repeat(64));
    run.evidence_dir = Some("runs/7b6f2c7f/out".to_owned());
    run.kind = RunKind::Smoke;
    run.context_rev = Some("c".repeat(64));
    let id = run.id;
    store.insert_run(&run).await.unwrap();
    let got = store.get_run(id).await.unwrap().unwrap();
    assert_eq!(got.harness_rev.as_deref(), Some("a".repeat(64).as_str()));
    assert_eq!(got.binary_rev.as_deref(), Some("b".repeat(64).as_str()));
    assert_eq!(got.evidence_dir.as_deref(), Some("runs/7b6f2c7f/out"));
    assert_eq!(got.kind, RunKind::Smoke);
    assert_eq!(got.context_rev.as_deref(), Some("c".repeat(64).as_str()));
}

#[tokio::test]
async fn run_mutations_fail_when_the_run_does_not_exist() {
    let (store, _dir) = temp_store().await;
    let missing = Uuid::new_v4();

    assert!(matches!(
        store
            .set_run_status(missing, RunStatus::Failed, Some(Utc::now()))
            .await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.set_run_stats(missing, 1, 1.0, 0).await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.set_run_samples(missing, "[]").await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.set_run_harness_source(missing, "source").await,
        Err(StorageError::NotFound(_))
    ));
    assert!(matches!(
        store.delete_run(&missing.to_string()).await,
        Err(StorageError::NotFound(_))
    ));
}

#[tokio::test]
async fn run_harness_source_roundtrips() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/proj", EngineKind::LibFuzzer, None, Utc::now());
    let id = run.id;
    store.insert_run(&run).await.unwrap();
    assert!(store.run_harness_source(id).await.unwrap().is_none());
    store
        .set_run_harness_source(id, "int LLVMFuzzerTestOneInput(){return 0;}")
        .await
        .unwrap();
    assert_eq!(
        store.run_harness_source(id).await.unwrap().as_deref(),
        Some("int LLVMFuzzerTestOneInput(){return 0;}")
    );
}

fn guardrail_decision(id: &str, decided_at: chrono::DateTime<Utc>) -> GuardrailDecisionRecord {
    GuardrailDecisionRecord {
        id: id.to_owned(),
        decided_at,
        action: "discover".to_owned(),
        risk_tier: "low".to_owned(),
        decision: "allowed".to_owned(),
        origin: "discover".to_owned(),
        project: Some("/proj".to_owned()),
        detail: None,
    }
}

#[tokio::test]
async fn guardrail_decision_round_trips_newest_first_and_bounded() {
    let (store, _dir) = temp_store().await;
    let base = Utc::now();
    let older = guardrail_decision(
        "00000000-0000-0000-0000-000000000001",
        base - chrono::Duration::seconds(10),
    );
    let mut newer = guardrail_decision("00000000-0000-0000-0000-000000000002", base);
    newer.action = "run_fuzzer".to_owned();
    newer.risk_tier = "high".to_owned();
    newer.decision = "denied".to_owned();
    newer.origin = "run_fuzzer".to_owned();
    newer.project = None;
    newer.detail = Some("High-risk action 'run libfuzzer for 60s' is denied by policy".to_owned());

    store.record_guardrail_decision(&older).await.unwrap();
    store.record_guardrail_decision(&newer).await.unwrap();

    let all = store.list_guardrail_decisions(100).await.unwrap();
    assert_eq!(all, vec![newer.clone(), older.clone()]);

    let bounded = store.list_guardrail_decisions(1).await.unwrap();
    assert_eq!(bounded, vec![newer]);
}

#[tokio::test]
async fn prune_guardrail_decisions_keeps_the_newest_window() {
    let (store, _dir) = temp_store().await;
    let base = Utc::now();
    for n in 0..5 {
        let record = guardrail_decision(
            &format!("00000000-0000-0000-0000-00000000000{n}"),
            base - chrono::Duration::seconds(n),
        );
        store.record_guardrail_decision(&record).await.unwrap();
    }

    let pruned = store.prune_guardrail_decisions(2).await.unwrap();
    assert_eq!(pruned, 3);

    let kept = store.list_guardrail_decisions(100).await.unwrap();
    assert_eq!(kept.len(), 2);
    assert_eq!(kept[0].id, "00000000-0000-0000-0000-000000000000");
    assert_eq!(kept[1].id, "00000000-0000-0000-0000-000000000001");
}
