//! Integration tests for the `SQLite` [`Store`].

use std::{path::PathBuf, time::Duration as StdDuration};

use chrono::{Duration, SubsecRound, Utc};
use hf_core::corpus::{CorpusEntry, CorpusSource};
use hf_core::crash::{Crash, CrashKind};
use hf_core::engine::EngineKind;
use hf_core::harness::{BuildCommand, Harness, HarnessStatus};
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use hf_storage::{
    AutoRevertEvent, AutomotiveOperationRecord, AutomotiveOperationStatus,
    AutomotiveStateCorpusRecord, CampaignHealthEventRecord, GuardrailDecisionRecord,
    HarnessAiReviewRecord, HarnessApprovalKind, HarnessWorkOrderAttemptCompletion,
    HarnessWorkOrderAttemptRecord, HarnessWorkOrderAttemptStage, HarnessWorkOrderAttemptStatus,
    HarnessWorkOrderRecord, HarnessWorkOrderSubmissionInsertError,
    HarnessWorkOrderSubmissionRecord, NewScheduleOccurrence, ProjectAutoRevert,
    RemediationOperationCompletion, RemediationOperationRecord, RemediationOperationStage,
    RemediationOperationStatus, RunKind, RunRecord, RunStatus, RunTelemetryRecord,
    ScheduleOccurrenceAcknowledgement, ScheduleOccurrenceInspection, ScheduleOccurrenceReservation,
    ScheduleOccurrenceTransition, ScheduleOccurrenceTransitionResult, SemgrepFindingRecord,
    SemgrepFindingSeverity, SemgrepPublication, SemgrepRunRecord, SemgrepRunStatus,
    SemgrepTargetScoreRecord, StorageError, Store,
};
use uuid::Uuid;

async fn temp_store() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let store = Store::connect(&path).await.expect("connect");
    (store, dir)
}

async fn insert_work_order_with_timestamp(
    store: &Store,
    id: String,
    created_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO harness_work_orders
            (id, target_id, project_root, schema_version, packet_json, created_at)
         VALUES (?1, ?2, '/projects/timestamps', 2, '{\"schema_version\":2}', ?3)",
    )
    .bind(id)
    .bind(Uuid::new_v4().to_string())
    .bind(created_at)
    .execute(store.pool())
    .await
    .map(|_| ())
}

async fn insert_work_order_submission(
    store: &Store,
    work_order_id: &str,
    source_sha256: String,
    origin_json: &str,
    lint_json: &str,
    submitted_at: &str,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_submissions
            (id, work_order_id, source, source_sha256, origin_json, parent_submission_id,
             lint_json, submitted_at)
         VALUES (?1, ?2, 'int LLVMFuzzerTestOneInput(void) { return 0; }', ?3, ?4, NULL, ?5, ?6)",
    )
    .bind(id.to_string())
    .bind(work_order_id)
    .bind(source_sha256)
    .bind(origin_json)
    .bind(lint_json)
    .bind(submitted_at)
    .execute(store.pool())
    .await
    .map(|_| id)
}

async fn insert_work_order_attempt(
    store: &Store,
    submission_id: Uuid,
    result_json: Option<&str>,
    failure_code: Option<&str>,
    failure_message: Option<&str>,
    started_at: &str,
    updated_at: &str,
    ended_at: Option<&str>,
) -> Result<(), sqlx::Error> {
    let terminal = ended_at.is_some();
    sqlx::query(
        "INSERT INTO harness_work_order_attempts
            (id, submission_id, status, current_stage, harness_id, smoke_run_id,
             result_json, failure_code, failure_message, started_at, updated_at, ended_at)
         VALUES (?1, ?2, ?3, ?4, NULL, NULL, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(submission_id.to_string())
    .bind(if terminal { "smoke_passed" } else { "running" })
    .bind(if terminal { "complete" } else { "compile" })
    .bind(result_json)
    .bind(failure_code)
    .bind(failure_message)
    .bind(started_at)
    .bind(updated_at)
    .bind(ended_at)
    .execute(store.pool())
    .await
    .map(|_| ())
}

fn work_order_record(
    id: char,
    target_id: Uuid,
    project_root: &str,
    created_at: chrono::DateTime<Utc>,
) -> HarnessWorkOrderRecord {
    HarnessWorkOrderRecord {
        id: id.to_string().repeat(64),
        target_id,
        project_root: project_root.to_owned(),
        schema_version: 2,
        packet_json: r#"{"schema_version":2}"#.to_owned(),
        created_at,
    }
}

fn submission_record(
    id: Uuid,
    work_order_id: &str,
    source: &str,
    source_sha256: String,
    parent_submission_id: Option<Uuid>,
    submitted_at: chrono::DateTime<Utc>,
) -> HarnessWorkOrderSubmissionRecord {
    HarnessWorkOrderSubmissionRecord {
        id,
        work_order_id: work_order_id.to_owned(),
        source: source.to_owned(),
        source_sha256,
        origin_json: r#"{"kind":"human"}"#.to_owned(),
        parent_submission_id,
        lint_json: "[]".to_owned(),
        submitted_at,
    }
}

fn running_attempt(
    id: Uuid,
    submission_id: Uuid,
    started_at: chrono::DateTime<Utc>,
) -> HarnessWorkOrderAttemptRecord {
    HarnessWorkOrderAttemptRecord {
        id,
        submission_id,
        status: HarnessWorkOrderAttemptStatus::Running,
        current_stage: HarnessWorkOrderAttemptStage::Compile,
        harness_id: None,
        smoke_run_id: None,
        result_json: None,
        failure_code: None,
        failure_message: None,
        started_at,
        updated_at: started_at,
        ended_at: None,
    }
}

fn json_string_at_limit(limit: usize) -> String {
    format!("\"{}\"", "x".repeat(limit - 2))
}

#[tokio::test]
async fn store_connections_enable_sqlite_write_ahead_logging() {
    let (store, _dir) = temp_store().await;

    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(store.pool())
        .await
        .expect("read journal mode");

    assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
}

#[tokio::test]
async fn harness_work_order_migration_enforces_durable_row_constraints() {
    let (store, _dir) = temp_store().await;
    let applied: i64 =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE version = 29")
            .fetch_one(store.pool())
            .await
            .expect("work-order migration receipt");
    assert_eq!(applied, 29);

    let work_order_id = "a".repeat(64);
    let target_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_orders
            (id, target_id, project_root, schema_version, packet_json, created_at)
         VALUES (?1, ?2, '/projects/work-order', 2, '{\"schema_version\":2}',
                 '2026-08-30T00:00:00Z')",
    )
    .bind(&work_order_id)
    .bind(target_id.to_string())
    .execute(store.pool())
    .await
    .expect("insert work order");

    for invalid_id in ["A".repeat(64), "a".repeat(63)] {
        assert!(sqlx::query(
            "INSERT INTO harness_work_orders
                (id, target_id, project_root, schema_version, packet_json, created_at)
             VALUES (?1, ?2, '/projects/work-order', 2, '{\"schema_version\":2}',
                     '2026-08-30T00:00:00Z')",
        )
        .bind(invalid_id)
        .bind(target_id.to_string())
        .execute(store.pool())
        .await
        .is_err());
    }
    assert!(sqlx::query(
        "INSERT INTO harness_work_orders
            (id, target_id, project_root, schema_version, packet_json, created_at)
         VALUES (?1, ?2, '/projects/work-order', 2, ?3, '2026-08-30T00:00:00Z')",
    )
    .bind("b".repeat(64))
    .bind(target_id.to_string())
    .bind(format!("\"{}\"", "x".repeat(262_145)))
    .execute(store.pool())
    .await
    .is_err());

    let submission_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_submissions
            (id, work_order_id, source, source_sha256, origin_json, parent_submission_id,
             lint_json, submitted_at)
         VALUES (?1, ?2, 'int LLVMFuzzerTestOneInput(void) { return 0; }', ?3,
                 '{\"kind\":\"human\"}', NULL, '[]', '2026-08-30T00:00:00Z')",
    )
    .bind(submission_id.to_string())
    .bind(&work_order_id)
    .bind("c".repeat(64))
    .execute(store.pool())
    .await
    .expect("insert submission");
    assert!(sqlx::query(
        "INSERT INTO harness_work_order_submissions
            (id, work_order_id, source, source_sha256, origin_json, parent_submission_id,
             lint_json, submitted_at)
         VALUES (?1, ?2, ?3, ?4, '{\"kind\":\"human\"}', NULL, '[]',
                 '2026-08-30T00:00:00Z')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&work_order_id)
    .bind("x".repeat(65_537))
    .bind("d".repeat(64))
    .execute(store.pool())
    .await
    .is_err());
    assert!(sqlx::query(
        "INSERT INTO harness_work_order_submissions
            (id, work_order_id, source, source_sha256, origin_json, parent_submission_id,
             lint_json, submitted_at)
         VALUES (?1, ?2, 'different source', ?3, '{\"kind\":\"human\"}', NULL,
                 '[]', '2026-08-30T00:00:00Z')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&work_order_id)
    .bind("D".repeat(64))
    .execute(store.pool())
    .await
    .is_err());
    assert!(sqlx::query(
        "INSERT INTO harness_work_order_submissions
            (id, work_order_id, source, source_sha256, origin_json, parent_submission_id,
             lint_json, submitted_at)
         VALUES (?1, ?2, 'int LLVMFuzzerTestOneInput(void) { return 0; }', ?3,
                 '{\"kind\":\"human\"}', NULL, '[]', '2026-08-30T00:00:00Z')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&work_order_id)
    .bind("c".repeat(64))
    .execute(store.pool())
    .await
    .is_err());

    assert!(
        sqlx::query("UPDATE harness_work_orders SET project_root = '/changed'")
            .execute(store.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE harness_work_order_submissions SET source = 'changed'")
            .execute(store.pool())
            .await
            .is_err()
    );

    let stages = ["compile", "review", "smoke", "complete"];
    let statuses = [
        "running",
        "compile_failed",
        "review_failed",
        "smoke_failed",
        "smoke_passed",
        "interrupted",
    ];
    assert_eq!(stages.len(), 4);
    assert_eq!(statuses.len(), 6);

    for stage in stages {
        for status in statuses {
            let valid = (status == "running" && stage != "complete")
                || (status != "running" && stage == "complete");
            let result = sqlx::query(
                "INSERT INTO harness_work_order_attempts
                    (id, submission_id, status, current_stage, harness_id, smoke_run_id,
                     result_json, failure_code, failure_message, started_at, updated_at, ended_at)
                 VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, NULL,
                         '2026-08-30T00:00:00Z', '2026-08-30T00:00:00Z', ?5)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(submission_id.to_string())
            .bind(status)
            .bind(stage)
            .bind(if valid && status != "running" {
                Some("2026-08-30T00:00:01Z")
            } else {
                None
            })
            .execute(store.pool())
            .await;
            assert_eq!(result.is_ok(), valid, "{status}/{stage}");
        }
    }

    let terminal_attempt_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_attempts
            (id, submission_id, status, current_stage, harness_id, smoke_run_id,
             result_json, failure_code, failure_message, started_at, updated_at, ended_at)
         VALUES (?1, ?2, 'smoke_passed', 'complete', NULL, NULL, '{\"verdict\":\"pass\"}',
                 NULL, NULL, '2026-08-30T00:00:00Z', '2026-08-30T00:00:01Z',
                 '2026-08-30T00:00:01Z')",
    )
    .bind(terminal_attempt_id.to_string())
    .bind(submission_id.to_string())
    .execute(store.pool())
    .await
    .expect("insert terminal attempt");
    assert!(sqlx::query(
        "UPDATE harness_work_order_attempts SET result_json = '{\"verdict\":\"changed\"}'
         WHERE id = ?1",
    )
    .bind(terminal_attempt_id.to_string())
    .execute(store.pool())
    .await
    .is_err());
}

#[tokio::test]
async fn harness_work_order_timestamp_columns_require_real_utc_rfc3339_values() {
    let (store, _dir) = temp_store().await;
    let work_order_id = "e".repeat(64);
    insert_work_order_with_timestamp(&store, work_order_id.clone(), "2024-02-29T23:59:59Z")
        .await
        .expect("accept canonical UTC timestamp");
    let submission_id = insert_work_order_submission(
        &store,
        &work_order_id,
        "f".repeat(64),
        "{\"kind\":\"human\"}",
        "[]",
        "2024-02-29T23:59:59.123456789Z",
    )
    .await
    .expect("accept fractional UTC timestamp");
    insert_work_order_attempt(
        &store,
        submission_id,
        Some("{}"),
        None,
        None,
        "2024-02-29T23:59:59.123456789Z",
        "2024-02-29T23:59:59.123456789Z",
        Some("2024-02-29T23:59:59.123456789Z"),
    )
    .await
    .expect("accept canonical attempt timestamps");

    for (ordinal, timestamp) in [
        "2026-99-01T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2024-02-30T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T23:60:00Z",
        "2026-01-01T23:59:61Z",
        "2026-01-01T00:00:00Z\0trailing",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            insert_work_order_with_timestamp(&store, format!("{ordinal:064x}"), timestamp,)
                .await
                .is_err()
        );
    }

    for (ordinal, timestamp) in [
        "2026-01-01T00:00:00.Z",
        "2026-01-01T00:00:00.12xZ",
        "2026-01-01T00:00:00+00:00",
        "2026-01-01T00:00:00z",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(insert_work_order_submission(
            &store,
            &work_order_id,
            format!("{ordinal:064x}"),
            "{\"kind\":\"human\"}",
            "[]",
            timestamp,
        )
        .await
        .is_err());
    }

    assert!(insert_work_order_attempt(
        &store,
        submission_id,
        None,
        None,
        None,
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00Z",
        Some("2026-01-01T00:00:00.1+00:00"),
    )
    .await
    .is_err());
}

#[tokio::test]
async fn harness_work_order_evidence_columns_enforce_json_and_byte_limits() {
    let (store, _dir) = temp_store().await;
    let work_order_id = "d".repeat(64);
    insert_work_order_with_timestamp(&store, work_order_id.clone(), "2026-08-30T00:00:00Z")
        .await
        .expect("insert work order");

    let origin_maximum = json_string_at_limit(4_096);
    let lint_maximum = json_string_at_limit(65_536);
    let origin_submission = insert_work_order_submission(
        &store,
        &work_order_id,
        "1".repeat(64),
        &origin_maximum,
        "[]",
        "2026-08-30T00:00:00Z",
    )
    .await
    .expect("accept origin JSON at its byte limit");
    insert_work_order_submission(
        &store,
        &work_order_id,
        "2".repeat(64),
        "{}",
        &lint_maximum,
        "2026-08-30T00:00:00Z",
    )
    .await
    .expect("accept lint JSON at its byte limit");
    assert!(insert_work_order_submission(
        &store,
        &work_order_id,
        "3".repeat(64),
        &json_string_at_limit(4_097),
        "[]",
        "2026-08-30T00:00:00Z",
    )
    .await
    .is_err());
    assert!(insert_work_order_submission(
        &store,
        &work_order_id,
        "4".repeat(64),
        "{}",
        &json_string_at_limit(65_537),
        "2026-08-30T00:00:00Z",
    )
    .await
    .is_err());
    for (ordinal, origin_json, lint_json) in [("5", "{", "[]"), ("6", "{}", "[")] {
        assert!(insert_work_order_submission(
            &store,
            &work_order_id,
            ordinal.repeat(64),
            origin_json,
            lint_json,
            "2026-08-30T00:00:00Z",
        )
        .await
        .is_err());
    }

    let result_maximum = json_string_at_limit(65_536);
    insert_work_order_attempt(
        &store,
        origin_submission,
        Some(&result_maximum),
        Some(&"c".repeat(128)),
        Some(&"m".repeat(4_096)),
        "2026-08-30T00:00:00Z",
        "2026-08-30T00:00:00Z",
        Some("2026-08-30T00:00:00Z"),
    )
    .await
    .expect("accept attempt evidence at every byte limit");
    for (result_json, failure_code, failure_message) in [
        (Some(json_string_at_limit(65_537)), None, None),
        (Some("{".to_owned()), None, None),
        (None, Some("c".repeat(129)), None),
        (None, None, Some("m".repeat(4_097))),
    ] {
        assert!(insert_work_order_attempt(
            &store,
            origin_submission,
            result_json.as_deref(),
            failure_code.as_deref(),
            failure_message.as_deref(),
            "2026-08-30T00:00:00Z",
            "2026-08-30T00:00:00Z",
            Some("2026-08-30T00:00:00Z"),
        )
        .await
        .is_err());
    }

    for (failure_code, failure_message) in [("X'63'", "NULL"), ("NULL", "X'6d'")] {
        let statement = format!(
            "INSERT INTO harness_work_order_attempts
                (id, submission_id, status, current_stage, harness_id, smoke_run_id,
                 result_json, failure_code, failure_message, started_at, updated_at, ended_at)
             VALUES (?1, ?2, 'compile_failed', 'complete', NULL, NULL, NULL,
                     {failure_code}, {failure_message}, '2026-08-30T00:00:00Z',
                     '2026-08-30T00:00:00Z', '2026-08-30T00:00:00Z')"
        );
        assert!(
            sqlx::query(&statement)
                .bind(Uuid::new_v4().to_string())
                .bind(origin_submission.to_string())
                .execute(store.pool())
                .await
                .is_err(),
            "nullable failure evidence must reject SQLite BLOB values"
        );
    }
}

#[tokio::test]
async fn harness_work_order_attempt_reader_rejects_blob_failure_evidence() {
    let (store, _dir) = temp_store().await;
    let work_order_id = "9".repeat(64);
    insert_work_order_with_timestamp(&store, work_order_id.clone(), "2026-08-30T00:00:00Z")
        .await
        .unwrap();
    let submission_id = insert_work_order_submission(
        &store,
        &work_order_id,
        "8".repeat(64),
        "{}",
        "[]",
        "2026-08-30T00:00:00Z",
    )
    .await
    .unwrap();
    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    let attempt_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO harness_work_order_attempts
            (id, submission_id, status, current_stage, harness_id, smoke_run_id,
             result_json, failure_code, failure_message, started_at, updated_at, ended_at)
         VALUES (?1, ?2, 'compile_failed', 'complete', NULL, NULL, NULL, X'63', X'6d',
                 '2026-08-30T00:00:00Z', '2026-08-30T00:00:00Z',
                 '2026-08-30T00:00:00Z')",
    )
    .bind(attempt_id.to_string())
    .bind(submission_id.to_string())
    .execute(&mut *connection)
    .await
    .unwrap();
    drop(connection);

    assert!(matches!(
        store.harness_work_order_attempt(attempt_id).await,
        Err(StorageError::Db(_))
    ));
}

#[test]
fn harness_work_order_attempt_states_round_trip_and_reject_unknown_storage_values() {
    assert_eq!(
        "compile".parse::<HarnessWorkOrderAttemptStage>().unwrap(),
        HarnessWorkOrderAttemptStage::Compile
    );
    assert_eq!(
        HarnessWorkOrderAttemptStatus::SmokePassed.to_string(),
        "smoke_passed"
    );
    assert!(matches!(
        "unknown".parse::<HarnessWorkOrderAttemptStage>(),
        Err(StorageError::InvalidData(_))
    ));
    assert!(matches!(
        "unknown".parse::<HarnessWorkOrderAttemptStatus>(),
        Err(StorageError::InvalidData(_))
    ));
}

#[tokio::test]
async fn harness_work_order_store_preserves_immutable_rows_and_submission_constraints() {
    let (store, _dir) = temp_store().await;
    let now = Utc::now().trunc_subsecs(0);
    let target_id = Uuid::new_v4();
    let first = work_order_record('a', target_id, "/projects/one", now);
    let second = work_order_record('b', target_id, "/projects/two", now + Duration::seconds(1));

    assert_eq!(
        store.insert_harness_work_order(&first).await.unwrap(),
        first
    );
    assert_eq!(
        store.insert_harness_work_order(&first).await.unwrap(),
        first,
        "an exact work-order retry returns the first persisted row"
    );
    let mut later_retry = first.clone();
    later_retry.created_at += Duration::seconds(1);
    assert_eq!(
        store.insert_harness_work_order(&later_retry).await.unwrap(),
        first,
        "a receipt retry retains the first persistence timestamp"
    );
    let mut conflicting_retry = first.clone();
    conflicting_retry.packet_json = r#"{"schema_version":2,"changed":true}"#.to_owned();
    assert!(matches!(
        store.insert_harness_work_order(&conflicting_retry).await,
        Err(StorageError::InvalidData(_))
    ));
    store.insert_harness_work_order(&second).await.unwrap();
    assert_eq!(
        store
            .list_harness_work_orders(None)
            .await
            .unwrap()
            .into_iter()
            .map(|record| record.id)
            .collect::<Vec<_>>(),
        vec![second.id.clone(), first.id.clone()]
    );
    assert_eq!(
        store
            .list_harness_work_orders(Some("/projects/one"))
            .await
            .unwrap(),
        vec![first.clone()]
    );

    let root_submission = submission_record(
        Uuid::new_v4(),
        &first.id,
        "int LLVMFuzzerTestOneInput(const uint8_t*, size_t) { return 0; }",
        "1".repeat(64),
        None,
        now,
    );
    let missing_work_order = submission_record(
        Uuid::new_v4(),
        &"e".repeat(64),
        "missing work order source",
        "e".repeat(64),
        None,
        now,
    );
    assert!(matches!(
        store
            .insert_harness_work_order_submission(&missing_work_order)
            .await,
        Err(HarnessWorkOrderSubmissionInsertError::MissingWorkOrder)
    ));
    assert_eq!(
        store
            .insert_harness_work_order_submission(&root_submission)
            .await
            .unwrap(),
        root_submission
    );
    let retry_with_new_id = submission_record(
        Uuid::new_v4(),
        &first.id,
        &root_submission.source,
        "1".repeat(64),
        None,
        now + Duration::seconds(2),
    );
    assert_eq!(
        store
            .insert_harness_work_order_submission(&retry_with_new_id)
            .await
            .unwrap(),
        root_submission,
        "a submission retry is identified by immutable submission evidence"
    );
    let cross_work_order_parent = submission_record(
        Uuid::new_v4(),
        &second.id,
        "different source",
        "2".repeat(64),
        Some(root_submission.id),
        now,
    );
    assert!(matches!(
        store
            .insert_harness_work_order_submission(&cross_work_order_parent)
            .await,
        Err(HarnessWorkOrderSubmissionInsertError::ParentWorkOrderMismatch)
    ));
    let missing_parent = submission_record(
        Uuid::new_v4(),
        &first.id,
        "missing parent source",
        "3".repeat(64),
        Some(Uuid::new_v4()),
        now,
    );
    assert!(matches!(
        store
            .insert_harness_work_order_submission(&missing_parent)
            .await,
        Err(HarnessWorkOrderSubmissionInsertError::MissingParent)
    ));

    for ordinal in 2..=20 {
        let submission = submission_record(
            Uuid::new_v4(),
            &first.id,
            &format!("source {ordinal}"),
            format!("{ordinal:064x}"),
            None,
            now + Duration::seconds(i64::from(ordinal)),
        );
        store
            .insert_harness_work_order_submission(&submission)
            .await
            .unwrap();
    }
    let twenty_first = submission_record(
        Uuid::new_v4(),
        &first.id,
        "source 21",
        "f".repeat(64),
        None,
        now + Duration::seconds(21),
    );
    assert!(matches!(
        store
            .insert_harness_work_order_submission(&twenty_first)
            .await,
        Err(HarnessWorkOrderSubmissionInsertError::SubmissionLimitReached)
    ));
    let submissions = store
        .list_harness_work_order_submissions(&first.id)
        .await
        .unwrap();
    assert_eq!(submissions.len(), 20);
    assert_eq!(
        submissions.first().map(|record| record.source.as_str()),
        Some("source 20")
    );
    assert_eq!(
        store
            .harness_work_order_submission(root_submission.id)
            .await
            .unwrap(),
        Some(root_submission)
    );
}

#[tokio::test]
async fn harness_work_order_store_rejects_uuid_conflict_before_secondary_submission_retry() {
    let (store, _dir) = temp_store().await;
    let now = Utc::now().trunc_subsecs(0);
    let work_order = work_order_record('c', Uuid::new_v4(), "/projects/uuid-conflict", now);
    store.insert_harness_work_order(&work_order).await.unwrap();
    let first = submission_record(
        Uuid::new_v4(),
        &work_order.id,
        "first source",
        "1".repeat(64),
        None,
        now,
    );
    let second = submission_record(
        Uuid::new_v4(),
        &work_order.id,
        "second source",
        "2".repeat(64),
        None,
        now + Duration::seconds(1),
    );
    store
        .insert_harness_work_order_submission(&first)
        .await
        .unwrap();
    store
        .insert_harness_work_order_submission(&second)
        .await
        .unwrap();
    let conflicting_retry = HarnessWorkOrderSubmissionRecord {
        id: first.id,
        ..second.clone()
    };

    assert!(matches!(
        store
            .insert_harness_work_order_submission(&conflicting_retry)
            .await,
        Err(HarnessWorkOrderSubmissionInsertError::Storage(
            StorageError::InvalidData(_)
        ))
    ));
    assert_eq!(
        store.harness_work_order_submission(first.id).await.unwrap(),
        Some(first)
    );
    assert_eq!(
        store
            .harness_work_order_submission(second.id)
            .await
            .unwrap(),
        Some(second)
    );
}

#[tokio::test]
async fn harness_work_order_attempts_use_compare_and_set_and_recover_running_rows() {
    let (store, _dir) = temp_store().await;
    let now = Utc::now().trunc_subsecs(0);
    let work_order = work_order_record('c', Uuid::new_v4(), "/projects/attempts", now);
    store.insert_harness_work_order(&work_order).await.unwrap();
    let submission = submission_record(
        Uuid::new_v4(),
        &work_order.id,
        "source",
        "3".repeat(64),
        None,
        now,
    );
    store
        .insert_harness_work_order_submission(&submission)
        .await
        .unwrap();
    let attempt = running_attempt(Uuid::new_v4(), submission.id, now);
    assert_eq!(
        store
            .insert_harness_work_order_attempt(&attempt)
            .await
            .unwrap(),
        attempt
    );
    let harness_id = Uuid::new_v4();
    let reviewed = store
        .transition_harness_work_order_attempt(
            attempt.id,
            HarnessWorkOrderAttemptStage::Compile,
            HarnessWorkOrderAttemptStage::Review,
            Some(harness_id),
            now + Duration::seconds(1),
        )
        .await
        .unwrap();
    assert_eq!(reviewed.harness_id, Some(harness_id));
    assert!(matches!(
        store
            .transition_harness_work_order_attempt(
                attempt.id,
                HarnessWorkOrderAttemptStage::Compile,
                HarnessWorkOrderAttemptStage::Review,
                None,
                now + Duration::seconds(2),
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));
    let smoking = store
        .transition_harness_work_order_attempt(
            attempt.id,
            HarnessWorkOrderAttemptStage::Review,
            HarnessWorkOrderAttemptStage::Smoke,
            None,
            now + Duration::seconds(3),
        )
        .await
        .unwrap();
    assert_eq!(smoking.harness_id, Some(harness_id));
    let completion = HarnessWorkOrderAttemptCompletion {
        expected_stage: HarnessWorkOrderAttemptStage::Smoke,
        status: HarnessWorkOrderAttemptStatus::SmokePassed,
        harness_id: Some(harness_id),
        smoke_run_id: Some(Uuid::new_v4()),
        result_json: Some(r#"{"verdict":"pass"}"#),
        failure_code: None,
        failure_message: None,
        completed_at: now + Duration::seconds(4),
    };
    let completed = store
        .complete_harness_work_order_attempt(attempt.id, completion)
        .await
        .unwrap();
    assert_eq!(completed.status, HarnessWorkOrderAttemptStatus::SmokePassed);
    assert_eq!(
        completed.current_stage,
        HarnessWorkOrderAttemptStage::Complete
    );
    assert!(matches!(
        store
            .transition_harness_work_order_attempt(
                attempt.id,
                HarnessWorkOrderAttemptStage::Complete,
                HarnessWorkOrderAttemptStage::Smoke,
                None,
                now + Duration::seconds(5),
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));

    let interrupted = running_attempt(Uuid::new_v4(), submission.id, now);
    store
        .insert_harness_work_order_attempt(&interrupted)
        .await
        .unwrap();
    assert_eq!(
        store
            .list_running_harness_work_order_attempts()
            .await
            .unwrap(),
        vec![interrupted.clone()]
    );
    assert!(store
        .recover_harness_work_order_attempt(interrupted.id, now + Duration::seconds(6),)
        .await
        .unwrap());
    assert!(!store
        .recover_harness_work_order_attempt(interrupted.id, now + Duration::seconds(7),)
        .await
        .unwrap());
    let recovered = store
        .harness_work_order_attempt(interrupted.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.status, HarnessWorkOrderAttemptStatus::Interrupted);
    assert_eq!(
        recovered.current_stage,
        HarnessWorkOrderAttemptStage::Complete
    );
    assert_eq!(
        recovered.failure_code.as_deref(),
        Some("attempt_interrupted")
    );
    assert!(recovered.ended_at.is_some());
}

#[tokio::test]
async fn harness_work_order_cleanup_removes_owned_or_orphaned_rows_and_retains_run_history_evidence(
) {
    let (store, _dir) = temp_store().await;
    let now = Utc::now().trunc_subsecs(0);
    let target = sample_target("/projects/clear");
    store.upsert_target(&target, now).await.unwrap();
    let work_order = work_order_record('d', target.id, "/projects/clear", now);
    store.insert_harness_work_order(&work_order).await.unwrap();
    let submission = submission_record(
        Uuid::new_v4(),
        &work_order.id,
        "source",
        "4".repeat(64),
        None,
        now,
    );
    store
        .insert_harness_work_order_submission(&submission)
        .await
        .unwrap();
    let harness_id = Uuid::new_v4();
    let smoke_run = RunRecord::new(
        "/projects/clear".to_owned(),
        EngineKind::LibFuzzer,
        None,
        now,
    );
    store.insert_run(&smoke_run).await.unwrap();
    let attempt = running_attempt(Uuid::new_v4(), submission.id, now);
    store
        .insert_harness_work_order_attempt(&attempt)
        .await
        .unwrap();
    store
        .complete_harness_work_order_attempt(
            attempt.id,
            HarnessWorkOrderAttemptCompletion {
                expected_stage: HarnessWorkOrderAttemptStage::Compile,
                status: HarnessWorkOrderAttemptStatus::CompileFailed,
                harness_id: Some(harness_id),
                smoke_run_id: Some(smoke_run.id),
                result_json: Some(r#"{"compile":"failed"}"#),
                failure_code: Some("compile_failed"),
                failure_message: Some("compile failed"),
                completed_at: now + Duration::seconds(1),
            },
        )
        .await
        .unwrap();

    store.clear_all_runs().await.unwrap();
    assert!(store
        .list_runs(Some("/projects/clear"))
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store.harness_work_order(&work_order.id).await.unwrap(),
        Some(work_order.clone())
    );
    assert_eq!(
        store
            .harness_work_order_submission(submission.id)
            .await
            .unwrap(),
        Some(submission.clone())
    );
    let retained = store
        .harness_work_order_attempt(attempt.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retained.harness_id, Some(harness_id));
    assert_eq!(retained.smoke_run_id, Some(smoke_run.id));
    assert_eq!(
        retained.result_json.as_deref(),
        Some(r#"{"compile":"failed"}"#)
    );

    store.clear_knowledge().await.unwrap();
    assert!(store
        .harness_work_order(&work_order.id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .harness_work_order_submission(submission.id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .harness_work_order_attempt(attempt.id)
        .await
        .unwrap()
        .is_none());

    let target = sample_target("/projects/delete-work-order");
    store.upsert_target(&target, now).await.unwrap();
    let project_work_order = work_order_record('e', target.id, "/projects/delete-work-order", now);
    store
        .insert_harness_work_order(&project_work_order)
        .await
        .unwrap();
    let project_submission = submission_record(
        Uuid::new_v4(),
        &project_work_order.id,
        "source",
        "5".repeat(64),
        None,
        now,
    );
    store
        .insert_harness_work_order_submission(&project_submission)
        .await
        .unwrap();
    store
        .insert_harness_work_order_attempt(&running_attempt(
            Uuid::new_v4(),
            project_submission.id,
            now,
        ))
        .await
        .unwrap();
    store
        .delete_project("/projects/delete-work-order")
        .await
        .unwrap();
    assert!(store
        .harness_work_order(&project_work_order.id)
        .await
        .unwrap()
        .is_none());

    let orphan_work_order = work_order_record('f', Uuid::new_v4(), "/projects/orphan", now);
    sqlx::query(
        "INSERT INTO harness_work_orders
            (id, target_id, project_root, schema_version, packet_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&orphan_work_order.id)
    .bind(orphan_work_order.target_id.to_string())
    .bind(&orphan_work_order.project_root)
    .bind(orphan_work_order.schema_version)
    .bind(&orphan_work_order.packet_json)
    .bind(
        orphan_work_order
            .created_at
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
    )
    .execute(store.pool())
    .await
    .unwrap();
    let orphan_submission = submission_record(
        Uuid::new_v4(),
        &orphan_work_order.id,
        "orphan source",
        "6".repeat(64),
        None,
        now,
    );
    store
        .insert_harness_work_order_submission(&orphan_submission)
        .await
        .unwrap();
    store
        .insert_harness_work_order_attempt(&running_attempt(
            Uuid::new_v4(),
            orphan_submission.id,
            now,
        ))
        .await
        .unwrap();
    store.delete_orphans().await.unwrap();
    assert!(store
        .harness_work_order(&orphan_work_order.id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .list_harness_work_order_submissions(&orphan_work_order.id)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn harness_ai_review_is_persisted_for_the_exact_source_revision() {
    let (store, _dir) = temp_store().await;
    let harness = sample_harness(Uuid::new_v4());
    store.upsert_harness(&harness).await.unwrap();
    let review = HarnessAiReviewRecord {
        harness_id: harness.id,
        source_sha256: "a".repeat(64),
        binary_sha256: "b".repeat(64),
        review_json: r#"{"exercises_target":true}"#.to_owned(),
        reviewed_at: Utc::now(),
    };

    store.record_harness_ai_review(&review).await.unwrap();

    assert_eq!(
        store.harness_ai_review(harness.id).await.unwrap(),
        Some(review)
    );
}

async fn remediation_fixture(store: &Store, project: &str) -> RemediationOperationRecord {
    let run = RunRecord::new(project, EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let finding_id = Uuid::new_v4();
    store
        .upsert_crash(&Crash {
            id: finding_id,
            run_id: run.id,
            target_id: Uuid::new_v4(),
            input_path: PathBuf::from("runs/input/crash"),
            stack_signature: "signature".to_owned(),
            kind: CrashKind::Asan,
            summary: "overflow".to_owned(),
            minimized: true,
            bug_report: None,
            casr: None,
            origin: hf_core::crash::CrashOrigin::Target,
        })
        .await
        .unwrap();
    RemediationOperationRecord {
        id: Uuid::new_v4(),
        run_id: run.id,
        finding_id,
        project_root: project.to_owned(),
        target: "parse_packet".to_owned(),
        status: RemediationOperationStatus::Draft,
        current_stage: RemediationOperationStage::Review,
        binding_json: serde_json::json!({"schema_version": 3}).to_string(),
        approval_json: None,
        verification_json: None,
        artifact_dir: format!("remediations/{finding_id}"),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        ended_at: None,
        failure_code: None,
        failure_message: None,
    }
}

#[tokio::test]
async fn remediation_transitions_are_compare_and_set_and_scope_is_immutable() {
    let (store, _dir) = temp_store().await;
    let draft = remediation_fixture(&store, "/projects/remediation").await;
    store.insert_remediation_operation(&draft).await.unwrap();

    let approval = serde_json::json!({"approval_id": Uuid::new_v4()}).to_string();
    store
        .approve_remediation_operation(draft.id, &approval, Utc::now())
        .await
        .unwrap();
    assert!(matches!(
        store
            .approve_remediation_operation(draft.id, &approval, Utc::now())
            .await,
        Err(StorageError::InvalidData(_))
    ));

    store
        .claim_remediation_operation(draft.id, Utc::now())
        .await
        .unwrap();
    store
        .advance_remediation_stage(
            draft.id,
            RemediationOperationStage::OriginalReplay,
            RemediationOperationStage::PatchBuild,
            Utc::now(),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .advance_remediation_stage(
                draft.id,
                RemediationOperationStage::OriginalReplay,
                RemediationOperationStage::Regression,
                Utc::now(),
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));

    let error = sqlx::query("UPDATE remediation_operations SET binding_json = '{}' WHERE id = ?1")
        .bind(draft.id.to_string())
        .execute(store.pool())
        .await
        .expect_err("immutable binding must reject direct mutation");
    assert!(error.to_string().contains("immutable"));
}

#[tokio::test]
async fn remediation_terminal_evidence_is_queryable_and_running_work_recovers() {
    let (store, _dir) = temp_store().await;
    let completed = remediation_fixture(&store, "/projects/remediation").await;
    store
        .insert_remediation_operation(&completed)
        .await
        .unwrap();
    store
        .approve_remediation_operation(completed.id, "{}", Utc::now())
        .await
        .unwrap();
    store
        .claim_remediation_operation(completed.id, Utc::now())
        .await
        .unwrap();
    store
        .finish_remediation_operation(
            completed.id,
            &RemediationOperationCompletion {
                status: RemediationOperationStatus::Verified,
                verification_json: Some("{\"status\":\"verified\"}"),
                failure_code: None,
                failure_message: None,
                completed_at: Utc::now(),
            },
        )
        .await
        .unwrap();
    let latest = store
        .latest_remediation_for_finding(completed.finding_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest.status, RemediationOperationStatus::Verified);
    assert_eq!(latest.current_stage, RemediationOperationStage::Complete);

    let interrupted = remediation_fixture(&store, "/projects/remediation").await;
    store
        .insert_remediation_operation(&interrupted)
        .await
        .unwrap();
    store
        .approve_remediation_operation(interrupted.id, "{}", Utc::now())
        .await
        .unwrap();
    store
        .claim_remediation_operation(interrupted.id, Utc::now())
        .await
        .unwrap();
    assert_eq!(
        store
            .recover_interrupted_remediations(Utc::now())
            .await
            .unwrap(),
        1
    );
    let recovered = store
        .remediation_operation(interrupted.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovered.status, RemediationOperationStatus::Inconclusive);
    assert_eq!(
        recovered.failure_code.as_deref(),
        Some("interrupted_after_restart")
    );
}

fn execution_json(
    execution_id: &str,
    schedule_id: &str,
    triggered_at: &str,
    status: &str,
) -> String {
    serde_json::json!({
        "execution_id": execution_id,
        "schedule_id": schedule_id,
        "triggered_at": triggered_at,
        "started_at": if status == "running" {
            Some(triggered_at)
        } else {
            None::<&str>
        },
        "completed_at": None::<&str>,
        "status": status,
        "workflow_execution_id": null,
        "request_summary": {},
        "response_summary": {},
        "error_message": null,
    })
    .to_string()
}

fn new_occurrence(id: &str, schedule_id: &str, execution_id: &str) -> NewScheduleOccurrence {
    let triggered_at = Utc::now().to_rfc3339();
    NewScheduleOccurrence {
        id: id.to_owned(),
        schedule_id: schedule_id.to_owned(),
        execution_id: execution_id.to_owned(),
        triggered_at: triggered_at.clone(),
        owner_id: "owner-1".to_owned(),
        lease_expires_at: (Utc::now() + Duration::seconds(60)).to_rfc3339(),
        execution_status: "pending".to_owned(),
        execution_data_json: execution_json(execution_id, schedule_id, &triggered_at, "pending"),
    }
}

fn transition(
    new: &NewScheduleOccurrence,
    from_state: &str,
    to_state: &str,
    execution_status: &str,
) -> ScheduleOccurrenceTransition {
    ScheduleOccurrenceTransition {
        occurrence_id: new.id.clone(),
        schedule_id: new.schedule_id.clone(),
        execution_id: new.execution_id.clone(),
        owner_id: new.owner_id.clone(),
        from_state: from_state.to_owned(),
        to_state: to_state.to_owned(),
        lease_expires_at: (to_state == "running")
            .then(|| (Utc::now() + Duration::seconds(60)).to_rfc3339()),
        recovery_detail: None,
        execution_status: execution_status.to_owned(),
        execution_data_json: execution_json(
            &new.execution_id,
            &new.schedule_id,
            &new.triggered_at,
            execution_status,
        ),
    }
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
async fn active_semgrep_runs_returns_every_nonterminal_phase_in_start_order() {
    let (store, _dir) = temp_store().await;
    let started_at = Utc::now();
    let mut active = Vec::new();
    for (index, status) in [
        SemgrepRunStatus::Staging,
        SemgrepRunStatus::Scanning,
        SemgrepRunStatus::Validating,
        SemgrepRunStatus::Persisting,
    ]
    .into_iter()
    .enumerate()
    {
        let mut run = semgrep_staging_run(
            &format!("/projects/active-{index}"),
            started_at + Duration::seconds(i64::try_from(index).unwrap()),
        );
        store.insert_semgrep_run(&run).await.unwrap();
        if status != SemgrepRunStatus::Staging {
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
        }
        if matches!(
            status,
            SemgrepRunStatus::Validating | SemgrepRunStatus::Persisting
        ) {
            store
                .set_semgrep_phase(
                    run.id,
                    SemgrepRunStatus::Scanning,
                    SemgrepRunStatus::Validating,
                    None,
                )
                .await
                .unwrap();
            run.status = SemgrepRunStatus::Validating;
        }
        if status == SemgrepRunStatus::Persisting {
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
        }
        active.push(run);
    }

    let failed = semgrep_staging_run("/projects/failed", started_at + Duration::seconds(5));
    store.insert_semgrep_run(&failed).await.unwrap();
    store
        .fail_semgrep_run(
            failed.id,
            SemgrepRunStatus::Failed,
            "fixture",
            "fixture failure",
            failed.started_at + Duration::milliseconds(1),
        )
        .await
        .unwrap();
    let mut done = semgrep_staging_run("/projects/done", started_at + Duration::seconds(6));
    advance_semgrep_to_persisting(&store, &mut done).await;
    let done_publication = semgrep_publication(done, 0, 0);
    store.publish_semgrep_run(&done_publication).await.unwrap();

    assert_eq!(store.active_semgrep_runs().await.unwrap(), active);
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
async fn semgrep_score_write_validation_enforces_capped_formula_and_match_consistency() {
    let invalid_scores = [
        ("inconsistent effective score", 0.6, 0.05, 0.8, 1),
        ("boost without a matched rule", 0.6, 0.05, 0.65, 0),
        (
            "sub-epsilon boost without a matched rule",
            0.6,
            f64::EPSILON / 2.0,
            0.6,
            0,
        ),
        ("non-canonical half-step boost", 0.6, 0.005, 0.605, 1),
        ("matched rule without a boost", 0.6, 0.0, 0.6, 1),
        ("non-finite boost", 0.6, f64::INFINITY, 0.65, 1),
        ("non-finite effective score", 0.6, 0.05, f64::NAN, 1),
    ];
    for (case, base_score, boost, effective_score, matched_rule_count) in invalid_scores {
        let (store, _dir) = temp_store().await;
        let mut run = semgrep_staging_run(&format!("/projects/{case}"), Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        let mut publication = semgrep_publication(run, 1, 1);
        publication.run.matched_candidate_count = Some(u32::from(matched_rule_count > 0));
        let overlay = &mut publication.scores[0];
        overlay.base_score = base_score;
        overlay.boost = boost;
        overlay.effective_score = effective_score;
        overlay.matched_rule_count = matched_rule_count;

        assert!(
            matches!(
                store.publish_semgrep_run(&publication).await,
                Err(StorageError::InvalidData(_))
            ),
            "{case} unexpectedly persisted"
        );
    }

    for (project, base_score, boost, effective_score) in [
        ("/projects/capped-score", 0.95, 0.10, 1.0),
        ("/projects/floating-score", 0.10, 0.20, 0.30),
        ("/projects/aggregate-boost", 0.60, 0.10 + 0.05, 0.75),
    ] {
        let (store, _dir) = temp_store().await;
        let mut run = semgrep_staging_run(project, Utc::now());
        advance_semgrep_to_persisting(&store, &mut run).await;
        let mut publication = semgrep_publication(run, 1, 1);
        let overlay = &mut publication.scores[0];
        overlay.base_score = base_score;
        overlay.boost = boost;
        overlay.effective_score = effective_score;
        store.publish_semgrep_run(&publication).await.unwrap();
    }
}

#[tokio::test]
async fn semgrep_finding_relative_path_enforces_exact_byte_limit_on_write_and_read() {
    let (store, _dir) = temp_store().await;
    let mut run = semgrep_staging_run("/projects/path-boundary", Utc::now());
    advance_semgrep_to_persisting(&store, &mut run).await;
    let mut publication = semgrep_publication(run, 1, 1);
    publication.findings[0].relative_file = "a".repeat(4_096);
    store.publish_semgrep_run(&publication).await.unwrap();
    assert_eq!(
        store
            .semgrep_publication(publication.run.id)
            .await
            .unwrap()
            .unwrap()
            .findings[0]
            .relative_file
            .len(),
        4_096
    );

    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("UPDATE semgrep_findings SET relative_file = ?2 WHERE scan_id = ?1")
        .bind(publication.run.id.to_string())
        .bind("b".repeat(4_097))
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    assert!(matches!(
        store.semgrep_publication(publication.run.id).await,
        Err(StorageError::InvalidData(_))
    ));

    let (store, _dir) = temp_store().await;
    let mut run = semgrep_staging_run("/projects/path-overflow", Utc::now());
    advance_semgrep_to_persisting(&store, &mut run).await;
    let mut publication = semgrep_publication(run, 1, 1);
    publication.findings[0].relative_file = "a".repeat(4_097);
    assert!(matches!(
        store.publish_semgrep_run(&publication).await,
        Err(StorageError::InvalidData(_))
    ));
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
        ("boost", "9e999"),
        ("effective_score", "9e999"),
        ("effective_score", "0.8"),
        ("boost", "0.0"),
        ("matched_rule_count", "0"),
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
async fn append_message_waits_for_transient_write_contention() {
    let (store, _dir) = temp_store().await;
    let session = store.create_session(None, Utc::now()).await.unwrap();

    // Keep two physical connections ready so the append immediately contends
    // with the write transaction instead of waiting for pool setup.
    let mut blocker = store.pool().acquire().await.unwrap();
    let ready = store.pool().acquire().await.unwrap();
    drop(ready);

    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *blocker)
        .await
        .unwrap();

    let append_store = store.clone();
    let append = tokio::spawn(async move {
        append_store
            .append_message(session, "user", "after contention", Utc::now())
            .await
    });

    tokio::time::sleep(StdDuration::from_secs(6)).await;
    sqlx::query("ROLLBACK")
        .execute(&mut *blocker)
        .await
        .unwrap();

    append
        .await
        .unwrap()
        .expect("a transient write lock must not lose the message");
    assert_eq!(
        store.session_history(session).await.unwrap(),
        vec![("user".to_owned(), "after contention".to_owned())]
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
        origin: hf_core::crash::CrashOrigin::Unknown,
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
        origin: hf_core::crash::CrashOrigin::Unknown,
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
        origin: hf_core::crash::CrashOrigin::Unknown,
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
            extra_flags: Vec::new(),
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
async fn harness_upsert_rejects_a_changed_source_for_an_existing_id() {
    let (store, _dir) = temp_store().await;
    let target_id = Uuid::new_v4();
    let harness = sample_harness(target_id);
    store.upsert_harness(&harness).await.unwrap();

    let mut replacement = harness.clone();
    replacement.source = "different immutable harness source".to_owned();
    let error = store
        .upsert_harness(&replacement)
        .await
        .expect_err("same harness id must not accept different source bytes");

    assert!(matches!(error, StorageError::InvalidData(_)));
    let persisted = store.get_harness(harness.id).await.unwrap().unwrap();
    assert_eq!(persisted.source, harness.source);
}

#[tokio::test]
async fn harness_upsert_rejects_a_changed_build_identity_for_an_existing_id() {
    let (store, _dir) = temp_store().await;
    let harness = sample_harness(Uuid::new_v4());
    store.upsert_harness(&harness).await.unwrap();

    let mut replacement = harness.clone();
    replacement.build_cmd.output = PathBuf::from("different-fuzz-target");
    let error = store
        .upsert_harness(&replacement)
        .await
        .expect_err("same harness id must not accept a different build identity");

    assert!(matches!(error, StorageError::InvalidData(_)));
    assert_eq!(
        store
            .get_harness(harness.id)
            .await
            .unwrap()
            .unwrap()
            .build_cmd
            .output,
        harness.build_cmd.output
    );
}

fn smoke_passed_harness(target_id: Uuid) -> Harness {
    let mut harness = sample_harness(target_id);
    harness.status = HarnessStatus::SmokePassed;
    harness.smoke_run = Some(hf_core::harness::SmokeRunSummary {
        duration_secs: 60,
        execs_per_sec: 1.0,
        crashes: 0,
        passed: true,
        source_sha256: Some("a".repeat(64)),
        binary_sha256: Some("b".repeat(64)),
        run_id: Some(Uuid::new_v4()),
    });
    harness
}

#[tokio::test]
async fn harness_promotion_and_digest_bound_approval_are_atomic_and_idempotent() {
    let (store, _dir) = temp_store().await;
    let mut harness = smoke_passed_harness(Uuid::new_v4());
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
async fn documented_findings_promotion_accepts_crash_bearing_smoke_evidence() {
    let (store, _dir) = temp_store().await;
    let mut harness = smoke_passed_harness(Uuid::new_v4());
    let smoke = harness.smoke_run.as_mut().unwrap();
    smoke.passed = false;
    smoke.crashes = 1;
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Promoted;

    let error = store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::KnownFindings,
            &"c".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect_err("documented findings promotion must bind the retained source digest");
    assert!(matches!(error, StorageError::InvalidData(_)));
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );

    let approval = store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::KnownFindings,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect("documented findings promotion must retain crash evidence");

    assert_eq!(approval.approval_kind, HarnessApprovalKind::KnownFindings);
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::Promoted
    );
}

#[tokio::test]
async fn clean_smoke_promotion_rejects_a_crash_bearing_summary_without_writes() {
    let (store, _dir) = temp_store().await;
    let mut harness = smoke_passed_harness(Uuid::new_v4());
    let smoke = harness.smoke_run.as_mut().unwrap();
    smoke.passed = false;
    smoke.crashes = 1;
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Promoted;

    let error = store
        .promote_harness_with_approval(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect_err("clean promotion must reject retained smoke crashes");

    assert!(matches!(error, StorageError::InvalidData(_)));
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );
    assert!(store
        .harness_approval(harness.id, &"a".repeat(64), &"b".repeat(64))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn harness_upsert_preserves_an_unchanged_revision_while_advancing_smoke_evidence() {
    let (store, _dir) = temp_store().await;
    let mut harness = sample_harness(Uuid::new_v4());
    store.upsert_harness(&harness).await.unwrap();

    harness.status = HarnessStatus::SmokePassed;
    harness.smoke_run = smoke_passed_harness(harness.target_id).smoke_run;
    store.upsert_harness(&harness).await.unwrap();

    let persisted = store.get_harness(harness.id).await.unwrap().unwrap();
    assert_eq!(persisted.status, HarnessStatus::SmokePassed);
    assert_eq!(
        persisted
            .smoke_run
            .as_ref()
            .and_then(|smoke| smoke.source_sha256.as_deref()),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
}

#[tokio::test]
async fn harness_promotion_rejects_changed_revisions_and_stale_current_status_without_writes() {
    let (store, _dir) = temp_store().await;
    let mut persisted = smoke_passed_harness(Uuid::new_v4());
    store.upsert_harness(&persisted).await.unwrap();
    let mut promoted = persisted.clone();
    promoted.status = HarnessStatus::Promoted;

    let mut changed_source = promoted.clone();
    changed_source.source = "different source".to_owned();
    let error = store
        .promote_harness_with_approval(
            &changed_source,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect_err("promotion must use the exact persisted revision");
    assert!(matches!(error, StorageError::InvalidData(_)));
    let unchanged = store.get_harness(persisted.id).await.unwrap().unwrap();
    assert_eq!(unchanged.status, persisted.status);
    assert_eq!(unchanged.source, persisted.source);
    assert_eq!(unchanged.build_cmd.output, persisted.build_cmd.output);
    assert!(store
        .harness_approval(persisted.id, &"a".repeat(64), &"b".repeat(64))
        .await
        .unwrap()
        .is_none());

    persisted.status = HarnessStatus::Compiled;
    store.upsert_harness(&persisted).await.unwrap();
    let error = store
        .promote_harness_with_approval(
            &promoted,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect_err("promotion must reject a stale current status");
    assert!(matches!(error, StorageError::InvalidData(_)));
    let unchanged = store.get_harness(persisted.id).await.unwrap().unwrap();
    assert_eq!(unchanged.status, persisted.status);
    assert_eq!(unchanged.source, persisted.source);
    assert_eq!(unchanged.build_cmd.output, persisted.build_cmd.output);
    assert!(store
        .harness_approval(persisted.id, &"a".repeat(64), &"b".repeat(64))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn harness_promotion_rolls_back_an_approval_when_its_conditional_update_loses() {
    let (store, _dir) = temp_store().await;
    let mut harness = smoke_passed_harness(Uuid::new_v4());
    store.upsert_harness(&harness).await.unwrap();
    sqlx::query(
        "CREATE TRIGGER ignore_harness_promotion
         BEFORE UPDATE ON harnesses
         WHEN NEW.status = 'Promoted'
         BEGIN
           SELECT RAISE(IGNORE);
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
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
        )
        .await
        .expect_err("a lost conditional update must abort the transition");

    assert!(matches!(error, StorageError::InvalidData(_)));
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );
    assert!(store
        .harness_approval(harness.id, &"a".repeat(64), &"b".repeat(64))
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn rejected_approval_rolls_back_the_promoted_harness_state() {
    let (store, _dir) = temp_store().await;
    let mut harness = smoke_passed_harness(Uuid::new_v4());
    harness.smoke_run.as_mut().unwrap().source_sha256 = Some("c".repeat(64));
    harness.smoke_run.as_mut().unwrap().binary_sha256 = Some("d".repeat(64));
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
        origin: hf_core::crash::CrashOrigin::Unknown,
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
                    origin: hf_core::crash::CrashOrigin::Unknown,
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
            origin: hf_core::crash::CrashOrigin::Unknown,
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
        origin: hf_core::crash::CrashOrigin::Unknown,
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
async fn occurrence_reservation_commits_receipt_and_pending_execution_together() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    let result = store.reserve_schedule_occurrence(&new).await.unwrap();
    assert!(matches!(result, ScheduleOccurrenceReservation::Reserved(_)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_occurrences WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-1' AND status = 'pending'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn duplicate_schedule_reservation_returns_existing_without_second_execution() {
    let (store, _dir) = temp_store().await;
    store
        .reserve_schedule_occurrence(&new_occurrence("occ-1", "schedule-1", "exec-1"))
        .await
        .unwrap();
    let duplicate = store
        .reserve_schedule_occurrence(&new_occurrence("occ-2", "schedule-1", "exec-2"))
        .await
        .unwrap();
    assert!(matches!(
        duplicate,
        ScheduleOccurrenceReservation::Existing(_)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn occurrence_constraints_reject_unknown_state_and_oversized_detail() {
    let (store, _dir) = temp_store().await;
    let unknown = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
         VALUES ('bad-state', 'schedule-a', 'exec-a', ?1, 'invented', 'owner', ?2)",
    )
    .bind(Utc::now().to_rfc3339())
    .bind((Utc::now() + Duration::seconds(60)).to_rfc3339())
    .execute(store.pool())
    .await;
    assert!(unknown.is_err());

    let oversized = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id,
             lease_expires_at, recovery_detail)
         VALUES ('bad-detail', 'schedule-b', 'exec-b', ?1, 'reserved',
                 'owner', ?2, ?3)",
    )
    .bind(Utc::now().to_rfc3339())
    .bind((Utc::now() + Duration::seconds(60)).to_rfc3339())
    .bind("x".repeat(4_097))
    .execute(store.pool())
    .await;
    assert!(oversized.is_err());
}

#[tokio::test]
async fn occurrence_constraints_reject_invalid_lease_shape() {
    let (store, _dir) = temp_store().await;
    let reserved_without_lease = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
         VALUES ('missing-lease', 'schedule-a', 'exec-a', ?1, 'reserved', 'owner', NULL)",
    )
    .bind(Utc::now().to_rfc3339())
    .execute(store.pool())
    .await;
    assert!(reserved_without_lease.is_err());

    let terminal_with_lease = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
         VALUES ('terminal-lease', 'schedule-b', 'exec-b', ?1, 'completed', 'owner', ?2)",
    )
    .bind(Utc::now().to_rfc3339())
    .bind((Utc::now() + Duration::seconds(60)).to_rfc3339())
    .execute(store.pool())
    .await;
    assert!(terminal_with_lease.is_err());
}

#[tokio::test]
async fn occurrence_inspection_preserves_safe_identity_for_malformed_rows() {
    let (store, _dir) = temp_store().await;
    sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id, lease_expires_at)
         VALUES
            ('occ-identifiable', 'schedule-identifiable', x'ff',
             '2026-07-30T00:00:00Z', 'completed', 'owner', NULL),
            ('occ-undecodable', CAST(x'ff' AS TEXT), 'exec-undecodable',
             '2026-07-30T00:00:01Z', 'completed', 'owner', NULL)",
    )
    .execute(store.pool())
    .await
    .unwrap();

    let inspected = store.inspect_schedule_occurrences().await.unwrap();
    assert_eq!(
        inspected,
        [
            ScheduleOccurrenceInspection::Malformed {
                schedule_id: Some("schedule-identifiable".to_owned()),
            },
            ScheduleOccurrenceInspection::Malformed { schedule_id: None },
        ]
    );
}

#[tokio::test]
async fn transition_updates_receipt_and_execution_in_one_transaction() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let result = store
        .transition_schedule_occurrence(&transition(&new, "reserved", "running", "running"))
        .await
        .unwrap();
    assert!(matches!(
        result,
        ScheduleOccurrenceTransitionResult::Applied(_)
    ));
    let states: (String, String) = sqlx::query_as(
        "SELECT o.state, e.status
         FROM schedule_occurrences o
         JOIN schedule_executions e ON e.id = o.execution_id
         WHERE o.id = 'occ-1'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(states, ("running".to_owned(), "running".to_owned()));
}

#[tokio::test]
async fn invalid_transition_changes_neither_row() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let result = store
        .transition_schedule_occurrence(&transition(&new, "reserved", "completed", "completed"))
        .await
        .unwrap();
    assert!(matches!(
        result,
        ScheduleOccurrenceTransitionResult::Conflict(_)
    ));
    let states: (String, String) = sqlx::query_as(
        "SELECT o.state, e.status
         FROM schedule_occurrences o
         JOIN schedule_executions e ON e.id = o.execution_id
         WHERE o.id = 'occ-1'",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(states, ("reserved".to_owned(), "pending".to_owned()));
}

#[tokio::test]
async fn exact_terminal_repeat_is_idempotent_but_different_terminal_is_a_conflict() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    store
        .transition_schedule_occurrence(&transition(&new, "reserved", "running", "running"))
        .await
        .unwrap();
    let completed = transition(&new, "running", "completed", "completed");
    store
        .transition_schedule_occurrence(&completed)
        .await
        .unwrap();
    assert!(matches!(
        store
            .transition_schedule_occurrence(&completed)
            .await
            .unwrap(),
        ScheduleOccurrenceTransitionResult::Idempotent(_)
    ));
    assert!(matches!(
        store
            .transition_schedule_occurrence(&transition(&new, "running", "failed", "failed"))
            .await
            .unwrap(),
        ScheduleOccurrenceTransitionResult::Conflict(_)
    ));
}

#[tokio::test]
async fn exact_terminal_repeat_is_receipt_idempotent_after_history_clear() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-cleared", "schedule-cleared", "exec-cleared");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    store
        .transition_schedule_occurrence(&transition(&new, "reserved", "running", "running"))
        .await
        .unwrap();
    let completed = transition(&new, "running", "completed", "completed");
    store
        .transition_schedule_occurrence(&completed)
        .await
        .unwrap();
    assert_eq!(store.clear_schedule_executions().await.unwrap(), 1);

    let replay = store
        .transition_schedule_occurrence(&completed)
        .await
        .unwrap();
    let ScheduleOccurrenceTransitionResult::Idempotent(receipt) = replay else {
        panic!("exact terminal receipt replay must remain idempotent");
    };
    assert_eq!(receipt.execution_status, None);
    assert_eq!(receipt.execution_data_json, None);
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-cleared'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0,
        "receipt-only replay must not recreate cleared execution history"
    );
}

#[tokio::test]
async fn terminal_receipt_replay_after_history_clear_rejects_every_metadata_mismatch() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-cleared", "schedule-cleared", "exec-cleared");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    store
        .transition_schedule_occurrence(&transition(&new, "reserved", "running", "running"))
        .await
        .unwrap();
    let completed = transition(&new, "running", "completed", "completed");
    store
        .transition_schedule_occurrence(&completed)
        .await
        .unwrap();
    store.clear_schedule_executions().await.unwrap();

    let mut schedule_mismatch = completed.clone();
    schedule_mismatch.schedule_id = "other-schedule".to_owned();
    let mut execution_mismatch = completed.clone();
    execution_mismatch.execution_id = "other-execution".to_owned();
    let mut owner_mismatch = completed.clone();
    owner_mismatch.owner_id = "other-owner".to_owned();
    let mut detail_mismatch = completed.clone();
    detail_mismatch.recovery_detail = Some("different detail".to_owned());
    let mut destination_mismatch = completed.clone();
    destination_mismatch.to_state = "failed".to_owned();
    destination_mismatch.execution_status = "failed".to_owned();

    for (field, mismatch) in [
        ("schedule", schedule_mismatch),
        ("execution", execution_mismatch),
        ("owner", owner_mismatch),
        ("detail", detail_mismatch),
        ("destination", destination_mismatch),
    ] {
        assert!(
            matches!(
                store
                    .transition_schedule_occurrence(&mismatch)
                    .await
                    .unwrap(),
                ScheduleOccurrenceTransitionResult::Conflict(_)
            ),
            "{field} mismatch must not be receipt-idempotent"
        );
    }

    let mut occurrence_mismatch = completed.clone();
    occurrence_mismatch.occurrence_id = "other-occurrence".to_owned();
    assert!(matches!(
        store
            .transition_schedule_occurrence(&occurrence_mismatch)
            .await
            .unwrap(),
        ScheduleOccurrenceTransitionResult::Missing
    ));

    let mut lease_mismatch = completed;
    lease_mismatch.lease_expires_at = Some((Utc::now() + Duration::seconds(60)).to_rfc3339());
    assert!(matches!(
        store.transition_schedule_occurrence(&lease_mismatch).await,
        Err(StorageError::InvalidData(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-cleared'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn acknowledgement_cannot_overtake_an_unexpired_lease() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let result = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &Utc::now().to_rfc3339(),
            "operator acknowledgement",
            "cancelled",
            &execution_json(
                &new.execution_id,
                &new.schedule_id,
                &new.triggered_at,
                "cancelled",
            ),
        )
        .await
        .unwrap();
    assert!(matches!(
        result,
        ScheduleOccurrenceAcknowledgement::Conflict(_)
    ));
}

#[tokio::test]
async fn lease_renewal_requires_the_current_owner() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let original = store
        .schedule_occurrence(&new.id)
        .await
        .unwrap()
        .unwrap()
        .lease_expires_at;
    assert!(!store
        .renew_schedule_occurrence_lease(
            &new.id,
            "different-owner",
            &(Utc::now() + Duration::seconds(120)).to_rfc3339(),
        )
        .await
        .unwrap());
    assert_eq!(
        store
            .schedule_occurrence(&new.id)
            .await
            .unwrap()
            .unwrap()
            .lease_expires_at,
        original
    );
}

#[tokio::test]
async fn acknowledgement_is_idempotent_after_expiry() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence("occ-1", "schedule-1", "exec-1");
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let now = Utc::now().to_rfc3339();
    assert!(store
        .release_schedule_occurrence_lease(&new.id, &new.owner_id, &now, "released for recovery",)
        .await
        .unwrap());
    let cancelled = execution_json(
        &new.execution_id,
        &new.schedule_id,
        &new.triggered_at,
        "cancelled",
    );
    let first = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &now,
            "operator acknowledgement",
            "cancelled",
            &cancelled,
        )
        .await
        .unwrap();
    let second = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &now,
            "operator acknowledgement",
            "cancelled",
            &cancelled,
        )
        .await
        .unwrap();
    assert!(matches!(
        first,
        ScheduleOccurrenceAcknowledgement::Acknowledged(_)
    ));
    assert!(matches!(
        second,
        ScheduleOccurrenceAcknowledgement::AlreadyCancelled(_)
    ));
}

#[tokio::test]
async fn concurrent_reservations_have_one_winner() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("race.db");
    let first = Store::connect(&path).await.unwrap();
    let second = Store::connect(&path).await.unwrap();
    let candidate_a = new_occurrence("occ-a", "schedule-1", "exec-a");
    let candidate_b = new_occurrence("occ-b", "schedule-1", "exec-b");
    let (a, b) = tokio::join!(
        first.reserve_schedule_occurrence(&candidate_a),
        second.reserve_schedule_occurrence(&candidate_b),
    );
    let results = [a.unwrap(), b.unwrap()];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ScheduleOccurrenceReservation::Reserved(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ScheduleOccurrenceReservation::Existing(_)))
            .count(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_occurrences WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(first.pool())
        .await
        .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE schedule_id = 'schedule-1'",
        )
        .fetch_one(first.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn execution_insert_failure_rolls_back_receipt() {
    let (store, _dir) = temp_store().await;
    store
        .upsert_schedule_execution(
            "exec-conflict",
            "other-schedule",
            &Utc::now().to_rfc3339(),
            "completed",
            "{}",
        )
        .await
        .unwrap();
    let new = new_occurrence("occ-rollback", "schedule-1", "exec-conflict");
    assert!(store.reserve_schedule_occurrence(&new).await.is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_occurrences WHERE id = 'occ-rollback'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn receipt_insert_failure_never_creates_an_execution() {
    let (store, _dir) = temp_store().await;
    store
        .reserve_schedule_occurrence(&new_occurrence("occ-conflict", "schedule-a", "exec-a"))
        .await
        .unwrap();
    let conflicting = new_occurrence("occ-conflict", "schedule-b", "exec-b");
    assert!(store
        .reserve_schedule_occurrence(&conflicting)
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-b'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn transition_execution_update_failure_rolls_back_receipt() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence(
        "occ-transition-rollback",
        "schedule-rollback",
        "exec-rollback",
    );
    store.reserve_schedule_occurrence(&new).await.unwrap();
    sqlx::query("DELETE FROM schedule_executions WHERE id = ?1")
        .bind(&new.execution_id)
        .execute(store.pool())
        .await
        .unwrap();

    let result = store
        .transition_schedule_occurrence(&transition(&new, "reserved", "running", "running"))
        .await;
    assert!(matches!(result, Err(StorageError::InvalidData(_))));
    let receipt = store.schedule_occurrence(&new.id).await.unwrap().unwrap();
    assert_eq!(receipt.state, "reserved");
    assert_eq!(receipt.lease_expires_at, Some(new.lease_expires_at));
}

#[tokio::test]
async fn acknowledgement_execution_update_failure_rolls_back_receipt() {
    let (store, _dir) = temp_store().await;
    let new = new_occurrence(
        "occ-ack-rollback",
        "schedule-ack-rollback",
        "exec-ack-rollback",
    );
    store.reserve_schedule_occurrence(&new).await.unwrap();
    let acknowledged_at = Utc::now().to_rfc3339();
    store
        .release_schedule_occurrence_lease(&new.id, &new.owner_id, &acknowledged_at, "released")
        .await
        .unwrap();
    sqlx::query("DELETE FROM schedule_executions WHERE id = ?1")
        .bind(&new.execution_id)
        .execute(store.pool())
        .await
        .unwrap();

    let result = store
        .acknowledge_schedule_occurrence(
            &new.id,
            &acknowledged_at,
            "acknowledged",
            "cancelled",
            "{}",
        )
        .await;
    assert!(matches!(result, Err(StorageError::InvalidData(_))));
    let receipt = store.schedule_occurrence(&new.id).await.unwrap().unwrap();
    assert_eq!(receipt.state, "reserved");
    assert_eq!(receipt.lease_expires_at, Some(acknowledged_at));
}

#[tokio::test]
async fn occurrence_mutations_enforce_utf8_recovery_detail_byte_limit() {
    let (store, _dir) = temp_store().await;
    let boundary = "é".repeat(2_048);
    let oversized = "é".repeat(2_049);
    let releasable = new_occurrence(
        "occ-release-bound",
        "schedule-release-bound",
        "exec-release",
    );
    store
        .reserve_schedule_occurrence(&releasable)
        .await
        .unwrap();
    let released_at = Utc::now().to_rfc3339();
    assert!(store
        .release_schedule_occurrence_lease(
            &releasable.id,
            &releasable.owner_id,
            &released_at,
            &boundary,
        )
        .await
        .unwrap());
    assert!(matches!(
        store
            .release_schedule_occurrence_lease(
                &releasable.id,
                &releasable.owner_id,
                &released_at,
                &oversized,
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));
    assert!(matches!(
        store
            .acknowledge_schedule_occurrence(
                &releasable.id,
                &released_at,
                &oversized,
                "cancelled",
                "{}",
            )
            .await,
        Err(StorageError::InvalidData(_))
    ));

    let running = new_occurrence(
        "occ-transition-bound",
        "schedule-transition-bound",
        "exec-transition",
    );
    store.reserve_schedule_occurrence(&running).await.unwrap();
    store
        .transition_schedule_occurrence(&transition(&running, "reserved", "running", "running"))
        .await
        .unwrap();
    let mut oversized_transition = transition(&running, "running", "failed", "failed");
    oversized_transition.recovery_detail = Some(oversized);
    assert!(matches!(
        store
            .transition_schedule_occurrence(&oversized_transition)
            .await,
        Err(StorageError::InvalidData(_))
    ));
}

#[tokio::test]
async fn history_deletion_preserves_non_terminal_receipt_executions_and_all_receipts() {
    let (store, _dir) = temp_store().await;
    let protected = new_occurrence("occ-live", "schedule-live", "exec-live");
    store.reserve_schedule_occurrence(&protected).await.unwrap();
    sqlx::query(
        "UPDATE schedule_executions
         SET status = 'completed', triggered_at = '2020-01-01T00:00:00Z'
         WHERE id = 'exec-live'",
    )
    .execute(store.pool())
    .await
    .unwrap();
    store
        .upsert_schedule_execution(
            "old-history",
            "schedule-live",
            "2020-01-01T00:00:00Z",
            "completed",
            "{}",
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .prune_schedule_executions("schedule-live", 0)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-live'",
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );

    let terminal = new_occurrence("occ-done", "schedule-done", "exec-done");
    store.reserve_schedule_occurrence(&terminal).await.unwrap();
    store
        .transition_schedule_occurrence(&transition(&terminal, "reserved", "running", "running"))
        .await
        .unwrap();
    store
        .transition_schedule_occurrence(&transition(&terminal, "running", "completed", "completed"))
        .await
        .unwrap();

    assert_eq!(store.clear_schedule_executions().await.unwrap(), 1);
    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT id FROM schedule_executions ORDER BY id")
            .fetch_all(store.pool())
            .await
            .unwrap();
    assert_eq!(remaining, ["exec-live"]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM schedule_occurrences")
            .fetch_one(store.pool())
            .await
            .unwrap(),
        2
    );
    let receipts = store.list_schedule_occurrences().await.unwrap();
    assert_eq!(receipts.len(), 2);
    let terminal_receipt = receipts
        .iter()
        .find(|receipt| receipt.id == "occ-done")
        .unwrap();
    assert_eq!(terminal_receipt.state, "completed");
    assert_eq!(terminal_receipt.execution_status, None);
    assert_eq!(terminal_receipt.execution_data_json, None);
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

    let first = cp("cp-1", 1);
    let second = cp("cp-2", 2);

    // Persist two checkpoints, then drop the store (simulating app exit).
    {
        let store = Store::connect(&path).await.expect("connect");
        let cps = SqliteChatCheckpointStore::new(store.pool().clone());
        cps.save(&first).await.unwrap();
        cps.save(&second).await.unwrap();
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
    assert_eq!(
        loaded, first,
        "round trip must preserve every field, including created_at precision"
    );

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
    // decided_at is stored at microsecond precision; nanosecond clock
    // resolution (Linux) must not make the round-trip comparison lossy.
    let base = Utc::now().trunc_subsecs(6);
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

#[tokio::test]
async fn promoted_harnesses_for_project_returns_only_that_projects_promotions() {
    let (store, _dir) = temp_store().await;
    let now = Utc::now();
    let mut first = sample_target("/projects/alpha");
    first.symbol = "parse_header".to_owned();
    let mut second = sample_target("/projects/alpha");
    second.symbol = "parse_body".to_owned();
    let mut other = sample_target("/projects/beta");
    other.symbol = "parse_other".to_owned();
    store.upsert_target(&first, now).await.unwrap();
    store.upsert_target(&second, now).await.unwrap();
    store.upsert_target(&other, now).await.unwrap();

    let mut promoted = sample_harness(first.id);
    promoted.status = HarnessStatus::Promoted;
    let still_draft = sample_harness(second.id);
    let mut promoted_elsewhere = sample_harness(other.id);
    promoted_elsewhere.status = HarnessStatus::Promoted;
    store.upsert_harness(&promoted).await.unwrap();
    store.upsert_harness(&still_draft).await.unwrap();
    store.upsert_harness(&promoted_elsewhere).await.unwrap();

    let rows = store
        .promoted_harnesses_for_project(std::path::Path::new("/projects/alpha"))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].harness.id, promoted.id);
    assert_eq!(rows[0].target_symbol, "parse_header");
}

#[tokio::test]
async fn promoted_harnesses_for_project_orders_newest_first() {
    let (store, _dir) = temp_store().await;
    let now = Utc::now();
    let mut first = sample_target("/projects/alpha");
    first.symbol = "parse_header".to_owned();
    let mut second = sample_target("/projects/alpha");
    second.symbol = "parse_body".to_owned();
    store.upsert_target(&first, now).await.unwrap();
    store.upsert_target(&second, now).await.unwrap();

    let mut older = sample_harness(first.id);
    older.status = HarnessStatus::Promoted;
    let mut newer = sample_harness(second.id);
    newer.status = HarnessStatus::Promoted;
    store.upsert_harness(&older).await.unwrap();
    store.upsert_harness(&newer).await.unwrap();

    let rows = store
        .promoted_harnesses_for_project(std::path::Path::new("/projects/alpha"))
        .await
        .unwrap();
    let ids: Vec<uuid::Uuid> = rows.iter().map(|row| row.harness.id).collect();
    assert_eq!(ids, vec![newer.id, older.id]);
}

fn telemetry(run_id: Uuid, observed_at: chrono::DateTime<Utc>) -> RunTelemetryRecord {
    RunTelemetryRecord {
        run_id,
        observed_at,
        last_progress_at: None,
        samples_json: "[]".to_owned(),
        current_execs: None,
        mean_execs: None,
        peak_execs: None,
        edges: None,
        throughput_sample_count: 0,
        throughput_sample_sum: 0.0,
        managed_invocations_expected: 0,
        managed_invocations_alive: 0,
        free_disk_bytes: None,
    }
}

fn health_event(
    run_id: Uuid,
    dedup_key: &str,
    observed_at: chrono::DateTime<Utc>,
) -> CampaignHealthEventRecord {
    health_event_for_condition(run_id, dedup_key, "coverage_plateau", observed_at)
}

fn health_event_for_condition(
    run_id: Uuid,
    dedup_key: &str,
    condition: &str,
    observed_at: chrono::DateTime<Utc>,
) -> CampaignHealthEventRecord {
    CampaignHealthEventRecord {
        schema_version: 2,
        id: Uuid::new_v4(),
        run_id,
        dedup_key: dedup_key.to_owned(),
        condition: condition.to_owned(),
        severity: "warning".to_owned(),
        detail: "coverage remained flat while execution continued".to_owned(),
        evidence_json: serde_json::json!({
            "schema_version": 2,
            "run_id": run_id,
            "condition": condition,
            "observed_at": observed_at,
            "run_status": "pending",
            "plateau_window": 3,
            "stale_progress_secs": 180,
            "disk_floor_bytes": 3_221_225_472_u64,
            "coverage_samples": [{"elapsed_secs": 0.0, "edges": 7, "execs": 50.0}],
            "last_progress_at": null,
            "progress_stale_secs": null,
            "current_execs": 50.0,
            "mean_execs": 50.0,
            "peak_execs": 50.0,
            "throughput_sample_count": 1,
            "throughput_sample_sum": 50.0,
            "managed_invocations_expected": 0,
            "managed_invocations_alive": 0,
            "free_disk_bytes": null
        })
        .to_string(),
        observed_at,
    }
}

#[tokio::test]
async fn campaign_health_migration_and_nullable_telemetry_round_trip() {
    let (store, _dir) = temp_store().await;
    let applied: i64 =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE version = 30")
            .fetch_one(store.pool())
            .await
            .expect("campaign-health migration receipt");
    assert_eq!(applied, 30);

    let run = RunRecord::new("/projects/health", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    let mut record = telemetry(run.id, Utc::now().trunc_subsecs(0));
    record.samples_json = r#"[{"elapsed_secs":0.0,"edges":7,"execs":50.0}]"#.to_owned();
    record.current_execs = Some(50.0);
    record.mean_execs = Some(50.0);
    record.peak_execs = Some(50.0);
    record.edges = Some(7);
    record.throughput_sample_count = 1;
    record.throughput_sample_sum = 50.0;

    store.upsert_run_telemetry(&record).await.unwrap();

    assert_eq!(store.run_telemetry(run.id).await.unwrap(), Some(record));
}

#[tokio::test]
async fn campaign_health_telemetry_rejects_delayed_snapshot_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("health-order.db");
    let first = Store::connect(&path).await.unwrap();
    let second = Store::connect(&path).await.unwrap();
    let run = RunRecord::new("/projects/health", EngineKind::LibFuzzer, None, Utc::now());
    first.insert_run(&run).await.unwrap();
    let mut newer = telemetry(run.id, Utc::now().trunc_subsecs(0));
    newer.current_execs = Some(40.0);
    newer.mean_execs = Some(30.0);
    newer.peak_execs = Some(40.0);
    newer.throughput_sample_count = 2;
    newer.throughput_sample_sum = 60.0;
    let mut older = telemetry(run.id, newer.observed_at - Duration::seconds(1));
    older.current_execs = Some(10.0);
    older.mean_execs = Some(10.0);
    older.peak_execs = Some(10.0);
    older.throughput_sample_count = 1;
    older.throughput_sample_sum = 10.0;

    assert!(first.upsert_run_telemetry(&newer).await.unwrap());
    assert!(!second.upsert_run_telemetry(&older).await.unwrap());

    assert_eq!(first.run_telemetry(run.id).await.unwrap(), Some(newer));
}

#[tokio::test]
async fn campaign_health_event_admission_is_atomic_and_survives_reconnect() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("health.db");
    let first = Store::connect(&path).await.unwrap();
    let second = Store::connect(&path).await.unwrap();
    let run = RunRecord::new("/projects/health", EngineKind::LibFuzzer, None, Utc::now());
    first.insert_run(&run).await.unwrap();
    let event = health_event(run.id, "run:plateau:7:3", Utc::now().trunc_subsecs(0));
    let competing = CampaignHealthEventRecord {
        id: Uuid::new_v4(),
        ..event.clone()
    };

    let (left, right) = tokio::join!(
        first.insert_campaign_health_event(&event),
        second.insert_campaign_health_event(&competing),
    );
    assert_eq!(
        [left.unwrap(), right.unwrap()]
            .into_iter()
            .filter(|inserted| *inserted)
            .count(),
        1
    );
    drop(first);
    drop(second);

    let reopened = Store::connect(&path).await.unwrap();
    let events = reopened
        .list_campaign_health_events(Some(run.id), 20)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].dedup_key, event.dedup_key);
}

#[tokio::test]
async fn campaign_health_event_deduplication_is_scoped_by_run_and_condition() {
    let (store, _dir) = temp_store().await;
    let first_run = RunRecord::new("/projects/a", EngineKind::LibFuzzer, None, Utc::now());
    let second_run = RunRecord::new("/projects/b", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&first_run).await.unwrap();
    store.insert_run(&second_run).await.unwrap();
    let observed_at = Utc::now().trunc_subsecs(0);

    let first = health_event(first_run.id, "same-state", observed_at);
    assert!(store.insert_campaign_health_event(&first).await.unwrap());
    let repeat = CampaignHealthEventRecord {
        id: Uuid::new_v4(),
        ..first.clone()
    };
    assert!(!store.insert_campaign_health_event(&repeat).await.unwrap());

    let other_run = health_event(second_run.id, "same-state", observed_at);
    assert!(store
        .insert_campaign_health_event(&other_run)
        .await
        .unwrap());
    let other_condition = health_event_for_condition(
        first_run.id,
        "same-state",
        "worker_stats_stale",
        observed_at,
    );
    assert!(store
        .insert_campaign_health_event(&other_condition)
        .await
        .unwrap());
}

#[tokio::test]
async fn campaign_health_event_pages_recover_older_events_and_reject_foreign_cursors() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/projects/health", EngineKind::LibFuzzer, None, Utc::now());
    let other = RunRecord::new("/projects/other", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();
    store.insert_run(&other).await.unwrap();
    let base = Utc::now().trunc_subsecs(0) - Duration::minutes(10);
    let plateau = health_event(run.id, "plateau:oldest", base);
    store.insert_campaign_health_event(&plateau).await.unwrap();
    for offset in 1..=101 {
        let event = health_event_for_condition(
            run.id,
            &format!("disk:{offset}"),
            "disk_pressure",
            base + Duration::seconds(offset),
        );
        store.insert_campaign_health_event(&event).await.unwrap();
    }
    let foreign = health_event(other.id, "foreign", base + Duration::minutes(20));
    store.insert_campaign_health_event(&foreign).await.unwrap();

    let first = store
        .campaign_health_event_page(run.id, None, 100)
        .await
        .unwrap();
    assert_eq!(first.events.len(), 100);
    let inserted_while_paging = health_event_for_condition(
        run.id,
        "newest:while-paging",
        "disk_pressure",
        base + chrono::Duration::seconds(1_000),
    );
    store
        .insert_campaign_health_event(&inserted_while_paging)
        .await
        .unwrap();
    let second = store
        .campaign_health_event_page(run.id, first.next_cursor, 100)
        .await
        .unwrap();
    assert_eq!(second.events.len(), 2);
    assert!(second.events.iter().any(|event| event.id == plateau.id));
    assert_eq!(second.next_cursor, None);
    assert!(!second
        .events
        .iter()
        .any(|event| event.id == inserted_while_paging.id));
    assert!(store
        .campaign_health_event_page(run.id, Some(foreign.id), 100)
        .await
        .is_err());
    assert!(store
        .campaign_health_event_page(run.id, None, 0)
        .await
        .is_err());
    assert!(store
        .campaign_health_event_page(run.id, None, 101)
        .await
        .is_err());
    assert_eq!(
        store
            .campaign_health_event_conditions(run.id)
            .await
            .unwrap(),
        vec!["coverage_plateau".to_owned(), "disk_pressure".to_owned()]
    );
}

#[tokio::test]
async fn campaign_health_schema_rejects_malformed_durable_evidence() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new("/projects/health", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&run).await.unwrap();

    assert!(sqlx::query(
        "INSERT INTO run_telemetry
            (run_id, observed_at, samples_json, throughput_sample_count,
             throughput_sample_sum, managed_invocations_expected,
             managed_invocations_alive)
         VALUES (?1, '2026-09-07T00:00:00Z', '{bad json', 0, 0.0, 0, 0)",
    )
    .bind(run.id.to_string())
    .execute(store.pool())
    .await
    .is_err());

    let event = health_event(run.id, "run:plateau:7:3", Utc::now());
    let mut invalid = event.clone();
    invalid.schema_version = 99;
    assert!(store.insert_campaign_health_event(&invalid).await.is_err());

    sqlx::query(
        "INSERT INTO run_telemetry
            (run_id, observed_at, samples_json, throughput_sample_count,
             throughput_sample_sum, managed_invocations_expected,
             managed_invocations_alive)
         VALUES (?1, '2026-09-07T00:00:00Z', '[null]', 0, 0.0, 0, 0)",
    )
    .bind(run.id.to_string())
    .execute(store.pool())
    .await
    .unwrap();
    assert!(store.run_telemetry(run.id).await.is_err());

    let second_run = RunRecord::new("/projects/other", EngineKind::LibFuzzer, None, Utc::now());
    store.insert_run(&second_run).await.unwrap();
    let mut empty_evidence = health_event(second_run.id, "empty-evidence", Utc::now());
    empty_evidence.evidence_json = "{}".to_owned();
    assert!(store
        .insert_campaign_health_event(&empty_evidence)
        .await
        .is_err());
}

#[tokio::test]
async fn health_event_pruning_preserves_active_runs_and_removes_old_terminal_events() {
    let (store, _dir) = temp_store().await;
    let old = Utc::now() - Duration::days(10);
    let active = RunRecord::new("/projects/active", EngineKind::LibFuzzer, None, old);
    let durable_pending_elsewhere = RunRecord::new(
        "/projects/active-in-another-process",
        EngineKind::LibFuzzer,
        None,
        old,
    );
    let mut terminal = RunRecord::new("/projects/terminal", EngineKind::LibFuzzer, None, old);
    terminal.status = RunStatus::Done;
    terminal.ended_at = Some(old);
    store.insert_run(&active).await.unwrap();
    let mut durable_running_elsewhere = RunRecord::new(
        "/projects/running-in-another-process",
        EngineKind::LibFuzzer,
        None,
        old,
    );
    durable_running_elsewhere.status = RunStatus::Running;
    store.insert_run(&durable_pending_elsewhere).await.unwrap();
    store.insert_run(&durable_running_elsewhere).await.unwrap();
    store.insert_run(&terminal).await.unwrap();
    store
        .insert_campaign_health_event(&health_event(active.id, "active:key", old))
        .await
        .unwrap();
    store
        .insert_campaign_health_event(&health_event(
            durable_pending_elsewhere.id,
            "durable-pending:key",
            old,
        ))
        .await
        .unwrap();
    store
        .insert_campaign_health_event(&health_event(
            durable_running_elsewhere.id,
            "durable-running:key",
            old,
        ))
        .await
        .unwrap();
    store
        .insert_campaign_health_event(&health_event(terminal.id, "terminal:key", old))
        .await
        .unwrap();

    assert_eq!(
        store
            .prune_campaign_health_events(Utc::now() - Duration::days(1), &[active.id])
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store
            .list_campaign_health_events(Some(active.id), 20)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .list_campaign_health_events(Some(durable_pending_elsewhere.id), 20)
            .await
            .unwrap()
            .len(),
        1,
        "a durable pending campaign may belong to another service process"
    );
    assert_eq!(
        store
            .list_campaign_health_events(Some(durable_running_elsewhere.id), 20)
            .await
            .unwrap()
            .len(),
        1,
        "a durable running campaign may belong to another service process"
    );
    assert!(store
        .list_campaign_health_events(Some(terminal.id), 20)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn deleting_a_run_removes_its_health_children_without_foreign_key_pragmas() {
    let (store, _dir) = temp_store().await;
    let run = RunRecord::new(
        "/projects/delete-health",
        EngineKind::LibFuzzer,
        None,
        Utc::now(),
    );
    store.insert_run(&run).await.unwrap();
    store
        .upsert_run_telemetry(&telemetry(run.id, Utc::now().trunc_subsecs(0)))
        .await
        .unwrap();
    store
        .insert_campaign_health_event(&health_event(run.id, "delete:key", Utc::now()))
        .await
        .unwrap();

    store.delete_run(&run.id.to_string()).await.unwrap();

    assert!(store.run_telemetry(run.id).await.unwrap().is_none());
    assert!(store
        .list_campaign_health_events(Some(run.id), 10)
        .await
        .unwrap()
        .is_empty());
}

fn build_profile(project: &str) -> hf_storage::ProjectBuildProfileRecord {
    hf_storage::ProjectBuildProfileRecord {
        project_root: project.into(),
        component_root: "components/parser".into(),
        build_system: hf_storage::ProfileBuildSystem::CMake,
        compile_database_path: "build/parser/compile_commands.json".into(),
        cmake_definitions: [("BUILD_TESTING".into(), "OFF".into())].into(),
        dependencies: vec![hf_storage::BuildDependency {
            kind: hf_storage::BuildDependencyKind::Command,
            name: "cmake".into(),
        }],
        sandbox_image_tag: "oxfuzz:latest".into(),
        sandbox_image_id: format!("sha256:{}", "a".repeat(64)),
        marker_path: "components/parser/CMakeLists.txt".into(),
        marker_sha256: "b".repeat(64),
        profile_sha256: "c".repeat(64),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn build_diagnosis(
    profile: &hf_storage::ProjectBuildProfileRecord,
) -> hf_storage::BuildDiagnosisRecord {
    hf_storage::BuildDiagnosisRecord {
        id: Uuid::new_v4(),
        project_root: profile.project_root.clone(),
        profile_sha256: Some(profile.profile_sha256.clone()),
        status: hf_storage::BuildDiagnosisStatus::Succeeded,
        diagnosis: hf_storage::BuildDiagnosisEvidence {
            schema_version: 1,
            operation: hf_storage::BuildDiagnosisOperation::Diagnose,
            profile: Some(profile.clone()),
            detected: vec![hf_storage::BuildSystemEvidence {
                build_system: hf_storage::DetectedBuildSystem::CMake,
                status: hf_storage::DetectedBuildStatus::Supported,
                markers: vec![profile.marker_path.clone()],
                missing_tool: None,
            }],
            profile_state: hf_storage::BuildProfileState::NeedsBuild,
            dependency_statuses: vec![hf_storage::BuildDependencyStatus {
                dependency: profile.dependencies[0].clone(),
                available: true,
            }],
            reasons: vec!["configured database is absent".into()],
            plan: Some(hf_storage::BuildPlanEvidence {
                steps: vec![hf_storage::BuildPlanStepEvidence {
                    argv: vec![
                        "cmake".into(),
                        "-S".into(),
                        ".".into(),
                        "-B".into(),
                        "../../build/parser".into(),
                    ],
                    working_dir: profile.component_root.clone(),
                    purpose: "configure parser".into(),
                }],
                component_root: profile.component_root.clone(),
                expected_artifact: profile.compile_database_path.clone(),
                profile_sha256: profile.profile_sha256.clone(),
                sandbox_image_tag: profile.sandbox_image_tag.clone(),
                sandbox_image_id: profile.sandbox_image_id.clone(),
            }),
            legacy_build_context_available: false,
            terminal: None,
        },
        created_at: Utc::now(),
    }
}

fn build_inputs(
    harness: &Harness,
    profile: &hf_storage::ProjectBuildProfileRecord,
) -> hf_storage::HarnessBuildInputsRecord {
    hf_storage::HarnessBuildInputsRecord {
        harness_id: harness.id,
        project_root: profile.project_root.clone(),
        profile_sha256: Some(profile.profile_sha256.clone()),
        compile_database_sha256: Some("d".repeat(64)),
        compile_flags_sha256: "e".repeat(64),
        sandbox_image_id: profile.sandbox_image_id.clone(),
        build_input_sha256: "f".repeat(64),
        created_at: Utc::now(),
    }
}

#[tokio::test]
async fn build_profile_upsert_preserves_creation_and_clear_retains_history() {
    let (store, _dir) = temp_store().await;
    assert!(store
        .project_build_profile("/proj")
        .await
        .unwrap()
        .is_none());
    let mut profile = build_profile("/proj");
    store.set_project_build_profile(&profile).await.unwrap();
    assert_eq!(
        store.project_build_profile("/proj").await.unwrap(),
        Some(profile.clone())
    );
    let diagnosis = build_diagnosis(&profile);
    store.append_build_diagnosis(&diagnosis).await.unwrap();
    store.set_project_build_profile(&profile).await.unwrap();
    let created = profile.created_at;
    profile.created_at += Duration::seconds(1);
    profile.updated_at += Duration::seconds(2);
    profile.profile_sha256 = "d".repeat(64);
    store.set_project_build_profile(&profile).await.unwrap();
    profile.created_at = created;
    assert_eq!(
        store.project_build_profile("/proj").await.unwrap(),
        Some(profile)
    );
    store.clear_project_build_profile("/proj").await.unwrap();
    assert!(store
        .project_build_profile("/proj")
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        store.build_diagnosis_history("/proj", 1).await.unwrap(),
        vec![diagnosis]
    );
}

#[tokio::test]
async fn build_profile_rejects_malformed_durable_configuration() {
    let (store, _dir) = temp_store().await;
    let profile = build_profile("/proj");
    for (column, value) in [
        ("cmake_definitions_json", "[]"),
        ("cmake_definitions_json", r#"{"bad_option":"ON"}"#),
        ("cmake_definitions_json", r#"{"BUILD_TESTING":"-bad"}"#),
        ("dependencies_json", r#"[{"kind":"shell","name":"make"}]"#),
        (
            "dependencies_json",
            r#"[{"kind":"command","name":"../make"}]"#,
        ),
        (
            "dependencies_json",
            r#"[{"kind":"command","name":"make","extra":true}]"#,
        ),
        (
            "dependencies_json",
            r#"[{"kind":"command","name":"z"},{"kind":"command","name":"a"}]"#,
        ),
        (
            "dependencies_json",
            r#"[{"kind":"command","name":"a"},{"kind":"command","name":"a"}]"#,
        ),
        ("profile_sha256", "BAD"),
        ("marker_sha256", "BAD"),
        ("sandbox_image_id", "mutable:tag"),
        ("created_at", "yesterday"),
        ("updated_at", "yesterday"),
        ("component_root", "./parser"),
        ("component_root", "../escape"),
        ("component_root", "/absolute"),
        ("component_root", "parser//nested"),
        ("component_root", "C:\\parser"),
        ("compile_database_path", "build/database.json"),
        ("marker_path", "a/../Makefile"),
    ] {
        store.clear_project_build_profile("/proj").await.unwrap();
        store.set_project_build_profile(&profile).await.unwrap();
        sqlx::query(&format!("UPDATE project_build_profiles SET {column} = ?1"))
            .bind(value)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            store.project_build_profile("/proj").await.is_err(),
            "accepted {column}: {value}"
        );
    }
}

#[tokio::test]
async fn build_diagnosis_history_is_bounded_ordered_and_immutable() {
    let (store, _dir) = temp_store().await;
    let mut first = build_diagnosis(&build_profile("/proj"));
    first.id = Uuid::from_u128(1);
    let mut second = first.clone();
    second.id = Uuid::from_u128(2);
    let mut newest = first.clone();
    newest.id = Uuid::from_u128(3);
    newest.created_at += Duration::seconds(1);
    for record in [&newest, &first, &second] {
        store.append_build_diagnosis(record).await.unwrap();
    }
    store.append_build_diagnosis(&first).await.unwrap();
    assert_eq!(
        store.build_diagnosis_history("/proj", 2).await.unwrap(),
        vec![newest, second]
    );
    assert!(store.build_diagnosis_history("/proj", 0).await.is_err());
    assert!(store.build_diagnosis_history("/proj", 101).await.is_err());
    assert!(store
        .build_diagnosis_history("/other", 100)
        .await
        .unwrap()
        .is_empty());
    first.diagnosis.reasons.push("different evidence".into());
    assert!(store.append_build_diagnosis(&first).await.is_err());
    let mut huge = first.clone();
    huge.id = Uuid::new_v4();
    huge.diagnosis.reasons = vec!["x".repeat(65_536)];
    assert!(store.append_build_diagnosis(&huge).await.is_err());
}

#[tokio::test]
async fn build_diagnosis_rejects_malformed_nested_durable_evidence() {
    let (store, _dir) = temp_store().await;
    // Simulate damaged durable data after bypassing the ordinary immutable-write guard.
    sqlx::query("DROP TRIGGER build_diagnosis_runs_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    let record = build_diagnosis(&build_profile("/proj"));
    store.append_build_diagnosis(&record).await.unwrap();
    let valid = serde_json::to_value(&record.diagnosis).unwrap();
    for (pointer, value) in [
        ("/schema_version", serde_json::json!(99)),
        ("/operation", serde_json::json!("invented")),
        ("/profile_state", serde_json::json!("invented")),
        ("/detected/0/build_system", serde_json::json!("invented")),
        (
            "/dependency_statuses/0/available",
            serde_json::json!("true"),
        ),
        ("/profile/profile_sha256", serde_json::json!("bad")),
        ("/plan/steps/0/working_dir", serde_json::json!("../escape")),
        ("/plan/sandbox_image_id", serde_json::json!("mutable:tag")),
        ("/plan/profile_sha256", serde_json::json!("a".repeat(64))),
    ] {
        let mut malformed = valid.clone();
        *malformed.pointer_mut(pointer).unwrap() = value;
        sqlx::query("UPDATE build_diagnosis_runs SET diagnosis_json = ?1")
            .bind(malformed.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            store.build_diagnosis_history("/proj", 1).await.is_err(),
            "accepted {pointer}"
        );
    }
    for malformed in ["{}".to_string(), {
        let mut value = valid.clone();
        value["plan"]["extra"] = serde_json::json!(true);
        value.to_string()
    }] {
        sqlx::query("UPDATE build_diagnosis_runs SET diagnosis_json = ?1")
            .bind(malformed)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(store.build_diagnosis_history("/proj", 1).await.is_err());
    }
}

#[tokio::test]
async fn build_inputs_atomic_retry_rolls_back_harness_changes_and_checks_ownership() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let profile = build_profile("/proj");
    let inputs = build_inputs(&harness, &profile);
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(inputs.clone())
    );
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    store.set_harness_build_inputs(&inputs).await.unwrap();
    let mut changed = inputs.clone();
    changed.created_at += Duration::seconds(1);
    let mut advanced = harness.clone();
    advanced.status = HarnessStatus::Compiled;
    assert!(store
        .upsert_harness_with_build_inputs(&advanced, &changed)
        .await
        .is_err());
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        harness.status
    );
    changed = inputs.clone();
    changed.compile_flags_sha256 = "a".repeat(64);
    assert!(store.set_harness_build_inputs(&changed).await.is_err());
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(inputs)
    );
    let other = sample_harness(target.id);
    let wrong_project = build_inputs(&other, &build_profile("/other"));
    assert!(store
        .upsert_harness_with_build_inputs(&other, &wrong_project)
        .await
        .is_err());
    assert!(store.get_harness(other.id).await.unwrap().is_none());
    let mut wrong_id = build_inputs(&other, &profile);
    wrong_id.harness_id = Uuid::new_v4();
    assert!(store
        .upsert_harness_with_build_inputs(&other, &wrong_id)
        .await
        .is_err());
    assert!(store.get_harness(other.id).await.unwrap().is_none());
    let missing_target = sample_harness(Uuid::new_v4());
    assert!(store
        .upsert_harness_with_build_inputs(&missing_target, &build_inputs(&missing_target, &profile))
        .await
        .is_err());
}

#[tokio::test]
async fn build_inputs_insert_failure_rolls_back_pair_and_legacy_null_roundtrips() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let mut inputs = build_inputs(&harness, &build_profile("/proj"));
    inputs.profile_sha256 = None;
    inputs.compile_database_sha256 = None;
    sqlx::query("CREATE TRIGGER reject_build_inputs BEFORE INSERT ON harness_build_inputs BEGIN SELECT RAISE(ABORT, 'reject inputs'); END")
        .execute(store.pool()).await.unwrap();
    assert!(store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .is_err());
    assert!(store.get_harness(harness.id).await.unwrap().is_none());
    sqlx::query("DROP TRIGGER reject_build_inputs")
        .execute(store.pool())
        .await
        .unwrap();
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(inputs)
    );
    // Simulate damaged durable data after bypassing the ordinary immutable-write guard.
    sqlx::query("DROP TRIGGER harness_build_inputs_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE harness_build_inputs SET compile_flags_sha256 = 'bad'")
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store.harness_build_inputs(harness.id).await.is_err());
}

#[tokio::test]
async fn build_profile_cleanup_preserves_configuration_and_other_projects() {
    let (store, _dir) = temp_store().await;
    let mut harness_ids = Vec::new();
    for project in ["/proj", "/other"] {
        let profile = build_profile(project);
        store.set_project_build_profile(&profile).await.unwrap();
        store
            .append_build_diagnosis(&build_diagnosis(&profile))
            .await
            .unwrap();
        let target = sample_target(project);
        store.upsert_target(&target, Utc::now()).await.unwrap();
        let harness = sample_harness(target.id);
        store
            .upsert_harness_with_build_inputs(&harness, &build_inputs(&harness, &profile))
            .await
            .unwrap();
        harness_ids.push(harness.id);
    }
    store.delete_project("/proj").await.unwrap();
    assert!(store
        .project_build_profile("/proj")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .build_diagnosis_history("/proj", 1)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .harness_build_inputs(harness_ids[0])
        .await
        .unwrap()
        .is_none());
    assert!(store
        .project_build_profile("/other")
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        store
            .build_diagnosis_history("/other", 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(store
        .harness_build_inputs(harness_ids[1])
        .await
        .unwrap()
        .is_some());
    store.clear_knowledge().await.unwrap();
    assert!(store
        .project_build_profile("/other")
        .await
        .unwrap()
        .is_some());
    assert!(store
        .build_diagnosis_history("/other", 1)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .harness_build_inputs(harness_ids[1])
        .await
        .unwrap()
        .is_none());
    store.delete_project("/other").await.unwrap();
    assert!(store
        .project_build_profile("/other")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn build_profile_guarded_promotion_rejects_stale_profile_and_input() {
    let (store, _dir) = temp_store().await;
    let profile = build_profile("/proj");
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.set_project_build_profile(&profile).await.unwrap();
    let mut harness = smoke_passed_harness(target.id);
    let inputs = build_inputs(&harness, &profile);
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    harness.status = HarnessStatus::Promoted;
    for (profile_hash, input_hash) in [
        ("a".repeat(64), inputs.build_input_sha256.clone()),
        (profile.profile_sha256.clone(), "a".repeat(64)),
    ] {
        let expected = hf_storage::ExpectedHarnessBuildIdentity {
            project_root: "/proj",
            profile_sha256: Some(&profile_hash),
            build_input_sha256: Some(&input_hash),
        };
        assert!(store
            .promote_harness_with_approval_and_build_identity(
                &harness,
                HarnessApprovalKind::CleanSmoke,
                &"a".repeat(64),
                &"b".repeat(64),
                Utc::now(),
                &expected
            )
            .await
            .is_err());
        assert_eq!(
            store.get_harness(harness.id).await.unwrap().unwrap().status,
            HarnessStatus::SmokePassed
        );
        assert!(store
            .harness_approval(harness.id, &"a".repeat(64), &"b".repeat(64))
            .await
            .unwrap()
            .is_none());
    }
    let expected = hf_storage::ExpectedHarnessBuildIdentity {
        project_root: "/proj",
        profile_sha256: Some(&profile.profile_sha256),
        build_input_sha256: Some(&inputs.build_input_sha256),
    };
    store
        .promote_harness_with_approval_and_build_identity(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
            &expected,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn build_inputs_writers_wait_before_reading_harness_revision() {
    let (store, dir) = temp_store().await;
    let other = Store::connect(dir.path().join("test.db")).await.unwrap();
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let mut harness = sample_harness(target.id);
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Compiled;
    let profile = build_profile("/proj");
    let inputs = build_inputs(&harness, &profile);
    for atomic in [false, true] {
        let writer = store.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
        let operation = async {
            if atomic {
                other
                    .upsert_harness_with_build_inputs(&harness, &inputs)
                    .await
            } else {
                other.upsert_harness(&harness).await
            }
        };
        tokio::pin!(operation);
        assert!(
            tokio::time::timeout(StdDuration::from_millis(100), &mut operation)
                .await
                .is_err(),
            "a competing writer must wait before reading, not fail upgrading a snapshot"
        );
        writer.commit().await.unwrap();
        operation.await.unwrap();
    }
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::Compiled
    );
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(inputs)
    );
}

#[tokio::test]
async fn build_profile_save_orders_before_guarded_promotion_on_another_connection() {
    let (store, dir) = temp_store().await;
    let other = Store::connect(dir.path().join("test.db")).await.unwrap();
    let profile = build_profile("/proj");
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    store.set_project_build_profile(&profile).await.unwrap();
    let mut harness = smoke_passed_harness(target.id);
    let inputs = build_inputs(&harness, &profile);
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    harness.status = HarnessStatus::Promoted;
    let expected = hf_storage::ExpectedHarnessBuildIdentity {
        project_root: "/proj",
        profile_sha256: Some(&profile.profile_sha256),
        build_input_sha256: Some(&inputs.build_input_sha256),
    };
    let mut writer = store.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
    sqlx::query(
        "UPDATE project_build_profiles SET profile_sha256 = ?1 WHERE project_root = '/proj'",
    )
    .bind("d".repeat(64))
    .execute(&mut *writer)
    .await
    .unwrap();
    let source = "a".repeat(64);
    let binary = "b".repeat(64);
    let operation = other.promote_harness_with_approval_and_build_identity(
        &harness,
        HarnessApprovalKind::CleanSmoke,
        &source,
        &binary,
        Utc::now(),
        &expected,
    );
    tokio::pin!(operation);
    assert!(
        tokio::time::timeout(StdDuration::from_millis(100), &mut operation)
            .await
            .is_err()
    );
    writer.commit().await.unwrap();
    assert!(matches!(operation.await, Err(StorageError::InvalidData(_))));
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::SmokePassed
    );
    assert!(store
        .harness_approval(harness.id, &source, &binary)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn build_evidence_sql_update_and_replace_cannot_rewrite_retained_rows() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let profile = build_profile("/proj");
    let inputs = build_inputs(&harness, &profile);
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    let diagnosis = build_diagnosis(&profile);
    store.append_build_diagnosis(&diagnosis).await.unwrap();
    for statement in [
        "UPDATE harness_build_inputs SET project_root = '/other'",
        "INSERT OR REPLACE INTO harness_build_inputs SELECT harness_id, '/other', profile_sha256, compile_database_sha256, compile_flags_sha256, sandbox_image_id, build_input_sha256, created_at FROM harness_build_inputs",
        "UPDATE build_diagnosis_runs SET project_root = '/other'",
        "INSERT OR REPLACE INTO build_diagnosis_runs SELECT id, '/other', profile_sha256, status, diagnosis_json, created_at FROM build_diagnosis_runs",
    ] {
        assert!(sqlx::query(statement).execute(store.pool()).await.is_err(), "accepted {statement}");
    }
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(inputs)
    );
    assert_eq!(
        store.build_diagnosis_history("/proj", 1).await.unwrap(),
        vec![diagnosis]
    );
    sqlx::query("DELETE FROM harnesses WHERE id = ?1")
        .bind(harness.id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store
        .harness_build_inputs(harness.id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn build_diagnosis_requires_complete_coherent_terminal_evidence() {
    let (store, _dir) = temp_store().await;
    let mut record = build_diagnosis(&build_profile("/proj"));
    record.diagnosis.operation = hf_storage::BuildDiagnosisOperation::Build;
    assert!(
        store.append_build_diagnosis(&record).await.is_err(),
        "build without terminal evidence"
    );
    record.diagnosis.terminal = Some(hf_storage::BuildTerminalEvidence {
        status: hf_storage::BuildTerminalStatus::Succeeded,
        step_index: Some(0),
        exit_code: Some(0),
        stdout: "configured".into(),
        stderr: String::new(),
        output_truncated: false,
        failure_code: None,
        failure_message: None,
    });
    store.append_build_diagnosis(&record).await.unwrap();
    let mut malformed = serde_json::to_value(&record.diagnosis).unwrap();
    malformed["terminal"]
        .as_object_mut()
        .unwrap()
        .remove("exit_code");
    assert!(
        serde_json::from_value::<hf_storage::BuildDiagnosisEvidence>(malformed).is_err(),
        "missing nullable field accepted"
    );
    record.id = Uuid::new_v4();
    record.status = hf_storage::BuildDiagnosisStatus::Failed;
    assert!(
        store.append_build_diagnosis(&record).await.is_err(),
        "terminal disagrees with row outcome"
    );
}

#[tokio::test]
async fn build_diagnosis_json_limit_counts_utf8_bytes_without_truncating_json() {
    let (store, _dir) = temp_store().await;
    let mut record = build_diagnosis(&build_profile("/proj"));
    record.diagnosis.reasons.clear();
    record.diagnosis.reasons.push(String::new());
    let overhead = serde_json::to_string(&record.diagnosis).unwrap().len();
    record.diagnosis.reasons[0] = "x".repeat(65_536 - overhead - 2) + "é";
    assert_eq!(
        serde_json::to_string(&record.diagnosis).unwrap().len(),
        65_536
    );
    store.append_build_diagnosis(&record).await.unwrap();
    assert_eq!(
        store.build_diagnosis_history("/proj", 1).await.unwrap(),
        vec![record.clone()]
    );
    record.id = Uuid::new_v4();
    record.diagnosis.reasons[0].push('x');
    assert!(store.append_build_diagnosis(&record).await.is_err());
    for invalid_json in [
        "not json".to_owned(),
        serde_json::to_string(&record.diagnosis).unwrap(),
    ] {
        assert!(sqlx::query("INSERT INTO build_diagnosis_runs VALUES (?1, '/proj', NULL, 'failed', ?2, '2026-09-08T00:00:00.000000000Z')")
            .bind(Uuid::new_v4().to_string()).bind(invalid_json).execute(store.pool()).await.is_err());
    }
}

#[tokio::test]
async fn build_profile_old_compile_capture_survives_save_but_cannot_promote() {
    let (store, _dir) = temp_store().await;
    let mut profile = build_profile("/proj");
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let mut harness = smoke_passed_harness(target.id);
    let captured = build_inputs(&harness, &profile);
    profile.profile_sha256 = "d".repeat(64);
    store.set_project_build_profile(&profile).await.unwrap();
    store
        .upsert_harness_with_build_inputs(&harness, &captured)
        .await
        .unwrap();
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(captured.clone())
    );
    harness.status = HarnessStatus::Promoted;
    let expected = hf_storage::ExpectedHarnessBuildIdentity {
        project_root: "/proj",
        profile_sha256: Some(&profile.profile_sha256),
        build_input_sha256: Some(&captured.build_input_sha256),
    };
    assert!(store
        .promote_harness_with_approval_and_build_identity(
            &harness,
            HarnessApprovalKind::CleanSmoke,
            &"a".repeat(64),
            &"b".repeat(64),
            Utc::now(),
            &expected
        )
        .await
        .is_err());
}

#[tokio::test]
async fn build_profile_cleanup_rolls_back_all_evidence_on_delete_failure() {
    let (store, _dir) = temp_store().await;
    let profile = build_profile("/proj");
    let diagnosis = build_diagnosis(&profile);
    store.set_project_build_profile(&profile).await.unwrap();
    store.append_build_diagnosis(&diagnosis).await.unwrap();
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let inputs = build_inputs(&harness, &profile);
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER reject_diagnosis_delete BEFORE DELETE ON build_diagnosis_runs BEGIN SELECT RAISE(ABORT, 'reject delete'); END")
        .execute(store.pool()).await.unwrap();
    for delete_project in [true, false] {
        let result = if delete_project {
            store.delete_project("/proj").await
        } else {
            store.clear_knowledge().await
        };
        assert!(result.is_err());
        assert_eq!(
            store.harness_build_inputs(harness.id).await.unwrap(),
            Some(inputs.clone())
        );
        assert!(store.get_harness(harness.id).await.unwrap().is_some());
        assert_eq!(
            store.project_build_profile("/proj").await.unwrap(),
            Some(profile.clone())
        );
        assert_eq!(
            store.build_diagnosis_history("/proj", 1).await.unwrap(),
            vec![diagnosis.clone()]
        );
    }
    sqlx::query("DROP TRIGGER reject_diagnosis_delete")
        .execute(store.pool())
        .await
        .unwrap();
    store.delete_project("/proj").await.unwrap();
    assert!(store
        .project_build_profile("/proj")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .build_diagnosis_history("/proj", 1)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn build_profile_roundtrips_canonical_project_roots_on_supported_platforms() {
    let (store, dir) = temp_store().await;
    let canonical = dir.path().canonicalize().unwrap();
    for project in [
        canonical.to_str().unwrap(),
        "/",
        "/projects/parser:v2",
        r"C:\projects\parser",
        r"C:\",
        r"\\?\C:\projects\parser",
        r"\\server\share\parser",
        r"\\?\UNC\server\share\parser",
    ] {
        let profile = build_profile(project);
        store.set_project_build_profile(&profile).await.unwrap();
        assert_eq!(
            store.project_build_profile(project).await.unwrap(),
            Some(profile),
            "{project}"
        );
    }
    for project in [
        "relative/project",
        "C:relative",
        r"C:\projects\..\other",
        r"C:\projects/../other",
        r"\\?\C:\projects\.\parser",
        r"\\server",
        r"\\?\UNC\server",
        r"UNC\server\share",
        "/projects/../other",
        "/projects//parser",
    ] {
        let profile = build_profile(project);
        assert!(
            store.set_project_build_profile(&profile).await.is_err(),
            "accepted {project}"
        );
    }
}

#[tokio::test]
async fn build_inputs_reject_every_changed_immutable_field_on_retry() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let inputs = build_inputs(&harness, &build_profile("/proj"));
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    let mut retries = Vec::new();
    let mut changed = inputs.clone();
    changed.project_root = "/other".into();
    retries.push(changed);
    let mut changed = inputs.clone();
    changed.profile_sha256 = None;
    retries.push(changed);
    let mut changed = inputs.clone();
    changed.compile_database_sha256 = Some("a".repeat(64));
    retries.push(changed);
    let mut changed = inputs.clone();
    changed.compile_flags_sha256 = "a".repeat(64);
    retries.push(changed);
    let mut changed = inputs.clone();
    changed.sandbox_image_id = format!("sha256:{}", "b".repeat(64));
    retries.push(changed);
    let mut changed = inputs.clone();
    changed.build_input_sha256 = "a".repeat(64);
    retries.push(changed);
    let mut changed = inputs.clone();
    changed.created_at += Duration::nanoseconds(1);
    retries.push(changed);
    for changed in retries {
        assert!(store.set_harness_build_inputs(&changed).await.is_err());
    }
    assert_eq!(
        store.harness_build_inputs(harness.id).await.unwrap(),
        Some(inputs)
    );
}

#[tokio::test]
async fn build_records_reject_corrupted_durable_digests_timestamps_enums_and_projects() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let profile = build_profile("/proj");
    let inputs = build_inputs(&harness, &profile);
    let diagnosis = build_diagnosis(&profile);
    store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .unwrap();
    store.append_build_diagnosis(&diagnosis).await.unwrap();
    // These fixtures bypass write guards to exercise decoding of damaged durable files.
    sqlx::query("DROP TRIGGER harness_build_inputs_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER build_diagnosis_runs_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    for (column, value) in [
        ("profile_sha256", "BAD"),
        ("compile_database_sha256", "BAD"),
        ("compile_flags_sha256", "BAD"),
        ("build_input_sha256", "BAD"),
        ("sandbox_image_id", "mutable:tag"),
        ("created_at", "yesterday"),
        ("project_root", "/other"),
    ] {
        let mut tx = store.pool().begin().await.unwrap();
        sqlx::query(&format!("UPDATE harness_build_inputs SET {column} = ?1"))
            .bind(value)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert!(
            store.harness_build_inputs(harness.id).await.is_err(),
            "accepted input {column}"
        );
        sqlx::query("DELETE FROM harness_build_inputs")
            .execute(store.pool())
            .await
            .unwrap();
        store.set_harness_build_inputs(&inputs).await.unwrap();
    }
    for (column, value) in [
        ("id", "not-a-uuid"),
        ("created_at", "yesterday"),
        ("profile_sha256", "BAD"),
        ("project_root", "relative"),
    ] {
        sqlx::query(&format!("UPDATE build_diagnosis_runs SET {column} = ?1"))
            .bind(value)
            .execute(store.pool())
            .await
            .unwrap();
        let project = if column == "project_root" {
            value
        } else {
            "/proj"
        };
        assert!(
            store.build_diagnosis_history(project, 1).await.is_err(),
            "accepted diagnosis {column}"
        );
        sqlx::query("DELETE FROM build_diagnosis_runs")
            .execute(store.pool())
            .await
            .unwrap();
        store.append_build_diagnosis(&diagnosis).await.unwrap();
    }
    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("UPDATE build_diagnosis_runs SET status = 'invented'")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = OFF")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    assert!(store.build_diagnosis_history("/proj", 1).await.is_err());
}

#[tokio::test]
async fn build_inputs_configured_capture_requires_database_evidence_in_sql_and_store() {
    let (store, _dir) = temp_store().await;
    let target = sample_target("/proj");
    store.upsert_target(&target, Utc::now()).await.unwrap();
    let harness = sample_harness(target.id);
    let mut inputs = build_inputs(&harness, &build_profile("/proj"));
    inputs.compile_database_sha256 = None;
    assert!(store
        .upsert_harness_with_build_inputs(&harness, &inputs)
        .await
        .is_err());
    assert!(store.get_harness(harness.id).await.unwrap().is_none());
    store.upsert_harness(&harness).await.unwrap();
    assert!(sqlx::query(
        "INSERT INTO harness_build_inputs VALUES (?1, '/proj', ?2, NULL, ?3, ?4, ?5, ?6)"
    )
    .bind(harness.id.to_string())
    .bind(&inputs.profile_sha256)
    .bind(&inputs.compile_flags_sha256)
    .bind(&inputs.sandbox_image_id)
    .bind(&inputs.build_input_sha256)
    .bind(inputs.created_at.to_rfc3339())
    .execute(store.pool())
    .await
    .is_err());
}

#[tokio::test]
async fn build_inputs_legacy_promotion_waits_for_an_existing_writer() {
    let (store, dir) = temp_store().await;
    let other = Store::connect(dir.path().join("test.db")).await.unwrap();
    let mut harness = smoke_passed_harness(Uuid::new_v4());
    store.upsert_harness(&harness).await.unwrap();
    harness.status = HarnessStatus::Promoted;
    let writer = store.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
    let source = "a".repeat(64);
    let binary = "b".repeat(64);
    let operation = other.promote_harness_with_approval(
        &harness,
        HarnessApprovalKind::CleanSmoke,
        &source,
        &binary,
        Utc::now(),
    );
    tokio::pin!(operation);
    assert!(
        tokio::time::timeout(StdDuration::from_millis(100), &mut operation)
            .await
            .is_err()
    );
    writer.commit().await.unwrap();
    operation.await.unwrap();
    assert_eq!(
        store.get_harness(harness.id).await.unwrap().unwrap().status,
        HarnessStatus::Promoted
    );
}

#[tokio::test]
async fn build_diagnosis_rejects_noncanonical_ordering_keys() {
    let (store, _dir) = temp_store().await;
    let diagnosis = build_diagnosis(&build_profile("/proj"));
    store.append_build_diagnosis(&diagnosis).await.unwrap();
    // Noncanonical external encodings must not silently change SQL history ordering.
    sqlx::query("DROP TRIGGER build_diagnosis_runs_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    for (column, value) in [
        ("created_at", "2026-09-08T00:00:00+08:00"),
        ("id", "urn:uuid:00000000-0000-0000-0000-000000000001"),
    ] {
        sqlx::query(&format!("UPDATE build_diagnosis_runs SET {column} = ?1"))
            .bind(value)
            .execute(store.pool())
            .await
            .unwrap();
        assert!(
            store.build_diagnosis_history("/proj", 100).await.is_err(),
            "accepted noncanonical {column}"
        );
        sqlx::query("DELETE FROM build_diagnosis_runs")
            .execute(store.pool())
            .await
            .unwrap();
        store.append_build_diagnosis(&diagnosis).await.unwrap();
    }
}

#[tokio::test]
async fn build_profile_update_cannot_predate_retained_creation() {
    let (store, _dir) = temp_store().await;
    let original = build_profile("/proj");
    store.set_project_build_profile(&original).await.unwrap();
    let mut replacement = original.clone();
    replacement.created_at = original.created_at - Duration::days(7);
    replacement.updated_at = original.created_at - Duration::days(6);
    replacement
        .cmake_definitions
        .insert("BUILD_TESTING".into(), "ON".into());
    replacement.profile_sha256 = "d".repeat(64);
    assert!(matches!(
        store.set_project_build_profile(&replacement).await,
        Err(StorageError::InvalidData(_))
    ));
    assert_eq!(
        store.project_build_profile("/proj").await.unwrap(),
        Some(original)
    );
}

#[tokio::test]
async fn build_profile_read_rejects_relative_unc_durable_project_root() {
    let (store, _dir) = temp_store().await;
    store
        .set_project_build_profile(&build_profile("/proj"))
        .await
        .unwrap();
    let relative = r"UNC\server\share";
    sqlx::query("UPDATE project_build_profiles SET project_root = ?1")
        .bind(relative)
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.project_build_profile(relative).await,
        Err(StorageError::InvalidData(_))
    ));
}

#[tokio::test]
async fn configured_harness_context_migration_retains_immutable_evidence_and_cleans_projects() {
    let (store, _dir) = temp_store().await;
    let id = Uuid::new_v4().to_string();
    let inserted=sqlx::query("INSERT INTO harness_build_contexts (id,project_root,profile_sha256,compile_database_sha256,context_json,created_at) VALUES (?1,'/project',?2,?2,'{\"schema_version\":1}', '2026-09-08T00:00:00.000000000Z')").bind(&id).bind("a".repeat(64)).execute(store.pool()).await;
    assert!(inserted.is_ok(), "{inserted:?}");
    assert!(
        sqlx::query("UPDATE harness_build_contexts SET context_json='{}' WHERE id=?1")
            .bind(&id)
            .execute(store.pool())
            .await
            .is_err()
    );
    store.delete_project("/project").await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM harness_build_contexts")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn configured_harness_context_roundtrip_retry_strict_decode_and_clear() {
    let (store, _dir) = temp_store().await;
    let record = hf_storage::HarnessBuildContextRecord {
        id: Uuid::new_v4(),
        project_root: "/project".into(),
        profile_sha256: "a".repeat(64),
        compile_database_sha256: "b".repeat(64),
        evidence: hf_storage::HarnessBuildContextEvidence {
            schema_version: 1,
            context: hf_core::build::BuildContext {
                defines: vec!["-DFOO=1".into()],
                entry_count: 1,
                ..Default::default()
            },
        },
        created_at: Utc::now(),
    };
    store.append_harness_build_context(&record).await.unwrap();
    store.append_harness_build_context(&record).await.unwrap();
    assert_eq!(
        store.harness_build_context(record.id).await.unwrap(),
        Some(record.clone())
    );
    let mut changed = record.clone();
    changed.evidence.context.defines.push("-DBAR=1".into());
    assert!(store.append_harness_build_context(&changed).await.is_err());
    changed.id = Uuid::new_v4();
    changed.evidence.context.defines = vec!["x".repeat(65536)];
    assert!(store.append_harness_build_context(&changed).await.is_err());
    sqlx::query("DROP TRIGGER harness_build_contexts_immutable")
        .execute(store.pool())
        .await
        .unwrap();
    let mut json = serde_json::to_value(&record.evidence).unwrap();
    json["context"]["unknown"] = true.into();
    sqlx::query("UPDATE harness_build_contexts SET context_json=?1 WHERE id=?2")
        .bind(json.to_string())
        .bind(record.id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store.harness_build_context(record.id).await.is_err());
    store.clear_knowledge().await.unwrap();
    assert!(store
        .harness_build_context(record.id)
        .await
        .unwrap()
        .is_none());
}
