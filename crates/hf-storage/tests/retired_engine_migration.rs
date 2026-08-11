use hf_storage::{StorageError, Store};

const OPERATION_ID: &str = "11111111-1111-4111-8111-111111111111";
const SECOND_OPERATION_ID: &str = "22222222-2222-4222-8222-222222222222";
const PLAN_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SECOND_PLAN_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

async fn pre_0024_pool(path: &std::path::Path) -> sqlx::SqlitePool {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true);
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .unwrap();
    let mut migrations = sqlx::migrate!();
    migrations
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 23);
    migrations.run(&pool).await.unwrap();
    pool
}

fn legacy_serde_engine_name() -> String {
    ["Cluster", "Fuzz", "Lite"].concat()
}

async fn insert_run(pool: &sqlx::SqlitePool, id: &str, engine: &str) {
    sqlx::query(
        r#"INSERT INTO runs
            (id, project_root, engine, status, started_at, ended_at, config_json,
             edges, execs, crash_count, samples_json, harness_rev, harness_source,
             binary_rev, evidence_dir, run_kind, context_rev, source_rev,
             corpus_rev, sandbox_rev)
         VALUES (?1, '/project', ?2, 'done', '2026-08-11T00:00:00Z',
                 '2026-08-11T00:01:00Z', NULL, 12, 34.5, 1, '[{"t":0}]',
                 'harness-rev', 'source', 'binary-rev', 'runs/evidence',
                 'campaign', 'context-rev', 'source-rev', 'corpus-rev',
                 'sandbox-rev')"#,
    )
    .bind(id)
    .bind(engine)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_legacy_graph(pool: &sqlx::SqlitePool) -> String {
    let retired = legacy_serde_engine_name();
    insert_run(pool, "run-cfl", &retired).await;
    insert_run(pool, "run-lib", "LibFuzzer").await;
    sqlx::query(
        r#"INSERT INTO harnesses
            (id, target_id, engine, source, status, smoke_run_json, data_json)
         VALUES
            ('harness-cfl', 'target-cfl', ?1, 'retired source', 'promoted',
             '{"ok":true}', '{"id":"harness-cfl","engine":"ClusterFuzzLite"}'),
            ('harness-lib', 'target-lib', 'LibFuzzer', 'active source', 'promoted',
             NULL, '{"id":"harness-lib","engine":"LibFuzzer"}')"#,
    )
    .bind(&retired)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO harness_approvals
            (id, harness_id, source_sha256, binary_sha256, approval_kind, approved_at)
         VALUES ('approval-cfl', 'harness-cfl', 'source-sha', 'binary-sha',
                 'clean_smoke', '2026-08-11T00:00:00Z')",
    )
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"INSERT INTO crashes
            (id, run_id, target_id, stack_signature, kind, summary, minimized,
             bug_report_json, data_json)
         VALUES ('crash-cfl', 'run-cfl', 'target-cfl', 'signature', 'Asan',
                 'summary', 1, '{"title":"report"}',
                 '{"id":"crash-cfl","run_id":"run-cfl"}')"#,
    )
    .execute(pool)
    .await
    .unwrap();
    let execution = serde_json::json!({
        "execution_id": "exec-cfl",
        "schedule_id": "schedule-cfl",
        "triggered_at": "2026-08-11T00:00:00Z",
        "started_at": null,
        "completed_at": null,
        "status": "pending",
        "workflow_execution_id": null,
        "request_summary": {
            "parameter_values": { "engine": retired }
        },
        "response_summary": {},
        "error_message": null
    })
    .to_string();
    sqlx::query(
        "INSERT INTO schedule_executions
            (id, schedule_id, triggered_at, status, data_json)
         VALUES ('exec-cfl', 'schedule-cfl', '2026-08-11T00:00:00Z',
                 'pending', ?1)",
    )
    .bind(execution)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id,
             lease_expires_at, recovery_detail, created_at, updated_at)
         VALUES ('occ-cfl', 'schedule-cfl', 'exec-cfl',
                 '2026-08-11T00:00:00Z', 'reserved', 'owner',
                 '2026-08-11T00:10:00Z', NULL,
                 '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z')",
    )
    .execute(pool)
    .await
    .unwrap();
    retired
}

async fn archive_rows(pool: &sqlx::SqlitePool) -> Vec<(String, String, String, String)> {
    sqlx::query_as(
        "SELECT record_kind, record_id, payload_json, archived_at
         FROM retired_engine_records ORDER BY record_kind, record_id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

const ASCII_TRIMMED_RETIRED_ID: &str = "\tCFL\n";
const UNICODE_TRIMMED_RETIRED_ID: &str = "\u{2003}CFLITE\u{3000}";

#[derive(Clone, Copy, Debug)]
enum RetiredRecordShape {
    RunColumn,
    RunJson,
    HarnessColumn,
    HarnessJson,
    ScheduleJson,
}

impl RetiredRecordShape {
    fn label(self) -> &'static str {
        match self {
            Self::RunColumn => "run-column",
            Self::RunJson => "run-json",
            Self::HarnessColumn => "harness-column",
            Self::HarnessJson => "harness-json",
            Self::ScheduleJson => "schedule-json",
        }
    }

    fn record_kind(self) -> &'static str {
        match self {
            Self::RunColumn | Self::RunJson => "run",
            Self::HarnessColumn | Self::HarnessJson => "harness",
            Self::ScheduleJson => "schedule_execution",
        }
    }
}

const RETIRED_RECORD_SHAPES: [RetiredRecordShape; 5] = [
    RetiredRecordShape::RunColumn,
    RetiredRecordShape::RunJson,
    RetiredRecordShape::HarnessColumn,
    RetiredRecordShape::HarnessJson,
    RetiredRecordShape::ScheduleJson,
];

async fn insert_retired_shape(
    pool: &sqlx::SqlitePool,
    shape: RetiredRecordShape,
    id: &str,
    engine: &str,
) {
    match shape {
        RetiredRecordShape::RunColumn => insert_run(pool, id, engine).await,
        RetiredRecordShape::RunJson => {
            insert_run(pool, id, "LibFuzzer").await;
            let config_json = serde_json::json!({ "engine": engine }).to_string();
            sqlx::query("UPDATE runs SET config_json = ?1 WHERE id = ?2")
                .bind(config_json)
                .bind(id)
                .execute(pool)
                .await
                .unwrap();
        }
        RetiredRecordShape::HarnessColumn | RetiredRecordShape::HarnessJson => {
            let column_engine = if matches!(shape, RetiredRecordShape::HarnessColumn) {
                engine
            } else {
                "LibFuzzer"
            };
            let json_engine = if matches!(shape, RetiredRecordShape::HarnessJson) {
                engine
            } else {
                "LibFuzzer"
            };
            let data_json = serde_json::json!({ "id": id, "engine": json_engine }).to_string();
            sqlx::query(
                "INSERT INTO harnesses
                    (id, target_id, engine, source, status, smoke_run_json, data_json)
                 VALUES (?1, ?2, ?3, 'source', 'draft', NULL, ?4)",
            )
            .bind(id)
            .bind(format!("target-{id}"))
            .bind(column_engine)
            .bind(data_json)
            .execute(pool)
            .await
            .unwrap();
        }
        RetiredRecordShape::ScheduleJson => {
            let schedule_id = format!("orphan-{id}");
            let data_json = serde_json::json!({
                "execution_id": id,
                "schedule_id": schedule_id,
                "triggered_at": "2026-08-11T00:00:00Z",
                "status": "pending",
                "request_summary": {
                    "parameter_values": { "engine": engine }
                }
            })
            .to_string();
            sqlx::query(
                "INSERT INTO schedule_executions
                    (id, schedule_id, triggered_at, status, data_json)
                 VALUES (?1, ?2, '2026-08-11T00:00:00Z', 'pending', ?3)",
            )
            .bind(id)
            .bind(&schedule_id)
            .bind(data_json)
            .execute(pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO schedule_occurrences
                    (id, schedule_id, execution_id, triggered_at, state, owner_id,
                     lease_expires_at, recovery_detail, created_at, updated_at)
                 VALUES (?1, ?2, ?3, '2026-08-11T00:00:00Z', 'reserved', 'owner',
                         '2026-08-11T00:10:00Z', NULL,
                         '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z')",
            )
            .bind(format!("occurrence-{id}"))
            .bind(schedule_id)
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn insert_schedule_history(
    pool: &sqlx::SqlitePool,
    execution_id: &str,
    occurrence_id: &str,
    schedule_id: &str,
    marker: &str,
) {
    let data_json = serde_json::json!({
        "execution_id": execution_id,
        "schedule_id": schedule_id,
        "triggered_at": "2026-08-11T00:00:00Z",
        "status": "pending",
        "request_summary": {
            "parameter_values": { "engine": "libfuzzer" }
        },
        "marker": marker
    })
    .to_string();
    sqlx::query(
        "INSERT INTO schedule_executions
            (id, schedule_id, triggered_at, status, data_json)
         VALUES (?1, ?2, '2026-08-11T00:00:00Z', 'pending', ?3)",
    )
    .bind(execution_id)
    .bind(schedule_id)
    .bind(data_json)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id,
             lease_expires_at, recovery_detail, created_at, updated_at)
         VALUES (?1, ?2, ?3, '2026-08-11T00:00:00Z', 'reserved', 'owner',
                 '2026-08-11T00:10:00Z', ?4,
                 '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z')",
    )
    .bind(occurrence_id)
    .bind(schedule_id)
    .bind(execution_id)
    .bind(marker)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_conflicting_archive(
    pool: &sqlx::SqlitePool,
    record_kind: &str,
    record_id: &str,
    payload: &serde_json::Value,
) {
    sqlx::query(
        "INSERT INTO retired_engine_records
            (record_kind, record_id, retired_engine, payload_json, migration_version)
         VALUES (?1, ?2, ?3, ?4, 24)",
    )
    .bind(record_kind)
    .bind(record_id)
    .bind(legacy_serde_engine_name().to_ascii_lowercase())
    .bind(payload.to_string())
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn migration_0024_archives_complete_retired_graph_without_relabelling() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("migration.db");
    let pool = pre_0024_pool(&path).await;
    let retired = seed_legacy_graph(&pool).await;
    sqlx::migrate!().run(&pool).await.unwrap();

    let rows = archive_rows(&pool).await;
    let identities = rows
        .iter()
        .map(|(kind, id, _, _)| (kind.as_str(), id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        identities,
        vec![
            ("crash", "crash-cfl"),
            ("harness", "harness-cfl"),
            ("harness_approval", "approval-cfl"),
            ("run", "run-cfl"),
            ("schedule_execution", "exec-cfl"),
            ("schedule_occurrence", "occ-cfl"),
        ],
    );
    let run_payload = rows
        .iter()
        .find(|(kind, _, _, _)| kind == "run")
        .map(|(_, _, payload, _)| serde_json::from_str::<serde_json::Value>(payload).unwrap())
        .unwrap();
    assert_eq!(run_payload["engine"], retired);
    assert_eq!(run_payload["source_rev"], "source-rev");
    assert_eq!(run_payload["corpus_rev"], "corpus-rev");
    assert_eq!(run_payload["sandbox_rev"], "sandbox-rev");

    for table in [
        "runs",
        "harnesses",
        "harness_approvals",
        "crashes",
        "schedule_executions",
        "schedule_occurrences",
    ] {
        let query = format!("SELECT COUNT(*) FROM {table} WHERE id LIKE '%-cfl'");
        let count: i64 = sqlx::query_scalar(&query).fetch_one(&pool).await.unwrap();
        assert_eq!(count, 0, "{table}");
    }
    let controls: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM runs WHERE id = 'run-lib') +
            (SELECT COUNT(*) FROM harnesses WHERE id = 'harness-lib')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(controls, 2);

    for statement in [
        "UPDATE retired_engine_records SET payload_json = '{}' WHERE record_kind = 'run'",
        "DELETE FROM retired_engine_records WHERE record_kind = 'run'",
    ] {
        let error = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("retired engine evidence is immutable"));
    }
    let preserved: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM retired_engine_records")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(preserved, 6);
}

#[tokio::test]
async fn migration_0024_is_idempotent_after_reconnect() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("idempotent.db");
    let pool = pre_0024_pool(&path).await;
    seed_legacy_graph(&pool).await;
    sqlx::migrate!().run(&pool).await.unwrap();
    let before = archive_rows(&pool).await;
    pool.close().await;

    let store = Store::connect(&path).await.unwrap();
    let after = archive_rows(store.pool()).await;
    assert_eq!(after, before);
}

#[tokio::test]
async fn migration_0024_rolls_back_when_archive_insert_fails() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rollback.db");
    let pool = pre_0024_pool(&path).await;
    seed_legacy_graph(&pool).await;
    sqlx::query(
        "CREATE TABLE retired_engine_records (
            record_kind TEXT NOT NULL,
            record_id TEXT NOT NULL,
            retired_engine TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            migration_version INTEGER NOT NULL,
            archived_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
            PRIMARY KEY (record_kind, record_id)
        )",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER force_archive_failure
         BEFORE INSERT ON retired_engine_records
         BEGIN SELECT RAISE(ABORT, 'forced archive failure'); END",
    )
    .execute(&pool)
    .await
    .unwrap();

    assert!(sqlx::migrate!().run(&pool).await.is_err());
    let active: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM runs WHERE id = 'run-cfl') +
            (SELECT COUNT(*) FROM harnesses WHERE id = 'harness-cfl') +
            (SELECT COUNT(*) FROM harness_approvals WHERE id = 'approval-cfl') +
            (SELECT COUNT(*) FROM crashes WHERE id = 'crash-cfl') +
            (SELECT COUNT(*) FROM schedule_executions WHERE id = 'exec-cfl') +
            (SELECT COUNT(*) FROM schedule_occurrences WHERE id = 'occ-cfl')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 6);
}

#[tokio::test]
async fn reconnect_rejects_retired_rows_restored_after_migration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("restored.db");
    let pool = pre_0024_pool(&path).await;
    sqlx::migrate!().run(&pool).await.unwrap();
    insert_run(&pool, "run-late", &legacy_serde_engine_name()).await;
    pool.close().await;

    let Err(error) = Store::connect(&path).await else {
        panic!("retired active row must fail startup");
    };
    assert!(matches!(error, StorageError::InvalidData(_)));
    assert!(error.to_string().contains("has been retired"));
    assert!(error.to_string().contains("run-late"));
}

#[tokio::test]
async fn archive_schedule_history_returns_zero_for_empty_input() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("empty.db"))
        .await
        .unwrap();

    assert_eq!(
        store
            .archive_schedule_history_for_retired_engine(&[])
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn archive_schedule_history_archives_bound_deduplicated_schedule_ids() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("schedule-history.db"))
        .await
        .unwrap();
    for suffix in ["a", "b"] {
        let execution_id = format!("execution-{suffix}");
        let schedule_id = format!("schedule-{suffix}");
        let occurrence_id = format!("occurrence-{suffix}");
        let data_json = serde_json::json!({
            "execution_id": execution_id,
            "schedule_id": schedule_id,
            "triggered_at": "2026-08-11T00:00:00Z",
            "status": "pending",
            "request_summary": {
                "parameter_values": { "engine": "libfuzzer" }
            }
        })
        .to_string();
        sqlx::query(
            "INSERT INTO schedule_executions
                (id, schedule_id, triggered_at, status, data_json)
             VALUES (?1, ?2, '2026-08-11T00:00:00Z', 'pending', ?3)",
        )
        .bind(&execution_id)
        .bind(&schedule_id)
        .bind(data_json)
        .execute(store.pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO schedule_occurrences
                (id, schedule_id, execution_id, triggered_at, state, owner_id,
                 lease_expires_at, recovery_detail, created_at, updated_at)
             VALUES (?1, ?2, ?3, '2026-08-11T00:00:00Z', 'reserved', 'owner',
                     '2026-08-11T00:10:00Z', NULL,
                     '2026-08-11T00:00:00Z', '2026-08-11T00:00:00Z')",
        )
        .bind(occurrence_id)
        .bind(schedule_id)
        .bind(execution_id)
        .execute(store.pool())
        .await
        .unwrap();
    }

    let archived = store
        .archive_schedule_history_for_retired_engine(&[
            "schedule-b".to_owned(),
            "schedule-a".to_owned(),
            "schedule-a".to_owned(),
        ])
        .await
        .unwrap();
    assert_eq!(archived, 4);

    let identities: Vec<(String, String)> = sqlx::query_as(
        "SELECT record_kind, record_id FROM retired_engine_records
         ORDER BY record_kind, record_id",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        identities,
        vec![
            ("schedule_execution".to_owned(), "execution-a".to_owned()),
            ("schedule_execution".to_owned(), "execution-b".to_owned()),
            ("schedule_occurrence".to_owned(), "occurrence-a".to_owned()),
            ("schedule_occurrence".to_owned(), "occurrence-b".to_owned()),
        ]
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM schedule_executions) +
            (SELECT COUNT(*) FROM schedule_occurrences)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(active, 0);

    let before_retry = archive_rows(store.pool()).await;
    let retry_count = store
        .archive_schedule_history_for_retired_engine(&[
            "schedule-a".to_owned(),
            "schedule-b".to_owned(),
        ])
        .await
        .unwrap();
    assert_eq!(retry_count, 0);
    assert_eq!(archive_rows(store.pool()).await, before_retry);
}

#[tokio::test]
async fn operation_bound_schedule_history_archive_persists_an_idempotent_proof() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("operation-proof.db"))
        .await
        .unwrap();
    insert_schedule_history(
        store.pool(),
        "execution-proof",
        "occurrence-proof",
        "schedule-proof",
        "active",
    )
    .await;
    let ids = vec!["schedule-proof".to_owned()];

    assert_eq!(
        store
            .archive_schedule_history_for_retired_engine_operation(OPERATION_ID, PLAN_DIGEST, &ids,)
            .await
            .unwrap(),
        2
    );
    assert!(store
        .schedule_retirement_history_proven(OPERATION_ID, PLAN_DIGEST, &ids)
        .await
        .unwrap());
    assert!(store.has_schedule_retirement_history_proof().await.unwrap());

    let before = archive_rows(store.pool()).await;
    assert_eq!(
        store
            .archive_schedule_history_for_retired_engine_operation(OPERATION_ID, PLAN_DIGEST, &ids,)
            .await
            .unwrap(),
        0
    );
    assert_eq!(archive_rows(store.pool()).await, before);

    let late = sqlx::query(
        "INSERT INTO schedule_executions
            (id, schedule_id, triggered_at, status, data_json)
         VALUES ('execution-late', 'schedule-proof', '2026-08-11T00:00:00Z',
                 'pending', '{}')",
    )
    .execute(store.pool())
    .await;
    assert!(
        late.is_err(),
        "retired schedule tombstone must reject late history"
    );
    assert!(store
        .schedule_retirement_history_proven(OPERATION_ID, PLAN_DIGEST, &ids)
        .await
        .unwrap());
}

#[tokio::test]
async fn operation_bound_schedule_history_proof_rejects_divergent_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("operation-proof-conflict.db"))
        .await
        .unwrap();
    let ids = vec!["schedule-proof".to_owned()];
    store
        .archive_schedule_history_for_retired_engine_operation(OPERATION_ID, PLAN_DIGEST, &ids)
        .await
        .unwrap();
    let before = archive_rows(store.pool()).await;

    let error = store
        .archive_schedule_history_for_retired_engine_operation(
            OPERATION_ID,
            SECOND_PLAN_DIGEST,
            &ids,
        )
        .await
        .unwrap_err();

    assert!(matches!(error, StorageError::InvalidData(_)));
    assert_eq!(archive_rows(store.pool()).await, before);
}

#[tokio::test]
async fn operation_proof_rejects_every_sql_mutation_form() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("immutable-proof.db"))
        .await
        .unwrap();
    let ids = vec!["schedule-proof".to_owned()];
    store
        .archive_schedule_history_for_retired_engine_operation(OPERATION_ID, PLAN_DIGEST, &ids)
        .await
        .unwrap();

    let statements = [
        format!(
            "UPDATE schedule_retirement_operations SET plan_digest = '{SECOND_PLAN_DIGEST}' \
             WHERE operation_id = '{OPERATION_ID}'"
        ),
        format!(
            "DELETE FROM schedule_retirement_operations \
             WHERE operation_id = '{OPERATION_ID}'"
        ),
        format!(
            "INSERT OR REPLACE INTO schedule_retirement_operations \
             (operation_id, plan_digest, schedule_ids_json) VALUES \
             ('{OPERATION_ID}', '{SECOND_PLAN_DIGEST}', '[\"other\"]')"
        ),
        format!(
            "INSERT INTO schedule_retirement_operations \
             (operation_id, plan_digest, schedule_ids_json) VALUES \
             ('{OPERATION_ID}', '{SECOND_PLAN_DIGEST}', '[\"other\"]') \
             ON CONFLICT(operation_id) DO UPDATE SET plan_digest = excluded.plan_digest"
        ),
    ];
    for statement in statements {
        assert!(sqlx::query(&statement).execute(store.pool()).await.is_err());
    }

    assert!(store
        .schedule_retirement_history_proven(OPERATION_ID, PLAN_DIGEST, &ids)
        .await
        .unwrap());
}

#[tokio::test]
async fn operation_proof_schema_rejects_invalid_shape_and_bounds() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("proof-shape.db"))
        .await
        .unwrap();
    let invalid_rows = [
        format!("NULL, '{PLAN_DIGEST}', '[]'"),
        format!("'not-a-uuid', '{PLAN_DIGEST}', '[]'"),
        format!("'{OPERATION_ID}', 'short', '[]'"),
        format!("'{OPERATION_ID}', '{PLAN_DIGEST}', '{{}}'"),
        format!("'{SECOND_OPERATION_ID}', '{PLAN_DIGEST}', '[\"dup\",\"dup\"]'"),
        format!("'{SECOND_OPERATION_ID}', '{PLAN_DIGEST}', '[1]'"),
        format!(
            "'{SECOND_OPERATION_ID}', '{PLAN_DIGEST}', '[\"{}\"]'",
            "x".repeat(513)
        ),
    ];
    for values in invalid_rows {
        let statement = format!(
            "INSERT INTO schedule_retirement_operations \
             (operation_id, plan_digest, schedule_ids_json) VALUES ({values})"
        );
        assert!(
            sqlx::query(&statement).execute(store.pool()).await.is_err(),
            "invalid proof row was accepted: {values}"
        );
    }
}

#[tokio::test]
async fn operation_tombstones_reject_late_inserts_and_schedule_id_updates() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("proof-tombstones.db"))
        .await
        .unwrap();
    let ids = vec!["schedule-proof".to_owned()];
    store
        .archive_schedule_history_for_retired_engine_operation(OPERATION_ID, PLAN_DIGEST, &ids)
        .await
        .unwrap();

    let execution_insert = sqlx::query(
        "INSERT INTO schedule_executions
            (id, schedule_id, triggered_at, status, data_json)
         VALUES ('late-execution', 'schedule-proof', '2026-08-11T00:00:00Z',
                 'pending', '{}')",
    )
    .execute(store.pool())
    .await;
    assert!(execution_insert.is_err());

    let occurrence_insert = sqlx::query(
        "INSERT INTO schedule_occurrences
            (id, schedule_id, execution_id, triggered_at, state, owner_id,
             lease_expires_at)
         VALUES ('late-occurrence', 'schedule-proof', 'late-occurrence-execution',
                 '2026-08-11T00:00:00Z', 'reserved', 'owner',
                 '2026-08-11T00:10:00Z')",
    )
    .execute(store.pool())
    .await;
    assert!(occurrence_insert.is_err());

    insert_schedule_history(
        store.pool(),
        "active-execution",
        "active-occurrence",
        "active-schedule",
        "active",
    )
    .await;
    assert!(sqlx::query(
        "UPDATE schedule_executions SET schedule_id = 'schedule-proof' \
         WHERE id = 'active-execution'",
    )
    .execute(store.pool())
    .await
    .is_err());
    assert!(sqlx::query(
        "UPDATE schedule_occurrences SET schedule_id = 'schedule-proof' \
         WHERE id = 'active-occurrence'",
    )
    .execute(store.pool())
    .await
    .is_err());
}

#[tokio::test]
async fn operation_retry_rejects_unrelated_proof_and_revalidates_exact_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("proof-retry.db"))
        .await
        .unwrap();
    store
        .archive_schedule_history_for_retired_engine_operation(
            OPERATION_ID,
            PLAN_DIGEST,
            &["schedule-proof".to_owned()],
        )
        .await
        .unwrap();

    let unrelated = store
        .archive_schedule_history_for_retired_engine_operation(
            SECOND_OPERATION_ID,
            SECOND_PLAN_DIGEST,
            &["other-schedule".to_owned()],
        )
        .await
        .unwrap_err();
    assert!(matches!(unrelated, StorageError::InvalidData(_)));

    assert_eq!(
        store
            .archive_schedule_history_for_retired_engine_operation(
                OPERATION_ID,
                PLAN_DIGEST,
                &["schedule-proof".to_owned()],
            )
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn proof_api_rejects_a_malformed_persisted_schema_even_if_checks_were_bypassed() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("malformed-proof.db"))
        .await
        .unwrap();
    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO schedule_retirement_operations
            (operation_id, plan_digest, schedule_ids_json)
         VALUES (?1, 'malformed-digest', '[\"schedule-proof\"]')",
    )
    .bind(OPERATION_ID)
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO schedule_retirement_schedule_ids
            (schedule_id, operation_id, ordinal)
         VALUES ('schedule-proof', ?1, 0)",
    )
    .bind(OPERATION_ID)
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = OFF")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);

    let error = store
        .has_schedule_retirement_history_proof()
        .await
        .unwrap_err();

    assert!(matches!(error, StorageError::InvalidData(_)));
}

#[tokio::test]
async fn migration_0024_archives_every_rust_trimmed_identifier_shape() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("whitespace-migration.db");
    let pool = pre_0024_pool(&path).await;

    let whitespace_cases = [
        ("ascii", ASCII_TRIMMED_RETIRED_ID),
        ("unicode", UNICODE_TRIMMED_RETIRED_ID),
    ];
    let mut expected = Vec::new();
    for shape in RETIRED_RECORD_SHAPES {
        for (case, engine) in whitespace_cases {
            let id = format!("{}-{case}", shape.label());
            insert_retired_shape(&pool, shape, &id, engine).await;
            expected.push((shape.record_kind().to_owned(), id.clone()));
            if matches!(shape, RetiredRecordShape::ScheduleJson) {
                expected.push(("schedule_occurrence".to_owned(), format!("occurrence-{id}")));
            }
        }
    }

    sqlx::migrate!().run(&pool).await.unwrap();

    let identities: Vec<(String, String)> = sqlx::query_as(
        "SELECT record_kind, record_id FROM retired_engine_records
         ORDER BY record_kind, record_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    expected.sort();
    assert_eq!(identities, expected);

    let direct_payload: String = sqlx::query_scalar(
        "SELECT payload_json FROM retired_engine_records
         WHERE record_kind = 'run' AND record_id = 'run-column-ascii'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let direct_payload: serde_json::Value = serde_json::from_str(&direct_payload).unwrap();
    assert_eq!(direct_payload["engine"], ASCII_TRIMMED_RETIRED_ID);

    let embedded_payload: String = sqlx::query_scalar(
        "SELECT payload_json FROM retired_engine_records
         WHERE record_kind = 'run' AND record_id = 'run-json-unicode'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let embedded_payload: serde_json::Value = serde_json::from_str(&embedded_payload).unwrap();
    let config: serde_json::Value =
        serde_json::from_str(embedded_payload["config_json"].as_str().unwrap()).unwrap();
    assert_eq!(config["engine"], UNICODE_TRIMMED_RETIRED_ID);

    let active: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM runs) +
            (SELECT COUNT(*) FROM harnesses) +
            (SELECT COUNT(*) FROM schedule_executions) +
            (SELECT COUNT(*) FROM schedule_occurrences)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(active, 0);
}

#[tokio::test]
async fn reconnect_rejects_every_restored_rust_trimmed_identifier_shape() {
    let whitespace_cases = [
        ("ascii", ASCII_TRIMMED_RETIRED_ID),
        ("unicode", UNICODE_TRIMMED_RETIRED_ID),
    ];
    for shape in RETIRED_RECORD_SHAPES {
        for (case, engine) in whitespace_cases {
            let directory = tempfile::tempdir().unwrap();
            let path = directory
                .path()
                .join(format!("{}-{case}.db", shape.label()));
            let pool = pre_0024_pool(&path).await;
            sqlx::migrate!().run(&pool).await.unwrap();
            let id = format!("late-{}-{case}", shape.label());
            insert_retired_shape(&pool, shape, &id, engine).await;
            pool.close().await;

            let Err(error) = Store::connect(&path).await else {
                panic!("restored {shape:?} {case} identifier must fail startup");
            };
            assert!(matches!(error, StorageError::InvalidData(_)));
            assert!(error.to_string().contains("has been retired"));
            assert!(error.to_string().contains(&id), "{shape:?} {case}");
        }
    }
}

#[tokio::test]
async fn execution_archive_collision_rolls_back_without_discarding_active_history() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("execution-collision.db"))
        .await
        .unwrap();
    insert_schedule_history(
        store.pool(),
        "execution-collision",
        "occurrence-new",
        "schedule-collision",
        "active",
    )
    .await;
    insert_conflicting_archive(
        store.pool(),
        "schedule_execution",
        "execution-collision",
        &serde_json::json!({
            "id": "execution-collision",
            "schedule_id": "schedule-archived",
            "triggered_at": "2026-08-10T00:00:00Z",
            "status": "completed",
            "data_json": "{\"marker\":\"archived\"}"
        }),
    )
    .await;
    let before = archive_rows(store.pool()).await;

    let error = store
        .archive_schedule_history_for_retired_engine(&["schedule-collision".to_owned()])
        .await
        .unwrap_err();
    assert!(matches!(error, StorageError::Db(_)));
    assert_eq!(archive_rows(store.pool()).await, before);
    let active: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM schedule_executions WHERE id = 'execution-collision') +
            (SELECT COUNT(*) FROM schedule_occurrences WHERE id = 'occurrence-new')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(active, 2);
}

#[tokio::test]
async fn occurrence_archive_collision_rolls_back_without_discarding_active_history() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::connect(directory.path().join("occurrence-collision.db"))
        .await
        .unwrap();
    insert_schedule_history(
        store.pool(),
        "execution-new",
        "occurrence-collision",
        "schedule-collision",
        "active",
    )
    .await;
    insert_conflicting_archive(
        store.pool(),
        "schedule_occurrence",
        "occurrence-collision",
        &serde_json::json!({
            "id": "occurrence-collision",
            "schedule_id": "schedule-archived",
            "execution_id": "execution-archived",
            "triggered_at": "2026-08-10T00:00:00Z",
            "state": "completed",
            "owner_id": "archived-owner",
            "lease_expires_at": null,
            "recovery_detail": "archived",
            "created_at": "2026-08-10T00:00:00Z",
            "updated_at": "2026-08-10T00:01:00Z"
        }),
    )
    .await;
    let before = archive_rows(store.pool()).await;

    let error = store
        .archive_schedule_history_for_retired_engine(&["schedule-collision".to_owned()])
        .await
        .unwrap_err();
    assert!(matches!(error, StorageError::Db(_)));
    assert_eq!(archive_rows(store.pool()).await, before);
    let active: i64 = sqlx::query_scalar(
        "SELECT
            (SELECT COUNT(*) FROM schedule_executions WHERE id = 'execution-new') +
            (SELECT COUNT(*) FROM schedule_occurrences WHERE id = 'occurrence-collision')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(active, 2);
}
