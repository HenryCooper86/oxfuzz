use hf_storage::{StorageError, Store};

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
}
