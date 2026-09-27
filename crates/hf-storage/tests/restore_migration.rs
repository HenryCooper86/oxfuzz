//! A disposable pre-0019 `SQLite` backup can be restored and migrated by `Store`.

#![cfg(unix)]

use std::path::Path;
use std::time::Duration;

use hf_storage::{RunStatus, Store};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use uuid::Uuid;

async fn run_probe(script: &Path, arguments: &[&Path]) {
    let mut command = tokio::process::Command::new("python3");
    command.arg(script).args(arguments).kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
        .await
        .expect("bounded disposable restore probe")
        .expect("start disposable restore probe");
    assert!(
        output.status.success(),
        "restore probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
#[ignore = "runs the Python restore probe against a disposable migration fixture"]
async fn pre_0019_backup_restores_and_migrates_to_current_store() {
    let root = tempfile::tempdir().unwrap();
    let database = root.path().join("pre-0019.db");
    let workspace = root.path().join("workspace");
    let archive = root.path().join("archive");
    let restored = root.path().join("restored");
    let run_id = Uuid::new_v4();
    let evidence = workspace
        .join("project-1234/parser/runs")
        .join(run_id.to_string())
        .join("out");
    std::fs::create_dir_all(&evidence).unwrap();
    std::fs::write(evidence.join("retained.json"), b"{}").unwrap();

    let opts = SqliteConnectOptions::new()
        .filename(&database)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal);
    let pool = SqlitePoolOptions::new().connect_with(opts).await.unwrap();
    let mut legacy = sqlx::migrate!();
    legacy
        .migrations
        .to_mut()
        .retain(|migration| migration.version <= 18);
    legacy.run(&pool).await.unwrap();
    sqlx::query(
        "INSERT INTO runs (id, project_root, engine, status, started_at, evidence_dir)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(run_id.to_string())
    .bind("/disposable/project")
    .bind("libfuzzer")
    .bind("done")
    .bind("2026-09-27T00:00:00Z")
    .bind(format!("runs/{run_id}/out"))
    .execute(&pool)
    .await
    .unwrap();

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/qualify_restore.py");
    run_probe(
        &script,
        &[
            Path::new("backup"),
            Path::new("--database"),
            &database,
            Path::new("--workspace"),
            &workspace,
            Path::new("--archive"),
            &archive,
        ],
    )
    .await;
    pool.close().await;
    run_probe(
        &script,
        &[
            Path::new("restore"),
            Path::new("--archive"),
            &archive,
            Path::new("--destination"),
            &restored,
        ],
    )
    .await;

    let reopened = Store::connect(restored.join("database.sqlite"))
        .await
        .unwrap();
    let run = reopened.get_run(run_id).await.unwrap().unwrap();
    assert_eq!(run.status, RunStatus::Done);
    assert_eq!(run.evidence_dir, Some(format!("runs/{run_id}/out")));
    assert!(restored
        .join("workspace/project-1234/parser/runs")
        .join(run_id.to_string())
        .join("out/retained.json")
        .is_file());
    let current = sqlx::migrate!().migrations.last().unwrap().version;
    let applied: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(applied, current);
    let approvals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM harness_approvals")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(approvals, 0);
}
