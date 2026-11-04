//! Migration 0050 retires the Coverage and Blockers closeout steps without
//! letting a trust verdict that depended on them resurface.

async fn pre_0050_pool(path: &std::path::Path) -> sqlx::SqlitePool {
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
        .retain(|migration| migration.version <= 49);
    migrations.run(&pool).await.unwrap();
    pool
}

async fn step(pool: &sqlx::SqlitePool, run: &str, step: &str, outcome: &str, detail: &str) {
    sqlx::query(
        "INSERT INTO run_closeout_steps (run_id, step, outcome, detail, recorded_at) \
         VALUES (?1, ?2, ?3, ?4, '2026-10-01T00:00:00Z')",
    )
    .bind(run)
    .bind(step)
    .bind(outcome)
    .bind(detail)
    .execute(pool)
    .await
    .unwrap();
}

async fn steps(pool: &sqlx::SqlitePool, run: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT step FROM run_closeout_steps WHERE run_id = ?1 ORDER BY step")
        .bind(run)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn retires_legacy_steps_and_the_trust_results_that_relied_on_them() {
    let dir = tempfile::tempdir().unwrap();
    let pool = pre_0050_pool(&dir.path().join("closeout.db")).await;
    // A: legacy coverage completed, so its trust verdict audited workspace evidence.
    step(&pool, "a", "Triage", "completed", "0 crash(es) attributed").await;
    step(
        &pool,
        "a",
        "Coverage",
        "completed",
        "91.0% of lines covered",
    )
    .await;
    step(&pool, "a", "Blockers", "completed", "0 blocker(s)").await;
    step(&pool, "a", "TrustReport", "completed", "Trusted").await;
    // B: trust blocked by a legacy step.
    step(&pool, "b", "Coverage", "failed", "no profile").await;
    step(&pool, "b", "Blockers", "blocked", "Coverage").await;
    step(&pool, "b", "TrustReport", "blocked", "Coverage").await;
    // C: already on the current ladder; untouched.
    step(&pool, "c", "Triage", "completed", "done").await;
    step(&pool, "c", "TrustReport", "completed", "Unqualified").await;

    let mut migrations = sqlx::migrate!();
    migrations.set_ignore_missing(true);
    migrations.run(&pool).await.unwrap();

    assert_eq!(steps(&pool, "a").await, vec!["Triage"]);
    assert!(steps(&pool, "b").await.is_empty());
    assert_eq!(steps(&pool, "c").await, vec!["Triage", "TrustReport"]);
}
