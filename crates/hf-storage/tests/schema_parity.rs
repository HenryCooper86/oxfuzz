//! Guards against schema drift between the two `SQLite` schema sources.
//!
//! The crate carries two schema definitions:
//! - `migrations/*.sql`, applied in production by [`Store::connect`] via
//!   `sqlx::migrate!`.
//! - `schema.sql`, applied by [`migration::run_embedded_migrations`] and used
//!   by the `hf-session` unit tests.
//!
//! Several tables are defined in BOTH, but only some are exercised by the SAME
//! production code against BOTH schemas. The clearest case is `session_metadata`:
//! `SqliteSessionStore` runs against `migrations/0005` in production and against
//! `schema.sql` in the `hf-session` unit tests. If those two definitions drift,
//! the session tests pass while production is missing columns the store reads --
//! a silent "green tests, broken prod" failure.
//!
//! Other shared tables intentionally differ (e.g. `schema.sql`'s richer
//! `schedule_executions`/`diag_*` are y-agent-ported and unused by production,
//! which uses the simpler `migrations/` versions), so this test enforces parity
//! only for the cross-exercised tables in `CROSS_EXERCISED_TABLES`, not all
//! shared tables. Full physical unification of the two schemas is tracked
//! separately.

/// Tables built by `migrations/` in production AND by `schema.sql` in tests, and
/// queried by the same production code in both contexts -- so their column sets
/// must stay identical.
const CROSS_EXERCISED_TABLES: &[&str] = &["session_metadata", "chat_checkpoints"];

use std::collections::BTreeSet;

use sqlx::Row;

async fn table_names(pool: &sqlx::SqlitePool) -> BTreeSet<String> {
    sqlx::query(
        "SELECT name FROM sqlite_master \
         WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(pool)
    .await
    .unwrap()
    .iter()
    .map(|r| r.get::<String, _>("name"))
    // sqlx's own migration bookkeeping table is not part of either schema.
    .filter(|n| n != "_sqlx_migrations")
    .collect()
}

async fn columns(pool: &sqlx::SqlitePool, table: &str) -> BTreeSet<String> {
    sqlx::query(&format!("SELECT name FROM pragma_table_info('{table}')"))
        .fetch_all(pool)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect()
}

#[tokio::test]
async fn overlapping_tables_have_identical_columns_across_schemas() {
    // Production schema: migrations/*.sql via Store::connect.
    let dir = tempfile::tempdir().unwrap();
    let store = hf_storage::Store::connect(dir.path().join("prod.db"))
        .await
        .expect("connect production store");
    let prod = store.pool();

    // Embedded/test schema: schema.sql via run_embedded_migrations.
    let cfg = hf_storage::StorageConfig::in_memory();
    let embedded = hf_storage::create_pool(&cfg).await.expect("embedded pool");
    hf_storage::migration::run_embedded_migrations(&embedded)
        .await
        .expect("embedded migrations");

    let prod_tables = table_names(prod).await;
    let embedded_tables = table_names(&embedded).await;

    for &table in CROSS_EXERCISED_TABLES {
        assert!(
            prod_tables.contains(table),
            "'{table}' must exist in the production (migrations/) schema"
        );
        assert!(
            embedded_tables.contains(table),
            "'{table}' must exist in the embedded (schema.sql) schema"
        );
        let prod_cols = columns(prod, table).await;
        let embedded_cols = columns(&embedded, table).await;
        assert_eq!(
            prod_cols, embedded_cols,
            "schema drift in table '{table}': migrations/={prod_cols:?} vs schema.sql={embedded_cols:?}"
        );
    }
}
