# Local SQLite dependency repair

This is `sqlx-sqlite` 0.8.6 from crates.io, corresponding to
[SQLx commit bab1b022](https://github.com/launchbadge/sqlx/tree/bab1b022bd56a64f9a08b46b36b97c5cff19d77e/sqlx-sqlite).
Its Rust implementation is unchanged; trailing spaces in three documentation
comment lines are normalized. The only functional change is the manifest's
`libsqlite3-sys` requirement, from `0.30.1` to `0.39.1`, which bundles SQLite
3.54.1. Both original licenses are retained.

RUSTSEC-2026-0459 affects bundled SQLite before 3.54.0: a database and sibling
WAL with mismatched page sizes can disclose uninitialized page-cache memory.
SQLx 0.8.6 pins the affected native dependency; SQLx 0.9.0 still caps it below
0.38.0. This patch retains the SQLx API and existing database schema while
selecting the repaired engine, without suppressing the advisory.

Remove the patch when a published SQLx SQLite adapter supports a repaired
native dependency. Verify with `cargo deny check -D warnings`, the
`bundled_sqlite_includes_wal_page_size_fix` runtime test, and the storage and
workspace suites. The runtime regression checks the engine used by actual
Store connections, not just the lockfile.
