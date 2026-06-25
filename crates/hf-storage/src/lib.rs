//! hf-storage: `SQLite` storage and persistence for `hobot_fuzz`.
//!
//! Implements the schema in `docs/standards/DATABASE_SCHEMA.md` on top of
//! `sqlx` + `SQLite`. The [`Store`] type owns a connection pool, runs
//! forward-only migrations on connect, and exposes typed repository methods for
//! runs, targets, harnesses, crashes, and corpus entries.

mod store;

pub use store::{RunRecord, RunStatus, StorageError, Store};
