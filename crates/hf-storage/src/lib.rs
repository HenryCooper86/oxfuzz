//! hf-storage: `SQLite` storage and persistence for `hobot_fuzz`.
//!
//! Implements the schema in `docs/standards/DATABASE_SCHEMA.md` on top of
//! `sqlx` + `SQLite`. The [`Store`] type owns a connection pool, runs
//! forward-only migrations on connect, and exposes typed repository methods for
//! runs, targets, harnesses, crashes, and corpus entries.

mod store;

pub mod checkpoint_store;
pub mod config;
mod error;
pub mod migration;
pub mod pool;
pub mod session_store;
pub mod transcript;
pub mod transcript_display;

pub use checkpoint_store::SqliteChatCheckpointStore;
pub use config::StorageConfig;
pub use pool::create_pool;
pub use session_store::SqliteSessionStore;
pub use store::{ProjectAutoRevert, RunRecord, RunStatus, StorageError, Store};
pub use transcript::JsonlTranscriptStore;
pub use transcript_display::JsonlDisplayTranscriptStore;
