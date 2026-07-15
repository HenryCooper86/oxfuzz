//! `hf-diagnostics`: durable trace and observation storage for LLM cost
//! evidence.
//!
//! Storage is abstracted behind the [`TraceStore`] trait. An in-memory
//! implementation is provided for testing; a SQLite-backed implementation
//! ([`SqliteTraceStore`]) persists production diagnostics in the shared
//! application database.

pub mod sqlite_trace_store;
pub mod trace_store;
pub mod types;

// Re-exports for convenient access.
pub use sqlite_trace_store::SqliteTraceStore;
pub use trace_store::{InMemoryTraceStore, TraceStore, TraceStoreError};
pub use types::*;
