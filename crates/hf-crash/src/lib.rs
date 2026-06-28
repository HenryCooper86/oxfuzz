//! hf-crash: Crash ingestion, dedup, minimization, bug report drafting.
//!
//! See `docs/design/crash-triage-design.md`.

pub mod casr;
pub mod classify;
pub mod dedup;
pub mod ingest;
pub mod minimize;
pub mod report;

pub use casr::{casr_command, cluster_from_path, kind_from_short, parse_casrep, severity_from_str};
pub use classify::{classify, looks_like_crash};
pub use dedup::dedup;
pub use ingest::ingest;
pub use minimize::build_minimize_args;
pub use report::draft_report;
