//! Coverage model.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// A coverage report for a fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub run_id: Uuid,
    pub edges: u64,
    pub blocks: u64,
    pub delta_edges: i64,
    pub stagnation_secs: u64,
    pub new_edges_files: Vec<PathBuf>,
}
