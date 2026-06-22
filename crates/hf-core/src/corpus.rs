//! Corpus model.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

/// Where a corpus entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CorpusSource {
    Seed,
    Fuzzer,
    Minimized,
    Manual,
}

/// A single corpus entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub source: CorpusSource,
    pub coverage_hash: Option<String>,
}

/// A corpus for a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Corpus {
    pub id: Uuid,
    pub target_id: Uuid,
    pub root: PathBuf,
    pub entries: Vec<CorpusEntry>,
}
