//! hf-knowledge: BM25 retrieval over chunked project text.
//!
//! `hf-service` builds one per-project index from a codebase's source and
//! documentation files and searches it for the GUI Knowledge view and the
//! agent's `KnowledgeSearch` tool. See `hf_service::knowledge`.
//!
//! # Components
//!
//! - [`bm25`] — BM25 inverted index for keyword search
//! - [`chunking::ChunkingStrategy`] — L0/L1/L2 multi-resolution chunking
//! - [`classifier`] — Domain classification of an entry's text
//! - [`config`] — Chunking, retrieval, and quality settings
//! - [`metadata`] — Multi-dimensional document metadata (`DocumentMetadata`)
//! - [`models`] — Core data models (`KnowledgeEntry`, `KnowledgeCollection`, etc.)
//! - [`quality`] — Quality filtering and deduplication
//! - [`retrieval::HybridRetriever`] — blend search (vector + BM25) with dedup
//! - [`tokenizer`] — English/Chinese text segmentation

pub mod bm25;
pub mod chunking;
pub mod classifier;
pub mod config;
pub mod error;
pub mod metadata;
pub mod models;
pub mod quality;
pub mod retrieval;
pub mod tokenizer;

// Re-export primary types.
pub use bm25::Bm25Index;
pub use chunking::{estimate_tokens, Chunk, ChunkLevel, ChunkerType, ChunkingStrategy};
pub use classifier::{Classifier, RuleBasedClassifier};
pub use config::KnowledgeConfig;
pub use error::KnowledgeError;
pub use metadata::DocumentMetadata;
pub use models::{EntryState, KnowledgeCollection, KnowledgeEntry, L1Section, SourceRef};
pub use quality::QualityFilter;
pub use retrieval::{HybridRetriever, SearchStrategy, SummaryGenerator};
pub use tokenizer::{AutoTokenizer, ChineseTokenizer, SimpleTokenizer, Tokenizer};
