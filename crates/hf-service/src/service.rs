//! Default `FuzzService` implementation (stub).

use hf_core::corpus::Corpus;
use hf_core::coverage::CoverageReport;
use hf_core::crash::Crash;
use hf_core::engine::{FuzzRunConfig, FuzzRunHandle};
use hf_core::harness::Harness;
use hf_core::target::{TargetInventory, TargetLanguage};
use std::path::PathBuf;
use uuid::Uuid;

/// A request to discover targets in a project.
#[derive(Debug, Clone)]
pub struct DiscoverRequest {
    pub project_root: PathBuf,
    pub language: TargetLanguage,
}

/// A request to generate a harness.
#[derive(Debug, Clone)]
pub struct HarnessRequest {
    pub target_id: Uuid,
    pub engine: hf_core::engine::EngineKind,
}

/// The top-level service trait.
#[async_trait::async_trait]
pub trait FuzzService: Send + Sync {
    async fn discover(
        &self,
        req: DiscoverRequest,
    ) -> Result<TargetInventory, hf_core::error::ClassifiedError>;
    async fn generate_harness(
        &self,
        req: HarnessRequest,
    ) -> Result<Harness, hf_core::error::ClassifiedError>;
    async fn run_fuzz(
        &self,
        cfg: FuzzRunConfig,
    ) -> Result<FuzzRunHandle, hf_core::error::ClassifiedError>;
    async fn triage(&self, run_id: Uuid) -> Result<Vec<Crash>, hf_core::error::ClassifiedError>;
    async fn coverage_report(
        &self,
        run_id: Uuid,
    ) -> Result<CoverageReport, hf_core::error::ClassifiedError>;
    async fn corpus_ops(&self, target_id: Uuid) -> Result<Corpus, hf_core::error::ClassifiedError>;
}

/// Stub service.
pub struct DefaultFuzzService;

#[async_trait::async_trait]
impl FuzzService for DefaultFuzzService {
    async fn discover(
        &self,
        _req: DiscoverRequest,
    ) -> Result<TargetInventory, hf_core::error::ClassifiedError> {
        Err(hf_core::error::ClassifiedError::Internal(
            "not implemented".to_owned(),
        ))
    }
    async fn generate_harness(
        &self,
        _req: HarnessRequest,
    ) -> Result<Harness, hf_core::error::ClassifiedError> {
        Err(hf_core::error::ClassifiedError::Internal(
            "not implemented".to_owned(),
        ))
    }
    async fn run_fuzz(
        &self,
        _cfg: FuzzRunConfig,
    ) -> Result<FuzzRunHandle, hf_core::error::ClassifiedError> {
        Err(hf_core::error::ClassifiedError::Internal(
            "not implemented".to_owned(),
        ))
    }
    async fn triage(&self, _run_id: Uuid) -> Result<Vec<Crash>, hf_core::error::ClassifiedError> {
        Err(hf_core::error::ClassifiedError::Internal(
            "not implemented".to_owned(),
        ))
    }
    async fn coverage_report(
        &self,
        _run_id: Uuid,
    ) -> Result<CoverageReport, hf_core::error::ClassifiedError> {
        Err(hf_core::error::ClassifiedError::Internal(
            "not implemented".to_owned(),
        ))
    }

    async fn corpus_ops(
        &self,
        _target_id: Uuid,
    ) -> Result<Corpus, hf_core::error::ClassifiedError> {
        Err(hf_core::error::ClassifiedError::Internal(
            "not implemented".to_owned(),
        ))
    }
}
