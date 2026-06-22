//! ClusterFuzzLite engine adapter stub.

use async_trait::async_trait;
use hf_core::coverage::CoverageReport;
use hf_core::crash::Crash;
use hf_core::engine::{BuildArtifact, EngineKind, FuzzEngine, FuzzRunConfig, FuzzRunHandle};
use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetLanguage};

/// ClusterFuzzLite adapter (stub).
pub struct ClusterFuzzLite;

#[async_trait]
impl FuzzEngine for ClusterFuzzLite {
    fn kind(&self) -> EngineKind {
        EngineKind::ClusterFuzzLite
    }

    fn supports(&self, _lang: TargetLanguage, _san: Sanitizer) -> bool {
        false
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite: not implemented".to_owned(),
        ))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite: not implemented".to_owned(),
        ))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite: not implemented".to_owned(),
        ))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite: not implemented".to_owned(),
        ))
    }
}
