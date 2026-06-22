//! AFL++ engine adapter stub.

use async_trait::async_trait;
use hf_core::coverage::CoverageReport;
use hf_core::crash::Crash;
use hf_core::engine::{BuildArtifact, EngineKind, FuzzEngine, FuzzRunConfig, FuzzRunHandle};
use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetLanguage};

/// AFL++ adapter (stub).
pub struct AflPlusPlus;

#[async_trait]
impl FuzzEngine for AflPlusPlus {
    fn kind(&self) -> EngineKind {
        EngineKind::AflPlusPlus
    }

    fn supports(&self, _lang: TargetLanguage, _san: Sanitizer) -> bool {
        false
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine("afl: not implemented".to_owned()))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine("afl: not implemented".to_owned()))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine("afl: not implemented".to_owned()))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine("afl: not implemented".to_owned()))
    }
}
