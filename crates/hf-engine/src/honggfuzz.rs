//! honggfuzz engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.

use hf_core::engine::{BuildArtifact, EngineKind, FuzzRunConfig};

/// Construct the `honggfuzz` argument list for a fuzz run.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, binary: &str, corpus: &str, out: &str) -> Vec<String> {
    let duration = cfg.duration.map_or(0, |d| d.as_secs());
    let mut args = vec!["honggfuzz".to_owned()];
    if duration > 0 {
        args.push(format!("--run_time={duration}"));
    }
    args.push("--input".to_owned());
    args.push(corpus.to_owned());
    args.push("--output".to_owned());
    args.push(out.to_owned());
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    args.extend(cfg.extra_args.iter().cloned());
    args.push("--".to_owned());
    args.push(binary.to_owned());
    args
}

/// The honggfuzz engine adapter (stub for the `FuzzEngine` trait).
pub struct Honggfuzz;

impl Honggfuzz {
    #[must_use]
    pub const fn kind() -> EngineKind {
        EngineKind::Honggfuzz
    }
}

use async_trait::async_trait;
use hf_core::coverage::CoverageReport;
use hf_core::crash::Crash;
use hf_core::engine::{FuzzEngine, FuzzRunHandle};
use hf_core::error::ClassifiedError;
use hf_core::harness::Harness;
use hf_core::runtime::RuntimeAdapter;
use hf_core::target::{Sanitizer, TargetLanguage};

#[async_trait]
impl FuzzEngine for Honggfuzz {
    fn kind(&self) -> EngineKind {
        EngineKind::Honggfuzz
    }

    fn supports(&self, lang: TargetLanguage, _san: Sanitizer) -> bool {
        matches!(lang, TargetLanguage::C | TargetLanguage::Cpp)
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "honggfuzz build: not implemented".to_owned(),
        ))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "honggfuzz run: not implemented".to_owned(),
        ))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "honggfuzz minimize: not implemented".to_owned(),
        ))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "honggfuzz coverage: not implemented".to_owned(),
        ))
    }
}
