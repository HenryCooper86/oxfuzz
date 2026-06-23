//! `ClusterFuzzLite` engine adapter.
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md`.
//!
//! `ClusterFuzzLite` wraps oss-fuzz build scripts. The `build_run_args`
//! function constructs the `python3 infra/helper.py run_fuzzer` command.

use hf_core::engine::{BuildArtifact, EngineKind, FuzzRunConfig};

/// Construct the `ClusterFuzzLite` run argument list.
///
/// `ClusterFuzzLite` uses `infra/helper.py run_fuzzer <project> <fuzzer_name>
/// --timeout=<seconds>`.
#[must_use]
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    _binary: &str,
    _corpus: &str,
    _out: &str,
) -> Vec<String> {
    let duration = cfg.duration.map_or(3600, |d| d.as_secs());
    let mut args = vec![
        "python3".to_owned(),
        "infra/helper.py".to_owned(),
        "run_fuzzer".to_owned(),
    ];
    if duration > 0 {
        args.push(format!("--timeout={duration}"));
    }
    if !cfg.env.is_empty() {
        let mut env_prefix = vec!["env".to_owned()];
        for (k, v) in &cfg.env {
            env_prefix.push(format!("{k}={v}"));
        }
        env_prefix.extend_from_slice(&args);
        args = env_prefix;
    }
    args.extend(cfg.extra_args.iter().cloned());
    args
}

/// The `ClusterFuzzLite` engine adapter (stub for the `FuzzEngine` trait).
pub struct ClusterFuzzLite;

impl ClusterFuzzLite {
    #[must_use]
    pub const fn kind() -> EngineKind {
        EngineKind::ClusterFuzzLite
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
impl FuzzEngine for ClusterFuzzLite {
    fn kind(&self) -> EngineKind {
        EngineKind::ClusterFuzzLite
    }

    fn supports(&self, lang: TargetLanguage, _san: Sanitizer) -> bool {
        matches!(
            lang,
            TargetLanguage::C
                | TargetLanguage::Cpp
                | TargetLanguage::Rust
                | TargetLanguage::Go
                | TargetLanguage::Python
        )
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite build: not implemented".to_owned(),
        ))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite run: not implemented".to_owned(),
        ))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite minimize: not implemented".to_owned(),
        ))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "clusterfuzzlite coverage: not implemented".to_owned(),
        ))
    }
}
