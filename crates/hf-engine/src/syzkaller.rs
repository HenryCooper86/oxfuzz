//! syzkaller engine adapter (Google's OS kernel fuzzer).
//!
//! Unlike libFuzzer/AFL++/honggfuzz, syzkaller fuzzes an OS kernel by
//! generating and mutating sequences of system calls, executing them inside a
//! managed VM whose kernel is built with coverage instrumentation (KCOV).
//! A campaign is driven by `syz-manager -config=<manager.cfg>`, which points at
//! a KCOV-enabled kernel image and a VM (qemu or GCE).
//!
//! See `docs/standards/ENGINE_ADAPTER_STANDARD.md` and
//! <https://github.com/google/syzkaller/blob/master/docs/linux/setup.md>.

use hf_core::engine::{BuildArtifact, EngineKind, FuzzRunConfig};

/// Construct the `syz-manager` argument list for a kernel fuzz campaign.
///
/// `config` is the path to the manager config (`manager.cfg`). The `corpus`
/// and `out` directories are managed by syz-manager via its config, so they
/// are not passed on the command line here.
#[must_use]
pub fn build_run_args(cfg: &FuzzRunConfig, config: &str, _corpus: &str, _out: &str) -> Vec<String> {
    let mut args = vec!["syz-manager".to_owned(), format!("-config={config}")];
    args.extend(cfg.extra_args.iter().cloned());
    args
}

/// The syzkaller engine adapter (stub for the `FuzzEngine` trait).
pub struct Syzkaller;

impl Syzkaller {
    #[must_use]
    pub const fn kind() -> EngineKind {
        EngineKind::Syzkaller
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
impl FuzzEngine for Syzkaller {
    fn kind(&self) -> EngineKind {
        EngineKind::Syzkaller
    }

    fn supports(&self, lang: TargetLanguage, _san: Sanitizer) -> bool {
        // Kernel sources are C.
        matches!(lang, TargetLanguage::C)
    }

    async fn build(
        &self,
        _h: &Harness,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<BuildArtifact, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "syzkaller build: kernel fuzzing uses a KCOV-enabled kernel image, not a harness binary"
                .to_owned(),
        ))
    }

    async fn run(
        &self,
        _cfg: &FuzzRunConfig,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<FuzzRunHandle, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "syzkaller run: launch via `syz-manager -config=manager.cfg`".to_owned(),
        ))
    }

    async fn minimize(
        &self,
        _c: &Crash,
        _rt: &dyn RuntimeAdapter,
    ) -> Result<Crash, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "syzkaller minimize: use `syz-repro` on the crash log".to_owned(),
        ))
    }

    async fn coverage(&self, _run: &FuzzRunHandle) -> Result<CoverageReport, ClassifiedError> {
        Err(ClassifiedError::Engine(
            "syzkaller coverage: served by the syz-manager web dashboard".to_owned(),
        ))
    }
}
