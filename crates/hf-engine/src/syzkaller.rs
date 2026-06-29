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

use hf_core::engine::FuzzRunConfig;

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

/// The syzkaller engine adapter. Kernel fuzzing launches `syz-manager`; see
/// [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Syzkaller;
