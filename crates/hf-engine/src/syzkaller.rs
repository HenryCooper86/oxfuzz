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
use hf_core::error::ClassifiedError;

/// Construct the `syz-manager` argument list for a kernel fuzz campaign.
///
/// `config` is the path to the manager config (`manager.cfg`). The `corpus`
/// and `out` directories are managed by syz-manager via its config, so they
/// are not passed on the command line here.
///
/// `FuzzRunConfig.input_timeout` is deliberately not translated: syz-manager's
/// config has no per-input timeout knob (per-program timing is syz-executor
/// internal), so there is no engine flag to emit. The sandbox wall-clock cap
/// remains the bound on a wedged campaign.
///
/// # Errors
/// Currently infallible; the shared adapter signature is fallible because
/// other engines validate flag combinations (see AFL++'s resume rule).
pub fn build_run_args(
    cfg: &FuzzRunConfig,
    config: &str,
    _corpus: &str,
    _out: &str,
) -> Result<Vec<String>, ClassifiedError> {
    let mut args = vec!["syz-manager".to_owned(), format!("-config={config}")];
    args.extend(cfg.extra_args.iter().cloned());
    Ok(args)
}

/// The syzkaller engine adapter. Kernel fuzzing launches `syz-manager`; see
/// [`build_run_args`] and the
/// [`EngineAdapter`](crate::registry::EngineAdapter) impl in `registry`.
pub struct Syzkaller;
