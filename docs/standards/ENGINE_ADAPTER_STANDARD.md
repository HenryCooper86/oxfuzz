# Engine Adapter Standard

Status: **active**. Scope: `hf-engine`, `hf-core`.

## 1. Contract

Every engine adapter implements `EngineAdapter` from `hf-engine`. Adapters own
only argument construction; the engine-agnostic `EngineRunner` executes the
command via `hf-runtime` and parses progress/coverage from its output uniformly
(`hf-engine::progress`). This keeps the sandbox-execution and output-parsing
policy in one place rather than duplicated per engine.

```rust
pub trait EngineAdapter: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn build_run_args(
        &self,
        cfg: &FuzzRunConfig,
        binary: &str,   // or, for syzkaller, the manager config path
        corpus: &str,
        out: &str,
    ) -> Vec<String>;
}
```

Register a new engine by adding its `EngineKind` variant and a match arm in
`hf-engine::registry::adapter_for`.

## 2. Engine Commands

| Engine | Build wrapper or input | Run entrypoint |
| --- | --- | --- |
| AFL++ | `afl-clang-fast` / `afl-clang-fast++` with `-fsanitize=fuzzer,address` for the generated `LLVMFuzzerTestOneInput` harness and AFLDriver | `afl-fuzz` |
| honggfuzz | `hfuzz-cc` / `hfuzz-c++` with `-fsanitize=address` | `honggfuzz` |
| libFuzzer | `clang` / `clang++` with `-fsanitize=fuzzer,address` | harness binary |
| syzkaller | KCOV-enabled kernel build (`make CONFIG_KCOV=y CONFIG_DEBUG_INFO=y`) | `syz-manager -config=<manager.cfg>` |

Syzkaller is the manager-config exception. It fuzzes syscall sequences in a
managed VM rather than a generated single-function harness. The adapter's
`binary` argument is the staged manager-config path, and `syz-manager` manages
the campaign corpus and output through that configuration instead of its
`corpus` and `out` arguments.

## 3. Run Args

Each adapter translates `FuzzRunConfig` into the engine's CLI. Resource limits
(memory, CPU, duration) are enforced by `hf-runtime`, not duplicated by the
engine where possible.

### 3.1 Deterministic Seeds

Every persisted run records a deterministic `FuzzRunConfig.seed` (derived from
the run id by default, so every run is reproducible) and may be re-executed
through `ServiceContainer::replay_run`. An adapter MUST translate a recorded
seed into its engine's genuine fixed-seed knob -- and MUST NOT invent a flag
the engine does not have:

| Engine | Seed knob | Form |
| --- | --- | --- |
| AFL++ (>= 2.53c) | `afl-fuzz -s <seed>` | CLI flag before `--` |
| libFuzzer | `-seed=N` (`0`/absent = random) | CLI flag |
| honggfuzz | none (RNG is seeded from arc4random//dev/urandom) | emit nothing |
| syzkaller | manager-owned fuzzing state | emit no `FuzzRunConfig.seed` flag |

A honggfuzz run with a recorded seed is therefore not RNG-deterministic; that
is an engine limitation, not a license to fabricate flags.

### 3.2 AFL++ File-Input Contract

The supported AFL++ harness is the generated `LLVMFuzzerTestOneInput` target
linked with AFL++'s libFuzzer-compatible driver. Input is always represented as
a file argument:

| Phase | Target argv after `--` |
| --- | --- |
| Fuzz run | `<binary> @@` |
| `afl-showmap` | `<binary> <input>` |
| `afl-tmin` | `<binary> @@` |
| Reproduction | `<binary> <input>` |

All four forms must be built through `hf-engine::afl`'s typed input-delivery
helpers. Omitting `@@` selects AFL++'s stdin mode and is a contract violation.

## 4. Progress Streaming

`EngineRunner` forwards `FuzzProgress` events as a run executes and returns
the final progress and coverage evidence. The events are `ExecsPerSec`,
`EdgesCovered`, `CrashesFound`, and `LogLine`; adapters supply the command
whose stdout/stderr the runner parses into those events.

For AFL++, stdout/stderr parsing is live-log telemetry only. Persisted terminal
statistics must be read from that run's exact `default/fuzzer_stats` file with
the bounded `hf-engine::afl::read_fuzzer_stats` API. Consumers must not scan a
target-wide output directory or infer final AFL++ counters from UI text.

## 5. Crash Output

For the userspace engines, crash ingestion (`hf-crash::ingest`) sees only
**regular files** placed **directly** in the directories below; it never
descends into per-crash subdirectories and never follows symlinks. An adapter
MUST therefore emit each crashing input as a flat file in its engine's
location:

| Engine | Crash input location | Accepted names |
| --- | --- | --- |
| libFuzzer | `<run_dir>/` | `crash-*`, `leak-*`, `timeout-*`, `oom-*` |
| honggfuzz | `<run_dir>/` (pass `--crashdir <run_dir>`) | `SIG<signal>.PC.<...>` |
| AFL++ | `<run_dir>/crashes/` and `<run_dir>/<instance>/crashes/` (e.g. `default/crashes/`) | any regular file except `README.txt` |
| syzkaller | manager-configured workdir | manager-produced crash evidence |

Syzkaller is the manager-config exception: its manager owns the kernel-campaign
workdir and crash evidence, so it does not use the userspace flat-artifact
layout.

A nested layout such as `<run_dir>/crashes/<crash_id>/{input,log.txt}` is NOT
ingested: directories under the crash root are skipped (AFL++ instance
directories are the one exception, and only their immediate `crashes/` child
is scanned). A userspace adapter that receives a per-crash directory layout
from its engine MUST flatten the input files into the locations above.

Sanitizer/engine logs are optional siblings of the input file, matched by
name convention (`log-<stem>.txt`, a stem-named `report-*`/`sanitizer-*`
file, or an unambiguous `report.txt`/`stderr.txt` when a directory holds a
single crash). A crash without a matched log ingests as `CrashKind::Other`.

## 6. Registration

The service selects the built-in adapter by `EngineKind` and confirms runtime
toolchain availability before use. Engine policy is not currently
user-editable; a TOML registry must not be exposed until `hf-service` owns and
applies a typed loader for it.

## 7. Non-Engine Protocol Adapters

Protocol decoders and transport sidecars do not implement `EngineAdapter` and
must not add an `EngineKind`. In particular, the planned Scapy sidecar uses the
feature-gated, versioned `hf-automotive` request/result/error envelopes. It is
invoked only by a service-owned operation through `hf-runtime` after capability,
limit, mode, allowlist, and approval preflight.

Such adapters may emit canonical transcript hashes and protocol-state
signatures. They may not emit those values as `FuzzProgress::EdgesCovered`,
source coverage, or normalized engine crash directories unless a later service
workflow independently validates and classifies an actual crash artifact. Raw
sidecar commands, Python imports in Rust, host execution, and direct physical
interface access are contract violations.
