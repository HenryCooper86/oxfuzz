# Engine Integration Design

Status: **active**. Owner: `hf-engine`. Standard: `ENGINE_ADAPTER_STANDARD.md`.

## 1. Goal

Provide a single `EngineAdapter` contract for AFL++, honggfuzz, libFuzzer, and
syzkaller. Adapters construct an engine command only. For userspace campaigns,
`hf-service` stages the run artifacts and delegates adapter argv execution to
`EngineRunner`, which uses `hf-runtime` and converts output into shared progress
and coverage evidence.

## 2. EngineAdapter Contract

```rust
pub trait EngineAdapter: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn build_run_args(
        &self,
        cfg: &FuzzRunConfig,
        binary: &str,
        corpus: &str,
        out: &str,
    ) -> Vec<String>;
}
```

`hf-engine::registry::adapter_for` registers one adapter for every
`EngineKind`. `hf-service` resolves the allowed-engine policy before it builds
or runs a campaign; presentation layers do not select an adapter directly.

## 3. Supported Engines

| Engine | `EngineKind` | Build wrapper or input | Run entrypoint |
| --- | --- | --- | --- |
| AFL++ | `AflPlusPlus` | `afl-clang-fast` / `afl-clang-fast++`, with the libFuzzer-compatible driver | `afl-fuzz` |
| honggfuzz | `Honggfuzz` | `hfuzz-cc` / `hfuzz-c++` | `honggfuzz` |
| libFuzzer | `LibFuzzer` | `clang` / `clang++` with `-fsanitize=fuzzer` | the harness binary |
| syzkaller | `Syzkaller` | KCOV-enabled kernel build (`make CONFIG_KCOV=y CONFIG_DEBUG_INFO=y`) | `syz-manager -config=<manager.cfg>` |

Syzkaller is the service-owned manager-config exception. It fuzzes syscall
sequences against a kernel in a managed VM, not a generated single-function
harness. Its registered adapter represents the `syz-manager -config` argv
contract, where `binary` is the staged `manager.cfg` path and `corpus`/`out`
are not forwarded. The service kernel-campaign path stages and rewrites the
manager config, then invokes `hf-runtime` directly with its bounded timeout
command rather than delegating execution to `EngineRunner`.

## 4. FuzzRunConfig

```rust
pub struct FuzzRunConfig {
    pub harness_id: Uuid,
    pub engine: EngineKind,
    pub duration: Option<Duration>,
    pub max_mem_mb: u64,
    pub max_cpus: u32,
    pub seed_corpus: Option<PathBuf>,
    pub sanitizer: Sanitizer,
    pub env: Vec<(String, String)>,
    pub extra_args: Vec<String>,
    pub seed: Option<u64>,
    pub replay_of: Option<Uuid>,
}
```

Before constructing this value, `hf-service` resolves the effective fuzzing
policy. It rejects engines outside the configured allowed set and durations
outside `(0, max_duration_secs]`, then copies the configured memory and CPU
limits into the run configuration. Presentation defaults are advisory only;
the service preflight is the authoritative enforcement boundary for direct,
scheduled, agent, CLI, REST, and desktop runs.

Engine-backed corpus operations use the same preflight. AFL++ coverage pruning
validates its 600-second operation budget and libFuzzer corpus minimization
validates its 300-second budget before reading or staging workspace artifacts.
Both reject disabled engines and copy the resolved memory and CPU ceilings into
their sandbox requests. A stricter per-input timeout may remain below the
operation-wide duration for coverage measurement.

## 5. Run Lifecycle

For the three userspace engines, `hf-harness` compiles a reviewed,
smoke-qualified harness inside `hf-runtime`. `hf-service` stages each
run-scoped corpus/output workspace and delegates the selected adapter argv to
`EngineRunner`. The runner streams shared `FuzzProgress` events, while
`hf-crash` ingests run-owned artifacts and `hf-coverage` retains coverage
evidence.

For syzkaller, `hf-service` stages the manager configuration and kernel-campaign
inputs in the managed workspace, including rewriting configured paths to the
staged artifacts. It invokes the bounded-timeout `syz-manager` command directly
through `hf-runtime`. The registered syzkaller adapter remains available for
the common argv contract, but the service kernel-campaign execution path does
not use `EngineRunner`. The manager owns the campaign corpus, workdir, and
output through its configuration; it does not use the userspace harness
lifecycle.

Every consumer resolves output through the persisted run id. Target-wide flat
output directories are legacy read-only fallbacks and are never launch targets
for new runs.

### 5.1 AFL++ Input Delivery

Generated C/C++ AFL++ harnesses expose `LLVMFuzzerTestOneInput` through the
AFL++ libFuzzer-compatible driver. The adapter uses one file-input contract in
every lifecycle phase:

- `afl-fuzz` and `afl-tmin` launch the target as `<binary> @@`, allowing AFL++
  to substitute its current input file.
- `afl-showmap` and direct reproduction launch the same target as
  `<binary> <concrete-input-path>`.

No phase silently switches the harness to stdin. The shared argument builder
in `hf-engine::afl` owns this contract so a future harness input mode cannot
change one phase without changing its contract tests.

### 5.2 AFL++ Terminal Statistics

AFL++ terminal metrics come from the exact run-owned
`<run-output>/default/fuzzer_stats` file, not from UI/log text on stdout. The
engine API bounds the file to 64 KiB, rejects symlinked/non-regular paths, and
parses only the exact keys `execs_per_sec`, `edges_found`, `total_edges`, and
`saved_crashes`. Unknown keys are ignored; malformed values for a recognized
key fail that snapshot rather than being reported as zero.

Streaming stdout remains useful for live logs, but it is not authoritative for
persisted AFL++ run statistics.

## 6. Automotive Protocol Sidecar Is Not an Engine

The optional Scapy sidecar does not implement `EngineAdapter` and is not added
to `EngineKind`. Engine adapters translate `FuzzRunConfig` into fuzzing
arguments and report engine evidence. Automotive capture decoding, field-aware
mutation planning, replay, and protocol-state feedback use the versioned
`hf-automotive` contract and a service-owned `hf-runtime` operation instead.

This separation prevents protocol state signatures from being mislabeled as
edges or functions, prevents sidecar capability discovery from becoming engine
registration, and keeps physical-interface policy out of `hf-engine`. A future
workflow may use both systems, but `hf-service` correlates their separately
typed evidence rather than adapting one contract into the other.

## 7. Open Questions

- Unified corpus format across userspace engines, or per-engine directories?
- Should we support parallel multi-engine runs on the same target?

## 8. Tests

- Unit: each adapter constructs the correct CLI args from a `FuzzRunConfig`.
- Integration: a mocked engine run streams progress and emits a fake crash.
- Service contract: disabled engines and excessive durations fail before run
  reservation, while accepted runs persist the resolved resource limits.
- Boundary contract: syzkaller receives a manager config rather than a
  generated userspace harness; the Scapy sidecar remains absent from
  `EngineKind` and the engine registry.
