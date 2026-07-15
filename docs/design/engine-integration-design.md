# Engine Integration Design

Status: **draft**. Owner: `hf-engine`. Standard: `ENGINE_ADAPTER_STANDARD.md`.

## 1. Goal

Provide a single `FuzzEngine` trait that fronts AFL++, honggfuzz, libFuzzer,
and ClusterFuzzLite so the agent can select and drive engines uniformly.

## 2. FuzzEngine Trait

```rust
#[async_trait]
pub trait FuzzEngine: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn supports(&self, lang: TargetLanguage, san: Sanitizer) -> bool;
    async fn build(&self, harness: &Harness, rt: &dyn RuntimeAdapter) -> Result<BuildArtifact>;
    async fn run(&self, cfg: &FuzzRunConfig, rt: &dyn RuntimeAdapter) -> Result<FuzzRunHandle>;
    async fn minimize(&self, crash: &Crash, rt: &dyn RuntimeAdapter) -> Result<Crash>;
    async fn coverage(&self, run: &FuzzRunHandle) -> Result<CoverageReport>;
}
```

## 3. Engines

| Engine | Kind | Build flags | Run binary |
| --- | --- | --- | --- |
| AFL++ | `AflPlusPlus` | `afl-cc` / `afl-clang-fast` | `afl-fuzz` |
| honggfuzz | `Honggfuzz` | `hfuzz-cc` | `honggfuzz` |
| libFuzzer | `LibFuzzer` | `-fsanitize=fuzzer` | harness binary itself |
| ClusterFuzzLite | `ClusterFuzzLite` | oss-fuzz build scripts | `infra/helper.py` |

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

1. `build` -- compile harness in sandbox -> `BuildArtifact` (binary path).
2. `run` -- allocate a unique run directory, verify the persisted source and
   binary digests, then launch the engine in a read-only sandbox workspace with
   only that run's corpus/output mounts writable -> `FuzzRunHandle` streaming
   progress (execs/sec, edges, crashes).
3. On crash -> `hf-crash` ingests artifacts.
4. `coverage` -- post-run coverage report for `hf-coverage`.
5. `minimize` -- reduce a crash input.

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
to `EngineKind`. Engine adapters translate `FuzzRunConfig` into source-fuzzer
arguments and report source coverage/crashes. Automotive capture decoding,
field-aware mutation planning, replay, and protocol-state feedback use the
versioned `hf-automotive` contract and a service-owned `hf-runtime`
operation instead.

This separation prevents protocol state signatures from being mislabeled as
edges or functions, prevents sidecar capability discovery from becoming engine
registration, and keeps physical-interface policy out of `hf-engine`. A future
workflow may use both systems, but `hf-service` correlates their separately
typed evidence rather than adapting one contract into the other.

## 7. Open Questions

- Unified corpus format across engines, or per-engine directories?
- Should we support parallel multi-engine runs on the same target?

## 8. Tests

- Unit: each adapter constructs the correct CLI args from a `FuzzRunConfig`.
- Integration: a mocked engine `run` streams progress and emits a fake crash.
- Service contract: disabled engines and excessive durations fail before run
  reservation, while accepted runs persist the resolved resource limits.
- Boundary contract: the Scapy sidecar remains absent from `EngineKind` and the
  engine registry; its pure domain tests run in `hf-automotive`.
