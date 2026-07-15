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

## 2. Build Flags

| Engine | Compiler wrapper | Link flags |
| --- | --- | --- |
| AFL++ | `afl-clang-fast` | (wrapper handles it) |
| honggfuzz | `hfuzz-cc` | `-lhfuzz` |
| libFuzzer | `clang` | `-fsanitize=fuzzer` |
| ClusterFuzzLite | project build script | oss-fuzz `compile` |

## 3. Run Args

Each adapter translates `FuzzRunConfig` into the engine's CLI. Resource limits
(memory, CPU, duration) are enforced by `hf-runtime`, not duplicated by the
engine where possible.

### 3.1 AFL++ File-Input Contract

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

`FuzzRunHandle` exposes a stream of `FuzzProgress` events: `ExecsPerSec`,
`EdgesCovered`, `CrashesFound`, `LogLine`. Adapters parse engine stdout/stderr
into these events.

For AFL++, stdout/stderr parsing is live-log telemetry only. Persisted terminal
statistics must be read from that run's exact `default/fuzzer_stats` file with
the bounded `hf-engine::afl::read_fuzzer_stats` API. Consumers must not scan a
target-wide output directory or infer final AFL++ counters from UI text.

## 5. Crash Output

Each adapter must normalize crash artifacts into a directory layout:

```
<run_dir>/crashes/
  <crash_id>/
    input
    log.txt
```

## 6. Registration

Engines register in `config/engines.toml`. The `hf-engine` registry loads
adapters by `EngineKind`.
