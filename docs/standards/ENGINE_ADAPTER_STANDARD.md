# Engine Adapter Standard

Status: **active**. Scope: `hf-engine`, `hf-core`.

## 1. Contract

Every engine adapter implements `FuzzEngine` from `hf-core`:

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

## 4. Progress Streaming

`FuzzRunHandle` exposes a stream of `FuzzProgress` events: `ExecsPerSec`,
`EdgesCovered`, `CrashesFound`, `LogLine`. Adapters parse engine stdout/stderr
into these events.

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