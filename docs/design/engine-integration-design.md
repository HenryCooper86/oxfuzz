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

## 5. Run Lifecycle

1. `build` -- compile harness in sandbox -> `BuildArtifact` (binary path).
2. `run` -- launch engine in sandbox under resource limits -> `FuzzRunHandle`
   streaming progress (execs/sec, edges, crashes).
3. On crash -> `hf-crash` ingests artifacts.
4. `coverage` -- post-run coverage report for `hf-coverage`.
5. `minimize` -- reduce a crash input.

## 6. Open Questions

- Unified corpus format across engines, or per-engine directories?
- Should we support parallel multi-engine runs on the same target?

## 7. Tests

- Unit: each adapter constructs the correct CLI args from a `FuzzRunConfig`.
- Integration: a mocked engine `run` streams progress and emits a fake crash.