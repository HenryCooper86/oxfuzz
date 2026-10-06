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

honggfuzz receives an explicit `--threads` count from the resolved run CPU
limit. Its default counts host CPUs even when Docker limits the container to
one CPU. Its fixed-size feedback file is larger than the ordinary run-output
file ceiling even at one thread. Smoke and campaigns therefore use bounded
container shared memory for `--workspace`, while `--crashdir`, `--output`, and
`--report` point to the retained run output. Both execution paths apply the
same shared-memory and per-file limits; runtime feedback is discarded with
the container, while findings remain durable.

The pinned sandbox image applies a tracked patch to honggfuzz's
libFuzzer-compatible driver. Its persistent loop otherwise never exits during
a normal short campaign, so LLVM's exit writer does not produce a profile.
When `LLVM_PROFILE_FILE` is set and both LLVM profile hooks are linked, the
driver writes counters after each 100 completed inputs and resets those
counters only after a successful write. The `%m` profile path merges windows
from the same binary. Unprofiled campaigns do not call the hooks. This patch
is verified against the pinned upstream revision and does not change the
human-approved harness source.

### 3.1 CPU Allocation and Intra-Target Parallelism

`max_cpus` is the run's CPU allocation, not only a ceiling: the sandbox
container is capped at that many CPUs and the selected engine is expected to
use them. honggfuzz maps the allocation to `--threads`. libFuzzer maps an
allocation above one to `-fork=N`, its own multi-process mode: the parent
process coordinates N children over the shared corpus directory, continues
after a child crash (artifacts still land through `-artifact_prefix`), and
stops at `-max_total_time`. An allocation of one keeps the historical
single-process argv unchanged, because fork mode is a different execution
model even at N=1; the flag is emitted before `extra_args` so a caller can
override it. An AFL++ allocation above one is orchestrated as N `afl-fuzz`
instances sharing one output tree: the primary runs under `-M main` with the
recorded RNG seed, and secondaries run under `-S sK`; every instance reads
the same staged corpus and keeps its own queue under the shared output tree,
which AFL++ syncs between instances. (The `-i -` resume form is not used:
staging always creates a fresh output tree, where a secondary has no own
queue to resume.) Every instance carries
the time budget and dictionary; a `bash -c` coordinator propagates a
cooperative Stop to all instances, logs each worker's exit status, and exits
with the primary's status, with
the sandbox wall-clock cap as the hard backstop. Smoke qualification stays
single-instance by design: a bounded qualification probe measures whether
the harness executes, not throughput, and must not change argv semantics
when an operator raises the ceiling.

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
outside `(0, max_duration_secs]`, accepts an optional per-run CPU request
within `(0, sandbox.max_cpus]`, then copies the configured memory and the
requested-or-configured CPU allocation into the run configuration.
Presentation defaults are advisory only;
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

AFL++ terminal metrics come from the exact run-owned `fuzzer_stats`
snapshots under the run output, not from UI/log text on stdout. A
single-instance run owns `<run-output>/default/fuzzer_stats`; a multi-worker
run owns one snapshot per instance directory (`<run-output>/<instance>/`),
aggregated run-wide by summing `execs_per_sec` and `saved_crashes` and
maximizing `edges_found` and `total_edges`, since instances share one
coverage bitmap but not one execution stream. The
engine API bounds each file to 64 KiB, rejects symlinked/non-regular paths, and
parses only the exact keys `execs_per_sec`, `edges_found`, `total_edges`, and
`saved_crashes`. Unknown keys are ignored; malformed values for a recognized
key fail that snapshot rather than being reported as zero.

Streaming stdout remains useful for live logs, but it is not authoritative for
persisted AFL++ run statistics. Live throughput retains fractional
executions per second, including rates below one. For the `N execs/sec` form,
parsing selects the preceding rate rather than a later unrelated counter.

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
- Unit: the libFuzzer adapter emits `-fork=N` only for a CPU allocation above
  one, positioned before `extra_args`.
- Integration: a mocked engine run streams progress and emits a fake crash.
- Service contract: disabled engines and excessive durations fail before run
  reservation, while accepted runs persist the resolved resource limits.
- Boundary contract: syzkaller receives a manager config rather than a
  generated userspace harness; the Scapy sidecar remains absent from
  `EngineKind` and the engine registry.

### Retained starting inputs

New userspace campaigns and smoke runs stage an immutable starting corpus beside
the approved source/binary under `runs/<id>/input/corpus`, then seed the engine's
writable corpus from that capture. Persisted comparison provenance refers to
the captured bytes. This preserves original input evidence while engines grow
the working corpus and the canonical target corpus evolves after merging.

### Retained source context

New userspace campaign and smoke runs retain the files included in their
existing source-context identity under `runs/<id>/input/source-context`, using
the same workspace-relative paths. This includes staged C/C++ source and headers,
Cargo manifests, and the recursive `src` tree. Capture precedes hashing; recorded
source and combined identities derive from the captured tree, not later reads
of the live workspace. The existing comparison limits (100,000 files and 16 GiB
combined input bytes) still apply, and copies stream within the remaining budget.
A failed staging attempt removes only the unique unreferenced run directory it
created.

This is the source context present at launch, not a claim that arbitrary project
files, dynamic dependencies, dictionaries, or the original compiler inputs have
all been archived. An exact-input rerun still needs complete execution-input
identity and admission. Old source hashes cannot recover files never retained.

### Immutable execution inputs

Campaigns retain a separate execution workspace, containing every regular file
visible to the engine except the runtime-owned `runs`, `corpus`, and `out`
directories. Symlinks and special files are rejected. The engine mounts this
capture read-only, with only its new corpus and output directories writable.
The selected dictionary is part of that capture. A versioned manifest binds
all retained file paths, bytes, executable permissions, the exact sandbox image,
and the complete run configuration; its SHA-256 is persisted with the config.
File and byte budgets bound capture and verification.

Before sealing a campaign manifest, stage empty `runs/<run-id>/input`,
`runs/<run-id>/corpus`, and `runs/<run-id>/out` directories inside the captured
execution workspace. Docker then mounts the retained input read-only and the
run-specific corpus and output writable at targets that already exist beneath
the read-only `/work` mount. The project-owned `runs` tree is excluded from
capture, so these directories contain no project data. On retained replay,
verify the old manifest first, remove only its empty runtime-owned mountpoint
directories, and stage new ones for the replay run before sealing its new
manifest. Unexpected content or a path conflict fails before run admission.

Replay verifies the manifest, copies the retained inputs into a new run, and
uses the retained promoted source/binary, starting corpus, dictionary, image,
seed, arguments, environment, duration and resource settings. Current engine,
duration and resource policy must admit those settings without silently changing
them. Approval and smoke evidence remain required. Replay does not activate an
old harness or rebuild from current source. Evidence is verified again before
dispatch. Missing legacy manifests are reported as unavailable; they cannot be
reconstructed retrospectively. Identical inputs do not guarantee identical
results from nondeterministic engines, thread scheduling, or external hardware.

For opt-in C/C++ function profiles, stage an empty reserved
`function-coverage` directory in the captured execution workspace before the
manifest is sealed. The read-only `/work` bind mount then already contains the
`/work/function-coverage` target for a separate writable raw-profile mount.
An existing project path at that reserved name is rejected before run
admission; it is never overlaid silently. The raw files stay in this run's
disposable output directory, and replay copies and verifies the same empty
mountpoint. Without the staged target, Docker cannot create a nested mountpoint
inside a read-only parent and the campaign fails before the engine starts.
Moving profile output into an unrecorded mutable workspace path would weaken
the exact-input and read-only guarantees.

The AFL++ libFuzzer-compatible driver normally keeps a persistent target
process alive for up to `INT_MAX` inputs, so its LLVM profile runtime may not
flush during a short campaign. For an opted-in profiled AFL++ campaign, persist
`AFL_FUZZER_LOOPCOUNT=100` in the run environment. The driver then returns
after at most 100 inputs, letting the target flush a raw profile before AFL++
starts another forkserver child. Smoke uses its existing settings. Historical
replay retains the same environment. This bounds the unflushed input window
and costs some throughput; missing raw profiles remain explicitly unavailable.
Profile merge and export use the LLVM version that compiled the harness:
Ubuntu's packaged AFL++ emits LLVM 17 profiles in the pinned image, while
libFuzzer and honggfuzz use LLVM 18. Mixing the default LLVM 18 `llvm-profdata`
with AFL++ raw profiles fails with a version mismatch. The image smoke check
must exercise both format versions before the image is accepted.

## Repeated userspace qualification

The opt-in `scripts/qualify_engines.py` operator tool runs the existing
`cancellation_live` qualification test for an explicit number of cycles. It
requires the exact approved source digest and an explicit per-cycle timeout.
It does not launch harnesses directly: compilation, review, smoke, campaign,
Stop, and replay remain owned by `hf-service` and `hf-runtime`.

Every invocation creates a fresh evidence directory and records the Git revision,
working-tree patch digest, source digest, command, and selected limits. Every
cycle receives a fresh child evidence directory and a log. A manifest is written
before launching each process and atomically replaced on completion. Failed,
interrupted, timed-out, missing-evidence, or incomplete cycles stop the sequence;
none contributes a passing result. A stale `running` record after abrupt host
loss remains incomplete; there is no automatic resume or retry.

Successful cycles require exactly one report for each userspace engine, distinct
campaign/replay UUIDs, finite bounded Stop times, and successful smoke evidence.
The runner summarizes median and nearest-rank P95 Stop latency by engine, with
sample counts. These are measurements for this fixture and environment only.
Timeout/interruption stops the owned local process group and records that sandbox
cleanup is unverified; it never deletes unrelated containers. Dedicated disposable
runtime resources remain required. Repeated normal cycles do not qualify worker
loss, disk pressure, service restart, physical hardware, or installed applications.
