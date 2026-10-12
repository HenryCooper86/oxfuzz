# Engine Adapter Standard

Status: **active**. Scope: `hf-engine`, `hf-core`.

## 1. Contract

Every engine adapter implements `EngineAdapter` from `hf-engine`. Adapters own
only argument construction. For AFL++, honggfuzz, and libFuzzer, `hf-service`
stages userspace corpus/output artifacts and delegates adapter argv execution
to the engine-agnostic `EngineRunner`, which executes through `hf-runtime` and
parses progress/coverage from output uniformly (`hf-engine::progress`).

Syzkaller remains a registered adapter, but kernel-campaign execution is the
service-owned manager exception: `hf-service` stages and rewrites the manager
config, then invokes its bounded-timeout command directly through `hf-runtime`.
It does not delegate that execution path to `EngineRunner`. Userspace execution
and output parsing are centralized in `EngineRunner`, while the distinct
syzkaller execution and parsing policy remains in the service-owned
kernel-campaign path.

```rust
pub trait EngineAdapter: Send + Sync {
    fn kind(&self) -> EngineKind;
    fn build_run_args(
        &self,
        cfg: &FuzzRunConfig,
        binary: &str,   // or, for syzkaller, the manager config path
        corpus: &str,
        out: &str,
    ) -> Result<Vec<String>, ClassifiedError>;
}
```

The builder is fallible because argument construction also *enforces*: a flag
combination the engine cannot honor (the AFL++ resume rule in §3.4) is
rejected here, so no caller can construct invalid argv.

Register a new engine by adding its `EngineKind` variant and a match arm in
`hf-engine::registry::adapter_for`.

## 2. Engine Commands

| Engine | Build wrapper or input | Run entrypoint |
| --- | --- | --- |
| AFL++ | `afl-clang-fast` / `afl-clang-fast++` with `-fsanitize=fuzzer` plus the selected sanitizer (`-fsanitize=address`, or `-fsanitize=undefined -fno-sanitize-recover=undefined`) for the generated `LLVMFuzzerTestOneInput` harness and AFLDriver | `afl-fuzz` |
| honggfuzz | `hfuzz-cc` / `hfuzz-clang++` with the selected sanitizer (`-fsanitize=address`, or `-fsanitize=undefined -fno-sanitize-recover=undefined`) | `honggfuzz` |
| libFuzzer | `clang` / `clang++` with `-fsanitize=fuzzer` plus the selected sanitizer (`-fsanitize=address`, or `-fsanitize=undefined -fno-sanitize-recover=undefined`) | harness binary |
| syzkaller | KCOV-enabled kernel build (`make CONFIG_KCOV=y CONFIG_DEBUG_INFO=y`) | `syz-manager -config=<manager.cfg>` |

Syzkaller is the manager-config exception. It fuzzes syscall sequences in a
managed VM rather than a generated single-function harness. The adapter's
`binary` argument is the staged manager-config path, and `syz-manager` manages
the campaign corpus and output through that configuration instead of its
`corpus` and `out` arguments. For kernel campaigns, `hf-service` stages and
rewrites that config and invokes its bounded-timeout command directly through
`hf-runtime`, rather than through `EngineRunner`.

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
| `afl-cmin` | `<binary> @@` |
| Reproduction | `<binary> <input>` |

All five forms must be built through `hf-engine::afl`'s typed input-delivery
helpers. Omitting `@@` selects AFL++'s stdin mode and is a contract violation.

### 3.3 Per-Input Timeout

`FuzzRunConfig.input_timeout` carries the resolved per-input timeout (one input
running longer is a hang finding). `hf-service` resolves it before launch: the
CLI `--timeout-ms` override, else `fuzzing.default_timeout_ms` (default
1000 ms), range-checked to `1..=3600000`. The user-facing unit is milliseconds
because AFL++ is millisecond-granular; engines that take whole seconds round
up, never to 0 (libFuzzer reads `-timeout=0` as "no timeout").

| Engine | Timeout knob | Unit |
| --- | --- | --- |
| AFL++ | `afl-fuzz -t <ms>` (every instance in a parallel run) | milliseconds, exact |
| libFuzzer | `-timeout=<s>` | seconds, rounded up |
| honggfuzz | `--timeout=<s>` | seconds, rounded up |
| syzkaller | none (syz-manager config has no per-input knob; per-program timing is syz-executor internal) | emit nothing |
| go-native | none (`go test -fuzz` has no per-input timeout flag) | emit nothing |

An adapter emits the flag only when `input_timeout` is `Some`; `None` (internal
probes such as smoke qualification, and runs persisted before timeouts were
recorded) keeps the engine's built-in default. AFL++'s auto-calculated timeout
is deliberately not used: the knob is always explicit.

Precedence over `extra_args`: an explicit `input_timeout` is emitted *after*
`extra_args`. All three userspace engines apply the last occurrence of a
repeated flag, so the configured timeout is never silently overridden by the
escape hatch; when `input_timeout` is `None`, `extra_args` remains the only
source of a timeout flag.

Hang findings surface as `EngineStats.hangs` (AFL++ `saved_hangs` from
`fuzzer_stats`, honggfuzz's `Timeouts` tick) and in the run summary's `hangs`
count, which additionally counts libFuzzer's `timeout-*` artifacts.

### 3.4 AFL++ Session Resume

`FuzzRunConfig.resume` (default `false`; resolved by `hf-service` from
`--resume` over `fuzzing.default_resume`) continues the most recent compatible
AFL++ output tree instead of cold-starting. The earlier decision -- never
resume, staging always builds a fresh tree -- is revised: fresh staging stays,
but a resume-enabled run's staging first receives a bounded host-side copy of
the donor tree, so every run still owns its complete evidence directory.

The mechanism is deliberately **not** `-i -`:

- The service copies the donor tree (instance queues and `.state`
  bookkeeping, `fuzzer_stats`, crashes/hangs, `_resume` leftovers) into the
  new run's fresh `out` directory, bounded to 32 MiB / 100 000 files with
  symlinks rejected.
- `hf-engine::runner` injects `AFL_AUTORESUME=1` into the sandbox environment
  when `cfg.resume` is set. Per `afl-fuzz`'s `handle_existing_out_dir`, this
  resumes each instance whose directory holds a `fuzzer_stats` and cold-starts
  any instance added by a grown `--cpus` allocation. `-i -` cannot express
  that mix: it FATALs on a launched instance whose directory is missing, and
  on a missing tree ("Resume attempted but old output directory not found"),
  so it would break exactly the cold-start fallback resume requires.
- The argv is identical between cold start and resume; resume is
  environment-driven and never an argument.

The typed field is the only source of resume truth. The AFL adapter rejects a
hand-passed `-i -`/`-i-` in `extra_args` in **both** resume states: without
`resume` it would be a hidden resume, and with it the flag would duplicate the
builder's own `-i <corpus>` (afl-fuzz refuses multiple `-i` options), so there
is no state in which a hand-passed `-i -` is valid under this mechanism. The
runner likewise rejects a hand-set `AFL_AUTORESUME` in `cfg.env`.

Donor identity (what "the same fuzzing session" means): newest terminal
(Done/Failed/Cancelled) AFL++ campaign run in the same target workspace whose
recorded `binary_rev` equals the new run's staged harness binary digest and
whose on-disk tree holds at least one instance with `fuzzer_stats` plus a
`queue/` or `_resume/` directory. Smoke runs, in-flight runs, other engines,
and other harness revisions are never donors; no donor means a cold start
(journaled), and a donor tree over the copy ceiling is a loud error.

`replay` never resumes: the retained config's `resume` is cleared on the
replay path, so an exact re-execution cannot silently become a session
continuation. The CI gate (`run_ci_gate`) pins resume off for the same reason
-- a gate verdict must measure the current tree, not a session's carried
crashes.

### 3.5 Sanitizer Selection

The sanitizer is baked into the harness binary at build time. The build-side
flag mapping lives in `hf_harness::build_command` (the operation that makes
the build, so no caller can bypass it), and the harness revision records the
choice in its persisted `Harness.sanitizer`. A run never selects a sanitizer
of its own: `FuzzRunConfig.sanitizer` records the promoted harness's build
sanitizer, and an explicit per-run request (CLI `--sanitizer`) is a constraint
checked against it -- a mismatch fails before any engine starts. The
configured `fuzzing.default_sanitizer` applies to NEW builds only, never as a
run-time default.

Flag mapping for C/C++ harnesses (all verified against the pinned sandbox
image: clang 18.1.3, AFL++ 4.09c wrapping clang 17.0.6, honggfuzz 2.6):

| Sanitizer | libFuzzer (`clang`) | AFL++ (`afl-clang-fast`) | honggfuzz (`hfuzz-cc`) |
| --- | --- | --- | --- |
| `address` (default) | `-fsanitize=fuzzer -fsanitize=address` | same flags (afl-cc passes `-fsanitize` through to clang) | `-fsanitize=address` |
| `undefined` | `-fsanitize=fuzzer -fsanitize=undefined -fno-sanitize-recover=undefined` | same flags | `-fsanitize=undefined -fno-sanitize-recover=undefined` |

Decisions and their evidence:

- **Halt-on-error**: `-fno-sanitize-recover=undefined` makes a UBSan finding
  terminate the process so the engine records a crash; the recoverable
  default would log and continue past the bug.
- **AFL++ builds pass the flags directly.** AFL++ 4.09c's documented
  `AFL_USE_UBSAN=1` expands to `-fsanitize=<checks>
  -fsanitize-trap=<same checks>`: trap mode kills the process (SIGILL) with
  NO diagnostics, so the `runtime error:`/`SUMMARY: UndefinedBehaviorSanitizer`
  lines the triage pipeline classifies would never exist. The passthrough
  build keeps the full report and still aborts (verified: afl-fuzz saved the
  finding as `sig:06`).
- **The runner never presets `UBSAN_OPTIONS` for AFL++/honggfuzz runs.** Both
  engines auto-configure sanitizer `abort_on_error` when they detect
  instrumentation; a preset `UBSAN_OPTIONS` suppresses that, turning UBSan's
  `Die()` (exit code 1, no signal) into a non-crash the signal-based engines
  never save (verified: AFL++ 4.09c saved 0 crashes with a preset, 1 without).
  For the direct libFuzzer run (exit-code based crash detection) the runner
  injects `UBSAN_OPTIONS=print_stacktrace=1` unless the operator set one, so
  reports carry frames for the dedup signature.
- **Rust is AddressSanitizer-only** on this pipeline: cargo-fuzz
  (libfuzzer-sys) has no UBSan/MSan/TSan path, so a non-`address` selection
  fails loud at the build constructor (and before any LLM drafting).
- **`memory`, `thread`, and `none` are rejected, not ignored.** MSan needs a
  fully instrumented libc/userspace (the sandbox's Ubuntu 24.04 runtime is
  not MSan-instrumented, so its findings would be false positives); TSan
  data-race reports do not map onto the crash-triage pipeline; and a
  sanitizer-less build has no sanitizer evidence to classify. syzkaller
  kernel builds take no userspace sanitizer (KASAN/UBSAN are kernel-image
  configuration).

Sanitizer is part of run identity wherever runs are compared or continued: the
auto-revert baseline check and comparison key include it, the change-impact
comparability gate refuses `DifferentSanitizer`, and the AFL++ resume donor
match keys on the staged binary's SHA-256 (a sanitizer change produces a
different binary, so a UBSan run never resumes an ASan session tree).

The environment comparison in the auto-revert baseline check and comparison
key ignores service-assigned run-scoped destinations (`LLVM_PROFILE_FILE`):
their values differ per run by construction, while an operator-set environment
difference still makes two runs incomparable. The per-run seed is not part of
either comparison; the revision gate, not the seed, attributes a coverage
change to the harness.

### 3.6 AFL++ CmpLog/Redqueen

CmpLog is AFL++'s answer to magic-byte and multi-byte comparison gates: a
second build of the same harness source compiled with `AFL_LLVM_CMPLOG=1`
logs every comparison operand, and `afl-fuzz -c <companion>` runs redqueen
input-to-state solving over it (AFL++ 4.09c,
`instrumentation/README.cmplog.md`).

**Build side.** `hf_harness::cmplog_build_command` constructs the companion
`BuildCommand`: the same afl-clang-fast driver, sanitizer flags, and project
flags as the main build, writing `<main output>.cmplog` beside the main
binary. The companion carries the sanitizer flags so the comparisons it logs
come from the same binary semantics; it never produces findings of its own.
The constructor rejects non-AFL++ engines and languages AFL++ cannot drive,
and the compile operation refuses a companion record on a non-AFL++ harness
(Engineering Protocol 2.19). `try_compile_with_options` compiles the
companion in the same sandbox with `AFL_LLVM_CMPLOG=1` in the compile
environment (the one place that variable is set; it is the definition of a
CmpLog build) and records the exact companion digest on the harness revision
(`Harness.cmplog: Option<CmpLogCompanion>`). The revision's persisted CmpLog
record is immutable, like its source and main build command.

**Run side.** `FuzzRunConfig.cmplog` (default `false`, per-run opt-in via
`--cmplog`; there is deliberately no `[fuzzing] default_cmplog` -- CmpLog
slows every interesting-input pass, so opting in is a per-run decision, not a
deployment default). An explicit request on a non-AFL++ engine fails at
policy resolution. When set, the service requires the promoted harness
revision to carry a completed companion record, verifies the workspace
companion against the recorded digest (stale or tampered fails closed), and
stages it into the run's retained inputs as `input/harness.cmplog` -- the
retained-inputs manifest binds its exact bytes, so a replay re-executes with
the identical companion. A missing or mismatched companion fails before any
sandbox launch, naming the build that produces one (`oxfuzz harness --target
<target> --engine afl++ --cmplog`).

The AFL adapter emits `-c <binary>.cmplog` when `cfg.cmplog` is set
(the suffix rule's one home is `hf_engine::afl::cmplog_binary_path`), after
`extra_args` and `-t`, before `--`. A hand-passed `-c` in `extra_args` is
rejected in both states, exactly like the resume rule: the typed config is
the only source of CmpLog truth.

**Parallel mode.** In the multi-instance coordinator, the `-M` primary never
carries `-c` and every `-S` secondary does. This follows AFL++ 4.09c
`docs/fuzzing_in_depth.md` 3c, which puts CmpLog/redqueen on secondaries
("one or two") while the main instance fuzzes the plain build; our
coordinator runs homogeneous workers with no other per-instance variation to
reserve cores for, so an opted-in run gives every secondary the companion. A
single-instance run takes `-c` on its one instance, which 4.09c accepts.

**Identity and comparability.** A CmpLog run is a different experimental
setup: `cmplog` is part of the auto-revert baseline check and the comparison
key, and the run record's persisted config carries it. Run summaries and the
run journal note an active CmpLog run, since its exec/s is not comparable
with a plain run's (cost visibility; the run is the same authorized sandboxed
run, so no new guardrail action exists). Edge-set capture (`run_edge_sets`),
replay, showmap, and minimization keep reading the MAIN staged binary; the
companion is never a replay target.

**Deliberate omissions.** `AFL_CMPLOG_ONLY_NEW` is not set (base CmpLog
covers the initial corpus too; the lighter mode is for large carried
corpora/CI and can be revisited when those exist). The `-l` CmpLog level knob
(`2AT` transform-following, scale mode) is not emitted; level 1 is the
feature's base.

### 3.7 AFL++ afl-cmin Batch Distillation

`oxfuzz corpus --op afl-cmin` reduces an AFL++ target's whole corpus to a
minimum covering set in ONE sandboxed `afl-cmin` invocation, next to the
per-input `afl-showmap` fingerprinting of `--op cprune` (one container spawn
per input, capped at 10 000 inputs). The op name spells the tool because
`cmin` is already the libFuzzer `minimize` alias. The batch tier is explicit
and never auto-selected: `cprune` answers "one input per whole-map
fingerprint", afl-cmin answers "smallest set covering every observed tuple",
and corpus size must not silently choose between them.

The argv is built by `hf_engine::cmin::build_cmin_args` against the pinned
interface (the sandbox image's Ubuntu `afl++` 4.09c-1ubuntu3 package ships
`/usr/bin/afl-cmin`; its usage line is `afl-cmin [options] --
/path/to/target_app [...]`):

```text
afl-cmin -i <corpus> -o <out> -m none -t <ms> [-T <tasks>] -- <binary> @@
```

- `-t` carries the resolved per-input timeout in exact milliseconds (the
  policy's `fuzzing.default_timeout_ms` for an internal corpus operation),
  the same granularity `afl-fuzz -t` takes (§3.3).
- `-m none` is always explicit. Promoted harnesses are sanitizer builds (ASan
  by default, §3.5), and any megabyte cap kills ASan's shadow-memory
  reservation; the script's own default is also `none`, and an explicit flag
  cannot be silently re-defaulted.
- `-T <tasks>` is emitted only when the resolved sandbox CPU allocation is
  greater than one: afl-cmin 4.09c rejects `-T 1` (its "between 1 and nproc"
  check reads strictly greater than one), so a one-CPU allocation keeps the
  sequential default path. The value never exceeds the sandbox CPU ceiling.
- The target argv is the §3.2 file-input contract (`<binary> @@`), the same
  form `afl-fuzz` and `afl-tmin` take.
- `-A`/`-C` are never passed. afl-cmin's default drops inputs that crash or
  time out from the distilled set (afl-showmap writes an empty trace for
  them); crash reproducers are triage-owned and re-enter the corpus through
  `corpus absorb`. With `-A`, a binary that crashes at entry on every input
  would trace everything identically and collapse a large corpus toward one
  file -- the garbage-adoption failure this op exists not to have.
- `-e` is never passed: hit-count-sensitive tuples match the bucket-sensitive
  fingerprints `hf_engine::showmap::coverage_hash` uses.

Execution and adoption live in `hf-service` (`corpus_afl_cmin`), mirroring
`corpus_minimize`: the exact promoted, smoke-qualified AFL++ harness and a
run-scoped corpus snapshot are digest-verified before launch; the sandbox
gets an immutable workspace, the snapshot mounted **writable** (afl-cmin
4.09c writes a `.afl-cmin.test` hardlink probe into its input directory) and
a bounded writable output; a live output monitor plus the sandbox wall clock
bound the run to the same 10-minute budget coverage pruning gets. The
distilled tree is validated on the host before adoption: it must be
non-empty and every survivor must be byte-identical (SHA-256) to a pre-run
corpus entry, since afl-cmin copies or hardlinks survivors verbatim; then
`hf_corpus::minimize` re-validates the flat regular tree and adopts it
through fresh-inode atomic writes. Any failure -- non-zero exit, empty or
foreign output, budget overflow, adoption error -- keeps the retained corpus
untouched (with rollback from the pristine snapshot), so a failed or garbage
run can never empty the corpus.

## 4. Progress Streaming

For userspace runs, `EngineRunner` forwards `FuzzProgress` events as a run
executes and returns the final progress and coverage evidence. The events are
`ExecsPerSec`, `EdgesCovered`, `CrashesFound`, `LogLine`, `Stats`, and `Done`;
`Done` is the successful terminal event. `Stats` carries an engine-neutral
snapshot (`EngineStats`, all fields optional): cumulative executions, corpus
size, cycles, stability, hangs, last-find age, and uptime as the engine
reports them. The scalar variants keep flowing for aggregation and health
telemetry; `Stats` is additive and may re-state the same measurement. Adapters
supply the command whose stdout/stderr the runner parses into those events.
The direct service-owned syzkaller path uses the same event types and emits
`Done` on successful completion.

For AFL++, stdout/stderr parsing is live-log telemetry only. During a run, the
service polls the run-owned output tree's `fuzzer_stats` (host-readable
through the bind mount) and streams each changed snapshot as a `Stats` event.
Persisted terminal statistics must be read from that run's exact
`default/fuzzer_stats` file with the bounded `hf-engine::afl::read_fuzzer_stats`
API; the same read at run close emits the closing `Stats` snapshot. Consumers
must not scan a target-wide output directory or infer final AFL++ counters
from UI text.

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
| syzkaller | `<run_dir>/crashes/<hash>/` | `description`, `report*`, `repro.prog`, `repro.cprog` |

A nested layout such as `<run_dir>/crashes/<crash_id>/{input,log.txt}` is NOT
ingested by the userspace path: directories under the crash root are skipped
(AFL++ instance directories are the one exception, and only their immediate
`crashes/` child is scanned). A userspace adapter that receives a per-crash
directory layout from its engine MUST flatten the input files into the
locations above.

### Syzkaller is the exception, and has its own path

`syz-manager` owns the kernel-campaign workdir and writes one directory per
distinct bug, so a syzkaller campaign cannot flatten its output the way a
userspace adapter must. It is ingested by `hf_crash::ingest::ingest_syzkaller`,
not by `ingest_for_engine`, and the two do not share a code path:

- The walk descends one level into `crashes/<hash>/` and takes the first
  `report*` body, using `repro.prog` / `repro.cprog` as the crash input when
  `syz-manager` reproduced the bug and the report itself when it did not.
- The reports are kernel oops text, not sanitizer logs, so they are parsed by
  `hf_crash::kernel` and classified as `CrashKind::KernelBug` with the specific
  class (KASAN, KMSAN, KCSAN, `BUG_ON`, `WARN_ON`, fault, hung task, panic) in
  the summary. `hf_crash::classify` is not involved.
- Signatures come from kernel call-trace symbols with offsets, addresses, and
  compiler suffixes stripped, and with the reporting machinery
  (`dump_stack`, `kasan_report`, ...) skipped -- otherwise every KASAN bug
  would share a top-of-stack and dedup would collapse distinct bugs.

This is a deliberate second path rather than an extension of the first: a
kernel finding must not inherit userspace assumptions
(`docs/design/patch-to-proof-design.md`).

Sanitizer/engine logs are optional siblings of the input file, matched by
name convention (`log-<stem>.txt`, a stem-named `report-*`/`sanitizer-*`
file, or an unambiguous `report.txt`/`stderr.txt` when a directory holds a
single crash). A crash without a matched log ingests as `CrashKind::Other`.

## 6. Registration

The registry contains one built-in adapter per `EngineKind`. For userspace
workflows, `hf-service` confirms runtime toolchain availability before it
delegates the selected adapter argv to `EngineRunner`. Syzkaller remains
registered but uses the service-owned manager-config execution path described
above. Engine policy is not currently user-editable; a TOML registry must not
be exposed until `hf-service` owns and applies a typed loader for it.

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
