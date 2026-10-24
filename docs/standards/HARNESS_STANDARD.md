# Harness Standard

Status: **active**. Scope: `hf-harness`, `hf-engine`, `hf-service`.

## 1. Harness Requirements

A harness is acceptable only if it satisfies all of:

1. **Engine entry point present** -- e.g. `LLVMFuzzerTestOneInput` for
   libFuzzer/AFL++, `HF_ITER` for honggfuzz, `Fuzz` function for Go.
2. **No host I/O** -- the harness does not read from or write to the host
   filesystem; all input comes from the fuzzer.
3. **Deterministic** -- same input -> same behavior (no time-based or RNG
   branches that break reproducibility).
4. **Compiles** with the selected sanitizer + engine flags in the sandbox.
5. **Independent LLM review passes before execution** -- the exact source is
   judged to exercise the target with fuzzer input and avoid unsafe side effects;
   missing or malformed review fails closed.
6. **Smoke fuzz passes** -- 60s run, no crash on empty input, execs/sec > 0, and
   the selected target function was entered when that run retained a profile.

## 2. Static Rules

Requirement 3 above, and the process and network half of requirement 2, are
checked before the harness reaches the sandbox by
`hf_harness::lint_harness_source`. The check is lexical, deterministic, and
free: no model call and no container. Rules are scoped per language: C, C++,
Rust (cargo-fuzz/libFuzzer targets), and Python (Atheris) have rule sets; a
language without one (Go) returns no findings, which means unchecked rather
than clean.

An `Error` finding blocks the build and is handed to the repair loop in section
5 as if it were compiler output. That is strictly cheaper than building first,
and it catches a class of defect the compiler accepts happily. A `Warning` is
recorded on the compile outcome and surfaced to the operator without blocking.

| Rule | Severity | Languages | Why |
| --- | --- | --- | --- |
| `no-process-exit` | Error | C, C++, Rust, Python | `exit`/`_exit`/`abort`/`sys.exit` on malformed input makes every such input look like a crash and ends the fuzz process. |
| `no-shell` | Error | C, C++, Python | `system`/`popen`/`exec*` (and Python's `os.system`) move execution outside the sandbox that is measuring the target. |
| `no-sleep` | Error | C, C++, Rust, Python | Sleeping in the fuzz loop destroys throughput, and a slow input is reported as a hang. |
| `no-network` | Error | C, C++, Rust, Python | A socket reaches outside the sandbox and makes the result depend on a service the run does not control. |
| `no-signal-handler` | Warning | C, C++ | A handler can swallow the fault the sanitizer exists to report. |
| `no-nondeterminism` | Warning | C, C++, Rust | A clock or RNG branch makes a crash irreproducible and breaks corpus minimization. |
| `no-catch-all` | Warning | C++ | `catch (...)` hides target failures the fuzzer exists to observe. |
| `no-strlen-on-fuzz-data` | Warning | C, C++ | Fuzz input is not NUL-terminated, so treating it as a C string reads out of bounds inside the harness itself. |
| `no-process-spawn` | Error | Rust | `Command::new` moves execution outside the sandbox that is measuring the target. |
| `no-catch-unwind` | Warning | Rust | `catch_unwind` hides the panic the fuzzing runtime treats as a finding. |
| `no-subprocess` | Error | Python | The `subprocess` module moves execution outside the sandbox that is measuring the target. |
| `no-random-module` | Warning | Python | A `random` branch makes a crash irreproducible and breaks corpus minimization. |
| `no-bare-except` | Warning | Python | A bare `except:` hides target failures the fuzzer exists to observe. |
| `persistent-loop-without-shm-init` | Warning | C, C++ | A `__AFL_LOOP` loop reads input through `__AFL_FUZZ_TESTCASE_BUF/LEN`, which only `__AFL_FUZZ_INIT()` backs; without it the harness runs empty iterations. |
| `persistent-shm-init-without-loop` | Warning | C, C++ | `__AFL_FUZZ_INIT()` without `__AFL_LOOP(N)` serves one input per forked child; the persistent-mode reuse never happens. |
| `persistent-mutable-global` | Warning | C, C++ | A persistent harness reuses one process for many inputs: mutable file-scope state that the per-iteration reset does not re-initialize leaks between inputs, and findings stop reproducing. |

Each call rule requires a non-identifier character before the name and an
opening parenthesis after it, so `exit_code` and `parse_time` are not calls;
path-qualified calls (`std::process::exit`, `sys.exit`, `time.sleep`) match the
same way. Comment-only lines are skipped (`//` and `/*` for the C family, `#`
for Python); a rule name in a string literal or a trailing comment still
matches, which is the safe direction for findings that only advise a repair
prompt.

The three `persistent-*` rules are structural rather than per-line call
patterns, and they apply only to a source that carries a `__AFL_LOOP` or
`__AFL_FUZZ_INIT` call (a persistent-mode harness; see section 7): the mutable
global scan keys on file-scope definitions (column 0, excluding `const`,
`typedef`, and `extern` lines), which is exactly the lexical level of the call
rules, so the warning stays advisory and a false positive costs a read, not a
blocked build. The structurally broken pairings the first two rules name are
hard compile or link failures one step later; the lint's early naming exists
for the repair loop.

Two deliberate omissions. File I/O is not a rule: an AFL++ file-mode harness
must open `argv[1]`, so the rule would fire on correct code, and a check with
false positives on the common case gets ignored. The lint is not feature-gated:
a safety check that a build configuration can remove is not one.

## 3. Naming

- Source file: `fuzz_<symbol>.<ext>` in `fuzz_workspace/harnesses/<target>/`.
- Build artifact: `fuzz_<symbol>_<engine>` binary.

## 4. Templates

Task prompts are rendered by `hf-prompt` (`crates/hf-prompt/src/render.rs`)
from built-in renderers in the binary; there is no prompt-override
configuration, and no per-language template files exist in the repository.
The harness prompt contains:

- The engine entry point skeleton.
- Include/import guidance, and the project's real include directories, defines,
  and language standard when it ships a compile database (see
  `docs/design/harness-generation-design.md` section 3).
- Previously promoted harnesses of the project as accepted examples: at most
  two, same language as the target, each source bounded, read from the
  persisted harness records. A project without promotions drafts unchanged.
- Compiler definitions are portable values only: embedded Unix, UNC, and
  drive-qualified Windows absolute paths are excluded before persistence or
  model use, while relative values and non-file URIs remain valid.
- A placeholder for the LLM to fill the target call.
- Safety assertions (no `system()`, no file writes). Section 2 enforces these
  rather than trusting the template to have carried them.

The AFL++ persistent-mode draft (section 7) embeds the canonical skeleton
verbatim instead of describing the shape: the model fills in the target's
includes, forward declaration, setup/reset bodies, and the target call. The
skeleton's one home is `hf_harness::persistent::render_harness_source`, which
the no-model heuristic draft emits directly.

## 5. Iteration Policy

- On a lint error: feed the findings back to the LLM without building (max 3
  rounds, shared with the compile budget below).
- On compile failure: feed compiler diagnostics back to the LLM (max 3 rounds).
- On smoke failure: feed engine log back (max 3 rounds).
- After 3 failed rounds: mark `Failed`, surface to user for guidance.

## 6. Promotion Gate

A Harness Work Order import creates an immutable draft and records its
deterministic lint findings without executing it. Any blocking lint finding
prevents qualification before sandbox work. Qualification binds the independent
review and smoke evidence to the exact harness id and complete source and
executable digests; it never promotes. Only an explicit promotion request for
that exact attempt can activate the revision.

A harness moves to `SmokePassed` only after its smoke evidence is persisted on
the exact active revision. That evidence records the full SHA-256 digest of the
staged source and executable plus the owning smoke-run id. Promotion and every
later campaign recompute the active source/executable digests and fail closed
if either differs from the qualified pair. A crash during smoke is useful
evidence but is not a clean pass and cannot be promoted. Only an explicit human
action moves a clean `SmokePassed` revision to `Promoted`.

Promotion also requires target-exercise evidence from that exact smoke run, read
through the retained function profile. When the run retained one, the selected
target symbol must carry a positive counter, matched by containment because
LLVM reports mangled C++ symbols. A measured run that never entered the target
cannot be promoted however clean its other evidence: it compiled and burned
cycles without exercising target code, which is the one failure the compiler,
the review, and the crash count cannot see. Promotion is a single check reached
by every transport, so a direct REST, desktop, or work-order caller cannot skip
it.

That evidence exists only when the operator left
`fuzzing.collect_function_coverage` enabled. It defaults to whether the
`proof-carrying` feature is built, because promotion reads it and a build that
can collect should not leave a C/C++ promotion unverifiable; instrumentation
costs about 4% of fuzzing throughput, measured on the qualification fixture. An
operator who turns collection off gets a promotion with no target-exercise
evidence, which the gate reports as unverified rather than as entry. Making the
evidence unconditional needs a qualification build separate from the campaign
binary; until then the check is enforced wherever the evidence exists. A revision
whose smoke evidence names no run cannot be checked at all, and is refused.

Work-order ranking retains the smoke verdict order `Pass`, `Suspect`, `Fail`,
then absent. A crash-bearing `Fail` is not a clean smoke result and is ineligible
for exact promotion. A crash-free `Suspect` remains technically eligible only
when the operator explicitly requests promotion of that exact attempt. The
advisory recommendation is to refine the harness and smoke the new revision
before promotion; ranking never promotes its winner implicitly.

Before the `RunHarness` human approval and the first smoke instruction, the
service persists a successful LLM review bound to the exact harness id and
source and compiled-binary SHA-256 values. The staged binary digest is checked
again before execution. Recompilation creates a new harness id and digests, so
it cannot inherit review evidence from the prior revision.

Every full, scheduled, CI, or agent-started `FuzzRun` must resolve the active
binary/source record and reject it unless its status is `Promoted`. Recompiling
or regenerating creates a new active revision and requires smoke qualification
and approval again. Agents and schedulers never promote revisions implicitly.

## 7. AFL++ Persistent-Mode Harnesses

The stock AFL++ harness exposes `LLVMFuzzerTestOneInput` and links AFL++'s
libFuzzer-compatible driver, which already loops in the forkserver child over
shared-memory input (`__afl_fuzz_ptr`/`__afl_fuzz_len`), with one-time init in
`LLVMFuzzerInitialize` already running before the deferred fork point. That
driver-owned loop is the right default. The persistent-mode flavor exists for
the targets it cannot serve well: a stateful target whose per-input state must
be explicitly reset, or a slow-to-initialize target whose setup placement the
harness (not the driver) must control.

A persistent-mode harness owns `main` and the forkserver loop. The canonical
skeleton (`hf_harness::persistent::render_harness_source`, emitted by
`oxfuzz harness --engine afl++ --persistent` and embedded in the LLM draft
prompt) is the AFL++ 4.09c `instrumentation/README.persistent_mode.md`
structure adapted to this pipeline's contracts:

```c
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
/* the target's headers / forward declaration */

__AFL_FUZZ_INIT();

static void oxfuzz_target_setup(void) { /* one-time init, before the fork point */ }
static void oxfuzz_target_reset(void) { /* re-initialize ALL mutable state */ }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    oxfuzz_target_reset();
    /* call the target with (data, size) */
    return 0;
}

int main(int argc, char **argv) {
    oxfuzz_target_setup();
    __AFL_INIT();                       /* deferred forkserver starts here */
    if (__afl_fuzz_ptr) {
        /* afl-fuzz / afl-showmap / afl-cmin attached the shared-memory buffer */
        unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
        while (__AFL_LOOP(oxfuzz_loop_count())) {
            size_t len = __AFL_FUZZ_TESTCASE_LEN;
            LLVMFuzzerTestOneInput(buf, len);
        }
        return 0;
    }
    /* standalone: replay each argv file once (the crash-replay form) */
    for (int i = 1; i < argc; i++) { /* read file, call the entry */ }
    return 0;
}
```

The discipline the shape must keep:

- **State reset is the contract.** `__AFL_LOOP(N)` serves N inputs in one
  process. Every mutable global/static the target or harness keeps between
  calls must return to its initial value before each target call, or state
  leaks between inputs and crashes stop reproducing (the classic persistent
  false-positive class). The `persistent-mutable-global` lint warning names
  file-scope mutable definitions so the author cannot miss the obligation;
  the reset body is the one section of the skeleton that is never optional.
- **One-time setup sits before `__AFL_INIT()`.** The deferred forkserver
  clones the process at that point, so setup cost is paid once per child (N
  inputs), not once per input. Setup must not read the fuzzed input, start
  threads, or open stateful handles the children would share (AFL++'s
  deferred-forkserver restrictions).
- **The loop count is named and bounded.** The skeleton defaults to 1000
  (`hf_harness::persistent::DEFAULT_LOOP_COUNT`, AFL++'s recommended starting
  point within its 100-10000 guidance) and honors the `AFL_FUZZER_LOOPCOUNT`
  environment override clamped to 1..=100000 -- the same knob the AFL++ driver
  documents and the function-coverage proof path already sets to 100 on
  profiled AFL++ campaigns so forkserver children exit and flush their LLVM
  profile counters regularly. The harness's own child exit every N iterations
  provides that flush even where the override is absent (smoke qualification).
- **The build drops the libFuzzer driver.** `__AFL_FUZZ_INIT()` and the driver
  both define `__afl_sharedmem_fuzzing` strongly, so a persistent source
  compiles with afl-clang-fast but WITHOUT `-fsanitize=fuzzer`. The build
  variant derives from the source's structure
  (`hf_harness::build_command_for_source` detects the `__AFL_LOOP` /
  `__AFL_FUZZ_INIT` call markers); every compile path -- CLI draft, GUI/REST
  source, work-order import -- gets the matching build with no separate flag,
  and a persistent source paired with the driver or a non-AFL++ engine fails
  at compile with the fix named rather than at the linker. Both wrong
  pairings fail loudly; a lint-undetected shape never misbuilds silently.

Run-time contracts a persistent harness must keep (all hold for the skeleton;
they are why the run path needs no flavor-specific argv):

- Fuzzing runs the unchanged `afl-fuzz ... -- <binary> @@` form
  (`docs/standards/ENGINE_ADAPTER_STANDARD.md` 3.2): afl-fuzz detects the
  shared-memory capability in the forkserver handshake, unlinks the `@@`
  output file, and delivers inputs through shared memory.
- Crash replay (`binary <input>`), `afl-showmap`, and `afl-cmin` keep working:
  with no fuzzer attached, `__afl_fuzz_ptr` is null and the standalone branch
  replays each file argument once; under the showmap/cmin forkserver the
  shared-memory branch serves one iteration per input.

The flavor is AFL++ + C/C++ only (`require_persistent_support` rejects other
engines and languages before any drafting), and is a per-invocation opt-in
with no `[fuzzing]` config default, like CmpLog. Smoke qualification, the
independent review, and the promotion gate are unchanged: a persistent harness
earns `SmokePassed` and `Promoted` through exactly the sections above.

