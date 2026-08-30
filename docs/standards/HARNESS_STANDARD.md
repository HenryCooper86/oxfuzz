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
6. **Smoke fuzz passes** -- 60s run, no crash on empty input, execs/sec > 0.

## 2. Static Rules

Requirement 3 above, and the process and network half of requirement 2, are
checked before the harness reaches the sandbox by
`hf_harness::lint_harness_source`. The check is lexical, deterministic, and
free: no model call and no container. It covers C and C++; other languages have
no rule set yet and return no findings, which means unchecked rather than clean.

An `Error` finding blocks the build and is handed to the repair loop in section
5 as if it were compiler output. That is strictly cheaper than building first,
and it catches a class of defect the compiler accepts happily. A `Warning` is
recorded on the compile outcome and surfaced to the operator without blocking.

| Rule | Severity | Why |
| --- | --- | --- |
| `no-process-exit` | Error | `exit`/`_exit`/`abort` on malformed input makes every such input look like a crash and ends the fuzz process. |
| `no-shell` | Error | `system`/`popen`/`exec*` move execution outside the sandbox that is measuring the target. |
| `no-sleep` | Error | Sleeping in the fuzz loop destroys throughput, and a slow input is reported as a hang. |
| `no-network` | Error | A socket reaches outside the sandbox and makes the result depend on a service the run does not control. |
| `no-signal-handler` | Warning | A handler can swallow the fault the sanitizer exists to report. |
| `no-nondeterminism` | Warning | A clock or RNG branch makes a crash irreproducible and breaks corpus minimization. |
| `no-catch-all` | Warning | `catch (...)` hides target failures the fuzzer exists to observe (C++ only). |
| `no-strlen-on-fuzz-data` | Warning | Fuzz input is not NUL-terminated, so treating it as a C string reads out of bounds inside the harness itself. |

Each call rule requires a non-identifier character before the name and an
opening parenthesis after it, so `exit_code` and `parse_time` are not calls.
Comment-only lines are skipped; a rule name in a string literal or a trailing
comment still matches, which is the safe direction for findings that only
advise a repair prompt.

Two deliberate omissions. File I/O is not a rule: an AFL++ file-mode harness
must open `argv[1]`, so the rule would fire on correct code, and a check with
false positives on the common case gets ignored. The lint is not feature-gated:
a safety check that a build configuration can remove is not one.

## 3. Naming

- Source file: `fuzz_<symbol>.<ext>` in `fuzz_workspace/harnesses/<target>/`.
- Build artifact: `fuzz_<symbol>_<engine>` binary.

## 4. Templates

Templates live in `config/prompts/harness_<lang>_<engine>.md`. They contain:

- The engine entry point skeleton.
- Include/import guidance, and the project's real include directories, defines,
  and language standard when it ships a compile database (see
  `docs/design/harness-generation-design.md` section 3).
- Compiler definitions are portable values only: embedded Unix, UNC, and
  drive-qualified Windows absolute paths are excluded before persistence or
  model use, while relative values and non-file URIs remain valid.
- A placeholder for the LLM to fill the target call.
- Safety assertions (no `system()`, no file writes). Section 2 enforces these
  rather than trusting the template to have carried them.

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
