# Defensive Patterns

Status: **active**. Scope: entire repository.

Bug-class rules. Each pattern below is a class of defect that ships silently,
stated as the rule that prevents it. Read this before writing lifecycle,
concurrency, subprocess, sandbox, or teardown code.

oxfuzz supervises untrusted code: fuzz targets are attacker-influenced by
construction, engine binaries are not trusted, and crash artifacts are produced
by the thing under test. Every rule below is stated in that setting.

Adapted from the `defensive-patterns` document in DeepSeek Harness
(`deepseek-ai/deepseek-harness`, MIT), which states each rule as a defect class
that actually shipped there. See `docs/design/deepseek-harness-study.md` for the
full comparison. Test-tier counterparts are in `TEST_STRATEGY.md`.

## 1. Report orthogonal outcomes independently

A run can be several things at once. A fuzzer that traps `SIGTERM` on a duration
cap exits `0`; a container that is OOM-killed exits `137` with no crash; a
harness that genuinely faults exits on a signal the sandbox did not send.

Surface each independent fact on its own field -- `timed_out`, `signal`,
`exit_code`, `oom_killed`, `denied_by_sandbox` -- and never nest one fact's
report inside another's branch. A caller that reads a cut-short campaign as a
clean completion records a false negative; a caller that reads a duration cap as
a crash records a false positive. Both are worse than an error.

```rust
// Wrong: the timeout branch hides the exit status.
if timed_out { RunOutcome::TimedOut } else { RunOutcome::Exited(code) }

// Right: independent facts, decided by the consumer.
RunOutcome { timed_out, signal, exit_code, oom_killed, denied_by_sandbox }
```

Applies to: `hf-runtime` container results, `hf-engine` adapter results,
`hf-harness` build and smoke results.

## 2. Honor public contracts on both sides

When an implementation can express one outcome in several representations,
normalize before returning through the public API, and document the normalized
contract where the type is defined.

A `RuntimeAdapter` may fail by returning `Err`, by returning a non-zero exit, or
by emitting a denial on stderr. Its public result must express a model-level
failure exactly one way, so a caller never has to guess whether a caught error
came from the adapter, the container, the engine, or its own parsing. Defects in
oxfuzz's own code stay as `Err`; outcomes of the supervised process do not.

Exercise every source form through the real consumer, not through a unit test of
the normalizer alone.

## 3. Async state is not synchronous state

"Is the campaign finished" is not answerable from a status flag. A scheduled
occurrence, a resumed WAL replay, an operator cancellation, and a duration cap
can share one `running` interval; a background triage can complete across a run
boundary.

A caller that owns a run must define its interval explicitly -- for example, from
the durable occurrence receipt through the next whole-campaign idle -- and must
describe anything it collects as interval-wide, not causally attributed to one
request. The rule cuts both ways: if the awaited transition can never occur,
the wait hangs. Handle the "nothing to wait for" branch explicitly.

Applies to: `hf-scheduler`, `hf-service::recovery`, `hf-session` checkpointing.

## 4. Dispose must reach quiescence, not just request it

Teardown that issues a kill and returns before the work stops leaves orphans. An
AFL++ process tree that outlives its container holds a core until the host is
rebooted; a detached `docker exec` keeps writing into a workspace the service
believes it has released.

Cleanup is async and awaits the child's exit: kill the process **group**, then
await `done`, then escalate after a bounded grace period. Close listener and
progress-notification registries **before** killing, so late completions from a
dying engine stay silent instead of resurrecting state.

Applies to: `hf-runtime` container teardown, `hf-engine` run cancellation,
`hf-service` campaign abort.

## 5. Contain callback exceptions in the dispatcher

A progress subscriber that panics must not poison the run that feeds it or
starve the subscribers after it. Wrap the dispatch loop, log the failure with the
subscriber's identity, and continue. One bad SSE client never breaks a campaign.

Applies to: `hf-web` SSE fan-out, `hf-service` progress broadcast, `hf-agent`
event listeners.

## 6. Never hand untrusted output the ambient environment or predictable paths

Spawned processes get a **scrubbed** environment. Drop every variable whose name
matches `KEY`, `SECRET`, `TOKEN`, `PASSWORD` (case-insensitive) and every
`HF_`-prefixed harness variable, then merge deliberately-forwarded values on top.
`PATH`, `HOME`, locale, and proxy settings survive.

This is not hypothetical for oxfuzz. `HF_PROVIDER_API_KEY` in the environment of
a process that runs attacker-influenced target code, whose stdout is then fed
back into an LLM prompt and persisted as evidence, is a one-line exfiltration:
any crash handler that dumps `environ` publishes the key into the transcript.

Temp, corpus, crash, and spill directories use a private (0700) root, random
names, and exclusive owner-only creation (`O_EXCL`, mode `0600`). Predictable,
world-readable paths invite symlink races and disclosure -- from a fuzz target
that is specifically being encouraged to do surprising things with the
filesystem.

Applies to: `hf-runtime` environment construction, `hf-engine` adapters,
`hf-corpus` and `hf-crash` artifact staging.

## 7. Unlink link-shaped paths; never recursively delete an unknown one

A fuzz target under a generated harness can create symlinks inside
`fuzz_workspace/`. Recursive deletion of a corpus, crash, or build directory will
follow one out of the workspace.

Remove a possibly-link path with `symlink_metadata()` plus `remove_file()`:
that deletes only the link and refuses a real directory, so it never follows the
link into its target. Reserve `remove_dir_all` for directories oxfuzz created
itself and has re-verified are real directories, not links, immediately before
the call.

```rust
// Wrong: follows a planted symlink out of the workspace.
fs::remove_dir_all(&crash_dir)?;

// Right: prove it is a real directory we own, at the moment we delete it.
let meta = fs::symlink_metadata(&crash_dir)?;
if meta.file_type().is_symlink() { fs::remove_file(&crash_dir)?; }
else if meta.is_dir() && is_within_workspace(&fs::canonicalize(&crash_dir)?) {
    fs::remove_dir_all(&crash_dir)?;
}
```

Applies to: `hf-corpus` prune, `hf-crash` artifact cleanup, `hf-runtime`
workspace reset, and any release or test-fixture cleanup script.

## 8. Check and use the same object

A path that was validated and a path that is then opened must be the *same*
resolved object, not the same spelling. Re-canonicalize immediately before the
operation and pass the freshly resolved path to it; never validate one value and
act on another.

Never lexically normalize a path that feeds an enforcement decision: `..`
collapsed before a preceding symlink is resolved produces a different target than
the kernel will. Use `std::fs::canonicalize` (syscall-based) and compare
canonical prefixes with a separator boundary.

The residual race -- an ancestor swapped between canonicalization and the
syscall -- is narrowed, not closed. Say so where the check lives, and do not
describe an in-process path check as a kernel boundary. `hf-runtime` is the
kernel boundary; `hf-tools`' project-root confinement is a policy check.

Applies to: `hf-tools` project-root confinement, `hf-runtime` bind-mount
construction.

## Verification

A rule is only enforced if a test proves the violating case fails. For each rule
adopted into a crate, add a test that introduces the defect and watch it go red
before reverting it. `TEST_STRATEGY.md` section 5 lists the gates these tests
run under.
