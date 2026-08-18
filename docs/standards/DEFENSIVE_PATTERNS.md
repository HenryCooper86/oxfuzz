# Defensive Patterns

Status: **active**. Scope: entire repository.

Bug-class rules for lifecycle, concurrency, subprocess, sandbox, and teardown
code. Each rule states a defect class and the practice that prevents it.

oxfuzz supervises untrusted code: fuzz targets are attacker-influenced by
construction, engine binaries are not trusted, and crash artifacts are produced
by the thing under test. Every rule is stated in that setting.

Several of these rules are already the established practice in this workspace.
Where that is so, the rule cites the code that implements it, and the standard's
job is to keep new code consistent with it rather than to report a defect. Where
a gap is named, it was confirmed by reading the source, not inferred.

Adapted from the `defensive-patterns` document in DeepSeek Harness
(`deepseek-ai/deepseek-harness`, MIT). Two of its seven rules do not transfer to
Rust unchanged and are restated below; see `docs/design/deepseek-harness-study.md`
for the full comparison. Test-tier counterparts are in `TEST_STRATEGY.md`.

## 1. Report orthogonal outcomes independently

A run can be several things at once. A fuzzer that traps `SIGTERM` on a duration
cap exits `0`. A container that is OOM-killed exits non-zero with no crash. Exit
status is meaningless until the terminal outcome is known.

**Established here.** `hf-runtime` returns one explicit terminal outcome --
`Completed`, `TimedOut`, or `Cancelled` -- and `runtime-design.md` section 5
states that exit status is authoritative only for `Completed`.
`hf-engine::runner` branches on `CommandTermination` before it reads
`exit_code`. New adapters and new callers follow that shape: never nest one
fact's report inside another's branch.

**Open gap.** The terminal outcome does not yet distinguish *the sandbox refused
the operation* from *the runner never started it*. Spawn errors, invalid
workspace paths, and failed forced teardown are all sandbox errors today. Those
are different facts: "the command never ran" and "confinement blocked it" lead
to different operator actions, and conflating either with a genuine target
crash produces a false finding. See the denial-classification design document
before extending the outcome enum.

## 2. Honor public contracts on both sides

When an implementation can express one outcome in several representations,
normalize before returning through the public API, and document the normalized
contract where the type is defined.

A caller must never have to guess whether a failure came from the adapter, the
container, the engine, or its own parsing. Defects in oxfuzz's own code stay as
`Err`; outcomes of the supervised process are values, not errors. Exercise every
source form through the real consumer, not through a unit test of the
normalizer alone.

## 3. Async state is not synchronous state

"Is the campaign finished" is not answerable from a status flag. A scheduled
occurrence, a resumed WAL replay, an operator cancellation, and a duration cap
can share one running interval; a background triage can complete across a run
boundary.

A caller that owns a run defines its interval explicitly -- for example, from
the durable occurrence receipt through the next whole-campaign idle -- and
describes anything it collects as interval-wide, not causally attributed to one
request. The rule cuts both ways: if the awaited transition can never occur, the
wait hangs, so handle the "nothing to wait for" branch explicitly.

Applies to: `hf-scheduler`, `hf-service::recovery`, `hf-session` checkpointing.

## 4. Dispose must reach quiescence, not just request it

Teardown that issues a kill and returns before the work stops leaves orphans. An
AFL++ process tree that outlives its container holds a core until the host is
rebooted; a detached `docker exec` keeps writing into a workspace the service
believes it has released.

**Established here.** `hf-runtime` gives each run a unique container name so
teardown can target it reliably, and treats a failed forced teardown as a
sandbox error rather than a silent success.

The rule for new code: cleanup is async and awaits the child's exit rather than
only requesting it, and closes progress and notification registries **before**
killing, so late output from a dying engine cannot resurrect state a caller
already considers released.

## 5. Contain listener panics in the dispatcher

A progress subscriber that panics must not poison the run that feeds it or
starve the subscribers after it. Catch at the dispatch boundary, log with the
subscriber's identity, and continue. One disconnected SSE client never ends a
campaign.

Applies to: `hf-web` SSE fan-out, `hf-service` progress broadcast, `hf-agent`
event listeners.

## 6. Never hand a spawned process the ambient environment

**Established here, for the path that matters most.** A sandboxed container's
environment is built explicitly: `hf-runtime` starts from an empty default map
and emits only `--env=K=V` flags for values the configuration names. Docker does
not forward the host environment, so a generated harness or a fuzzer running
inside the sandbox never sees `HF_PROVIDER_API_KEY`. Keep it that way: the
container environment is an allow-list, never a passthrough.

**Host-side helpers were the gap, and it is closed.** They inherit everything by
default, so the `docker` CLI, `git` in the workbench, `pandoc` in report export,
and the DefectDojo lifecycle commands all used to start with the full parent
environment. Trusted binaries, which is why this was a gap and not an incident,
but the blast radius of a bug or a compromised tool in that set is every secret
the process holds.

`hf-runtime::process_env` is the one home for the rule. `scrubbed_command` and
`scrubbed_tokio_command` build a command whose environment is the parent's minus
every variable whose name matches `KEY`, `SECRET`, `TOKEN`, or `PASSWORD`
(case-insensitively), plus the `HF_` prefix so a nested oxfuzz cannot silently
adopt its parent's workspace root or provider routing. `PATH`, `HOME`, locale,
and proxy settings survive: a helper that cannot find its own binary is not
safer, only broken. The match is deliberately broad -- `MONKEY` contains `KEY`
and is dropped -- because a false positive drops a variable a child did not need
while a false negative leaks a credential.

Every host-side spawn goes through one of those two constructors. Constructing a
`Command` directly anywhere outside `process_env` and outside a test module is
the defect this rule names, and the two constructors exist as a pair precisely
so that an async call site has no reason to hand-roll the rule and drift from
it. A caller that genuinely needs a credential forwards it explicitly with
`Command::env` afterwards, which keeps the exception visible at the call site
and greppable across the workspace. Presentation crates reach the constructor
through `hf-service`'s re-export rather than depending on `hf-runtime` directly.

Temp, corpus, crash, and spill directories use a private (0700) root, random
names, and exclusive owner-only creation. Predictable, world-readable paths
invite symlink races and disclosure -- from a fuzz target that is specifically
being encouraged to do surprising things with the filesystem.

## 7. Know what your deletion primitive actually does

The upstream form of this rule is a Node.js hazard: `fs.rmSync(path, {recursive:
true})` can descend through a junction into its target, so a link-shaped path
must be removed with `lstat` plus `unlink` instead.

**That hazard does not transfer to Rust.** `std::fs::remove_dir_all` does not
follow symbolic links: it removes a link itself rather than its target, and on
Unix it walks with `openat` so a component swapped mid-walk cannot redirect it.
A top-level path that is a symlink to a directory produces an error rather than
a deletion of the target.

The rule that does transfer is the reason behind it: **know the traversal
semantics of the primitive you chose, and do not assume they are the same across
languages, platforms, or crates.** A hand-rolled recursive walk, a
`walkdir`-based delete, or a crate that reimplements removal has to re-establish
what `std` gives for free. `hf-corpus`, `hf-crash`, `hf-discovery`, `hf-engine`,
`hf-harness`, and `hf-runtime` already use `symlink_metadata` rather than
`metadata` when a link must not be followed; that is the pattern for any walk
this workspace writes itself.

The one production recursion over tool-created content is the syzkaller staging
cleanup in `hf-service::syzkaller`, which removes `inputs`, `scratch`, and
`workdir`. It is safe today because it uses `std`. It would stop being safe the
moment it were reimplemented.

## 8. Check and use the same object

A path that was validated and a path that is then opened must be the same
resolved object, not the same spelling. Re-canonicalize immediately before the
operation and pass the freshly resolved path to it.

Never lexically normalize a path that feeds an enforcement decision: `..`
collapsed before a preceding symlink is resolved names a different target than
the kernel will open. Use `std::fs::canonicalize`, which is syscall-based, and
compare canonical prefixes on a separator boundary.

**Established here.** `hf-runtime` resolves the real filesystem path before a
workspace is mounted, read, or written, validates missing paths through their
nearest existing parent, and fails closed on parent traversal and symlink
escape.

The residual race -- an ancestor swapped between canonicalization and the
syscall -- is narrowed, not closed. Say so where the check lives, and do not
describe an in-process path check as a kernel boundary. `hf-runtime` is the
kernel boundary; `hf-tools`' project-root confinement is a policy check over a
model-controlled path.

## Verification

A rule is enforced only when a test proves the violating case fails. For each
rule applied to a crate, introduce the defect, watch the test go red, then
revert. A guard that has never been seen to fail is a guard nobody has checked.
