# DeepSeek Harness (`dsh`) -- Study and Adoption Analysis for oxfuzz

Study date: 2026-08-18.
Subject: `https://github.com/deepseek-ai/deepseek-harness` at `HEAD` (developer preview).
Comparison target: `oxfuzz` working tree at `/Users/admin/oxfuzz`.

Method: full clone of `dsh`, four parallel deep reads (architecture, agent loop,
safety model, engineering practice) against source and docs, cross-referenced
against oxfuzz's `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/design/`,
`docs/standards/`, crate layout, and CI. Every claim below cites a file.

---

## 1. What dsh actually is

`dsh` is DeepSeek's open-source agent harness: a TypeScript pnpm monorepo of
roughly 300 packages under `packages/*/*`, built on a **vendored copy of the
Cordis** dependency-injection framework (`vendor/cordis`, republished as
`@deepseek-ai/cordis` by `scripts/rescope-vendor.ts`).

Its organising claim, from `docs/architecture.md`:

> "Every part of the product is a plugin, including the model adapter, the tool
> registry, the session log, and the agent loop itself... There is no privileged
> core to patch: you extend dsh by mounting a plugin beside the others, and
> registrations are effects that unwind when their plugin unloads."

Three structural ideas carry the whole design:

1. **Capability seams.** A seam is a triple: a *Service Definition* (interface),
   a *Service Provider* (implementation), and a *Consumer* (usually a
   model-facing tool). `docs/capability-seams.md` is a generated catalogue of
   every seam -- `ctx.llm`, `ctx.fs`, `ctx.shell`, `ctx.subprocess`,
   `ctx.sandbox`, `ctx.subagents`, `ctx.compaction`, `ctx.spillStore`,
   `ctx.credentials`, `ctx.skills`, and about twenty more -- with owner,
   implementations, and direct consumers. The payoff they state: "Filesystem and
   subprocess providers share one execution world, so pointing them at a remote
   sandbox moves Bash, PTY, and LSP with them, with no provider forks." That is
   how `packages/e2b` relocates all execution into a remote microVM by
   swapping two providers.

2. **The session log is the only truth.** The invariant, verbatim from
   `AGENTS.md`: *"Model-visible <=> logged: anything that reaches a model request
   must be reconstructable from the session log; a new model-visible input
   requires a session event."* The LLM message array is **derived**
   (`deriveMessages()` over an ordered "surface" projection), never stored. Fork,
   resume, replay, telemetry, token metering, and compaction are all the same
   mechanism. A runtime invariant asserts it.

3. **Waterfall events as the only extension points.** `agent/pre-step`,
   `agent/request`, `tools/pre-execute`, `tools/execute`, `tools/post-execute`,
   `fs/write-intent`, `system-prompt/assemble` are `next()`-delegating
   waterfalls; not calling `next()` vetoes. Everything else observes.

It is worth being clear about what dsh is **not**: it is a general coding
agent harness in developer preview, explicitly "iterating rapidly" with
"COMPATIBILITY-BREAKING CHANGES", and `CONTRIBUTING.md` says outright *"We are
sorry that we cannot accept external pull requests at the moment... You may
consider this repository an idea, an official showcase, and a source of
inspiration, but not a mandate from us."* Treat it as a source of patterns,
not a dependency.

---

## 2. Shape comparison

| Dimension | dsh | oxfuzz |
| --- | --- | --- |
| Language / unit | TypeScript, ~300 npm packages | Rust, 26 workspace crates |
| Composition | Runtime plugin tree (Cordis), hot-swappable, config-driven mount | Compile-time layering, traits in `hf-core`, feature flags |
| Extension mechanism | Typed waterfall events + service seams | Trait objects + `hf-service` orchestration |
| Domain | General coding agent | AI fuzzing agent (narrow, deep) |
| Trust model | Model has bash + write; sandbox is the fence | Model has **four read-only tools**; all mutation is service-owned |
| Session state | Append-only event log; messages derived | `hf-session` tree + checkpoints; `hf-storage` transcripts |
| Approval binding | Tool name + call id only, not content-bound | Bound to the **exact harness revision**; regeneration invalidates |
| Sandbox | bwrap / Landlock / Seatbelt / Windows ACL, file effects only | Mandatory Docker `hf-runtime`, no host fallback |
| Docs discipline | Generated + verified catalogues, budgets, bilingual pairing gate | Hand-maintained design docs + alignment table |
| Tests | 6 vitest tiers, 100% per-file coverage gate | 1 `cargo test --workspace`, 80%/70% targets |

The two projects converge more than the language difference suggests. oxfuzz's
`hf-core` traits (`LlmProvider`, `Tool`, `RuntimeAdapter`, `EngineAdapter`) are
seams in dsh's sense; `hf-service`'s ownership rule is dsh's "enforce a decision
in the operation that makes it" rule. The genuine differences are (a) runtime vs
compile-time composition, (b) event-sourced session state, and (c) the amount of
machinery dsh puts behind documentation and CI.

---

## 3. Ranked adoption list

Ranking is by **(safety or correctness impact for a fuzzing agent) x (fit with
oxfuzz's existing architecture) / effort**. Tier 1 items I would do; Tier 2 are
worth a design doc; Tier 3 are speculative.

### Tier 1 -- high value, low friction

#### 1.1 Port `docs/defensive-patterns.md` as `docs/standards/DEFENSIVE_PATTERNS.md`

**Source:** `/tmp/deepseek-harness/docs/defensive-patterns.md` (33 lines, 7 rules).
**Target:** new oxfuzz standard, referenced from `AGENTS.md` section 5.
**Impact: high. Effort: hours.**

This is the single most transferable artifact in the repo. It is framed as
"hard-won bug-class rules: each pattern below is a class of defect that actually
shipped or nearly shipped here." Four of the seven land directly on oxfuzz's
threat surface:

- **Rule 1 -- report orthogonal outcomes independently.** "A process can time out
  AND exit 0 (trapped signal). Surface `timedOut`, `signal`, `exitCode` each on
  its own; never nest one flag's report inside another's branch, or a caller
  reads a cut-short run as clean success." This is precisely the fuzz-run
  reporting problem: a libFuzzer process that traps SIGTERM and exits 0 after a
  duration cap must not be recorded as a clean campaign completion.
- **Rule 4 -- dispose must reach quiescence, not just request it.** "Teardown
  that issues kills/aborts but returns before work stops leaves orphans. Make
  cleanup async and await children's exit (kill -> await `done`); close
  listener/notification registries BEFORE killing so late completions stay
  silent." oxfuzz kills Docker containers holding fuzzer process trees; an
  orphaned AFL++ tree eating a core is a real failure mode.
- **Rule 6 -- never hand untrusted output the ambient environment or predictable
  paths.** Scrubbed env for spawned commands; temp/spill files in a private 0700
  dir with random names and exclusive owner-only opens (`'wx'`, `0o600`).
- **Rule 7 -- unlink link-shaped paths.** "A possibly-symlink/junction path is
  removed via `lstat().isSymbolicLink()` then `unlink`... Reserve recursive `rm`
  for known real directories." **This is a live risk for oxfuzz specifically**: a
  fuzz target running under a harness can create symlinks inside
  `fuzz_workspace/`, and any recursive cleanup of a corpus or crash directory can
  then descend through one into the host tree.

Rules 2 (honor public contracts on both sides), 3 (async state is not
synchronous state), and 5 (contain callback exceptions in the dispatcher) are
good general Rust guidance too -- rule 3 in particular maps onto
`hf-scheduler`/`hf-service` "is the campaign done" questions.

Recommended action: write the oxfuzz version with Rust-idiomatic examples, then
audit `hf-runtime/src/docker.rs`, `hf-engine`, and `hf-corpus` against rules 1,
4, 6, 7 as the first application.

#### 1.2 Scrub secrets from every spawned process environment

**Source:** `packages/subprocess/subprocess/src/index.ts:44`:

```ts
export const SENSITIVE_ENV_PATTERN = /KEY|PASSWORD|SECRET|TOKEN/i

export function scrubbedParentEnv(): Record<string, string> { /* drop matches + DSH_* prefix */ }
```

One definition, shared by `subprocess-local` **and** the MCP stdio transport.
`PATH`/`HOME`/locale/proxy survive; explicit caller env merges *after* the scrub
so a deliberately forwarded credential still works.

**Target:** `hf-runtime` (Docker `--env` construction) and any `hf-engine`
adapter that spawns a process.
**Impact: high. Effort: hours.**

oxfuzz's own `docs/standards/TOOL_CALL_PROTOCOL.md` section 4 already admits the
gap: *"The registry does not yet provide a general secret-redaction guarantee, so
executable tools must not return credentials or other service secrets."* That is
a discipline rule where a mechanism is cheap. The specific oxfuzz hazard is
sharper than dsh's: `HF_PROVIDER_API_KEY` sitting in the environment of a process
that runs **attacker-influenced target code**, whose stdout is then fed back into
an LLM prompt. A single `env`-dumping crash handler exfiltrates the key into the
model context and the transcript. Do this one first.

#### 1.3 Adopt "spill" for oversized tool and engine output

**Source:** `packages/spill/*`, `docs/subsystems/spill.md`.
**Target:** new `hf-spill` or a module in `hf-storage`, consumed by `hf-agent`'s
result path and by `hf-service` when returning engine logs.
**Impact: high. Effort: days.**

The seam: `saveText({owner, source, suggestedName, content}) -> {locator, bytes,
retrievalHint}`. The consumer (`spill-policy`) is a `tools/post-execute`
transformer that replaces plain-text results over `maxInlineBytes` with a
head/tail preview plus a notice. Three details are the actual craft:

- The replacement is **sized so that preview + notice stays within the cap** --
  spilling can never *add* bytes.
- It **skips the `read` tool**, to avoid a read -> spill -> read loop.
- A save failure keeps the inline result rather than turning a success into an
  error (best-effort, never fail-worse).
- `spill-local` writes to `<root>/session-<sha256(id)>/<random>-<safeName>` with a
  0700 root and `open(path, 'wx', 0o600)` "so a planted symlink can't redirect
  it" -- i.e. defensive-patterns rule 6 actually implemented.

Fit for oxfuzz is unusually good, because oxfuzz's tool outputs are the biggest
in the business: ASan stack traces, AFL++ `fuzzer_stats` and plot data, llvm-cov
reports, corpus directory listings, syzkaller logs. Today these either blow the
4,000-token prompt budget (`docs/design/agent-prompt-security-design.md` section
4) or get truncated with information loss. A locator-plus-preview lets the model
ask for the part it needs, and keeps the full artifact as retained evidence --
which oxfuzz already promises in its README ("Retained Evidence").

#### 1.4 Make guardrails monotonic: deny-only, no allow verb

**Source:** `packages/core/tools/src/index.ts:704`, `:1101-1124`, and
`docs/tool-execution-pipeline.md`.

```ts
export type PreToolDecision = { kind: 'allow' } | { kind: 'deny'; reason: string } | { kind: 'ask'; reason?: string }
export type ToolGuard = (execution) => string | undefined   // returns a denial reason, or nothing
```

The pipeline is: extensible `tools/pre-execute` waterfall -> approval resolution
-> **monotonic guards**. The guards run *after* the extensible chain and have no
allow result, so, in their words, *"listener ordering cannot turn a denial back
into permission."* Guard evaluation walks the global layer then the scope chain,
farthest-first, first-denial-wins. Separately, `'never'` approval policy is
decided **inside the service body**, not as a prepended listener, "deliberately
so registration order can't defeat it."

**Target:** `hf-guardrails` (`src/lib.rs`, `src/action.rs`, `src/hitl.rs`).
**Impact: high. Effort: days.**

oxfuzz today has a policy scorer plus loop detection. Restructuring it as
*extensible-advisory-chain, then non-bypassable deny-only guards* gives a
type-level guarantee that no future extension, skill, or agent-role text can
re-permit something the safety layer denied. For a system whose central promise
is "generated harnesses never run on the host", encoding non-bypassability in the
type rather than in review discipline is worth the refactor. The related dsh rule
from `packages/AGENTS.md` is the one to quote in the design doc:

> "Enforce a decision in the operation that makes it. Schema omission, prompt
> filtering, facades, wrappers, and listener order are not enforcement when
> direct or alternate callers can bypass them; test denial through the executor."

#### 1.5 Never let a recovered/resumed run spontaneously act

**Source:** `packages/goal/goal` -- the goal record persists objective, phase,
revision, and admitted-round count, but **"activation ('armed') is never
persisted"**: a fresh cache and every `agent/session-start` disarms. Resume, fork,
and driver replacement retain the objective without resuming work.
**Target:** `hf-service` durable run recovery, `hf-scheduler` one-time occurrence
recovery, `hf-session` checkpoint restore.
**Impact: high. Effort: 1-2 days.**

oxfuzz has "durable run recovery (`ServiceContainer`)" and durable one-time
schedule occurrences. The dsh rule says: a recovered campaign should restore
*what it was doing* but must require a fresh authorisation to *start doing it
again*. That is a strong safety property for an agent that drives fuzzers under
budget, and it composes with oxfuzz's existing revision-bound approval: after a
crash-restart, the promoted-revision approval is still valid, but the *armed*
state is not.

#### 1.6 Fix compaction cut boundaries and ordering

**Source:** `packages/compaction/*`, `docs/subsystems/compaction.md`.
**Target:** `hf-context/src/compaction.rs`, `hf-context/src/pruning/`.
**Impact: medium-high. Effort: 1-3 days each, independently landable.**

oxfuzz already has both halves (a compaction module and an intra-turn pruner),
so these are refinements, not a rewrite:

- **Never split a tool call from its result.** `selectCompactableRange` walks
  backwards to the retention budget, then walks the cut point *head-ward* while
  `toolPairingBalancedBefore(session, seq)` is false. Their test names are the
  spec: *"rounds a retention cut head-ward to preserve tool-call/result
  pairing"*, *"declines when rounding a cut would consume the only tool pair"*.
- **Prune before you summarize, and skip the model if pruning suffices.** The
  deterministic head/middle/tail pruner runs *before* range selection; if it
  clears pressure, the LLM summarization call is skipped entirely. Zero tokens
  spent on the common case. oxfuzz has the pruner but should check the ordering.
- **Reject a summary that does not shrink its source**, remeasured through the
  token meter; retry up to a bound; then fail loud.
- **Bracket-first locking.** `compaction/start` is appended *before* the async
  work and `compaction/end` *last*, "so a crash leaves a detectable orphaned
  lock, not a false success." Generalises to every long oxfuzz operation:
  harness build, smoke fuzz, campaign, triage.
- **KV-cache-preserving summarization.** The summarizer call replays the
  conversation's own system prompt, tool schemas, and shadowed messages
  *byte-for-byte* and appends the compaction instruction as the final user
  message, so the provider's warm prefix cache is reused. Most harnesses pay full
  price here. Worth measuring against oxfuzz's provider pool; note it interacts
  with tag-based routing, since the cache is per-provider.
- Slice by **Unicode code point**, not byte, when truncating (no split
  surrogates). In Rust this is `char_indices`, and it matters because ASan output
  and source snippets are not guaranteed ASCII.

#### 1.7 Adopt the bilingual pairing gate for README/CONTRIBUTING

**Source:** `docs/i18n/README.md`, `scripts/verify-translation-pairing.ts`.
**Target:** oxfuzz's `README.md`/`README.zh.md`, `CONTRIBUTING.md`.
**Impact: medium. Effort: 1 day.**

oxfuzz maintains `README.md` (7,408 B) and `README.zh.md` (7,358 B) by hand, with
no mechanism to detect that one was edited and the other was not. dsh's answer is
a **triplet**: `foo.md`, `foo.zh.md`, and `foo.i18n.yaml` recording the **git blob
hash** of each side:

```yaml
README.md: 8a4bd01332a23ce4144c661784bc549e0ba72d21
README.zh.md: b7bc214bfb1fd8a76a47de3f0aa242122aeb7603
```

Blob hashes, not commit hashes, "so the record is computable for files edited in
the same PR and consistency is a pure content comparison." The gate checks: the
triplet is complete; both recorded hashes match current content; the language
switcher line is present right after the H1; and a **structural signature match**
-- heading depths, verbatim code blocks, table row/column counts, list kinds,
item counts, and every link target apart from the switcher.

Two honest notes they make that are worth copying with it: *"Both languages carry
equal authority"* (neither is the source), and *"a green gate means the pair was
confirmed consistent at these exact contents, not that the confirmation was
sound."*

This is a ~150-line script and a CI gate that removes a whole class of silent
doc rot. Highest ratio of value to effort in the engineering-practice bucket.

#### 1.8 CI: add an aggregating required check with `if: always()`

**Source:** `.github/workflows/ci.yml` in dsh -- a single `all-checks-passed`
job with a load-bearing comment:

> "`if: always()` is load-bearing: without it a failed dependency would SKIP this
> job, and GitHub counts a skipped required check as passing"

**Target:** `oxfuzz/.github/workflows/ci.yml`.
**Impact: medium. Effort: 15 minutes.**

oxfuzz's CI has four jobs (`rust`, `cross-platform` matrix, `frontend`,
`supply-chain`) and no aggregator. The `cross-platform` matrix produces
dynamically-named checks (`macOS tests`, `Windows tests`) that branch protection
must be configured to require by name -- brittle, and a renamed matrix label
silently drops a required check. One aggregating job fixes both.

### Tier 2 -- worth a design doc first

#### 2.1 Event-sourced session log with derived messages

**Source:** `packages/core/session`, `packages/session/session-persistence*`,
plus the `AGENTS.md` invariant "Model-visible <=> logged".
**Target:** `hf-session` + `hf-storage`.
**Impact: very high. Effort: weeks.**

This is dsh's best structural idea and also the most expensive to adopt. Today
oxfuzz stores transcripts and has a session tree with checkpoints; dsh stores an
append-only `SessionEvent` log and *derives* the message array. Consequences that
oxfuzz currently pays for separately:

- Replay, fork, and resume are one mechanism. oxfuzz's `DESIGN_OVERVIEW.md`
  currently concedes: *"replay is available only for supported active-engine
  runs"* -- an event log makes replay total.
- Crash recovery is **close, not truncate**: `load` preserves the real events and
  durably appends synthetic closers (a risk-classified error result for each
  unanswered tool call, then step/turn closers) so a rehydrated history is a
  *valid provider transcript*. Only a torn tail is dropped. That is exactly the
  problem oxfuzz's WAL-based recoverability pillar is trying to solve.
- Test fixtures become free -- see 2.4.
- It forces the discipline: adding a new model-visible input **requires** a new
  event type, which is the mechanism behind their prompt-security guarantee.

If this is too large to swallow whole, the cheap partial adoption is the
invariant alone: write a test that reconstructs the exact `ChatRequest` from
persisted state and asserts equality with what was sent. oxfuzz's
`agent-prompt-security-design.md` section 6 already captures the real
`ChatRequest`; extending that to "and it is reconstructable from storage" is a
tractable first step.

#### 2.2 One canonical writable-root derivation, shared by tools and sandbox

**Source:** `packages/sandbox/sandbox/src/roots.ts`:

```ts
export function writableRoots(policy: SandboxExecutionPolicy): string[] {
  if (policy.mode !== 'workspace-write') return []
  return [...new Set([policy.workspaceRoot, '/tmp', tmpdir()].map(canonicalPath))]
}
```

consumed by both the Seatbelt profile generator and the in-process FS fence, so
that "bash can write /tmp but the write tool can't" asymmetries are structurally
impossible. Two supporting details:

- `canonicalPath` uses `realpathSync.native` specifically because Node's JS
  realpath "lexically collapses `..` before resolving a preceding symlink on some
  platforms". The Rust equivalent, `std::fs::canonicalize`, is already
  syscall-based -- but the *rule* ("never lexically normalise a path that feeds
  an enforcement layer") is the transferable part.
- `checkedTarget()` **re-resolves the path at check time and delegates with the
  fresh target, never the stale one** -- "no check-here-write-there TOCTOU".

**Target:** unify the root derivation used by `hf-tools`' project-scoped
`FileRead`/`Glob`/`Grep` boundary and by `hf-runtime`'s Docker bind-mount
construction (`hf-runtime/src/docker.rs`, `tests/workspace_boundary.rs`).
**Impact: high. Effort: days.**

oxfuzz has both boundaries and tests for each, but as far as the layout shows
they are derived independently. One function, two consumers, one test asserting
they agree.

#### 2.3 Distinguish "the runner failed" from "the sandbox denied it"

**Source:** `packages/sandbox/sandbox-local` -- `ConfinedArgv.denialSignatures`
are **backend-specific** stderr substrings (EROFS under bwrap, EACCES under
Landlock, EPERM under Seatbelt), *deliberately not a cross-backend union*
because a union "claims denials a given backend never produces". A separate
`RunnerFailureRule { allowedExitCodes?, fatalSignatures, informationalLines? }`
proves the runner died before the command ran, and **runner failure outranks
denial**.

Also: `confine()` either returns the argv to spawn *instead of* yours, or
**throws** `SandboxUnavailableError`. Silent unconfined passthrough is
structurally forbidden.

**Target:** `hf-runtime/src/docker.rs`.
**Impact: medium-high. Effort: days.**

oxfuzz's `hf-runtime` needs the same three-way classification and probably has it
implicitly: Docker daemon unreachable / image missing / container OOM-killed
(runner failure) vs. seccomp or read-only-mount denial (policy denial) vs. the
harness genuinely crashing (the *interesting* result). Conflating the first two
with the third produces false crashes; conflating denial with runner failure
produces a campaign that silently ran unconfined-looking. The fail-closed
`SandboxUnavailableError` rule is already oxfuzz policy ("no production
host-execution fallback") -- make sure it is a type, not a comment.

#### 2.4 Split the test suite into resource-posture tiers

**Source:** six vitest configs; `docs/testing.md`.
**Target:** `docs/standards/TEST_STRATEGY.md`, `scripts/tests/gates.sh`.
**Impact: medium-high. Effort: days.**

The insight is that each config is a **resource posture**, not just a file
filter: parallelism, timeouts, `.env` loading, coverage on/off, and
browser/subprocess needs differ per tier. oxfuzz today has one gate
(`cargo test --workspace`) doing unit, integration, and E2E work, with the
sandbox and harness-qualification contract test folded in.

Proposed oxfuzz tiers:

| Tier | Contents | Posture |
| --- | --- | --- |
| `test-unit` | pure functions, trait mocks | fast, always, in every gate run |
| `test-integration` | multi-crate with mocked LLM + `MockEngine` | default gate |
| `test-sandbox` | requires Docker; `hf-runtime` and qualification contracts | opt-in locally, required in CI |
| `test-snapshot` | assembled system prompt, tool catalogue, CLI/REST output | records goldens; serial |
| `test-provider` | real LLM provider behaviour | needs `HF_PROVIDER_API_KEY`, self-skips |

Three specific rules from `docs/testing.md` worth importing verbatim into
oxfuzz's `TEST_STRATEGY.md`:

> "Verify the world, not the self-report. An e2e assertion re-runs the command or
> re-reads the file externally; **a keyword probe on the agent's own output lets a
> cheating agent pass.** Assert untouched files are byte-identical."

For oxfuzz this is the difference between asserting the agent *reported* a
heap-buffer-overflow and asserting the minimized reproducer *actually
reproduces* under a fresh sandboxed run.

> "A guard only guards if the regression actually fails it: introduce the
> regression, watch red, revert."

Apply to every safety gate -- the promoted-revision check, the sandbox mandate,
the HITL gate.

> "Prefer the real implementation over a mock. Mock only the expensive or
> non-deterministic boundary (LLM adapter, network, clock); keep everything
> downstream real."

Consistent with oxfuzz's existing "avoid heavy mock frameworks" rule.

Bonus: their **`llm-replay` test-support package uses the persisted session JSONL
*as* the fixture** -- `assistant/chunk` events grouped by `(turn, step)`
reconstruct each `stream()` call, so there is no separate recording format to
maintain. That only works if you have 2.1. It is a strong argument for it.

#### 2.5 Generated-and-verified documentation catalogues

**Source:** `scripts/gen-config-catalog.ts` + `verify-config-catalog`,
`gen-doc-graphs` + `verify-doc-graphs`, `gen-tool-catalog`, and the
` ```ts type-equiv ` fences checked by `verify-type-equiv` (which re-extracts the
symbol via the TypeScript parser and diffs it against the pasted declaration).
**Target:** `docs/design/DESIGN_OVERVIEW.md` alignment table, `docs/ARCHITECTURE.md`
crate map, `docs/standards/TOOL_CALL_PROTOCOL.md` tool catalogue,
`docs/standards/DATABASE_SCHEMA.md`.
**Impact: medium-high. Effort: days per generator.**

oxfuzz's `AGENTS.md` marks multi-doc and alignment-table changes as **High risk**
-- which is an admission that they drift. Every table listed above is derivable
from source:

- The crate map from `Cargo.toml` + crate-level rustdoc.
- The alignment table's Contract column from the actual public types.
- The tool catalogue from the registry -- and oxfuzz *already* has "the registry
  assembly test in `hf-agent::agent_tools` enforces exact parity between this
  catalog and the executable surface", so the doc should be generated from the
  same source rather than hand-kept in parallel.
- `DATABASE_SCHEMA.md` (34 KB!) from the sqlx migrations.

The pattern to copy is the **dual-mode generator**: every `gen-*` script also runs
with `--check` as its own freshness gate. One script, two jobs, zero drift.

The strongest single instance for oxfuzz is a **config catalogue**. dsh's
generator "cross-checks the runtime schema against the pasted declaration so the
paste cannot hide a loader-accepted field." oxfuzz's own audit backlog has a
section literally titled **"Config knobs that silently no-op"** -- a generated
catalogue derived from the structs that `hf-service` actually reads is the
mechanical fix for that entire class.

#### 2.6 Skill catalogue: progressive disclosure and digest-gated re-injection

**Source:** `packages/skill/*`.
**Target:** `hf-skills/src/registry.rs`, `hf-prompt`.
**Impact: medium. Effort: days.**

oxfuzz's skills are `skill.toml` + `root.md` with a <=2,000-token root-doc rule.
dsh's three-level disclosure is a strict improvement on the same idea:

1. The catalogue in context carries only `name` + a **capped** `description`
   (default 500 chars).
2. `skill(name)` re-reads and re-parses the file, returning content plus a
   resource list.
3. Resource guidance resolves **only paths explicitly referenced by the
   instructions** -- the result "never enumerates the skill directory".

Two mechanisms worth lifting regardless:

- **Catalogue digest over the durable `{name, description}` entries, not the
  rendered prose.** Reframing the catalogue template cannot trigger a
  re-injection; only a real skill change can. Directly protects oxfuzz's 4,000-
  token prompt budget and the provider prefix cache.
- **Invocation policy fails closed**: a camelCase frontmatter key or a
  non-boolean drops *the entire skill* with a warning rather than defaulting
  permissive. Correct default for a security tool.

#### 2.7 Subagent delegation hardening

**Source:** `packages/subagent/*`.
**Target:** `hf-agent` delegation, `docs/standards/AGENT_AUTONOMY.md`.
**Impact: medium. Effort: days.**

Three rules that fit oxfuzz's autonomy model directly:

- **A delegated child's approval policy is pinned explicitly and written to the
  child's own log** (`source: 'delegation'`), so the child's effective policy is
  reconstructable from its log alone. dsh pins children to `'never'` because
  nobody is watching a delegated prompt; oxfuzz should pin the *opposite* --
  a sub-agent may not inherit `Autonomous` -- but the mechanism is the same, and
  oxfuzz's `AGENT_AUTONOMY.md` already states the intent ("Physical approval
  cannot be inherited from a prior plan or granted by `Autonomous` mode") without
  a described mechanism.
- **Delegation depth is monotone**: runtime options may deepen it but never lower
  it, so a resumed child cannot be re-counted as top-level.
- **Structured output is capability-gated**: an `outputSchema` request is
  rejected *before child creation* if the provider does not advertise support,
  rather than failing after work is done.

Also worth noting their honest caveat, which oxfuzz should *not* copy: they mark
agent-scope security an explicit non-goal, and `inheritsParentContext` is
descriptive, not an authority statement. oxfuzz needs delegation to be an
authority boundary.

#### 2.8 Approval audit pairing

**Source:** `packages/interaction/user-approval` -- every ask appends
`approval/asked {id, toolName, callId?, reason?}` and exactly one
`approval/decided {id, outcome}`. `request()` **throws if no turn is open** (a
bare event between turns is "crash-tail garbage on reload"), and an audit append
that fails before commit **rejects rather than returning an unlogged decision**.
Under parallel asks, an audit id is claimed only if it is the newest undecided,
unclaimed, and **symmetrically callId-matched** record, "so neither shape can
steal the other's audit id."
**Target:** `hf-guardrails/src/hitl.rs`, `hf-storage`.
**Impact: medium. Effort: 1-2 days.**

The "no decision without a durable audit record, and the write happens before the
grant is returned" rule is exactly right for a tool whose whole value proposition
includes "policy decisions retained for review".

### Tier 3 -- interesting, lower fit

- **Code Mode** (`packages/core/tools/src/code-mode.ts`): the model writes a
  program that calls tools; sub-calls go through the *real* pipeline (policy,
  guards, approval) with deterministic ids and log-only dispatch events, but
  **only the program's curated return value re-enters model context**. Large
  token savings without losing auditability. Lower fit for oxfuzz because its
  advertised tool surface is four read-only inspection tools by design; revisit
  only if that surface grows.
- **Workflow DSL** (`packages/workflow/*`): a deterministic JS orchestration
  script (`agent()`, `parallel()`, `pipeline()`, `phase()`) run in a worker
  thread. oxfuzz's workflow is fixed and encoded in Rust deliberately -- that is
  a design pillar, not a gap. The one transferable line is their candour: *"`node:vm`
  inside a worker is an API-shaping mechanism, not a security boundary."*
- **Runtime plugin composition (Cordis) and HMR**: see section 5.
- **`jscpd` duplicate-code detection as a blocking gate** (`minTokens: 60`,
  `minLines: 6`, `exitCode: 1`) and **`knip --treat-config-hints-as-errors`** for
  dead code. Rust analogues: `cargo-machete` / `cargo-udeps` for unused deps;
  `jscpd` itself does support Rust. oxfuzz has a "Dead code removed" audit
  section, so the concern is live -- but a blocking duplication gate on a young
  codebase generates noise. Try it non-blocking first.
- **Lint-config fingerprinting**: `scripts/lint-rule-fingerprint.spec.ts` pins a
  SHA-256 of each override's rule set so silent rule loss fails CI, and
  `oxlint-contract.spec.ts` spawns the real linter against generated probe files
  to prove rules actually fire. A small Rust version -- a test that asserts
  `clippy.toml` + the `-D warnings` invocation still reject a known-bad snippet
  -- would enforce oxfuzz's "no inline lint suppression" rule mechanically.

---

## 4. Engineering-practice rules worth copying verbatim

These are one-line `AGENTS.md` additions, all from dsh's `AGENTS.md` or
`packages/AGENTS.md`, chosen because they fill a gap in oxfuzz's protocol rather
than restating it.

- **"Model-visible <=> logged"**: anything reaching a model request must be
  reconstructable from the session log; a new model-visible input requires a
  session event.
- **"Tests describe behavior, not correctness. Change obsolete behavior with its
  tests; explain why in the PR."** oxfuzz's TDD rule is strong on process and
  silent on this.
- **"Trust the type system at typed same-process boundaries.** Do not add runtime
  validation, fallback behavior, or hostile-input tests solely for values the
  static interface requires; validate at parser/config, queued, model/tool JSON,
  durable/file, worker, process, and wire boundaries." A precise antidote to
  defensive-programming sprawl, and the boundary list transfers to Rust
  unchanged.
- **"Explicit > implicit at package boundaries: defaulting is an explicit
  `resolve(request) -> Spec` step in the owning implementation, never a hidden
  `?? default` inside `run()`."** Paired with **"No hardcoded tunables: deployment-
  varying choices are validated `Config` fields; a `DEFAULT_*` constant or test
  hook is not configurability."** Together these are the root-cause fix for
  oxfuzz's "config knobs that silently no-op" backlog.
- **"Misconfiguration fails loud** at load when self-contained, otherwise at the
  earliest resolvable point; never silently skip a missing referent."
- **"An empty `catch` names what it swallows** and why nothing else can reach it;
  keep the `try` to one statement." Rust form: every `let _ = ...`, `.ok()`, and
  `unwrap_or_default()` on a fallible call carries a comment naming what is
  swallowed.
- **"Prefer symmetry for parallel values; unexplained asymmetry usually signals a
  missed extraction."**
- **"Wire mechanically checkable invariants into an executed top-level gate and
  prove each changed acceptance path rejects an invalid case. Use narrow,
  justified exceptions instead of disabling a rule globally."** Aligns with
  oxfuzz's rule 2.10.
- **Word-choice policy**: *"Before writing `contract`, `boundary`, or `shape`, ask
  whether a more exact term names the subject."* / *"Do not use metaphors."* /
  *"Do not comment on facts obvious from code."*
- **Three TODO tiers with release semantics**: `FIXME` blocks a release, `TODO` is
  soon, `XXX` is someday.
- **The sunset clause.** dsh's pre-release section ends: *"Remove this section at
  the first tagged release. With no external consumers, prefer the correct
  foundation over compatibility shims: rename or repackage freely and update
  every reference together."* A rule that deletes itself at a named event is a
  neat pattern; oxfuzz is pre-1.0 and could use exactly this one.

One rule to consider but **not** adopt unchanged:

> "Never default to the full suite or repeat a passing check for commit or push.
> CI owns exhaustive coverage and the platform matrix; rehearse all locally only
> by explicit request, for CI diagnosis, or for an irreducibly repository-wide
> change. Match evidence to the surface."

This directly contradicts oxfuzz's `AGENTS.md` 4.5 ("run the following checks in
order... No task is complete until every applicable gate passes cleanly") and
`TEST_STRATEGY.md` section 5 (ten gates). dsh can afford selectivity because it
has 14 CI aggregate modes and a `change-scope` tool to compute the affected
surface. oxfuzz's ten gates take minutes, not hours. Keep the current rule; the
transferable half is only "match evidence to the surface" as a way to choose
*which* gate to re-run while iterating, not what to run before declaring done.

Two structural documentation practices also stand out:

- **Every package README carries mandatory "Model Experience" (What the model
  sees / Token effect / **KV cache effect**) and "Known Limitations and Deferred
  Work" sections**, verified by `verify-package-readme-model-experience` and
  `-limitations`. For oxfuzz, requiring every crate that contributes to the
  prompt (`hf-prompt`, `hf-skills`, `hf-tools`, `hf-context`, `hf-agent`) to
  document its token effect makes prompt-budget regressions visible in a diff
  -- which is exactly what the 4,000-token cap needs.
- **Agent Notes**: `.agents/notes/{lifecycle}/{class}/yyyy-mm-dd-topic.md` with
  lifecycle in `proposed|implemented|rejected` (+ frozen `archived/`) and a
  **closed** class set `feature|bug-fix|simplification|architecture|process|testing`,
  enforced by format and classification gates. *"`refactor` is deliberately absent
  -- it overlaps `simplification`."* Cross-references must be relative Markdown
  links "never bare prose or numbers -- so they are mechanically checkable and
  survive moves between folders." oxfuzz already has `docs/superpowers/plans` and
  `specs` plus `.claude/plans`; the classification scheme, the `Status:`
  must-agree-with-folder gate, and the archived-notes-are-frozen rule would give
  that corpus a lifecycle.

---

## 5. What not to adopt

**The Cordis plugin runtime and "everything is a plugin".** This is the load-
bearing idea in dsh and the worst fit for oxfuzz. oxfuzz's central safety claim
is that certain paths are *non-bypassable*: every build and run goes through
`hf-runtime`; all business logic lives in `hf-service`; presentation crates
cannot reach domain crates. `DESIGN_OVERVIEW.md` 4.1 states it plainly:
*"Mandatory safety boundaries are deliberately not configurable."* A runtime tree
of hot-swappable plugins where "there is no privileged core to patch" is the
architectural opposite of that guarantee. Rust's trait objects plus feature flags
already give oxfuzz the seam property (swap `EngineAdapter`, swap `LlmProvider`)
at compile time, where it can be *verified*. Take the seam *discipline* and the
generated seam *catalogue*; leave the runtime.

**dsh's permission model.** It is weaker than oxfuzz's on five axes, each
acknowledged in their own docs: no persistent grants (only `allowed-once`; policy
is just `ask`/`never`); no per-path or per-argument rules; **approval is not
content-bound** and the request "carries no tool arguments"; **no read-side
workspace boundary at all** (the FS fence is write-only, and bwrap `--ro-bind /`
still permits reading everything); and the sandbox vocabulary "expresses no
network, process, syscall, device, or credential restrictions." Copy the
*composition* rules (monotonic guards, fail-closed normalisation, audit pairing);
do not copy the policy surface.

**Their prompt-injection posture.** There is effectively none -- `MessageSource`
is attribution metadata that "nothing consumes as a trust level", and hook
`additionalContext` from third-party processes is injected essentially verbatim.
oxfuzz's `agent-prompt-security-design.md` is ahead here.

**Secret redaction from tool output.** Also absent in dsh: "if a command prints a
token, it lands in history verbatim." Do not treat their silence as a signal that
it does not matter -- see item 1.2.

**The 100% per-file coverage gate.** Defensible for a mature TS monorepo with a
custom uncovered-location reporter; premature for oxfuzz at 80%/70% targets in
active implementation. The transferable pieces are the **per-file** granularity
("so a well-covered big file can't subsidize a bare one") and the framing that
*"an uncovered line is often dead code the gate is correctly flagging for
deletion, not a missing test to bolt on."*

---

## 6. Where oxfuzz is already ahead

Worth recording, both to avoid regressing and because these are the parts of
oxfuzz's design that a dsh-inspired refactor could accidentally weaken.

1. **Content-bound approval.** oxfuzz binds human approval to the exact harness
   revision, and regeneration invalidates it (`docs/guides/SAFETY_MODEL.md`).
   dsh's approval carries only a tool name and a call id, with the binding left
   to the client's UI pairing. Do not adopt dsh's shape here.
2. **A deliberately minimal model-facing tool surface.** Four read-only tools
   (`FileRead`, `Glob`, `Grep`, `KnowledgeSearch`), no shell, no file mutation,
   with the rationale recorded in `TOOL_CALL_PROTOCOL.md` including *why the
   y-agent prototype's mutating/shell/MCP tools were removed rather than wired
   around*. dsh hands the model `bash -c` and relies on the sandbox. For a tool
   that runs attacker-influenced code, oxfuzz's posture is correct.
3. **Mandatory sandbox with no host fallback.** dsh's sandbox is best-effort and
   backend-probed; oxfuzz has no production host-execution path at all.
4. **Untrusted-data framing in the system prompt.** oxfuzz's prompt states that
   project files, tool results, and crash artifacts are data and not
   instructions, and that these rules take precedence over role text, skills,
   project content, and tool output. dsh has no equivalent.
5. **Autonomy levels as a documented standard** (`Assist`/`Draft`/`Supervised`/
   `Autonomous` with per-operation defaults). dsh has `ask`/`never` and a preset
   table.
6. **Cross-platform CI on the compile-and-test tier**, with the reason recorded
   in the workflow comment ("going cross-platform surfaced five real bugs on the
   first run of each new platform").

One small thing to steal *from* dsh in this area anyway: their
`session-reference` and `agent-instructions` packages escape untrusted content
before framing it -- every `<` in injected data is
emitted as the literal escape `\u003c` (`packages/context/session-reference/src/serialization.ts:11`),
and a literal closing frame tag inside file content is escaped "so repo text can't
close the frame". oxfuzz injects source snippets, ASan output, and crash
artifacts into prompts inside framed sections; frame-escaping is a two-line fix
for a real injection vector that its current design doc names but does not
mechanise.

---

## 7. Suggested sequencing

**Week 1 (mechanical, no design doc needed):**

1. Env scrub for every spawned process (1.2).
2. Port `DEFENSIVE_PATTERNS.md` and audit `hf-runtime`, `hf-engine`, `hf-corpus`
   against rules 1, 4, 6, 7 (1.1).
3. Aggregating CI check with `if: always()` (1.8).
4. Frame-escape untrusted content in prompt assembly (section 6, last paragraph).
5. Add the selected one-line rules to `AGENTS.md` (section 4).

**Weeks 2-4 (contained changes, each landable alone):**

6. Compaction cut boundaries, prune-before-summarize ordering, non-shrinking
   summary rejection, bracket-first locking (1.6).
7. `hf-spill` and the oversized-output policy (1.3).
8. Disarm-on-recovery for campaigns and schedules (1.5).
9. Translation pairing gate (1.7).
10. Monotonic deny-only guards in `hf-guardrails` (1.4).

**Design docs to write (Tier 2):**

- `docs/design/session-event-log-design.md` -- the "model-visible <=> logged"
  invariant and what it would cost (2.1). Write this one even if the answer is
  "not yet"; the analysis will sharpen the replay and recovery pillars.
- `docs/design/sandbox-root-unification-design.md` (2.2) and the runner-failure
  vs denial classification (2.3), likely one doc.
- `docs/design/generated-doc-catalogues-design.md` (2.5), starting with the
  config catalogue because it closes a named audit backlog item.
- A `TEST_STRATEGY.md` revision for tiering (2.4).

---

## 8. Evidence index

dsh files cited, all under a clone of `deepseek-ai/deepseek-harness`:

`README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `packages/AGENTS.md`,
`docs/architecture.md`, `docs/capability-seams.md`, `docs/rescope.md`,
`docs/config-catalog.md`, `docs/defensive-patterns.md`, `docs/testing.md`,
`docs/development.md`, `docs/tool-execution-pipeline.md`, `docs/agent-lifecycle.md`,
`docs/i18n/README.md`, `docs/cordis-api/*.md`, `docs/subsystems/{compaction,spill,credentials,system-prompt,typert,settings}.md`,
`packages/core/tools/src/{index.ts,code-mode.ts}`,
`packages/compaction/compaction-basic/src/region.ts`,
`packages/spill/spill-local/src/store.ts`, `packages/spill/spill-policy/src/index.ts`,
`packages/sandbox/sandbox/src/{index.ts,roots.ts,escalation.ts}`,
`packages/sandbox/sandbox-local/src/profiles.ts`,
`packages/fs/fs-sandbox/src/{index.ts,containment.ts}`, `packages/fs/fs-local/src/fsio.ts`,
`packages/subprocess/subprocess/src/index.ts`,
`packages/interaction/user-approval/src/{index.ts,types.ts}`,
`packages/interaction/permission-presets/src/index.ts`,
`packages/credentials/credentials/src/types.ts`,
`packages/hooks/hook-protocol/src/{matcher.ts,types.ts}`,
`packages/skill/*`, `packages/subagent/*`, `packages/goal/*`,
`packages/workflow/workflow-worker-thread/src/runtime.ts`,
`packages/test-support/*`, `.agents/skills/*`, `.agents/notes/README.md`,
`.github/workflows/{ci.yml,e2e.yml,expected-filenames.yml}`, `.gitlab-ci.yml`,
`lefthook.yml`, `knip.json`, `.oxlintrc.json`, `.jscpd.json`,
`vitest*.config.ts`, `scripts/{run-gates,verify-translation-pairing,gen-config-catalog,rescope-vendor,lint-rule-fingerprint.spec}.ts`,
`scripts/doc-budgets.manifest.json`.

oxfuzz files read for comparison:

`README.md`, `VISION.md`, `AGENTS.md`, `CLAUDE.md`, `TODO.md`, `Cargo.toml`,
`docs/ARCHITECTURE.md`, `docs/README.md`,
`docs/design/{DESIGN_OVERVIEW,runtime-design,agent-prompt-security-design}.md`,
`docs/standards/{TOOL_CALL_PROTOCOL,AGENT_AUTONOMY,TEST_STRATEGY,ENGINEERING_STANDARDS}.md`,
`docs/guides/{SAFETY_MODEL,CI}.md`, `.github/workflows/ci.yml`, `.gitlab-ci.yml`,
and the file listings of `crates/{hf-agent,hf-session,hf-context,hf-guardrails,hf-skills,hf-runtime}`.

---

## 9. Notes on accuracy

- Claims about dsh internals come from reading source and docs in the cloned
  repo, not from its README marketing. Where dsh's own docs state a limitation
  (no read-side FS boundary, approval not content-bound, no secret redaction,
  `node:vm` is not a security boundary, `code-runtime` isolation is "a label...
  not a security claim"), that limitation is reported here as they state it.
- Claims about oxfuzz internals come from its docs plus crate/file listings. Two
  recommendations (2.2 root unification, 2.3 runner-vs-denial classification)
  are inferred from directory structure -- `hf-runtime/src/docker.rs`,
  `hf-runtime/tests/workspace_boundary.rs`, and `hf-tools`' documented project-
  root confinement -- and should be checked against the actual implementations
  before the design docs are written; it is possible one or both are already
  unified.
- `oxfuzz/CLAUDE.md` and `oxfuzz/AGENTS.md` are intentionally different documents
  (mechanics vs protocol, with CLAUDE.md pointing at AGENTS.md first), unlike
  dsh where `CLAUDE.md` is a symlink to `AGENTS.md`. They do overlap on
  architecture and crate description, which is a small drift surface; dsh's
  `.claude/skills -> ../.agents/skills` symlink trick is the general pattern for
  keeping one source of truth projected to multiple agent products.
- oxfuzz's `AGENTS.md` is ~980 words, comfortably under dsh's 1,924-word,
  machine-enforced ceiling, so a doc-budget gate is not urgent for that file.
