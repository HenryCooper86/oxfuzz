# Harness Generation Design

Status: **active implementation**. Owners: `hf-service` for workflow and input
policy, `hf-harness` for generation/compilation, and `hf-storage` for evidence.
Phase 6 build-input capture and enforcement below specify the next implementation.

## 1. Goal

Given a `TargetCandidate` and an engine, produce a compilable, smoke-fuzzed
`Harness`.

## 2. Harness

```rust
pub struct Harness {
    pub id: Uuid,
    pub target_id: Uuid,
    pub engine: EngineKind,
    pub source: String,
    pub language: TargetLanguage,
    pub build_cmd: BuildCommand, // compiler, engine args, project flags
    pub sanitizer: Sanitizer,
    pub status: HarnessStatus, // Draft | Compiled | SmokePassed | Promoted
    pub smoke_run: Option<SmokeRunSummary>,
}
```

## 3. Pipeline

0. **Build diagnosis and context** -- before draft authorization, discovery,
   or any provider call, `hf-service` checks saved-profile readiness, including
   live configured image freshness, as defined in
   [Build Doctor](build-doctor-design.md). Profiles are optional. An
   `Unconfigured` project keeps the ordered search of `compile_commands.json`,
   `build/compile_commands.json`, `out/compile_commands.json`, then
   `.oxfuzz-build/compile_commands.json`, and proceeds without a database when
   its existing language workflow allows it. Prompt context remains best-effort
   only in this unconfigured case; compilation still fails on a selected
   malformed database. A configured project uses its exact saved database and
   component. `NeedsBuild`, `Stale`, or `Invalid` stops generation before a
   provider call, with named reasons. Direct harness compilation requires the
   same configured readiness and actual valid database. `NeedsBuild` still offers its reviewed
   project-build plan. `Stale` marker/image assumptions require review/save.
1. **Draft** -- LLM produces harness source from target signature + project
   context (includes, types, existing test patterns) and, when step 0 produced
   one, the project's real include directories, defines, and standard. Without
   those the model guesses header paths and guesses whether a configuration
   macro is set, and each wrong guess costs a repair round through the provider.
   The draft is also conditioned on the project's previously promoted
   harnesses (accepted examples): up to two, same language as the target,
   newest first, read from the persisted `harnesses` rows a human promotion
   approved, each source bounded to 6 000 characters. A project without
   promotions, a failed read, or a missing store renders the prompt exactly
   as without this step, so the conditioning only ever adds signal.
2. **Compile** -- `hf-runtime` builds the harness in-sandbox with the
   selected sanitizer + engine link flags, plus the step 0 flags. Project
   sources are staged preserving the complete project directory layout, so
   `<project>/include` resolves at `/work/include` and safe sibling includes
   remain usable for nested components. Before each direct or repair attempt,
   capture the exact build inputs and dispatch the captured immutable image
   as specified below. Successful compilation creates a new harness revision
   and atomically persists its input record before publishing the active marker.
3. **LLM safety review** -- recheck the exact compiled harness's build inputs
   before provider access or reuse of previous review evidence. Before any
   compiled harness binary executes, a separate model call reviews the exact
   persisted source for target exercise, fuzz-input use, and unsafe side effects. The structured verdict, model,
   response id, exact source and compiled-binary digests, and review time are persisted. Missing
   provider, provider failure, malformed output, a source larger than the review
   ceiling, or a negative verdict fails closed. A draft/model generation call is
   not its own independent review.
4. **Smoke fuzz** -- after the LLM review passes, reload the exact harness and
   recheck its build inputs before authorization, run allocation, image
   resolution, or staging. Request a 60-second run with a tiny seed corpus; before
   staging evidence, `hf-service` validates that engine and duration against the
   current fuzzing policy. The resolved duration, memory, and CPU values are one
   immutable `FuzzRunConfig` used unchanged by the engine command, runtime limits,
   persisted run evidence, and smoke summary. Require no immediate crash on
   empty input and at least one exec/sec.
5. **Iterate** -- on a static-rule error (`docs/standards/HARNESS_STANDARD.md`
   section 2), compile failure, or smoke failure, feed diagnostics back to the
   LLM for up to N rounds (default 3). A rule error short-circuits before the
   container starts.
6. **Review** -- persist the smoke evidence on the exact active harness record;
   the evidence binds the full source and executable SHA-256 digests to the
   smoke-run id, and a crash-free run leaves it at `SmokePassed`.
7. **Promote** -- only an explicit human action changes that exact revision to
   `Promoted`. Both promotion modes, the final post-qualification reload,
   and every full or scheduled fuzz run recheck captured build inputs as well
   as source/binary digests. Mismatches fail closed and require rebuild and
   requalification. Campaign admission performs this check before seed-provider
   calls or corpus mutation; the final fuzzer executor repeats it for all callers.

### 3.1 One Captured Input Set per Compile Attempt

The service owns one resolver for both direct `harness_compile` and each
`compile_source_with_repair_locked` attempt. After staging and immediately
before compilation, capture canonical project, optional current profile digest,
selected database path and its exact bounded bytes, parsed context, selected
marker identity/digest, image tag, and resolved immutable image reference.
Validate staged marker identity against the saved profile. Read database bytes
once (at most 64 MiB, regular-file and containment checks), hash those bytes,
and derive compilation flags from that same parsed value. The ordered token
vector returned by `hf_discovery::build_context::staged_compile_flags` is both
the emitted vector and the source of the flags digest; do not independently
reconstruct flags for hashing.

Configured compile-database readiness requires a successfully parsed nonempty
entry list with nonempty compiler invocations, even when the allowlisted ordered extra-flag vector is empty. Such
an empty vector remains captured build-input evidence, together with the exact
database bytes; it is not absence of a configured database. Legacy unconfigured
resolution continues treating databases without extra flags as no context. The
shared parser decodes command-form quoting and escaping without shell execution
or expansion; normalized databases use argument arrays to preserve token values.

`build_input_sha256` hashes versioned canonical serialization with explicit
fields for optional `profile_sha256`, optional raw database-byte SHA-256,
ordered emitted-flags SHA-256, and immutable image ID. Absent database/profile
values are explicit nulls, including Rust/no-database compilation. Profile
identity already binds the component, database path, options, dependencies,
marker, and saved image. The in-memory capture owns the exact bytes and tokens
for its attempt; the durable input row records their digests, not a later reread.

Use an image/options-aware `hf-harness` compile/try-compile entry point and pass
`SandboxOptions.image = Some(captured_immutable_reference)`. Recording an image
ID while dispatching a mutable tag is insufficient. The existing wrapper may
remain for unaffected callers, but shared service compile paths use the pinned
entry point. Resolve a fresh capture before each repair attempt. If a profile,
database, or image changes during the awaited compile, retain successful
compilation with its old captured inputs; the next guarded action must reject
it against current inputs. Never reread after the await and label the old binary
with new inputs. A configured readiness failure is not a repair-provider prompt.

Every new service compilation requires an available persistent Store before provider
or runtime work, including projects without a profile or database. Pure draft/read
paths may remain store-free. Historical unconfigured stored harnesses without
input rows preserve exact source/binary approval behavior.

Configured provider context is retained before dispatch in immutable
`harness_build_contexts` records: version 1, canonical project, profile digest,
exact database digest, and the exact serialized BuildContext supplied to prompt
rendering. No additional profile fields are rendered. A storage failure prevents
the provider call. This is scoped to configured context; legacy prompt behavior
is unchanged. Records survive profile replacement and are deleted with project
knowledge. The serialized context is strict and bounded to 64 KiB.

Executing admission reuses a retained successful Ready diagnosis matching the
exact profile, immutable image, and all merged prerequisites, then checks the
live image and current filesystem inputs. An immutable image with network-free
probes in an empty workspace permits reuse of dependency evidence. Missing
matching diagnosis is `build_diagnosis_unavailable`, including feature-off builds.
Compile staging explicitly copies the selected bounded regular marker and checks
its digest; legacy source staging alone does not include build markers.

A successful attempt inserts the new immutable harness revision and its
`harness_build_inputs` row in one storage transaction before `harness.source`
and `harness.active` expose it. A failed compile writes no input record. If
persistence fails, publish no new active marker and propagate the error. The
storage transaction reserves the SQLite writer before reads, shares the
existing exact-revision checks, and accepts an identical input retry for the
same harness UUID only; differing fields are rejected. Input evidence is not
mutated when ordinary qualification updates the harness status. No fields are
added to `hf-core::Harness`, core approval types, or Work Order v2 solely for
profiles; exact Work Order compile/review/smoke/promotion uses these shared paths.

### 3.2 Enforcement and Read-Only Availability

A configured harness requires a retained input row matching current profile,
database, staged flags, and immutable image. Adding a profile to a historical
harness without a row requires rebuilding and requalifying it. Unconfigured
historical harnesses without a row retain existing source/binary/approval
checks; clearing a profile explicitly returns the project to that behavior.
Storage failures never masquerade as missing optional configuration.

Provider-bearing `harness_generate`/draft and review admission must resolve the
configured image tag live and compare its immutable ID with the saved profile
before any provider access. A moved tag is `Stale` even when retained diagnosis,
profile, marker, database, and flags still match; image-resolution failure is an
error. Retained diagnosis cannot substitute for this admission check.

Use one pre-review input check after exact harness/language/status selection
and before `require_harness_ai_review`, including the live image check above.
Shared `harness_smoke_locked` rechecks retained/filesystem inputs after review
awaits and reloads, before `Action::RunHarness`, run allocation, or staging.
The executing-mode check also verifies the live immutable image immediately
before sandbox dispatch. Compose the input checks with
`verify_harness_qualification_locked` for already-qualified harnesses, including
policy/revert and corpus operations. Both
`harness_promote_locked` and `harness_promote_with_findings` check before
mutation; the exact clean path checks again after its final reload. The
promotion transaction reserves the writer before reads, compares the expected
current profile/input digest, and preserves existing exact revision/approval
logic. Concurrent profile saves have a defined before/after order with promotion.
Filesystem checks occur immediately before mutation; later filesystem changes
are rejected again at execution.

`run_campaign` passes its exact promoted harness into the shared seed-generation
operation. That operation checks current configured inputs after discovery and
before provider dispatch, and again after provider/target-resolution awaits,
immediately before publishing provider or heuristic seeds. A provider failure
still uses the existing heuristic fallback. Campaign discovery, validation,
storage, and corpus-publication errors propagate before fuzzer dispatch; they
are not optional provider failures. Standalone seed generation does not require
a qualified campaign harness and preserves its existing fallback behavior.
`run_fuzzer_with_started_inner` and each engine-backed corpus executor repeat
executing-mode checks immediately before sandbox dispatch, preserving existing
source/binary, human approval, policy, and workspace checks. Each later showmap
dispatch rechecks after the preceding command returns. Coverage pruning and
minimization check again before corpus mutation; regeneration checks before
removal, provider access, and seeding. Changed inputs leave an operation-specific
failure and prevent the next side effect. A UI readiness view,
wrapper, or Work Order preflight is not the executor check.

Executing mode must resolve the configured image tag, compare it to the saved
immutable ID, and probe prerequisites through the sandbox as needed. The
zero-runtime/image/provider rule applies only to read-only corpus availability,
not provider-bearing generation/review admission. Read-only corpus capabilities
use only validated stored profile/input records, current marker
and database bytes/flags, and a retained successful diagnosis for the same
profile/image ID with satisfied dependencies. They never call `RuntimeAdapter`,
`system_status`, `resolve_image_reference`, or a provider. Missing matching
retained evidence returns `build_diagnosis_unavailable`; retained evidence does
not claim that a Docker tag still identifies that image now. The executor
performs the live check. Durable records and configured-input enforcement
remain available with `build-doctor` disabled, including no-default builds.

## 4. Templates

Per language + engine templates live in `config/prompts/harness_*`. The LLM
fills the template; the template guarantees the engine entry point is present.

## 5. Safety

- Harness source is written to `fuzz_workspace/` only, never into the target
  project unless the user opts in.
- Generated harness source passes the static rules in
  `docs/standards/HARNESS_STANDARD.md` section 2 before any container starts.
- The exact compiled source passes a separate fail-closed LLM review before the
  high-risk human approval prompt and smoke execution. Review evidence is
  durable and bound to both source and compiled-binary digests; a review of an
  earlier or substituted revision is invalid.
- A `compile_commands.json` is a file inside the untrusted project whose values
  reach a compiler invocation, so it is validated by an allowlist rather than a
  denylist: include directories must resolve inside the project root, a `-D`
  must name a C identifier and carry no control character, `-std=` must name a
  dialect and version, and code-generation flags come from a fixed list.
  Optimization and warning flags are dropped so a project cannot override the
  sanitizer build oxfuzz needs. Rejected tokens are recorded, not discarded
  silently. Every emitted token is shell-quoted in the single place the compile
  command is built.
- Staging a project into the sandbox workspace refuses symlinks, skips version
  control and build output, and stops at a file cap, so an untrusted project
  cannot turn staging into an unbounded host traversal or pull in a file from
  outside its own root. The corpus and run-output directories are never
  compiled: they hold attacker-controlled bytes that may carry a source name.
- Build and smoke fuzz always run in `hf-runtime` sandbox.
- Smoke qualification fails before staging or run reservation when its engine
  is disabled or its 60-second request exceeds the configured duration ceiling.
- The agent never executes a harness directly on the host.
- `harness.source` and `harness.active` bind the active binary to its persisted
  source and qualification id. The smoke summary binds that record to the full
  source and executable digests that actually ran. Every successful recompile
  creates a new active revision and invalidates prior approval.
- Agents may prepare and smoke-test a harness, but they cannot promote it.

## 6. Harness Tournament

Status: **active implementation**. Owner: `hf-service`, behind the
`harness-tournament` feature.

### 6.1 Goal

One draft is a sample of one. The tournament generates several harness
candidates for the same target, takes each through the existing compile and
smoke paths, and ranks them on what actually happened, so the operator promotes
a harness that was chosen against alternatives rather than the first one the
model produced.

### 6.2 Candidates

A tournament of `n` candidates produces one deterministic heuristic draft and
`n - 1` LLM drafts. The heuristic baseline is always included: it costs no
model call, and a tournament where every LLM draft fails should still leave the
operator something that builds. LLM variation comes from independent draft
calls, not from prompt mutation, so a candidate is never handicapped by a
prompt the others did not get.

The candidate count is bounded. Each candidate costs a model call, a sandbox
compile, and a sandbox smoke run, so an unbounded tournament is an unbounded
bill.

### 6.3 Evidence

Every candidate is compiled through the existing repair loop, and every
candidate that compiles is smoke-qualified. Both results are retained for every
candidate, not only the winner:

- source digest, so a candidate is reconstructable;
- whether it compiled, and how many repair passes it needed;
- the compile diagnostics when it did not; and
- the smoke verdict, executions per second, and crash count when it did.

A tournament that produces no compiling candidate is a result with its
diagnostics, not an error.

### 6.4 Ranking

Ranking is deterministic and objective. Candidates are ordered by, in sequence:

1. compiled before not compiled;
2. smoke verdict `Pass` before `Suspect` before `Fail` or absent;
3. fewer repair passes;
4. higher executions per second; and
5. lower candidate index, so equal evidence yields a stable order.

No model opinion enters the ranking. Executions per second is a tie-break among
candidates that already passed, never a primary signal: a harness that does
nothing quickly is not better than one that does the right thing.

### 6.5 What the Tournament Does Not Do

It does not promote. Promotion stays the existing explicit human step against
the existing approval evidence, and the tournament's ranking is an input to that
decision rather than a substitute for it.

Because each compile writes the workspace's active-harness marker and binary,
the tournament recompiles the winner after ranking so the workspace holds the
winner's artifacts rather than the last candidate's. That recompile creates a
new harness revision with a fresh captured input record. It must be reviewed
and smoke-qualified before promotion; a previous candidate's evidence cannot
qualify the new binary.

### 6.6 Rejected Alternatives

- **Ranking with an LLM judge** -- the product position is that model opinions
  are advisory; a promotion decision must rest on what was observed.
- **Skipping smoke for all but the front-runner** -- a candidate that compiles
  but does nothing at runtime would win on static signals alone.
- **Prompt-mutating each candidate** -- differences would then reflect the
  prompt rather than the draft, and a losing candidate could not be attributed.
- **Auto-promoting the winner** -- promotion is a human approval bound to
  qualification evidence, and the tournament does not create that authority.
- **Dropping losing candidates' evidence** -- an operator cannot judge a
  selection without seeing what it beat.

## 7. Open Questions

- Should we support custom mutators (libFuzzer `custom_mutator`)?
- How to share harness scaffolding across engines for the same target?

## 8. Tests

- Unit: draft -> compile -> smoke loop with a mocked LLM and a trivial
  target function.
- Integration: generate a harness for a fixture `parse_value` and assert
  smoke fuzz completes.
- Integration: promotion before smoke fails; a full campaign before promotion
  fails; smoke and promotion update the same persisted harness id; tampering
  with either qualified artifact blocks promotion and campaign execution.
- Unit: a compile database yields only allowlisted flags, rejects an include
  directory outside the project root, and its tokens survive shell quoting.
- Unit: a harness whose source breaks a static rule never reaches the sandbox.
- End-to-end: a project with sources under `src/`, headers under `include/`,
  and a compile database compiles; the same project without the build-context
  feature fails on the missing header.
- Unit: tournament ranking orders compiled over uncompiled, `Pass` over
  `Suspect` over `Fail`, then fewer repairs, then higher throughput, then index.
- Integration: every candidate's evidence is retained, a tournament with no
  compiling candidate is a result rather than an error, and the tournament
  promotes nothing.

- Integration: configured `NeedsBuild`/`Stale`/`Invalid` stops draft before
  provider calls; unconfigured best-effort prompts and four-location resolution
  remain available.
- Integration: direct and repaired compiles use one bytes/flags capture per
  attempt and the captured immutable image; concurrent profile/database edits
  never relabel an old binary. Failed compilation stores no inputs.
- Storage: atomic harness/input insertion failure leaves no partial pair or
  active marker, exact retries succeed, and differing input retries fail.
- Integration: direct review/smoke, both promotion modes and final reload,
  campaign admission before seed generation, and final fuzzer/corpus executors
  reject stale configured inputs, including Work Order callers. Rebuilding and
  requalifying restores eligibility.
- Integration: changed configured image tag with otherwise identical retained
  diagnosis/profile/marker/database/flags reports `Stale` at generation/review
  admission and makes zero generation/review provider calls. For the same
  fixture, read-only corpus availability still makes zero runtime/image calls;
  final executors independently recheck the live image before dispatch.
- Integration: read-only corpus readiness invokes no runtime/image/provider
  and names missing diagnosis evidence; feature-off builds retain configured
  enforcement and accept unconfigured historical harnesses without input rows.
