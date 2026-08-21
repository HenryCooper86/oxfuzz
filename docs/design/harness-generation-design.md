# Harness Generation Design

Status: **draft**. Owner: `hf-harness`.

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

0. **Build context** -- if the project ships a `compile_commands.json`, read
   the include directories, preprocessor defines, and language standard its own
   build uses. Looked for at the project root and in the `build` and `out`
   trees CMake and Bear write into. A project without one skips this step and
   the rest of the pipeline is unchanged; a project with one that cannot be
   parsed fails the build rather than degrading silently, because building
   without the flags fails later with a confusing missing-header error instead
   of naming the real fault.
1. **Draft** -- LLM produces harness source from target signature + project
   context (includes, types, existing test patterns) and, when step 0 produced
   one, the project's real include directories, defines, and standard. Without
   those the model guesses header paths and guesses whether a configuration
   macro is set, and each wrong guess costs a repair round through the provider.
2. **Compile** -- `hf-runtime` builds the harness in-sandbox with the
   selected sanitizer + engine link flags, plus the step 0 flags. Project
   sources are staged preserving their directory layout, so an include
   directory at `<project>/include` resolves at `/work/include` and every
   nested translation unit is handed to the compiler.
3. **Smoke fuzz** -- request a 60-second run with a tiny seed corpus; before
   staging evidence, `hf-service` validates that engine and duration against the
   current fuzzing policy. The resolved duration, memory, and CPU values are one
   immutable `FuzzRunConfig` used unchanged by the engine command, runtime limits,
   persisted run evidence, and smoke summary. Require no immediate crash on
   empty input and at least one exec/sec.
4. **Iterate** -- on a static-rule error (`docs/standards/HARNESS_STANDARD.md`
   section 2), compile failure, or smoke failure, feed diagnostics back to the
   LLM for up to N rounds (default 3). A rule error short-circuits before the
   container starts.
5. **Review** -- persist the smoke evidence on the exact active harness record;
   the evidence binds the full source and executable SHA-256 digests to the
   smoke-run id, and a crash-free run leaves it at `SmokePassed`.
6. **Promote** -- only an explicit human action changes that exact revision to
   `Promoted`. Promotion and every full or scheduled fuzz run recompute both
   digests and fail closed for a mismatch or every other state.

## 4. Templates

Per language + engine templates live in `config/prompts/harness_*`. The LLM
fills the template; the template guarantees the engine entry point is present.

## 5. Safety

- Harness source is written to `fuzz_workspace/` only, never into the target
  project unless the user opts in.
- Generated harness source passes the static rules in
  `docs/standards/HARNESS_STANDARD.md` section 2 before any container starts.
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

## 6. Open Questions

- Should we support custom mutators (libFuzzer `custom_mutator`)?
- How to share harness scaffolding across engines for the same target?

## 7. Tests

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
