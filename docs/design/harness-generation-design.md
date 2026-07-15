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
    pub build_cmd: BuildCommand,
    pub sanitizer: Sanitizer,
    pub status: HarnessStatus, // Draft | Compiled | SmokePassed | Promoted
    pub smoke_run: Option<SmokeRunSummary>,
}
```

## 3. Pipeline

1. **Draft** -- LLM produces harness source from target signature + project
   context (includes, types, existing test patterns).
2. **Compile** -- `hf-runtime` builds the harness in-sandbox with the
   selected sanitizer + engine link flags.
3. **Smoke fuzz** -- run the engine for 60 seconds with a tiny seed corpus;
   require no immediate crash on empty input and at least one exec/sec.
4. **Iterate** -- on compile failure or smoke failure, feed diagnostics back
   to the LLM for up to N rounds (default 3).
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
- Build and smoke fuzz always run in `hf-runtime` sandbox.
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
