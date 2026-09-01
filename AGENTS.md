# oxfuzz Engineering Protocol

Scope: entire repository. All rules are mandatory.

## 1) Project Snapshot

**oxfuzz** -- Rust-first AI fuzzing agent. Phase: **active implementation**.

Goal: an autonomous agent that analyzes a target project, identifies functions
worth fuzzing, writes fuzz harnesses, drives open-source fuzzing engines
(AFL++, honggfuzz, libFuzzer, and syzkaller), triages crashes, and
iterates on corpus and coverage -- all under human-in-the-loop supervision.

Design pillars: async-first (P95 tool dispatch < 100ms) - model-agnostic -
full observability - WAL-based recoverability - user-extensible skills -
**safety-first fuzzing** (sandboxed builds and execution).

### 1.1 Workspace Crates

**Core**: `hf-core`
**Infrastructure**: `hf-provider` - `hf-session` - `hf-context` - `hf-storage` - `hf-knowledge` - `hf-diagnostics` - `hf-spill`
**Middleware**: `hf-guardrails` - `hf-prompt`
**Capabilities**: `hf-tools` - `hf-skills` - `hf-runtime` - `hf-scheduler`
**Fuzzing Domain**: `hf-discovery` - `hf-harness` - `hf-engine` - `hf-crash` - `hf-corpus` - `hf-coverage` - `hf-analysis` - `hf-automotive`
**Orchestration**: `hf-agent`
**Service**: `hf-service` (all business logic)
**Presentation**: `hf-cli` (CLI + TUI) - `hf-web` (REST API) - `hf-gui` (Tauri desktop app, `crates/hf-gui/src-tauri`)
**Testing**: `hf-test-utils`

### 1.2 Repository Layout

```
oxfuzz/
  docs/
    design/            -- detailed design documents
    standards/         -- engineering, testing, DB, skills, tool-call, target, harness standards
  config/
    prompts/           -- core prompt sections bundled by hf-prompt; prompts.example.toml
                          documents the override format
  crates/              -- Rust workspace crates (skills and agent definitions are built into
                          hf-skills and hf-agent; user definitions may be dropped into the
                          runtime config dir, none ship as repository files)
  data/                -- runtime SQLite data
  docker/              -- sandbox image build context
  examples/            -- small example projects used by demos and tests
  scripts/             -- automation, release, health-check, test helper scripts
  sidecars/            -- sandbox-external helper services (e.g. scapy automotive lab)
  tests/               -- workspace-level integration tests
  third_party/         -- vendored third-party material (semgrep, semgrep-rules)
  fuzz_workspace/      -- runtime corpora, crashes, build artifacts (gitignored)
```

## 2) Engineering Principles

- **2.1 Architectural Stability** -- Extend via traits/middleware/plugins; feature-flag every new subsystem.
- **2.2 Separation of Concerns** -- `hf-service` orchestrates business logic; Presentation layers are thin I/O wrappers; Fuzzing-domain crates (`hf-discovery`, `hf-harness`, `hf-engine`, `hf-crash`, `hf-corpus`, `hf-coverage`) provide discrete functions; Infrastructure safely abstracts state.
- **2.3 Explicit Over Implicit** -- State assumptions; document rejected alternatives; measurable success criteria.
- **2.4 Token Efficiency** -- Skill root docs <= 2 000 tokens; MAP steps <= 2 000 tokens; Working Memory carries `token_estimate`.
- **2.5 Defense in Depth for Fuzzing** -- Isolation via sandboxed build (`hf-runtime`) -> Interception via middleware (`hf-guardrails`) -> User-approved execution (HITL). Fuzzing executes untrusted, possibly malformed code; no single abstraction layer failure makes the system unsafe. Never run a generated harness on the host without explicit user approval.
- **2.6 Fail Fast, Recover Cheap** -- Checkpoint at task level; retry from failed step; freeze/thaw providers; compensation for side effects.
- **2.7 TDD** -- Red -> Green -> Refactor. No production code without a preceding test. See `docs/standards/TEST_STRATEGY.md`.
- **2.8 English** -- All docs, comments, commits in English.
- **2.9 Service-Layer Ownership** -- All business logic lives in `hf-service`; `hf-cli`, `hf-web` are thin presentation layers -- they handle I/O, rendering, and user interaction only. No domain logic in presentation crates.
- **2.10 No Inline Lint Suppression** -- Never add `#[allow(clippy::...)]`, `#[allow(rustc_lint)]`, or `// eslint-disable` to source code by default. Fix the lint, refactor the code, or move the rule adjustment to the owning config with a comment explaining why. The sole Rust exception is `#[allow(dead_code)]` on struct fields/variants kept for API completeness.
- **2.11 Modular & Concise Code** -- Code should be modular and concise, with logic broken into reusable components or functions. Minimize duplication through abstraction and ensure loose coupling by managing dependencies carefully.
- **2.12 Fuzzing Safety First** -- Every harness build and fuzzer invocation must go through `hf-runtime` sandboxing. Engine binaries are not trusted. Generated harness source is reviewed by an LLM triage step AND approved by a human before execution. Crash artifacts are parsed in a sandbox; untrusted inputs never touch the host filesystem outside the workspace.
- **2.13 Model-Visible Implies Logged** -- Anything that reaches a provider request must be reconstructable from persisted state. A new model-visible input requires a new persisted record, not an ad-hoc field on a struct in memory.
- **2.14 Trust the Type System at Typed, Same-Process Boundaries** -- Do not add runtime validation, fallback behavior, or hostile-input tests solely for values the Rust type already guarantees. Validate at the boundaries that actually admit foreign data: config and CLI parsing, provider and tool JSON, durable/file formats, sandbox and process boundaries, and the REST/IPC wire.
- **2.15 Explicit Defaults at Crate Boundaries** -- Defaulting is an explicit `resolve(request) -> Spec` step in the owning implementation, never a hidden `unwrap_or_default()` inside the operation. A `DEFAULT_*` constant or a test hook is not configurability: a deployment-varying choice is a validated config field.
- **2.16 Misconfiguration Fails Loud** -- Fail at load when the problem is self-contained, otherwise at the earliest resolvable point. Never silently skip a missing referent, and never accept a setting the owning component does not read.
- **2.17 Swallowed Errors Are Named** -- Every `let _ = ...`, `.ok()`, and `unwrap_or_default()` on a fallible call carries a comment naming what is being swallowed and why nothing else can reach it. Keep the fallible expression to one call.
- **2.18 Prefer Symmetry for Parallel Values** -- Unexplained asymmetry between two things that should be parallel usually signals a missed extraction. One meaning gets one home; two consumers of that meaning derive it from that home rather than restating it.
- **2.19 Enforce a Decision in the Operation That Makes It** -- Schema omission, prompt filtering, facades, wrappers, and listener order are not enforcement when a direct or alternate caller can bypass them. Test every denial through the executor that actually runs the action.
- **2.20 Tests Describe Behavior, Not Correctness** -- A passing test is evidence of behavior, not proof of correctness. When behavior is genuinely obsolete, change it together with its tests and explain why in the commit.

## 3) Risk Tiers

- **Low** -- typo fixes, open question additions
- **Medium** -- new sections, targets, alternatives
- **High** -- shared concepts (permission model, sandbox policy, harness generation pipeline, engine adapter contract), `DESIGN_OVERVIEW.md` alignment table, multi-doc changes

When uncertain -> High.

## 4) Agent Workflow

### 4.1 Implementation (TDD)

> Standards: `docs/standards/TEST_STRATEGY.md` - `docs/standards/ENGINEERING_STANDARDS.md`

- **Before coding**: read the design doc in `docs/design/` + `DESIGN_OVERVIEW.md`. Implementation must conform. Impractical design -> update doc first, then code.
- **TDD cycle**: Red (failing test) -> Green (minimal code) -> Refactor -> Repeat.
- Rust casing: `snake_case` files/fns - `PascalCase` types - `SCREAMING_SNAKE_CASE` consts.
- Dependencies point inward to `hf-core`; every subsystem behind a feature flag.

### 4.2 Sub-Agent Work

- Read `docs/standards/AGENT_AUTONOMY.md` before designing or implementing any sub-agent component (delegation, agent pools, autonomy).

### 4.3 R&D Planning

- **Before any R&D action**: write a plan to `.claude/plans` covering scope, steps, dependencies, and verification criteria. No implementation until the plan exists.

### 4.4 Commit Discipline

- One concern per change; cross-doc changes in one batch; English commit messages; no secrets.

### 4.5 Post-Development Quality Gates

After completing Rust code changes, run the following checks **in order** and fix all issues before considering the task done.

- **`cargo fmt --all`** -- Format all workspace crates according to `rustfmt.toml`.
- **`cargo clippy --fix --allow-dirty --workspace -- -D warnings`** -- Automatically apply Clippy suggestions.
- **`cargo clippy --workspace -- -D warnings`** -- All Clippy lints must pass with zero warnings.
- **`cargo check --workspace`** -- Full workspace compilation must succeed with no errors.
- **`cargo doc --workspace --no-deps`** -- Documentation must build without errors.

No task is complete until every applicable gate passes cleanly.

### 4.6 Rust Test Output Filtering

When running `cargo test`, always pipe output through `grep` to extract error information. Use the following filter:

```bash
cargo test [args] 2>&1 | grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' | head -200
```

## 5) Key References

- `docs/standards/DEFENSIVE_PATTERNS.md` -- Bug-class rules for lifecycle, concurrency, subprocess, sandbox, and teardown code
- `docs/standards/TEST_STRATEGY.md` -- TDD methodology, pyramid, quality gates
- `docs/standards/ENGINEERING_STANDARDS.md` -- Rust coding standards
- `docs/standards/DATABASE_SCHEMA.md` -- SQLite schema
- `docs/standards/AGENT_AUTONOMY.md` -- Sub-agent autonomy model & delegation protocol
- `docs/standards/TOOL_CALL_PROTOCOL.md` -- Tool call protocol specification
- `docs/standards/TARGET_TAXONOMY.md` -- Fuzzing target classification
- `docs/standards/HARNESS_STANDARD.md` -- Harness authoring and validation standard
- `docs/standards/ENGINE_ADAPTER_STANDARD.md` -- Fuzzing engine adapter contract

## 6) Formatting Constraints

- **No emoji anywhere.**
- **Word choice** -- Before writing `contract`, `boundary`, or `shape`, ask whether a more exact term names the subject: write `trait method`, `JSON validation`, or `public API` instead. No metaphors. Do not comment on facts that are obvious from the code.

## 7) TODO Tiers

Three markers with release semantics, so a grep answers "what blocks a tag":

- `FIXME` -- blocks a release. A known defect on a shipped path.
- `TODO` -- soon. Planned work with a named owner or issue.
- `XXX` -- someday. An idea recorded so it is not rediscovered.

## 8) Pre-1.0 Stance

**Remove this section at the first 1.0 release.** oxfuzz has no external
consumers pinned to its internal APIs. Prefer the correct foundation over a
compatibility shim: rename, repackage, or re-layer freely, and update every
reference in the same change.
