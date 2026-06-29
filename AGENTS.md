# hobot_fuzz Engineering Protocol

Scope: entire repository. All rules are mandatory.

## 1) Project Snapshot

**hobot_fuzz** -- Rust-first AI fuzzing agent. Phase: **active implementation**.

Goal: an autonomous agent that analyzes a target project, identifies functions
worth fuzzing, writes fuzz harnesses, drives open-source fuzzing engines
(AFL++, honggfuzz, libFuzzer, oss-fuzz/ClusterFuzzLite), triages crashes, and
iterates on corpus and coverage -- all under human-in-the-loop supervision.

Design pillars: async-first (P95 tool dispatch < 100ms) - model-agnostic -
full observability - WAL-based recoverability - self-evolving skills -
**safety-first fuzzing** (sandboxed builds and execution).

### 1.1 Workspace Crates

**Core**: `hf-core`
**Infrastructure**: `hf-provider` - `hf-session` - `hf-context` - `hf-storage` - `hf-knowledge` - `hf-diagnostics`
**Middleware**: `hf-hooks` - `hf-guardrails` - `hf-prompt` - `hf-mcp`
**Capabilities**: `hf-tools` - `hf-skills` - `hf-runtime` - `hf-scheduler` - `hf-journal`
**Fuzzing Domain**: `hf-discovery` - `hf-harness` - `hf-engine` - `hf-crash` - `hf-corpus` - `hf-coverage`
**Orchestration**: `hf-agent` - `hf-bot`
**Service**: `hf-service` (all business logic)
**Presentation**: `hf-cli` (CLI + TUI) - `hf-web` (REST API) - `hf-gui` (Tauri desktop app, `crates/hf-gui/src-tauri`)
**Testing**: `hf-test-utils`

### 1.2 Repository Layout

```
hobot_fuzz/
  docs/
    design/            -- detailed design documents
    standards/         -- engineering, testing, DB, DSL, skills, tool-call, target, harness standards
  config/
    agents/            -- agent configuration
    prompts/           -- prompt templates (discovery, harness, triage)
  crates/              -- Rust workspace crates
  data/                -- runtime SQLite data
  scripts/             -- automation, release, health-check, test helper scripts
  skills/              -- bundled skill content (target-triage, harness-author, crash-triage)
  tests/               -- workspace-level integration tests
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

- `DESIGN_RULE.md` -- Design doc standards, playbooks, validation checklist
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