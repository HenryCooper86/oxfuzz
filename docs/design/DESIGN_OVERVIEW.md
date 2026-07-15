# Design Overview

Status: **active**. Supersedes: none. Owner: hobot_fuzz core team.

## 1. Purpose

hobot_fuzz is an AI fuzzing agent. It discovers fuzzing targets in a project,
writes harnesses, drives fuzzing engines (AFL++, honggfuzz, libFuzzer,
oss-fuzz/ClusterFuzzLite), triages crashes, and iterates on corpus/coverage --
all under human-in-the-loop supervision.

## 2. Design Pillars

1. **Model-agnostic** -- the fuzzing workflow is encoded in Rust traits; the
   LLM is a pluggable reasoning engine.
2. **Safety-first** -- every build and fuzz run goes through `hf-runtime`
   sandboxing; generated harness source is reviewed by an LLM triage step and
   approved by a human before execution.
3. **Durable workflow** -- target -> harness -> engine -> crash -> corpus ->
   coverage -> target. This loop is stable across model generations.
4. **Observability** -- every run is journaled and replayable; cost and
   coverage deltas are first-class metrics.

## 3. Alignment Table

| Concept | Owner Crate | Trait (hf-core) | Design Doc |
| --- | --- | --- | --- |
| LLM provider pool | hf-provider | `LlmProvider`, `ProviderPool` | (reuse y-agent) |
| Target discovery | hf-discovery | `TargetCandidate`, `TargetInventory` | target-discovery-design.md |
| Harness generation | hf-harness | `Harness`, `HarnessDraft` | harness-generation-design.md |
| Engine integration | hf-engine | `FuzzEngine`, `FuzzRunHandle` | engine-integration-design.md |
| Crash triage | hf-crash | `Crash`, `CrashReport` | crash-triage-design.md |
| Corpus management | hf-corpus | `Corpus`, `CorpusEntry` | corpus-coverage-design.md |
| Coverage tracking | hf-coverage | `CoverageReport` | corpus-coverage-design.md |
| Sandbox / runtime | hf-runtime | `RuntimeAdapter` | runtime-design.md |
| Tool registry | hf-tools | `Tool`, `ToolRegistry` | (reuse y-agent) |
| Skill evolution | hf-skills | `SkillRegistry` | (reuse y-agent) |
| Service orchestration | hf-service | - | service-orchestration-design.md |
| Agent loop | hf-agent | `AgentDelegator` | (reuse y-agent) |
| Web API security / transport | hf-web | - | web-api-security-design.md |

## 4. Crate Dependency Rules

- All crates may depend on `hf-core`.
- Domain crates (`hf-discovery`, `hf-harness`, `hf-engine`, `hf-crash`,
  `hf-corpus`, `hf-coverage`) depend on `hf-core` and may depend on each other
  only through `hf-core` traits or via `hf-service`.
- `hf-service` depends on domain + infrastructure crates; presentation crates
  (`hf-cli`, `hf-web`) depend only on `hf-service`.
- No presentation crate imports a domain or infrastructure crate directly.

## 5. Open Questions

1. Tree-sitter vs. clang AST for C/C++ target discovery? (Leaning: Tree-sitter
   for portability, clang AST optional for precision.)
2. Should `hf-runtime` support native sandbox (seccomp/pledge) in addition to
   Docker?
3. How to share corpora across engines for the same target?
4. ClusterFuzzLite integration: wrapper around its scripts, or native
   reimplementation?

## 6. Rejected Alternatives

- **Wrapping OSS-Fuzz directly** -- too project-specific; we need a
  target-level, not project-level, workflow.
- **Single engine** -- the value is engine portability; AFL++ and honggfuzz
  have complementary strengths.
- **Host execution of generated harnesses** -- rejected for safety; sandbox
  is mandatory.

## 7. Validation Checklist

- [ ] Every domain crate exposes a trait in `hf-core`.
- [ ] No presentation crate imports a domain crate.
- [ ] `cargo check --workspace` passes.
- [ ] `cargo clippy --workspace -- -D warnings` passes.
- [ ] At least one integration test covers the discover -> harness -> run ->
      triage loop end-to-end (mocked engine).
