# Design Overview

Status: **active**. Supersedes: none. Owner: oxfuzz core team.

## 1. Purpose

oxfuzz is an AI fuzzing agent. It discovers fuzzing targets in a project,
writes harnesses, drives fuzzing engines (AFL++, honggfuzz, libFuzzer, and
syzkaller), triages crashes, and iterates on corpus/coverage --
all under human-in-the-loop supervision.

## 2. Design Pillars

1. **Model-agnostic** -- the fuzzing workflow is encoded in Rust traits; the
   LLM is a pluggable reasoning engine.
2. **Safety-first** -- every build and fuzz run goes through `hf-runtime`
   sandboxing; generated harness source is reviewed by an LLM triage step and
   approved by a human before execution.
3. **Durable workflow** -- target -> harness -> engine -> crash -> corpus ->
   coverage -> target. This loop is stable across model generations.
4. **Observability** -- all run evidence is journaled and preserved; replay is
   available only for supported active-engine runs; cost and coverage deltas are
   first-class metrics.

## 3. Alignment Table

| Concept | Owner Crate | Contract | Design Doc |
| --- | --- | --- | --- |
| LLM provider pool | hf-provider | `LlmProvider`, `ProviderPool` | (reuse y-agent) |
| Target discovery | hf-discovery | `TargetCandidate`, `TargetInventory` | target-discovery-design.md |
| Semgrep target enrichment | hf-discovery + hf-service | `SemgrepFinding`, `SemgrepTargetScore`, `SemgrepInventoryView` | target-discovery-design.md + service-orchestration-design.md |
| Project build context | hf-discovery + hf-core | `BuildContext`, `CompileEntry` | harness-generation-design.md |
| Harness generation | hf-harness | `Harness`, `HarnessDraft` | harness-generation-design.md |
| Engine integration | hf-engine | `EngineAdapter`, `FuzzRunConfig`, `FuzzProgress` | engine-integration-design.md |
| Automotive protocol contracts | hf-automotive | versioned DTO + `Validate` contract | automotive-protocol-fuzzing-design.md |
| Crash triage | hf-crash | `Crash`, `CrashReport`, `CrashOrigin` | crash-triage-design.md |
| Finding proof view | hf-service | `FindingProofCard`, `CrashReviewItem` | finding-proof-card-design.md |
| Corpus management | hf-corpus | `Corpus`, `CorpusEntry` | corpus-coverage-design.md |
| Coverage tracking | hf-coverage | `CoverageReport` | corpus-coverage-design.md |
| Campaign evidence and advice | hf-service + hf-coverage | versioned evidence/advice DTOs | proof-carrying-campaign-intelligence.md |
| Sandbox / runtime | hf-runtime | `RuntimeAdapter` | runtime-design.md |
| Tool registry | hf-tools | `Tool`, `ToolRegistry` | ../standards/TOOL_CALL_PROTOCOL.md |
| Skill evolution | hf-skills | `SkillRegistry` | (reuse y-agent) |
| Agent prompt security | hf-prompt | - | agent-prompt-security-design.md |
| Service orchestration | hf-service | - | service-orchestration-design.md |
| Durable one-time schedule occurrences | hf-scheduler + hf-storage + hf-service | `OneTimeOccurrence`, `OneTimeRecoveryView` | portfolio-campaigns.md + service-orchestration-design.md + DATABASE_SCHEMA.md |
| Agent loop | hf-agent | `AgentDelegator` | agent-prompt-security-design.md |
| Web API security / transport | hf-web | - | web-api-security-design.md |
| Remediation handoff | hf-crash + hf-service | versioned remediation DTO | proof-carrying-campaign-intelligence.md |

## 4. Crate Dependency Rules

- All crates may depend on `hf-core`.
- Domain crates (`hf-discovery`, `hf-harness`, `hf-engine`, `hf-crash`,
  `hf-corpus`, `hf-coverage`) depend on `hf-core` and may depend on each other
  only through `hf-core` traits or via `hf-service`.
- `hf-automotive` is a pure optional schema leaf: it has no execution or
  service dependency. Future orchestrators consume it optionally behind the
  `automotive-scapy` feature; it never depends outward on them.
- `hf-service` depends on domain + infrastructure crates; presentation crates
  (`hf-cli`, `hf-web`) depend only on `hf-service`.
- No presentation crate imports a domain or infrastructure crate directly.

## 4.1 Effective Runtime Configuration

Configuration exposed to operators is part of the runtime contract, not merely
serialized UI state. Provider token prices are copied into the corresponding
`ProviderMetadata` so both cost-aware routing and recorded spend use the same
values. Global knowledge, session, and scheduler settings are resolved by
`hf-service` and passed to their owning infrastructure components. Unsupported
settings are rejected or removed instead of being accepted as no-ops.

Operator fuzzing settings are a service-owned execution policy. The validated
`[fuzzing]` table in `oxfuzz.toml` defines the allowed engine set, the
default engine and duration presented to interactive clients, the maximum
requested duration, and the memory/CPU limits recorded in each
`FuzzRunConfig`. `hf-service` resolves that policy immediately before harness
work or execution, so desktop, REST, CLI, agents, and schedules cannot bypass a
disabled engine. An already-running campaign keeps the policy snapshot it
started with.

Mandatory safety boundaries are deliberately not configurable: generated
harnesses still require smoke evidence and explicit human promotion, all builds
and runs still use `hf-runtime`, and fuzzer network access remains disabled.
Presentation layers may display those guarantees but must not expose switches
that imply they can be weakened.

Automotive protocol support follows the same split. Product crates enable the
feature by default so the workspace is always present, while a
`--no-default-features` build has no Scapy or Python requirement. The optional
`hf-automotive` crate owns only versioned, serializable protocol contracts and
deterministic evidence hashing.
The pinned Scapy adapter is a separately packaged runtime component;
`hf-service` owns runtime enablement, capability negotiation, policy, scoped
approval, immutable artifact staging, retained evidence, and state-corpus
promotion. It also owns deterministic campaign synthesis and citation-validated,
advisory AI interpretation; state novelty is never recast as source coverage or
a vulnerability. REST, CLI, and desktop surfaces call those service operations
and do not construct sidecar commands, resolve host interfaces, or recompute
report findings themselves.

Browser configuration uses service-owned typed DTOs for protected integration
settings. Secret values, secret environment names, headers, and absolute paths
are never returned; omitted protected fields are preserved and replacement or
clearing must be explicit. The same service boundary returns the validated
fuzzing policy so clients fail closed instead of rebuilding defaults from raw
TOML.

Integration patch read-modify-write transactions are serialized per resolved
config directory within a process. Potentially path-shaped values use an opaque
configured/value state and never round-trip a redaction marker. Atomic file
replacement protects integrity across processes, but cross-process updates are
not serialized and therefore remain last-writer-wins.

Schedule definitions inherit scheduler defaults when a per-schedule policy is
absent. Once resolved, concurrency and hourly-rate policies are enforced before
dispatch, and every policy skip or cancellation remains visible in execution
history. Cron expressions are evaluated in their persisted IANA timezone; new
non-UTC schedules use the explicit `CRON_TZ=<zone> <expression>` form.

One-time schedules use a durable SQLite occurrence receipt before dispatch;
recurring schedules retain their existing scheduling path.

## 5. Open Questions

1. Tree-sitter vs. clang AST for C/C++ target discovery? (Leaning: Tree-sitter
   for portability, clang AST optional for precision.)
2. Should `hf-runtime` support native sandbox (seccomp/pledge) in addition to
   Docker?
3. How to share corpora across engines for the same target?
4. How should syzkaller's kernel-campaign configuration coexist with the
   userspace fuzzing policy?

## 6. Rejected Alternatives

- **Wrapping OSS-Fuzz directly** -- too project-specific; we need a
  target-level, not project-level, workflow.
- **Single engine** -- the value is engine portability; AFL++ and honggfuzz
  have complementary strengths.
- **Host execution of generated harnesses** -- rejected for safety; sandbox
  is mandatory.

## 7. Validation Checklist

- [ ] Execution-oriented domain crates expose shared traits in `hf-core`; pure
      schema crates expose an explicitly versioned serialization contract.
- [ ] No presentation crate imports a domain crate.
- [ ] `cargo check --workspace` passes.
- [ ] `cargo clippy --workspace -- -D warnings` passes.
- [ ] At least one integration test covers the discover -> harness -> run ->
      triage loop end-to-end (mocked engine).
