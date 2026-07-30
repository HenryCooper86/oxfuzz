# grok-build vs. oxfuzz — architecture study and actionable lessons

**Date:** 2026-07-19
**Subject:** x.AI's open-sourced `grok-build` agent harness (<https://github.com/xai-org/grok-build>)
**Method:** Full source clone (~73 MB, ~60 workspace crates under `crates/codegen/`, pinned via a
`SOURCE_REV` file) read directly, plus a breadth sweep. Claims about oxfuzz were cross-read
against our own crates.

> Provenance note: this report was produced by a research subagent that cloned and read the real
> grok-build tree (not a stub). Two of its most consequential claims were spot-checked by hand
> against our code and confirmed:
> - **L1 premise** — `hf-service/src/agent.rs:236-331` dispatches `discover`/`harness`/`run`/`triage`/`corpus`
>   via a plain string `match` with `arg_str()` extraction, no schema validation.
> - **Meta-finding** — `config/prompts/core_self_evolution.txt` references `agent-architect`,
>   `skill-creator`, and `tool-engineer` meta-agents; grepping `crates/` for those identifiers
>   returns nothing. The self-evolution prompt describes capabilities not implemented in code.
>
> Other file-level claims below are the subagent's and are reliable enough to act on, but verify
> the specific line before making a change.

---

## 1. What grok-build is

grok-build (`grok`) is x.AI's terminal-based AI coding agent — a full-screen Rust TUI (plus
headless and editor/ACP modes) that reads codebases, edits files, runs shell commands, searches
the web, and manages long-running tasks. It is a direct competitor to Claude Code / Codex /
opencode, and ports tool implementations from `openai/codex` and `sst/opencode`
(`crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md`). It is not a toy: `xai-grok-shell` alone
is ~338k lines, `xai-grok-tools` ~113k.

---

## 2. Architecture of grok-build's harness

### Agent loop — ReAct with two control layers stacked on top
Core is a classic ReAct loop (sample -> tool_calls -> execute -> feed results -> resample), in
`crates/codegen/xai-grok-shell/src/session/acp_session_impl/turn.rs`. Three nested loops:

- **Inner (ReAct):** `process_conversation_turn` (turn.rs:1693-2306) — `loop { build_request ->
  sample -> if tool_calls empty break else execute, continue }`. Turn ends when the model returns
  no tool calls (turn.rs:2112), subject to gates.
- **Middle (completion-requirement recovery):** `process_conversation_turn_with_recovery`
  (turn.rs:1346-1478) — if the agent definition declares a `completionRequirement { tool,
  reminder, recovery }`, the wrapper checks the required tool was called; if not, it injects the
  `reminder` as a synthetic user message and retries with exponential backoff up to `max_retries`.
- **Outer (goal continuation):** an autonomous "goal harness" that re-injects a continuation
  directive so the agent keeps working across model turns without new user input
  (`GoalRoundDecision::{Continue, EndTurn}`).

**Mid-loop steering** is done by pushing synthetic `system-reminder` user messages
(`push_system_reminder`, reminders.rs) picked up on the next iteration — used for MCP status, date
rollover, task-completion notifications, a "TodoGate" nudge, and user interjections.
**Interjections** (`xai-interjection-core`) are drained at the top of every ReAct iteration and
merged as genuine user turns — mid-turn steering without interrupting generation.

### Tool interface — native function-calling, streaming, declarative availability
- Tools are a **trait** (`crates/common/xai-tool-runtime/src/tool.rs`): `Tool` with associated
  `Args: JsonSchema` and streaming `execute -> ToolStream<Output>` (invariant `[Progress*,
  Terminal]`), type-erased via an object-safe `ToolDyn` blanket impl.
- **Schema = OpenAI-style function-calling JSON**, `parameters` generated from typed `Args` via
  `schemars::JsonSchema` (`registry/types.rs::generate_schema`). MCP tools pass server schema verbatim.
- **Declarative per-agent availability:** a boolean-expression DSL `Expr<ToolRequirement>`
  (`types/requirements.rs`) — a tool declares "I need tool X / any tool of kind K / param
  condition"; evaluated against the proposed toolset at `finalize()`. This is how
  `get_task_output`/`kill_task` only appear when a background-task producer is enabled.
- **Self-referential descriptions:** a `TemplateRenderer` lets tool docs write
  `tools.by_kind.read` / `params.edit.replace_all` so tool renames propagate into every other
  tool's description automatically.
- **Error recovery in tools:** codex-ported `apply_patch` uses a 4-pass fuzzy line matcher; `edit`
  returns the current file content on a failed match so the model needn't re-read; tool-parse
  errors feed back the JSON error position + original args (capped 2000 bytes).

### Context management — layered pruning + compaction
- **Compaction** (`crates/common/xai-grok-compaction`): triggers at `context_window * 85%`;
  `FullReplace` builds a structured 9-section summary (Primary Request, Key Concepts, Files/Code,
  Errors/Fixes, Pending Tasks, Current Work, Next Step...) via a dedicated prompt.
  **`snap_to_safe_boundary`** ensures an assistant's tool_calls and their tool_results are never
  split (orphaned `tool_use` -> provider 400). Rejects a compaction that didn't shrink >=20%.
- **Tool-output pruning** (separate, cheaper, `xai-chat-state`): after every user turn, eagerly
  soft-trims tool results (keep head+tail, `[...trimmed...]`) between `keep_last_n_turns=3` and
  `hard_clear_age_turns=10`, and hard-clears beyond that — no LLM call.
- **Memory** (`xai-grok-memory`, experimental): markdown `MEMORY.md` per workspace + SQLite
  FTS5+vec hybrid; a periodic "Dream" pass consolidates/deduplicates session logs.

### Prompting / skills — budget-aware progressive disclosure
Agent definitions are markdown + YAML frontmatter (`.grok/agents/*.md`), `promptMode: extend|full`
rendered through MiniJinja. **Skills** (`SKILL.md` dirs) use a **3-tier degrading renderer**
(`listing.rs`): Tier 1 full descriptions (capped 400 bytes), Tier 2 proportionally shortened, Tier
3 names-only with an overflow marker — Level-1 listing in the system prompt, Level-2 full body
loaded only when the `skill` tool invokes it. Vendor-compat: also reads `.claude/`, `.cursor/`
skill dirs. `AGENTS.md`/`CLAUDE.md` discovery walks repo-root -> cwd, deeper files win.

### Sandboxing / safety — OS-level, agent-scoped
`xai-grok-sandbox` wraps the `nono` crate -> **Landlock** (Linux >=5.13) / **Seatbelt** (macOS),
applied once process-wide and irreversibly. Profiles: `off`/`workspace`/`devbox`/`read-only`/`strict`.
**Permission pipeline** (5 steps): `PreToolUse` hooks -> rules (`deny > ask > allow`) -> remembered
grants -> built-in read-only auto-approvals (word-boundary shell allowlist) -> mode policy
(`default`/`dontAsk`/`bypassPermissions`/`acceptEdits`/`plan`). A hardcoded dangerous-commands list
(`rm`, `chmod`, `git push`, ...) always re-prompts. Plan mode is a 4-state machine that rejects
edits to any file except `plan.md`. Hooks fail open by design.

### Model interaction — 3-layer sampler, rich retry, self-correction
`xai-grok-sampler`: Layer 1 raw streams, Layer 2 `SamplingEvent`, Layer 3 concurrent actor with
cancellation. **Multi-backend routing:** one client protocol-adapts to OpenAI Chat Completions,
OpenAI Responses, and Anthropic Messages. **Retry classification** (`retry.rs`):
`RetryDecision::{Retry, RetryWithBackoff, RetryWithImageStrip, RetryWithClientRebuild,
EmitToSession, Fatal}` — 5xx retried 15x with jittered backoff, **first retry rebuilds the HTTP
client forcing HTTP/1.1** to escape a poisoned HTTP/2 pool, 413 strips images, context-overflow is
`Fatal`, auth errors trigger token refresh + resubmit. **Doom-loop detection:** the server streams
a `response.doom_loop_check` SSE event; the client aborts mid-stream and resamples on a separate
budget.

### Verification / self-correction — many layers, cheapest -> most-expensive
1. **TodoGate** — nudges `continue` if the turn ends with pending todos (capped fires).
2. **Laziness classifier** — LLM judge of whether the model prematurely stalled.
3. **completionRequirement recovery** — declarative per-agent invariant + backoff retry.
4. **Structured-output validation retry** — up to 3x on JSON-schema mismatch.
5. **Doom-loop resampling.**
6. **`/check-work` skill** — spawns a **verifier subagent** that reconstructs the request as a
   checklist, inspects real state (not the transcript's claims), builds+tests, and returns
   `VERDICT: PASS/FAIL`; the parent fixes and re-verifies up to 3x.
7. **Goal-harness "adversarial skeptic panel"** (`session/goal_classifier.rs`) — when the model
   claims a goal is complete, spawns N skeptic subagents in parallel, each returns a JSON verdict,
   aggregated by **majority-refute** voting; two identical "gap fingerprints" auto-pause the goal
   instead of burning the run cap.
8. **`/best-of-n` skill** — implements a task N ways in parallel isolated worktrees, evaluates all
   candidates on correctness/quality/safety, applies the winner.

### Genuinely novel / clever
- Requirement `Expr<T>` DSL for tool availability (declarative, not feature-flags).
- Self-referential `TemplateRenderer` descriptions surviving tool renames.
- Doom-loop server-assisted mid-stream resampling; HTTP/1.1-rebuild retry.
- Adversarial skeptic-panel goal verification with majority-refute + gap-fingerprint stall detection.
- Large-output "dump to disk + steer" (MCP results >20 KB written to `<session>/mcp/<id>.json`
  with a hint telling the model to `grep`/`bash` the file rather than a pager API).
- `search_tool`+`use_tool` lazy MCP discovery (never dumps full MCP schemas into context).

---

## 3. Head-to-head

| Dimension | grok-build | oxfuzz (today) |
|---|---|---|
| **Agent loop** | ReAct + completion-recovery + goal-continuation layers; native function-calling; `turn.rs` | Single ReAct loop, `hf-agent/src/lib.rs::run_turn`, `max_iterations`; prompt-based `{thought,tool,args}` JSON protocol, hand-parsed |
| **Tool interface** | Trait + `schemars` JSON Schema, native tool-calls, streaming, declarative `Expr` availability, self-referential descriptions | Split: fuzzing tools dispatched by ad-hoc `match` in `hf-service/src/agent.rs` (no schema validation); only 4 inspection tools use the real `hf-tools` JSON-Schema pipeline. Rich `hf-tools` framework built but largely unwired |
| **Context mgmt** | 85% compaction w/ structured summary + safe boundary; age-based tool-output pruning (free); Dream memory | `hf-context/src/simple.rs`, token budget, LLM compaction at budget; dead-branch pruning. Large `ContextPipeline`/`RecallStore`/memory framework unwired |
| **Prompting / skills** | Budget-aware 3-tier progressive disclosure; MiniJinja; self-verify/best-of-n/create-skill as skills | Static name-list skill injection (char cap), fixed prompt sections. "Self-evolving" is doc aspiration only — no agent-driven skill mutation |
| **Sandboxing** | OS-level Landlock/Seatbelt scoped to the agent's file access; 5-step permission pipeline; plan mode | **Docker** container isolation for untrusted harness/fuzzer execution (`hf-runtime`); risk-tiered `authorize_recorded` chokepoint + audit log; `ShellExec` hard-denied |
| **Model routing** | 3-layer sampler, multi-backend, rich in-stream retry classification, doom-loop resample | `hf-provider` tag-based routing, freeze/thaw backoff, 5 backends. No in-call retry/failover — only excludes failed provider on the next call |
| **Verification** | 8 layers incl. verifier subagent (PASS/FAIL loop) + adversarial skeptic panel + best-of-n | `LoopGuard` (redundant/repetition/oscillation/drift) — negative backstop only. No LLM self-verification loop; domain steps single-shot |

---

## 4. Concrete lessons (ranked)

### Genuinely worth adopting

**L1 — Route fuzzing-domain tools through the real schema-validated tool pipeline. [High impact / Medium effort]**
grok-build gives every tool a `schemars`-derived JSON Schema and native function-calling with
typed `Args`. Our privileged fuzzing tools (`discover`, `harness`, `run`, `triage`, `corpus`) are
dispatched by an ad-hoc `match` in `hf-service/src/agent.rs:236-331` that pulls args with
`arg_str()` — no schema validation, no typed args. The full validation pipeline (`ToolExecutor` ->
`JsonSchemaValidator`, Draft 7) already exists and is used for our 4 inspection tools
(`hf-agent/src/agent_tools.rs`). **Change:** give each fuzzing tool a JSON-Schema `ToolDefinition`
and route it through `ToolExecutor::execute`. Mostly wiring, not greenfield.

**L2 — Add an LLM self-verification loop for harness/run/triage outcomes. [High impact / Medium-High effort]**
grok-build's `check-work` skill spawns a verifier subagent that reconstructs the request as a
checklist, inspects actual state, and loops PASS/FAIL up to 3x; the goal harness escalates to an
adversarial skeptic panel with majority-refute voting. We have none — `harness_smoke` and
`triage_run` are single-shot, and `LoopGuard` only detects pathology. This is squarely our domain:
"did the harness actually compile and exercise the target?", "did the crash reproduce
deterministically?", "is coverage actually increasing?". **Change:** add a verification step (a
skill + a verifier agent using our existing depth-1 `delegate` tool) after harness generation and
triage that inspects sandbox outputs and returns a structured verdict, with a bounded
fix-and-recheck loop. Start with a deterministic PASS/FAIL verifier before the parallel skeptic
panel. **(This report's companion plan starts here — see
`.claude/plans/2026-07-19-agent-self-verification-loop.md`.)**

**L3 — Age-based tool-output pruning + large-output-to-disk, separate from compaction. [High impact / Low-Medium effort]**
Fuzzing tool results are huge (fuzzer logs, coverage reports, crash dumps). Today our only knobs
are dead-branch pruning and an expensive at-budget LLM compaction (`hf-agent/src/lib.rs::maybe_compact`);
UI-facing truncation is a crude char cut. grok-build cheaply hard-clears tool results older than
`hard_clear_age_turns=10` with no LLM call, and for oversized outputs writes the full payload to a
session file and steers the model to grep/read it. **Change:** (a) add free age-based
soft-trim/hard-clear of old tool results in `hf-context`; (b) persist large sandbox output to the
workspace and hand the model a path + hint. We already capture up to 1 MiB in `hf-runtime/docker.rs`.

**L4 — `completionRequirement` + positive "keep going" nudge. [Medium impact / Low-Medium effort]**
grok-build lets an agent require a specific tool be called before the turn ends (reminder +
backoff recovery) and has a TodoGate that nudges forward. Our `LoopGuard` is purely negative.
**Change:** add an optional `completion_requirement` to `AgentDefinition` and a reminder-injection
path in `run_turn`, reusing the synthetic-message idea (L5).

**L5 — System-reminder mid-loop injection as a general steering primitive. [Medium impact / Medium effort]**
grok-build's most reused mechanism is pushing synthetic `system-reminder` messages the next
iteration reads — underlying interjections, task-completion auto-wake, todo nudges, and completion
recovery. Our `run_turn` is a closed `for` loop with no injection channel. **Change:** add a
synthetic-message queue drained at the top of each iteration. Unlocks L4, background-task
completion notices for `hf-scheduler` runs, and eventual user interjection.

**L6 — Harden compaction against orphaned tool calls. [Prevents real bugs / Low effort]**
Our `maybe_compact` splits `[system][middle][tail]` and summarizes the middle. If the split lands
between an assistant tool_call and its tool_result, strict providers reject the request (400).
grok-build's `snap_to_safe_boundary` prevents this. **Change:** snap our split point past any
tool-call/tool-result run.

**L7 — In-call provider retry/failover. [Medium impact / Medium effort]**
grok-build's `retry.rs` retries within a call (backoff, HTTP/1.1 rebuild on a poisoned pool,
image-strip on 413, auth refresh + resubmit). Our `hf-provider` pool calls one provider once and
only fails over on the next call after freeze. **Change:** add bounded in-call retry with
error-classified backoff before returning `Err`; our `error_classifier.rs` already produces the taxonomy.

### They do it, but we already have equivalent or better
- **Sandboxing:** our Docker container isolation for untrusted, crashy, memory-corrupting fuzz
  targets is the right model for our threat surface. grok-build's Landlock/Seatbelt restricts the
  agent's own file access in-process — a weaker boundary that would be a downgrade for executing
  untrusted harnesses. Keep Docker.
- **Loop detection:** our `LoopGuard` (4 detectors on the full `(action, args)` signature) is
  comparable to grok-build's heuristics; grok-build also leans on a server-side signal we can't replicate.
- **Guardrails:** our risk-tiered `authorize_recorded` chokepoint + durable audit log is a clean,
  domain-fit design.
- **Orchestration:** `hf-scheduler`/`CampaignScheduler` (cron/interval campaigns, concurrency gate,
  portfolio round-robin) is a domain capability grok-build has no equivalent of.

### Not applicable to a fuzzing agent
- ACP / editor-embedding, `xai-codebase-graph` LSP go-to-definition, voice, plugin marketplace,
  TUI theming, auto-updater, vendor-compat skill dirs. Our "codebase understanding" is target
  discovery (`hf-discovery`), a different problem.
- `best-of-n` parallel worktree tournaments and Dream memory consolidation are clever but
  low-priority and would require a parallel-subagent facility we don't have (our `delegate` is
  depth-1 synchronous). Don't gold-plate.

---

## 5. What to explicitly NOT copy

1. **Do NOT replace Docker harness isolation with an in-process syscall sandbox.** grok-build's
   Landlock/Seatbelt sandboxes the agent, not untrusted execution. Our targets are adversarial,
   crash-prone binaries processing malformed input — they need container/VM isolation. Adopting
   grok-build's model here would be a security regression.
2. **Do NOT make native function-calling a hard requirement across the provider pool.** Our
   prompt-based `{thought,tool,args}` protocol is a deliberate portability choice across 5 backends
   incl. Ollama. Add native tool-calling as an option for capable providers (L1's schema validation
   works either way), but keep the prompt-based path.
3. **Do NOT port grok-build's three-crate compaction complexity.** Adopt the ideas (safe boundary,
   age-based pruning) as small additions to `hf-context`.
4. **Do NOT expand our unwired framework to match grok-build's breadth.** The opposite is the lesson.

### Meta-finding worth surfacing
oxfuzz carries a large amount of built, unit-tested, but unreachable framework ported from an
internal template: `ContextPipeline`, `InjectTools/Memory/Bootstrap`, `ContextManager`,
`ContextWindowGuard`, `RecallStore`, LTM/STM memory clients, `DynamicToolManager`, `ToolTaxonomy`,
`ToolActivationSet`, `ResultFormatter`, and `hf-core` traits (`AgentRunner`, `SkillRegistry`,
`MemoryClient`) with zero implementations. Worse, `AGENTS.md`/`CLAUDE.md` and
`config/prompts/core_self_evolution.txt` advertise "self-evolving skills" and
`agent-architect`/`skill-creator`/`tool-engineer` meta-agents that do not exist in code (verified).
grok-build's discipline is the contrast: it wires what it builds. Before adopting any new grok-build
idea, the higher-leverage move is to **wire or delete** this dead framework — several lessons above
(L1, L3, L5) are partly a matter of connecting components we already built. The claim/reality gap
in our own docs is itself a trust and maintenance hazard.

## July 29, 2026 follow-up

- Fresh upstream revision inspected: 5da6962e4adb9c857f3def762542b52b4ec3e522.
- July 22 sync a5727c5960452e7527a154b25cb5bf00cda0545e introduced
  the applicable durable one-shot occurrence-journal lesson.
- oxfuzz adopted only the architectural lesson: a permanent unique receipt,
  transactional pending history, fail-closed restart reconciliation, and
  explicit recovery.
- oxfuzz added its own 60-second renewable owner lease and 15-second heartbeat
  so a second process cannot acknowledge work still owned by a live scheduler.
- No grok-build implementation code or agent-specific notification protocol
  was copied.
- Exact repeated tool-call stationarity remains a separate candidate because
  oxfuzz already has loop guards and coverage-stagnation controls.
