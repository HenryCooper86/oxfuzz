# Session Event Log Design

Status: **proposed**. Supersedes: none. Owner: `hf-session`, `hf-storage`,
`hf-context`, `hf-agent`.
Related: `docs/design/deepseek-harness-study.md` item 2.1,
`docs/design/agent-prompt-security-design.md`, `AGENTS.md` 2.13.

## 1. Purpose

Decide whether oxfuzz should move from "a session tree with checkpoints plus a
persisted transcript" to "an append-only event log from which the provider
message array is derived".

This document exists to make that decision reviewable. It is written before the
work rather than to justify it, and **the recommended answer is not yet** --
see section 7. The analysis is worth having anyway, because it sharpens two
claims oxfuzz already makes and currently under-delivers.

## 2. The invariant

`AGENTS.md` 2.13, adopted from the DeepSeek Harness study:

> Anything that reaches a provider request must be reconstructable from
> persisted state. A new model-visible input requires a new persisted record.

DeepSeek Harness states it as "model-visible implies logged" and enforces it at
runtime. Its payoff is not tidiness. It is that fork, resume, replay, transcript
export, token metering, and compaction all become the *same* mechanism, because
each is a different projection of one log.

## 3. What oxfuzz promises today, and what it delivers

| Promise | Source | Status |
| --- | --- | --- |
| "every run, corpus mutation, and crash is journaled and replayable" | `VISION.md` | Partial |
| "replay is available only for supported active-engine runs" | `DESIGN_OVERVIEW.md` section 2 | The concession |
| "WAL-based recoverability" | `AGENTS.md` design pillars | Holds for runs |
| Prompt contract asserted on a captured `ChatRequest` | `agent-prompt-security-design.md` section 6 | Asserted at send time, not reconstructable afterwards |

The gap is specific: run evidence is durable, but the *agent's* model-visible
input is not independently reconstructable. A campaign can be replayed; the
reasoning that produced its harness cannot be re-derived from storage.

## 4. Proposed shape

`hf-session` gains an append-only `SessionEvent` log. The provider message array
is **derived**, never stored:

```rust
pub fn derive_messages(surface: &Surface) -> Vec<ChatMessage>;
```

A *surface* is the ordered projection of message-producing events. Non-message
events (policy decisions, approvals, compaction brackets, tool dispatch records)
are logged but never projected.

Three consequences that carry the value:

- **Compaction becomes a surface operation.** A summary rides on a message
  carrying `replace(start, end)` rather than mutating history. Nothing is
  deleted; the shadowed span stays for audit. This is how `hf-context`'s
  existing compaction and pruning can keep their algorithms while gaining a
  reviewable record of what they hid.
- **Crash recovery closes rather than truncates.** A crashed turn is repaired by
  durably appending synthetic closers -- an error result for each unanswered
  tool call, then the turn terminator -- so a rehydrated history is a *valid*
  provider transcript. Only a torn tail is dropped. This is what
  `hf-service::recovery` is reaching for.
- **The replay fixture is the log.** A recorded session replays as a provider
  double with no separate recording format to maintain, which is the concrete
  enabler for the provider test tier in the test-tiering proposal.

## 5. Cost

Honest accounting, because this is the expensive item.

- `hf-session` (`manager.rs` is 59 KB, `canonical.rs` 21 KB, `checkpoint.rs`
  24 KB) is rewritten around events rather than around a tree of states.
- `hf-storage` gains an event table and a replay path; `DATABASE_SCHEMA.md`
  (34 KB) changes materially, and existing rows need a migration or a declared
  discontinuity.
- `hf-context` compaction and pruning move from mutating a message vector to
  emitting surface operations.
- `hf-agent`'s loop appends events rather than assembling messages directly.
- Every presentation layer that reads a transcript reads a projection instead.

This is weeks, and it touches the crates whose tests are the safety net for
everything else. It is not a change to start alongside four other refactors.

## 6. Cheaper partial adoptions

Each is independently valuable and none forecloses the full change.

1. **Assert the invariant without implementing it.** Extend the existing
   prompt-contract test so it reconstructs the `ChatRequest` from persisted
   state and asserts equality with what was sent. If that test cannot be
   written, the gap is measured rather than argued. **Do this first.**
2. **Bracket long operations.** Append a start record before the async work and
   an end record last, so a crash leaves a detectable orphan rather than a
   false success. Applies to harness build, smoke fuzz, campaign, and triage
   with no event-log dependency at all.

   **Resolved 2026-08-19: no schema change, and most of this is already done.**
   The question left open was whether brackets belong in the database, since
   `sessions.last_compaction` and `sessions.compaction_count` exist and nothing
   writes them. They are the wrong shape and should stay unused by this work: a
   counter is written *after* the fact, so it records exactly the false success
   a bracket exists to prevent. Making them bracket-shaped means adding an
   in-progress column plus a startup sweep, which is a second implementation of
   something the codebase already has.

   The substrate is the file-backed journal. oxfuzz has it twice --
   `hf-service::recovery::RunJournal` and
   `hf-service::semgrep_recovery::SemgrepJournal` -- both appending an open
   record before the work and a close record after, both surfacing
   open-without-close at startup. A third substrate would be a third thing to
   reconcile during recovery.

   Against that, of the four operations named above:

   - **Smoke fuzz** and **fuzz runs** are bracketed (`container/harness.rs`,
     `container/run.rs`), and `container/lifecycle.rs` reconciles the orphans to
     `Failed` on the next launch.
   - **Semgrep operations** are bracketed by their own journal.
   - **Harness build** and **triage** persist no in-progress state at all: they
     read, compute, and return. A crash leaves nothing claiming to be running,
     so there is no orphan to detect and a bracket around them would be
     ceremony rather than safety. Do not add one.
   - **Campaign executions** are the open question. A crashed campaign's *run*
     row is reconciled, but no startup sweep for a `ScheduleExecution` left in
     `Running` was found. Confirm before building anything; that, and not
     compaction, is where remaining value would be.

   Compaction, the operation the upstream pattern is named for, is the worst
   candidate here rather than the first: `hf-agent::maybe_compact` holds an
   in-memory `Vec<Message>` with no storage handle and no session id, so
   bracketing it means threading identity through the agent loop before there is
   anything to record.
3. **Log compaction decisions.** Record what was hidden and why, even while
   compaction still mutates the message vector. This is most of the audit value
   for a fraction of the work.

## 7. Recommendation

**Not yet.** Do 6.1 through 6.3 in the current architecture and re-open this
document once they are in place, for three reasons:

- 6.1 converts a hypothesis into a measurement. If the reconstruction test
  passes, the promise is already kept and this whole change is unnecessary.
- The Tier 1 work from the study touches `hf-guardrails`, `hf-context`, and
  `hf-service`. Rewriting `hf-session` underneath it would make every one of
  those changes harder to review.
- oxfuzz's log is not primarily a conversation. It is *fuzzing evidence* --
  corpora, coverage deltas, crash reproducers, policy decisions. A design copied
  from a coding agent's conversation log needs a pass for that difference before
  it is committed to, and that pass has not been done.

## 8. Rejected alternatives

- **Store the message array directly and version it.** Rejected: it is the
  current design's problem restated. A stored array cannot express "this span is
  hidden from the model but retained as evidence" without a second mechanism.
- **Event-source only the agent loop, leave runs on the WAL.** Rejected as a
  starting point: two durable models for one session is the drift this
  document exists to avoid. Reconsider only if 6.1 shows the gap is confined to
  the agent loop.
- **Adopt DeepSeek Harness's `SessionEvent` taxonomy directly.** Rejected: it
  models a coding agent's turns and tool calls. oxfuzz's durable facts include
  campaign progress, coverage deltas, and approval bound to a harness revision,
  which that taxonomy has no place for.

## 9. Validation checklist

Applies when this document moves to **active**, not before.

- [ ] `derive_messages` is pure and total over any log a writer can produce.
- [ ] A session forked at a boundary produces a prefix that is a valid provider
      transcript.
- [ ] A log with an unanswered tool call rehydrates to a valid transcript
      through synthetic closers, and the repair is durable.
- [ ] A torn tail is the only content dropped on load.
- [ ] The captured `ChatRequest` equals the one reconstructed from the log.
- [ ] Compaction never splits an assistant tool call from its result.
- [ ] Approval bound to a harness revision survives fork and resume, and the
      armed state does not.
