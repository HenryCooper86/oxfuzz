# Sandbox Outcome Classification and Root Derivation Design

Status: **proposed**. Supersedes: none. Owner: `hf-runtime` and `hf-tools`.
Related: `runtime-design.md`, `docs/standards/DEFENSIVE_PATTERNS.md` rules 1, 6,
and 8, `docs/design/deepseek-harness-study.md` items 2.2 and 2.3.

## 1. Purpose

Two narrow changes to the sandbox boundary, both prompted by the DeepSeek
Harness study and both scoped down after reading the current implementation.

1. A sandboxed command's terminal outcome does not distinguish *confinement
   refused the operation* from *the runner never started it*. Both are sandbox
   errors today. For a fuzzing agent those are different facts with different
   operator actions, and either can be mistaken for a target crash.
2. `hf-runtime` and `hf-tools` each derive the paths they will admit. They agree
   today. Nothing makes them agree tomorrow.

Neither is a reported defect. Both are places where the current design leaves a
correct answer to convention rather than to a mechanism.

## 2. What already holds

Stated here so the change does not re-litigate it.

`hf-runtime` returns exactly one terminal outcome per started command --
`Completed`, `TimedOut`, or `Cancelled` -- and exit status is authoritative only
for `Completed` (`runtime-design.md` section 5). `hf-engine::runner` branches on
that outcome before reading `exit_code`. Spawn errors, invalid workspace paths,
and failed forced teardown are sandbox errors rather than run results.

`hf-runtime` resolves the real filesystem path of a workspace before mounting,
reading, or writing it, validates a missing path through its nearest existing
parent, and fails closed on parent traversal and symlink escape
(`runtime-design.md` section 2). The container environment starts empty and
carries only explicitly configured `--env` values.

## 3. Problem 1: denial is not distinguishable from runner failure

### 3.1 The three facts

| Fact | Example | Correct operator action |
| --- | --- | --- |
| The runner never ran the command | Docker daemon unreachable, image missing, `docker run` itself failed | Fix the environment; the campaign produced no evidence |
| Confinement refused an operation | A write outside the mounted workspace, a blocked network syscall under the hardened profile | Fix the harness or the profile; the campaign ran but was constrained |
| The command ran and failed | The target faulted under ASan | Triage it; this is the finding |

Collapsing the first two into one "sandbox error" loses the distinction between
"nothing happened" and "something was stopped". Collapsing either into the third
manufactures a crash.

### 3.2 Proposal

Extend the terminal outcome with a fourth variant and keep the existing three
unchanged:

```rust
pub enum CommandTermination {
    Completed,
    TimedOut,
    Cancelled,
    Denied(DenialEvidence),
}
```

`RuntimeError` gains a variant that proves the runner never started, carrying
the same evidence shape. The invariant that decides precedence:

> **Runner failure outranks denial.** If the runner did not start the command,
> the command produced no denial, whatever its stderr resembles.

### 3.3 Denial evidence is backend-specific, not a union

The signature that proves a denial belongs to the enforcement backend that
produced it. A cross-backend union of signatures would claim denials a given
backend never emits, and a match against another backend's dialect is a false
positive by construction.

Each `RuntimeAdapter` therefore owns:

- `denial_signatures: &[&str]` -- stderr fragments that this backend, and only
  this backend, emits on refusal.
- `runner_failure: RunnerFailureRule { allowed_exit_codes, fatal_signatures,
  informational_lines }` -- evidence that the runner itself died.

Classification runs runner-failure rules first, denial signatures second, and
falls through to the existing outcome. A signature that matches neither is not
guessed at.

### 3.4 Non-goals

Docker is the only production backend. This change does not add a second one; it
gives the trait a place to put backend-specific evidence so that adding one
later does not require a cross-cutting edit. The `EngineAdapter` contract is
untouched: engines consume the terminal outcome, they do not classify it.

## 4. Problem 2: two independent root derivations

### 4.1 Current state

`hf-runtime` derives the host workspace root it will bind-mount.
`hf-tools` confines `FileRead`, `Glob`, and `Grep` to the exact active project
root, with additional read roots supplied explicitly and subject to canonical
symlink-boundary validation (`TOOL_CALL_PROTOCOL.md` section 4).

Two derivations, one meaning. They agree today because both were written
carefully. An asymmetry between them -- the inspection tools reading a path the
sandbox will not mount, or the reverse -- would be a silent policy hole rather
than a compile error.

### 4.2 Proposal

One function in `hf-core` is the single home for "the set of paths this
operation may touch":

```rust
pub fn admitted_roots(policy: &WorkspacePolicy) -> Result<Vec<CanonicalPath>, PathError>;
```

`hf-runtime` derives its bind-mount set from it. `hf-tools` derives its
inspection boundary from it. `CanonicalPath` is a newtype that can only be
constructed by canonicalization, so a lexically-normalized path cannot reach an
enforcement decision by accident -- the rule in `DEFENSIVE_PATTERNS.md` 8
becomes a type rather than a review note.

A test asserts the two consumers admit the same set for the same policy. That
test is the actual deliverable; the shared function is how it is made possible.

### 4.3 What this does not change

`hf-runtime` remains the kernel boundary and `hf-tools` remains a policy check
over a model-controlled path. Sharing a root derivation does not make the second
one stronger, and the code comments must keep saying so. The residual race --
an ancestor swapped between canonicalization and the syscall -- is narrowed by
re-resolving immediately before use and is accepted for this threat model.

## 5. Rejected alternatives

- **A cross-backend denial signature union.** Rejected: it claims denials a
  backend never produces, and produces false positives across dialects.
- **Classifying denial in `hf-engine`.** Rejected: engines would each
  reimplement the classification, and the evidence belongs to the runtime that
  produced it.
- **Making `hf-tools` call `hf-runtime`.** Rejected: it inverts the dependency
  direction (`ARCHITECTURE.md`), and the two need a shared *meaning*, not a
  shared *implementation*.
- **Leaving the root derivations separate and adding a comment.** Rejected:
  `AGENTS.md` 2.18 -- unexplained asymmetry between parallel values signals a
  missed extraction.
- **A `Denied` variant without evidence.** Rejected: a boolean that cannot be
  traced to the signature that set it cannot be reviewed after the fact, and
  retained evidence is a product promise.

## 6. Validation checklist

- [ ] A runner failure whose stderr contains a denial signature classifies as
      runner failure, not denial.
- [ ] A denial signature from backend A does not classify a backend B result.
- [ ] A genuine target crash is unaffected by both rules.
- [ ] `hf-runtime` and `hf-tools` admit an identical root set for the same
      policy, proven by a test that fails if either derivation changes alone.
- [ ] A lexically-normalized path cannot be constructed as a `CanonicalPath`.
- [ ] Each new rejection path is proven by introducing the defect and watching
      the test go red (`DEFENSIVE_PATTERNS.md`, Verification).
- [ ] `cargo clippy --workspace -- -D warnings` and `cargo test --workspace`
      pass.

## 7. Open questions

1. Does `Denied` belong on `CommandTermination` or on a separate field, given
   rule 1 says orthogonal facts get orthogonal fields? A denial and a timeout
   can co-occur if a write is refused and the run then exceeds its cap.
   Leaning: a separate `denials: Vec<DenialEvidence>` field, with
   `CommandTermination` unchanged. Resolve before implementation.
2. Should `hf-tools`' additional read roots participate in `admitted_roots`, or
   remain a separate, narrower set the sandbox never sees?
