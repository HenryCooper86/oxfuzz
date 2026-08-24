# Finding Proof Card

Status: **active implementation**. Owner: `hf-service`, with rendering in
`hf-gui` and transport-only serialization in `hf-web` and Tauri.

## 1. Goal

Give an operator one evidence-grounded view of a retained crash without
combining different security questions into a single severity label. The card
answers five questions independently:

1. which component contains the observed fault;
2. whether deterministic reproduction has been established;
3. how CASR classified exploitability;
4. whether a path from an external input to the fault has been demonstrated;
   and
5. whether a candidate fix passed matching sandbox verification.

The card is a read-only projection of durable service state. It neither invokes
a model nor runs a target, harness, reproducer, patch, or fuzzer.

## 2. Ownership and Serialization

`hf-service` owns a versioned `FindingProofCard` attached to every
`CrashReviewItem`. The Dashboard consumes it directly. Triage reloads the same
workbench projection after persisting a triage result and joins only by crash
id; React does not derive a determination from raw crash fields. REST and Tauri
serialize the same DTO without changing its values.

The initial schema version is 1. Each claim contains:

- a typed determination;
- an evidence state: `supported`, `not_verified`, or `unavailable`;
- stable explanatory text for REST and other non-localized consumers; and
- references to the durable records that support the claim.

`unavailable` means the required evidence is absent. `not_verified` means the
question is meaningful but the retained evidence does not satisfy its proof
requirements. Neither value is a negative security conclusion.

## 3. Determination Rules

### 3.1 Fault origin

`Crash.origin` is the only source. `target`, `harness`, and `runtime` are
`supported` by the persisted crash record. `unknown` is `unavailable`. A target
symbol or a drafted model report cannot replace the persisted origin.

### 3.2 Deterministic reproduction

Schema version 1 reports `not_verified`. A CASR report proves that CASR produced
analysis from a sandbox replay, but no retained record currently proves
multiple equivalent replays. `Crash.minimized` and the advisory LLM
`CrashVerdict.reproduces_deterministically` are not accepted as evidence.

A later schema may report a verified value only after a durable service-owned
replay record binds repeated outcomes to the exact reproducer, harness, binary,
and sandbox image.

### 3.3 CASR exploitability

When `Crash.casr` is present, its exact `CrashSeverity` value is `supported`:
`exploitable`, `probably_exploitable`, `not_exploitable`, or `undefined`.
`undefined` is a real CASR result and remains distinct from a missing CASR
report, which is `unavailable`.

CASR exploitability is not a vulnerability verdict by itself. The separate
origin, reachability, and reproduction claims remain visible beside it.

### 3.4 External reachability

Schema version 1 reports `not_verified`. `TargetCandidate.reachable_functions`
describes functions reachable from a selected target; it does not establish an
external-input-to-fault path and is therefore not used.

### 3.5 Fix verification

Schema version 1 reports `not_verified` because remediation handoffs are
currently exported artifacts rather than indexed durable service state. A
draft patch, a clean replay alone, or a model recommendation cannot produce a
verified result. The Patch-to-Proof phase may expose `verified`, `rejected`, or
`inconclusive` only from the existing exact-input remediation state machine
after its records are retained and addressable by finding id.

## 4. Evidence References

References contain a kind and stable record id, never a mutable active path.
The initial kinds are:

- `crash_record` with the persisted crash UUID;
- `run_record` with the persisted run UUID; and
- `casr_report` with the crash UUID, identifying the CASR payload embedded in
  that crash record.

The service attaches only the references relevant to each claim. The GUI may
shorten UUIDs for display but must retain the complete value in accessible
text.

## 5. Presentation

Dashboard crash cards and the selected Triage crash show the same compact
five-row card. Each row renders the claim name, service determination, evidence
state, explanation, and retained evidence reference. Existing surface colors,
spacing, typography, and status badges are reused. `supported` uses the normal
success treatment, `not_verified` uses the warning treatment, and
`unavailable` uses the neutral treatment. CASR `not_exploitable` does not use a
success color that could imply that the finding itself is safe.

English and Chinese labels remain paired. Localization translates the service
codes and explanations; it does not change their meaning.

## 6. Rejected Alternatives

- **One combined vulnerability score** -- it would obscure missing evidence
  and combine exploitability, origin, reachability, and remediation into a
  conclusion the retained data cannot support.
- **Deriving the card in React** -- other presentation surfaces could disagree,
  and raw field absence could be mistaken for a negative result.
- **Treating CASR or minimization as deterministic reproduction** -- neither
  supplies retained repeated-replay evidence.
- **Treating the static call graph as external reachability** -- it starts at a
  chosen fuzz target rather than a demonstrated external entry point.
- **Scanning exported remediation directories from the workbench read path** --
  mutable filesystem discovery would create an unindexed second evidence
  source.

## 7. Verification Criteria

- Every persisted crash receives schema version 1 with all five claims.
- Missing CASR is `unavailable`; CASR `Undefined` is `supported`.
- Harness and runtime origins never render as target findings.
- No minimized flag or LLM verdict can mark reproduction verified.
- No claim uses a host path as evidence.
- Dashboard, Triage, REST, and Tauri consume identical serialized values.
- Feature-disabled builds still return an honest card with fix verification
  `not_verified`.
- Tests execute no generated or target code.
