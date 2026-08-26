# Triage Disposition

Status: **active implementation**. Owner: `hf-service`, deriving from the
Finding Proof Card, with rendering in `hf-cli` and `hf-gui`.

## 1. Goal

A campaign produces more crashes than a person can read. The Finding Proof Card
already answers, per crash, *what the retained evidence supports*. It does not
answer the question an operator actually opens the triage queue with: **which of
these deserves my attention next, and what may I say about it?**

This subsystem answers exactly that, with one ordered disposition per crash, one
next action, and a ceiling on what the evidence permits anyone to claim.

It proposes and orders. It starts nothing.

## 2. Feature and Ownership

The subsystem is enabled by the `triage-disposition` feature in `hf-service`,
which implies `proof-carrying`. `hf-service` owns derivation and ordering. REST
and Tauri serialize the view. The CLI and React render it and never recompute a
disposition, an action, or a claim.

## 3. Evidence Sources

Two, both already owned by the service:

- the `FindingProofCard` for the crash, including any `patch-to-proof`
  enrichment already applied to its `fix_verification` claim; and
- the persisted `Crash` record, for `kind`, `minimized`, and `casr`.

Nothing else. In particular the disposition never reads the harness source, the
coverage export, or a model opinion. A disposition that depended on a model
opinion would not be reconstructable from persisted state (AGENTS.md 2.13).

The card is the single home for per-claim detail. The disposition **does not
restate it**: it carries the tier, the action, and the claim ceiling, and a
consumer that wants to know why reads the card it was derived from
(AGENTS.md 2.18).

## 4. Dispositions

One ordered enum. Ordering is by descending operator attention: the first
variant is what to open first.

- **`Resolved`** -- `fix_verification` is `Verified`. A sandbox verification
  workflow reproduced the finding before a patch and confirmed it no longer
  reproduces after. No triage work remains.
- **`ReportReady`** -- fault origin is `Target`, the input is minimized, and
  external reachability is `Demonstrated`. Everything a report needs is
  retained.
- **`ReachabilityUnproven`** -- fault origin is `Target` and the input is
  minimized, but no retained evidence connects an external input to the fault.
  The bug is real; its security relevance is not established.
- **`MinimizationPending`** -- fault origin is `Target` and the input is not
  minimized. Minimization is the cheapest next step and every downstream
  analysis is worth more after it.
- **`SymbolizationPending`** -- fault origin is `Unknown`. The crash has no
  symbolized frames, so it cannot be attributed to target, harness, or runtime.
  This ranks below every attributed target fault and above the two attributed
  non-findings, because a cheap rebuild can promote it and cannot promote them.
- **`RuntimeArtifact`** -- fault origin is `Runtime`. The fault is inside the
  fuzzer driver or sanitizer runtime. It is a configuration signal, never a
  finding about the target.
- **`HarnessDefect`** -- fault origin is `Harness`. The fault is in code oxfuzz
  generated. It blocks the campaign and must be fixed, but it is never a finding
  about the target.

`ReportReady` is currently unreachable by construction, and that is deliberate.
`finding_proof_card` returns `external_reachability` as `NotVerified` for every
crash because oxfuzz retains no external-input-to-fault evidence, and no
enrichment function supplies one. Reporting a reachable top tier that no
evidence can support would be the same fabrication
`coverage-blocker-design.md` section 3 rejects. The variant exists so that when
reachability evidence is retained, the ladder already has the correct place for
it and no consumer changes.

## 5. Next Action

Exactly one per disposition, from a fixed vocabulary, carrying a stable
`reason_code` for localization and a human sentence:

| Disposition | Action | Meaning |
| --- | --- | --- |
| `Resolved` | `no_action` | Verified fixed; nothing to do. |
| `ReportReady` | `write_report` | Draft the finding from retained evidence. |
| `ReachabilityUnproven` | `demonstrate_reachability` | Establish a path from an external input to the fault. |
| `MinimizationPending` | `minimize_input` | Reduce the input before further analysis. |
| `SymbolizationPending` | `rebuild_with_symbols` | Rebuild the target with symbols and re-triage. |
| `RuntimeArtifact` | `review_engine_configuration` | Inspect engine and sanitizer settings. |
| `HarnessDefect` | `repair_harness` | Fix the generated harness and re-run. |

The action names a step; it does not perform one. `minimize_input` and
`repair_harness` both correspond to paths that already exist with their own
approval surfaces, and the disposition deliberately does not offer a second
entrypoint to either (AGENTS.md 2.19).

## 6. Claim Ceiling

The strongest statement the retained evidence permits, and -- separately -- the
statement a reader must not make. Both are required: naming only the ceiling
invites a reader to treat the gap above it as merely unstated rather than
unsupported.

Ceilings, ordered:

- **`NoTargetClaim`** -- `HarnessDefect` and `RuntimeArtifact`. Nothing may be
  claimed about the project under test.
- **`FaultObserved`** -- `SymbolizationPending`. A fault occurred; it is not
  attributed to any layer.
- **`TargetFaultObserved`** -- an attributed target fault whose input is not
  minimized.
- **`TargetFaultMinimized`** -- an attributed, minimized target fault.
- **`ExploitabilityClassified`** -- CASR produced a supported exploitability
  determination. This ceiling is granted by CASR evidence, not by crash kind,
  and it raises a `TargetFaultMinimized` ceiling only when the fault is already
  attributed to the target.
- **`RemediationVerified`** -- `Resolved`.

The paired `claim_limit` sentence states what is not supported. For every
ceiling below `ExploitabilityClassified` on a target fault it states that
exploitability is unclassified and the finding must not be described as
exploitable. This is the discipline the ladder exists to enforce: an
out-of-bounds read with no exploitability evidence is a read primitive and a
denial of service, and calling it anything stronger is a claim without a record
behind it.

## 7. Ordering

Deterministic, in sequence:

1. disposition, in the section 4 order;
2. CASR exploitability, most severe first, with `Unavailable` last -- between
   two crashes at the same disposition, the one CASR classified more severely is
   opened first; then
3. crash id, so equal evidence yields a stable order.

CASR breaks the tie rather than crash kind because CASR is a retained
determination and crash kind is a label. Where CASR never ran, every crash at a
disposition shares rank two and falls through to the stable id order, which is
the correct outcome: with no exploitability evidence there is no basis to
prefer one over another.

## 8. Rejected Alternatives

- **A numeric value score** -- fuzzctl's approach. A scalar assembled from
  unexplained constants cannot be audited, cannot be explained to an operator,
  and silently encodes policy as arithmetic. Typed tiers with named tie-breaks
  carry the same ordering and can be read.
- **A separate scoring pass over the crash log** -- would build a second source
  of truth alongside the proof card and let the two disagree about the same
  crash.
- **Product or vendor mapping as a tier** -- fuzzctl reserves its top two tiers
  for crashes mapped to a shipped product path, then stubs the mapping so
  nothing ever reaches them. oxfuzz retains no product-surface model; adding
  tiers that no evidence can populate would repeat that defect.
- **Folding attribution and evidence completeness into two separate public
  fields** -- an operator orders one queue, so the ordering key must be one
  value. Attribution remains readable on the proof card.
- **Letting a model assign the disposition** -- model opinions stay advisory
  here as everywhere; a deterministic derivation is reconstructable from
  persisted state.
- **Treating `Unknown` origin as a target fault** -- it is exactly the
  substitution of a negative determination for a missing one that rule 2 of the
  Tier 2 plan forbids.
- **Ranking `SymbolizationPending` below `HarnessDefect`** -- an unattributed
  fault may become a target finding after a cheap rebuild; an attributed harness
  defect never will.

## 9. Verification Criteria

- A crash whose origin is `Harness` yields `HarnessDefect` and `NoTargetClaim`
  regardless of crash kind, CASR severity, or minimization.
- A crash whose origin is `Runtime` yields `RuntimeArtifact` and
  `NoTargetClaim`.
- A crash whose origin is `Unknown` yields `SymbolizationPending` and
  `FaultObserved`, and is never attributed to the target.
- An unminimized target fault yields `MinimizationPending`; the same crash
  minimized yields `ReachabilityUnproven`.
- A verified remediation yields `Resolved` and `RemediationVerified`, and
  outranks every unresolved crash.
- A rejected or inconclusive remediation does not yield `Resolved`.
- CASR evidence raises the claim ceiling only for an attributed target fault,
  and never raises the disposition.
- `claim_limit` names exploitability as unsupported for every target fault
  without a supported CASR determination.
- Ordering is total and stable: the same crash set in any input order yields the
  same output order.
