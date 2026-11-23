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
opinion would not be reconstructable from persisted state (ENGINEERING_PROTOCOL.md 2.13).

The card is the single home for per-claim detail. The disposition **does not
restate it**: it carries the tier, the action, and the claim ceiling, and a
consumer that wants to know why reads the card it was derived from
(ENGINEERING_PROTOCOL.md 2.18).

## 4. Dispositions

One ordered enum. Ordering is by descending operator attention: the first
variant is what to open first. Completed work sorts last and is excluded from
the default queue; an operator can include it explicitly.

- **`ReportReady`** -- fault origin is `Target`, the input is minimized, and
  external reachability is `Demonstrated`. Everything a report needs is
  retained.
- **`ReachabilityUnproven`** -- fault origin is `Target` and the input is
  minimized, but no retained evidence connects an external input to the fault.
  The bug is real; its security relevance is not established.
- **`MinimizationPending`** -- fault origin is `Target` and the input is not
  minimized. Minimization is the cheapest next step and every downstream
  analysis is worth more after it.
- **`InputIndependentFault`** -- fault origin is `Target`, minimized or not, but
  the proof card's
  `input_dependence` claim is a supported `InputIndependent`: the same failure
  reproduced on every benign control input (section 4.1). Either the harness
  violates an API precondition or the target fails on nearly any input. The
  retained evidence does not distinguish the two, so a person reviews the
  harness call sequence before this is treated as a target finding.
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
- **`Resolved`** -- `fix_verification` is `Verified`. A sandbox verification
  workflow reproduced the finding before a patch and confirmed it no longer
  reproduces after. No triage work remains.

`ReportReady` is currently unreachable by construction, and that is deliberate.
`finding_proof_card` returns `external_reachability` as `NotVerified` for every
crash because oxfuzz retains no external-input-to-fault evidence, and no
enrichment function supplies one. Reporting a reachable top tier that no
evidence can support would be the same fabrication
`coverage-blocker-design.md` section 3 rejects. The variant exists so that when
reachability evidence is retained, the ladder already has the correct place for
it and no consumer changes.

### 4.1 Control-Input Replay

Stack frames cannot separate a target bug from a harness that misuses the
target's API, because the fault lands in target frames in both cases. The
`control-replay` feature adds one deterministic experiment. For each
target-origin AFL++ or libFuzzer crash, after the minimization attempt, triage
replays the crash's current input twice with the retained binary in the same
immutable image, read-only and without network. When both replays produce one
failure identity, it replays each control once:

- `same_length_zeros` -- the candidate's length, every byte `0x00`;
- `same_length_fill` -- the candidate's length, every byte `0x41`;
- `single_byte` -- one byte, `0x01`.

Controls keep the candidate's length where a harness may have a minimum-size
guard. There is no empty control because the AFL++ driver may not invoke the
target for an empty file, which would make the result engine-dependent.

Controls do not require successful minimization. An input-independent fault can
minimize to an empty file, which the minimization path rejects, so requiring it
would skip the crashes this experiment exists to identify. Those crashes keep
their original input, and `InputIndependentFault` takes precedence over
`MinimizationPending`.

The proof card recomputes `input_dependence` from the retained logs, using the
same failure identity as reproduction confirmation. Saved flags never establish
a match, and each control's digest is recomputed from its kind and length.

| Observed | Determination | Status |
| --- | --- | --- |
| Every control reproduces the failure | `input_independent` | `supported` |
| Some reproduce, the others exit cleanly | `size_or_content_sensitive` | `supported` |
| Every control exits cleanly | `input_dependent` | `supported` |
| Timeout, runtime error, different failure, invalid evidence, or a control identical to the candidate | `inconclusive` | `not_verified` |
| No control evidence retained | `not_verified` | `not_verified` |

Only `input_independent` changes the disposition. `input_dependent` does not
raise any claim: a harness can misuse an API in a way that depends on input.
Control replay never changes `CrashOrigin` and never removes a crash from the
triage queue or the campaign report.

### 4.2 Export Hold and Usage Review

SARIF and `DefectDojo` publish outside oxfuzz, so an input-independent fault is
held out of both until a person reviews the harness's API usage. The mappers
`crashes_to_sarif` and `crashes_to_generic` enforce the hold, so every caller
gets it. A SARIF run records the held count in
`properties.heldForUsageReview`, because an empty result list must not read as
a clean run. A `DefectDojo` push reports `findings_held`, and a push that would
carry only held findings is refused with the reason.

The reviewer resolves a hold in one of two ways:

- repair the harness and re-run, after which the fault no longer reproduces; or
- record that the usage is valid with `oxfuzz triage --accept-usage <id>`, the
  REST route `POST /findings/{id}/usage-review`, or the Triage view. The finding
  returns to the ordinary target ladder and to exports.

Recording a review takes the `PublishFindings` approval. The record is bound to
the digests of the reviewed input and run binary, survives re-triage of the same
evidence, and stops applying when either digest changes. `--hold-usage <id>`
withdraws it.

The hold fails closed across re-triage. A retained finding keeps its control
evidence until a later replay replaces it, an inconclusive replay does not
replace evidence that is holding a finding, and a change to the input path the
crash names does not release it. Crashes triaged before this feature have no
control evidence and are not held.

Issue filing and webhook notifications are not covered: each is outside this
decision, and issue filing is already an explicit per-finding action.

## 5. Next Action

Exactly one per disposition, from a fixed vocabulary. The action is a typed
value whose serialized name is the stable identifier a consumer localizes
against; it carries a human sentence alongside. There is no separate reason code,
because a second identifier for the same meaning would be a second home for it
(ENGINEERING_PROTOCOL.md 2.18).

| Disposition | Action | Meaning |
| --- | --- | --- |
| `Resolved` | `no_action` | Verified fixed; nothing to do. |
| `ReportReady` | `write_report` | Draft the finding from retained evidence. |
| `ReachabilityUnproven` | `demonstrate_reachability` | Establish a path from an external input to the fault. |
| `MinimizationPending` | `minimize_input` | Reduce the input before further analysis. |
| `InputIndependentFault` | `review_harness_usage` | Check the harness call sequence against the API's preconditions. |
| `SymbolizationPending` | `rebuild_with_symbols` | Rebuild the target with symbols and re-triage. |
| `RuntimeArtifact` | `review_engine_configuration` | Inspect engine and sanitizer settings. |
| `HarnessDefect` | `repair_harness` | Fix the generated harness and re-run. |

The action names a step; it does not perform one. `minimize_input` and
`repair_harness` both correspond to paths that already exist with their own
approval surfaces, and the disposition deliberately does not offer a second
entrypoint to either (ENGINEERING_PROTOCOL.md 2.19).

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
- **`TargetFramesFault`** -- `InputIndependentFault`. The fault is in target
  frames, but valid API usage is not established.
- **`TargetFaultObserved`** -- an attributed target fault whose input is not
  minimized.
- **`TargetFaultMinimized`** -- an attributed, minimized target fault.
- **`ExploitabilityClassified`** -- CASR produced a supported exploitability
  determination. This ceiling is granted by CASR evidence, never by crash kind.
  It is reached only by raising a `TargetFaultMinimized` ceiling, so it requires
  a fault attributed to the target *and* a minimized input. CASR run against an
  unminimized input does not raise the ceiling: the ladder is ordered, and a
  claim above `TargetFaultMinimized` on an input that was never minimized would
  assert more than the rung below it.
- **`RemediationVerified`** -- `Resolved`.

The paired `claim_limit` sentence states what is not supported. For every
ceiling below `ExploitabilityClassified` on a target fault it states that
the finding must not be described as exploitable. An unminimized input may
already have a CASR classification; its limit names missing minimization without
claiming that classification is absent. This is the discipline the ladder exists to enforce: an
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

The service applies disposition filtering before returning a queue. Its default
filter includes every unresolved disposition and excludes `Resolved`. Report
draft presence is not a disposition input and never removes an unresolved
finding. An explicit all or resolved filter provides retained-history access.

Latest-run report and DefectDojo requests may carry the run identifier the
operator selected. The service resolves the target's latest retained run once
inside the operation and rejects the action when that run differs from the
expected identifier. This prevents a run completing between detail loading and
the explicit action from silently changing the evidence that is reported or
published. Callers that intentionally request the latest run omit the expected
identifier. Historical findings keep these actions unavailable; their report
must not combine retained crash evidence with coverage from the current
workspace.

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
- **Reassigning an input-independent fault to `CrashOrigin::Harness`** -- it
  would exclude a possibly real, shallow target bug from reports on an inference
  the evidence does not establish.
- **Asking a model whether the crash is API misuse** -- the disposition must be
  reconstructable from retained observations.
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
- A target fault reproduced by its baseline and every control yields
  `InputIndependentFault` and `TargetFramesFault`, even when CASR classified it
  or minimization did not complete.
- Partial, clean, inconclusive, tampered, or absent control evidence leaves the
  disposition unchanged.
- A held finding is absent from SARIF and `DefectDojo` until a review of its
  exact evidence is recorded, and returns to being held when it is withdrawn.
- An unminimized target fault yields `MinimizationPending`; the same crash
  minimized yields `ReachabilityUnproven`.
- A verified remediation yields `Resolved` and `RemediationVerified`, sorts
  after every unresolved crash, and is excluded from the default queue.
- A rejected or inconclusive remediation does not yield `Resolved`.
- CASR evidence raises the claim ceiling only for an attributed target fault,
  and never raises the disposition.
- `claim_limit` names exploitability as unsupported for every target fault
  without a supported CASR determination.
- Ordering is total and stable: the same crash set in any input order yields the
  same output order.
