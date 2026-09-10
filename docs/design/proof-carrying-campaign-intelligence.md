# Proof-Carrying Campaign Intelligence

Status: **active implementation**. Owner: `hf-service`, with pure scoring in
`hf-coverage` and remediation contracts in `hf-crash`.

## 1. Goal

Make every campaign decision and remediation handoff auditable without turning
advice into authority. The subsystem adds three related capabilities:

1. a canonical evidence manifest that binds a run to its approved harness,
   sandbox, corpus context, coverage, findings, and cost inputs;
2. a deterministic coverage-per-cost advisor that proposes the next campaign
   action and explains the measurements behind it; and
3. a remediation handoff contract that cannot claim verification without exact
   reproducer, patch, source, sandbox, and regression evidence.

The implementation extends existing immutable run evidence, crash regression,
reproduction-bundle, diagnostics, and human-promotion contracts. It does not
introduce a second execution path, automatically apply a patch, promote a
harness, start a fuzzer, or transmit automotive traffic.

## 2. Feature Boundary

The subsystem is exposed through the `proof-carrying` feature in `hf-service`.
That feature enables the `campaign-advisor` feature in `hf-coverage` and the
`remediation-handoff` feature in `hf-crash`. Pure types remain dependency-light;
all filesystem, storage, and orchestration decisions remain in `hf-service`.

Presentation crates consume service-owned serializable DTOs. They may render,
download, or request advice, but they do not recompute hashes, economics,
verification status, or safety gates.

## 3. Canonical Evidence Manifest

Schema version 1 contains:

- manifest id, schema version, generation time, project display name, target,
  run id, and run status;
- engine and complete normalized run configuration;
- source, approved harness, staged binary, comparison-context, corpus, and
  sandbox-image digests;
- explicit human harness-promotion evidence tied to the exact source and binary;
- coverage totals and delta, crash identities, minimized reproducer digests,
  and model/compute cost inputs when available; and
- a manifest SHA-256 computed over the schema body without the digest field.

All maps use deterministic key order. Floating-point values must be finite and
non-negative. Digest values are lowercase 64-character SHA-256 strings. A
manifest is valid only when required identifiers are non-empty, the run is
terminal, the approval matches the harness and binary revisions, and recomputing
the canonical body produces the retained digest. Mutating any bound field
invalidates verification.

The service gathers manifests only from durable records and immutable evidence.
It never substitutes a mutable active path for run-owned evidence. Legacy runs
without full provenance return an explicit incomplete-evidence error instead of
a partially trusted manifest. In storage, exact Docker provenance is tagged as
`docker-image-id-sha256:<digest>` so a historical hash of a mutable image name
cannot be mistaken for a resolved image ID. Evidence emits the validated raw
digest only after removing that exact type marker. This provenance guarantee is
evidence schema v2; schema-v1 manifests fail verification instead of being
silently upgraded.

### 3.1 Promotion provenance

Harness promotion creates a durable approval row containing a service-owned
approval id, harness id, exact source and smoke-qualified binary digests,
approval kind (`clean_smoke` or `known_findings`), and timestamp. The approval
write and promoted harness update are one storage transaction. Re-promoting the
same exact revision returns its existing approval; a different revision receives
a new record. Agents and schedules have no promotion entrypoint.

## 4. Coverage-Per-Cost Advisor

`hf-coverage` owns a pure deterministic advisor. Inputs are a bounded sequence
of comparable campaign observations, enabled engines, operator-supplied
per-engine hourly rates, and a finite budget. Each observation carries exact
run identity, engine, duration, edge delta, crash delta, corpus additions, and
any attributable model cost.

The advisor produces one of:

- continue the current campaign;
- improve corpus or mutation inputs;
- review a new harness revision;
- switch to a named enabled engine; or
- stop spending on the target.

Budget exhaustion wins over optimization. Otherwise the advisor compares
marginal edges per dollar, recent plateau windows, corpus growth, and engine
diversity. Every result includes ordered evidence strings, measured cost,
marginal yield, and `requires_human_approval = true` for any action that could
lead to execution or a new harness. It has no runtime, storage, provider, or
tool dependency and cannot perform its recommendation.

Invalid, non-finite, negative, incomparable, excessive, or duplicate run inputs
fail closed. Ties are resolved by stable engine id and run id so identical input
always yields identical output.

### 4.1 Reviewed scheduled allocations

The `campaign-allocation` feature extends advice with a service-owned project
allocation. A proposal freezes selected file-qualified targets, engines, exact
active promoted harness UUIDs and source digests, qualification-owned workspace
selectors, and retained run facts. The
latest two successful campaigns with matching comparison keys and binary
digests support within-target growth: positive growth receives weight two;
plateau or unavailable comparable evidence receives weight one with a reason.
Absolute edge counts from different targets are never compared.

Every selected target receives one run before remaining runs are distributed
in a stable weighted cycle. Each target owns its quota; a frequently firing
schedule cannot spend another target's minimum. Minimum service means reserved
opportunities, conditional on a matching enabled schedule actually firing.
The per-run sandbox fuzz-time cap is floor(total seconds / total runs); any
remainder remains unallocated. These are requested fuzz seconds, not a bound on
build, seed generation, triage, or total wall-clock time. This is not a dollar
budget; the existing coverage-per-cost advisor remains available separately.

The operator approves an exact proposal UUID and SHA-256. Versioned JSON state
under the configured workspace retains the proposal, review state and every
reservation. Canonical project identity determines storage ownership. Each
mutation uses an OS file lock and an atomic synced replacement. Previous revoked
plans are archived before replacement. Invalid durable state fails closed.
There is one current plan per project; replacing an approved plan requires
revocation and a new explicit approval, never an automatic budget reset.

Every scheduled campaign requests admission in its dispatcher. A project with
no plan keeps existing scheduling behavior. Draft, revoked, exhausted, stale
harness, or feature-disabled plans deny new admission. Approval limits one
iteration per grant and the granted duration. A reservation is durable before
execution and remains charged after failure, cancellation, or process death.
The executor verifies the exact approved harness, granted duration and
single-attempt allowance before preparing a userspace run. Existing human promotion, scheduler arming, build-input checks and runtime
sandboxing still apply. Revocation affects future admissions; issued grants
remain authorized. Manual runs use their existing independent operator authority.

Presentation lists candidates, requests proposals, displays retained reasons,
quotas and consumption, approves an exact digest, or revokes a plan. It does not
compute weights or resource decisions. JSON sidecars reuse the scheduler's
synced state writer and avoid coupling allocation history to run pruning;
SQLite transactions remain a valid future storage choice, not a destructive
migration risk. Client-supplied yield values and silent failed-run refunds are
rejected because neither provides reproducible resource accounting.

## 5. Remediation Handoff

`hf-crash` owns a versioned, serializable remediation contract. A draft binds:

- finding and source revision;
- patch candidate SHA-256 and bounded unified-diff text or artifact identity;
- minimized reproducer SHA-256;
- harness and binary revisions; and
- the evidence-manifest SHA-256 from section 3.

The state transition to `verified` requires a completed sandbox-verification
record that names the exact patch, source, reproducer, harness, binary, and
pinned sandbox image. The record must prove the original reproducer crashed,
the patched replay completed without that crash, and the bounded regression
set completed successfully. Timeout, cancellation, missing replay, digest
mismatch, or an empty regression set remains `inconclusive` or `rejected`.

The service writes a handoff directory atomically from bounded inputs. It
contains `remediation.json`, `PATCH.diff`, the reproducer, and a deterministic
Markdown summary. Draft export is useful but visibly unverified. A verified
claim can only be assembled from a service-owned sandbox verification result;
presentation-supplied booleans are never accepted as authority.

The `patch-to-proof` feature extends this handoff into a durable, approved
workflow. Remediation evidence version 3 names the original binary in the
binding and the patched binary in execution evidence; these identities must not
be equal by assumption. Original replay, patched replay, a non-empty retained
regression corpus, and bounded follow-up fuzzing are separate required stages.
See `patch-to-proof-design.md`.

## 6. Automotive State Intelligence

`hf-automotive` extends its pure offline analysis with collision-safe
`FrameIdentity { id, extended }` keys and bounded ISO-TP/UDS state extraction.
Standard and extended frames that share a numeric id remain distinct through
statistics, change maps, capture diffs, and serialized service DTOs.

For each `(channel, frame identity, direction)` stream, the analyzer reassembles
ISO-TP PDUs and emits deterministic UDS state observations: request service,
positive response service, negative response service/code, or other payload.
It reports unique states, state transitions with occurrence counts, completed
PDUs, and malformed/truncated frames. Repeated transitions increase counts but
not novelty. The result is protocol-state evidence only; it never increments
source edges or implies a vulnerability.

## 7. Safety and Authority

- Advice and manifests are read-only.
- Draft bundles never claim a fix is verified.
- Verification execution, when separately requested, uses `hf-runtime`, a
  pinned image, immutable inputs, no network, bounded output, and guardrails.
- Harness promotion remains a direct human action.
- Automotive state analysis is offline and opens no interface.
- No model response can alter evidence, mark remediation verified, or perform a
  recommended action.

## 8. Rejected Alternatives

- **An autonomous campaign optimizer** -- a score must not become execution
  authority; recommendations remain reviewable proposals.
- **Signing partial legacy evidence as complete** -- absence of provenance is a
  meaningful result and must remain visible.
- **Using numeric CAN id alone** -- standard and extended namespaces collide.
- **Calling protocol novelty coverage** -- it produces misleading comparisons.
- **Marking a suggested patch verified after a clean replay alone** -- without
  exact digest binding and regression evidence, the conclusion is not portable.
- **Building the contracts in REST, CLI, or React** -- duplicates business logic
  and makes evidence surface-dependent.

## 9. Verification Criteria

- Equivalent evidence bodies produce the same digest; any field mutation fails
  manifest verification.
- Promotion provenance is atomic with the promoted harness state.
- Standard and extended CAN frames with the same numeric id remain distinct in
  Rust analysis, service DTOs, REST JSON, and GUI rendering.
- Repeated UDS traffic does not increase unique-transition counts; malformed
  ISO-TP traffic cannot panic or fabricate a state.
- Advice is deterministic, bounded, budget-aware, and side-effect free.
- Remediation cannot transition to `verified` without every required matching
  digest and successful sandbox/regression outcome.
- Default tests use mocks and fixtures; they execute no generated harness,
  fuzzer, patch, Python sidecar, CAN interface, or physical bench.
