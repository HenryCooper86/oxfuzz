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
a partially trusted manifest.

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
