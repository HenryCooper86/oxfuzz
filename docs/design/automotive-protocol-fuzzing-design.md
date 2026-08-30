# Automotive Protocol Fuzzing Design

Status: **professional campaign workflow implementation active; live vcan and
physical-bench validation remain separately approved activities**. Owner:
`hf-automotive` for the pure contract and `hf-service` for orchestration.

## 1. Goal and Current Boundary

The automotive subsystem extends `oxfuzz` from source-coverage fuzzing to
protocol-state exploration without weakening the existing sandbox and human
approval boundaries. The implemented software scope includes the optional
`hf-automotive` Rust contract, pinned Python sidecar package, service-owned
orchestration and persistence, REST/CLI/Tauri transports, and the desktop
Automotive workspace. The domain crate itself contains serializable values,
fail-closed validation, and deterministic evidence hashing only.

`hf-automotive` does not import Scapy, execute processes, access the filesystem,
open a socket, select an interface, or contain service policy. Its own
`automotive-scapy` Cargo feature is disabled by default *at the library level*:
the crate is a pure optional dependency and never turns itself on. The shipped
product crates (`hf-cli`, `hf-web`, `hf-service`, and the `hf-gui` Tauri shell)
enable the feature in their own `default` set so the automotive workspace is a
first-class, always-present part of the application in every build, including
developer builds. A consumer that wants the MIT contract crate without the
subsystem builds with `--no-default-features`, which forwards no automotive
dependency and exercises the fail-closed "feature not included in this build"
paths. Enabling the feature only compiles pure-Rust contract and orchestration
code; it never links Scapy.

The following implemented behavior deliberately remains outside the domain
crate and is verified by its owning workstream:

- service policy, persistence, approval, and workspace orchestration;
- REST, CLI, Tauri, and GUI transports.

## 2. Supported Protocol and Mode Vocabulary

The schema has stable identifiers for CAN, CAN FD, ISO-TP, UDS, GMLAN,
SOME/IP, SOME/IP-SD, DoIP, OBD, CCP, XCP, BMW HSFZ, and SecOC. Capability
negotiation remains authoritative: presence in the vocabulary does not claim
that every pinned sidecar build can decode or execute every protocol.

Three modes are represented:

| Mode | Purpose | Default safety posture |
| --- | --- | --- |
| `offline_pcap` | Decode captures, derive mutations, and plan replay | No interface, network disabled |
| `virtual_can` | Execute an approved plan on sandbox-visible vcan | Disabled until service/runtime capability checks pass |
| `physical_bench` | Execute on an isolated, allowlisted bench interface | Disabled by default; fresh human approval required |

Physical-bench DTOs carry an opaque approval record id, but the domain crate
does not decide whether it is valid. `hf-service` enforces
interface, arbitration-id, diagnostic-service, duration, payload, and rate
allowlists. Programming, reset, security-access, communication-control, and
other dangerous services remain denied unless a later policy explicitly models
and approves them.

## 3. Versioned Sidecar Contract

`SchemaEnvelope<AutomotiveRequest>` serializes with the exact top-level shape
`{schema_version, request_id, operation, payload}`. The typed request is
flattened into the envelope so no additional wrapper object can drift from the
JSONL protocol. `ResponseEnvelope` serializes as
`{schema_version, request_id, ok, result, error, transcript_sha256}` and
validates the exclusive success-result or failure-error relationship. Schema
version 1 defines:

- `AutomotiveRequest`: capabilities, capture analysis, deterministic mutation
  generation, replay-plan generation, and replay execution;
- `AutomotiveResult`: capability, capture-analysis, mutation, and replay
  results;
- `AutomotiveError`: a stable error code, redacted message, optional field,
  retryability, and bounded non-secret details;
- `OperationLimits`: event, payload, wall-clock, and transmission-rate bounds;
- `ArtifactRef`: opaque service id, SHA-256, and media type, deliberately
  excluding a host path;
- `ReplayPlan`: protocol, mode, deterministic seed, and ordered typed actions;
- `StateSignature`: protocol-scoped, canonical state observations and digest.

Every request and result implements the pure `Validate` contract. Validation
rejects unsupported schemas, empty identifiers, unsafe interface strings,
missing physical approval references, malformed lowercase hex, invalid
digests, duplicate replay/transcript sequences or state signatures, mixed
protocols or modes, inconsistent capability and result claims, and hard-limit
violations. Virtual interfaces use the bounded `vcanN` form; physical interface
identifiers and staged artifact ids are bounded non-path values. Replay
validation requires contiguous sequence order and applies aggregate payload,
schedule-duration, and action-rate limits. A successful response's top-level
transcript digest must exactly match its typed result. Deserialization alone does
not authorize execution; callers must validate before acting.

The Rust request variants serialize directly to the sidecar's public operation
names: `capabilities`, `analyze_capture`, `generate_mutations`,
`build_replay_plan`, and `execute_replay`. Requests retain opaque
`ArtifactRef`s; only after immutable service staging may the sandbox artifact
store resolve one to a sidecar-visible path. The sidecar dispatches those typed
operations to its internal PCAP decoder, mutation planner, replay builder, or
injected transport, but internal primitives never become alternate public
operations or service authorities. Capability/result maps and error codes use
the corresponding `CapabilityReport`, tagged `AutomotiveResult`, and
`AutomotiveError` serde shapes so the service can deserialize and validate the
versioned contract without reconstructing domain values from ad hoc JSON.

The sidecar transport is one JSON object per line. It must accept one
bounded envelope and return exactly one correlated result or structured-error
envelope. Unstructured stdout, shell fragments, raw host paths, and Python
tracebacks are not protocol fields.

## 4. Deterministic Evidence and Feedback

`canonical_transcript_hash` validates events, sorts them by unique sequence,
serializes only schema-defined integer/string fields and `BTreeMap` metadata,
and computes SHA-256. Wall-clock timestamps and insertion-ordered maps are not
part of the canonical representation. `StateSignature::from_observations` uses
the same schema-, protocol-, and key-order-stable approach.

Protocol-state novelty is a separate feedback signal from source coverage.
The service can promote a verified input or typed-result output artifact only
from a completed operation that retained the exact validated state signature.
For an input, it also revalidates the staged digest and size against the exact
request JSONL retained under the operation and bound to the durable request
hash; outputs are revalidated against their typed result `ArtifactRef`. It
rechecks regular-file and workspace containment, copies to a digest-addressed
project path with create-new atomic publication, and persists the row only
after the copy succeeds. An exact project/protocol/state/artifact retry returns
the first persisted promotion. Public DTOs expose only digests, source
operation attribution, and a workspace-relative path; state observations
remain in the operation evidence. These rows never update source edges, lines,
functions, regions, engine corpora, or coverage-regression baselines. Replay
and minimization must retain the canonical transcript hash, state digest,
protocol, mode, adapter identity, deterministic seed, and policy/approval
evidence needed to reproduce the result.

## 5. Runtime and Service Boundary

The Python adapter runs only as an operation-scoped sidecar through
`hf-runtime`. Before admission, the service resolves the configured image
selector to an immutable SHA-256 image ID and passes only that ID to the
runtime. Physical approval evidence and its scope digest include the same image
ID, so changing a tag cannot substitute different executable code after an
operator approves a plan. The Rust process will never import or link Scapy.
Inputs are service-staged, digest-verified, read-only artifacts; outputs are
bounded files inside a unique workspace. Runtime networking and capabilities are typed:
offline analysis uses `SandboxNetworkMode::None` with no added capabilities;
vcan uses `SandboxNetworkMode::None` plus only `SandboxCapability::NetAdmin`
and `SandboxCapability::NetRaw`; physical bench uses
`SandboxNetworkMode::Host` plus only `SandboxCapability::NetRaw`. All three
retain capability dropping and `no-new-privileges`. `Bridge` networking is not
an automotive default. Interfaces may not be selected with a raw command or
generic tool call.

`hf-service` owns, in this order:

1. compile-time feature and runtime-setting checks;
2. schema, capability, protocol, mode, and limit validation;
3. physical approval and allowlist checks;
4. workspace lease, immutable staging, run reservation, and recovery journal;
5. the single `hf-runtime` sidecar call;
6. result validation, digest verification, persistence, and corpus/triage
   routing.

Failures before step 4 create no workspace or run record. Presentation layers
transport service-owned DTOs and never construct sidecar commands or
reimplement physical-bench readiness.

## 6. Agent and Human Authority

Agents may propose capture analysis, mutation, or replay plans. They cannot
enable the feature, choose an unlisted interface, manufacture approval evidence,
relax limits, or authorize physical execution. Offline analysis is non-live but
still sandboxed through the sidecar. Virtual execution is supervised.
Every physical-bench operation requires a fresh service-verified human approval
after the exact plan, budgets, and immutable sidecar image identity are known.
Because guardrail interaction and workspace leasing may wait, the service
revalidates the complete scope and freshness at the timestamp used for the
atomic approval claim; an approval that expires while waiting cannot execute.
Approvals are single-use: the
service records each consumed approval id in a durable ledger
(`automotive_consumed_approvals`) and claims it with an atomic, uniqueness-backed
insert before any bus access, so one approval authorizes exactly one physical
transmission even within its freshness window and even under concurrent
execution. A reused approval is rejected before the sidecar runs.

## 7. Campaign Synthesis, Reporting, and AI Assistance

Automotive reporting is a service-owned campaign operation over durable
evidence, not a sidecar operation and not a source-fuzzer report with renamed
fields. `hf-service` gathers a bounded project snapshot from retained automotive
operations and the promoted protocol-state corpus, then renders a deterministic
Markdown fact sheet. The snapshot and report include:

- operation totals and lifecycle outcomes, including retained failures and
  interrupted work;
- protocol and mode distribution without treating state novelty as source
  coverage;
- unique validated state-signature digests and promoted state-corpus evidence;
- an evidence manifest binding every row to the operation id, request digest,
  transcript digest when present, and workspace-relative artifact directory;
- the effective safety posture and explicit limits on what the campaign proves;
- prioritized, deterministic next actions based on missing workflow stages,
  failures, unpromoted state evidence, and unvalidated live modes.

The deterministic report is always available without a model provider. When a
provider is configured, the service may request a clearly labelled
**AI-assisted interpretation** of that fact sheet. Provider routing remains
model-agnostic. The prompt requires evidence citations in the stable
`[OP:<uuid>]`, `[STATE:<sha256>]`, and `[TRANSCRIPT:<sha256>]` forms. The service
rejects an empty response or any citation that is not present in the retained
snapshot and falls back to the deterministic report on provider or validation
failure. AI prose is appended to, and never replaces, the deterministic
evidence sections.

AI interpretation may explain observed states, identify campaign gaps, and
recommend additional offline analysis, deterministic mutation, or supervised
virtual validation. It must label hypotheses and missing evidence. It cannot
claim a vulnerability from protocol novelty alone, modify a replay plan, enable
policy, relax a limit, choose an interface, manufacture approval, or cause
traffic. An AI recommendation becomes executable only through the existing
typed planning, validation, guardrail, and human-approval flow.

REST, CLI, Tauri, and GUI surfaces consume the same serialized campaign-report
DTO. Export uses the existing service-owned report exporters. Presentation
layers may choose a destination or render a preview, but they do not recompute
totals, readiness, findings, citations, or safety posture.

## 8. Stateful Lab: Sequence Planning and Protocol-State Coverage

Status: **active implementation**, behind the `automotive-lab` feature.

### 8.1 Goal

A single request tells you little about a protocol implementation whose defects
depend on the order of calls. This extends the retained state corpus with two
things an operator can act on: what the evidence shows was actually reached, and
an ordered plan for reaching what it has not.

### 8.2 Modes, and why the bench is excluded

A plan may name only `OfflinePcap` or `VirtualCan`. A plan naming
`PhysicalBench` is refused, and the refusal says why.

This is not conservatism for its own sake. The existing rule is that each
physical transmission requires a fresh, single-use human approval, and the
service fails closed if one reaches execution without it. A sequence runner on
the bench would convert one approval into many transmissions -- exactly the
property that rule exists to prevent. The stateful lab therefore adds no
physical code path at all, rather than adding one with a gate that has to keep
holding.

### 8.3 Protocol-state coverage

Coverage is computed from retained evidence: the promoted state corpus and the
state signatures recorded on completed operations. It reports each distinct
state observed, its digest, and the operation that first produced it.

It does **not** report a percentage by default. Retained evidence establishes
which states were observed; it cannot establish how many exist. A denominator
requires a reviewed state model, supplied explicitly, and when one is supplied
the view names it and reports covered and unreached against it. Without a model
there is no total, no percentage, and no unreached list -- an absent denominator
is reported as absent rather than filled in with the observed count, which would
render every campaign as complete coverage of itself.

### 8.4 Sequence plan

A plan is an ordered list of steps. Each step names the operation to run, the
retained state it is expected to start from when one is known, and a stable
reason code for why it was chosen. Ordering is deterministic: unreached states
from the supplied model first, then states observed least recently, then digest
order for stability.

The plan is advisory. Running it uses the existing approved automotive execution
path, with its existing per-mode rules. Planning itself executes nothing and
opens no interface.

### 8.5 Rejected alternatives

- **Allowing bench sequences under one scoped approval** -- it would multiply a
  single-use approval into many transmissions, and a sequence that diverged
  mid-run would transmit frames the approval never described.
- **Allowing bench sequences with a per-step approval** -- it preserves the rule
  literally, but builds a physical execution loop whose safety depends on a gate
  never regressing. No bench path is safer than a guarded one.
- **Reporting observed states as full coverage** -- with no model the observed
  set is its own denominator, so every campaign would report complete coverage
  of itself.
- **Inferring the state model from captures** -- an inferred model is exactly as
  incomplete as the evidence that produced it, and presenting it as a
  denominator would give that incompleteness the appearance of a measurement.
- **Executing the plan from the planner** -- automotive execution has an
  approval path per mode; a second entrypoint would duplicate it.

## 8b. Stateful Lab: Responder Model and Reset Evidence

### 8b.1 What this is, and what it is not

A virtual ECU here is a **model**, not a bus participant. It is a deterministic
responder implemented in Rust and driven by a reviewed script, used to check
whether a sequence plan is coherent before anyone runs it, and to give reset a
definition that can be checked.

It does not answer real requests on a virtual CAN interface. The sidecar's
operation vocabulary has no responder, and adding one is cross-language work in
the image whose distribution licensing is still open. Every verdict the model
produces is therefore a statement about the script, not about any real ECU, and
the surface says so. Confusing the two would be the worst failure available
here: a plan that the model says is fine tells you nothing about hardware.

### 8b.2 The script

A script names an initial state and a set of rules. Each rule maps a state and a
request to a response and a next state. Validation is deterministic and fails
closed:

- names and identifiers are bounded and non-empty;
- no two rules share a state and request, since a non-deterministic model cannot
  validate anything; and
- the initial state must appear in the rules, so a script cannot start nowhere.

The script is reviewed evidence. It is retained with any result derived from it,
so a later reader can see what the model assumed.

### 8b.3 Plan simulation

A sequence plan is walked against the script. Each step is reported as reachable
or unreachable *under this script*, with the state the model was in when it got
there. An unreachable step is not a defect: it usually means the script is
incomplete, which is exactly what a reviewer needs to see.

A plan is never rewritten by the simulation. The planner owns ordering; the
model only reports what it would do.

### 8b.4 Reset evidence

Reset is the claim that the target was returned to a known state between
sequences. That claim is checkable: the state signature observed after a reset
must equal a recorded baseline signature.

Three outcomes, and only three:

- **`confirmed`** -- the observed digest equals the baseline.
- **`mismatched`** -- both digests are present and differ. The reset did not
  restore the baseline.
- **`unconfirmed`** -- a digest is missing, so nothing was compared.

An unconfirmed reset is never treated as a successful one. Findings produced
after a reset that was not confirmed are marked as not attributable to the
sequence that followed it, because the starting state is unknown and any
attribution would be a guess presented as evidence.

### 8b.5 Rejected alternatives

- **Calling the responder a virtual ECU without qualification** -- it does not
  answer on a bus, and a reader who believed otherwise would trust a plan the
  model approved as if hardware had approved it.
- **Adding the responder to the Scapy sidecar now** -- cross-language work in an
  image whose distribution licensing is unresolved; it belongs in its own phase.
- **Treating an unconfirmed reset as confirmed** -- it would attribute findings
  to a sequence whose starting state was never established.
- **Letting the simulation reorder a plan** -- the planner owns ordering from
  retained evidence; a model rewriting it would substitute the script's
  assumptions for the campaign's evidence.
- **Failing a plan because the model could not reach a step** -- an incomplete
  script is the common case, and refusing on it would train operators to ignore
  the result.

## 9. Distribution and Licensing

The Rust core remains MIT and links no Scapy code. Enabling the
`automotive-scapy` feature in the product crates' default set does not change
that: the feature compiles only pure-Rust contract and orchestration types, and
Scapy 2.7.0 stays a GPL-2.0 Python sidecar distributed as a separate, pinned
Docker image that `hf-runtime` runs at operation time. The licensing boundary
therefore attaches to distributing that sidecar image, not to the Cargo feature:
any package that distributes the sidecar must retain the applicable license
notices and source-availability obligations. Release review must verify those
obligations before publishing the sidecar image; this design is an engineering
boundary, not legal advice.

## 10. Rejected Alternatives

- **Vendoring Scapy into the Rust/core distribution** -- couples the default
  MIT artifact to an optional GPL component and obscures upgrade provenance.
- **Embedding or linking Python/Scapy in the Rust process** -- bypasses the
  runtime isolation and makes cancellation/resource enforcement unreliable.
- **Host-side Python, SocketCAN, or raw shell execution** -- bypasses
  `hf-runtime`, workspace containment, and the service approval boundary.
- **Treating Scapy as an `EngineAdapter`** -- protocol decoding/state feedback
  is not source-fuzzer argument construction or source coverage.
- **Treating state signatures as coverage edges** -- creates false coverage and
  invalid comparisons with AFL++, honggfuzz, or libFuzzer.
- **Letting an LLM replace or mutate the evidence report** -- makes a
  non-deterministic provider response authoritative and breaks traceability.
- **Calling the model from CLI, REST, Tauri, or React directly** -- duplicates
  prompts and policy outside `hf-service` and produces inconsistent reports.

## 11. Verification

The implemented contract is covered by feature-enabled pure Rust tests for the
complete vocabulary, serde names, mode/approval validation, capability reports,
request/result consistency, replay ordering, structured errors, schema
rejection, and deterministic transcript/state hashes. The pure-Rust feature
never introduces a Scapy, Python, CAN, process, filesystem, or networking
dependency; a `--no-default-features` build of any product crate drops the
`hf-automotive` dependency entirely and exercises the feature-absent fallbacks.

Service and presentation tests use fake-runtime JSONL transcripts and immutable
fixtures. Unit and CI tests must not open a CAN interface or execute a real
fuzzer. A live vcan or physical-bench test requires separate explicit operator
approval and is never part of the default quality gate.

Campaign-report tests construct retained operation and state-corpus fixtures in
SQLite, render the deterministic report without a provider, and use a fake
provider for accepted and rejected AI citations. They prove that failures stay
visible, host paths do not leak into shareable report prose, state novelty is
not described as source coverage or a vulnerability, and feature-disabled
builds retain no automotive or Python dependency.
