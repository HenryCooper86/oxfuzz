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
open a socket, select an interface, or contain service policy. Its
`automotive-scapy` Cargo feature is disabled by default. Consumers must
declare `hf-automotive` as an optional dependency and explicitly forward that
feature.

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

The Python adapter runs only as a pinned, operation-scoped sidecar through
`hf-runtime`. The Rust process will never import or link Scapy. Inputs are
service-staged, digest-verified, read-only artifacts; outputs are bounded files
inside a unique workspace. Runtime networking and capabilities are typed:
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
after the exact plan and budgets are known. Approvals are single-use: the
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

## 8. Distribution and Licensing

The Rust core remains MIT and has no Scapy dependency. Scapy 2.7.0 is pinned as
a GPL-2.0 sidecar dependency distributed separately from the default
feature-disabled core. Any package that distributes the sidecar must retain the
applicable license notices and source-availability obligations. Release review
must verify those obligations before enabling sidecar packaging; this design is
an engineering boundary, not legal advice.

## 9. Rejected Alternatives

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

## 10. Verification

The implemented contract is covered by feature-enabled pure Rust tests for the
complete vocabulary, serde names, mode/approval validation, capability reports,
request/result consistency, replay ordering, structured errors, schema
rejection, and deterministic transcript/state hashes. Default-feature builds
contain no Scapy, Python, CAN, process, filesystem, or networking dependency.

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
