# SavvyCAN-Inspired Automotive Analysis and Live Tooling Design

Status: **proposed; phased implementation active**. Owner: `hf-automotive`
(pure analysis primitives) and `hf-service` (orchestration, live operations).
Extends `automotive-protocol-fuzzing-design.md`; that document's boundaries
(sandbox, human-in-the-loop, physical-bench gating, deterministic evidence)
remain authoritative and are not weakened here.

## 1. Goal and Scope

Add reverse-engineering and live-analysis capabilities to the automotive
subsystem, inspired by the feature set of SavvyCAN, so that oxfuzz can
understand a CAN target (not only fuzz raw bytes) and drive richer live tests.
The additions are:

- **DBC signal database** -- load DBC files and decode raw CAN frames into named
  signals (scaling, units, ranges, multiplexing).
- **Multi-format capture import** -- ingest candump, Vector ASC, CRTD, and GVRET
  CSV in addition to today's PCAP (BLF deferred, see 5.3).
- **ISO-TP reassembly** -- turn raw CAN frames into ISO 15765-2 PDUs for correct
  UDS/GMLAN/OBD decode.
- **UDS discovery scan** -- enumerate responding ECUs and supported (read-only)
  services on a bench to seed fuzz targets.
- **Live sniffer + bus statistics** -- a bounded live capture with per-byte
  change highlighting and bus-load/frame-rate/per-ID statistics.
- **Follow-on RE tools** -- signal graphing over time, capture diff, and a
  periodic/scheduled frame sender, plus DBC-aware (signal-level) mutation.

Non-goals: porting SavvyCAN's UI or device drivers, an embedded scripting
engine, MQTT/CAN-bridge/firmware-flash tooling, or any relaxation of the
physical-bench approval model.

## 2. Provenance and Licensing

SavvyCAN is **GPLv3**. This design borrows *concepts*, not code: every feature
is reimplemented clean-room from open specifications, and no SavvyCAN source is
read into or copied into this tree. The building blocks are open or permissive:

- **DBC** is a de-facto open interchange format; parsing uses a permissively
  licensed Rust crate (see 4.1) or a focused in-tree parser, never a GPL source.
- **ISO-TP / UDS** are ISO standards (15765-2, 14229-1); implemented from the
  standard byte layouts.
- **Capture formats** (candump, ASC, CRTD, GVRET CSV) are simple documented
  formats implemented from their specifications.

The MIT Rust core therefore gains no GPL linkage. Internal-only deployment
further bounds distribution obligations, but clean-room reimplementation keeps
the core clean regardless of deployment.

## 3. Architecture: two layers

The features divide along the existing safety boundary:

### 3.1 Pure-Rust offline analysis layer (no sidecar)

Lives in the `hf-automotive` crate as new modules alongside `contract`:
`dbc`, `capture` (format importers), `isotp` (reassembly), and `analysis`
(capture diff, per-byte change map, signal series). These are pure,
deterministic, `#![forbid(unsafe_code)]`, allocate-bounded, and fail-closed on
malformed input. They never open an interface or spawn a process, so they add no
new runtime attack surface and run even when the sidecar is absent. `hf-service`
calls them directly to service offline operations without a sidecar round-trip.

All per-frame analysis keys include both the numeric arbitration id and its
standard/extended namespace. ISO-TP/UDS analysis additionally emits bounded
state observations and transitions per channel/id/direction stream. Repeated
transitions affect occurrence counts but not novelty, and the output remains
separate from source coverage.

This layer is the foundation: DBC decode, importers, ISO-TP reassembly, and diff
are prerequisites for the live and visualization features.

### 3.2 Sidecar-backed live layer (gated)

Live bus interaction (bounded live capture/sniffer, UDS discovery scan, periodic
frame sender) extends the versioned sidecar contract with new request/result
variants and goes through the full `hf-service` order from the base design:
compile-time + runtime checks, schema/capability/limit validation, physical
approval and allowlists, workspace lease and staging, the single `hf-runtime`
sidecar call, then result validation and persistence. Virtual CAN is supervised;
physical bench stays disabled by default and approval-gated. No live feature
introduces an unbounded stream: every live operation is time- and rate-bounded
and returns the same canonical transcript evidence as an offline analysis.

## 4. DBC signal database (pure Rust, `hf-automotive::dbc`)

### 4.1 Parsing

Load DBC messages (`BO_`), signals (`SG_`), value tables (`VAL_`), and
multiplexing (`M` / `m<N>` and extended `SG_MUL_VAL_`). Parsing uses a focused,
line-based in-tree parser for this subset, keeping `hf-automotive`
dependency-light and fully under test; the permissively licensed `can-dbc` crate
(MIT/Apache-2.0) remains a drop-in if full DBC coverage (attributes, environment
variables) is later needed. Encoding rules that the parser applies: a `BO_` id
carries the 29-bit extended-frame flag in bit 31 (`id & 0x1FFF_FFFF`,
`extended = id & 0x8000_0000 != 0`); byte order `1` = little-endian (Intel),
`0` = big-endian (Motorola); value type `+` = unsigned, `-` = signed.

### 4.2 Deterministic decode

Decode a frame payload into signal values: extract `bit_length` bits at
`start_bit` honoring byte order (Intel/little vs Motorola/big -- the classic
start-bit interpretation difference), apply sign, then `raw * factor + offset`,
clamp/report against `[min, max]`, attach unit and any value-table label.
Decoding is total and deterministic; unknown IDs decode to "raw only". A
`DecodedFrame` carries the message name and the ordered `DecodedSignal`s.

### 4.3 Uses

- Human-readable decode in the GUI and reports.
- **Signal-aware mutation** (phase 3): mutate at the signal level within valid
  ranges / boundary values rather than blind byte flips, feeding the existing
  deterministic mutation flow.
- Signal series extraction for graphing (8.1).
- Richer state signatures keyed on decoded signals rather than raw bytes.

DBC databases are project-scoped configuration (like a corpus), loaded from a
staged artifact; they never carry host paths into evidence.

## 5. Capture import (pure Rust, `hf-automotive::capture`)

### 5.1 Model

Each importer parses file *content* (bytes provided by the service, not a path
it opens) into a normalized `Vec<FrameRecord>` -- timestamp, bus/channel, CAN id
(with standard/extended flag), dlc, data, direction, and remote/error/FD flags.
The normalized frames feed either the canonical transcript (reusing the existing
transcript + hash, so imports produce the same evidence as an `AnalyzeCapture`)
or DBC decode. Parsers are bounded by the operation limits and fail closed with
a typed error on malformed input.

### 5.2 Phase-1 formats

candump (SocketCAN `candump -l`), Vector ASC, CRTD (OVMS), GVRET native CSV.
Field-level semantics are taken from each format's specification. Standard vs
29-bit extended identification, remote/error frames, and the CAN-FD form are
handled per format.

### 5.3 BLF (deferred)

Vector BLF is a compressed binary container (LOBJ objects inside zlib-compressed
blocks) and is materially more complex than the text formats. It is deferred to
a later phase pending a permissively licensed reader (the `ablf` crate,
MIT/Apache-2.0, is the candidate; the GPLv3 C++ reference is avoided); the
importer trait is shaped so BLF drops in without touching the others.

### 5.4 Service operation

A new `ImportCapture` operation stages the file, parses it in-process (no
sidecar), optionally DBC-decodes, and persists the same operation evidence as an
offline analysis, so imported captures flow into planning, corpus seeding, and
reporting unchanged.

## 6. ISO-TP reassembly + UDS discovery

### 6.1 ISO-TP reassembly (pure Rust, `hf-automotive::isotp`)

Deterministic receiver reassembly per ISO 15765-2: parse the PCI type nibble
(SF/FF/CF/FC), Single-Frame length (classic and the CAN-FD escape), First-Frame
12-bit and 32-bit-escape lengths, Consecutive-Frame sequence numbers with 15->0
wraparound, and Flow-Control (FlowStatus CTS/Wait/Overflow, Block Size, STmin).
Normal, normal-fixed, extended, and mixed addressing are handled by a
`pci_offset` plus optional address-extension byte. The output is reassembled
PDUs that feed correct UDS/GMLAN/OBD decode. This is offline and adds no live
capability by itself.

### 6.2 UDS discovery scan (live, sidecar, gated)

A live, read-only scan enumerates responding ECUs and supported services to seed
fuzz targets. Presence is proven by the *existence* of a reply (positive
`SID+0x40` or negative `0x7F SID NRC`); silence means absent. `0x78`
(ResponsePending) extends the wait to P2* with a bounded pending-cycle cap.

**Safety (critical).** The scan is restricted to a read-only allowlist:
`0x3E` TesterPresent, `0x10 01` (default session only), `0x22` ReadDataByIdentifier
against an allowlisted safe-DID set, `0x19` ReadDTCInformation, `0x1A`
ReadEcuIdentification. All state-changing / actuating / security / memory /
programming services are **denied by default** and require explicit, logged human
approval: `0x11` ECUReset, `0x14` ClearDiagnosticInformation, `0x27`
SecurityAccess, `0x28` CommunicationControl, `0x2C`, `0x2E`
WriteDataByIdentifier, `0x2F` IOControl, `0x31` RoutineControl, `0x23`/`0x3D`
memory access, `0x34`-`0x38` transfer/flash, `0x85` ControlDTCSetting, `0x87`
LinkControl, and any `0x10` session change other than default. This maps onto the
existing `physical_bench` policy, which already carries a `uds_services`
allowlist and an `allow_dangerous_services` switch; the scan reuses and tightens
that model and never escalates a session automatically.

## 7. Live sniffer + bus statistics (live, sidecar, gated)

A new `LiveMonitor` operation performs a bounded live capture on an approved
interface (virtual CAN now; physical bench gated) for a limited number of frames
or wall-clock window. It returns the canonical transcript plus:

- a **per-byte change map** per arbitration id (which byte positions vary), the
  sniffer's core RE signal, computed in pure Rust from the transcript;
- **bus statistics** -- frames/sec, per-id counts, DLC distribution, and bus
  load estimate.

The change map and statistics are deterministic post-processing over the
transcript, so they are reproducible from retained evidence. The operation is
rate/time-bounded by the existing `OperationLimits` and guardrails.

## 8. Follow-on RE tools

### 8.1 Signal graphing (GUI)

Render DBC-decoded signal values over time from a decoded transcript. Pure
client-side rendering over evidence already produced by 4.2; no new backend
authority. Multi-signal, with export of the underlying series.

### 8.2 Capture diff (pure Rust, `hf-automotive::analysis`)

Compare two transcripts and report added/removed ids, changed payloads per id,
and timing deltas -- a direct RE aid and a complement to state-signature
novelty. A `DiffCaptures` service operation runs it over two staged artifacts.

### 8.3 Frame sender / periodic transmit

Extend the replay model with periodic/scheduled repetition (interval, count) and
a GUI sender panel. It reuses replay execution, the peak-rate guard, guardrails,
and approval; it introduces no new execution authority, only a scheduling shape
over existing send actions.

## 9. Contract changes

New pure-Rust operations (`ImportCapture`, `DecodeSignals`, `DiffCaptures`,
ISO-TP reassembly) are handled service-side and do not require sidecar-contract
variants. Live operations (`LiveMonitor`, `ScanUds`) add request/result variants
and new `AutomotiveCapability` values (e.g. `LiveMonitor`, `ScanUds`). The schema
remains v1 with additive variants where back-compatible; a version bump is used
only if an existing shape must change. Capability negotiation stays authoritative
-- presence of a variant does not imply the pinned sidecar supports it.

## 10. Safety model (unchanged boundaries)

Defense in depth is preserved: sandboxed execution (`hf-runtime`) -> guardrail
interception (`hf-guardrails`) -> human-approved execution. The offline layer is
pure, bounded, and fail-closed, adding no new attack surface. Every live
operation is bounded and returns canonical evidence. The UDS scan is read-only by
default (6.2). Physical bench remains disabled by default with mandatory,
single-use, service-verified approval. Agents may propose scans, imports, decode,
and plans, but cannot enable the feature, relax a limit, choose an unlisted
interface, add a dangerous service, or authorize physical execution.

## 11. Presentation

`AutomotiveView` gains panels, each thin over a `ServiceContainer` method: DBC
load + signal table, capture import, live sniffer (frame grid + change
highlight) with bus-stat tiles, UDS scan results (discovered ECUs/services),
signal graph, capture diff, and a frame sender. All strings are added to the
en/zh i18n dictionaries. Presentation renders service-owned DTOs and never
constructs sidecar commands or reimplements readiness.

## 12. Phasing

- **Phase 1 (pure-Rust foundation):** DBC parse+decode, capture importers
  (candump/ASC/CRTD/GVRET CSV), ISO-TP reassembly, capture diff, sniffer change
  analysis, and GUI for these offline features. Self-contained, no sidecar.
- **Phase 2 (live, sidecar):** `LiveMonitor` (sniffer + bus stats), `ScanUds`
  discovery, periodic frame sender. New contract variants and guardrails.
- **Phase 3 (intelligence):** DBC-aware signal-level mutation and signal-keyed
  state signatures; signal graphing polish.

## 13. Rejected alternatives

- **Porting SavvyCAN C++** -- GPLv3 contamination of the MIT core and a wrong
  technology stack (Qt vs Rust/Tauri).
- **Embedding a JS scripting engine** (SavvyCAN feature) -- conflicts with the
  agent/skills model and the safety boundary; arbitrary in-tool code execution
  is exactly what the sandbox exists to prevent.
- **Reimplementing device drivers** (GVRET/serial/Kvaser/SLCAN) -- the sidecar
  already owns interface access via `python-can`; live backends become config,
  not new driver code.
- **Unbounded live streaming sniffer** -- breaks the one-shot bounded evidence
  model and the rate/time safety bounds; a bounded live capture with
  post-processing gives the same RE value safely.
- **Treating a decoded signal series as source coverage** -- as in the base
  design, protocol/signal novelty is not source coverage.

## 14. Verification

TDD throughout. Pure-Rust modules get unit tests with known vectors: DBC decode
against hand-computed Intel/Motorola signals (signed, factor/offset,
multiplexing); each importer against a golden sample file with extended IDs,
remote/error/FD frames; ISO-TP reassembly against multi-frame SF/FF/CF/FC
sequences including wraparound, escape lengths, and both addressing modes;
diff determinism. All parsers are fuzz-friendly and must fail closed on malformed
input without panicking. Live operations are tested with fake-runtime JSONL
transcripts; no unit or CI test opens a real interface or runs a real scan.
Feature-disabled (`--no-default-features`) builds retain no automotive
dependency. The UDS safe-allowlist and dangerous-service denial are covered by
explicit policy tests.
