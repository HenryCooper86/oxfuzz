# Service Orchestration Design

Status: **draft**. Owner: `hf-service`.

## 1. Goal

`hf-service` owns all business logic: it orchestrates the
discover -> harness -> run -> triage -> corpus -> coverage loop, manages
sub-agent delegation, and exposes a clean API to presentation layers.

## 2. Service API (sketch)

```rust
pub trait FuzzService: Send + Sync {
    async fn discover(&self, req: DiscoverRequest) -> Result<TargetInventory>;
    async fn generate_harness(&self, req: HarnessRequest) -> Result<Harness>;
    async fn run_fuzz(&self, req: FuzzRunRequest) -> Result<FuzzRunHandle>;
    async fn triage(&self, req: TriageRequest) -> Result<Vec<Crash>>;
    async fn corpus_ops(&self, req: CorpusOp) -> Result<Corpus>;
    async fn coverage_report(&self, run_id: Uuid) -> Result<CoverageReport>;
}
```

## 3. Workbench Readiness

`hf-service` owns workbench readiness derivation. Presentation layers receive a
dashboard DTO with state, score, blockers, and detail text instead of
re-deriving readiness from raw counts. This keeps REST, Tauri, CLI, and future
surfaces aligned on the same operational status.

Operational health follows the same ownership rule. The service probes the
mandatory Docker boundary and the engine tools inside the sandbox image, then
derives core fuzzing readiness. CLI, web, and desktop surfaces may format that
result, but they must not infer readiness from host engine binaries or make an
optional integration such as DefectDojo a release gate.

### 3.1 CI Gate Ownership

The non-interactive CI pipeline is a service operation. `hf-service` selects an
explicit permissive guardrail instance for that operation, requires an already
smoke-qualified and human-promoted harness, attempts seed generation, runs the
bounded campaign, triages its artifacts, and always produces SARIF. The CLI
only parses input, renders progress/outcome, writes the service-produced SARIF
to the requested destination, and chooses its process exit status. It never
mutates process-global guardrail environment variables.

## 4. Orchestration Flow

1. `discover` -> `TargetInventory` persisted; HITL selects targets.
2. For each selected target: `generate_harness` -> compile -> persisted smoke
   evidence (`SmokePassed`).
3. HITL explicitly promotes the exact revision -> `run_fuzz` -> streaming
   `FuzzRunHandle`. Agents and schedules fail closed before this approval.
4. On crash: `triage` -> `Vec<Crash>` with draft reports.
5. Background: `corpus_ops` + `coverage_report` loop; on stagnation, propose
   new harness.

`run_campaign` consumes an already smoke-qualified, explicitly promoted
harness. It does not generate, repair, refine, or promote code in a headless
flow, and its outcome reports only work that it actually performed. Harness
generation and repair remain separate reviewable operations.

Every engine-specific harness or execution entrypoint first resolves the
service-owned fuzzing policy. A disabled engine, zero duration, or request above
the configured duration ceiling fails before filesystem staging, database run
reservation, recovery-journal mutation, or sandbox launch. Accepted runs use
the resolved memory/CPU values in their persisted `FuzzRunConfig`; changing
Settings affects subsequent operations without rewriting an active run.

This preflight also covers smoke qualification and maintenance commands that
invoke an engine. Smoke resolves its 60-second qualification request into the
single `FuzzRunConfig` shared unchanged by persistence, `hf-harness`, the engine
command, and the runtime deadline. AFL++ coverage
pruning and libFuzzer corpus minimization validate their bounded operation
durations and resolve sandbox resources before workspace preparation, corpus
reads, artifact staging, or guardrail authorization.

Every persisted execution, including smoke qualification, carries the harness
identifier in its run configuration. Target-specific consumers resolve the run
through `run.config.harness_id -> harness.target_id`; they never infer target
ownership from whichever project run happened most recently.

Project identity is service-owned and canonical. Every project-scoped entrypoint
resolves an existing project root before discovery, persistence, workspace
selection, or deterministic target-id derivation. Relative paths and symlink
aliases therefore address the same project. A requested target must resolve to
a discovered or durably stored candidate; the nil UUID is reserved for legacy
fixtures and is never a valid service persistence identity.

Configured persistence is part of an evidence-bearing operation's success
contract. Discovery, ranking, compiled harness revisions, triaged crashes, and
other authoritative results return a storage error when their required write
fails. Filesystem markers are committed only after the corresponding database
record is durable, or are compensated before returning an error. Best-effort
maintenance may warn and continue only when its outcome cannot be presented as
durable evidence.

Before smoke or full execution, the service allocates the run id and its
evidence directory. The run stores its kind (`smoke` or `campaign`), full source
and binary SHA-256 digests, and a comparison-context digest covering the staged
target sources, starting corpus, and sandbox image. Launch is rejected if
either active artifact no longer matches the approved revision. Records that
claim run-scoped evidence never fall back to mutable active paths: crash,
corpus, coverage, export, and report flows verify the exact run directory and
staged executable digest first. Only pre-migration records with no evidence
metadata may use the legacy flat paths.

Presentation layers that need non-blocking execution call the service run-start
API. The service completes all preflight checks, stages immutable evidence,
inserts the running row, syncs the recovery journal, and registers cooperative
cancellation before returning the UUID. It then owns the background task and
emits run-id-attributed progress and lifecycle callbacks. A pre-reservation
failure returns directly to the caller and never creates a phantom id; a
post-reservation failure repairs the persisted row to `failed` before emitting
the terminal lifecycle event. Status and cancellation queries use service DTOs
rather than presentation-side reconstruction from run history.

Run deletion is also evidence-aware. Running records and runs referenced by a
harness qualification cannot be deleted, and successful deletion removes only
the validated, run-owned directory. A cancelled campaign stops orchestration
immediately and is never reported to schedulers or presentation layers as a
successful iteration.

Whole-workspace cleanup is likewise service-owned and fail-closed. The service
uses a canonical-root lease shared by independent containers, plus a
root-digest-keyed advisory file lock outside the deletable workspace so separate
CLI, GUI, TUI, and web processes share the same boundary. All workspace staging,
build, smoke, fuzz, corpus, crash, coverage, export, and evidence operations hold
a shared lease for their complete asynchronous lifetime, while whole-root
cleanup requires the exclusive lease. Cleanup fails busy if an operation is
already active, including the pre-registration window before a run appears in
the cancellation registry; an operation arriving after cleanup began cannot
enter and either waits on the process-local gate or fails busy on the file gate.
Cleanup then deletes only a canonical, non-symlink workspace root whose
versioned ownership manifest names that exact path.
Environment overrides cannot authorize deletion of filesystem, home,
repository, configuration, or data ancestors. The implicit per-user default may
be marked during a legacy upgrade, while an unmarked non-empty environment
override is preserved for explicit operator recovery.

Campaign lifecycle recovery is fail-closed. Before creating run-owned files or
launching the sandbox, the service rejects a recovery journal with a replay,
compaction, or append durability error. Opening and closing a run are synced WAL
events. The database becomes terminal only after metrics and coverage samples
are durable; if the final journal close cannot be confirmed, the database row
is downgraded to failed and later campaigns remain blocked. WAL replay is
bounded and preserves malformed input for operator recovery instead of
compacting ambiguous evidence away. This bounded JSONL WAL is owned directly by
`hf-service` and is the sole recovery-state model; there is no parallel
in-memory scope journal.

For one-time schedule creation and execution, `hf-service` requires readable
SQLite. It loads and validates occurrence receipts before recovery planning,
reconciles stale JSON cursors before ticking, and owns recovery DTOs plus
acknowledgement. Corrupt or unavailable receipt evidence blocks one-time work
only. Startup preserves a safely decoded schedule identity before strict row
conversion and quarantines each identifiable malformed receipt before cursor
restoration or schedule-file writes. An undecodable schedule identity
quarantines the complete startup definition snapshot, so later full writes
cannot overwrite unknown damaged evidence; recurring schedules still execute
from their in-memory definitions.

Persistent chat context is session-owned. Presentation-supplied session ids are
validated before transcript file I/O, and the session metadata row must exist
before the service loads model context or retains a per-session turn lock. Raw
session strings never become filesystem paths outside the transcript store.

### 4.1 Persistent Chat Durability

Every mutation of a persistent conversation is serialized through one
per-session service lock. This includes model turns, rollback, branching, and
deletion; presentation layers never mutate chat state directly.

A completed turn is visible only after its user and assistant messages have
been written to both the display and context transcripts, session metadata has
been updated, and its rollback checkpoint has been persisted. Transcript
dual-writes use pre-mutation counts for compensating truncation. If any step
fails, the service returns an error and restores the prior transcript counts;
it never returns an assistant answer as though persistence succeeded.

Rollback snapshots both transcripts before changing them. A failure in the
second transcript, metadata update, or checkpoint invalidation triggers a
best-effort restoration of the pre-rollback transcript and metadata state and
is surfaced to the caller. Branch creation copies through the session manager;
a failed copy cleans up the incomplete child instead of returning its id.
Deletion clears both transcripts before deleting or tombstoning metadata, so a
reported success cannot leave a live transcript behind.

After any successful persistent mutation, presentation layers reload the
canonical display transcript. Optimistic tool-progress entries are transient
and are not used to calculate rollback or branch indices. A cached session id
that no longer exists is discarded and replaced with a newly-created session
instead of silently switching to frontend-only history.

### 4.2 Coverage Regression Rollback

Automatic harness rollback is evidence-gated. A completed campaign run may be
compared only with an earlier successful campaign for the same target whose
engine, requested duration, memory/CPU limits, sanitizer, corpus location,
environment, engine arguments, and comparison-context digest match. Smoke
qualification, cross-engine, cross-budget, failed, cancelled, unattributed,
same-revision, and legacy runs without complete provenance are not rollback
baselines. Baseline search continues past ineligible or same-revision runs.

Restoring a historical run reactivates the exact persisted source and staged
binary only after both digests are verified against that run and its promoted
harness qualification. It never recompiles historical text and transfers old
qualification metadata onto different bytes.

The active source revision is stored separately from language-specific compiler
inputs and is committed only after a successful sandbox build. Failed builds may
leave attempt files for diagnostics, but they do not change the active revision
or the binary/source attribution used by run history and rollback decisions.
Coverage-drop thresholds are finite percentages in `(0, 100]`; invalid global
values fall back to the safe default and invalid per-project writes are rejected.

Run-history presentation receives an opaque service-owned comparison key. This
prevents desktop/web clients from calling adjacent runs a regression when they
belong to another target or use incomparable execution conditions.

### 4.3 Syzkaller Campaign Isolation

Before `syz-manager` starts, `hf-service` allocates a unique staging directory
below the runtime's approved workspace root. It validates the selected config,
kernel, rootfs, and SSH key as regular non-symlink files and copies them into
that directory. The rootfs copy is disposable; qemu never receives a writable
mount of the selected original. An existing manager config may reference files
beside the config, but an implicit reference that resolves outside that config
directory is rejected. A separately selected artifact is treated as an
explicit override and is still copied before use.

The service parses and rewrites both supplied and synthesized manager configs.
`kernel`, `image`, `sshkey`, `workdir`, and `syzkaller` resolve only to fixed
container locations backed by the unique staging directory. Other absolute or
parent-traversing config paths fail closed. The sandbox mounts the primary
workspace and staged inputs read-only, exposes only the disposable rootfs
directory and work directory as writable, disables container networking, keeps
the standard capability and privilege hardening, and passes through only
`/dev/kvm` when native KVM is available. Staging is removed when the service
call ends or is aborted. The rewritten config clamps both manager processes and
VM count to a maximum of four, including values inherited from a supplied
config.

Input staging and writable output are bounded independently. The service
rejects manager configs and SSH keys over 1 MiB, kernels over 2 GiB, and rootfs
images over 32 GiB before copying. Each copy is limited while reading and
rechecks the open source metadata and destination byte count to reject files
that change during staging. During execution a live aggregate monitor cancels
the runtime if scratch/workdir logical growth exceeds 4 GiB, their combined
tree exceeds 100,000 entries, or any symlink/special file appears. A final scan
runs before success is returned. The container also receives a per-file limit
large enough for the staged rootfs and that growth allowance.

Rejected alternatives: mounting an existing config directory verbatim exposes
unreviewed host paths; mounting the selected rootfs writable lets a campaign
modify the user's source artifact; and disabling the entire hardening profile
grants qemu more privilege than its device contract requires.

### 4.4 Automotive Protocol Orchestration

The feature-gated `hf-automotive` crate owns only versioned DTOs, validation,
and canonical evidence hashes. It does not grant a capability or perform an
operation. Automotive workflows are service operations, not engine or
presentation shortcuts.

Before filesystem staging or operation persistence, `hf-service` checks the
compile-time feature, runtime setting, schema, pinned-adapter contract,
protocol, mode, artifact digest, and operation limits. Virtual execution also
requires an allowlisted vcan interface. Physical-bench execution additionally
requires a fresh human approval tied to the exact replay-plan digest, interface,
arbitration/service allowlists, rate, and duration; an agent-supplied approval id
is evidence to verify, never authority by itself.

After preflight, the service takes the workspace operation lease, stages only
immutable artifact references into an operation directory, persists recovery
state, and invokes one bounded sidecar request through `hf-runtime`. It validates
the correlated result/error envelope, declared output sizes, artifact hashes,
and canonical transcript/state digests before marking the operation complete.
Presentation layers receive redacted service-owned summaries and cannot
construct JSONL, choose devices, or reinterpret state novelty as source
coverage.

Offline capture analysis, mutation generation, replay planning, virtual replay,
physical replay, and state-corpus promotion are distinct operations with
distinct policy and approval requirements. Failure before persistence leaves no
operation record; failure after persistence is retained with a terminal status
and redacted failure reason.

Campaign synthesis is also service-owned, but it is read-only and never invokes
the sidecar. The service loads a bounded operation/state-corpus snapshot,
validates every retained typed result and digest, removes canonical host paths,
and renders the deterministic Automotive report. The report carries workflow
stage status, typed result summaries, failed and partial operations,
protocol-state evidence, request/transcript attribution, safety posture,
limitations, and deterministic next actions. State novelty remains explicitly
separate from source coverage and vulnerability claims.

When requested and a provider is configured, the service sends the complete
fact sheet through the provider pool and accepts only bounded prose whose
`[OP:<uuid>]`, `[STATE:<sha256>]`, and `[TRANSCRIPT:<sha256>]` citations resolve
to the snapshot. Accepted AI interpretation is appended after the fact sheet;
empty, malformed, uncited, or ungrounded output falls back to the deterministic
report. REST, CLI, Tauri, and React transport this one service DTO and do not
recompute its metrics or authority boundaries.

### 4.5 Session Diagnostics

The diagnostics recorder assigns a fresh identifier to each recorder instance.
Its cost summary includes only generation traces carrying that identifier, even
when the trace store is persistent and contains earlier sessions. Persisted
traces remain available for retention, search, and historical reporting, but
they are not presented as current-session spend.

Summary reads are fail-closed. Trace or observation query failures propagate
through the service API and presentation transports; callers may retain a last
known value only while visibly reporting that diagnostics are unavailable. A
storage failure must never be converted into a zero-call summary, because zero
is a valid measurement and would conceal an observability outage.

### 4.6 Proof-Carrying Campaign Intelligence

Behind the `proof-carrying` feature, `hf-service` assembles canonical campaign
evidence from durable run, harness-promotion, crash, coverage, corpus, sandbox,
and diagnostics records. Missing legacy provenance is an explicit incomplete
result; mutable active paths are never substituted for run-owned evidence.

The service also adapts comparable run history into the pure `hf-coverage`
campaign advisor and packages `hf-crash` remediation contracts. Both outputs are
advisory until an operator uses the existing guarded workflow. A remediation
claim becomes verified only from service-owned sandbox evidence tied to the
exact patch and reproducer digests. See
`proof-carrying-campaign-intelligence.md` for the versioned contracts.

### 4.7 Semgrep Target Enrichment

Semgrep enrichment is an explicit, feature-gated service operation for a
persisted C or C++ inventory. Normal discovery, agents, schedules, campaigns,
and effective-ranking reads never start a scan. `hf-service` exposes
asynchronous start, status, cancel, and result operations; start completes
admission, inserts a durable running operation, registers cooperative
cancellation, and returns the operation UUID without awaiting Semgrep. One
project may have only one active Semgrep scan, and a second start fails busy.
The `semgrep-enrichment` feature is enabled by default in normal product crates;
`--no-default-features` excludes the integration and every Semgrep presentation
entrypoint.

The service takes the shared workspace lease before the first Semgrep database
or journal write, transfers it into the background worker, and retains it
through cleanup and journal close or abort. It also retains an exclusive
digest-keyed cross-process project lease for that interval so the one-active
project rule remains true while a published database row is `done` but not yet
durably closed. Admission rechecks recovery health after taking both leases.
Global knowledge deletion takes the exclusive workspace lease before deleting
Semgrep rows. Project deletion takes the shared workspace lease and then the
same canonical digest-keyed project lease as admission before deleting that
project's database rows or workspace. A conflicting explicit deletion fails
busy. These boundaries prevent deletion from removing an active parent while
its journal remains open and preserve the global workspace-then-project lock
order.
After nondurable preflight, an owned service task performs lease acquisition,
reservation, the staging-row insert, synced journal `Begin`, and worker
handoff. The start API awaits a one-shot result, but dropping that caller does
not cancel the owned durable-admission task. A successful UUID is sent only
after the scan worker owns the reservation and both leases. The service then
creates a source snapshot from the canonical C/C++ discovery set. Every input
must be a regular, non-symlink file below the canonical project root and remain
stable while copied. The normalized relative path and source snapshot bounds
are:

- 25,000 files;
- 2 MiB per file;
- 512 MiB aggregate bytes; and
- 4,096 bytes per normalized relative path.

Exceeding a bound fails the whole operation; a partial project is never
scanned. The snapshot is mounted read-only, and its deterministic SHA-256 is
the enrichment revision.

After output validation and immediately before `ready_to_commit`, the service
re-walks and re-hashes the current eligible source set under the same bounds.
Any added, removed, changed, unstable, or newly ineligible source changes the
revision and rejects the operation atomically before publication. No finding
or score row is published for that scan.

Semgrep CE `1.169.0` may omit `paths.skipped` when no target was skipped.
`hf-discovery` normalizes only that omission to an empty collection. An
explicit non-empty `paths.skipped`, a missing `paths` or `paths.scanned`, or a
normalized `paths.scanned` set that differs from the staged snapshot manifest
remains an atomic incomplete-analysis failure. This compatibility rule lives
in the strict parser; the fixed in-image wrapper stays an `exec`-based
no-argument boundary so PID 1 receives cancellation signals directly.

The durable publication sequence is:

```text
synced WAL open
-> synced ready_to_commit
-> one database publication transaction
-> staged-artifact cleanup
-> synced WAL close
```

The WAL open is durable before background work begins. After validation, the
`ready_to_commit` record contains the provenance and output digest. The
database transaction publishes every finding and target score together with
the terminal `done` run. The service then durably removes the source snapshot
and raw output and only afterward appends the synced successful close. Keeping
the journal in `ready_to_commit` through cleanup means a cleanup, close, or
compensation failure remains recoverable and cannot expose a
`done`-plus-closed overlay.

The database `done` state is internal until the journal close is verifiable.
The process-local reservation moves from cancellable to finalizing at the
completion claim and remains busy until terminal journal persistence. During
that interval, status reports `persisting`, cancellation reports inactive, and
the project lease rejects competing starts from other processes. Only a
successfully closed publication is externally `done`; an externally observed
success cannot later regress because cleanup compensation ran.

Every persistent journal replay or transition is serialized by an exclusive
advisory lock on a fixed, securely descriptor-opened lock file in the journal
directory. Initial replay and each replay/validate/read/append transaction hold
the lock for the complete transaction. Journal construction is filesystem-lazy:
it normalizes and retains the path without creating, opening, validating, or
replaying journal state. The first write/replay access occurs only while the
service owns its workspace lease. Result-only reads may open existing state but
never create missing state. The fixed lock entry is excluded from
operation-journal enumeration. The global lock order is workspace lease,
project lease, journal lock, then database transaction. Result-only reads take
only the journal lock and never acquire an earlier lease afterward.

The successful close record is deliberately distinct from a terminal abort
record. After a failed/cancelled database transition or a recovery
compensation is durable, the service may append a synced abort from either the
open or ready state. An abort contains only the terminal category, never
invented ready-to-commit provenance, and never satisfies the successful-close
gate used by result readers. If cleanup, compensation, or the abort append
fails, the journal stays interrupted so recovery can retry and new starts fail
closed.

If cleanup fails after database publication, a compensation transaction
deletes that scan's findings and scores and marks the run `failed`. A close
append error is indeterminate because the record may already have been synced;
the service marks recovery degraded, exposes only an `IncompleteJournal`
base-only view, and does not compensate solely from that return value. On
restart, a valid replayed close preserves the successful publication, while a
replayed ready state triggers compensation. Startup recovery performs the same
fail-closed repair for interrupted non-terminal runs, unclosed
`ready_to_commit` runs, and already-failed or cancelled rows whose abort was
interrupted, then cleans only the validated operation-owned staging directory
before appending the terminal abort. Failed and explicitly cancelled runs
publish no finding or score rows. If compensation or cleanup cannot be made
durable, the journal remains unclosed so startup recovery can repair the run.

Recovery also reconciles the two durable stores instead of assuming every
active database parent has a journal. It first repairs every open or
`ready_to_commit` journal. An interrupted journal whose database parent is
absent is still authoritative for its operation UUID: recovery removes only
that exact operation directory and appends a recovered abort. It then queries
all remaining `staging`, `scanning`, `validating`, or `persisting` parents. Such
a residual parent has no recoverable journal lifecycle, including the crash
window after the staging-row commit and before journal `Begin`. Recovery
removes the exact UUID operation directory first and only then atomically
deletes any children and marks the parent `failed` with
`recovered_missing_journal`. It does not fabricate `Begin` or `Abort`. The
active parent remains the retry marker until cleanup and terminalization both
succeed, so a second crash cannot strand artifacts without recovery evidence.
This repair derives its cleanup target from the managed workspace and validated
operation UUID; it does not require the source project to still exist.

Startup recovery takes the exclusive workspace recovery lease before journal
replay and retains it through database repair, cleanup, and terminal abort. If
a live process holds a shared workspace lease, recovery is deferred without
reading or mutating the journal and the new container rejects Semgrep starts.
The corresponding live operation acquired its shared lease before its database
insert and journal open, so bootstrap cannot misclassify a live pre-`Begin`
database row as interrupted. The same exclusion covers the complete
journal-to-database reconciliation pass.

Recovery cleanup is idempotent. Descriptor-relative validation must prove
either that the exact `workspace/semgrep/<operation-uuid>` directory was
removed and its parent synced or that this exact UUID child is already absent
beneath validated, non-symlink ancestors. An absent staging directory is
expected after a crash between cleanup and close; ambiguous or replaced
ancestors remain errors. An absent `semgrep` child beneath the validated
managed workspace is also proven absence for an operation that failed before
staging created that parent, but only through `openat` on a retained workspace
descriptor followed by a pathname/descriptor identity post-check. A path-based
`NotFound` is never sufficient evidence. Cleanup then repeats the
descriptor-relative `semgrep` lookup and accepts absence only if the second
lookup also returns `ENOENT`; a recreated parent or exact operation child is
rejected. Recovery's exclusive workspace lease prevents compliant service
operations from creating the parent during this proof. Live-operation cleanup
uses a shared lease and therefore detects and fails safely if a different
project creates the parent concurrently.

Every ranking consumer asks `hf-service` for `SemgrepInventoryView`; clients do
not join or rescore results. A result reader accepts an overlay only when the
database row is terminal `done` and the corresponding recovery journal is
successfully closed. A missing, interrupted, aborted, corrupt, or otherwise
unverifiable journal maps to `IncompleteJournal`: status and historical
findings remain readable, but ranking uses base scores only. New starts still
fail closed on sticky journal or recovery degradation.

After that publication gate, an overlay is current only when the eligible
source digest matches its scan revision and every stored base score matches
the current candidate base score. A mismatch makes it stale: the historical
scan remains queryable, but effective ranking immediately uses base scores
only. Repeated successful scans recompute from the current immutable base
inventory and never compound prior boosts.

Exact historical reconstruction permits an empty current same-language
inventory and reports a findings-preserving `StaleBase` view. Admission still
requires at least one persisted candidate. If reconstruction fails for another
reason, the status endpoint still returns the parent operation and uses a null
result rather than hiding the lifecycle row.

## 5. Sub-Agents

`hf-agent` owns only the model reason/act loop and depends on an inward
`AgentBackend` port. `hf-service` implements that port and owns tool dispatch,
knowledge access, diagnostics, guardrails, session locking, checkpoints, and
transcript persistence. Presentation crates depend on `hf-service` only; CI
manifest tests enforce this boundary and prevent a service/agent cycle.

- `discovery-agent` -- owns target ranking.
- `harness-agent` -- owns harness draft/iterate.
- `triage-agent` -- owns crash classification and bug report drafting.
- `coverage-agent` -- owns stagnation detection and harness proposals.

### 5.1 User Agents and Skills

User-authored agent and skill registries are service-owned configuration. Agent
definitions live under `config_dir()/agents`; skill definitions live under
`config_dir()/skills`. This makes source-checkout CLI/web use `<repo>/config`
while an installed desktop app uses its pinned per-user configuration root.

`ServiceContainer` owns list/read/save/delete operations and chat execution uses
the same resolvers. Registry writes use same-directory atomic replacement. Tauri
and REST handlers are typed transports only; neither constructs a registry or
chooses a path. A missing selected agent is a validation error rather than a
silent fallback, while an omitted agent id intentionally selects the default.

## 6. Tests

- Integration: end-to-end loop with mocked LLM and mocked engine.
- Regression: failed harness builds preserve the active revision.
- Regression: auto-revert baselines reject target, engine, budget, sanitizer,
  corpus, environment, and argument mismatches.
- Regression: target rediscovery preserves the original target id and all
  harness/corpus/crash attribution.
- Regression: reports, exports, regression replay, and corpus absorption ignore
  a newer run that belongs to another target in the same project.
- Security regression: malformed session ids cannot escape transcript storage,
  and unknown sessions are rejected before model invocation.
- Durability regression: failed transcript, metadata, checkpoint, rollback,
  branch, and delete mutations return errors without reporting partial success.
- Concurrency regression: every persistent mutation for one session shares a
  lock, while independent sessions remain concurrent.
- Concurrency regression: whole-workspace cleanup cannot overlap pre-run
  staging, builds, smoke, fuzz, corpus, crash, coverage, or evidence operations;
  independent containers share the root gate and an advisory-file regression
  proves the same exclusion primitive used by separate processes.
- Semgrep recovery regression: a committed active parent without a journal is
  cleaned and failed without a fabricated lifecycle, while an interrupted
  journal without a database parent is cleaned and recovered-aborted.
- Semgrep concurrency regression: global knowledge deletion holds the exclusive
  workspace lease, and project deletion holds the canonical project lease, so
  neither can remove a live Semgrep parent or its open journal.
- Presentation regression: successful turns, rollback, and branching reload the
  canonical display transcript instead of slicing optimistic local messages.
- Diagnostics regression: a current-session summary excludes persisted traces
  from earlier sessions, and storage read failures are surfaced to callers.
- Contract: presentation manifests contain no direct domain, runtime, or agent
  dependencies.
- Automotive contract: feature-enabled pure tests cover schema/version,
  protocol/mode/capability negotiation, replay validation, structured errors,
  and canonical transcript/state hashing. Future service tests use fake runtime
  envelopes and prove every invalid or unapproved request fails before staging.
