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

## 4. Orchestration Flow

1. `discover` -> `TargetInventory` persisted; HITL selects targets.
2. For each selected target: `generate_harness` -> compile -> persisted smoke
   evidence (`SmokePassed`).
3. HITL explicitly promotes the exact revision -> `run_fuzz` -> streaming
   `FuzzRunHandle`. Agents and schedules fail closed before this approval.
4. On crash: `triage` -> `Vec<Crash>` with draft reports.
5. Background: `corpus_ops` + `coverage_report` loop; on stagnation, propose
   new harness.

Every persisted execution, including smoke qualification, carries the harness
identifier in its run configuration. Target-specific consumers resolve the run
through `run.config.harness_id -> harness.target_id`; they never infer target
ownership from whichever project run happened most recently.

Before smoke or full execution, the service allocates the run id and its
evidence directory. The run stores its kind (`smoke` or `campaign`), full source
and binary SHA-256 digests, and a comparison-context digest covering the staged
target sources, starting corpus, and sandbox image. Launch is rejected if
either active artifact no longer matches the approved revision. Records that
claim run-scoped evidence never fall back to mutable active paths: crash,
corpus, coverage, export, and report flows verify the exact run directory and
staged executable digest first. Only pre-migration records with no evidence
metadata may use the legacy flat paths.

Run deletion is also evidence-aware. Running records and runs referenced by a
harness qualification cannot be deleted, and successful deletion removes only
the validated, run-owned directory. A cancelled campaign stops orchestration
immediately and is never reported to schedulers or presentation layers as a
successful iteration.

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

### 4.4 Session Diagnostics

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
- Presentation regression: successful turns, rollback, and branching reload the
  canonical display transcript instead of slicing optimistic local messages.
- Diagnostics regression: a current-session summary excludes persisted traces
  from earlier sessions, and storage read failures are surfaced to callers.
- Contract: presentation manifests contain no direct domain, runtime, or agent
  dependencies.
