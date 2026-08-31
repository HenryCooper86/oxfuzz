# Harness Work Order v2 Design

Status: **approved for implementation planning**. Owner: `hf-service`, with
durable records in `hf-storage` and thin CLI/REST presentation.

## 1. Goal

Harness Work Order v2 provides a durable, provider-free authoring packet and a
safe way to import one or more externally authored harness candidates. Export
and import execute nothing. A separate, explicit qualification operation routes
one imported candidate through the existing sandbox compile, independent model
review, smoke, and human-promotion requirements.

This is the foundation for OSS-Fuzz-Gen-style candidate iteration without
copying another project's implementation or creating an alternate harness
execution path.

## 2. Scope

The first implementation includes:

- deterministic, content-addressed work-order export;
- durable work orders, submissions, and qualification attempts;
- multiple immutable submissions with repair ancestry;
- human and external-tool provenance;
- deterministic lint findings at import;
- qualification of one selected submission through the existing harness path;
- objective ranking over retained qualification evidence;
- explicit promotion of one exact, active, smoke-passed attempt;
- CLI and REST operations; and
- replacement of the non-durable v1 Rust and presentation APIs.

The first implementation does not include:

- an internal model call to author or repair a submission;
- automatic repair after compile or review failure;
- FuzzTest property harnesses;
- Grammar-Mutator configuration;
- batch qualification without a fresh human execution approval;
- pre-promotion coverage campaigns; or
- a desktop work-order workflow.

Corrected externally authored candidates are new immutable submissions whose
`parent_submission_id` records the repair ancestry. An internal repair agent can
be added later only with exact persisted provider requests and responses.

## 3. Ownership and Feature Flags

`hf-service` owns packet construction, normalization, import validation,
qualification orchestration, ranking, and promotion validation. `hf-storage`
owns the records and state transitions. `hf-cli` and `hf-web` parse input and
render service results without reconstructing decisions.

The existing `harness-work-order` feature remains the subsystem flag and
continues to imply `build-context`. Product crates keep their existing feature
wiring. No presentation crate imports `hf-storage`, `hf-harness`, or another
domain crate directly.

## 4. Work-Order Identity

The public document is:

```rust
pub struct HarnessWorkOrder {
    pub schema_version: u32,
    pub id: String,
    pub payload: HarnessWorkOrderPayload,
}
```

`schema_version` is `2`. `id` is the lowercase SHA-256 of the canonical JSON
serialization of `payload`; the identifier is not part of the hashed payload.
The payload uses Rust structs and enums rather than arbitrary JSON maps. Before
serialization, every set-like vector is sorted and deduplicated. Re-exporting
unchanged retained evidence therefore produces the same identifier and bytes.

The payload contains:

- stable target evidence: symbol, signature, language, project-relative source
  location, and discovery rationale, but not the database target UUID;
- selected engine;
- a source excerpt capped at `65,536` bytes and `60` lines, plus an explicit
  `truncated` flag;
- SHA-256 of the complete candidate source file;
- normalized compile context and its SHA-256;
- harness rules derived from `hf_harness::harness_rules()`;
- at most `20` seed references, sorted by content digest; and
- typed validation steps.

Absolute host paths do not enter the payload. The complete candidate source
must be a regular, non-symlink project file no larger than `4,194,304` bytes.
Project files are represented by validated project-relative paths. Include
directories are project-relative or fixed sandbox paths. A retained corpus
seed is represented by content digest and size, not its workspace path.
Failure to normalize a path inside the project is a validation error, not a
reason to emit the host path.

Compiler definitions are at most `4,096` bytes each. Discovery drops and
categorizes any definition value containing an embedded Unix, UNC, or
drive-qualified Windows absolute path, including `file:///...` and
punctuation-prefixed forms such as `prefix:/...`. Service packet normalization
applies the same shared bounded linear scan and rejects a path-bearing value
before persistence. Relative values and non-file URI values such as
`https://example.test/api` remain portable.

The database row separately stores the canonical project root and target id so
the service can find and delete project-owned records. Those lookup fields are
not model-visible packet content.

Persistence is write-first and receipt-idempotent. One auto-committed
`INSERT ... ON CONFLICT(id) DO NOTHING` statement serializes concurrent writers.
After that statement returns, storage loads the immutable durable row and
compares every field. Concurrent exports of identical evidence therefore return
the same row without a deferred transaction that can contend during a write
upgrade; the same identifier with different evidence remains an error.

## 5. Typed Validation Steps

V2 stores semantic steps rather than interpolated shell strings:

```rust
pub enum WorkOrderStep {
    Import,
    Qualify,
    Rank,
    Promote,
    RunCampaign { duration_secs: u64 },
    Coverage,
}
```

The renderer derives argv from the step and the work-order data. Unknown values
such as project root, source filename, submission origin, submission id, and
attempt id use typed placeholders.
The CLI renderer quotes every concrete POSIX argument in one helper. JSON
clients receive argv arrays and placeholder metadata, not a command string.

Every emitted argv array parses through the real CLI. Import includes the
required `--origin` value. Run uses `oxfuzz run <project>`, `--lang`, and
`--duration <seconds>s`; coverage uses `oxfuzz coverage <project>`. Run and
coverage both retain the exact `relative_source::symbol` selector rather than a
bare symbol.

The rendered order is import, qualify, rank, promote, campaign, coverage.
Promotion is visibly an explicit human step. No generated command claims that a
full campaign can run before promotion. The `Qualify`, `Promote`, and
`RunCampaign` views state their approval requirement; no boolean supplied by an
external packet can weaken the service policy.

## 6. Submissions

One work order accepts up to `20` immutable submissions. The public model is:

```rust
pub struct HarnessWorkOrderSubmission {
    pub id: Uuid,
    pub work_order_id: String,
    pub source: String,
    pub source_sha256: String,
    pub origin: WorkOrderSubmissionOrigin,
    pub parent_submission_id: Option<Uuid>,
    pub lint: Vec<LintFinding>,
    pub submitted_at: DateTime<Utc>,
}

pub enum WorkOrderSubmissionOrigin {
    Human,
    ExternalTool {
        tool: String,
        model: Option<String>,
        response_id: Option<String>,
    },
}
```

Source must be non-empty UTF-8 and no larger than `65,536` bytes, matching the
existing independent-review ceiling. `tool` and `model` are at most `128`
bytes; `response_id` is at most `256` bytes. Values must be non-empty after
trimming and contain no control characters. These fields are untrusted
provenance supplied by the importer, not verified provider attestations.

The parent must already exist under the same work order. Because a submission
can name only an existing row, repair ancestry cannot contain a cycle. An exact
retry with the same work order, source digest, canonical origin, and parent is
idempotent and returns the first submission. A genuinely new submission beyond
the limit fails with `submission_limit_reached`.

Import runs the deterministic harness lint for the work order's language and
persists all findings. Blocking findings do not prevent storage: an imported
draft is evidence worth correcting. They do prevent qualification before any
sandbox call.

Import performs no provider call, build, review, smoke run, coverage run, or
promotion. Durable storage is required; an unavailable store is an error.

## 7. Qualification Attempts

Qualification is a separate explicit operation over one submission. At most
five attempt identifiers may be ranked in one request, matching the existing
tournament cap.

Before compiling, the service:

1. loads the immutable work order and submission;
2. verifies the stored packet identifier and submission source digest;
3. recomputes the candidate-source and compile-context digests;
4. rejects changed evidence with `stale_work_order`;
5. rejects blocking import lint findings; and
6. durably creates a running attempt at stage `compile`.

The attempt stages are `compile`, `review`, `smoke`, and `complete`. Terminal
outcomes are `compile_failed`, `review_failed`, `smoke_failed`,
`smoke_passed`, and `interrupted`. Identity fields and terminal rows are
immutable. State updates use the expected previous stage and require exactly
one affected row.

Compilation calls the existing `harness_compile` service operation. A
successful compile records the resulting harness id before review begins. The
current compile result is extended to return that id rather than rediscovering
it from workspace marker files.

Independent review uses the existing exact-source and binary-digest review
path. The review step is extracted from `harness_smoke` into a reusable internal
service method; ordinary smoke behavior remains unchanged. The persisted work
order and submission make every work-order field shown to that review
reconstructable, and the existing `harness_ai_reviews` record retains the
provider response metadata.

Smoke uses the existing bounded `hf-runtime` path and persists the normal run
and harness evidence. Qualification never promotes. Before inserting its
running row, qualification acquires an OS advisory lease named by the new
attempt UUID and holds it through the terminal transition. Before accepting
work-order operations at service startup, recovery enumerates running attempts
and attempts the same lease independently for each row. A busy lease proves the
qualification is live and is skipped. Acquiring the lease proves the old owner
is gone and permits a compare-and-set transition of that attempt alone to
`interrupted`. Enumeration, lease, or transition errors fail the work-order
recovery gate closed. Retry creates a new attempt rather than rewriting
history.

## 8. Ranking and Promotion

Ranking is read-only and deterministic. It maps retained attempts to the
existing candidate-ranking inputs and orders them by:

1. successful compilation;
2. smoke verdict (`Pass`, then `Suspect`, then `Fail`, then absent);
3. shorter repair ancestry;
4. higher executions per second; and
5. stable submission time and identifier.

Ranking starts no process, changes no active harness, and promotes nothing.
Every attempt remains visible, including interrupted and failed attempts.

Promotion accepts one attempt id. The service requires:

- terminal `smoke_passed` outcome;
- a linked harness with `SmokePassed` status;
- the linked harness to be the exact active workspace revision; and
- matching source and binary digests from smoke evidence.

It then calls the existing atomic harness-promotion operation. The presentation
invocation supplies the existing human approval event, and the service still
enforces promotion policy; the work-order packet does not contain approval
authority. If another qualification replaced the active workspace revision,
promotion fails with `attempt_not_active`. The operator must qualify the
selected submission again, producing fresh review and smoke evidence.

Campaign and coverage operations remain the existing post-promotion service
paths. Work Order v2 never runs a pre-promotion coverage campaign.

## 9. Durable Schema

Migration `0029_harness_work_orders.sql` creates three tables.

### `harness_work_orders`

- `id TEXT PRIMARY KEY`: lowercase 64-character SHA-256.
- `target_id TEXT NOT NULL`: logical target reference.
- `project_root TEXT NOT NULL`: canonical project root used only for lookup.
- `schema_version INTEGER NOT NULL CHECK (schema_version = 2)`.
- `packet_json TEXT NOT NULL`: valid JSON, at most `262,144` bytes.
- `created_at TEXT NOT NULL`: RFC 3339 first-persisted time.

An update trigger makes every column immutable. An exact insert retry verifies
the persisted packet and lookup fields; a digest collision or conflicting row
fails loudly.

### `harness_work_order_submissions`

- UUID primary key;
- work-order id;
- source and lowercase source SHA-256;
- canonical origin JSON, at most `4,096` bytes;
- optional parent submission id;
- lint JSON, at most `65,536` bytes;
- submission time; and
- a uniqueness key over work-order id, source digest, origin JSON, and the
  normalized parent value, implemented with
  `COALESCE(parent_submission_id, '')`.

An update trigger makes the complete row immutable. Store validation enforces
the submission cap and same-work-order parent rule in the insertion
transaction.

### `harness_work_order_attempts`

- UUID primary key;
- submission id;
- status and current stage;
- optional linked harness id and smoke-run id;
- optional result JSON, at most `65,536` bytes, retaining compilation success,
  smoke verdict, repair depth, source and binary digests, executions per
  second, and crash count when those values are available;
- bounded failure code (`128` bytes) and message (`4,096` bytes);
- started, updated, and optional terminal timestamps.

Checks enforce valid stage/status combinations. Triggers preserve identity and
terminal evidence. Compare-and-set transitions prevent two writers from
advancing the same attempt.

Indexes support target/project work-order lookup, ordered submission listing,
and attempt listing by submission and status.

`clear_knowledge`, `delete_project`, and orphan cleanup delete attempts before
submissions and submissions before work orders. Clearing run history does not
delete work orders or submissions; attempt links whose run history is removed
retain their bounded result JSON and harness id but do not recreate cleared
runs. Ranking reads the retained result JSON and does not depend on a run row
that an operator has cleared.

## 10. Service and Presentation APIs

The service exposes operations to:

- export or return an existing work order;
- get and list work orders;
- import and list submissions;
- qualify one submission;
- get and list qualification attempts;
- rank up to five attempts; and
- promote one smoke-passed active attempt.

The CLI becomes a subcommand group:

```text
oxfuzz work-order export <project> --target <symbol> --lang <lang> --engine <engine> [--out <file>]
oxfuzz work-order import --work-order <id> --source <file> --origin <human|external-tool> [...]
oxfuzz work-order list [--project <project>]
oxfuzz work-order submissions --work-order <id>
oxfuzz work-order qualify --submission <id>
oxfuzz work-order rank --attempt <id>...
oxfuzz work-order promote --attempt <id>
```

CLI import accepts a file path only. It uses symlink metadata, requires a
regular non-symlink file, checks size before reading, and reads at most one byte
beyond the limit before rejection. The final open does not follow a link and
holds a handle that prevents rename or deletion until the bounded read ends.
Unix uses `O_NOFOLLOW`; Windows uses `FILE_FLAG_OPEN_REPARSE_POINT` and omits
delete sharing. Metadata, size validation, and the read use that same handle.

REST exposes these routes:

```text
POST /harness/work-orders
GET  /harness/work-orders
GET  /harness/work-orders/{work_order_id}
POST /harness/work-orders/{work_order_id}/submissions
GET  /harness/work-orders/{work_order_id}/submissions
POST /harness/work-order-submissions/{submission_id}/qualifications
GET  /harness/work-order-submissions/{submission_id}/qualifications
GET  /harness/work-order-attempts/{attempt_id}
POST /harness/work-order-attempts/rank
POST /harness/work-order-attempts/{attempt_id}/promotion
```

Import request bodies are capped at `131,072` bytes. Public errors retain
stable service codes and bounded sanitized messages. JSON responses contain
argv arrays for validation steps and never return the canonical project root.

The service also resolves a work-order, submission, or attempt identifier to
its immutable owning project. REST uses only those service methods for owner
resolution, then applies its approved-root policy before every ID-based read,
mutation, or execution. Ranking authorizes every supplied attempt. An unscoped
work-order list filters out owners outside the approved roots; handlers never
read storage directly.

Desktop commands and views are not part of the first implementation.

## 11. Errors

The service returns typed validation/storage/sandbox/provider errors with
stable detail codes including:

- `storage_required`;
- `invalid_work_order_digest`;
- `unsupported_work_order_schema`;
- `source_empty`;
- `source_too_large`;
- `invalid_provenance`;
- `parent_not_found`;
- `parent_work_order_mismatch`;
- `submission_limit_reached`;
- `submission_has_blocking_lint`;
- `stale_work_order`;
- `attempt_interrupted`;
- `attempt_not_smoke_passed`; and
- `attempt_not_active`.

Once a store is configured, read and write failures never become empty lists or
successful ephemeral exports.

## 12. V1 Replacement

The current v1 packet has no durable table and no import API. Under the
repository's pre-1.0 policy, v2 replaces its Rust types and CLI/REST request
format directly. The implementation updates every in-repository caller and
test in the same change.

V1 JSON is rejected explicitly as `unsupported_work_order_schema`; there is no
database migration from v1. The existing design status changes from `planned`
to `active implementation` when the first production task lands.

## 13. Security Properties

- Export and import start no process and call no provider.
- Imported source is stored as untrusted data and cannot become active through
  import.
- Every build, review-associated execution, smoke run, campaign, and coverage
  run remains service-owned and uses `hf-runtime` where execution occurs.
- Blocking lint findings stop qualification before sandbox work.
- Independent review and human promotion remain mandatory and digest-bound.
- External provenance is descriptive only and grants no authority.
- No arbitrary command, environment variable, shared library path, absolute
  host path, or approval field is accepted from a packet.
- Packet, source, provenance, lint, submission count, ranking count, REST body,
  and failure detail all have explicit limits.

## 14. Verification

### Pure and service tests

- Identical retained evidence produces byte-identical packets and ids.
- Concurrent exports of identical retained evidence return one durable packet.
- A changed source excerpt, complete source digest, compile context, rule, seed
  reference, engine, or language changes the id.
- Absolute and escaping project paths fail before persistence, including
  embedded Unix and Windows paths in compiler definitions.
- Every substituted validation argv parses through the real Clap parser and
  retains exact file-qualified, namespaced target selectors.
- Import persists one exact retry idempotently and preserves distinct origin or
  parent records.
- Empty, oversized, control-character provenance, cross-work-order parent, and
  twenty-first distinct submissions fail with their stable code.
- Import invokes neither runtime nor provider and records blocking lint.
- Qualification rejects stale evidence and blocking lint before runtime.
- Compile, review, and smoke failures persist the correct terminal stage and
  bounded diagnostics.
- A second store-backed container skips a truly live qualification while
  recovering a simultaneous unowned attempt as `interrupted`.
- Ranking is deterministic and starts no process.
- Promotion rejects failed, non-active, digest-mismatched, and non-smoke-passed
  attempts and succeeds only through the existing atomic promotion operation.

### Storage tests

- Migration checks reject malformed digests, oversized JSON/source fields,
  invalid stage/status pairs, and conflicting retries.
- Work orders and submissions are immutable.
- Terminal attempts are immutable and transitions use expected prior state.
- Project deletion, knowledge clearing, and orphan cleanup remove records in
  dependency order.
- Run-history clearing does not delete work orders or submissions.

### Presentation tests

- CLI import refuses symlinks, directories, and oversized regular files before
  service invocation.
- CLI import accepts bounded regular files on every shipped desktop platform;
  the native Windows suite verifies the exact 65,536-byte limit.
- REST import enforces the body limit and returns stable service errors.
- REST hides service-created outside-root records and denies every ID route
  before mutation, provider use, or runtime dispatch.
- CLI and REST render service-owned fields without recomputing ranking,
  approval, or execution decisions.

### Completion gates

Run the repository quality gates in the order required by `AGENTS.md` and
`docs/standards/TEST_STRATEGY.md`. All `cargo test` output uses the repository's
error-output filter. No test executes a generated harness or fuzzer on the
host; runtime and provider behavior use controlled adapters.

## 15. Rejected Alternatives

- **Persist imported source directly as a `Harness`**: an uncompiled external
  draft would appear in the executable harness lifecycle and weaken the meaning
  of harness status.
- **Filesystem-only packets and sidecars**: insufficient recoverability,
  provenance, multi-client access, and model-visible reconstruction.
- **One mutable latest submission**: destroys losing candidates and repair
  ancestry.
- **Automatic qualification during import**: makes a data-ingest operation run
  untrusted code and bypasses fresh execution approval.
- **Automatic model repair in the first implementation**: introduces provider
  request persistence and spend without being necessary to establish the safe
  lifecycle.
- **Pre-promotion coverage ranking**: creates another target-execution path and
  weakens the existing promotion rule.
- **Restoring an older candidate binary for promotion**: retained binary copies
  are not a substitute for fresh review and smoke evidence on the exact active
  revision; the selected candidate is qualified again instead.
