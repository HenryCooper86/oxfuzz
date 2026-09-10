# Coverage Experiments

Status: **implemented**. Owners: `hf-service` for experiment
policy and workflow, `hf-storage` for durable records and reference protection,
`hf-web` and `hf-gui` for presentation. This document is the authoritative
experiment design; [Coverage Blockers](coverage-blocker-design.md) supplies
optional suggestions. The feature retains proposals and results but does not
execute experiment work.

## 1. Operator workflow and scope

An engineer selects a retained terminal campaign for the current project and
target, reviews `grow_corpus` or `refine_harness`, a goal function, their own
hypothesis, and a positive duration budget. Preparation persists that exact
intent and baseline evidence before any navigation. The engineer explicitly
uses existing Corpus and Harness workflows, then explicitly starts the existing
CLI replay operation with the baseline seed and attaches one later terminal campaign, or cancels the investigation with a reason. Reopening shows
the immutable proposal and its history, including unsuccessful attempts.

Preparation is an evidence write, not execution authorization. Create, get,
list, complete, cancel, and owner lookup call no discovery, provider, runtime,
image resolution, source coverage calculation, refinement, promotion, corpus
mutation, or engine. They do not add a scheduler, agent tool, approval type, or
recovery worker. Existing qualification, policy, provider, execution, and
promotion paths retain their current behavior. Cancelling an experiment changes
only its record; it never cancels a campaign.

One experiment accepts one result. To retain another attempt, prepare a new
experiment, even if its hypothesis and baseline match an earlier record.
History has no automatic pruning. There is no public single-experiment deletion
operation; explicit project deletion and knowledge clearing own cleanup.

## 2. Public APIs and ownership

All methods are async and return `Result<_, CoverageExperimentError>`. The
service owns these request/view types in `coverage_experiments`; transports
re-export their serialization rather than reconstructing policy. Implemented names:

```rust
create_coverage_experiment(CreateCoverageExperimentRequest) -> CoverageExperimentView
coverage_experiment(Uuid, CoverageExperimentScope) -> CoverageExperimentView
list_coverage_experiments(ListCoverageExperimentsRequest) -> CoverageExperimentPage
complete_coverage_experiment(Uuid, CompleteCoverageExperimentRequest) -> CoverageExperimentView
cancel_coverage_experiment(Uuid, CancelCoverageExperimentRequest) -> CoverageExperimentView
coverage_experiment_owner(Uuid) -> CoverageExperimentOwner
validate_coverage_experiment_scope(Uuid, CoverageExperimentScope, Option<Uuid>) -> ()
```

| Request | Exact fields |
| --- | --- |
| `CreateCoverageExperimentRequest` | `project: PathBuf`, `target_id: Uuid`, `baseline_run_id: Uuid`, `kind: CoverageExperimentKind`, `goal_function: String`, `hypothesis: String`, `duration_secs: u64` |
| `ListCoverageExperimentsRequest` | `project: PathBuf`, `target_id: Option<Uuid>`, `limit: usize`, `before: Option<CoverageExperimentCursor>` |
| `CoverageExperimentCursor` | `created_at: DateTime<Utc>`, `id: Uuid` |
| `CoverageExperimentScope` | `project: PathBuf`, `target_id: Uuid` |
| `CoverageExperimentOwner` | `project_root: PathBuf`, `target_id: Uuid` |
| `CompleteCoverageExperimentRequest` | `scope: CoverageExperimentScope`, `result_run_id: Uuid` |
| `CancelCoverageExperimentRequest` | `scope: CoverageExperimentScope`, `reason: String` |

Kind is exactly `grow_corpus | refine_harness`; status is exactly
`prepared | completed | cancelled`. No `no_experiment_available` record kind
exists. The create request has no caller-selected experiment ID, timestamps,
source evidence, or provider-authored hypothesis. Service generates a v4 UUID
and timestamps. Create retries are separate proposals; clients recover an
uncertain create response by listing, not by assuming duplicate submission is
idempotent. Disable repeated submit while a request is outstanding.

The view contains `schema_version: 1`, the immutable proposal, status,
`result: Option<CoverageExperimentResultEvidenceV1>`,
`cancellation_reason: Option<String>`, `created_at`, `updated_at`, and `ended_at`.
The proposal includes ID, canonical project, target ID/symbol, baseline run ID,
kind, goal, hypothesis, duration, and baseline evidence. The page contains
`schema_version: 1`, `items: Vec<CoverageExperimentView>`, and nullable
`next_cursor`; it returns at most `limit` records. Use strict request JSON with
unknown fields rejected. All nullable evidence fields must be present as JSON
null when unavailable; omitted keys are malformed, never historical defaults.

The unconditional storage module is `coverage_experiment_store.rs`, with
`CoverageExperimentRecord`, `CoverageExperimentRunEvidenceV1`,
`CoverageExperimentResultEvidenceV1`, and strict enums. Store methods:
`insert_coverage_experiment(&record)`, `coverage_experiment(id)`,
`list_coverage_experiments(project, target_id, limit, before)`,
`complete_coverage_experiment(id, &result, ended_at)`,
`cancel_coverage_experiment(id, reason, ended_at)`, and
`coverage_experiment_run_reference(run_id) -> Option<CoverageExperimentRunReference>`.
Storage methods return `Result<_, StorageError>`: insert returns `()`, get
returns `Option<CoverageExperimentRecord>`, list returns a bounded record page
with cursor, complete/cancel return the retained `CoverageExperimentRecord`,
and reference lookup returns the optional typed reference.
The reference has experiment UUID and role `baseline | result`; choose the
lexically smallest `(experiment_id, role)` when several references exist. A
single internal query accepts the transaction connection, so public lookup,
run deletion, and clearing share this meaning. Store insertion accepts an
identical full prepared record retry, but rejects any different same-ID record.

Storage enforces durable structure, source-record identity, chronology, immutable
proposal, and CAS. Service owns setup comparison and interpretation. Writes
re-read the referenced run/config, harness/target owner, and build-input row
under the reserved SQLite writer, and require exact equality with the supplied
snapshot. Thus a service comparison cannot commit evidence changed since its
reads. Extract transaction-capable strict readers from existing Store methods;
do not issue nested pool reads while holding the writer. On terminal retries,
compare against retained terminal evidence first, as specified in section 6.

## 3. Evidence and strict limits

`CoverageExperimentRunEvidenceV1` contains exactly these fields:

| Field | Type / meaning |
| --- | --- |
| `schema_version` | integer 1 |
| `run_id`, `target_id`, `harness_id` | UUIDs resolved from persisted run/config/harness |
| `project_root`, `target_symbol` | canonical owner and captured target label |
| `engine`, `status`, `kind` | typed active engine, terminal run status, Campaign |
| `started_at`, `ended_at` | required UTC timestamps from run; start is the existing run allocation timestamp |
| `duration_secs`, `max_mem_mb`, `max_cpus`, `sanitizer` | exact persisted run settings |
| `engine_env`, `engine_args` | exact ordered `Vec<(String,String)>` and `Vec<String>` |
| `seed` | explicit nullable u64 from config |
| `seed_corpus`, `replay_of` | explicit nullable UTF-8 path and UUID; provenance/display only |
| `harness_rev`, `binary_rev`, `source_rev`, `corpus_rev` | required lowercase full SHA-256 identities |
| `sandbox_rev` | required exact `docker-image-id-sha256:<64 lowercase hex>` |
| `context_rev` | explicit nullable full SHA-256 composite; retained but not compared |
| `edges` | explicit nullable nonnegative integer peak count |
| `build_inputs` | explicit nullable exact `HarnessBuildInputsRecord` snapshot |

This is a complete comparison snapshot, not a copy of source, crash artifacts,
run logs, samples, throughput, or current workspace metadata. It deliberately
omits those unrelated/unbounded fields. Never truncate a setup field to fit.
The existing strict `run_record`, `run_target_id`, and
`Store::harness_build_inputs` paths are the source readers; require a resolved
non-null target. Resolve target symbol/project through the stored target row,
not a client label or best-effort target guess.

Both JSON evidence envelopes are at most 65,536 UTF-8 bytes each, including
escaping and keys. Result evidence contains `schema_version: 1`, `run` (the
snapshot above), `input_change`, `build_comparison`, `edge_comparison`,
`target_entry`, and `limitations`. Field limits apply before serialization too:

| Value | Bound and validation |
| --- | --- |
| project and seed-corpus path text | 1–4,096 bytes when present; no control characters; project uses existing normalized absolute Unix/Windows syntax |
| target symbol and goal function | 1–1,024 bytes; non-whitespace, trimmed, no control characters |
| hypothesis and cancellation reason | 1–4,096 bytes; non-whitespace, trimmed; only LF and TAB permitted among control characters |
| environment | at most 128 ordered pairs; nonempty key at most 256 bytes, value 0–4,096 bytes; neither contains NUL; preserve duplicates/order |
| engine arguments | at most 128 entries, each 0–4,096 bytes, no NUL; preserve order and empty arguments |
| duration | integral seconds 1–604,800; `Some(Duration)` required, subsecond remainder must be zero |
| memory and CPUs | positive, respectively at most `i64::MAX` and `u32::MAX`; compare recorded values, do not resolve replacements |
| edges | null or 0–`i64::MAX`, matching SQLite's retained integer range |
| seed | null or full u64; serialize as a decimal string in presentation DTOs to avoid JavaScript integer loss; durable JSON uses the typed u64 |
| list limit | required integer 1–100; no silent clamp or implicit default |
| timestamps | UTC RFC 3339 with exactly nine fractional digits and `Z`, years 0001–9999; valid calendar values, no client-generated mutation times |
| UUIDs | lowercase canonical hyphenated text, non-nil; experiment IDs are v4; existing referenced UUIDs need not be v4 |
| limitations | sorted unique stable enum codes, at most 16; no arbitrary free-text evidence |

Views must likewise encode edge counts, edge deltas, and other potentially
unsafe JavaScript integers as decimal strings; bounded duration/CPU values can
remain numbers. Typed Rust fields remain integers. Environment values may be
sensitive: do not log evidence or request bodies, and preserve existing public
response redaction for network clients; explicitly redact every environment
value in public JSON rather than depending on secret-name heuristics. Service
returns comparison verdicts so the browser never needs those values to compare.
Redaction is presentation only and never
changes persisted or compared values. Render strings as text, never HTML.

At create, canonicalize the supplied project using existing service identity
resolution and validate baseline engine/duration via existing fuzzing policy
`effective_fuzzing_settings()?.resolve(Some(engine), Some(duration_secs))`.
Require the resolved duration to equal the request and baseline duration. Use
its admission verdict; do not replace baseline memory/CPU settings with current
policy values. The storage ceiling mirrors the existing seven-day hard ceiling;
the deployment's configured maximum may be lower. Attachment/get/list/cancel
use recorded settings, not today's execution policy: a policy change must not
hide a completed attempt. Actual execution independently checks current policy.

Malformed persisted JSON, unknown versions/enums/fields, omitted nullable keys,
invalid scalar values, duplicate JSON object keys, invalid digest/image syntax,
wrong state combinations, and mismatched relational/JSON identity are errors on
both reads and writes. Do not treat a damaged row as absence. Validate durable
foreign data, not impossible variants of already typed same-process values.

## 4. Eligibility and build-input provenance

Both baseline and result must be `RunKind::Campaign` and terminal `Done`,
`Failed`, or `Cancelled`, with `started_at <= ended_at`. Baseline end must be
at or before experiment creation. Result UUID must differ from baseline, and
`result.started_at > experiment.created_at`; also require result end at or
before attachment time. The existing start timestamp records allocation, not
proof of the first engine instruction. These comparisons deliberately require
a run allocated after preparation. Equal timestamps fail the strict later-run
rule. Service-clock reversal fails with `invalid_chronology`, never clamps time.

Require config, matching run/config/harness engine and sanitizer, an existing
harness and target owned by the canonical project, a `harness_rev` equal to
the SHA-256 of the exact stored harness source, and all required identities
in section 3. Target ID is the identity; symbol alone cannot disambiguate two
same-named functions in different files. A free-text goal names the operator's
intent and is not discovery or proof that such a function exists.

A present build-input snapshot retains every Phase 6 field: `harness_id`,
`project_root`, nullable `profile_sha256`, nullable `compile_database_sha256`,
`compile_flags_sha256`, `sandbox_image_id`, `build_input_sha256`, `created_at`.
Require its harness/project to match the run's resolved owner and its capture
time at or before run start. Configured profile evidence requires a database
digest. Parse `sandbox_image_id` as `ImmutableImageReference`, not prefix-only
text; its digest must equal the digest in typed `sandbox_rev`. Recompute the
combined input digest using the exact Phase 6 schema-1 field order and compact
JSON encoding (`schema_version`, optional profile, optional database, flags,
image). Read-only digest checks hash retained metadata or retained source only. Reuse/extract
the Phase 6 digest definition rather than defining a second encoding. No source
files, database files, flags, or images are re-resolved during experiments.

Null profile/database values in a present input row are known absence, including
Rust with a digest of an actually empty ordered flags vector. A missing entire
row is `legacy_build_inputs_unavailable`, not evidence of empty flags or an
unconfigured historical project. Current profile absence cannot prove historical
absence. If either or both rows are missing, use the explicit legacy evidence case:
record `build_comparison = unavailable_legacy`, retain an otherwise matching
attempt, and suppress edge comparison. Snapshot each side exactly, including
mixed presence. This permits refinement of a historical harness into a newly
compiled Phase 6 harness; refusing mixed presence would make that prepared
investigation impossible to complete through the normal compile workflow. It
does not establish preserved build setup: label the comparison inconclusive.
Both present with different profile/database/flags/image/combined digest are
refused as `different_build_inputs`, even if source digests match. Configured
present evidence never falls back to the legacy case on parse/lookup errors.
Existing configured execution still requires a matching input row; experiment
retention does not relax admission or authorize a legacy harness.

Migration 0032's `HarnessBuildContextRecord` records provider-visible configured
context before generation. It is neither a harness compile-input replacement
nor run-scoped function coverage. It is not read or copied by this subsystem.

## 5. Exact comparison and claim limits

Compare two captured snapshots using this exhaustive matrix. All equality is
exact typed/content equality, including ordered environment pairs. No
whole-`FuzzRunConfig` equality or current workspace check is used.

| Field | `grow_corpus` | `refine_harness` |
| --- | --- | --- |
| canonical project, target ID, engine | equal | equal |
| source revision and typed sandbox identity | equal | equal |
| sanitizer, requested duration, memory, CPUs | equal | equal |
| environment pairs, ordered engine args, retained seed option | equal | equal |
| profile/database/flags/image/combined build digests | equal when both captured | equal when both captured |
| harness source digest | equal | may change |
| executable digest | equal | may change with harness source |
| corpus content digest | may change | equal |
| harness UUID and input capture timestamp | retain, do not compare | retain, do not compare |
| corpus path, composite context digest, replay parent UUID | retain, do not compare | retain, do not compare |
| run UUID, times, terminal status, edges | record observations; not setup equality | record observations; not setup equality |

A changed corpus digest is the only intended input change for `grow_corpus`.
A changed harness source digest, with its compiled artifact, is the only
intended input change for `refine_harness`. Refinement with equal source but a
different executable is refused as `unexpected_binary_change`; binary bytes
alone are not evidence of source refinement. Refinement with changed source and
equal binary is retained as source changed; optimization may erase a source
edit. Captured build UUID/time changes alone are not build-configuration changes.

Equal intended digests are accepted as `input_change = no_observed_input_change`.
Otherwise report exactly `corpus_changed` or `harness_source_changed`. Do not
require a change to preserve an ineffective attempt. Any disallowed setting,
owner, or chronology change refuses attachment and leaves the prepared row
untouched. Missing required setup refuses preparation/attachment. The only
missing-setup exceptions are absent build-input evidence on either side and retained seed
absence as explicitly described here; missing edges never refuse an otherwise
matching attempt.

`build_comparison` is `matched | unavailable_legacy`. `target_entry` is always
`{status: unavailable, reason_code: no_exact_run_scoped_function_coverage}`.
Never call `coverage_functions`, `coverage_summary`, or blocker exploration
inside experiment operations: they can calculate from a mutable workspace.
Aggregate edge counts cannot establish entry into the goal function and never
verify the hypothesis or attribute a gain to the intervention.

`edge_comparison` is a strict tagged value: either
`{status: observed, baseline_edges, result_edges, delta}` or
`{status: unavailable, reason_code}`. With matched captured build inputs and
both edge counts, `delta = result - baseline` as a signed i64; zero baseline
is valid, and no percentage is reported. Counts reflect the same adapter's
recorded peak metric. Even for changed harness instrumentation they are only
a difference in recorded totals, not a difference between mapped target edges.
Unavailable reason precedence is `legacy_build_inputs_unavailable`, then
`baseline_edges_unavailable`, then `result_edges_unavailable`. When both edge
counts are missing, use the baseline reason and retain both limitation codes.
These are the only unavailable edge-reason values. Retain all limitations
independently.

Sorted unique limitation codes are drawn from exactly:
`aggregate_edges_not_function_entry`, `no_observed_input_change`,
`legacy_build_inputs_unavailable`, `baseline_failed`, `baseline_cancelled`,
`result_failed`, `result_cancelled`, `baseline_edges_unavailable`,
`result_edges_unavailable`, `random_seed_unrecorded`,
`engine_ignores_retained_seed`, `harness_instrumentation_may_differ`.
The aggregate-edge limitation is always present. Seed null must match null and
adds `random_seed_unrecorded`; Some versus None is a mismatch. Equal Some(seed)
on honggfuzz adds `engine_ignores_retained_seed`, because its current adapter
ignores the retained seed. Equal seeds on other adapters do not prove causality.
Changed harness source adds `harness_instrumentation_may_differ`.

A completed experiment means a result was attached, even when its run failed,
was cancelled, had no input change, or lacks an edge measurement. UI displays
those independent facts. There is no success/verified hypothesis boolean.

## 6. Lifecycle, concurrency, and errors

| Existing state | Requested action | Result |
| --- | --- | --- |
| absent ID | get/complete/cancel | not found; never creates a record |
| prepared | complete with valid later result | atomically completed |
| prepared | cancel with valid reason | atomically cancelled |
| prepared | invalid result/reason | error, every field unchanged |
| completed | repeat same result ID and exact retained result payload | return original row unchanged |
| cancelled | repeat exact cancellation reason | return original row unchanged |
| terminal | differing result, differing reason, or other terminal action | conflict, unchanged |

Creation uses `created_at = updated_at`; terminal fields are null. A successful
terminal transition sets `updated_at = ended_at >= created_at`. Completed
requires result ID/evidence and no reason; cancelled requires reason and no
result ID/evidence. Completed end must also be at or after result run end.
No edits to goal, hypothesis, budget, baseline, or any terminal field are exposed.

Every writing transaction reserves SQLite's writer before validation reads
(`BEGIN IMMEDIATE`). Use `UPDATE ... WHERE id = ? AND status = 'prepared'` and
require one row. Zero affected rows load the strict record and apply the retry
matrix. Competing completion/cancellation writers cannot both win. Never
`REPLACE`/upsert over a retained proposal or terminal row. SQL triggers protect
proposal fields, forbid duplicate-ID inserts, and reject terminal updates.

Service complete retry loads the existing record before generating a new
attachment timestamp or refreshing the result snapshot. Same ID means returning
the existing exact payload; it never rereads mutable workspace evidence to
rewrite history. A direct Store retry supplies the same evidence/reason; a new
candidate end time is ignored on an exact retry, preserving the original end.
Different supplied result evidence is conflict even for the same result UUID.
On first transition, Store verifies the supplied snapshot against the current
retained source rows within the transaction. No automatic transition occurs on
restart: prepared is a durable idle state, and cancellation has no compensation.

Stable error codes: `feature_unavailable`, `storage_unavailable`, `storage_error`,
`not_found`, `invalid_request`, `invalid_project_path`, `project_not_authorized`,
`invalid_baseline`, `invalid_result`, `missing_setup_evidence`,
`invalid_chronology`, `different_project`, `different_target`,
`different_engine`, `different_source`, `different_sandbox`,
`different_run_settings`, `different_build_inputs`,
`different_harness`, `different_corpus`, `unexpected_binary_change`,
`terminal_conflict`, `source_evidence_changed`, `run_retained_by_experiment`.
Errors identify the differing field using a bounded code, not secret environment
values. Missing configured storage is an error for every operation, including
list; an absent store never returns a fabricated empty history.

## 7. Storage, reference protection, and cleanup

Allocate **0033_coverage_experiments.sql** after actual Phase 6 migrations 0031
and 0032. [Database Schema](../standards/DATABASE_SCHEMA.md#coverage_experiments)
is authoritative for columns/checks/indexes. No existing migration is edited.
Migrations, typed reads/writes, and reference protection are unconditional in
`hf-storage`, including service feature-off builds.

Baseline and result reference `runs(id) ON DELETE RESTRICT`; experiments retain
runs in prepared and both terminal states. The direct `Store::delete_run` and
`clear_all_runs` reserve the writer, query experiment references before deleting
any crashes or runs, and return `run_retained_by_experiment` with run UUID,
experiment UUID and role. The same helper feeds the service's retained-run guard
before resolving/removing evidence directories. Preserve existing active-run
and harness-qualification checks. A race after the service precheck is caught
by Store and returns the same precise refusal; no filesystem deletion occurs.
The FK is the last protection for alternate SQL paths, not the only check.

Failed deletion/clear rolls back every row, including crashes and experiment
history. `clear_all_runs` does not remove experiments to make deletion succeed.
`Store::delete_project` explicitly deletes experiments whose canonical project
matches before build-input/harness/crash/run/target cleanup, in the same writer
transaction. It preserves other projects. Unexpected cross-project references
cause rollback rather than deleting another project's experiment. The
experiment deletion is keyed directly by project even if no targets remain.
`clear_knowledge` deletes all experiments first, then the existing ordered
knowledge rows; project build profiles and project settings remain configuration.
Service retains existing workspace cleanup locking and removes project files
only after successful storage cleanup. No experiment-specific artifact directory
or filesystem cleanup is introduced.

## 8. Features, transports, and GUI

`hf-service` adds independent `coverage-experiments = []`, in its default product
feature list. `hf-web` and Tauri forward to `hf-service/coverage-experiments`;
`hf-cli` forwards to both service and web through its explicit Cargo feature
forwarding. All four product default feature lists enable it.
Service standalone `--no-default-features --features coverage-experiments`
requires neither `change-aware` nor `coverage-blockers`; do not reuse their
comparison or proposal types. No new CLI command is required. Storage stays
unconditional. Feature-off REST retains all five operations as authorized stubs,
returning HTTP 501 with exactly
`{"code":"feature_unavailable","error":"coverage experiments are not included in this application build"}`.
Registered Tauri stubs return the same stable code/message after native scope
validation. No capability endpoint or new permission subsystem is introduced.
GUI maps both transports to the same English/Chinese unavailable explanation and
disables preparation/attachment/cancellation controls without hiding storage
deletion refusals. A 404 remains a missing ID; it is never interpreted as proof
that the feature is disabled.

REST routes (relative to the existing router base): POST and GET
`/coverage/experiments`, GET `/coverage/experiments/{id}`, POST
`/coverage/experiments/{id}/complete`, POST
`/coverage/experiments/{id}/cancel`. GET list carries project/target/limit and
cursor query fields. Tauri commands are `coverage_experiment_create`,
`coverage_experiment_get`, `coverage_experiment_list`,
`coverage_experiment_complete`, and `coverage_experiment_cancel`, with matching
request DTOs. Requests are at most 16,384 bytes before JSON deserialization.
Desktop experiment commands alone send `TextEncoder(JSON.stringify(args))` as
`Uint8Array`. Create/list carry their service request DTO directly; get uses
`{id, scope}`, and complete/cancel use `{id, request}`. Native handlers accept
only raw bodies, reject framework-parsed JSON bodies, and check the 16,384-byte
limit before application DTO deserialization. IDs remain text until the shared
strict experiment ID parser. Other desktop commands retain their existing IPC
arguments. Oversized native requests return `invalid_request`; REST returns 413.
This does not prevent Tauri framework parsing of JSON sent by other callers.

Use existing structured error translation/redaction; domain mismatch is 422,
conflict 409, not found 404, authorization 403, malformed request 400, oversized
body 413, storage failure 500, and authorized feature-unavailable response 501.
No response returns raw debug errors.

REST uses existing `AppState::approve_project` for create/list. ID get/complete/
cancel resolves `coverage_experiment_owner(id)` first, authorizes its project,
then returns or mutates the record. Completion additionally authorizes the
result's `run_project(id)` before reading its full evidence. Never authorize a
caller-supplied project and then operate on an unrelated ID. Existing root
policy refuses unavailable project directories; do not weaken it for history.
Native Tauri retains its existing trusted-local access model: current desktop
state has no configured root allowlist. Phase 7 adds no desktop root-policy
configuration or permission subsystem. Native get/complete/cancel carry selected
project and target in `CoverageExperimentScope`; create/list carry their project
and applicable target fields. Service canonicalizes that scope and requires it
to match the stored owner before exposing evidence or mutating a record. REST
uses the same scoped service APIs in addition to its configured-root checks;
GET by ID supplies project/target query fields. Owner lookup returns only the
canonical project and target UUID needed for authorization and scope validation.
UI-selected scope never replaces the persisted owner as authority. This explicit split follows existing REST and
trusted-local desktop access models.

The request/scope/owner/error DTOs and the two access-only service methods above
remain compiled with `coverage-experiments` off. The unconditional service free
function `validate_coverage_experiment_project(&Path) -> Result<PathBuf,
CoverageExperimentError>` applies existing filesystem project identity resolution
for native create/list stubs without a selected experiment ID. It is access-only:
canonicalization reads filesystem identity, but performs no mutation, baseline or
history lookup, policy admission, or lifecycle execution. Transports reuse this
function instead of implementing filesystem normalization. Store exposes unconditional
`coverage_experiment_owner(id) -> Result<Option<CoverageExperimentOwnerRecord>, StorageError>`;
the record contains only canonical `project_root: String` and `target_id: Uuid`.
Its strict query selects only `project_root, target_id` by ID; validate their
canonical syntax without loading evidence JSON or executing the experiment
lifecycle. Service translates absent owner to `not_found` and storage failures
normally. `validate_coverage_experiment_scope(id, scope, result_run_id)`
canonicalizes selected project, compares stored owner project/target, and, when
a result ID is supplied, uses existing strict run/harness target resolution to
require its project/target to match. It performs no setup comparison, coverage
calculation, or lifecycle mutation. The same access-only methods serve enabled
operations and disabled stubs; do not enable another optional feature to obtain
them. REST's existing `AppState::approve_project` wrapper must be exposed
independently of its current `harness-work-order` cfg (or call its existing
security helper directly), including no-default builds with experiments off.

Disabled handlers parse the same bounded requests and preserve access-error
precedence. Create/list first authorize the selected project with the existing
root policy; since no experiment exists/is selected, they do not validate
baseline eligibility or load experiment history. Get/complete/cancel first load
the experiment owner, authorize its canonical project, and validate selected
project/target scope. Complete additionally resolves and authorizes the result's
`run_project` before passing its ID to scope validation. Native stubs apply the
same selected-scope checks under the existing trusted-local model, without REST's
root allowlist. Missing IDs, denied roots, scope mismatch and storage failures
retain their normal errors; only an authorized, matching request receives
`feature_unavailable`. Stubs never call enabled create/get/list/complete/cancel,
provider/runtime/discovery/image/coverage operations, or write/delete any row.

The actual HTTP transport must preserve the structured 501 code/message instead
of reducing it to a generic fetch error; the GUI uses that code, paired with the
native error code, to show the same translated unavailable state. Do not show an
empty history or missing-record explanation for 501, and do not hide an ordinary
404/403/storage error as feature absence. Existing asynchronous scope invalidation
also applies to late unavailable responses.

Extend existing `CorpusView` / `CoverageBlockerPanel`, with experiment preparation
and history available even when blocker suggestions are disabled. Use existing
retained run/target inventories for the baseline picker; no exploration call is
needed. Existing run history additionally exposes nullable typed `target_id` and
`requested_duration_secs` from its retained harness/config. Requested duration
is distinct from existing elapsed `duration_secs`; missing config stays null.
Review items and run history additionally expose nullable service-owned
`target_selector`, the complete relative-file-qualified target identity alongside
the display symbol. Qualified desktop selections match that exact value; bare
selections retain their existing symbol filter and explicit duplicate-UUID choice.
Selector formatting is shared with retained replay/closeout resolution.

A selected terminal campaign supplies the exact target UUID and requested budget.
When one symbol has several retained target IDs, the operator selects the ID
explicitly before viewing scoped history. A selected blocker may prefill kind/function; the operator reviews and
edits them and writes the hypothesis. Show baseline status, duration, unavailable
evidence and limits. Prepare persists first; only then offer explicit navigation
to Corpus for growth or Harness for refinement. For a baseline with a retained
seed, show the exact command `oxfuzz run . --replay <baseline UUID>` using the
same oxfuzz configuration and database as the app. The required positional `.`
is ignored by replay, which resolves the original project from the retained run;
the project must remain available. Existing replay and closeout share exact
retained workspace-selector resolution described in [Run Closeout](run-closeout-design.md),
preserving both ordinary bare-symbol and imported file-qualified workspaces.
Replay uses the current promoted harness and
corpus under current policy; all other compared settings must remain unchanged.
Ordinary Run derives a new seed and cannot provide a matching experiment result.
A legacy baseline with no retained seed cannot be recreated by replay; direct
the operator to start a new campaign and prepare against its recorded seed.
There is no new REST/native replay capability, automatic execution, or relaxed
seed comparison. No navigation handler invokes an action. Preserve experiment ID when returning. The GUI stores only the selected ID in a
local preference keyed by canonical project and target UUID, then reloads its
record through the scoped service read. Preference failures are visible; this
pointer never substitutes for the durable record.

Reopen via bounded history. For a prepared record, pick a later Done/Failed/
Cancelled campaign and explicitly Attach result, or enter a reason and Cancel
experiment. A mismatched attachment displays the service refusal and keeps the
form/prepared record. Terminal views show baseline/result statuses, intended
input difference or no observed input change, build-input comparison, missing
measurements, descriptive delta and function-entry unavailability. Failed and
cancelled runs are never labeled successful experiments.

Key asynchronous state by canonical project, target ID, experiment ID, and a
request-generation counter. Clear selection/form/evidence/error state on project
or target switch; invalidate pending load/save callbacks. A late successful
prepare may remain stored under its original project, but cannot update another
project's UI or navigate it. Reopening that project's history recovers the record.
Apply this rule to list/get/baseline/result loads and complete/cancel responses.
English and Chinese translation keys are paired for all statuses, controls,
errors, limits, and empty/feature-unavailable states; transport codes are stable.

## 9. Decisions and verification handoff

The historical preflight's Done-only baseline, migration 0030, and mandatory
changed corpus/harness digest are superseded: terminal Campaign is the baseline
rule, 0033 is next, and no-op attempts are retained. Environment/argv/seed and
Phase 6 build inputs are required comparison dimensions. Exact whole-config
comparison is rejected because harness IDs/corpus paths may differ without a
content change. Change-aware comparison is rejected because it requires changed
source and another feature. Current workspace coverage is rejected as historical
function evidence. Legacy build absence, including mixed absent/captured inputs
after refinement, is retained with no edge comparison rather than silently
proving build equality. Setup mismatches are refused;
measurement absence and unsuccessful run outcomes remain evidence.

Before implementation, parent reviews this design. The desktop access split
above is the parent-approved scope; no new allowlist is required. Storage
implementation starts with failing tests for strict
schema/read/write validation, snapshot identity and chronology, exact retries,
concurrent terminal writers, FK protection, deletion rollback, and project/
knowledge cleanup. Service tests cover every comparison dimension, terminal
baseline/result statuses, no-op attempts, legacy/mixed/captured build cases,
policy duration validation, seed limitations, chronology, and zero calls to
provider/runtime/discovery/coverage/refinement/promotion. Transport tests deny
out-of-root path and ID requests before evidence/mutation; GUI tests cover
prepare-before-navigation, reopen, failed/cancelled attachment, cancellation,
claim limits, and delayed responses across project switches. Check standalone
service feature and feature-off storage retention. In a no-default REST build
with both experiments and harness-work-order disabled, test all five registered
stubs: authorized valid scopes receive the exact 501 JSON; out-of-root experiment
and result IDs, wrong selected project/target, missing IDs, malformed/oversized
requests, and storage failures preserve their errors. Assert no lifecycle writes
and zero provider/runtime/coverage calls. GUI tests must exercise the actual HTTP
transport mapping of the 501 response and native unavailable response into the
same translated disabled state, distinguishing 404/403/storage errors and
ignoring late feature-off responses after project switches. Run repository-required
quality gates for implementation changes; design-only verification uses diff,
reference checks and requirement self-review.

## Run History comparison inspection

The existing two-run history view requests a service-owned assessment of its
selected baseline and result. Completed campaign status and retained setup keys
establish whether the target, engine, duration, memory/CPU settings, sanitizer,
starting corpus, environment, arguments and captured context match. A missing
setup is reported as unavailable; mismatched setup is reported separately.

Raw edge totals are directly compared only when both runs also retain the same
exact executable SHA-256 and coverage totals. Changed executables can change
instrumented edge identities, so matching settings alone do not justify an edge
delta. The response identifies harness/executable changes independently and
returns the signed delta as a decimal string, preserving the full integer range
through JavaScript. Random seeds can still affect measurements; a delta is an
observation, not evidence of correctness or exploitability.

HTTP authorizes each retained run's project before requesting the assessment.
Desktop IPC delegates to the same service. Presentation renders its reason,
loads by exact selected IDs, ignores superseded replies and keeps history usable
when comparison is unavailable. Existing experiment lifecycle and approval
requirements remain owned by their operations. Allocation evidence uses the
same service measurement assessment for selecting comparable retained runs.
