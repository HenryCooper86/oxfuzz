# Semgrep Target Enrichment Design

Status: **approved design**. Owner: `hf-discovery` and `hf-service`.

## 1. Goal

Add an explicit, sandboxed Semgrep enrichment operation that uses the
`0xdea/semgrep-rules` C/C++ ruleset to improve fuzz-target prioritization.
Semgrep findings are advisory static-analysis signals. They are not confirmed
vulnerabilities, fuzzing crashes, or authority to generate, promote, build, or
execute a harness.

The first release is intentionally narrow:

- C and C++ targets only;
- explicit user opt-in;
- deterministic, capped score boosts;
- a pinned Semgrep CLI and pinned bundled rules snapshot;
- atomic success or failure;
- no user-supplied rules or arbitrary Semgrep arguments; and
- no CVE Binary Tool integration.

## 2. Approved Product Decisions

1. Normal target discovery does not run Semgrep.
2. The user opts in after or as part of C/C++ discovery.
3. Valid findings automatically affect prioritization through capped boosts.
4. The base discovery score remains immutable and visible.
5. The rules are bundled at a reviewed immutable commit; scans never fetch
   rules from the Semgrep Registry or the network.
6. Any execution, validation, mapping, or persistence error rejects the whole
   enrichment. Partial findings never affect ranking.
7. The implementation extends the existing discovery subsystem instead of
   introducing a generic static-analysis framework or agent-created tool.

## 3. Upstream Baseline

The initial sandbox build pins:

- Semgrep CLI `1.169.0`;
- `0xdea/semgrep-rules` commit
  `4d66ecf30bfb1809a984085f2c86a8c3915bfc71`; and
- the non-noisy C/C++ rules under `rules/c`.

The sandbox image records a deterministic SHA-256 tree digest of the installed
rules. The digest covers lexicographically ordered, length-prefixed
`(relative_path, file_bytes)` pairs for every regular file in `rules/c`. The
build fails if the checked-out commit differs, the complete local rules
configuration cannot be loaded and executed, the tested Semgrep version
differs, or the fixture scan does not produce the expected rule identifiers.
Semgrep CE `1.169.0`'s dedicated `scan --validate` path is not used because it
unconditionally fetches the registry-hosted `p/semgrep-rule-lints` pack.
Instead, the network-disabled fixed-wrapper scan validates the bundled
configuration by loading and executing every local rule against the fixed
fixtures.

Semgrep CE `1.169.0` omits `paths.skipped` from successful JSON when no path was
skipped. The strict parser treats only that omission as an empty collection.
An explicit non-empty skipped collection remains an incomplete-analysis
failure, and the normalized `paths.scanned` collection must exactly equal the
staged source manifest.

The Semgrep Community Edition executable is a separate process licensed under
LGPL-2.1. The `0xdea/semgrep-rules` content is MIT-licensed. Distribution
artifacts retain both notices and upstream source/revision references.

## 4. Architectural Ownership

### 4.1 `hf-core`

`SourceLocation` gains optional end coordinates:

```rust
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub end_col: Option<u32>,
}
```

Existing serialized inventories remain readable. Semgrep enrichment requires
complete spans; an older C/C++ inventory without end coordinates must be
rediscovered before enrichment.

No Semgrep-specific type enters `hf-core`.

### 4.2 `hf-discovery`

Behind the `semgrep-enrichment` feature, `hf-discovery` owns:

- strict parsing of the supported Semgrep JSON schema;
- normalized finding, severity, range, and fingerprint types;
- deterministic finding-to-candidate mapping;
- distinct-rule deduplication;
- pure score calculation; and
- the enriched-inventory overlay returned to `hf-service`.

This module accepts bytes and domain values. It does not launch a process,
access the network, stage files, mutate storage, or authorize another action.

### 4.3 `hf-service`

Behind its `semgrep-enrichment` feature, `hf-service` owns:

- operation admission, lifecycle, cancellation, and progress;
- canonical project validation and the workspace lease;
- bounded source snapshot creation;
- the typed Semgrep command and sandbox profile;
- invocation through `RuntimeAdapter`;
- bounded output loading and digesting;
- atomic storage transactions;
- stale-overlay checks; and
- presentation-safe DTOs.

All ranking consumers, including automatic campaign target selection, ask the
service for the effective inventory. Presentation clients do not join findings
to candidates or recalculate scores.

### 4.4 `hf-runtime`

`hf-runtime` remains the only execution boundary. Semgrep uses the existing
pinned oxfuzz sandbox image and a specialized hardened `SandboxOptions`
profile. There is no host fallback and no direct presentation-layer Docker or
Python invocation.

### 4.5 `hf-storage`

`hf-storage` persists operation history, normalized findings, per-candidate
score overlays, and complete provenance. A successful overlay is visible only
after one transaction commits all findings, scores, and the terminal operation
state.

### 4.6 Presentation

`hf-cli`, `hf-web`, and `hf-gui` call service operations and render service
DTOs. They contain no Semgrep command construction, path matching, scoring,
staleness, or safety logic.

## 5. Feature Boundary

`hf-discovery` defines the `semgrep-enrichment` feature. The corresponding
`hf-service` feature enables it and is enabled in normal product builds.
`--no-default-features` builds exclude the integration and its presentation
entrypoints.

Compile-time availability does not imply execution. No discovery, campaign,
agent, or schedule invokes Semgrep without an explicit enrichment request.

The initial release does not register Semgrep as an agent tool or scheduler
action. A future agent or scheduler entrypoint must pass a dedicated
`AnalyzeSource` guardrail action and require an explicit human decision.

## 6. Source Snapshot

The service scans the same canonical C/C++ source set used by discovery,
including supported header extensions. It honors the discovery ignore walker
and excludes `.git`, build artifacts, runtime workspaces, and ignored vendor
trees.

Before copying, the service requires every selected input to be a regular,
non-symlink file beneath the canonical project root. The snapshot preserves
only normalized relative paths and rejects path traversal, absolute relative
names, unstable metadata, or files that change while being copied.

Initial fixed bounds are:

- 25,000 source files;
- 2 MiB per source file;
- 512 MiB aggregate source bytes; and
- 4,096 bytes per normalized relative path.

Exceeding any limit fails the enrichment instead of silently scanning a partial
project. The snapshot is written to a unique operation directory below the
managed workspace, hashed as a lexicographically ordered sequence of
length-prefixed `(relative_path, file_bytes)` pairs, then mounted read-only.

The source digest is also the enrichment revision. Before service-owned ranking
uses an overlay, the service verifies the current eligible source set against
that digest. A mismatch marks the overlay stale and restores base-only ranking.
The historical scan remains queryable.

## 7. Sandbox Contract

The command schema is versioned independently from Semgrep. Schema version 1:

- invokes `semgrep scan`;
- loads only `/opt/oxfuzz/semgrep-rules/rules/c`;
- writes JSON to the operation output mount;
- disables metrics and autofix;
- does not log in or use registry configuration;
- supplies no tokens or credentials;
- scans only the staged `/work/source` directory; and
- accepts no caller-provided flags, environment, config, or rule paths.

The service requires `errors`, `paths`, and `paths.scanned`. It accepts
`paths.skipped` when the field is absent or explicitly empty because Semgrep CE
`1.169.0` omits the field on a no-skip success. A non-empty `errors` or
`paths.skipped`, a `paths.scanned` set that does not exactly equal the staged
manifest, parse failure, per-file timeout, or size-based skip is incomplete
analysis and rejects the whole enrichment.

The container has no network, drops every capability, sets
`no-new-privileges`, and receives:

- 2 CPUs;
- 4 GiB memory;
- 128 processes;
- a 10-minute wall-clock limit;
- a 64 MiB maximum output file; and
- only the read-only source mount plus one operation-owned writable output
  mount. The pinned rules remain read-only inside the image.

The normalized result is limited to 50,000 findings. Rule identifiers are
limited to 512 bytes and messages to 4,096 bytes. Any truncation, limit breach,
timeout, cancellation, missing output, or non-zero tool exit is a terminal
non-success.

## 8. Finding Contract

A normalized finding contains:

- a service-owned deterministic fingerprint;
- rule identifier;
- `Error`, `Warning`, or `Info` severity;
- bounded message;
- normalized project-relative path;
- start and end line/column;
- optional matched target id; and
- nominal severity weight.

The fingerprint is SHA-256 over a version byte followed by length-prefixed rule
id, severity, relative path, start/end coordinates, and message. It does not
trust or persist an upstream Semgrep fingerprint. Nominal weights remain
visible on individual findings, while candidate scoring deduplicates
`(candidate_id, rule_id)` before applying them.

Raw source snippets, metavariable captures, absolute host paths, login state,
and arbitrary upstream JSON are not persisted or returned.

Unknown severity values, missing required fields, invalid coordinates,
duplicate fingerprints with different content, absolute paths, parent
traversal, or paths absent from the staged manifest invalidate the entire scan.

## 9. Candidate Mapping

A finding is eligible for a score boost only when:

1. its normalized path exactly equals a candidate definition path;
2. the candidate belongs to the scanned C/C++ inventory revision; and
3. the finding start coordinate is contained by exactly one complete candidate
   source span.

Zero containing spans leaves the finding unmatched. More than one containing
span is ambiguous and also leaves it unmatched. Unmatched findings remain
visible at scan level but contribute no score.

One rule may contribute at most once to one candidate, regardless of how many
matching locations it reports. Deduplication uses `(candidate_id, rule_id)`;
findings remain individually retained by fingerprint.

## 10. Scoring

The weights are:

| Semgrep severity | Per-distinct-rule boost |
| --- | ---: |
| `Error` | `0.10` |
| `Warning` | `0.05` |
| `Info` | `0.01` |

For candidate `c`:

```text
semgrep_boost(c) =
    min(0.20, sum(weight(severity(rule))) for distinct matched rules)

effective_score(c) =
    min(1.0, base_score(c) + semgrep_boost(c))
```

If one rule somehow produces different severities for the same candidate, the
highest severity is used. Sorting uses effective score descending, then base
score descending, then relative file, symbol, and target UUID ascending. The
tie-break order makes repeated scans deterministic.

The base `TargetCandidate.fit_score` is never overwritten. A
`SemgrepTargetScore` overlay contains the base score observed at scan time,
boost, effective score, distinct matched-rule count, and scan id. An overlay
whose stored base score no longer equals the current candidate base score is
stale even if the source digest matches.

## 11. Operation Lifecycle

The service exposes start, status, cancel, and result operations. Start
validates feature availability, language, project identity, and the existence
of a persisted inventory, inserts a durable `running` operation, registers
cooperative cancellation, and returns its UUID without awaiting Semgrep.

Progress states are:

```text
staging -> scanning -> validating -> persisting -> done
                                             \-> failed
                                             \-> cancelled
```

Only `done`, `failed`, and `cancelled` are terminal. Process termination caused
by a timeout is `failed`; an explicit cooperative cancellation is `cancelled`.
The service retains a bounded, redacted failure code and message.

One project may have only one active Semgrep enrichment. A second request fails
busy. Workspace cleanup cannot overlap the operation because the service holds
the shared workspace lease from before the database insert and journal open
through terminal cleanup and journal close or abort. The admitted operation
also owns an exclusive, digest-keyed cross-process project lease for that same
interval. The workspace lease prevents startup recovery or whole-workspace
cleanup from classifying a live operation as interrupted; the project lease
preserves the one-active-operation rule after the database publication has
temporarily moved the row to `done` but before cleanup and journal closure are
durable. Admission rechecks recovery health after taking both leases and before
its first durable write. Both leases are transferred into the background
worker, rather than reacquired after spawning.

After nondurable preflight, admission runs in an owned service task and returns
its result through a one-shot response. Dropping the caller's start future
cannot cancel the durable admission section between reservation, staging-row
insert, journal `Begin`, and worker handoff. The owned task either returns an
admission error with its reservation and leases released, or durably begins the
journal and transfers the reservation and leases to the scan worker. It sends a
successful operation UUID only after that handoff.

The process-local operation registry distinguishes cancellable work from
finalizing work. Completion claims atomically move the reservation into
`finalizing`; cancellation is then inactive, but the reservation remains busy
until cleanup and terminal journal persistence finish. A database `done` row
whose successful journal close is not yet verifiable is exposed through the
status API as `persisting`, with an `IncompleteJournal` base-only result when
the historical result can be reconstructed. Only a closed `done` publication
is externally terminal `done`. Therefore a terminal success observed by a
client cannot later regress to `failed` because cleanup compensation ran.

Before starting background work, the service appends a synced recovery-journal
entry naming the operation and project. After validation, it syncs a
`ready_to_commit` entry containing the provenance and output digest before the
database publication transaction. After database publication, it durably
removes the exact staged artifacts and syncs their parent, then appends the
successful journal close. The journal remains `ready_to_commit` until cleanup
succeeds.

Persistent journal replay and transitions use a securely descriptor-opened
advisory lock file in the journal directory. The service takes its exclusive
cross-process lock around each complete replay/validate/read/append
transaction, including the first lifecycle replay. Journal construction opens
no filesystem object: it normalizes and retains the journal path only. The
first create/open/validate/replay filesystem access occurs from an operation
that already owns the shared workspace/project leases or from recovery after it
owns the exclusive workspace lease. Result-only reads may open existing
journal state but never create missing state. The fixed lock entry is not
interpreted as an operation journal. Compliant processes use this order
whenever multiple locks are needed:

```text
workspace lease -> project lease -> journal lock -> database transaction
```

Result-only journal reads take only the journal lock and never acquire an
earlier lock afterward. This serialization prevents competing processes from
both validating `ready_to_commit` and appending incompatible `close` and
`abort` records.

The journal has two different terminal outcomes. `close` is accepted only
after `ready_to_commit` and is the sole evidence of a successful publication.
`abort` is accepted from `open` or `ready_to_commit` only after the
failed/cancelled database transition or recovery compensation is durable and
the operation-owned staging directory is safely removed. It records a bounded
terminal category without fabricating publication provenance. An aborted
journal is no longer interrupted but never passes the successful-close check.

If cleanup fails after database publication, a compensation transaction
removes that scan's finding/score rows and marks the run `failed`. A close
append error is indeterminate because the close record may already be synced.
The current process marks recovery degraded and exposes only an
`IncompleteJournal` base-only view; it does not compensate solely because
`close` returned an error. On restart, a valid replayed close preserves the
successful publication, while a replayed ready state triggers compensation.
Startup recovery performs the same fail-closed repair for an interrupted
non-terminal, unclosed `ready_to_commit`, or already-failed/cancelled
operation whose abort was interrupted, then cleans only its validated
operation-owned staging directory and appends the terminal abort.
If compensation, cleanup, or abort cannot complete, the journal remains
interrupted and new starts fail closed so recovery can retry.

Startup recovery must first take the exclusive workspace recovery lease and
retain it through journal replay, database repair, descriptor-relative cleanup,
and terminal abort. If another process holds a shared operation lease, recovery
does not inspect or mutate journals, is deferred, and that container rejects
new Semgrep starts. Reads remain available. This is deliberately fail-closed:
absence of an exclusive recovery lease is not evidence that an open journal
belongs to a dead process.

Recovery cleanup treats descriptor-proven absence of the exact UUID child as
idempotent success, covering a crash after cleanup but before close or abort.
It still rejects a missing or ambiguous managed root, symlinked or replaced
ancestors, and every path that is not exactly
`workspace/semgrep/<operation-uuid>`.
An absent `semgrep` child beneath the validated managed workspace is also
idempotent absence for a failure that occurred before staging created it, but
only when `openat(workspace_fd, "semgrep", O_NOFOLLOW | O_DIRECTORY)` returns
`ENOENT` and a post-check proves that the workspace pathname still names the
opened workspace descriptor. After that post-check, cleanup performs a second
descriptor-relative `semgrep` lookup and succeeds only if it still returns
`ENOENT`; appearance of the parent or exact UUID child is an error. Recovery's
exclusive workspace lease excludes compliant creators. Live-operation cleanup
holds a shared lease so another project's operation may create the parent; the
second lookup detects that race and fails safely. All existing-parent and
exact-operation checks remain descriptor-relative through removal and parent
synchronization.

After successful cleanup and close, only the digests and normalized durable
records remain. Failed and cancelled
operations also remove staged artifacts after recording terminal state.

## 12. Atomic Persistence

The storage migration introduces:

### `semgrep_enrichment_runs`

- operation id;
- canonical project root and language;
- source SHA-256, nullable only while staging;
- sandbox image reference and resolved image SHA-256;
- Semgrep version;
- rules commit and rules tree SHA-256;
- command schema version;
- lifecycle state and timestamps;
- output SHA-256, nullable until validation succeeds;
- finding and matched-candidate counts;
- duration; and
- bounded redacted failure metadata.

A `done` row requires every provenance field, terminal timestamp, count, and
digest. A `failed` or `cancelled` row may lack values that its operation never
produced.

### `semgrep_findings`

- scan id and fingerprint;
- rule id, severity, and message;
- relative file and source range;
- nullable target id; and
- nominal severity weight.

### `semgrep_target_scores`

- scan id and target id;
- base score, boost, and effective score; and
- distinct matched-rule count.

The success transaction inserts every normalized finding and score, updates the
run to `done`, and selects it as the latest overlay for its project/language
revision. Any insert or update failure rolls back the entire transaction and a
separate compensation changes the run to `failed`. A `failed` or `cancelled`
run has no finding or score rows.

If the compensation write itself cannot be made durable, recovery leaves the
operation unclosed and repairs it on the next service startup. A result reader
accepts an overlay only when the database row is `done` and the recovery
journal has the successful close outcome; an abort is never sufficient. Thus
incomplete compensation cannot publish an overlay.

A missing, interrupted, aborted, corrupt, or otherwise unverifiable journal is
reported as `IncompleteJournal` for reads. Historical findings and the parent
operation remain readable, but the view uses base-only scores. Sticky journal
or recovery degradation still blocks every new start.

Historical reconstruction accepts an empty current same-language inventory.
An empty candidate set is a valid base mismatch, so the exact result retains
its normalized matched and unmatched findings, contains no current candidates,
and reports `StaleBase`. Scan admission still requires a non-empty persisted
inventory. If an unrelated reconstruction error prevents building the result,
the status endpoint returns the parent operation with `result: null` instead of
making its lifecycle unreadable.

Repeated successful scans never compound: every score is recomputed from the
current base inventory and the current scan's distinct rules.

## 13. Presentation Contract

The CLI adds an explicit `--semgrep` flag to `discover`:

```text
oxfuzz discover <project> --lang c --semgrep
```

The command performs normal discovery, starts enrichment, follows progress,
and prints the effective ranking. Omitting `--semgrep` preserves existing
behavior exactly. `--semgrep` with a non-C/C++ language fails validation before
an operation is inserted.

REST adds:

- `POST /semgrep/enrich` to start;
- `GET /semgrep/enrich/{operation_id}` for status/result; and
- `POST /semgrep/enrich/{operation_id}/cancel` to cancel.

Tauri exposes matching typed commands. The GUI shows an **Enrich with Semgrep**
action after C/C++ discovery and displays base score, Semgrep boost, effective
score, matched-rule count, operation state, and stale state.

Every surface labels results **Semgrep static-analysis signals** and does not
describe them as confirmed vulnerabilities or crashes.

## 14. Observability and Evidence

Every service operation has a tracing span keyed by operation id, project
identity digest, language, source digest, sandbox digest, rules digest, and
command schema. Logs never include source text, finding messages, absolute
paths, or Semgrep raw output.

Counters and durations cover staging, scan execution, validation, mapping,
persistence, findings by severity, matched/unmatched findings, boosted
candidates, cancellations, timeouts, stale overlays, and atomic rollbacks.

The scan provenance is sufficient to identify the exact source set, sandbox,
Semgrep binary, rules, command contract, and normalized output without claiming
that the advisory signal is verified fuzz evidence.

## 15. Failure Semantics

The following are terminal atomic failures:

- unsupported language or missing/span-incomplete inventory;
- unsafe, unstable, oversized, or excessive source input;
- sandbox unavailability, timeout, or non-zero exit;
- missing, oversized, malformed, or unsupported Semgrep JSON;
- unsafe or inconsistent finding content;
- finding-count or field-size limit breach;
- source revision change before commit;
- storage transaction failure; and
- workspace cleanup or forced-teardown failure that prevents safe completion.

No failure path changes candidate scores. The last valid matching overlay, if
one exists, remains historical but is not replaced by partial new state.

## 16. Testing Strategy

Implementation follows Red -> Green -> Refactor.

### Unit tests

- Parse valid Error/Warning/Info fixtures.
- Accept the real Semgrep `1.169.0` no-skip shape with omitted
  `paths.skipped`; reject malformed JSON, unknown severities, missing
  `paths`/`paths.scanned`, explicit non-empty skips, scanned-manifest mismatch,
  bad coordinates, unsafe paths, conflicting duplicate fingerprints, and
  excessive findings.
- Map only an exact file plus unique containing function span.
- Leave file-level and ambiguous findings unmatched.
- Deduplicate repeated `(candidate_id, rule_id)` matches.
- Prove all weights, the `0.20` boost cap, and the `1.0` effective ceiling.
- Prove stable tie-breaking and no repeated-scan compounding.
- Reject stale source and base-score revisions.

### Service and storage integration tests

- Use a recording `RuntimeAdapter`; never execute host Semgrep.
- Assert network isolation, hardening, resource limits, mount modes, local
  config path, and absence of caller-controlled flags.
- Cover asynchronous lifecycle, busy rejection, cancellation, timeout, and
  workspace lease behavior.
- Use real child processes and actual service admission to pause after journal
  `Begin` and before `Close`. At both points, prove bootstrap recovery defers,
  a second process cannot admit the same project, the database/journal/staging
  state remains untouched, and the admitted worker still owns both leases.
  Add mutation-sensitive pauses immediately after both leases are acquired but
  before the first durable write, and after `Close` but before lease release.
  At the first pause a competing process must be busy even though no active
  database row exists; at the second it must remain busy even though the
  database row is `done` and the journal is closed. Also prove close/abort
  journal transitions serialize.
- Abort a caller while the owned admission task is paused between the staging
  insert and journal `Begin`; prove the detached task completes journal/worker
  handoff and leaves no orphaned reservation or staging row.
- Prove source snapshot bounds and time-of-check/time-of-use detection.
- Race workspace replacement and `semgrep`-parent recreation against cleanup;
  only descriptor-proven stable absence is successful.
- Prove success publication is one transaction.
- Inject each persistence failure and prove no partial overlay exists.
- Prove a source mutation before commit causes atomic failure.
- Prove database `done` remains externally `persisting` until close, competing
  admission stays busy, and visible `done` never regresses to `failed`.
- Deterministically compensate between the status API's parent-row read and
  exact-result reconstruction; status must remain readable, return no
  inconsistent result, and converge to `failed` on the next read.
- Delete and reclassify every current same-language candidate and prove exact
  history remains readable as findings-preserving `StaleBase`.
- Prove feature-disabled builds reject presentation entrypoints.

### Presentation tests

- CLI parsing accepts `discover --semgrep` and rejects unsupported languages
  through the service.
- REST and Tauri transport service DTOs without recomputing scores.
- GUI rendering distinguishes base, boost, effective, stale, failed, and
  cancelled states.

### Sandbox release gate

A real container-only test:

1. asserts Semgrep `1.169.0`;
2. asserts rules commit
   `4d66ecf30bfb1809a984085f2c86a8c3915bfc71`;
3. validates the bundled rules by loading and executing the complete local
   configuration without the registry-dependent `scan --validate` path;
4. scans a fixed vulnerable and clean C fixture with networking disabled; and
5. accepts absent-or-empty `paths.skipped`, asserts that `paths.scanned` is
   exactly the two-file fixture manifest, asserts one expected vulnerable
   rule identifier, and rejects a finding from any rule in the clean fixture.

Normal unit, integration, and workspace tests do not run Semgrep.

## 17. Success Criteria

- Discovery without explicit opt-in produces the same candidates and ranking
  behavior as before.
- Identical source, inventory, sandbox, Semgrep, rules, and command schema
  produce identical normalized findings and effective ranking.
- No candidate receives more than `0.20` total Semgrep boost or exceeds an
  effective score of `1.0`.
- A source or base-score change prevents the overlay from affecting ranking.
- Any scan or persistence failure leaves all target scores unchanged.
- Automatic campaign target selection uses a valid effective ranking.
- No scan accesses the network, host execution, registry rules, credentials,
  arbitrary caller flags, or paths outside the managed workspace.
- All findings remain visibly advisory.
- All applicable repository quality gates pass cleanly.

## 18. Rejected Alternatives

- **Generic analyzer framework** -- unnecessary abstraction for one supported
  analyzer and ruleset.
- **Agent-created/dynamic Semgrep tool** -- weakens typed command, evidence,
  scoring, and service ownership.
- **Runtime registry download** -- breaks offline execution and reproducibility.
- **User-supplied rules in the first release** -- expands trust, validation,
  compatibility, and support scope.
- **Unbounded additive scoring** -- lets noisy rule counts dominate fuzzability.
- **Overwriting the base score** -- loses attribution and risks repeated-scan
  compounding.
- **Keeping partial output after failure** -- creates rankings with incomplete
  and potentially misleading evidence.
- **Postprocessing JSON in the scan wrapper** -- fabricating an empty
  `paths.skipped` field would add parsing and rewrite behavior to the fixed
  execution boundary, prevent the final Semgrep process from remaining the
  wrapper's `exec` target, and complicate PID 1 signal and cancellation
  semantics. The strict Rust parser owns the one documented compatibility
  default instead.
- **Fabricating `ready_to_commit` to close a failed operation** -- falsely
  claims validated publication provenance; a distinct terminal abort preserves
  recovery evidence without passing the successful-publication gate.
- **Immediately compensating every `close` error** -- an append can report an
  error after the close record is synced; current reads fail closed and restart
  replay reconciles the durable state instead of undoing an indeterminate
  success.
- **Treating a Semgrep match as a vulnerability** -- static patterns are
  research signals, not proof of exploitability.
