# ClusterFuzzLite Removal Design

**Status:** Approved for implementation planning

**Decision date:** 2026-08-11

**Risk tier:** High -- shared engine contracts, persistence, scheduling, and all presentation surfaces

## 1. Purpose

Remove ClusterFuzzLite from oxfuzz completely as an active fuzzing engine. The supported engine set becomes exactly:

- AFL++
- honggfuzz
- libFuzzer
- syzkaller

This is an integrity release, not an engine replacement release. It removes an adapter that oxfuzz cannot execute correctly in its normal run layout while preserving historical evidence and rejecting legacy configuration explicitly.

## 2. Problem Statement

The current ClusterFuzzLite integration presents a readiness and execution contract that oxfuzz does not actually satisfy:

- runtime probing treats `python3` as sufficient engine readiness;
- the adapter invokes `python3 infra/helper.py`;
- the runtime image does not provide the OSS-Fuzz helper project layout;
- a normal oxfuzz run stages a harness under its own run workspace, not an OSS-Fuzz project checkout;
- the adapter derives its project name from that incompatible staged path.

The result is a selectable engine that can be reported ready but cannot run through the supported workflow. Keeping it undermines fail-closed engine selection and makes readiness misleading.

## 3. Goals

1. Expose only the four genuinely supported engines in core types, configuration, runtime readiness, services, APIs, CLI, desktop UI, prompts, and documentation.
2. Remove ClusterFuzzLite-specific implementation code and tests rather than leaving a dormant adapter or feature flag.
3. Preserve existing ClusterFuzzLite database and scheduler evidence without relabelling it as another engine.
4. Reject retired names and aliases with an actionable error; never silently fall back to libFuzzer or another engine.
5. Prevent legacy data from being replayed, promoted, scheduled, or dispatched.
6. Add a repository guard against accidentally restoring an active ClusterFuzzLite integration.

## 4. Non-Goals

This change does not:

- add native Go fuzzing;
- add FuzzTest, Centipede, LibAFL, or another engine;
- change the behavior of AFL++, honggfuzz, libFuzzer, or syzkaller;
- run a generated harness or fuzzer on the host;
- perform the dependency-health work identified during the repository audit;
- delete user corpus, crash, log, build, or other filesystem artifacts;
- undertake unrelated refactoring.

Native Go fuzzing and dependency health will receive separate designs and implementation plans. FuzzTest remains a later evaluation candidate; standalone Centipede and LibAFL are not part of the near-term engine set.

## 5. Approaches Considered

### 5.1 Staged hard removal with evidence archival -- selected

Remove the active engine across every layer, migrate historical records into immutable evidence storage, quarantine file-backed schedules, and reject retired identifiers at boundaries. This gives users an honest engine list while retaining provenance.

### 5.2 Compatibility tombstone in `EngineKind` -- rejected

Keeping a hidden enum variant would simplify deserialization of old records, but the retired engine would continue to infect exhaustive matches, capability logic, API schemas, and future maintenance. It would not be complete removal.

### 5.3 Relabel historical records as libFuzzer -- rejected

ClusterFuzzLite may ultimately drive libFuzzer, but its helper, build layout, invocation, and operational provenance are distinct. Relabelling would falsify evidence and could make invalid runs appear replayable.

### 5.4 Remove and replace in one release -- rejected

Adding Go fuzzing or another engine at the same time would mix removal correctness with a new execution and sandboxing contract. Separate releases make failures attributable and verification measurable.

## 6. Active Engine Contract

`EngineKind` contains exactly four variants: `AflPlusPlus`, `Honggfuzz`, `LibFuzzer`, and `Syzkaller`. Canonical wire identifiers remain `afl++`, `honggfuzz`, `libfuzzer`, and `syzkaller`.

All exhaustive engine behavior is updated to that set, including:

- language compatibility and capability reporting;
- adapter registration and runner dispatch;
- dictionary, seed, crash-ingest, minimization, and coverage behavior;
- harness generation and promotion validation;
- scheduling, campaign validation, replay, and service advice;
- runtime binary probing and system readiness;
- default and example configuration;
- REST payloads, CLI output, Tauri commands, frontend types, settings, status, help, and translations;
- prompts, bundled agent configuration, architecture documents, standards, and guides.

Runtime readiness probes only the actual executables required by the four engines: `clang` or the existing libFuzzer toolchain probe, `afl-fuzz`, `honggfuzz`, and `syz-manager`. Python availability has no bearing on engine readiness.

## 7. Legacy Identifier Policy

The canonical retired identifier is `clusterfuzzlite`. The former aliases `cfl` and `cflite`, plus case-insensitive forms of those identifiers, are retired as well.

New parsing returns a specific retirement error for these identifiers, for example:

> fuzzing engine 'clusterfuzzlite' has been retired; choose one of: afl++, honggfuzz, libfuzzer, syzkaller

Unknown identifiers continue to receive the generic unknown-engine error. No retired identifier is accepted and converted to another `EngineKind`.

This error applies consistently to TOML configuration, CLI input, REST input, desktop settings, schedule creation or update, persisted active schedules, run replay, and any other engine-selection boundary.

## 8. Historical Data Preservation

### 8.1 SQLite migration

A forward-only storage migration creates an evidence-only archive for records whose engine is ClusterFuzzLite. The archive stores:

- record kind and original primary key;
- canonical retired engine identifier;
- the complete original row encoded as valid JSON;
- migration version and archival timestamp.

The archive has a unique key over record kind and original primary key, making migration retries idempotent. It has no repository methods that can promote, replay, schedule, or dispatch archived records.

Within one SQLite transaction, the migration:

1. identifies legacy runs and harnesses by exact historical serialized engine values;
2. archives the complete run and harness rows;
3. archives harness approvals linked to those harnesses;
4. archives crashes linked to those runs;
5. identifies scheduler executions whose resolved `parameter_values.engine` is a retired identifier, archives them, and archives their linked one-time occurrences;
6. removes the archived dependent rows and then the retired active rows;
7. leaves all unrelated records unchanged.

If any archive insert, validation, or delete fails, the transaction rolls back and active data remains untouched. The migration never rewrites an engine value to `libfuzzer`.

Historical filesystem artifacts are not deleted or moved. Their paths remain preserved in the archived payload even if an artifact was already absent before migration.

### 8.2 File-backed schedule definitions

Schedule definitions live in an atomically rewritten JSON state file rather than SQLite. At service initialization, a one-time, idempotent retirement step separates campaign schedules whose `parameter_values.engine` is a retired identifier.

The step performs this order:

1. load and validate the bounded schedule file;
2. identify retired campaign schedules using parsed JSON fields, not substring matching;
3. atomically merge the exact original schedule objects into a sibling retired-schedule archive keyed by schedule ID;
4. after the file archive is durable, archive any SQLite scheduler executions and occurrences linked to those schedule IDs in an idempotent transaction;
5. only after both archives are durable, atomically rewrite the active schedule file without those schedules;
6. load the remaining schedules into the scheduler.

Before the first durable effect, the service validates every classified
retired schedule identity against the database proof domain: the manifest is
non-empty when a retirement is required, contains at most 4,096 unique IDs,
every ID is non-empty, NUL-free, and at most 512 UTF-8 bytes, and the exact
compact JSON encoding of the sorted identities is at most 2,097,152 bytes,
including quotes, commas, UTF-8, and JSON escaping. One shared validated
manifest owns both the canonical identities and those encoded bytes so service
preflight and SQLite persistence cannot apply different bounds. Invalid legacy
identities leave the active file and every archive, receipt, certificate,
proof, and tombstone unchanged; recovery is an offline rename or removal
followed by restart.

A crash after either archive is created but before active-file replacement is safe: the next initialization deduplicates both archives by record identity and repeats the remaining work. If the file or SQLite archive cannot be written, the active file is not changed and service initialization fails with the affected schedule IDs and a recovery path.

Retired schedule definitions are never automatically converted, enabled, or dispatched. The retired archive is evidence only.

A retired file-schedule ID is a permanent identity tombstone, not only an
engine-specific marker. After the one-time retirement is proven, an active,
created, updated, persisted, or dispatched schedule that reuses that ID fails
closed even if it names a supported engine. Recovery requires a new schedule
ID; changing the engine does not revive the retired identity. The service
checks the receipt and normalized database tombstones before registration and
dispatch so a persistence rejection cannot be logged and then followed by
execution.

One reconciliation result is the sole source of the runtime permanent-ID set.
Whenever SQLite persistence is available, every receipt phase reloads the
validated operation proof and normalized tombstones. A database-backed
non-empty receipt must match the exact operation ID, plan digest, and schedule
identity set; a database-backed empty receipt requires no proof at all. An
explicit no-database receipt is valid only while persistence remains
unconfigured. A configured-but-unavailable store never implies an empty proof
set. Missing, attached, or contradictory authorities fail before scheduler
registration or dispatch and do not mutate durable evidence. Receipt operation
IDs and database proofs use canonical lowercase RFC 4122 version-4 UUIDs.

All service instances that share `schedules.json` participate in the same
advisory-lock protocol. Online edits by older binaries, editors, scripts, or
other processes that ignore that lock are unsupported: stop every service
instance, make the edit offline, and restart. Service writes verify the exact
bytes they intended before accepting a new generation, but the protocol does
not claim atomic compare-and-swap against non-cooperating writers.

### 8.3 Unsupported legacy input after migration

Any retired record or schedule introduced after the migration, such as by restoring an old configuration or replacing a state file, fails closed with the retirement error. Reusing a permanently retired schedule ID with a supported engine also fails with recovery guidance to choose a new identity. It is not silently ignored when doing so could make the operator believe work was scheduled or replayed.

Receipt version 1 and the intermediate proof layouts were never distributed.
Receipt version 2, completion certificates, and migration 0025 therefore ship
as one unreleased migration unit; any other receipt version fails closed rather
than attempting an ambiguous upgrade.

## 9. Source and Surface Removal

The implementation deletes the ClusterFuzzLite adapter module and removes all engine-specific branches, registrations, fixtures, readiness flags, API properties, UI controls, help content, prompts, and active documentation.

References to the retired engine may remain only where they are required to:

- recognize and archive historical data;
- assert retired-identifier regression behavior;
- explain the removal in release history or migration documentation.

A repository test scans active source, configuration, documentation, and frontend files using an explicit allowlist for those historical locations. This prevents a future change from reintroducing a selectable engine, misleading readiness property, or stale user guidance.

## 10. Error Handling and Safety

- Engine selection remains explicit and fail-closed.
- No compatibility fallback chooses libFuzzer on the user's behalf.
- No archived object can enter active typed repositories that require `EngineKind` deserialization.
- A failed database migration leaves the database unchanged.
- A failed schedule archival leaves the active schedule file unchanged.
- The service reports record or schedule identifiers when legacy data blocks startup or an operation.
- No migration executes harnesses, parses crash artifacts outside the sandbox, or deletes workspace artifacts.
- Existing human approval and `hf-runtime` sandbox requirements remain unchanged for all four supported engines.

## 11. Test Strategy

Tests precede production changes and cover the removal at each boundary.

### 11.1 Core and configuration

- Assert the canonical engine set contains exactly four values.
- Assert every active canonical ID round-trips.
- Assert all retired identifiers produce the targeted retirement error.
- Assert unknown identifiers remain distinguishable from retired identifiers.
- Assert defaults and examples contain only the four active engines.

### 11.2 Persistence

- Seed a pre-migration database with retired runs, harnesses, approvals, crashes, scheduler executions, and one-time occurrences.
- Assert complete payload preservation and original identifiers in the archive.
- Assert no relabelling, no active retired rows, and no changes to unrelated rows.
- Assert migration retry behavior is idempotent.
- Force an archival failure and assert transaction rollback.
- Seed a mixed schedule file and assert retired definitions are archived exactly once while active schedules remain byte-equivalent at the data-model level.
- Force retired-schedule archive failure and assert the active file is unchanged.

### 11.3 Runtime and domain behavior

- Assert Python alone cannot make any engine ready.
- Assert registry, runner, harness, crash, coverage, scheduler, replay, and service behavior is exhaustive over four engines.
- Assert legacy replay, promotion, schedule, and dispatch attempts fail closed.

### 11.4 Presentation and documentation

- Assert the REST readiness payload no longer contains a ClusterFuzzLite property.
- Assert CLI and desktop engine choices contain exactly the four active identifiers.
- Assert English and Chinese UI content contain no active ClusterFuzzLite guidance.
- Assert the repository retirement guard passes and rejects a deliberately introduced active reference fixture.

No test launches a real fuzzer or generated harness on the host.

## 12. Completion Criteria

The removal is complete when:

1. only AFL++, honggfuzz, libFuzzer, and syzkaller are selectable or reported;
2. historical records and schedules are preserved as non-executable evidence;
3. retired aliases fail with the targeted error and never fall back;
4. no ClusterFuzzLite adapter, readiness flag, active configuration, or active user guidance remains;
5. the repository retirement guard permits only migration, regression, and release-history references;
6. all applicable repository quality gates pass in the mandated order:
   - `cargo fmt --all`
   - `cargo clippy --fix --allow-dirty --workspace -- -D warnings`
   - `cargo clippy --workspace -- -D warnings`
   - `cargo check --workspace`
   - `cargo doc --workspace --no-deps`
   - workspace Rust tests with the required output filter
   - no-default-features checks
   - dependency policy checks
   - script tests
   - frontend tests, build, and lint
7. a final source search finds the retired name only in the approved historical allowlist.
