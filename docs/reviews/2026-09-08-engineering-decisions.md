# Daily-work engineering decisions

This record preserves every ruling captured across the eight daily-work phase
ledgers through the Phase 8 Task 3 Rust freeze. Entries follow phase and local
ledger order. Phases overlapped, so this is not a global timestamp ordering.
The entries are self-contained; retained ledger labels identify their original
provenance and are not required to understand the decisions.
This companion names the practical cost of each choice and the delivered design
or implementation area. Later final-review or publication rulings must be
appended before release.

## Phase 1: comparison claims

Delivered references: `docs/design/change-aware-pr-fuzzing-design.md`,
`docs/design/finding-proof-card-design.md`, and the Phase 1 implementation at
commit `55b73f6efbe948e8900bdf9dab43c9b925eeaf37`.

1. **Use the requested clean main checkout.** Work proceeded in the existing
   clean tree to preserve the prior assessment and avoid checkout churn
   Cost: a concurrent remote update would
   require integration before push and could force revalidation.
2. **Allow observational cross-revision labels without replay.** Verified fixes
   continue through Patch to Proof; the comparison view removes false causal
   claims without duplicating execution.
   Cost: introduction cannot be proven by this view and remains a future
   explicitly executed workflow.

## Phase 2: durable triage scope

Delivered references: `docs/design/finding-proof-card-design.md`,
`docs/design/triage-disposition-design.md`, and Phase 2 commit
`0b203b61c165e83a695056c84c4fe325bf102e7f`.

3. **Do not substitute latest-run reproduction for historical evidence.** The
   existing export stages the current workspace harness, so historical findings
   use an exact-evidence operation or show a precise unavailable reason
   Cost: some historical actions are disabled
   until exact retained inputs exist.
4. **Deliver both triage tasks as one phase with one shared-file owner.** Tests
   precede each increment; parent review and gates precede publication
   Cost: shared-file work is serialized and a
   defect can delay both related deliverables.
5. **Remove mount-time and summary-time triage/report effects.** Scan and report
   remain explicit; ID-based proof-card and issue-export authorization share a
   durable crash-owner resolver. Cost: the
   operator must initiate work that older mounts triggered automatically.
6. **Distinguish missing storage from an empty queue.** A missing persistent
   store is an explicit unavailable state, and expected-run report/publication
   admission is tested in the executing service.
   Cost: presentation code must handle a third state and cannot use an empty
   list as a fallback.

## Phase 5: Campaign Health and desktop lifecycle

Delivered references: `docs/design/campaign-health-design.md`, retained
telemetry in `hf-storage`, run admission in `hf-service`, and Phase 5 commit
`f1b7e154276f120f94d9a470b79d3bb04952b963` plus support
`3e958bbdca39021416b38ea4316038f13d67af1c`.

7. **Recover the whole-run mean from service cumulative telemetry.** A selected
   browser reads one owner-authorized snapshot after missed callbacks; it never
   labels a session subset as the whole-run mean.
   Cost: one additional bounded telemetry read and recovery path.
8. **Do not add unsequenced callbacks to cumulative telemetry.** A snapshot
   read coalesces a dirty follow-up rather than replaying callbacks whose
   inclusion cannot be known. Cost: a
   display may wait for the authoritative refresh instead of updating from an
   ambiguous local event.
9. **Recover selected scheduled runs through history, ownership, and telemetry.**
   Scheduled producers do not publish global progress/start events, so the UI
   shows no fabricated log. Cost: scheduled
   runs have less live detail than foreground runs.
10. **Page retained health events and compute summaries from complete distinct
    condition facts.** Keyset pages carry a bounded `next_cursor`; summary
    classification does not depend on a truncated newest-100 array
    Cost: every transport and client must
    implement cursor pagination.
11. **Correlate foreground admission with a request-scoped callback.** HTTP uses
    the start response and native IPC uses a channel from the service
    `on_started` callback so Stop receives the exact UUID
    Cost: a small adapter API extension
    and repeated Rust verification.
12. **Escalate incomplete frontend completion to a fresh implementer.** Three
    partial returns left lifecycle and recovery cases unfinished, so the frozen
    source was handed to a fresh worker.
    Cost: context and review had to be repeated; completed backend work stayed
    intact.
13. **Fix delayed CampaignCrashToaster registration within the App hierarchy.**
    The StrictMode fixture reproduced duplicate scheduled-crash notices, so the
    same frontend owner added an active-callback guard and immediate cleanup
    Cost: a small listener lifecycle
    change that required integration verification.

## Phase 6: build profiles and immutable inputs

Delivered references: `docs/design/build-doctor-design.md`,
`docs/design/harness-generation-design.md`, Phase 6 commit
`8e93d817c152fb271751b461052f12a86f0ec5ba`, and support commits
`ec3dd41e26a6ebfbcdab7104f752df05e83c2e0d` and
`e783de30210493222cdd4034f2bd1dd5be331365`.

14. **Stage the complete project and select the component with the sandbox
    workdir.** This preserves approved sibling paths that a component-only mount
    would hide (`phase-6-build-profiles/progress.md:38`). Cost: container path
    conventions are broader and may need adjustment on another runtime.
15. **Treat saved profiles as configuration during knowledge clearing.**
    `clear_knowledge` removes diagnosis and learned harness-input evidence but
    keeps profiles; project deletion removes all three families
    (`phase-6-build-profiles/progress.md:44`). Cost: changing this classification
    later requires a cleanup semantics migration.
16. **Represent absent compile-database evidence as null.** The canonical input
    digest encodes explicit null, while emitted flags always hash the actual
    ordered vector (`phase-6-build-profiles/progress.md:46`). Cost: the pre-1.0
    storage encoding would need revision if absence later becomes invalid.
17. **Keep `ServiceContainer::bootstrap` infallible.** Build-profile settings
    are strictly loaded by profile-dependent operations before provider/runtime
    action; unrelated bootstrap callers do not change
    (`phase-6-build-profiles/progress.md:74`). Cost: a future universal startup
    error model needs a separately scoped API migration.
18. **Centralize pure profile plan construction and metadata sizing.**
    `profile_build_plan` supplies both exact sizing and Task 4 execution, with a
    bounded terminal/reason reserve (`phase-6-build-profiles/progress.md:76`).
    Cost: if ownership changes, one helper moves; near-limit tests must remain.
19. **Allow strict reads of a saved profile that current policy would reject for
    execution.** Current-assumption checks stop actions, while display remains
    available for correction (`phase-6-build-profiles/progress.md:80`). Cost:
    clients must distinguish inspectable configuration from executable state.
20. **Define database usability by a parsed nonempty entry list.** An entry with
    no extra include/define/flag tokens is still valid evidence; malformed or
    zero-entry files remain Invalid (`phase-6-build-profiles/progress.md:98`).
    Cost: readiness became less strict about auxiliary flags and required a
    focused regression.
21. **Parse compilation-database command strings with cached `shlex` 2.0.1.**
    Arguments arrays retain precedence, malformed quoting is rejected, and no
    shell expansion or execution occurs (`phase-6-build-profiles/progress.md:106`).
    Cost: one optional dependency and parser behavior must remain compatible
    across supported paths.
22. **Require persistent service storage before every new harness compilation.**
    Successful harness and input evidence commit atomically before activation;
    pure draft/read and historical unconfigured harness behavior remain
    (`phase-6-build-profiles/progress.md:116`). Cost: ephemeral compile callers
    must supply a real store.
23. **Record a rejected build artifact as an Invalid build-operation result.**
    Preserve any earlier usable database; a later Diagnose may report Ready from
    that evidence (`phase-6-build-profiles/progress.md:118`). Cost: build history
    can show a failed operation beside a still-usable prior artifact and clients
    must present both accurately.
24. **Persist exact configured provider context in a dedicated immutable table.**
    `harness_build_contexts` records versioned bounded context before dispatch so
    model-visible input is reconstructable (`phase-6-build-profiles/progress.md:128`).
    Cost: one internal pre-1.0 table/API and its cleanup/validation obligations.
25. **Reuse a retained Ready prerequisite result only with exact profile and
    immutable-image identity.** Live image, marker, database, and input checks
    still run before provider or execution (`phase-6-build-profiles/progress.md:130`).
    Cost: changing image identity forces a fresh prerequisite diagnosis.
26. **Bound one Semgrep lease test's setup retry to ten seconds.** It retries
    only the exact cleanup-busy precondition and never changes production lease
    behavior (`phase-6-build-profiles/progress.md:142`). Cost: that test may wait
    longer under contention and its exception must stay module-local.
27. **Use a private campaign seed helper tied to the exact promoted harness.**
    The standalone seed command remains independent; campaign discovery,
    storage, corpus, and publication errors stop admission, while the existing
    optional provider fallback remains (`phase-6-build-profiles/progress.md:156`).
    Cost: campaigns that once continued after seed publication failure now fail
    before runtime.
28. **Classify invalid build-history limits as service Validation.** The service
    reuses the storage maximum so REST returns a client error rather than 500
    (`phase-6-build-profiles/progress.md:168`). Cost: one public error mapping
    changed while storage faults remain distinct.
29. **Keep profile reads available when Build Doctor is disabled.** Diagnosis,
    history, mutation, and execution return explicit unavailable responses
    (`phase-6-build-profiles/progress.md:174`). Cost: feature-off presentation
    must expose a read-only subset consistently.
30. **Embed the locked Windows Common Controls manifest for native library
    tests.** Generic MSVC linker arguments disable only Tauri's duplicate app
    manifest resource (`phase-6-build-profiles/progress.md:214`). Cost: Windows
    loader/link behavior required fresh hosted verification.
31. **Preserve frozen Phase 7 storage while repairing independent Windows
    support paths.** Local gates included those bytes, but no Phase 7 publication
    preceded successful support CI (`phase-6-build-profiles/progress.md:222`).
    Cost: an overlap error would force integration rework, not authorize
    unreviewed publication.
32. **Reject rooted or drive-qualified suffixes before build database
    publication.** Ordinary relative suffixes use native joins; ambiguous
    slash, UNC, verbatim-root, or drive forms become ArtifactInvalid
    (`phase-6-build-profiles/progress.md:228`). Cost: unusual POSIX filenames
    resembling Windows roots are refused to avoid silent root replacement.

## Phase 7: coverage experiments

Delivered references: `docs/design/coverage-experiments-design.md`, migration
0033 and experiment records in `hf-storage`, experiment operations in
`hf-service`, and Phase 7 commit
`f8cb49f4dd45fc642553d615ce3a45c5fb1db465`.

33. **Split design, storage, service, and transport/GUI into reviewed stages.**
    Typed handoffs precede each consumer (`phase-7-experiments/progress.md:30`).
    Cost: extra freeze/review overhead.
34. **Supersede the early Done-only, changed-digest, migration-0030 preflight.**
    Terminal Campaign baselines, retained no-op outcomes, and migration 0033 are
    authoritative (`phase-7-experiments/progress.md:32`). Cost: an error in this
    broader design would need explicit Task 1 correction rather than silent
    narrowing.
35. **Allow Phase 7 design work after the immutable Phase 6 push while hosted CI
    runs.** Source implementation and publication still wait for CI resolution
    (`phase-7-experiments/progress.md:38`). Cost: a platform correction could
    force design rework.
36. **Reuse REST approved-root policy and retain trusted-local native access.**
    Native scope is checked against durable project/target owners; no nonexistent
    desktop root-policy subsystem is claimed (`phase-7-experiments/progress.md:44`).
    Cost: native IPC keeps its existing local privilege level until a separate
    permission design is delivered.
37. **Retain mixed absent/captured build evidence as explicitly inconclusive.**
    Both-captured inputs still compare strictly; owner/setup/chronology mismatch
    refuses attachment (`phase-7-experiments/progress.md:50`). Cost: a result may
    be retained without build comparability and must never attribute improvement.
38. **Move the pure input-digest encoding/hash into storage.** Service uses the
    shared implementation so unconditional storage validation does not depend on
    service or duplicate encoding (`phase-7-experiments/progress.md:58`). Cost:
    any encoding error threatens historical identity compatibility and required
    fixed-vector tests.
39. **Allow storage implementation while the last Phase 6 Windows job runs.**
    The earlier immutable APIs and local gates were stable; publication still
    waited for CI (`phase-7-experiments/progress.md:64`). Cost: a Windows defect
    touching shared fixtures could force controlled freeze and rework.
40. **Accept existing RFC3339 run timestamps but canonically encode new
    experiment timestamps.** New experiment SQL/JSON requires nine-digit `Z`;
    legacy `+00:00` and variable fractions remain readable
    (`phase-7-experiments/progress.md:72`). Cost: equivalent legacy timestamp
    spellings remain accepted.
41. **Split storage structural validation from service experiment policy.**
    Storage checks snapshot-derived consistency and stable limitation codes;
    service owns setup admission and full limitation computation
    (`phase-7-experiments/progress.md:76`). Cost: duplicated derivation would
    drift, so primitive meanings need one owner.
42. **Extend the scheduler's exhaustive storage-error classification narrowly.**
    New experiment/retention validation variants are nonretryable like existing
    validation errors (`phase-7-experiments/progress.md:80`). Cost: an incorrect
    mapping would change retry behavior.
43. **Introduce service-owned `RunHistoryError` with typed retention data.**
    REST/native deletion adapters carry code, IDs, and role without parsing
    strings (`phase-7-experiments/progress.md:90`). Cost: a small pre-1.0 return
    type and caller migration.
44. **Use one strict public experiment-ID parser.** Canonical non-nil v4 parsing
    occurs before REST/native path spelling is erased
    (`phase-7-experiments/progress.md:98`). Cost: one additional public service
    parser must remain stable across transports.
45. **Use one service project-identity validator for native create/list stubs.**
    It performs identity reads only and no experiment lifecycle work
    (`phase-7-experiments/progress.md:100`). Cost: a small public helper performs
    filesystem canonicalization and is not I/O-free.
46. **Send exactly five native experiment requests as bounded UTF-8 bytes.**
    The application checks the 16,384-byte request limit and strict envelopes;
    HTTP uses 413 for oversize and disabled builds preserve access-error
    precedence (`phase-7-experiments/progress.md:112`). Cost: this narrow wire
    form may need migration if native command framing changes; it does not claim
    to prevent Tauri framework JSON parsing.
47. **Share minimal retained target/harness/run test fixtures.** Existing
    feature-gated service test support is forwarded only where actual HTTP and
    native tests need it (`phase-7-experiments/progress.md:114`). Cost: fixture
    coupling across presentation tests.
48. **Extend run history with nullable target UUID and requested duration.**
    Values come from already-resolved retained harness/config evidence; elapsed
    time is never substituted (`phase-7-experiments/progress.md:116`). Cost: a
    public DTO and its fixtures changed before 1.0.
49. **Let the service decide result chronology.** The picker may display other
    terminal campaigns with exact start text; rejected attachment keeps the
    prepared record unchanged (`phase-7-experiments/progress.md:122`). Cost: the
    UI may offer an older result that the service then refuses, avoiding
    nanosecond-loss policy duplication in JavaScript.
50. **Overlap full Rust gates with a frontend-only fix after a verified Rust
    freeze.** Parent rechecks hashes and repeats affected gates if Rust changes
    (`phase-7-experiments/progress.md:130`). Cost: a mistaken freeze requires
    rerunning the affected gate sequence.

## Phase 8: acceptance and operator evidence

Delivered references: `docs/design/harness-work-order-design.md`,
`docs/design/run-closeout-design.md`, `docs/design/coverage-experiments-design.md`,
Phase 8 Task 1/2 reports, and the operator guides updated with this record.

51. **Permit Phase 8 planning during Phase 7 design but wait for final APIs
    before source changes.** Evidence mapping used idle time without binding to
    stale interfaces (`phase-8-acceptance/progress.md:23`). Cost: a changed API
    would require rewriting ignored planning notes.
52. **Permit Phase 8 source work after reviewed/gated Phase 7 push while its
    immutable SHA runs in hosted CI.** Any hosted defect requires a controlled
    worker freeze and support correction before Phase 8 publication
    (`phase-8-acceptance/progress.md:36`). Cost: overlapping work may need
    reapplication, never publication over a failing base.
53. **Add an actual Patch to Proof operator interaction to Task 2.** Existing
    service/REST stage tests are reused; the frontend test covers explicit draft,
    approval, confirmation, start, and retained polling without inventing a
    production RED (`phase-8-acceptance/progress.md:44`). Cost: modest component
    test maintenance.
54. **Keep new documentation English while correcting matching README command
    blocks and paired product strings.** Existing Chinese prose is preserved;
    detailed operator prose belongs in English guides
    (`phase-8-acceptance/progress.md:48`). Cost: the localized README receives
    English command comments to keep exact commands paired.
55. **Use existing CLI replay for experiment follow-up.** The panel shows
    `oxfuzz run . --replay <baseline UUID>` with the same configuration/database,
    retained original project, current promoted harness/corpus, and unchanged
    compared settings. Null-seed legacy baselines require a new seeded baseline
    (`phase-8-acceptance/progress.md:50`). Cost: desktop users perform a CLI step;
    no new execution API or weaker comparison is introduced.
56. **Resolve replay and closeout workspaces from the exact retained target.**
    Only service-computed bare/file-qualified managed corpus paths may match;
    arbitrary paths are rejected and absent legacy provenance keeps bare
    behavior (`phase-8-acceptance/progress.md:52`). Cost: unconventional historical
    paths can be refused rather than silently executed.
57. **Carry the reviewed file-qualified selector from Work Order promotion into
    Run and inventory.** Service DTOs retain the complete selector beside the
    display symbol; discovery preserves a valid current selection and never
    splits namespaced symbols (`phase-8-acceptance/progress.md:58`). Cost: tighter
    restoration and internal DTO/fixture changes, without a new execution API.
58. **Overlap parent Rust gates only after Task 3 freezes and releases its Rust
    work.** Remaining prose, frontend, and browser work is not a compiled Rust
    input; database schema, bundled skills, and compiled fixtures remain frozen
    (`phase-8-acceptance/progress.md:73`). Cost: any later Rust, manifest, or
    compiled-input change requires coordination and repetition of affected
    gates. This overlap does not replace Task 3 review or final publication
    checks.
59. **Resolve final integration findings before the Phase 8 publication.**
    Review identified qualified run cleanup and Triage actions that lost the
    selected target's workspace. Correct these through existing service
    operations and exact retained identity, with direct service and component
    regressions. Cost: publication waits for refreshed verification; no new
    execution endpoint or weaker historical-action checks are introduced.
60. **Keep small review observations explicit without a general rewrite.**
    Result attachment still reads the global target inventory, so unrelated
    malformed target rows can fail the scoped operation. Some per-field storage
    rejection tests can also pass through source-equality validation. These
    remain known limitations: the current validators are present and no
    unauthorized acceptance was found. Cost: lookup work scales with inventory,
    and future validator changes need stronger independent test coverage.
61. **Describe retained workspace selection as deterministic matching.**
    The resolver tries the two service-computed candidates in bare-symbol then
    file-qualified order; retained paths never become arbitrary execution
    roots. This revises the earlier planning requirement to reject multiple
    matches. No practical collision was found, and the workspace naming scheme
    itself uses truncated digests. Cost: a theoretical collision between these
    candidates keeps bare-first behavior; this change does not claim globally
    collision-free workspace names.
