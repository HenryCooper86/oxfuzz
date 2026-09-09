# Retained starting corpus

## Problem and behavior

A run previously copied the shared corpus directly into its writable engine
corpus. After the engine mutated that directory, the original input bytes were
no longer available as a separate retained set. Run provenance also hashed the
shared corpus before staging, which could identify bytes different from those
actually copied.

Campaign and smoke staging now capture the shared corpus under
`runs/<run-id>/input/corpus`, then copy that captured set into the writable run
corpus. The recorded corpus digest uses the captured bytes and stable logical
`corpus/<filename>` names. A missing retained directory fails before execution;
there is no fallback to current shared inputs. The existing read-only workspace
mount protects retained inputs inside the sandbox, while separate writable
mounts permit engine corpus and output updates.

This adds one corpus copy, using the existing bounded corpus snapshot operation.
It does not turn the current fixed-seed replay into an exact historical rerun.
Retained dictionary/configuration evidence and a separate execution path remain
necessary; old runs cannot recover starting inputs that were never saved.
Read-only sandbox access does not make host-side files tamper-proof.

## Verification

The staging regression failed on the missing retained seed before implementation.
The digest test then failed because captured-context support did not exist.
After implementation, staging tests cover independent working/shared mutations,
recorded identity independent of later shared edits, missing-snapshot rejection,
and read-only input mounting. A service integration test checks that both smoke
and campaign records identify their retained seeds.

Formatting, fixing/strict workspace Clippy, compilation, all-target Clippy and
strict private-item documentation passed. The script suite passed 93 tests;
frontend passed 518 tests in 72 files, production build/bundle budgets and lint.
Dependency and translation checks passed; measured domain line coverage remained
91.12%. Full workspace tests passed: 3,244 passed, zero failed, seven ignored,
across 179 test summaries. The ordinary workspace documentation build also passed.

Raw local logs use `/tmp/oxfuzz-phase3-*.log`. These are controlled software tests,
not real fuzzer campaigns or comparative effectiveness measurements. Hosted CI
will run on the pushed commit; local checks do not establish Windows acceptance.
