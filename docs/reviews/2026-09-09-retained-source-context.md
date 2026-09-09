# Retained launch-time source context

Run provenance previously hashed staged target source/header files but did not
retain those files separately. Later workspace edits could therefore remove the
bytes behind an otherwise valid historical source digest.

Campaign and smoke staging now copy the existing source-context file set into
`runs/<id>/input/source-context`, preserving workspace-relative paths. The source
and combined context digests are computed from that copy. Source selection and
logical hash names retain their prior meaning: C/C++ source and headers, Cargo
manifests, and the recursive `src` tree. The archive remains read-only inside the
sandbox, independent of later live source edits.

Copies stream under the existing comparison byte ceiling and reject excessive
files. This adds retained disk usage; the existing combined context limit is
100,000 files and 16 GiB including starting corpus. It is not a content-deduplicated
archive. If staging fails, its unique unreferenced directory is removed, while
preexisting files/directories are preserved; cleanup failures are logged.

This records the source context present at launch. It is not a complete archive
of arbitrary runtime dependencies or proof of historical compiler inputs. Exact
reruns still require complete execution-input identity, dictionary/configuration
evidence, and a separate admitted executor. Legacy hashes cannot recover source
files that were never retained.

## Verification

Before implementation, tests failed on missing retained source files and a leaked
staging directory after an invalid corpus input. The copy-budget test failed
before the bounded helper existed. Focused tests now pass for nested C sources,
headers and Rust source, independence from later source edits, stable captured
digests, missing snapshot rejection, byte-budget rejection, read-only mounting,
and failed-staging cleanup. A service integration test confirms retained source
for both a smoke run and a campaign.

Full workspace verification passed: 3,253 tests passed, zero failed, seven
ignored across 180 summaries. Formatting, fixing and strict workspace Clippy,
compilation, documentation and strict all-target Clippy passed. Dependency
policy, domain coverage, script tests, translation pairing, frontend tests,
production build and bundle budgets, and frontend lint also passed.
Local logs use `/tmp/oxfuzz-source-context-*.log`. No real generated harness or
fuzzer runs are part of these tests. Hosted CI for this phase is separate from
these local results.
