# Harness Work Order v2 final remediation report

Date: 2026-08-30

Base: `bbacdebe334ff593694757ab5a8b9eec66d0c551`

Final remediation range: `bbacdebe334ff593694757ab5a8b9eec66d0c551..HEAD`.
The report commit is the range tip.

## Result

Every Important and Minor item in `final-fix-brief.md` is resolved. The final
workspace test, the ordered Rust quality gates, dependency policy checks, and
repository audits pass. No generated harness or fuzzer was executed on the
host.

## Commits

- `6b9a09f7` `fix(work-orders): recover only unowned qualifications`
- `288ebc8f` `fix(work-orders): preserve namespaced target identity`
- `6ceacb20` `fix(work-orders): emit parser-valid validation commands`
- `b308be80` `fix(web): authorize durable work-order owners`
- `cefadfe6` `fix(work-orders): reject embedded host paths`
- `bca44e89` `test(service): surface discarded synchronization errors`
- `d79c11c3` `docs(work-orders): align final safety behavior`

## Remediation decisions

### Qualification recovery

Qualification now chooses its attempt UUID and acquires a nonblocking OS
advisory lease before inserting the running attempt. It holds the lease through
the terminal transition. Startup recovery enumerates running attempts and
tries the same UUID-derived lease independently for each one. A busy lease
leaves the live attempt untouched. An acquired lease permits a per-attempt
compare-and-set transition to `interrupted`. Enumeration, lease, and storage
errors retain fail-closed startup behavior.

The strengthened regression pauses a real qualification during sandbox compile,
creates an unowned peer attempt, and starts recovery through an independent
store and service container. Recovery skips the paused live attempt, interrupts
only the peer, and the qualification resumes without a hang or race.

### Exact target identity and validation commands

File-qualified selection compares the complete formatted
`relative_file::symbol` spelling. It does not split on the last `::`, so a
namespaced C++ symbol remains intact while plain unique and ambiguous-symbol
behavior is preserved.

Validation commands use typed project and submission-origin placeholders.
Import supplies `--origin`; run and coverage supply the positional project;
run uses the supported language and duration options. Run and coverage retain
the exact file-qualified selector. A CLI regression substitutes every
placeholder and parses all six argv arrays through the real Clap parser.

### REST project authorization

`hf-service` resolves work-order, submission, and attempt identifiers to their
verified immutable project. REST handlers apply the configured approved-root
policy to that owner before any ID-based read, mutation, provider request, or
runtime dispatch. Ranking checks every attempt. Unscoped lists omit records
whose owners are not approved. The web layer does not access storage directly.

### Portable compiler definitions

One shared `hf-core` byte scanner detects embedded Unix, drive-qualified
Windows, UNC, and file-URI absolute paths. It is allocation-free and linear in
the value length, uses fixed-size URI-scheme look-behind, and is paired with a
4,096-byte per-definition cap. Discovery drops unsafe definitions; the service
independently rejects them before packet persistence. Relative values and
non-file URIs remain accepted.

### Fallible operations

Branch-added test synchronization sends and receives now fail immediately when
their peers disappear. File reads propagate classified errors. Lease failures
are matched and logged explicitly. Optional coverage parsing no longer uses
fallible-discard spellings.

## TDD and focused verification

The five regressions were introduced before their production changes. They
demonstrated live-attempt interruption, namespaced selector misparsing, argv
rejection by Clap, outside-root ID access, and retained embedded host paths.
Each then passed after the corresponding implementation.

All focused Cargo tests used the repository-required error filter with
`set -o pipefail` and an empty-filter-success wrapper. Final focused runs were:

- `cargo test -p hf-storage harness_work_order`
- `cargo test -p hf-discovery --features build-context build_context`
- `cargo test -p hf-service --features harness-work-order --test harness_work_order`
- `cargo test -p hf-service --features harness-work-order --test harness_work_order_qualification`
- `cargo test -p hf-service --lib work_order_recovery_tests`
- `cargo test -p hf-service --lib lifecycle::tests`
- `cargo test -p hf-service --lib queued`
- `cargo test -p hf-service --lib holds_the_revision_lease`
- `cargo test -p hf-cli --features harness-work-order work_order`
- `cargo test -p hf-web --features harness-work-order --test harness_work_order_api`

Every focused command exited `0` with no filtered failure output.

## Complete verification

The final code was verified in the required order:

1. `cargo test --workspace` with the mandated filter: exit `0`, no filtered
   failure output.
2. `cargo fmt --all`: exit `0`.
3. `cargo clippy --fix --allow-dirty --workspace -- -D warnings`: exit `0`.
4. `cargo clippy --workspace -- -D warnings`: exit `0`, zero warnings.
5. `cargo check --workspace`: exit `0`.
6. `cargo doc --workspace --no-deps`: exit `0`.
7. `cargo deny check`: exit `0`; advisories `ok`, bans `ok`, licenses `ok`,
   sources `ok`.

The full workspace test and all five Rust gates were repeated after the last
test-only scope correction, so this evidence applies to the committed code.

## Audits

- `git diff --check`: clean.
- Status and diff path scans: no tracked build, corpus, crash, database, log,
  profile, or binary artifact was added.
- Gitleaks 8.30.1 scanned the complete remediation patch (about 100.7 KB): no
  leaks found.
- The branch-wide added-line scan for `let _ =`, `.ok()`, and
  `unwrap_or_default()` found no added match beyond diff headers.
- The approved planning artifact in the main checkout was neither modified nor
  moved.

## Residual concern

No unresolved correctness concern remains for the supported single-host
service. The advisory lease is deliberately host-local and its lock file is
kept to preserve inode identity. A future deployment where processes share a
database across multiple hosts must replace or supplement it with durable
database ownership and staleness tracking before enabling cross-host recovery.
