# Service run journal process-loss probe, 2026-09-27

Outcome: **passed for retained run status and WAL replay after an owned test
process is terminated**. This is partial A3 evidence.

The clean checkout was `367f357358943bd6730f16480f50adeab7794fc5`.
The [integration test](../../crates/hf-service/tests/recovery_process.rs) had
SHA-256 `6209d64f32a886556d524d4ea289c0667dbd4ee4134a4e275035daf2147fa534`.
`./scripts/cargo-test-filtered.sh -p hf-service --test recovery_process`
exited successfully on the local macOS arm64 host. The full workspace test
suite, default and no-default replay tests, feature behavior, and ordered Rust
quality gates also passed for this change.

The test starts an owned child process in a disposable directory. The child
inserts a `Running` run row, syncs an `open` event to the service WAL, and
publishes its run ID. The parent kills and reaps that child, reopens the WAL,
and confirms exactly that run appears as interrupted. Service reconciliation
changes the retained row to `Failed` once; a repeated pass makes no further
change. A separate test confirms that a terminal row with an unclosed WAL
entry is downgraded, because its journal close cannot be confirmed.

The child uses `Store` and `RunJournal` directly. It does not launch a fuzzer,
exercise the presentation start API, or prove that Docker cleanup and WAL
repair complete together. The [runtime recovery probe](runtime-recovery-2026-09-27.md)
separately confirms owned-container cleanup after a killed command owner.
Full service admission, closeout interruption, evidence-write failure,
schedule restart, backup/restore, and the 12-hour soak remain open.
