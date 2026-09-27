# Owned Docker recovery probe, 2026-09-27

Outcome: **passed for an owned sandbox command after owner-process termination**
on a local macOS arm64 Docker host. This is partial A3 evidence, not a service
WAL, closeout, backup/restore, or overnight-soak result.

The tested checkout was clean at
`509d6d9b9e563b49f2bb25721821cb5449c58487`, using sandbox image ID
`sha256:a43a1e6fc8bcff6e19bb823999b9df20787395caaf4fb68744086beb5475429c`.
The ignored [live probe](../../crates/hf-runtime/tests/live_isolation.rs) had
SHA-256 `6033e55111b0235887fe218a569304c347720b5b6bf09efd158184ec2dc9df2c`.
It ran harmless shell and sleep commands through `hf-runtime` in disposable
workspaces; no generated harness or fuzzer ran in this probe.

The process-loss scenario started a helper process that launched a named Docker
container. The parent observed its durable ownership record and the live
container, then terminated only that helper process. A fresh `DockerRuntime`
instance inspected the recorded name and matching workspace label, removed the
surviving container, confirmed it was absent, cleared the record, and completed
a subsequent harmless command. The tests also verified that active records are
skipped, a foreign label and failed removal preserve the record, a stalled
inspection returns an error, and an initially absent container is checked
again before the record is cleared.

All six ignored live isolation/recovery tests passed. The [earlier isolation
record](isolation-2026-09-27.md) describes the network, mount, cgroup, and
timeout probes. A final Docker inventory found no `hf-run-` containers. The
private raw test log is
`/Users/admin/.codex/qualification-evidence/a3-owned-recovery-2026-09-27/process.log`,
SHA-256 `a06300b460f2967a26338648f9a23c1876217d33c3aa7ca13861586860dd5022`.

This probe does not kill the full service after a durable run admission. It
does not establish that a WAL reminder implies Docker cleanup; the runtime
inventory and service WAL are separate records. It also does not test disk
exhaustion, one-time schedule restart, closeout resumption, backup/restore, or
12-hour fault behavior. Those A3 scenarios remain open.
The later [service journal process-loss probe](service-recovery-process-2026-09-27.md)
tests WAL replay and retained run status separately.
The [backup/restore probe](backup-restore-2026-09-27.md) verifies a separate
SQLite/WAL snapshot and immutable workspace copy.
The [bounded fault suite](recovery-fault-runner-2026-09-27.md) combines the
existing recovery tests into one revision-linked result.
