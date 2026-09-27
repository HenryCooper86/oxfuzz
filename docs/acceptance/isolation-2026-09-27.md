# Local Docker isolation probe, 2026-09-27

Outcome: **two initial live `hf-runtime` probes passed** on a disposable macOS
arm64 workspace. This is partial A3 evidence. The later
[owned-container recovery probe](runtime-recovery-2026-09-27.md) covers a helper
process termination; full-service recovery, disk pressure, backup/restore, and
the 12-hour soak remain separate.

The production code was clean at `984f4712`; the new ignored live test had
SHA-256 `6956077c259a57e4ae513aba0b63432761895aba4109f1fc5db4c6a126086b20`.
The runtime used `oxfuzz/fuzz-sandbox:0.1.0`, image ID
`sha256:a43a1e6fc8bcff6e19bb823999b9df20787395caaf4fb68744086beb5475429c`.
No generated harness ran in this probe. The commands inside the sandbox read
cgroup and network-interface state, attempted a denied write to a read-only
input, wrote one small output into an explicitly writable mount, and slept
past a one-second limit. The configured limits were one CPU and 256 MiB.

The [live tests](../../crates/hf-runtime/tests/live_isolation.rs) observed:

| Scenario | Observed result |
| --- | --- |
| Network, input and output mounts, CPU and memory | No `eth0`; input content readable but write denied; output write retained; cgroup quota `100000 100000` and memory ceiling `268435456` bytes |
| Wall-clock timeout and cleanup | Runtime returned `TimedOut`; no newly created `hf-run-` container remained after the call or in a final Docker inventory |

The private raw log is
`/Users/admin/.codex/qualification-evidence/a3-isolation-2026-09-27/process.log`,
SHA-256 `5351edd5b79f145e16ac6650f9a631a4b2ff6aaa499997149417427487a8c92c`.
Both tests passed with no failures. This probe used a local Docker daemon and
does not establish identical behavior on Linux or Windows. The [A3 recovery
plan](../design/runtime-design.md) describes the still-open process-crash case.
