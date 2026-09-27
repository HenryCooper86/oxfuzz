# Bounded recovery fault suite, 2026-09-27

Outcome: **five fixed scenarios passed** on a clean local macOS arm64
checkout. This is partial A3 evidence, not the complete fault schedule or
12-hour soak.

The candidate was `a18c271454508f3c8577a1ea5d4bb52673511739`.
The [runner](../../scripts/qualify_recovery.py) had SHA-256
`d03a1e0c47506b54398abb083342ffe8a8c6973958c8f89991026b8fade67d4f`.
Its [fake-worker suite](../../scripts/tests/test_qualify_recovery.py) had
SHA-256 `8f2b8b8ece7e4051304ff52beab4d7988c2c58729af25a764336c5b9fd23290e`.
`script-tests` passed 137 Python and 18 Node tests. The private
`/Users/admin/.codex/qualification-evidence/a3-fault-runner-2026-09-27/manifest.json`
has SHA-256 `61e2f4e37aa3e56876e829d09982649fc3d1f224a7dfa922fa89603ee68f40eb`.

| Scenario | Result | What it establishes |
| --- | --- | --- |
| Journal process loss | Passed | Owned child termination leaves a replayable WAL entry; retained run repair is repeatable. |
| Closeout restart | Passed | Aborting the first step leaves no false completed row; a new store instance can retry. |
| One-time restart | Passed | Existing durable occurrence states do not cause a second dispatch after restart. |
| Terminal status-write failure | Passed | The service awaits monitor cleanup when the terminal database write fails. |
| Runtime owner loss | Passed | A fresh Docker runtime removes a surviving workspace-labeled container after its owner process dies. |

Each case returned one passing test under a 600-second deadline. The runner
retained separate bounded logs and rechecked the complete source identity
around each command. The runtime case used image ID
`sha256:a43a1e6fc8bcff6e19bb823999b9df20787395caaf4fb68744086beb5475429c`;
its test runs harmless shell commands through `hf-runtime`, with no generated
harness. The final Docker inventory showed no `hf-run-` containers.

The journal test uses synthetic admission through `Store` and `RunJournal`,
and closeout cancellation occurs within a test process. The status-write case
is a database failure, not disk exhaustion during campaign artifact writes.
Full service termination after a real campaign admission, a crash after a
persisted closeout step, bounded artifact-write failure, and the 12-hour fault
soak remain open.
