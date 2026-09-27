# Recovery fault qualification runner

Status: implemented for a bounded subset of A3. Owner:
`scripts/qualify_recovery.py`. The runner is an acceptance tool, not a service
or runtime operation.

The command list is fixed in the script and contains five existing tests:
service WAL process loss, closeout cancellation and store reopen, one-time
schedule restart, terminal status-write failure, and Docker owner-process loss.
The first four use synthetic stores or runtimes. The Docker test runs only
harmless shell commands through `hf-runtime`; none of these commands builds or
executes a generated harness. These results must not be described as full
service termination after a real campaign admission or disk exhaustion during
campaign evidence writes.

The runner records the complete repository identity before launch and checks
it around every case. Each owned subprocess gets a new process group, a bounded
output log, and a deadline. A timeout or output overrun kills that group and
stops later cases. It never scans or kills unrelated processes. The Docker
test itself verifies its workspace-labeled container is removed; a timeout
leaves cleanup unverified in the manifest. A process exit code of zero alone
is insufficient: one test must report one pass. The manifest and partial logs
are retained in a new private directory outside the source checkout.

Further scenarios require dedicated tests and must be added to the fixed list
only when they can verify retained state, actual runtime cleanup, and safe
subsequent admission. A passing runner means this listed subset passed, not
that A3 or a release is qualified.
