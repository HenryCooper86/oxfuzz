# Userspace engine qualification

This benign target reads at most four bytes after checking the input length.
The harness calls it once per input, stores its result in a bounded scalar, and
returns zero. Neither source allocates memory, opens files or sockets, starts
processes, or deliberately crashes. The qualification covers engine operation,
retained-input replay, per-run Stop, cleanup, and positive function counters
from the replay binary. It requires the `proof-carrying` feature and does not
establish useful vulnerability discovery.

## Review and approval

Review [parser.c](parser.c) and [harness.c](harness.c). Their combined identity is
SHA-256 of `parser.c`, a zero byte, then `harness.c`:

```text
a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591
```

The live test refuses to start unless `OXFUZZ_LIVE_APPROVAL_SHA256` contains
that identity. Set it only after human approval of these exact sources. A real
configured provider additionally reviews the source through the normal service
review path before smoke. Provider rejection remains a failure, not a skipped
test or a synthetic approval.

## Execution and evidence

After approval, set `OXFUZZ_LIVE_EVIDENCE_ROOT` to a durable disposable directory
and run the ignored `cancellation_live` test with the repository's test-output
filter. A configured review provider, Docker, and the local
`oxfuzz/fuzz-sandbox:0.1.0` image are required. No host harness execution occurs.

Each of libFuzzer, AFL++, and honggfuzz compiles in `hf-runtime`, completes a
10-second smoke, promotes that harness revision, starts a 10-second campaign,
and stops it after measured progress. Stop must finish within 15 seconds. A
10-second retained-input replay follows. The test checks that no new sandbox
containers remain after each engine. It never removes unrelated containers.

The selected directory receives a unique `qualification-<uuid>` child with the
database, isolated config, workspace, immutable inputs, journals, and per-engine
`qualification.json` records. Evidence is retained on success and failure.
Record the tested git revision and working-tree diff alongside this directory.
An incomplete engine is not a pass. This bounded check is not an overnight soak,
Linux/KVM qualification, physical-bench validation, or packaged-app user testing.

## Repeated qualification cycles

After approval of the sources above, the operator can set
`OXFUZZ_LIVE_APPROVAL_SHA256` to that approved digest and run:

```bash
python3 scripts/qualify_engines.py \
  --output /absolute/path/to/new-qualification-evidence \
  --cycles 10 \
  --cycle-timeout-secs 900
```

The output directory must be new and outside this repository. The runner is
currently POSIX-only. Each cycle invokes the normal live fixture with the
`proof-carrying` feature, including a fresh real-provider review. The timeout
includes Cargo startup/build time. Cycle count and timeout are explicit; a
cycle count does not promise an elapsed overnight duration.

`manifest.json` records repository/file identities, platform, command, limits,
cycle outcomes, and per-engine median/nearest-rank P95 Stop latency with sample
counts. Each `cycle-NNNNN` retains its process log and the fixture's database,
workspace, profiles, and reports. Environment values and patch contents are not
copied into the manifest. Keep the evidence directory private; logs are retained
as produced by the fixture.

The runner stops on the first failure, source/repository change, missing report,
reused run identity, timeout, or interruption. Nonzero exits never count as a
pass, even if some engine reports exist. Timeout or interruption kills the owned
local process group and marks sandbox cleanup unverified; inspect the dedicated
runtime before another invocation. A manifest left `running` after abrupt host
loss is incomplete. There is no automatic resume, retry, or container deletion.

These cycles exercise normal qualification and Stop repeatedly. They do not
inject worker loss, disk pressure, or service restarts, and do not replace those
separate acceptance scenarios.
