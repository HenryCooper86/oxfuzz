# Qualifying a Windows host

**Windows is not supported for now, and Windows installers are not built or
published, and CI no longer compiles or tests Windows.** The source paths and
this procedure are kept so support can come back. The workflow that automated
steps 2 and 3, `windows-qualification.yml`, was removed on 2026-11-24 and is in
the history before that date. The rest of this guide is unchanged, so its
statements about CI describe the state before that date.

The workspace compiles and passes its unit tests on Windows in CI. No reviewed Docker build, smoke run, campaign, Stop and
resume has been recorded on Windows 10 or 11, so the
[support matrix](SUPPORT_MATRIX.md) makes no Windows campaign claim. This
guide is the procedure that produces that record.

**Status: run in part, once, and not on the usual configuration.** On
2026-11-22 the image build and steps 1 to 3 were run on a hosted Windows
Server 2025 runner with Rancher Desktop as the engine
([record](../acceptance/windows-host-2026-11-22.md)). The image build, step
1, step 2 and the source-engine and Stop-and-resume tests of step 3 passed.
The three binary-only tests of step 3 failed. Steps 4 to 6 have not been run
on Windows. Nothing has been run on Windows 10 or 11 or with Docker Desktop.

The steps are host-independent and list the project's existing live tests in
the order that isolates a failure fastest. Steps 4 and 5 are the procedures
behind the macOS records
[userspace-2026-09-27](../acceptance/userspace-2026-09-27.md) and
[service-campaign-process-loss-2026-09-27](../acceptance/service-campaign-process-loss-2026-09-27.md).
Treat each Windows-specific note below as a place to look, not as a known
result, unless it names where it was seen. A failed step is a result too:
record it.

`.github/workflows/windows-qualification.yml` runs the image build and steps
2 and 3 on a hosted runner. It is started by hand. It cannot run steps 4 and
5, which need a provider and a human approval.

## What you need

- Windows 10 or 11 on x86_64.
- A container engine that runs Linux containers and accepts a Windows path
  as a bind source: Docker Desktop, or Rancher Desktop with the `moby`
  engine. A Podman machine also translates the path, but oxfuzz has not been
  run against Podman. A `dockerd` started by hand inside a WSL distribution
  does not: it rejects `D:\...` as "not absolute", so oxfuzz cannot use it
  from Windows. Record the engine, its version, which backend it uses (WSL 2
  or Hyper-V) and where the repository checkout lives (a Windows drive, a UNC
  path, or inside a WSL distribution). Only a checkout on a Windows drive is
  covered by the mount-argument tests; the others are separate
  configurations.
- The Rust toolchain named in `rust-toolchain.toml`, with the MSVC build
  tools, and Git for Windows (the gate script is bash).
- The sandbox image `oxfuzz/fuzz-sandbox:0.2.4` for `linux/amd64` in that
  engine. It is not published. `scripts/build-sandbox.sh` builds and
  verifies it; run it from Git Bash in the checkout. A default Git for
  Windows checkout rewrites line endings; `.gitattributes` keeps the files
  the image build copies in with LF, so no git setting needs changing. The
  amd64 image was also built and passed the
  script's verification on 2026-11-22, on an arm64 Mac under emulation. Run
  against that image there, the six isolation tests of step 2, the Bazel
  build test and twelve of the fifteen engine tests of step 3 passed. The
  three `binary_only` tests did not: AFL++ QEMU mode ran at about a
  fifteenth of its native speed inside the emulated container, found
  nothing in the time allowed and reported a timeout on a benign request.
  Whether they pass on a real x86_64 host is not established.
- For steps 4 and 5 only: a configured review provider, and a human who has
  read `examples/qualification/parser.c` and `harness.c` and approves them.
  See [the qualification README](../../examples/qualification/README.md) for
  the approval value. Do not set it without that review.

## Before you start

Record, for the acceptance record: the commit and `git status --short`, the
Windows version (`cmd /c ver`), `docker version`, the backend, `wsl --version`
if WSL 2 is used, and the image ID
(`docker image inspect --format "{{.Id}}" oxfuzz/fuzz-sandbox:0.2.4`).

Run every command from Git Bash in the repository root.

## Steps

### 1. Unit tests without Docker

```bash
scripts/tests/gates.sh check test
```

This is what CI runs on `windows-latest`. It must pass before anything below
means anything.

### 2. Sandbox isolation

```bash
cargo test -p hf-runtime --test live_isolation -- --ignored --test-threads=1
```

Six tests: a sandboxed command has no network and cannot write its inputs,
output stays within its byte limit, a timeout waits for container cleanup,
each container is registered and labeled, and a fresh runtime removes a
container left by a killed process. This is the first step that passes a
Windows path to `docker run`, so a mount or path-translation problem shows
here before any engine is involved.

### 3. Engines without a provider

```bash
cargo test --workspace --lib -- --ignored --test-threads=1 \
  live_go_native live_qemu_session live_socket_session live_bisection \
  live_cpp_memory_sanitizer live_atheris live_jazzer live_cargo_fuzz \
  live_stop_and_resume
```

Sixteen tests. Fifteen build a small program with a planted bug in the
sandbox, fuzz it for a bounded time, and check that the bug is found,
replayed and classified. The sixteenth, `live_stop_and_resume`, builds an
AFL++ harness, starts a ten-minute campaign, stops it once the host reads
measured progress from the engine's own files, requires the Stop to finish
within 15 seconds with no container left, and then resumes the same output
tree and checks that the stopped campaign's queue was carried over. Nothing
here asks a model for anything and no approval is involved: the sources are
constants in the test files. It is the building blocks of steps 4 to 6
without the review, the promotion and the service's run records, so it does
not replace them.

Look closely at the three `binary_only` tests and the Stop-and-resume test.
They run AFL++ with its output directory on the host, and AFL++ 4.09c names
queue and crash files with colons (`id:000000,sig:11,...`). A Windows file
name cannot hold a colon. Through a WSL 2 drive mount the file is stored
with U+F03A in place of each colon: seen on Windows Server 2025 with
Rancher Desktop 1.25.0, with Podman 6.2.0 and with a plain `dockerd`, on
2026-11-22. The container still sees the colon. oxfuzz reads such names
with either character. Whether Docker Desktop stores the same substitute
has not been observed; if these tests fail there, record the names that
appear under the session's `out/default/crashes` directory as Windows shows
them.

### 4. Build, smoke, promotion, campaign, Stop and replay

```bash
export OXFUZZ_LIVE_APPROVAL_SHA256=<value from the qualification README, after review>
export OXFUZZ_LIVE_EVIDENCE_ROOT=<a new empty directory outside the repository>
cargo test -p hf-service --features proof-carrying --test cancellation_live \
  stop_button_cancels_a_real_fuzz_run -- --ignored --exact --nocapture
```

For libFuzzer, AFL++ and honggfuzz in turn: the harness compiles in the
sandbox, a 10-second smoke run passes the provider review, the revision is
promoted, a campaign starts and is stopped after measured progress (Stop must
finish within 15 seconds), the retained inputs are replayed, and no container
is left behind. Each engine writes a `qualification.json` under the evidence
directory. An engine that does not finish is not a pass.

`scripts/qualify_engines.py`, which repeats this for many cycles, supervises
its child with POSIX process groups and refuses to run on Windows. One cycle
through the command above is the Windows record.

### 5. Process loss and a second campaign

```bash
cargo test -p hf-service --lib -- --ignored --exact --nocapture \
  container::live_recovery_tests::approved_campaign_survives_service_process_loss
```

It uses the same two environment variables. The service process is killed
during a campaign; a fresh service must clean up the owned container and
admit a new campaign for the same target. `scripts/qualify_recovery.py`, the
wider fault runner, is POSIX-only.

### 6. Resume

Not covered by a live test on any host. On a project of your own with a
promoted AFL++ harness, run a short campaign twice, the second time with
`--resume`:

```bash
oxfuzz run <project> --target <sym> --engine afl++ --duration 2m
oxfuzz run <project> --target <sym> --engine afl++ --duration 2m --resume
```

Record whether the second run continues the first run's queue. On an
in-place resume AFL++ moves the earlier `crashes` and `hangs` directories
aside under names with a timestamp that contains colons, so this is the
second place the file-name question shows.

## What the record must say

Write it in the [acceptance record format](../acceptance/README.md) as
`docs/acceptance/windows-host-<date>.md`: the identity collected above, the
limits each step ran with, each step's outcome with its run identifiers and
Stop latencies, and what was not run. Until a reviewed record with steps 1 to
5 passing exists, the support matrix keeps its current wording, and steps
that fail become defects linked from the record.

Not in scope here and separately unavailable on Windows: Patch-to-Proof
(fails closed), syzkaller campaigns, and the automotive lab.

## Checking Windows compilation from another host

`scripts/check-windows-target.sh` type-checks the workspace and its tests for
`x86_64-pc-windows-msvc` on Linux or macOS. It finds code that does not
compile for Windows before CI does. It links and runs nothing, so it does not
replace step 1.
