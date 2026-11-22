# Qualifying a Windows host

Windows installers ship, and the workspace compiles and passes its unit tests
on Windows in CI. No Docker build, smoke run, campaign, Stop or resume has
been recorded on a Windows host, so the
[support matrix](SUPPORT_MATRIX.md) makes no Windows campaign claim. This
guide is the procedure that produces that record.

**Status: this procedure has not been run on Windows.** It lists the
project's existing live tests in the order that isolates a failure fastest.
The steps are host-independent. Steps 1 to 3 pass on macOS arm64 on the tree
this guide was written against (2026-11-22). Steps 4 and 5 are the procedures
behind the macOS records
[userspace-2026-09-27](../acceptance/userspace-2026-09-27.md) and
[service-campaign-process-loss-2026-09-27](../acceptance/service-campaign-process-loss-2026-09-27.md);
they were not rerun for this guide. Treat each Windows-specific note below as
a place to look, not as a known result. A failed step is a result too: record
it.

## What you need

- Windows 10 or 11 on x86_64.
- Docker Desktop running Linux containers. Record which backend it uses
  (WSL 2 or Hyper-V) and where the repository checkout lives (a Windows
  drive, a UNC path, or inside a WSL distribution). Only a checkout on a
  Windows drive is covered by the mount-argument tests; the others are
  separate configurations.
- The Rust toolchain named in `rust-toolchain.toml`, with the MSVC build
  tools, and Git for Windows (the gate script is bash).
- The sandbox image `oxfuzz/fuzz-sandbox:0.2.3` for `linux/amd64` in that
  Docker daemon. It is not published. `scripts/build-sandbox.sh` builds and
  verifies it; the script is bash and has not been run from a Windows shell,
  so running it inside a WSL distribution that shares the Docker Desktop
  daemon is the safer route. The amd64 image was built and passed the
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
(`docker image inspect --format "{{.Id}}" oxfuzz/fuzz-sandbox:0.2.3`).

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
  live_cpp_memory_sanitizer live_atheris live_jazzer live_cargo_fuzz
```

Fifteen tests. Each builds a small program with a planted bug in the
sandbox, fuzzes it for a bounded time, and checks that the bug is found,
replayed and classified. Nothing here asks a model for anything and no
approval is involved: the sources are constants in the test files.

Look closely at the three `binary_only` tests. They run AFL++ with its output
directory on the host, and AFL++ 4.09c names queue and crash files with
colons (`id:000000,sig:11,...`). A Windows file system does not store a colon
in a file name. What Docker Desktop does with such a name on a Windows-drive
bind mount (refuse it, or store a substitute character) decides whether
oxfuzz then finds the crash files, and it has not been observed. If these
tests fail, record the names that appear under the session's
`out/default/crashes` directory as Windows shows them.

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
