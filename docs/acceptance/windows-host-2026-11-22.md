# Windows host, hosted runner, 2026-11-22

Outcome: **partial. Not a Windows qualification.** On a GitHub-hosted Windows
Server 2025 runner, with oxfuzz running on Windows and its containers in a
Linux engine inside WSL 2, the sandbox image was built and verified from a
Windows checkout, the sandbox isolation tests passed, the provider-free
source-engine tests passed, and an AFL++ campaign was stopped and resumed.
The three binary-only session tests failed. The reviewed campaign, the
process-loss step and a CLI resume (runbook steps 4 to 6) were not run. The
host is not Windows 10 or 11 and the engine is not Docker Desktop, so this
record does not cover the configuration most Windows users have.

The procedure is [Qualifying a Windows host](../guides/WINDOWS_QUALIFICATION.md).
The [support matrix](../guides/SUPPORT_MATRIX.md) keeps its Windows wording.

## Identity and limits

| Item | Tested value |
| --- | --- |
| Candidate source | Commit `e40edf97` on `feat/msan-tsan-sanitizers`, clean checkout by the runner |
| Workflow | `.github/workflows/windows-qualification.yml`, run 45010360596. An earlier run, 45005294376 on commit `f6cd641e`, is described under Earlier run |
| Host | GitHub-hosted `windows-2025` runner: Windows Server 2025 Datacenter 10.0.26100.33828, x86_64, 4 logical processors, 16 GiB; runner image `win25-vs2026` 20261116.315.1 |
| Container engine | Rancher Desktop 1.25.0, `moby` engine: Docker engine 29.9.2, client 29.9.3-rd, `overlayfs` storage, 4 CPUs and 7.75 GiB; Kubernetes off. WSL 3.0.5.0, kernel 6.18.58.1-microsoft-standard-WSL2 |
| Checkout and workspaces | `D:\a\oxfuzz\oxfuzz` on a Windows drive, with the runner's system-wide `core.autocrlf=true`. Test workspaces under `D:\a\_temp`: the runner's default temporary path is an 8.3 short name, which was not tested as a bind source |
| Image | `oxfuzz/fuzz-sandbox:0.2.3`, `linux/amd64`, image ID `sha256:ec10849bcbd9f5fa25dc688e601570d1741685158612b65c740c9276a246a214`, built on the runner by `scripts/build-sandbox.sh` from Git Bash in 28 min 32 s. Not published; it existed only on that runner |
| Kernel settings seen by a container | `core_pattern` is `\|/wsl-capture-crash %t %E %p %s`; `vm.mmap_rnd_bits` is 32 |
| Provider and approval | None. Nothing here asks a model for anything; every source is a constant in a test file. No approval was requested or given |
| Bounds | Each test's own: one short, bounded fuzz run per engine case, and a ten-minute AFL++ campaign that is stopped on request. One trial of each test |

## Results

| Runbook step | What ran | Result |
| --- | --- | --- |
| 1. Unit tests without Docker | The Windows job of `ci.yml` on the same commit (run 45010360592) | passed |
| Image | `scripts/build-sandbox.sh`: build, compiler probes, offline Semgrep scan with a read-only source mount and a writable output mount, host-side report check | passed |
| 2. Sandbox isolation | `live_isolation`, six tests | 6 passed |
| 3. Source engines | Go native (2), Jazzer.js (2), Jazzer (3), Atheris (2), cargo-fuzz with a vendored crate, MemorySanitizer C++ on libFuzzer and honggfuzz, bisection | 12 passed in 466 s |
| 3. Campaign, Stop and resume | `live_stop_and_resume_keeps_the_queue_of_a_stopped_campaign` (AFL++) | passed |
| 3. Binary-only sessions | `live_qemu_session`, `live_socket_session` (2) | 0 passed, 3 failed |
| 4. Reviewed build, smoke, promotion, campaign, Stop, replay | not run | needs a review provider and a human approval of the sample sources |
| 5. Process loss | not run | same |
| 6. Resume from the command line | not run | needs a promoted harness |

Stop and resume: the campaign was stopped 0.35 s after the request, with 60
queue entries and 25,716 executions read from the engine's files on the
Windows side. No container was left. The resumed 15-second run ended with 70
queue entries and 424,030 executions, and every entry of the stopped campaign
was carried over. This test drives the engine runner directly. It does not
go through the service's review, promotion and run records.

The engine listed no containers at all at the end of the run.

## Failures

**Binary-only sessions.** AFL++ QEMU mode started and ran, but slowly:

| Test | Executions | Rate | Observed |
| --- | --- | --- | --- |
| File input | 4,745 | 115.7 per second | the planted crash was not found in the time allowed |
| TCP server | 4,113 | 102.8 per second | one hang reported on a benign request |
| UDP and stateful exchange | 4,024 | 99.1 per second | one hang reported |

The same tests pass on Linux arm64 at about 3,400 executions per second and
fail the same way on the amd64 image under emulation on an arm64 Mac. The
cause on this host is not established: it may be the nested virtualization
of a hosted runner, QEMU user mode on this kernel, or the amd64 build of the
engine in the image. A Linux x86_64 host would separate these.

**MemorySanitizer, once.** In the earlier run the libFuzzer control of the
MemorySanitizer test reported a crash with no executions measured. In this
run the test passed twice: once in step 3, and once more after
`vm.mmap_rnd_bits` was lowered to 28 in the engine's WSL distribution. A
minimal MemorySanitizer program exited 0 at the default setting. The earlier
failure was not reproduced and its cause is not established, so the lowered
setting is not shown to matter.

## Defects found and fixed on the way

Each was found by a run on this host and fixed before the run recorded here.

- afl-fuzz refused to start because the kernel pipes core dumps, which a
  container cannot change. AFL++ runs now carry
  `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`. The same applies to a Linux
  host that pipes core dumps.
- A file the fuzzer names `id:000000,sig:11,...` is listed on the Windows
  side with U+F03A in place of each colon. Binary-only sessions matched only
  the colon and found no crash files. Seen with Rancher Desktop, with a
  Podman machine and with a plain `dockerd` in WSL.
- The image build from a Windows checkout failed in three places: line
  endings rewritten by git in files the build copies into the image, bind
  sources named as `/d/...` by Git Bash, and a report check that used file
  flags Windows Python does not have.
- Three unit tests assumed a POSIX host. Two pass in the Windows CI job now
  and one, which writes file names with colons, is Unix-only.

## Earlier run

Run 45005294376 on commit `f6cd641e`, same host and engine versions. The
image built and passed its in-container checks, then the host-side report
check failed (fixed above), so the image identity was not recorded. Isolation
passed 6 of 6. Source engines passed 11 of 12; the MemorySanitizer test
failed as described. No binary-only session started (the core-dump setting,
fixed above). The Stop-and-resume test did not exist yet.

Before it, two probe runs (45003179857 and 45004731390) established that WSL
2 works on this runner, that a `dockerd` started by hand inside a WSL
distribution rejects a Windows path as a bind source, and that Rancher
Desktop 1.25.0 and a Podman 6.2.0 machine both accept one. Rancher Desktop
did not start in the first probe because the workflow forced UTF-8 output on
`wsl.exe`; that was a mistake in the workflow.

## Scope and follow-ups

- Not covered: Windows 10 or 11, Docker Desktop, a Hyper-V backend, a
  checkout on a UNC path or inside a WSL distribution, a temporary directory
  with an 8.3 short name, more than one run of each test, Patch-to-Proof,
  syzkaller, the desktop app.
- Open: the binary-only failure; runbook steps 4 to 6; a second engine.
- Evidence: the workflow run's console log and its `windows-qualification-logs`
  artifact (the image build log and one log per step), kept by GitHub for 30
  days. Nothing was copied elsewhere.

## Review

Produced by an AI coding agent on 2026-11-22 from the workflow runs named
above. Not independently reviewed. The maintainer has not approved the sample
sources for steps 4 and 5 and was not asked to for this record.
