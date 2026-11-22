# Kernel campaign under emulation, 2026-11-22

Outcome: **passed as functional validation on local macOS arm64, without
KVM**. A syzkaller campaign started through the service operation that
`oxfuzz kernel` and the desktop app call booted a KCOV and KASAN kernel in a
sandboxed qemu guest, executed programs, reported coverage, kept a corpus,
and was recorded as a finished run. This is one host, one kernel, one guest
and emulated execution. It is not a throughput record, not a KVM record, and
a clean bounded run says nothing about the absence of kernel bugs.

## Identity and limits

| Item | Tested value |
| --- | --- |
| Candidate source | Uncommitted working tree on `feat/msan-tsan-sanitizers`, on top of commit `ffe2cfef`; no patch digest was taken, so this record does not identify an exact revision |
| Operation | `ServiceContainer::run_syzkaller_observed_with_environment`, driven by the ignored live test `live_syzkaller_boots_executes_programs_and_records_the_campaign` (`crates/hf-service/src/container/run.rs`); the `oxfuzz kernel` command line itself was not run |
| Runtime | macOS 27.2.1 arm64 host; Docker 29.8.2 in an OrbStack Linux VM with no `/dev/kvm`; `hf-runtime` image `oxfuzz/fuzz-sandbox:0.2.3`, image ID `sha256:4b27346ee252093a6b0b79c8eddc9bb76d253de7ee9f12074a3ab98f532d6330` (built locally, not published) |
| Engine | syzkaller commit `27a8bd60fa3a186e2b15eb9c4706689e3d2be6f2`, QEMU 8.2.2, `-machine virt,accel=tcg -cpu max` |
| Kernel | Linux 6.12.118 arm64, `defconfig` plus `kvm_guest.config` with the options of [the setup guide](../guides/SYZKALLER_SETUP.md) (KCOV, KASAN inline, `BINFMT_MISC`); `Image` SHA-256 `06927c9f3a7699aa42b2d1fbfe94004bd9b5c28a34a103d42ce8655e7551b6b8` |
| Guest | Debian bookworm rootfs built with `debootstrap`, 2 GiB ext4, SHA-256 `7c6874d3a115cf6995cec7ca606b3f283bf5006c8280fb52b0f44008552d2eb2` |
| Bounds | Sandbox budget 2 CPUs and 6,144 MiB (`[fuzzing.sandbox]`); one guest with 2 virtual CPUs and 5,632 MiB; `procs` 6; no network outside the container |
| Approval | None requested: the test constructs the service without an approval handler. An operator run goes through the `oxfuzz kernel` approval |

## Results

| Campaign | Length | Machine check done | First corpus entry | Programs | Corpus | Edges | Crashes | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 5 (final tree) | 1,800 s | 9 min 44 s | 18 min 20 s | 1,698 | 30 | 3,634 | 0 | passed |
| 2 | 1,200 s | 10 min 12 s | about 17 min | 1,105 | 8 | 1,670 | 0 | passed |

Both runs were recorded with status `Done`, syz-manager was stopped by the
campaign timer (exit code 124), and `corpus.db` was retained under the run's
output directory. In campaign 5 that directory was inside the test's
temporary workspace root; campaign 2 predates that isolation and wrote to
the operator's application workspace.

## Failed and withdrawn attempts

| Campaign | Difference | Result |
| --- | --- | --- |
| 1 | Default sandbox budget (1 virtual CPU, 1,536 MiB); kernel command line without `net.ifnames=0` | The guest booted but had no network address: `can't ssh into the instance`. 0 programs. The run was still recorded as `Done`. Fixed by adding the option to the synthesized config |
| 3 | `-machine virt -accel tcg` (the spelling for which syz-manager lengthens its timeouts tenfold), `procs` 6, 1,200 s | Machine check after 12 min 54 s; no seed program finished in the remaining 7 minutes. 647 programs (all from the machine check), 0 edges |
| 4 | `-accel tcg`, `procs` 2, 1,800 s | Machine check after 14 min; 990 programs, no corpus entry and 0 edges in the remaining 16 minutes |

Campaigns 3 and 4 ran while lint jobs used other host cores, so their boot
times are not comparable with 2 and 5. Neither recorded a corpus entry in a
window where 2 and 5 did. The cause was not isolated; the spelling and the
process count were returned to their previous values and the comparison is
kept in the source comment and in `.claude/plans/kernel-cli-and-bazel-profile-20261122.md`.

An earlier kernel built from the guide as it then stood stopped in emergency
mode: the arm64 default configuration does not build `BINFMT_MISC`, which
the rootfs mounts. The guide now enables it.

## Scope and follow-ups

Not established: KVM acceleration and any campaign on a Linux host with
`/dev/kvm`; throughput (about one program per second here); amd64 guests;
more than one guest; a crash found, reproduced and triaged; a supplied
`manager.cfg`; the desktop app's launch path; the `oxfuzz kernel` command
line end to end; Stop and resume. A campaign that ends before the first
corpus entry is recorded as `Done` with zero coverage; the command line now
says that such a run tested nothing, and the service record does not
distinguish it.

Operator and reviewer: produced by an AI coding agent in the maintainer's
session on 2026-11-22; not independently reviewed.
