# Kernel campaign with KVM, 2026-11-24

Outcome: **passed as functional validation on hosted Linux x86_64 runners
with `/dev/kvm`**. Two syzkaller campaigns started through the service
operation that `oxfuzz kernel` and the desktop app call booted a KCOV and
KASAN kernel in a KVM-accelerated qemu guest inside the `hf-runtime`
sandbox, executed programs, reported coverage, kept a corpus, and were
recorded as finished runs. This is one kernel, one guest per campaign, two
30-minute campaigns on two shared runners. It is a first KVM record, not a
throughput qualification, and a clean bounded run says nothing about the
absence of kernel bugs.

## Identity and limits

| Item | Tested value |
| --- | --- |
| Candidate source | Campaign 4: commit `3ea909a725d17b69b5a9a6082f6bb5efc2d2d70e`; campaign 3: commit `cf26fb40ee1896ee18a14e376724ab72476e1e3a`. Both on the temporary branch `kvm-run-20261124` (since deleted). Commit `3ea909a7` differs from the integrated change only by the workflow's temporary `push` trigger; `cf26fb40` also used the earlier boot-comparison marker described below |
| Runs | Campaign 4: <https://github.com/HenryCooper86/oxfuzz/actions/runs/45358003693>; campaign 3: <https://github.com/HenryCooper86/oxfuzz/actions/runs/45346836012>. Workflow `.github/workflows/kernel-kvm.yml`; evidence artifacts `kernel-kvm-evidence-<run>-1` (logs, staged `manager.cfg`, identities, hashes, `docker inspect` summary; no kernel, rootfs or key) |
| Operation | `ServiceContainer::run_syzkaller_observed_with_environment`, driven by the ignored live test `live_syzkaller_boots_executes_programs_and_records_the_campaign` (`crates/hf-service/src/container/run.rs`); the `oxfuzz kernel` command line itself was not run |
| Hosts | GitHub-hosted `ubuntu-24.04` runners, Ubuntu 24.04.5 LTS, 4 CPUs, Docker 28.0.4 (rootful). Campaign 4: image `ubuntu24` 20261116.376.1, host kernel 7.0.0-1017-azure, AMD EPYC 7763 (`svm`), 15,983 MiB. Campaign 3: image `ubuntu24` 20261116.133.1, host kernel 7.0.0-1014-aws, Intel Xeon 6975P-C (`vmx`), 15,701 MiB |
| KVM on the host | A udev rule set `/dev/kvm` to mode 0666 for the runner user's own probe; `KVM_GET_API_VERSION` returned 12 and `KVM_CREATE_VM` returned a VM descriptor, on the host and inside a container with the campaign's hardening and `--device /dev/kvm`; the same container without the device had no `/dev/kvm` |
| Runtime | `hf-runtime` image `oxfuzz/fuzz-sandbox:0.2.3` built on each runner with `scripts/build-sandbox.sh` (run as root, see failed attempts), amd64, not published. Image ID `sha256:c59934d2dacc61803fed0a1fc864f8ecbbc875b62781cddb1105261ca305e886` (campaign 4), `sha256:7e2080413373a8becd486b30c0934a0535c0cc4612d5b7bf90d37ee8e3305d35` (campaign 3) |
| Engine | syzkaller commit `27a8bd60fa3a186e2b15eb9c4706689e3d2be6f2`, QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18), `-machine pc,accel=kvm -cpu host` |
| Kernel | Linux 6.12.118 x86_64 from `linux-6.12.118.tar.xz` (SHA-256 `08308460320e852ac0745b2be3c7ae1cd81bdad713506ed7d817ba1ec9e1a5a5`, as listed in kernel.org's `sha256sums.asc`), `defconfig` plus `kvm_guest.config` with the options of [the setup guide](../guides/SYZKALLER_SETUP.md) (KCOV with comparisons, KASAN inline, DWARF4 debug info, `BINFMT_MISC`), GCC 13.3.0; `bzImage` SHA-256 `ad7a8178aeb847737642e0b6e97bc5599766811d83c9fbd395f497fd63e39148`, `.config` SHA-256 `fd124d658ee7fdd01719a9c388de49949678f3532c6d53330282f307a59a2913`; built in 636 s on 4 CPUs by run 45338249719 and restored from the Actions cache by both campaigns |
| Guest | Debian bookworm rootfs from syzkaller's `tools/create-image.sh` at the engine commit (script SHA-256 `be1588c107f8fa096cdd8c81eefddc46d789ea83ab3f082ba1c5b89b4f2ddf34`), 2 GiB ext4. The SSH key is generated on the runner for each run and not uploaded, so the image differs per run: SHA-256 `b15a66a1ab49c20b87253d722d6de057842bb0879b43701d24bd93c5d932eba4` (campaign 4), `395d8a515314be1be75dec762ba1bd4ab3116ceab0a70c2ca005f8f3354271d3` (campaign 3) |
| Bounds | Sandbox budget 2 CPUs and 6,144 MiB (`[fuzzing.sandbox]`), the emulated record's values so the two compare; one guest with 2 virtual CPUs and 5,632 MiB; `procs` 6; no container network |
| Approval | None requested: the test constructs the service without an approval handler, and `HF_AUTO_APPROVE` was not set. An operator run goes through the `oxfuzz kernel` approval. No provider or secret was used |

### Proof that KVM was used

- The staged `manager.cfg` had `"qemu_args": "-machine pc,accel=kvm -cpu host"`,
  and the campaign log said "qemu uses KVM acceleration (/dev/kvm passed
  through)". qemu does not fall back to TCG when `accel=kvm` fails.
- The guest's qemu process, sampled from the host shortly after launch:
  `qemu-system-x86_64 -m 5632 -smp 2 ... -machine pc,accel=kvm -cpu host ...
  -hda /syzbench/scratch/rootfs.img -snapshot -kernel /syzbench/inputs/kernel
  -append root=/dev/sda console=ttyS0 net.ifnames=0`. Its open descriptors
  included `/dev/kvm`, `anon_inode:kvm-vm`, and `anon_inode:kvm-vcpu:0` and
  `:1` (both campaigns).
- The campaign container, from `docker inspect` (both campaigns):
  `Privileged` false, `CapAdd` none, `CapDrop` `ALL`, `SecurityOpt`
  `no-new-privileges`, `NetworkMode` `none`, `Devices` only `/dev/kvm`
  (`rwm`), no device cgroup rules, 2 CPUs, 6 GiB, PID limit 512, read-only
  mounts for `/work` and `/syzbench/inputs`, writable mounts only for
  `/syzbench/scratch` and `/syzbench/workdir`, the image's user (root).
- Boot comparison: the same kernel and rootfs booted directly by qemu in the
  same hardened profile, 2 virtual CPUs and 5,632 MiB. In campaign 4's run
  the guest reached systemd's multi-user target 16 s after `docker run` with
  `accel=kvm -cpu host` and 126 s with `accel=tcg -cpu max`; by the guest's
  clock init started at 8.8 s and 73.1 s. In campaign 3's run, by the guest's
  clock, init started at 3.7 s and the serial getty at 6.9 s with KVM,
  against 39.0 s and 76.8 s under TCG. Campaign 3's wall-clock marker, the
  login prompt, was not usable: the prompt has no newline and `docker logs`
  held it back, so that step reported no prompt for KVM and 1,320 s for TCG.
  The workflow now times the multi-user target.

## Results

Times are from the launch of syz-manager.

| Campaign | Length | Machine check done | First corpus entry | Programs | Corpus | Edges | Crashes | Outcome |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4 (AMD EPYC 7763) | 1,800 s | 51 s | by 77 s | 48,785 | 2,118 | 44,314 | 0 | passed |
| 3 (Intel Xeon 6975P-C) | 1,800 s | 32 s | by 40 s | 143,404 | 4,826 | 59,982 | 1 syz-manager report (`SYZFAIL: posix_spawnp failed`, not reproduced); service count 0 | passed |

Both runs were recorded with status `Done`, syz-manager was stopped by the
campaign timer (exit code 124), and `corpus.db` was retained under the run's
output directory inside the test's temporary workspace root. syz-manager
reported about 27 programs per second in campaign 4 and about 84 in
campaign 3; the two runners differ in CPU and cloud, and a hosted runner's
nested virtualization is shared, so neither figure is a throughput claim.
The emulated arm64 record executed 1,698 programs in the same length and
budget. Coverage figures between this record and the emulated one are not
comparable: the architectures, kernel configurations and coverage points
differ.

In campaign 3, at 27 min 55 s, syz-manager reported `VM 0: crash: SYZFAIL:
posix_spawnp failed`, an executor failure inside the guest rather than a
kernel report, and used the only VM to try to reproduce it for the rest of
the campaign; programs stopped increasing 35 s later. The reproduction did
not succeed. The service's crash counter stayed at 0 because the status line
of this syzkaller version carries no crash count (see scope).

## Failed and withdrawn attempts

| Run | Difference | Result |
| --- | --- | --- |
| [45338249719](https://github.com/HenryCooper86/oxfuzz/actions/runs/45338249719) | `scripts/build-sandbox.sh` run as the runner user | The image built; its Semgrep check failed with `rm: cannot remove '/work/output/semgrep.json': Permission denied`. On native Linux Docker the container's root user, with every capability dropped, cannot write the runner user's 0700 temporary directory. The workflow now runs the script as root; the script is unchanged. The kernel built here was reused by the later runs. Cancelled after the failure |
| [45342892924](https://github.com/HenryCooper86/oxfuzz/actions/runs/45342892924) | Staging as it was on `main` | `syz-manager` exited at once: `failed to read config file: open /syzbench/inputs/manager.cfg: permission denied`. The staged files were 0400 and owned by the runner user, which the container's root user cannot read without `CAP_DAC_OVERRIDE`. The run was recorded `Failed`. Fixed in the service (staging modes, a private SSH key copy, output made removable on exit); cancelled during the boot comparison |

The emulated record did not meet either problem because OrbStack maps file
ownership between the Mac and the container.

## Scope and follow-ups

Not established: throughput qualification (two 30-minute campaigns on
shared hosted runners); more than one guest; a kernel crash found,
reproduced and triaged; the service's crash count for this syzkaller version
(`parse_syzkaller_status` reads the `coverage=` and `exec total=` status
line and reports 0 crashes, so `SyzkallerSummary.crashes` and the live
counter miss crashes that syz-manager reports; the crash directory itself is
retained); the cause of the guest's `SYZFAIL: posix_spawnp failed`; a
supplied `manager.cfg`; the desktop app's launch path; the `oxfuzz kernel`
command line end to end; Stop and resume, and the root-owned files a
campaign removed with `docker rm -f` can leave in its staging directory; a
self-hosted Linux machine and rootless Docker; the userspace engines on
native Linux Docker, whose workspace mounts may meet the same ownership
problem that the kernel staging had (not checked); a repeat of the emulated
macOS run with the changed staging.

Operator and reviewer: produced by an AI coding agent in the maintainer's
session on 2026-11-24; not independently reviewed.
