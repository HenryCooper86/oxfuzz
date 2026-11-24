# syzkaller Kernel-Fuzzing Setup

This guide explains how to run a real syzkaller kernel-fuzzing campaign from
oxfuzz. Unlike the three userspace engines (AFL++, honggfuzz, and libFuzzer),
syzkaller does not fuzz a single function through a generated
harness. It mutates sequences of system calls and executes them inside a managed
qemu VM whose kernel is built with coverage instrumentation (KCOV). A campaign is
driven by `syz-manager`, which needs three artifacts you provide:

1. a KCOV-instrumented kernel image,
2. a matching rootfs disk image (plus its SSH key), and
3. a `syz-manager` config (oxfuzz can synthesize this for you).

> Scope note: a useful bug-finding run needs the artifacts below plus an
> accelerated VM. Under Docker on macOS there is no `/dev/kvm`, so qemu runs in
> TCG emulation (correct but slow). Treat local runs as functional validation
> (section 4.3 says what one looks like); run real campaigns on a Linux host
> with KVM for throughput (section 4.4).

## 1. Prerequisites

### 1.1 Sandbox image with the syzkaller toolchain

The shared sandbox image (`oxfuzz/fuzz-sandbox:0.2.4`) must contain the
syzkaller toolchain (Go 1.26, qemu, and the `syz-*` binaries). The Docker layer
that installs it lives in `docker/sandbox/Dockerfile`.

Build it one of two ways:

- Double-click `rebuild-sandbox-image.command` in the repo root. It builds the
  image for your host architecture and then verifies `syz-manager` is present.
- Or, in the app: open Settings > General > Sandbox and switch the Architecture
  (this forces a rebuild). To force a same-arch rebuild instead, remove the
  image first: `docker image rm oxfuzz/fuzz-sandbox:0.2.4`.

Confirm the toolchain is present:

```bash
docker run --rm oxfuzz/fuzz-sandbox:0.2.4 bash -lc 'which syz-manager && syz-manager --help | head -1'
```

### 1.2 Architecture matching

The kernel you build must match the sandbox Architecture selected in
Settings > General:

- `linux/arm64` (Apple Silicon native) builds and runs `qemu-system-aarch64`.
- `linux/amd64` (x86_64) builds and runs `qemu-system-x86_64`.

A non-host arch runs under emulation. Keep the kernel arch, the rootfs arch, and
the sandbox Architecture consistent.

## 2. Build a KCOV-instrumented kernel

These steps follow the upstream syzkaller setup guide
(<https://github.com/google/syzkaller/blob/master/docs/linux/setup.md>); run them
on a Linux build host (or a Linux VM) with the usual kernel build tools
(`flex bison bc libelf-dev libssl-dev` and a C toolchain).

```bash
git clone --depth=1 https://github.com/torvalds/linux.git
cd linux
make defconfig
make kvm_guest.config

# Enable the options syzkaller needs (KCOV coverage + debug info + sandboxing).
./scripts/config \
  -e CONFIG_KCOV \
  -e CONFIG_KCOV_INSTRUMENT_ALL \
  -e CONFIG_KCOV_ENABLE_COMPARISONS \
  -e CONFIG_DEBUG_INFO_DWARF4 \
  -e CONFIG_KASAN \
  -e CONFIG_KASAN_INLINE \
  -e CONFIG_CONFIGFS_FS \
  -e CONFIG_SECURITYFS \
  -e CONFIG_DEBUG_FS \
  -e CONFIG_BINFMT_MISC \
  -e CONFIG_NET_9P \
  -e CONFIG_NET_9P_VIRTIO \
  -e CONFIG_CMDLINE_BOOL

make olddefconfig
make -j"$(nproc)"
```

`CONFIG_BINFMT_MISC` is built in by the x86 default configuration but not by
the arm64 one. The rootfs below mounts `binfmt_misc` at boot; without the
option that mount fails, the guest stops in emergency mode before `sshd`
starts, and the campaign reports that it cannot connect to the VM.

On arm64 the kernel command line option is a string, not `CONFIG_CMDLINE_BOOL`:
use `./scripts/config --set-str CONFIG_CMDLINE "console=ttyAMA0"`.

The kernel image to hand to oxfuzz:

- `linux/amd64`: `arch/x86/boot/bzImage`
- `linux/arm64`: `arch/arm64/boot/Image` (use this file as the "Kernel image")

## 3. Build a rootfs image

syzkaller ships a helper that produces a minimal Debian rootfs plus an SSH key:

```bash
# from your syzkaller checkout (or clone google/syzkaller)
sudo apt-get install -y debootstrap
cd tools
./create-image.sh            # add: --arch arm64   when targeting linux/arm64
```

This produces (names vary by distro/arch):

- `bullseye.img`  -> the "Rootfs disk image"
- `bullseye.id_rsa` -> the "SSH key (rootfs login)"

## 4. Run from oxfuzz

A campaign starts from the desktop app or from the command line. Both call
the same service operation, ask for the same approval, and record the same
run.

From the command line:

```bash
oxfuzz kernel <project> --kernel-image arch/arm64/boot/Image \
  --rootfs bullseye.img --ssh-key bullseye.id_rsa --vms 1 --duration 1h
```

`<project>` is the directory the run is recorded against. Progress lines
from `syz-manager` print as they arrive; the command ends with the programs
executed, the coverage reached, the crash count, and the `oxfuzz triage`
command for the run. `--manager-cfg` takes an existing configuration as in
section 4.2, `--arch` selects `amd64` or `arm64`, and `--json` prints the
result as JSON with progress on standard error. The REST API does not start
kernel campaigns.

### 4.1 Synthesized config (recommended)

In the desktop app:

1. Open the **Run** view and set **Engine** to `syzkaller (kernel)`.
2. Fill in the **Kernel campaign artifacts** card:
   - Kernel image (bzImage / Image)
   - Rootfs disk image
   - SSH key (rootfs login)
   - VM count (start with 1-2)
3. Set a **Duration** and click **Launch Campaign**.

`oxfuzz` validates and copies your artifacts into a unique service-owned
staging directory. It writes a qemu `manager.cfg` for the selected architecture,
then runs
`timeout <duration> syz-manager -config=...`. Live coverage / executed / crash
counts stream to the UI; the raw `syz-manager` log appears below.

The selected rootfs is never mounted writable. Each campaign runs against a
disposable copy, while the kernel, SSH key, and manager config are mounted
read-only. The container has no external Docker network and retains the normal
capability-drop and no-new-privileges policy. On a compatible Linux host,
`/dev/kvm` is the only additional device passed through.

For host-disk safety, manager configs and SSH keys are limited to 1 MiB,
kernels to 2 GiB, and rootfs images to 32 GiB. A campaign may grow its combined
scratch/workdir trees by at most 4 GiB and 100,000 entries. Exceeding either
limit, or creating a symlink/special entry there, cancels the campaign and
returns a sandbox error. VM count and manager processes are clamped to four,
even when a larger value appears in an existing config.

The synthesized config looks like this (arm64 example):

```json
{
  "target": "linux/arm64",
  "http": "127.0.0.1:56741",
  "workdir": "/syzbench/workdir",
  "image": "/syzbench/scratch/rootfs.img",
  "sshkey": "/syzbench/key/id_rsa",
  "syzkaller": "/opt/syzkaller",
  "procs": 2,
  "type": "qemu",
  "vm": {
    "count": 2,
    "kernel": "/syzbench/inputs/kernel",
    "cpu": 2,
    "mem": 2048,
    "qemu_args": "-machine virt,accel=tcg -cpu max",
    "cmdline": "net.ifnames=0"
  }
}
```

Container path mapping (set up automatically):

| Staged artifact    | Container path                         |
| ------------------ | -------------------------------------- |
| Kernel image       | `/syzbench/inputs/kernel` (read-only)  |
| Rootfs disk copy   | `/syzbench/scratch/rootfs.img`         |
| SSH key            | `/syzbench/inputs/id_rsa` (read-only); syz-manager uses a private copy at `/syzbench/key/id_rsa` inside the container |
| Manager config     | `/syzbench/inputs/manager.cfg` (read-only) |
| syzkaller toolchain| `/opt/syzkaller`                       |
| Working directory  | `/syzbench/workdir`                    |

### 4.2 Bring your own manager.cfg (advanced)

If you supply **Existing manager.cfg (optional override)**, `oxfuzz` parses
and rewrites it instead of mounting its parent directory. The config must use
`"type": "qemu"`. Its `image`, optional `sshkey`, and `vm.kernel` references
may be relative to the config or point to regular files inside the config's
directory. Implicit references outside that directory and symlinks are rejected.
You may explicitly select kernel, rootfs, or key files in the artifact fields to
override those references; explicit overrides are still copied into staging.

The service fixes `syzkaller`, `workdir`, `image`, `sshkey`, and `vm.kernel` to
the managed container locations shown above. Any other absolute or
parent-traversing path in the supplied JSON is rejected so the config cannot
expose undeclared host content.

### 4.3 Running without KVM

On a host without `/dev/kvm` (Docker on macOS, most containers) the guest
runs under qemu's TCG emulation. oxfuzz selects it by itself: the
synthesized config uses `accel=tcg` and `-cpu max`, a supplied config has
`accel=kvm` and `-cpu host` rewritten, and the campaign log says so. The
campaign is the same; it is far slower.

Give the sandbox more than its default budget. The default (`max_cpus = 1`,
`max_mem_mb = 2048`) leaves the one guest a single virtual CPU and 1,536 MiB,
which is too little for an emulated kernel with KASAN:

```toml
[fuzzing.sandbox]
max_cpus = 2
max_mem_mb = 6144
```

Use a duration of 30 minutes or more. Recorded on an Apple Silicon Mac
(Linux 6.12 arm64 with KCOV and KASAN, one guest with two virtual CPUs and
5,632 MiB): the guest answered SSH after about five minutes, syzkaller's
machine check finished after about ten, and the first coverage was reported
after about eighteen. Until then the counters show programs executed and no
coverage; a campaign that ends in that window is recorded with zero coverage
and `oxfuzz kernel` says that it tested nothing. The
[acceptance record](../acceptance/kernel-emulated-2026-11-22.md) has the
numbers.

syzkaller lengthens its timeouts for an emulated guest when the `vm` section
contains the text `-accel tcg`. oxfuzz does not write that spelling: in the
recorded comparison it produced no coverage in a 30-minute campaign. If you
supply your own config and want syzkaller's behavior, write `-accel tcg` in
its `qemu_args` yourself; oxfuzz leaves it alone.

### 4.4 Running with KVM

On a Linux host whose `/dev/kvm` is a character device, with a sandbox
Architecture equal to the host's, oxfuzz passes `/dev/kvm` into the campaign
container and the synthesized config uses `accel=kvm` and `-cpu host`. The
campaign log says "qemu uses KVM acceleration". Nothing else about the
container changes: all capabilities stay dropped, `no-new-privileges` stays
on, there is no container network, and `/dev/kvm` is the only device. The
runtime refuses any other device. The Docker daemon passes the node, so the
user who runs oxfuzz does not need to be in the `kvm` group; the user does
need to run Docker (rootful Docker; rootless Docker was not tested).

Recorded on two GitHub-hosted `ubuntu-24.04` runners (Linux 6.12 x86_64
with KCOV and KASAN, one guest with two virtual CPUs and 5,632 MiB, the
budget of section 4.3): syzkaller's machine check finished 32 and 51
seconds after launch, coverage was reported within the next minute, and the
30-minute campaigns executed 143,404 and 48,785 programs. The guest booted
about eight times faster than under TCG on the same runner.
`.github/workflows/kernel-kvm.yml` repeats the run on demand, and the
[acceptance record](../acceptance/kernel-kvm-2026-11-24.md) has the
identities and the evidence.

## 5. Watch progress

`syz-manager` still creates its HTTP dashboard inside the container, but the
campaign container has networking disabled and does not publish the dashboard
to the host. Progress needed by the application is streamed from manager output.
Do not bypass the service staging boundary with a hand-written `docker run` for
production campaigns.

## 6. Troubleshooting

- **"syz-manager not found in the sandbox image"** — the image predates the
  toolchain layer. Rebuild it (section 1.1).
- **`qemu-system-aarch64: No machine specified`** — the qemu config lacks a
  machine type. The synthesized config sets `-machine virt,accel=tcg` for arm64
  and `-machine pc,accel=tcg` for amd64; if you provide your own config, set the
  equivalent in `qemu_args`.
- **`boot error` / `<empty boot output>`** — the kernel did not boot. Check that
  the kernel arch matches the sandbox Architecture, that KCOV options are
  enabled, and that the rootfs + SSH key correspond to that kernel.
- **`failed to connect to the VM` after the guest prints `Emergency Mode`** —
  a mount listed in the rootfs `/etc/fstab` failed, most often `binfmt_misc`
  on an arm64 kernel built without `CONFIG_BINFMT_MISC` (section 2).
- **`can't ssh into the instance` although the guest reaches a login prompt** —
  the guest has no network address. A rootfs from `create-image.sh` configures
  `eth0`, and without `net.ifnames=0` on the kernel command line udev renames
  the interface. The synthesized config passes that option; a config of your
  own needs `"cmdline": "net.ifnames=0"` in its `vm` section on arm64.
- **`failed to read config file: ... permission denied`** — the campaign
  container could not read its staged inputs. oxfuzz releases before
  2026-11-24 staged them with owner-only modes, which the container's root
  user cannot read on a native Linux Docker host; update oxfuzz.
- **Extremely slow** — expected under TCG emulation on Docker-on-macOS (no
  `/dev/kvm`): see "Running without KVM" in section 4. Use a Linux host with
  KVM for real throughput.

## 7. References

- syzkaller setup: <https://github.com/google/syzkaller/blob/master/docs/linux/setup.md>
- syzkaller configuration: <https://github.com/google/syzkaller/blob/master/docs/configuration.md>
- KCOV: <https://docs.kernel.org/dev-tools/kcov.html>
- Engine adapter contract: `docs/standards/ENGINE_ADAPTER_STANDARD.md`
