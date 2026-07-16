# syzkaller Kernel-Fuzzing Setup

This guide explains how to run a real syzkaller kernel-fuzzing campaign from
hobot_fuzz. Unlike the in-process engines (libFuzzer, AFL++, honggfuzz,
ClusterFuzzLite), syzkaller does not fuzz a single function through a generated
harness. It mutates sequences of system calls and executes them inside a managed
qemu VM whose kernel is built with coverage instrumentation (KCOV). A campaign is
driven by `syz-manager`, which needs three artifacts you provide:

1. a KCOV-instrumented kernel image,
2. a matching rootfs disk image (plus its SSH key), and
3. a `syz-manager` config (hobot_fuzz can synthesize this for you).

> Scope note: a useful bug-finding run needs the artifacts below plus an
> accelerated VM. Under Docker on macOS there is no `/dev/kvm`, so qemu runs in
> TCG emulation (correct but slow). Treat local runs as functional validation;
> run real campaigns on a Linux host with KVM for throughput.

## 1. Prerequisites

### 1.1 Sandbox image with the syzkaller toolchain

The shared sandbox image (`hobot/fuzz-sandbox:0.1.0`) must contain the
syzkaller toolchain (Go 1.26, qemu, and the `syz-*` binaries). The Docker layer
that installs it lives in `docker/sandbox/Dockerfile`.

Build it one of two ways:

- Double-click `rebuild-sandbox-image.command` in the repo root. It builds the
  image for your host architecture and then verifies `syz-manager` is present.
- Or, in the app: open Settings > General > Sandbox and switch the Architecture
  (this forces a rebuild). To force a same-arch rebuild instead, remove the
  image first: `docker image rm hobot/fuzz-sandbox:0.1.0`.

Confirm the toolchain is present:

```bash
docker run --rm hobot/fuzz-sandbox:0.1.0 bash -lc 'which syz-manager && syz-manager --help | head -1'
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
  -e CONFIG_NET_9P \
  -e CONFIG_NET_9P_VIRTIO \
  -e CONFIG_CMDLINE_BOOL

make olddefconfig
make -j"$(nproc)"
```

The kernel image to hand to hobot_fuzz:

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

## 4. Run from hobot_fuzz

### 4.1 Synthesized config (recommended)

1. Open the **Run** view and set **Engine** to `syzkaller (kernel)`.
2. Fill in the **Kernel campaign artifacts** card:
   - Kernel image (bzImage / Image)
   - Rootfs disk image
   - SSH key (rootfs login)
   - VM count (start with 1-2)
3. Set a **Duration** and click **Launch Campaign**.

`hobot_fuzz` validates and copies your artifacts into a unique service-owned
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
  "sshkey": "/syzbench/inputs/id_rsa",
  "syzkaller": "/opt/syzkaller",
  "procs": 2,
  "type": "qemu",
  "vm": {
    "count": 2,
    "kernel": "/syzbench/inputs/kernel",
    "cpu": 2,
    "mem": 2048,
    "qemu_args": "-machine virt,accel=tcg -cpu max"
  }
}
```

Container path mapping (set up automatically):

| Staged artifact    | Container path                         |
| ------------------ | -------------------------------------- |
| Kernel image       | `/syzbench/inputs/kernel` (read-only)  |
| Rootfs disk copy   | `/syzbench/scratch/rootfs.img`         |
| SSH key            | `/syzbench/inputs/id_rsa` (read-only)  |
| Manager config     | `/syzbench/inputs/manager.cfg` (read-only) |
| syzkaller toolchain| `/opt/syzkaller`                       |
| Working directory  | `/syzbench/workdir`                    |

### 4.2 Bring your own manager.cfg (advanced)

If you supply **Existing manager.cfg (optional override)**, `hobot_fuzz` parses
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
- **Extremely slow / no executions** — expected under TCG emulation on
  Docker-on-macOS (no `/dev/kvm`). Use a Linux host with KVM for real throughput.

## 7. References

- syzkaller setup: <https://github.com/google/syzkaller/blob/master/docs/linux/setup.md>
- syzkaller configuration: <https://github.com/google/syzkaller/blob/master/docs/configuration.md>
- KCOV: <https://docs.kernel.org/dev-tools/kcov.html>
- Engine adapter contract: `docs/standards/ENGINE_ADAPTER_STANDARD.md`
