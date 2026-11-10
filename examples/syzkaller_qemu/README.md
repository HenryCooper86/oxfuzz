# syzkaller: one Linux QEMU guest

This example tests oxfuzz's kernel-campaign workflow with a Linux/amd64 guest.
It provides a [manager.cfg](manager.cfg) template; you provide the kernel,
root filesystem, and SSH key. There is no planted kernel vulnerability and no
promise of a crash. The initial success criterion is a booted guest with
increasing execution and coverage counters, followed by a controlled stop.

Use a dedicated Linux x86-64 host with working KVM and the oxfuzz desktop app.
The current [support matrix](../../docs/guides/SUPPORT_MATRIX.md) lists dedicated
Linux/KVM acceptance as open. This example's configuration and artifact staging
are tested with inert files; it is not evidence of live VM qualification.

To check the example's staging integration without Docker, kernel artifacts,
or a VM launch, run this from the repository root:

```bash
cargo test -p hf-service --lib community_qemu_example_stages_its_relative_artifacts
```

## Prerequisites

- Docker and the sandbox image built for `linux/amd64`; see
  [installation](../../docs/guides/INSTALL.md).
- A Linux/amd64 kernel built with KCOV and the options needed for syzkaller's
  namespace sandbox, plus a matching bootable rootfs image and its root SSH key.
  Follow the [kernel setup guide](../../docs/guides/SYZKALLER_SETUP.md) and
  [upstream Linux setup instructions](https://github.com/google/syzkaller/blob/master/docs/linux/setup.md).
- Enough disk space for the original image and oxfuzz's disposable copy. The
  service accepts rootfs images up to 32 GiB and separately bounds writable
  growth. Use a small test image.
- A fuzzing policy that enables `syzkaller` and permits the selected duration.
  For this one-VM example, set `fuzzing.sandbox.max_mem_mb` to at least 4096
  and `fuzzing.sandbox.max_cpus` to 2 in your existing configuration. The service
  reserves manager memory and derives guest resources from those limits.

The sandbox image contains syzkaller, QEMU, and the OpenSSH client tools
(`ssh` and `scp`). You do not need to install them
on the host to run this example through oxfuzz. Starting the kernel campaign
does not require generating a userspace harness or calling a model provider.

## Prepare local artifacts

From the repository root, copy your prepared artifacts to the exact names the
configuration references. Replace the three `/path/to/...` source paths:

```bash
mkdir -p examples/syzkaller_qemu/artifacts
cp /path/to/linux/arch/x86/boot/bzImage examples/syzkaller_qemu/artifacts/kernel
cp /path/to/rootfs.img examples/syzkaller_qemu/artifacts/rootfs.img
cp /path/to/rootfs.id_rsa examples/syzkaller_qemu/artifacts/id_rsa
chmod 600 examples/syzkaller_qemu/artifacts/id_rsa
```

Use regular files, not symbolic links. `artifacts/` is ignored by Git, including
the private SSH key. No kernel, disk image, or credential is distributed here.
The `namespace` setting also requires the corresponding kernel namespace
support; use the upstream setup's kernel configuration rather than only enabling
KCOV in an arbitrary production kernel.

## Launch through oxfuzz

1. Open `examples/syzkaller_qemu` as the project in the desktop app. No userspace
   target discovery or harness promotion is needed for a kernel campaign.
2. In **Settings > General > Sandbox**, select `linux/amd64` and verify that
   the sandbox image is ready.
3. Open **Run**, select **syzkaller (kernel)**, and set **VM count** to **1**.
4. In **Existing manager.cfg**, select this directory's `manager.cfg`. Leave
   the individual kernel, rootfs, and key fields empty to use its relative
   `artifacts/` paths. Explicitly selecting those files also works.
5. Set a bounded duration such as **10 minutes**, review the inputs and resource
   settings, and click **Launch Campaign**.

The CLI's `harness`, `run`, and demo-script commands support userspace engines
only; do not pass `--engine syzkaller` to them. This template is intended for
oxfuzz's desktop workflow, not a direct host invocation of `syz-manager`.

The service copies the selected files, rewrites manager paths into its private
staging directory, and runs the manager through `hf-runtime`. The kernel and
key are read-only inputs; the guest uses a writable disposable rootfs copy.
The template requests KVM on the native Linux host. Service policy owns guest
CPU/RAM, process count, and managed paths; editing those values in the template
cannot override that policy. Configuration fields follow the
[upstream manager configuration](https://github.com/google/syzkaller/blob/master/docs/configuration.md).

## Expected results and troubleshooting

Watch the manager log and the **executed** and **coverage** counters in Run.
VM startup can consume much of a short run. A launch that ends without any
executions is not a successful fuzzing test, even if no crashes were reported.
Kernel crashes are optional outcomes; inspect retained reports before claiming
a kernel defect.

- **Missing artifact:** verify the three filenames above and that they are
  regular files under `artifacts/`.
- **Boot or SSH failure:** check that the kernel, rootfs, and key match, and
  that the rootfs is configured for the login described by the upstream guide.
  A minimal Debian rootfs using `systemd-networkd` also needs `udev` to initialize
  its network interface, plus an enabled DHCP configuration and SSH server.
  A guest reaching multi-user mode does not establish that SSH is reachable.
  Rebuild older sandbox images that lack `ssh` or `scp`; the build script now
  checks both tools.
- **Missing KVM or very slow execution:** verify `/dev/kvm` on the dedicated
  Linux host. oxfuzz can normalize the config to emulation when KVM is absent,
  but that does not establish Linux/KVM acceptance.
- **Memory rejection:** raise the configured sandbox memory budget; the service
  refuses a budget that cannot accommodate one guest and the manager.
- **No host dashboard:** the sandbox disables external networking and does not
  publish the manager's HTTP port. Use oxfuzz's streamed log and progress.

This minimal template does not supply a kernel build tree or `vmlinux` for full
symbolization. Do not add arbitrary host paths such as `kernel_obj` to the
config: unmanaged paths are rejected by oxfuzz.

## Stop and clean up

Use **Stop** in the Run view or wait for the duration limit, then verify the
run is no longer active. oxfuzz cleans its transient staging directory and
retains campaign evidence in its configured workspace. Keep the run ID,
configuration, kernel version, and relevant logs when reporting an issue;
never include the SSH private key. Once the campaign has stopped, you may
remove your local `artifacts/` copies if they are no longer needed.
