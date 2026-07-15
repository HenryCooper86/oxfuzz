# Sandbox Runtime Design

Status: **active**. Owner: `hf-runtime`.

## 1. Goal

`hf-runtime` is the only execution boundary for generated harness builds,
fuzzer processes, crash reproduction, minimization, and coverage tooling. The
production adapter launches ephemeral Docker containers with explicit resource,
network, capability, process-count, and wall-clock limits.

## 2. Host Workspace Boundary

Each `DockerRuntime` is constructed with one approved host workspace root.
Before a primary workspace is mounted, read, or written, the runtime resolves
the real filesystem path and proves that it is the root or one of its
descendants. Missing paths are validated through their nearest existing parent.
Parent traversal and symlink escapes fail closed.

The service constructs the production runtime with
`hf_service::workspace_root()`. A caller-controlled project path or target name
must never cause Docker to bind-mount another host directory.

Specialized extra mounts, currently limited to the service-owned Syzkaller
flow, are explicit `SandboxOptions` inputs rather than substitutes for the
primary workspace. The service first copies user-selected inputs into a unique
run staging directory below the approved workspace root. The runtime never
bind-mounts the original kernel image, rootfs, SSH key, or manager config.
Immutable staged inputs are read-only. Only the run's disposable rootfs/scratch
directory and Syzkaller work directory are writable. Staging is bounded before
copy (1 MiB manager config and SSH key, 2 GiB kernel, 32 GiB rootfs), and the
copy verifies a stable source metadata snapshot and exact byte count.

## 3. Execution Profiles

- Harness build: network disabled, capabilities dropped, no new privileges,
  bounded memory/CPU/processes/time, approved workspace mounted.
- Fuzzer run: the same hardened profile with cooperative cancellation and a
  unique container name for reliable teardown.
- Crash triage: the hardened profile plus the minimum ptrace capability needed
  by CASR.
- Syzkaller: the hardened profile with a target platform, staged mounts, and at
  most `/dev/kvm` declared per call. Container networking remains disabled;
  qemu user networking is constrained by that outer boundary. The profile does
  not disable capability dropping or `no-new-privileges`. Its per-file limit
  accommodates the staged rootfs plus 4 GiB, while a live service monitor
  cancels the campaign if combined scratch/workdir growth exceeds 4 GiB, the
  tree exceeds 100,000 entries, or a symlink/special file appears.

## 4. Artifact Integrity

The promoted harness source and binary identify the exact revision approved by
the operator. A full run must verify that revision immediately before launch.
Each smoke or full campaign owns a unique run directory. Its output, logs, and
other evidence are written below that directory rather than a target-wide
shared `out` path. The run record persists the approved source and binary
digests; the service recomputes both immediately before launch and fails closed
on a mismatch.

The primary workspace mount is read-only for fuzzer execution. Only explicit,
service-created corpus and run-output directories are mounted writable. Extra
mounts use structured host/container/read-only fields rather than raw Docker
volume strings. Immediately before launch, the runtime canonicalizes every host
source and rejects anything outside its approved workspace root, including a
directory redirected through a symlink. This prevents an untrusted engine from
rewriting its approved executable, source, configuration, or evidence belonging
to another run.

## 5. Failure Semantics

Spawn errors, invalid workspace paths, and failed forced teardown are sandbox
errors. Once a command has started, its result carries one explicit terminal
outcome: `Completed`, `TimedOut`, or `Cancelled`. Exit status is authoritative
only for `Completed`; callers must branch on the terminal outcome before
interpreting it. A fuzz campaign that exceeds the sandbox headroom is a failed
run, while an explicit user cancellation is retained as cancelled evidence.

Captured stdout and stderr are capped independently. Streaming callbacks may
observe further bounded lines, but retained buffers never grow without limit
and include a truncation marker when data was discarded. A single unterminated
line is bounded as well, so malformed output cannot bypass the cap.

## 6. Tests

- Pure argument tests cover resource, network, capability, device, and mount
  flags without requiring a Docker daemon.
- Filesystem tests prove outside-root paths, parent traversal, and symlink
  escapes are rejected before Docker or host I/O is attempted.
- Mocked process tests cover timeout/cancellation status and bounded output.
- Service contract tests prove every build and run uses `hf-runtime`, the
  promoted-revision gate, digest verification, run-scoped evidence, and the
  read-only execution mount profile.
- Syzkaller staging tests prove configs contain only managed container paths,
  implicit config references cannot escape the config directory, symlinks are
  rejected, and mutating the staged rootfs cannot modify the selected original.
