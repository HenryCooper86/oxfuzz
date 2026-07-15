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
primary workspace. They should be read-only unless the external tool requires a
documented writable artifact.

## 3. Execution Profiles

- Harness build: network disabled, capabilities dropped, no new privileges,
  bounded memory/CPU/processes/time, approved workspace mounted.
- Fuzzer run: the same hardened profile with cooperative cancellation and a
  unique container name for reliable teardown.
- Crash triage: the hardened profile plus the minimum ptrace capability needed
  by CASR.
- Syzkaller: an explicit exceptional profile for qemu/KVM, with platform,
  devices, mounts, and network declared per call.

## 4. Artifact Integrity

The promoted harness source and binary identify the exact revision approved by
the operator. A full run must verify that revision immediately before launch.
The runtime should evolve toward separate immutable harness/source mounts and
writable corpus/output mounts so an untrusted engine cannot rewrite its own
approved executable or evidence.

## 5. Failure Semantics

Required behavior: spawn errors, invalid workspace paths, wall-clock expiry,
and forced teardown are sandbox failures, not successful command exits. User
cancellation is reported distinctly by the service run lifecycle, and captured
output is bounded so an untrusted process cannot exhaust host memory through
stdout or stderr.

The current Docker adapter still needs distinct timeout/cancellation results
and bounded output capture; until those are implemented, callers must not treat
its synthesized exit status as authoritative after forced teardown.

## 6. Tests

- Pure argument tests cover resource, network, capability, device, and mount
  flags without requiring a Docker daemon.
- Filesystem tests prove outside-root paths, parent traversal, and symlink
  escapes are rejected before Docker or host I/O is attempted.
- Mocked process tests cover timeout/cancellation status and bounded output.
- Service contract tests prove every build and run uses `hf-runtime` and the
  promoted-revision gate.
