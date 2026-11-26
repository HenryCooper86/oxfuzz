# Binary-Only Fuzzing Design

Status: **implemented as a standalone session, acceptance open** (2026-11-21);
assists, history, progress and triage section added 2026-11-26.
Owners: `hf-service` (`container/binary_only.rs`) for admission, staging, and
the session; `hf-engine` for the AFL++ argv; `hf-runtime` for every process.
Feature flag: `binary-only-fuzzing` (default on). Presentation: `oxfuzz binary`.

## Goal

Fuzz a Linux ELF executable the operator has no source for. There is nothing
to discover, draft, review, or compile, so the path is one sandboxed AFL++
QEMU-mode session over the binary as given, followed by a sandboxed replay of
each saved crash.

## Why a standalone session

The harness lifecycle is built around a source artifact: draft, lint, model
review, compile, smoke, promotion, and a run that stages the exact reviewed
binary. Every one of those steps, and replay, triage, minimization,
`afl-showmap`, and `afl-cmin` after them, assumes an instrumented harness
binary with a libFuzzer-shaped or AFL-shaped entry. A binary-only target has
none of that: there is no source to review, the binary is not instrumented,
there is no sanitizer, and there is no path that creates a target without
discovery. Threading
a second shape through all of those steps would change core contracts for one
capability, so the session stands beside the lifecycle and states plainly
what it does not produce.

## Admission

`ServiceContainer::binary_fuzz` validates before anything is staged or run:

- The binary is a regular file of at most 256 MiB whose first bytes are a
  64-bit little-endian ELF executable or position-independent executable for
  AArch64 or x86-64.
- The binary's machine must be the sandbox image's own (`uname -m` inside the
  sandbox). The image carries `afl-qemu-trace` for its own architecture only;
  another architecture is refused with both names rather than run under a
  missing emulator.
- Duration is between 1 second and 24 hours; the per-execution timeout is
  between 1 ms and one hour.
- The operation is authorized as `Action::RunHarness` and recorded, and holds
  the project's workspace-operation lease. Running a stranger's binary is the
  same act as running a generated harness and passes the same gate.

## Staging

A session owns one directory, `<workspace root>/<project>/.binary/<sha16 of
the binary>/<session uuid>/`:

| Path | Content |
| --- | --- |
| `target` | The binary, mode 0755 |
| `libs/` | Shared objects (`*.so*`) the operator supplied, when any |
| `corpus/` | The operator's seeds as `seed-NNNNN`, or one default seed |
| `out/` | The AFL++ output tree |
| `findings/` | Crash inputs kept from the session |
| `minimized/` | Minimized inputs that replayed as the same crash |
| `crashinfo/` | The replay crash reporter's source and compiled library |
| `desock/` | The socket shim's source and compiled library, socket mode only |
| `report.json` | The session report |

Seeds and libraries are copied as regular files only; symbolic links and
directories are skipped, and the counts are bounded.

## Execution

The fuzz command is the AFL++ adapter's own argv with `-Q` added:

```
afl-fuzz -i /work/corpus -o /work/out -V <secs> -Q -t <ms> -- /work/target @@
```

For a target that reads standard input, and for a server target (below), the
trailing `@@` is dropped. The environment is the AFL++ run environment
(crashing seeds kept as crashes, stats refreshed every second), plus
`QEMU_SET_ENV=LD_LIBRARY_PATH=/work/libs` when libraries were staged, so the
emulated target and not the emulator resolves them.

The session directory is mounted read-only with only `out/` writable, the
network is disabled, capabilities are dropped, and CPU, memory, file size,
and wall-clock are bounded like any other run. A session whose output has no
`fuzzer_stats` failed to start and is reported as an error with the tail of
the fuzzer's output.

## Server targets (`--socket`, `--messages`)

A server reads its input from a connection it accepts or a datagram socket
it binds, not from a file or standard input. In the server modes the session
compiles a small preload shim (`container/binary_desock.c`, the product's
own source) with the image's `clang` into `desock/` in the session
directory, and passes `LD_PRELOAD=/work/desock/oxfuzz_desock.so` to the
emulated process through `QEMU_SET_ENV`, beside the library path when there
is one. The fuzzer delivers each input on standard input, and the shim hands
it to the server.

Stream servers:

- `bind` does nothing, so no port is taken and a privileged port needs no
  capability.
- `listen` replaces the listening descriptor with one that is always ready,
  so `select`, `poll`, and `epoll` return at once.
- The first `accept` returns one end of a socket pair. A helper thread
  writes the input into the other end, signals end of stream, and discards
  what the server sends. The connection is a real stream socket, so `recv`,
  `send`, and readiness calls behave as they do on a network connection.
- A later `accept` ends the process with exit 0: one input is one
  connection.

Datagram servers:

- `bind` of a datagram socket to an IPv4 or IPv6 address replaces the socket
  with one end of a datagram socket pair, keeping its non-blocking and
  close-on-exec flags; the helper thread sends the input into the other end.
- `recvfrom` and `recvmsg` report a loopback IPv4 sender. `sendto` and
  `sendmsg` on the socket succeed and send nothing.
- A datagram socket has no end of stream. When every datagram has been
  read, the shim marks the input used up and shuts the socket's read side,
  which wakes a blocked receive and makes readiness calls fire; the next
  receive that finds nothing (`recvfrom`, `recvmsg`, `recv`, `read`, and
  their fortified forms) ends the process with exit 0.

Without `--messages` a stream server gets the whole input as one byte
stream and a datagram server gets it as one datagram (at most 65,507 bytes).

### Message sequences (`--messages`)

`BinaryInput::SocketMessages` sets `OXFUZZ_DESOCK_MESSAGES=1` for the
emulated process. The shim splits the input on the four bytes `FF FE FD FC`
(`MESSAGE_SEPARATOR`; empty messages are skipped) and sends each message
only after the server has read all of the one before. It learns that from
the kernel (`SIOCOUTQ` on its end of the pair is zero once the peer has
consumed everything), not from a timer, so delivery is the same on every
execution: a stream server that reads one request per `recv` gets one
message per `recv`, and a datagram server gets one datagram per message. A
fixed 20 ms pause is the fallback where that query is not available.

The session stages `desock/messages.dict` holding the separator and passes
it to `afl-fuzz -x`, so mutation adds, moves, and removes whole messages.
Replays and the minimizer run with the same setting.

What the server sends is still discarded. A sequence is a script, not a
conversation: a step that must echo a value the server chose is not
reachable.

The shim opens no network connection and the sandbox has no network.

Limits: programs that `connect` out are not handled; a server that hands
the connection to a forked child hides the child's crash from the fuzzer;
one input is one connection or one datagram socket; a datagram socket
registered with `epoll` before it is bound loses that registration; TLS is
not terminated; and a statically linked binary ignores the preload, which
shows as every seed timing out.

## Findings

Crash files are read from `out/default/crashes/id:*` with file-count and
byte limits. Each is copied to `findings/crash-<sha16>` and replayed under
`afl-qemu-trace` in the sandbox, with the input as the file argument or on
standard input. The emulator runs as a child of a shell: it reports a guest
signal by raising it on itself, which the first process of a container
ignores, so a direct replay of a crash would hang instead of dying. A finding records the signal AFL++ named in the crash file
name and the signal the replay ended with; it is `confirmed` when the two
agree.

### Signature

The replay, and only the replay, preloads a crash reporter
(`container/binary_crashinfo.c`, the product's own source, compiled with the
image's `clang` into `crashinfo/`). On SIGSEGV, SIGBUS, SIGFPE, SIGILL, or
SIGABRT it prints a report on an alternate stack and then dies from the same
signal, so the replay's exit status is unchanged:

```
==ERROR: oxfuzz-crashinfo: SEGV (signal 11) at (/work/target+0x89c), fault address 0x0
    #0 0x550000089c (/work/target+0x89c)
    #1 0x5500000858 (/work/target+0x858)
SUMMARY: oxfuzz-crashinfo: SEGV (signal 11) at (/work/target+0x89c)
```

Frames come from the C library unwinder, which is started when the library
loads so the handler loads nothing, and are printed as module offsets, with
the symbol when the dynamic symbol table has one. `hf_crash::classify` reads
this format as it reads a sanitizer report: the kind from the signal name
and the signature from the kind and the top three frames, which do not
depend on load addresses. An abort is attributed to the first frame outside
the module that raised it, so two failed assertions in different functions
are two findings and not one "abort in libc". A watchdog ends a handler that
cannot finish and keeps the original signal.

The fuzz run does not load the reporter: the report is evidence about one
input and not something to pay for on every execution.

A statically linked target takes no preload, and a target that installs its
own handlers for these signals replaces the reporter. Such a finding keeps
its signal and has no kind, signature, or frames.

### Grouping

A finding whose signature equals an earlier finding's is kept on disk and
marked `duplicate_of` with that finding's input digest; the report counts
`distinct_findings`. A finding without a signature is always distinct:
nothing says it is the same bug as another.

### Minimization

Each confirmed, distinct finding, up to ten per session, is shrunk with
`afl-tmin -Q` under the session's emulated environment (two minutes each).
`afl-tmin` keeps an input while it still crashes, not while it is the same
crash, so the result is replayed and kept in `minimized/` only when it dies
from the same signal and, when the finding has a signature, prints the same
one. Anything else is deleted.

### Filing

`oxfuzz binary-issue <project> --report <session>/report.json --finding
<digest prefix> [--draft]` drafts or files one finding
(`container/binary_issue.rs`). The report must lie inside the project's own
`.binary` directory and be at most 4 MiB; the finding is named by at least
eight hex digits of its input digest. The body states the binary's name and
digest, the architecture, how input was delivered, the signal, the replay
result, the input and minimized-input digests, the signature, and the
frames. It carries the same hidden signature marker a triaged crash carries,
and filing uses the same approval (`PublishFindings`), tracker client, and
durable exactly-once claim, so a signature that was already filed returns
the existing issue. Host paths are not part of the body.

### What a finding is not

There is no sanitizer, so memory errors that do not fault are not seen.
Findings are written to the session directory and the report; they are not
rows of the crash table and do not appear in proof, reports, or SARIF,
because every consumer of that table assumes a target, a harness, and a run
record that a binary-only session does not have. The Triage view reads them
from the session reports instead (Sessions and triage, below).

## Assists (2026-11-26)

### Inspection

`binary_inspect` reads the ELF without running it (bounded, memory-safe
parsing on the host): the undefined dynamic symbols from `.dynsym`, whether
the binary is statically linked (no `PT_INTERP` and no `.dynsym`), and its
printable strings. From the imports it suggests an input mode with its
reasons: `accept` means a stream server, a bound socket read with
`recvfrom`/`recvmsg` a datagram server, a file-opening call a file argument,
and only standard-input readers standard input. A static binary is flagged:
the replay reporter and the socket shim are preloads and do not load into it.

### Dictionary

QEMU mode gets no automatic dictionary, so tokens are taken from the
binary's strings (short keyword- and magic-like strings, bounded) and staged
as `dictionary.dict`, passed with a second `-x` beside the message
separator dictionary. The operator chooses whether to use it. With a
provider, the model may prune and extend the list; its answer is parsed as
AFL dictionary entries and bounded like the heuristic list.

### Seed drafts

With a provider, the model drafts seeds from the binary's name, machine,
input mode, imports and strings, and an optional description from the
operator. They are written under `.binary/<sha16>/seed-drafts/<draft>/` and
shown as previews; the operator decides to use them as the session's seed
directory. Nothing the model proposes is used without that choice.

### Crash explanation

For one finding, the model receives the signal, kind, summary, frames,
replay result, duplicate count and a bounded hex preview of the (minimized)
input, and answers with a likely bug class, what the evidence supports,
severity guidance and next steps. It is shown as model output and never
changes the finding. One explanation is kept per session and finding.

Every prompt above is retained in `binary_llm_drafts` before it is sent
(Engineering Protocol 2.13); text taken from the binary is fenced in the
prompt as untrusted data. Without a store or a provider nothing is sent.

## Sessions and triage (2026-11-26)

- **History.** `binary_sessions` lists the project's sessions from their
  reports (bounded count and size, contained in the project's `.binary`
  directory); `binary_session` opens one. Reports carry `started_at` and
  `finished_at`; older reports read without them.
- **Progress.** While a session runs, the service keeps its stage (staging,
  fuzzing, replaying, minimizing) and reads `fuzzer_stats` on request, so the
  desktop polls executions, speed, edges, corpus, saved crashes and hangs.
- **Continue.** A session may start from an earlier session of the same
  binary (same digest): that session's queue seeds the new corpus, bounded
  like operator seeds.
- **Triage.** The Triage view lists the sessions and their findings with
  signal, kind, confirmation, minimization, frames, the explanation, and
  the issue draft. It reads reports and stored explanations only.

## Out of scope

Binaries for another architecture; persistent, snapshot, and CompCov QEMU
modes; Frida and Unicorn modes; Windows and macOS binaries; network services
beyond the single-connection and single-socket servers above; coverage reports; and
the crash table, proof, and report surfaces for these findings.

## Verification

Unit tests cover ELF admission, the fuzz and replay argv for both input
modes, signal reading from crash names and exit codes, session staging, and
the environment. One ignored live test builds an uninstrumented
planted-crash program in the pinned image and runs a whole session over it
in each input mode: the crash is found, and its replay ends with the same
signal (2026-11-22, linux/arm64, about 3,500 executions per second). A second
ignored live test runs a socket session over a server that binds port 80,
waits in `poll`, and reads its request with `recv`: the planted crash is
found and confirmed, no hang is saved, and a benign request ends with exit 0
at the second `accept` (2026-11-22, about 800 executions per second). The
approval gate and workspace lease in `binary_fuzz` are not part of those
tests, and no run through `oxfuzz binary` is recorded.

Both live tests also assert the findings pipeline (2026-11-22): every
finding has a 64-digit signature and frames in the target, all inputs that
reach one faulting site share one signature and all but the first are marked
duplicates, and the first is minimized to the four bytes that reach the
fault and replays as the same crash, in file, stdin, and socket mode. Unit
tests cover the report reader, grouping, the minimizer argv and environment,
the report round trip, and the issue body, finding lookup, and report path
containment. Filing against a live tracker is not recorded.

A third ignored live test covers the shim beyond one unprompted stream
(2026-11-22, about 360 executions per second each, no hang saved): a UDP
server that blocks in `recvfrom`, checks the sender's family, and answers
with `sendto`; a stateful UDP server on a non-blocking socket behind `poll`
that faults only on a datagram after a separate `HELO`; and a stateful TCP
server that reads one request per `recv` and faults only on a five-byte
request after a five-byte `LOGIN`, which one unprompted stream never
reaches. Each fault is found, confirmed, and signed, several crashing
inputs group into one finding, the minimized input keeps the opening
message and the separator, and an input that does not reach the fault exits
0. The reporter is
exercised on linux/arm64 only; its x86-64 register read is untested.
