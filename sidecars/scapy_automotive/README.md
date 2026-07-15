# hobot_fuzz Scapy automotive sidecar

This optional Python package provides bounded automotive packet primitives for
the Rust-first `hobot_fuzz` application. It runs as an operation-scoped JSONL
sidecar inside `hf-runtime`; it is not imported into the Rust process and must
not be launched on the host for a fuzzing operation.

Scapy is used by the offline PCAP decoder. Interface access is never selected
by a JSONL request. The default transport always fails closed. For replay, the
sandbox runtime may inject an already service-approved execution policy; only a
successfully validated `virtual_can` or `physical_bench` policy selects the
lazy python-can transport. Construction does not run a command, import
python-can, or open a bus.

## Pinned dependencies

- Python 3.12.9 in the provided container definition.
- `Scapy==2.7.0` for offline decoding.
- Optional `python-can==4.6.1` through the `can` extra. Its direct runtime
  dependencies are pinned in `requirements-can.txt` for the sidecar image.
- Debian bookworm `iproute2==6.1.0-3` in the sidecar image only.

The optional distribution has license obligations beyond the default MIT Rust
application. Read [LICENSE-DISTRIBUTION.md](LICENSE-DISTRIBUTION.md) before
packaging or shipping it.

## JSONL contract v1

Each stdin line is exactly one request:

```json
{"schema_version":1,"request_id":"cap-1","operation":"capabilities","payload":{}}
```

Each stdout line is exactly one correlated response. No logs, tracebacks, shell
commands, or raw host paths are written to stdout.

```json
{"error":null,"ok":true,"request_id":"cap-1","result":{"data":{},"result":"capabilities"},"schema_version":1,"transcript_sha256":null}
```

The public operation and typed result names match `hf-automotive`:

| Operation | Payload | Successful result tag |
| --- | --- | --- |
| `capabilities` | Empty object | `capabilities` |
| `analyze_capture` | `protocol`, staged `capture`, `limits` | `capture_analysis` |
| `generate_mutations` | `protocol`, staged `source`, seed, count, `limits` | `mutations` |
| `build_replay_plan` | `protocol`, staged `source`, target mode, seed, `limits` | `replay_plan` |
| `execute_replay` | typed mode, replay plan, `limits` | `replay` |

Errors use only the Rust contract's error codes. Error detail values are
strings. Transcript hashes are present only for operations that observed a
canonical transcript.

Artifact requests contain an opaque identifier, SHA-256, and media type. The
runtime supplies fixed sandbox roots out of band:

- `HOBOT_SCAPY_INPUT_ROOT`: read-only staged inputs;
- `HOBOT_SCAPY_OUTPUT_ROOT`: operation-scoped bounded outputs;
- `HOBOT_SCAPY_EXECUTION_CONFIG_JSON`: optional service-approved execution
  policy for the one replay operation in the container.

Artifact identifiers cannot contain a directory separator. Symlinks, hash
mismatches, unknown fields, unbounded data, and absent roots fail closed.

`analyze_capture` writes an immutable canonical transcript artifact with media
type `application/vnd.hobot-fuzz.automotive-transcript+json`. Its JSON value is
the exact Rust hash preimage `[1,"automotive-transcript",events]`, so the file's
SHA-256, returned `transcript.sha256`, typed `transcript_hash`, and response
`transcript_sha256` are identical. `build_replay_plan` accepts this canonical
artifact directly after staged size and digest verification; the legacy
`{"events": [...]}` test shape remains accepted for compatibility.

## Safety policy

The internal validator supports `offline_pcap`, `virtual_can`, and
`physical_bench`. Offline mode rejects all interface and approval fields.
Virtual CAN requires a `vcanN` interface, interface and arbitration-ID
allowlists, UDS service allowlists, and packet/rate/time/size caps. Physical
bench mode additionally requires all of the following:

- `physical_enabled: true` (the default is false);
- a safe interface present in the interface allowlist;
- non-empty arbitration-ID and diagnostic-service allowlists;
- at most 1,000 events, 100 events per second, and 300 seconds;
- approved evidence whose SHA-256 scope matches the entire policy;
- explicit opt-in before any dangerous UDS service is allowed.

ECU reset, security access, communication control, writes, routine control,
upload/download, transfer, and DTC-setting services are denied by default.
Validation occurs before the injected transport receives a call. Tests use
only fake transports and never open an interface.

The SocketCAN boundary is intentionally narrow:

- a virtual policy accepts only an exact validated `vcanN` name and may run
  only `/usr/sbin/ip link show`, `link add ... type vcan`, and `link set ... up`
  as fixed argv with `shell=False` and a two-second process timeout;
- a physical policy never configures its interface;
- the bus is opened lazily for the one validated interface, with loopback
  reception disabled;
- send and receive validate the interface, arbitration-ID allowlist,
  classic-CAN/CAN-FD payload size, frame flags, and a one-second I/O deadline;
- replay sleeps occur only after the full plan budget is validated, each sleep
  is capped at five seconds, and unit tests inject a non-blocking sleeper.

Virtual setup needs only the sandbox's typed `NET_ADMIN` and `NET_RAW`
capabilities. Physical replay needs `NET_RAW`; it does not receive a setup
command path. Neither mode is enabled by installing this sidecar.

Response parsing and state-signature helpers are internal adapter primitives;
they are not additional public service authorities. State signatures are
protocol-state feedback and must not be reported as source coverage.

## Local verification

Use an environment that already contains the pinned development dependencies:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
ruff check --no-cache src tests
```

The real Scapy test writes and reads a temporary PCAP only. It does not open a
network or CAN interface. Building or running the provided container is not
part of the default test suite.
