# AFL++: length-prefixed packet parser

A dependency-free C project for testing oxfuzz with AFL++. The entry point is
`packet.c::parse_packet` in [packet.c](packet.c). The packet format is a type
byte, a declared payload-length byte, then the payload.

## Run from the repository root

Complete the [shared prerequisites](../README.md#community-quick-starts) first.
You need Docker, the oxfuzz sandbox image, a configured model provider, Bash,
and Python 3. The demo uses this checkout's CLI through Cargo; set `OXFUZZ_BIN`
to an installed `oxfuzz` binary to use that instead.

```bash
# Check readiness without drafting or executing the target.
bash scripts/demo-cve-rediscovery.sh \
  --example aflpp_persistent --engine afl++ --duration 1m --preflight-only

# Qualify a retained harness and review it before approving the campaign.
bash scripts/demo-cve-rediscovery.sh \
  --example aflpp_persistent --engine afl++ --duration 1m
```

Preflight checks configuration, not provider credentials or target behavior.
The full demo requires provider access and may incur provider charges. It
prints the submitted source and qualification evidence before asking for
approval. Declining, EOF, or a failed smoke test prevents the campaign.

For an offline discovery-only check:

```bash
cargo run -q -p hf-cli -- discover examples/aflpp_persistent --lang c --ai off
```

## What to expect

Discovery finds `parse_packet`. The function allocates its output from the
actual payload size, but passes the untrusted declared length to `memcpy`.
For example, bytes `01 08 41` declare eight payload bytes while supplying one.
This can produce an AddressSanitizer heap-buffer-overflow finding; the first
reported violation may be a source read or a destination write, depending on
the generated harness and instrumentation. It is a deliberately faulty target.

A short campaign may or may not find a crash. Qualification can find one
before the campaign; the demo then retains the smoke evidence and stops.
Do not bypass that failed qualification merely to make the demo continue.

The normal AFL++ build uses the bundled libFuzzer-compatible driver. The
folder name does not mean this demo requests a custom `__AFL_LOOP` harness.
For explicit harness-owned persistent mode and reset requirements, see
[AFL++ persistent mode](../../docs/guides/CLI_REFERENCE.md#afl-persistent-mode).
All builds, qualification probes, and campaigns go through oxfuzz's sandbox.

## Inspect and stop

```bash
cargo run -q -p hf-cli -- runs list --project examples/aflpp_persistent
```

The duration bounds the campaign. For early cancellation, use the
[run-control commands](../../docs/guides/CLI_REFERENCE.md#run-lifecycle-list-status-stop).
Temporary demo files are removed on exit; retained corpora, harnesses, and
crash evidence stay in the configured oxfuzz workspace. Preserve relevant run
IDs and evidence when reporting an issue. Stop active runs before cleaning an
isolated demo workspace.
