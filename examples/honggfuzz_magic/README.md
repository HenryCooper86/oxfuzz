# honggfuzz: magic-byte target

A dependency-free C project for trying oxfuzz's discovery, harness authoring,
sandbox qualification, human approval, fuzzing, and triage workflow with
honggfuzz. The entry point is `magic.c::match_magic` in [magic.c](magic.c).

## Run from the repository root

Complete the [shared prerequisites](../README.md#community-quick-starts) first.
You need Docker, the oxfuzz sandbox image, a configured model provider, Bash,
and Python 3. The demo uses this checkout's CLI through Cargo; set `OXFUZZ_BIN`
to an installed `oxfuzz` binary to use that instead.

```bash
# Check the engine, duration policy, sandbox, and provider configuration.
bash scripts/demo-cve-rediscovery.sh \
  --example honggfuzz_magic --engine honggfuzz --duration 1m --preflight-only

# Draft and qualify a harness, review the exact source and evidence at the
# prompt, then approve its bounded campaign if the evidence is satisfactory.
bash scripts/demo-cve-rediscovery.sh \
  --example honggfuzz_magic --engine honggfuzz --duration 1m
```

Preflight does not authenticate the provider or run the target. The full demo
requires provider access and may incur provider charges. Declining the prompt,
EOF, or failed qualification stops before promotion and the campaign.

For an offline discovery-only check:

```bash
cargo run -q -p hf-cli -- discover examples/honggfuzz_magic --lang c --ai off
```

## What to expect

Discovery finds `match_magic`. Its comparisons accept a byte buffer and call
`abort()` when at least four bytes are present and the first four are `ABCD`
(hex `41 42 43 44`). Other inputs return normally. This is an intentional
SIGABRT demonstration, not a memory-corruption claim.

A successful campaign can retain an abort finding and triage evidence. A
one-minute run is a bounded experiment, not a guarantee that the fuzzer finds
the trigger. Qualification may find it first; in that case the demo retains the
failed smoke evidence and stops instead of promoting a failing harness.

The harness and seed corpus are generated through oxfuzz. The target does not
need host-installed honggfuzz, a hand-built executable, or an existing corpus.
For more realistic signatures and third-party libraries, see the separate
[upstream honggfuzz examples](../honggfuzz_upstream/README.md).

## Inspect and stop

```bash
cargo run -q -p hf-cli -- runs list --project examples/honggfuzz_magic
```

The campaign ends at its duration limit. For early cancellation, use the
[run-control commands](../../docs/guides/CLI_REFERENCE.md#run-lifecycle-list-status-stop).
The demo removes its temporary authoring files on exit; oxfuzz retains run and
crash evidence in its configured workspace. Keep that evidence when reporting
an issue, and stop active runs before cleaning an isolated demo workspace.
