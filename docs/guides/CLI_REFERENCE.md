# CLI Reference

[← Back to the README](../../README.md)

## Quick Start (CLI)

### 1. Initialize configuration

```bash
oxfuzz init
oxfuzz doctor
```

This materializes the supported `config/*.example.toml` templates and creates
the database. Environment overrides remain explicit in `.env.example`; `init`
does not create or modify `.env`.

### 2. Configure at least one LLM provider

Copy `config/providers.example.toml` to `config/providers.toml` and fill it in,
then export the matching key in the environment that launches `oxfuzz`:

```toml
[[providers]]
id = "openai-main"
provider_type = "openai"
model = "gpt-4o"
tags = ["reasoning", "general"]
api_key_env = "OPENAI_API_KEY"
```

`.env.example` is a variable reference, not an automatically loaded file. If
you keep local values in `.env`, export them before launching the process (for
example, `set -a; source .env; set +a` in a POSIX shell).

### 3. Run a campaign

```bash
# Discover and rank targets in a project
oxfuzz discover /path/to/project --lang c --rank

# Generate a harness for a specific target
oxfuzz harness /path/to/project --target parse_value --engine afl++ --promote

# Run the fuzzer
oxfuzz run /path/to/project --target parse_value --engine afl++ --duration 60m

# Triage the crashes it found
oxfuzz triage /path/to/project --target parse_value
```

### Optional Semgrep target enrichment

After ordinary C or C++ discovery, you can explicitly enrich the ranking:

```bash
oxfuzz discover /path/to/c-project --lang c --semgrep
```

Without `--semgrep`, discovery is unchanged and Semgrep does not run. The
enriched output is labelled **Semgrep static-analysis signals**. A signal is an
advisory prioritization hint, not a confirmed vulnerability or a fuzzing crash.
Each target retains its immutable base discovery score, shows the Semgrep
boost separately, and reports the effective score used for ordering. Distinct
matched rules contribute by severity, but the total boost is capped at `0.20`
and the effective score cannot exceed `1.0`.

The first release supports only C and C++, permits one active enrichment
operation per canonical project, and lets Ctrl-C or the desktop **Stop** action
cancel that exact operation. Source or base-score changes make a saved overlay
stale; oxfuzz then uses base-only ranking and asks you to rediscover or rerun
enrichment. Scan, validation, mapping, persistence, cancellation, or cleanup
failure is atomic: partial findings and partial score changes are never
published.

The sandbox uses Semgrep CE `1.169.0` and the reviewed
[`0xdea/semgrep-rules` commit `4d66ecf30bfb1809a984085f2c86a8c3915bfc71`](https://github.com/0xdea/semgrep-rules/tree/4d66ecf30bfb1809a984085f2c86a8c3915bfc71)
offline. Runtime scans do not contact the Semgrep Registry and do not accept
user-provided rules, configuration, flags, tokens, or autofix requests. CVE
Binary Tool integration is outside this release's scope.

## Command Reference

| Command | What it does |
| --- | --- |
| `init` | Scaffold config from templates and create/migrate the database. |
| `doctor [--json]` | Probe the mandatory Docker sandbox and its bundled engines; exit non-zero when fuzzing is not ready. |
| `discover <project> --lang c [--rank] [--semgrep]` | Scan a project and produce a ranked Target Inventory; `--semgrep` explicitly adds advisory C/C++ enrichment. |
| `harness <project> --target <sym> --engine <e> [--draft-only] [--repair N] [--refine] [--promote]` | Write, compile (optionally auto-repair or coverage-refine), and smoke-qualify a harness; `--promote` is the explicit approval step. |
| `run <project> --target <sym> --engine <e> --duration 60m` | Run a sandboxed campaign with the active promoted harness (Ctrl-C cancels cooperatively). |
| `campaign <project> --target <sym> --engine <e>` | Run and triage a bounded campaign using an already smoke-qualified, human-promoted harness. |
| `triage <project> --target <sym>` | Ingest, dedup, classify (CASR), and draft reports for crashes. |
| `corpus <project> --target <sym> --op seed\|llmseed\|grow\|prune\|cprune\|minimize\|cmin\|absorb\|list` | Manage the corpus (`llmseed` = LLM-authored seeds, `cprune`/`cmin` = coverage-guided prune/minimize). |
| `coverage <project> --target <sym>` | Summarize line/region/function coverage. |
| `regress <project> --target <sym>` | Re-run the known crash reproducers to verify they still (or no longer) crash. |
| `ci <project> --target <sym> --engine <e> [--sarif out.sarif]` | CI gate: seed, run, triage, and export SARIF; exits non-zero when crashes are found. |
| `sarif <project> --target <sym> --out results.sarif` | Export triaged crashes as a SARIF report for code scanning. |
| `defectdojo <project> --target <sym>` | Push triaged crashes to DefectDojo as findings. |
| `ingest <project> <file>` | Ingest a document (PDF/Office/HTML) into the knowledge base. |
| `knowledge index\|search <project> [query]` | Index a project for search, or run a full-text (BM25) query over it. |
| `agent <project> "<message>"` | Drive the conversational agent from the terminal. |
| `schedule list\|create\|history\|recovery list\|recovery acknowledge <occurrence-id>\|... ` | Manage scheduled headless fuzzing campaigns and acknowledge an ambiguous one-time occurrence as cancelled. |
| `session list\|history\|new\|... ` | Manage chat sessions and their checkpoints. |
| `report <project> --target <sym> --out report.md [--report-lang en\|zh]` | Render a full Markdown campaign report. `--report-lang zh` writes it in Simplified Chinese; file paths, stack frames, symbol names, crash signatures, engine and sanitizer names and all figures stay verbatim. |
| `export [project] --output evidence.json` | Export a reproducibility bundle containing scoped targets, runs, harnesses, crashes, corpus, and filesystem evidence. |
| `serve --host 127.0.0.1 --port 8081` | Start the REST + SSE API (`hf-web`). Non-loopback hosts require `HF_WEB_TOKEN`. |
| `tui <project>` | Browse the target inventory and copy accurate next-step commands. |

Engines: `afl++`, `honggfuzz`, `libfuzzer`, `clusterfuzzlite`, `syzkaller`.

The REST API exposes discovery, harness, user-space run start/status/cancel,
corpus, triage, reporting, and management endpoints. Syzkaller remains a
trusted-local-desktop workflow because its kernel, rootfs, SSH, and VM inputs
require a stronger boundary.

#### Recover an ambiguous one-time campaign

```bash
oxfuzz schedule recovery list
oxfuzz schedule recovery acknowledge <occurrence-id>
```

Acknowledgement records an expired, non-terminal occurrence with an unknown
prior outcome as cancelled and permanently consumes that one-time schedule. It
does not stop, resume, or adopt an orphaned sandbox process, and does not prove
its termination. To retry, create a new one-time schedule so it receives a new
schedule identifier and a new durable receipt. Recurring schedules remain
available when the one-time journal is blocked.

The equivalent REST operations are:

```text
GET  /schedule/recovery
POST /schedule/recovery/{occurrence_id}/acknowledge
```

### Optional automotive protocol workflows

The `automotive-scapy` feature adds sandboxed automotive capture analysis,
deterministic mutation and replay-plan generation, retained operation evidence,
state-signature corpus promotion, and evidence-backed campaign reporting. It is
enabled by default in the product crates (CLI, web, desktop) and turned on at
runtime out of the box, so the CAN/UDS workspace is always present; build with
`--no-default-features` to drop it. Physical-bench access stays disabled and
approval-gated regardless. The Rust application never imports Scapy or runs host
Python; Scapy 2.7.0 and optional `python-can` support live in a separately built
GPL-2.0 sidecar image.

```bash
# Build the separately distributed, pinned sidecar image.
./scripts/build-scapy-sidecar.sh

# The transport contract is compiled in by default (use --no-default-features
# to exclude it).
cargo build -p hf-cli

# The subsystem is enabled by default; inspect the active policy (and
# `automotive disable` if you need to turn it off).
target/debug/oxfuzz automotive settings

# Offline capture analysis never contacts a CAN interface.
target/debug/oxfuzz automotive analyze /path/to/project \
  --protocol uds --capture /path/to/capture.pcap

# Compose a deterministic report from retained operations and protocol states.
target/debug/oxfuzz automotive report /path/to/project \
  --output automotive-campaign.html --format html

# Compose it in Simplified Chinese. Evidence citations, pipeline stage
# identifiers, protocol/bus/ECU/adapter names, digests, paths and every figure
# stay verbatim; omitting the flag composes in English.
target/debug/oxfuzz automotive report /path/to/project --report-lang zh

# Optionally append provider-neutral AI interpretation. Unknown evidence
# citations are rejected and the deterministic report remains authoritative.
target/debug/oxfuzz automotive report /path/to/project --ai
```

The Automotive workspace follows a practical evidence pipeline: inspect the
pinned adapter, analyze an immutable capture, generate deterministic mutations,
build a typed replay plan, optionally perform a separately confirmed virtual
replay, and compose a campaign report. Reports retain failed and partial
operations, distinguish protocol-state novelty from source coverage, cite
operation/request/transcript/state evidence, show the effective safety posture,
and list concrete missing stages and next actions. When an LLM provider is
configured, AI may add a clearly labelled interpretation with hypotheses and
recommendations; it cannot modify a plan, enable policy, approve traffic, or
replace deterministic facts. Composed reports are saved to the shared Reports
workspace and can be exported as Markdown or HTML, plus DOCX/PDF when the host
has the required document tools.

Offline analysis uses a network-disabled sandbox. Virtual CAN additionally
requires an allowlisted `vcanN` interface and a high-risk guardrail approval.
Physical-bench mode is excluded from the default policy and requires explicit
enablement, an exact interface/arbitration/service allowlist, a fresh
plan-scoped human approval, and stricter limits. No generated plan is executed
on a host or vehicle as part of the normal test or build process.
