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

### 3. Qualify and review a retained harness

```bash
# Discover and rank targets in a project
oxfuzz discover /path/to/project --lang c --rank

# Export an immutable authoring packet. The packet carries its work-order SHA-256.
oxfuzz work-order export /path/to/project --target parse_value --lang c \
  --engine afl++ --out work-order.md

# Author harness.c from that packet, then retain the submission UUID in the JSON.
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin human

# Compile, independently review, and smoke-test that immutable submission.
# Retain the attempt UUID returned in the JSON.
oxfuzz work-order qualify --submission <submission UUID>

# Stop and review the exact source, lint, review, binary digest, and smoke result.
# Promotion is a separate human action bound to that retained attempt.
oxfuzz work-order promote --attempt <attempt UUID>
```

### 4. Run and inspect the campaign

```bash
# Work Order runs always use the complete selector returned by the retained order.
oxfuzz run /path/to/project --target src/parser.c::parse_value \
  --engine afl++ --duration 60m

# Read retained health without changing the run.
oxfuzz health --run <run UUID>

# Triage the crashes it found
oxfuzz triage /path/to/project --target src/parser.c::parse_value

# Explicitly run or resume the retained seven-step terminal closeout.
oxfuzz closeout --run <run UUID>
```

`work-order import` and `work-order qualify` never promote. Rerunning
`oxfuzz harness` generates a new draft, so it is not an approval operation for
the source you just reviewed. A full campaign requires the exact promoted
harness revision and still executes only through the mandatory sandbox.

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
| `harness <project> --target <sym> --engine <e> [--draft-only] [--repair N] [--refine] [--promote]` | Write, compile (optionally auto-repair or coverage-refine), and smoke-qualify a newly generated harness. Without `--promote`, review the output; rerunning creates another draft. Use the retained Work Order flow below when approval must name a previously reviewed source. |
| `work-order export\|import\|list\|submissions\|qualify\|rank\|promote ...` | Manage immutable external harness packets, submissions, qualification attempts, deterministic ranking, and exact-attempt promotion. |
| `run <project> --target <sym> --engine <e> --duration 60m` | Run a sandboxed campaign with the active promoted harness (Ctrl-C cancels cooperatively). A file-qualified selector is `<relative-file>::<complete-symbol>`; a retained Work Order run always uses that complete selector. |
| `run . --replay <run UUID>` | Replay a retained run with its recorded engine, duration, and deterministic seed under current policy. The positional `.` is ignored in replay mode; the retained run resolves its original project. |
| `campaign <project> --target <sym> --engine <e>` | Run and triage a bounded campaign using an already smoke-qualified, human-promoted harness. |
| `health --run <run UUID>` | Assess retained campaign health. This read-only command never stops, restarts, or resizes the run. |
| `closeout --run <run UUID>` | Explicitly run or resume the seven retained terminal closeout steps. Successful/skipped steps remain retained; failed or dependency-blocked work can be retried. |
| `triage <project> --target <sym>` | Ingest, dedup, classify (CASR), and draft reports for crashes. |
| `corpus <project> --target <sym> --op seed\|llmseed\|grow\|prune\|cprune\|survival\|regen\|minimize\|absorb\|concolic\|import\|list [--from <dir>]` | Manage the corpus. `prune` removes byte duplicates; `cprune`, `survival`, `regen`, `minimize`, and optional `concolic` have the distinct execution/provider requirements below; `import` requires `--from`. |
| `build diagnose <project> [--json]` | Read current build prerequisites and the exact available plan without building. |
| `build profile show\|set\|clear ...` | Read or explicitly change the optional CMake/plain-Make project build profile. `show` remains available in builds without Build Doctor. |
| `build history <project> [--limit N] [--json]` | Read retained diagnosis and build output. |
| `build run <project> --expected-profile-sha256 <digest> [--json]` | Execute the exact reviewed profile in the sandbox and reject a stale profile digest. |
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

Engines: `afl++`, `honggfuzz`, `libfuzzer`, `syzkaller`.

### Harness Work Order commands

The Work Order feature exposes exactly seven CLI operations:

```bash
oxfuzz work-order export <project> --target <symbol> --lang c \
  --engine libfuzzer [--out packet.md]
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin human [--parent <submission UUID>]
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin external-tool --tool <name> \
  [--model <label>] [--response-id <id>] [--parent <submission UUID>]
oxfuzz work-order list [--project <project>]
oxfuzz work-order submissions --work-order <work-order SHA-256>
oxfuzz work-order qualify --submission <submission UUID>
oxfuzz work-order rank --attempt <attempt UUID> [--attempt <attempt UUID> ...]
oxfuzz work-order promote --attempt <attempt UUID>
```

Export returns a content-addressed work-order ID. Import returns an immutable
submission UUID and records provenance; source must be a nonempty regular,
non-symlink UTF-8 file of at most 65,536 bytes. Qualification returns a new
attempt UUID and is the only operation above that compiles, reviews, and smoke
tests. Rank reads retained attempts. Before promote, inspect the source and the
retained lint, independent review, source/binary digests, verdict, crashes, and
throughput for the selected attempt. Promote accepts only that exact attempt ID
and does not redraft or requalify it. A `Suspect` attempt can technically be
promoted explicitly, but refinement and a new smoke qualification are the
recommended response. A crash-bearing failed attempt is ineligible.

The work order retains the complete `relative-file::symbol` selector. Use it
for every run, coverage, and corpus command that follows the Work Order flow,
including when the display symbol is currently unique. A symbol label by itself
does not preserve the reviewed Work Order workspace identity.

### Campaign health and closeout

`oxfuzz health --run <UUID>` evaluates retained evidence for coverage plateau,
stale worker statistics, missing managed invocation, disk pressure, and terminal
failure. Missing evidence is reported as unavailable. Health is observational;
it does not control the campaign and does not prove a Docker process, worker, or
VM is alive.

`oxfuzz closeout --run <UUID>` operates only on a terminal, harness-backed
campaign and resumes at unfinished work. The retained steps are triage,
minimize, corpus absorb, coverage, blockers, disposition, and trust report.
Opening Run History in the desktop app is read-only; the CLI command itself is
the explicit execution request. Historical source coverage and blocker results
remain unavailable when current workspace files cannot establish them.

### Build profiles

Build profiles support only `cmake` and `make`. A set operation is explicit:

```bash
oxfuzz build profile set /path/to/project \
  --component-root . --build-system cmake \
  --compile-database-path build/compile_commands.json \
  --define BUILD_TESTING=OFF --dependency command:cmake
oxfuzz build diagnose /path/to/project --json
oxfuzz build run /path/to/project \
  --expected-profile-sha256 <reviewed profile SHA-256> --json
oxfuzz build history /path/to/project --limit 20 --json
oxfuzz build profile clear /path/to/project --json
```

Review the normalized component, expected compile database, dependencies,
exact argv, immutable image, and profile digest returned by diagnose. `build
run` writes the oxfuzz-owned build area inside the selected project and runs
only through the sandbox. Clearing a profile keeps diagnosis/build history.

### Corpus operation meanings

`seed`, `grow`, `prune`, `absorb`, `import`, and `list` use deterministic corpus
operations. `llmseed` contacts the configured provider. `survival`, `cprune`,
and `regen` require an exact promoted, smoke-qualified AFL++ harness; `regen`
also asks the provider for bounded replacement seeds. `minimize` (also accepted
as `cmin`) requires an exact promoted, smoke-qualified libFuzzer harness.
`concolic` is available only with its feature and performs sandboxed symbolic
enrichment. Engine-backed actions repeat qualification and current policy checks
at execution time. `prune` claims byte deduplication only; `cprune` retains one
input per whole-map fingerprint and is not a global minimum covering set.

### Coverage experiments and replay

There is no coverage-experiment lifecycle subcommand in the current CLI. The
desktop Corpus view, REST resources under `/coverage/experiments`, and trusted
local native commands create, list, read, complete, or cancel retained
experiments. These operations retain evidence and perform no discovery,
provider call, coverage calculation, promotion, harness execution, or fuzzer
execution.

For a prepared experiment whose baseline has a retained seed, the existing CLI
handoff is:

```bash
# Run this with the same oxfuzz configuration/database used by the application.
oxfuzz run . --replay <baseline UUID>
```

Replay resolves the original project from the retained baseline, which must
still be available. It pins the recorded seed, engine, and duration, while using
the current promoted harness and current corpus under current policy. Keep every
other compared setting unchanged. Ordinary `oxfuzz run` derives a new seed and
will not produce an attachable match. A legacy baseline with a null seed cannot
be reproduced for comparison by replay; run a new seeded baseline and prepare a
new experiment. After the later run terminates, refresh the experiment and
explicitly attach its run UUID. Failed/cancelled/no-op outcomes remain visible;
an edge delta is descriptive and does not prove entry into the goal function.

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
