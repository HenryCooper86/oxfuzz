# oxfuzz

<a id="english"></a>
**English** &middot; [中文](#chinese)

> An AI fuzzing agent that discovers targets, writes harnesses, drives open-source fuzzing engines, and triages the crashes -- under human-in-the-loop supervision and sandboxed execution.

**Target Discovery** &middot; **Harness Generation** &middot; **Engine Integration** &middot; **Crash Triage** &middot; **Corpus & Coverage Loop** &middot; **User-Extensible Skills**

<p align="center">
  <img src="docs/screenshots/hero.png" alt="oxfuzz Dashboard showing operational readiness, harness review, recent runs, and crash handoff" width="900">
</p>

---

## New to fuzzing? Start here

In plain language: **fuzzing** means automatically throwing millions of weird and
malformed inputs at a program to find the ones that make it crash -- each crash
is a potential bug, often a security hole. Doing this by hand takes expert work:
deciding what to test, writing test code, running it safely, and making sense of
the crashes.

**oxfuzz coordinates that workflow with AI and deterministic tooling.** You
point it at a codebase and it ranks candidate targets, drafts and qualifies test
harnesses, drives a real fuzzing engine inside a mandatory sandbox, and retains
evidence for the crashes it finds. Human approval is bound to the exact harness
revision that is allowed to enter a full campaign.

If you are not a fuzzing engineer, read the **[Getting Started
guide](docs/guides/GETTING_STARTED.md)** first -- it explains everything from
scratch, walks through your first run in the desktop app, and includes a glossary
of every term. The rest of this README is the technical reference.

---

## Table of Contents

- [New to fuzzing? Start here](#new-to-fuzzing-start-here)
- [Highlights](#highlights)
- [The Desktop App](#the-desktop-app)
- [Install & Build](#install--build)
- [Release Readiness](#release-readiness)
- [Quick Start (CLI)](#quick-start-cli)
- [Command Reference](#command-reference)
- [Configuration Reference](#configuration-reference)
- [Safety Model](#safety-model)
- [Architecture](#architecture)
- [Crate Map](#crate-map)
- [Documentation](#documentation)
- [Acknowledgements](#acknowledgements)
- [License](#license)

---

## Highlights

| Capability | Description |
| --- | --- |
| **Operational Dashboard** | Readiness, harness-review state, recent campaigns, crash handoff, and evidence counts in one operator-focused view. |
| **Target Discovery** | Semantic + static-analysis scan of a project producing a ranked Target Inventory (fit score, input surface, complexity, call-graph reachability). |
| **Optional Semgrep Enrichment** | Explicit C/C++-only enrichment adds capped, advisory static-analysis signals from a pinned offline rules snapshot without changing normal discovery. |
| **Harness Generation** | LLM-authored, compile-validated, smoke-fuzzed harnesses per target. |
| **Engine Integration** | AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, and Syzkaller behind one `EngineAdapter` trait. |
| **Crash Triage** | Dedup by stack signature, CASR severity/exploitability, minimize, and LLM-drafted bug reports under human review. |
| **Corpus & Coverage** | Seed, grow, prune, and merge corpora; track coverage deltas; feed crashes back into the corpus. |
| **AI Assistant** | A conversational control surface for the same service-owned workflow, with visible tool activity and policy-enforced human approval gates. |
| **Multi-Provider LLM Pool** | Tag-based routing, automatic failover, provider freeze/thaw across OpenAI, Anthropic, Gemini, and OpenAI-compatible backends. |
| **Sandboxed Execution** | Every harness build and fuzz run goes through the mandatory Docker-backed `hf-runtime`; there is no production host-execution fallback. |
| **Scheduled Campaigns** | Headless, budget-bounded fuzzing on an interval/cron/once schedule, rotating through a project's promoted targets. |
| **Issue & Vuln Tracking** | File crashes as GitHub/GitLab issues or push them to DefectDojo as findings; export SARIF for code scanning. |
| **Retained Evidence** | Run history, policy decisions, reports, crash reproducers, corpora, coverage, and exportable project evidence remain available for review. |
| **Desktop, CLI & Web** | A native macOS app (Tauri v2 + React) with a built-in Help guide, a full CLI/TUI, and a REST + SSE API -- all over the same service core. |

---

## The Desktop App

The desktop app (Tauri v2 + React 19) is the primary way to drive oxfuzz. It
links the `hf-service` core directly, so the AI Assistant, discovery, fuzzing,
and triage all run locally with the same sandboxing and guardrails as the CLI.

```bash
./scripts/build-app.sh        # builds target/release/bundle/macos/oxfuzz.app + .dmg
open target/release/bundle/macos/oxfuzz.app
```

On first launch a short setup wizard configures your LLM provider, checks the
sandbox, and points oxfuzz at your first project. After that the left
sidebar is your control panel. Pipeline surfaces cover the Dashboard, AI
Assistant, guided workflow, Discover, Harness, Run, Triage, and Corpus. Library
and operations surfaces add Projects, Artifacts, Reports, Run History, Policy
Audit, Agents, Skills, Knowledge, Automation, Automotive, DefectDojo, Help &
Docs, and Settings.

### A campaign, end to end

**0. Confirm readiness and the next operator action.** The Dashboard summarizes
sandbox and engine readiness, retained evidence, harness promotion state,
recent campaigns, and crash handoff. A blocked requirement stays visible
instead of being hidden behind a generic status.

**1. Discover the attack surface.** Point oxfuzz at a C/C++ project and it
scans for fuzzable functions, ranking them into a Target Inventory by fit score,
input surface, complexity, and reachability from entry points.

![Discover -- ranked Target Inventory](docs/screenshots/discover.png)

**2. Generate, qualify, and promote a harness.** Pick a target and the agent
drafts a harness, compiles it in the sandbox, runs bounded smoke qualification,
and prepares a seed corpus. You then review and explicitly promote that exact
revision before any full campaign can start. Regeneration invalidates the prior
promotion.

![Harness -- promoted revision and five-step sandbox qualification flow](docs/screenshots/harness.png)

**3. Run the fuzzer.** Launch an enabled engine against the promoted harness.
The Run view shows campaign limits and retained metrics -- executions/sec,
coverage edges, elapsed time, and findings -- with cooperative cancellation for
an active sandboxed run.

![Run -- approved target, bounded campaign configuration, and retained metrics](docs/screenshots/run.png)

**4. Triage the crashes.** Crashes are ingested, deduplicated by stack
signature, minimized, and classified with CASR for severity and exploitability.
The agent can draft a report from retained evidence for human review, and the
result can be exported or handed off to DefectDojo.

![Triage -- deduplicated sanitizer crash and exploitability classification](docs/screenshots/triage.png)

**Review retained evidence.** The Artifacts view collects persisted crash
reproducers and corpus inputs across the selected project in one place. Reports,
run history, policy audit, and evidence export provide the wider audit trail.

![Artifacts -- crashes and corpus](docs/screenshots/artifacts.png)

### Talk to it instead

Everything above is also available conversationally. The **AI Assistant** uses
the same service tools for discovery, harnessing, running, and triage. It can
recommend and prepare work, but it cannot turn a draft into an approved full
campaign by itself. Guardrails, sandbox policy, and the human promotion record
remain authoritative.

### Settings

The Settings panel is the single source of truth for operator configuration:
LLM providers, enabled fuzzing engines, run defaults, sandboxed campaign limits,
storage cleanup, and external integrations. Mandatory sandboxing, blocked
fuzzer networking, and human promotion before full campaigns are displayed as
enforced guarantees rather than switches.

![Fuzzing settings -- engine availability, campaign limits, and mandatory protections](docs/screenshots/settings.png)

> The GUI also runs in the browser against the REST API for development:
> `cd crates/hf-gui && npm run dev:web` (talks to `oxfuzz serve` over HTTP).

---

## Install & Build

### Prerequisites

| Dependency | Required? | Notes |
| --- | --- | --- |
| **Rust 1.94+** | Yes | Pinned in `rust-toolchain.toml` |
| **Node 20.19+ or 22.12+ / npm** | Desktop app | Vite 7 requirement; GitLab CI uses Node 22 |
| **Docker** | Yes | Mandatory boundary for harness builds, fuzz runs, and crash parsing |
| **SQLite 3.35+** | Embedded | Bundled, no action needed |
| **Fuzzing engines** | Bundled | AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, and syzkaller live in the sandbox image |

### The CLI binary

```bash
git clone <your-oxfuzz-remote>
cd oxfuzz
cargo build --release
# Binary: target/release/oxfuzz

# Build and verify the versioned sandbox toolchain.
./scripts/build-sandbox.sh
```

### Download a prebuilt app

Prebuilt installers for each release are attached to the
**[Releases page](https://github.com/HenryCooper86/oxfuzz/releases)**:

| Platform | File |
| --- | --- |
| macOS (Apple silicon) | `oxfuzz_*_aarch64.dmg` |
| macOS (Intel) | `oxfuzz_*_x64.dmg` |
| Linux | `oxfuzz_*.AppImage`, `.deb`, `.rpm` |
| Windows | `oxfuzz_*.msi`, `*-setup.exe` |

These builds are unsigned, so the OS warns on first launch -- see the release
notes for the per-platform steps. Docker must be installed and running before
any fuzzing starts.

Maintainers cut a release by pushing a version tag. `.github/workflows/release.yml`
builds every platform and publishes the release automatically -- but only after
all four builds have uploaded, so a release is never public while a platform is
still missing. If any platform fails, the release stays a draft to retry or
publish by hand:

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Building the desktop app yourself (macOS)

```bash
./scripts/build-app.sh
# App:  target/release/bundle/macos/oxfuzz.app
# DMG:  target/release/bundle/dmg/oxfuzz_0.1.0_aarch64.dmg
```

To install a packaged build, open the `.dmg` and drag **oxfuzz** into
**Applications**. The app is ad-hoc signed (not notarized), so on first launch
macOS Gatekeeper will block it: right-click the app and choose **Open** once (or
run `xattr -cr /Applications/oxfuzz.app`). See the
**[Getting Started guide](docs/guides/GETTING_STARTED.md#installing-the-desktop-app)**
for the full walkthrough.

### DefectDojo (optional findings dashboard)

oxfuzz adopts a local DefectDojo rather than bundling one. `scripts/setup-defectdojo.sh`
(double-click `setup-defectdojo.command`) installs it for you: it clones
DefectDojo's upstream compose project, pulls the released images, starts the
stack on `http://localhost:8080`, and writes `config/defectdojo.toml`. The
environment-setup entry points (`rebuild-sandbox-image.command`,
`scripts/build-app.sh`) run it best-effort and idempotently; set
`HF_SKIP_DEFECTDOJO=1` to skip. Fuzzing never depends on it.

```bash
./scripts/setup-defectdojo.sh        # first run pulls several GB; idempotent thereafter
```

`scripts/health-check.sh` delegates to `oxfuzz doctor`, which probes the
Docker daemon, sandbox image, and engine tools inside that image. Host engine
binaries and optional integrations do not determine core readiness.

---

## Release Readiness

A release candidate is ready only when its source gates, sandbox health, CLI
artifact, and platform bundle have all been verified from the same commit. The
repository provides a local gate runner, GitLab CI jobs for locked all-feature
coverage, and release build scripts:

```bash
./scripts/tests/gates.sh
./scripts/build-sandbox.sh
./scripts/test-semgrep-sandbox.sh
./scripts/build-release.sh
target/release/oxfuzz doctor
./scripts/build-app.sh
```

The Semgrep gate runs only the committed C fixtures through the fixed wrapper
inside the already-built versioned sandbox. A source-only release build does
not download or run Semgrep. Release candidates can require the sandbox gate
from the CLI build with
`OXFUZZ_VERIFY_SEMGREP_SANDBOX=1 ./scripts/build-release.sh`.

On macOS, `build-app.sh` verifies the `.app` signature and the generated DMG.
Its default ad-hoc signature is suitable for local QA, not public distribution;
a distributed build still needs the organization's Developer ID signing and
notarization workflow. Use the **[release checklist](docs/guides/RELEASE_CHECKLIST.md)**
for the full evidence, packaging, safety, and handoff gates.

---

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

---

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
| `report <project> --target <sym> --out report.md` | Render a full Markdown campaign report. |
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

---

## Configuration Reference

Only settings consumed by the production service are exposed as editable
configuration:

- `providers.toml` -- LLM provider pool (routing tags, failover, freeze/thaw).
- `oxfuzz.toml` -- enabled engines, run defaults/resource limits,
  coverage-stagnation, scheduling/session, coverage-regression policy, and the
  optional automotive sidecar policy.
- `defectdojo.toml` -- DefectDojo connection and lifecycle settings.
- `issue_tracker.toml` -- GitHub/GitLab crash issue integration.
- `agents/*.toml` -- Sub-agent definitions (discovery, harness, triage).

Mandatory sandbox/approval/network policy, storage internals, and tool-registry
policy use service-owned safe defaults rather than editable TOML. Runtime
locations are overridden with documented environment variables such as
`HF_WORKSPACE_DIR`, `HF_DB_PATH`, and `HF_CONFIG_DIR`; see `.env.example`.
Unsupported legacy section files are rejected by the config API instead of
being accepted as apparently editable settings.

The REST API binds to loopback by default and is **fail-closed**: set
`HF_WEB_TOKEN` to require a bearer token, or `HF_WEB_TOKEN_OPTIONAL=1` for
unauthenticated local development. A non-loopback `--host` is rejected unless a
token is configured. Browser origins are an exact allowlist in
`HF_WEB_CORS_ORIGINS`; project paths must be below `HF_WEB_PROJECT_ROOTS`. A
local web build sends the bearer value from `VITE_API_TOKEN` (set it to the same
value as `HF_WEB_TOKEN`).

---

## Safety Model

Defense in depth, non-negotiable:

1. **Sandboxed build & run** -- every harness build, fuzzer invocation, and
   crash parse goes through Docker-backed `hf-runtime`; engine binaries and
   generated harnesses are treated as untrusted and never execute on the host.
2. **Middleware interception** -- `hf-guardrails` scores each action, enforces a
   permission policy, and detects agent loops.
3. **Human-approved execution** -- generated harnesses are reviewed by an LLM
   triage step *and* a human before running. Smoke evidence and approval are
   persisted against the exact active revision; regenerating invalidates the
   approval. Crash artifacts are parsed in the sandbox and never touch the host
   outside the workspace.

**Generated harnesses are never run on the host. Human approval authorizes a
sandboxed run of the exact promoted revision; it never weakens isolation.**

---

## Architecture

Strict layering; dependencies point inward toward `hf-core`. All domain logic
lives in `hf-service` -- the CLI, web, and desktop app are thin presentation
layers over the same `ServiceContainer`.

```
Presentation:  hf-cli (CLI+TUI)  .  hf-web (REST+SSE)  .  hf-gui (Tauri desktop)
                                  |
Service:                      hf-service          <- ALL business logic
                         /                 \
Agent loop:       hf-agent . hf-skills      Fuzzing: hf-discovery . hf-harness . hf-engine
                  . hf-tools                . hf-crash . hf-corpus . hf-coverage
                         \                 /
                                  |
Infrastructure: hf-provider . hf-session . hf-context . hf-storage . hf-knowledge . hf-runtime
                                  |
Core:                          hf-core            <- traits, types, contracts
```

---

## Crate Map

| Crate | Role |
| --- | --- |
| `hf-core` | Core types/traits: `LlmProvider`, `Tool`, `TargetCandidate`, `Harness`, `Crash` (the `EngineAdapter` trait lives in `hf-engine`). |
| `hf-provider` | LLM provider pool with tag routing, failover, freeze/thaw. |
| `hf-session` | Session tree, parent/child delegation, compaction. |
| `hf-context` | Token-budget-aware prompt assembly pipeline. |
| `hf-tools` | Tool registry and validation with project-scoped `FileRead`, `Glob`, and `Grep`; the agent adds service-backed `KnowledgeSearch`. |
| `hf-skills` | Skill registry, versioning, experience capture. |
| `hf-prompt` | Prompt templates for discovery, harness, triage. |
| `hf-storage` | SQLite storage (sqlx), transcript persistence. |
| `hf-runtime` | Mandatory Docker sandbox, resource limits, and build isolation. |
| `hf-scheduler` | Cron-style and one-shot campaign scheduling. |
| `hf-knowledge` | Full-text (BM25) retrieval over project source and ingested documents; optional vector search behind the `vector_qdrant` feature. |
| `hf-diagnostics` | Persistent LLM trace, token-usage, and cost evidence. |
| `hf-guardrails` | Permission model, loop detection, risk scoring. |
| `hf-discovery` | Target discovery: static analysis, semantic ranking, reachability. |
| `hf-harness` | Harness generation, compile validation, smoke fuzz. |
| `hf-engine` | `EngineAdapter` adapters: AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, Syzkaller. |
| `hf-crash` | Crash ingestion, dedup, minimization, bug-report drafting. |
| `hf-corpus` | Corpus management: seed, grow, prune, merge. |
| `hf-coverage` | Coverage delta tracking, stagnation detection. |
| `hf-service` | Business logic orchestrating all of the above, including durable run recovery (`ServiceContainer`). |
| `hf-agent` | Service-agnostic reason/act loop and delegation behind the `AgentBackend` port. |
| `hf-web` | REST API + SSE streaming. |
| `hf-cli` | CLI + TUI. |
| `hf-gui` | Tauri v2 + React 19 desktop app. |
| `hf-test-utils` | Shared test fixtures and helpers. |

---

## Documentation

- **[Getting Started](docs/guides/GETTING_STARTED.md) -- plain-language intro for non-experts (start here).**
- [Documentation map](docs/README.md) -- routes readers by audience and task.
- [Release checklist](docs/guides/RELEASE_CHECKLIST.md) -- source, sandbox, packaging, and handoff gates.
- [Screenshot guide](docs/screenshots/README.md) -- reproducible capture and privacy requirements.
- [Contributing](CONTRIBUTING.md) -- contribution workflow, safety requirements, and quality gates.
- [Security policy](SECURITY.md) -- supported versions, private reporting, and safe research expectations.
- [Vision](VISION.md) -- project vision.
- [Engineering protocol](AGENTS.md) -- TDD, risk tiers, and quality gates.
- [Design documents](docs/design/) -- detailed subsystem designs.
- [Engineering standards](docs/standards/) -- testing, harness, target, engine, database, and tool-call standards.

---

## Acknowledgements

oxfuzz is inspired by and based on **[y-agent](https://github.com/gorgiaxx/y-agent)** by [Gorgias (gorgiaxx)](https://github.com/gorgiaxx) -- a model-agnostic Rust agent framework that turns objectives into controlled, recoverable, and observable work. Its design (agent orchestration, skills, knowledge retrieval, recovery, and multi-surface CLI/TUI/REST/desktop presentation) shaped the foundations of this project. Please visit and use his awesome project.

The optional enrichment sandbox runs
[`Semgrep CE 1.169.0`](https://github.com/semgrep/semgrep/tree/v1.169.0) as a
separate LGPL-2.1 process and bundles the MIT-licensed
[`0xdea/semgrep-rules` C/C++ snapshot](https://github.com/0xdea/semgrep-rules/tree/4d66ecf30bfb1809a984085f2c86a8c3915bfc71).
Distribution notices and exact provenance are retained in
[`third_party/semgrep`](third_party/semgrep) and
[`third_party/semgrep-rules`](third_party/semgrep-rules).

---

## License

[MIT](LICENSE)

---

<a id="chinese"></a>

# oxfuzz（中文）

[English](#english) &middot; **中文**

> 一个 AI 模糊测试代理：它发现目标、编写测试桩（harness）、驱动开源模糊测试引擎，并对崩溃进行三查（triage）—— 全程处于人工闭环监督与沙箱化执行之下。

**目标发现** &middot; **测试桩生成** &middot; **引擎集成** &middot; **崩溃三查** &middot; **语料库与覆盖率闭环** &middot; **用户可扩展技能**

<p align="center">
  <img src="docs/screenshots/hero.png" alt="oxfuzz 仪表盘：运营就绪度、测试桩审核、近期运行与崩溃移交" width="900">
</p>

> 本节是上方英文文档的完整中文镜像，章节结构一一对应。命令、代码块、文件路径、配置键、crate 名称与 CLI 参数均保持原文（不翻译），以便直接复制使用。

---

## 模糊测试新手？从这里开始

用大白话说：**模糊测试（fuzzing）** 就是自动向一个程序投喂数以百万计的畸形、奇怪的输入，找出会让它崩溃的那些 —— 每一次崩溃都是一个潜在缺陷，往往是安全漏洞。手工做这件事需要专家级的工作：决定测什么、编写测试代码、安全地运行它，并读懂崩溃。

**oxfuzz 用 AI 与确定性工具来协调这套工作流。** 你把它指向一份代码库，它会对候选目标进行排名、起草并资格化测试桩、在强制沙箱内驱动真实的模糊测试引擎，并为发现的崩溃保留证据。人工审批被绑定到被允许进入完整 campaign 的那一个确切的测试桩修订版。

如果你不是模糊测试工程师，请先阅读 **[入门指南](docs/guides/GETTING_STARTED.md)** —— 它从零开始解释一切，带你在桌面应用里走完第一次运行，并附有每个术语的词汇表。本 README 的其余部分是技术参考。

---

## 亮点

| 能力 | 说明 |
| --- | --- |
| **运营仪表盘** | 在一个面向操作员的视图中集中呈现就绪度、测试桩审核状态、近期 campaign、崩溃移交与证据计数。 |
| **目标发现** | 对项目进行语义 + 静态分析扫描，产出排名后的目标清单（契合度评分、输入面、复杂度、调用图可达性）。 |
| **测试桩生成** | 由 LLM 编写、经编译校验、经冒烟模糊的按目标测试桩。 |
| **引擎集成** | AFL++、honggfuzz、libFuzzer、ClusterFuzzLite 与 Syzkaller，统一收敛到一个 `EngineAdapter` trait 之后。 |
| **崩溃三查** | 按栈签名去重、以 CASR 判定严重度/可利用性、最小化，以及在人工审核下由 LLM 起草的缺陷报告。 |
| **语料库与覆盖率** | 播种、扩展、修剪与合并语料库；跟踪覆盖率增量；把崩溃回喂到语料库。 |
| **AI 助手** | 面向同一套服务托管工作流的对话式控制界面，工具活动可见，并有策略强制的人工审批门。 |
| **多提供方 LLM 池** | 基于标签的路由、自动故障转移，以及跨 OpenAI、Anthropic、Gemini 及 OpenAI 兼容后端的提供方冻结/解冻。 |
| **沙箱化执行** | 每一次测试桩构建与模糊运行都经过强制的、以 Docker 为后盾的 `hf-runtime`；不存在生产环境的主机执行回退。 |
| **计划化 campaign** | 无头、预算受限的模糊测试，按间隔/cron/一次性计划运行，在项目已提升的目标间轮换。 |
| **问题与漏洞跟踪** | 将崩溃作为 GitHub/GitLab issue 提交，或作为 finding 推送到 DefectDojo；导出 SARIF 供代码扫描。 |
| **保留的证据** | 运行历史、策略决策、报告、崩溃复现器、语料库、覆盖率与可导出的项目证据均保留可审。 |
| **桌面、CLI 与 Web** | 原生 macOS 应用（Tauri v2 + React），内置帮助指南；完整的 CLI/TUI；以及 REST + SSE API —— 全部构建在同一套服务核心之上。 |

---

## 桌面应用

桌面应用（Tauri v2 + React 19）是驱动 oxfuzz 的主要方式。它直接链接 `hf-service` 核心，因此 AI 助手、发现、模糊测试与三查都在本地运行，并具备与 CLI 相同的沙箱与护栏。

```bash
./scripts/build-app.sh        # 构建 target/release/bundle/macos/oxfuzz.app + .dmg
open target/release/bundle/macos/oxfuzz.app
```

首次启动时，一个简短的设置向导会配置你的 LLM 提供方、检查沙箱，并把 oxfuzz 指向你的第一个项目。此后，左侧边栏就是你的控制面板。流水线相关界面涵盖仪表盘、AI 助手、引导式工作流、发现（Discover）、测试桩（Harness）、运行（Run）、三查（Triage）与语料库（Corpus）。资料库与运营界面则新增项目、制品（Artifacts）、报告、运行历史、策略审计、代理（Agents）、技能（Skills）、知识（Knowledge）、自动化（Automation）、汽车（Automotive）、DefectDojo、帮助与文档，以及设置。

### 一次完整的 campaign

**0. 确认就绪度与下一步操作。** 仪表盘汇总沙箱与引擎就绪度、保留的证据、测试桩提升状态、近期 campaign 与崩溃移交。被阻塞的前置条件会保持可见，而不会被藏在一个笼统的状态之后。

**1. 发现攻击面。** 把 oxfuzz 指向一个 C/C++ 项目，它会扫描可模糊的函数，并按契合度评分、输入面、复杂度与从入口点的可达性，把它们排入目标清单。

![发现 —— 排名后的目标清单](docs/screenshots/discover.png)

**2. 生成、资格化并提升一个测试桩。** 选定一个目标，代理会起草测试桩、在沙箱中编译、运行有界的冒烟资格化，并准备种子语料库。随后你要审核并显式提升那个确切的修订版，之后才能启动任何完整 campaign。重新生成会使先前的提升失效。

![测试桩 —— 已提升的修订版与五步沙箱资格化流程](docs/screenshots/harness.png)

**3. 运行模糊测试。** 用一个已启用的引擎对已提升的测试桩发起运行。Run 视图展示 campaign 限制与保留的指标 —— 每秒执行数、覆盖率边、已用时间与发现 —— 并支持对进行中的沙箱运行进行协作式取消。

![运行 —— 已批准的目标、有界的 campaign 配置与保留的指标](docs/screenshots/run.png)

**4. 三查崩溃。** 崩溃会被摄取、按栈签名去重、最小化，并用 CASR 分类严重度与可利用性。代理可以基于保留的证据起草一份报告供人工审核，结果可导出或移交给 DefectDojo。

![三查 —— 去重后的 sanitizer 崩溃与可利用性分类](docs/screenshots/triage.png)

**审阅保留的证据。** Artifacts 视图把所选项目内持久化的崩溃复现器与语料库输入集中到一处。报告、运行历史、策略审计与证据导出提供更广的审计线索。

![制品 —— 崩溃与语料库](docs/screenshots/artifacts.png)

### 或者，直接与它对话

上述一切也都可以通过对话完成。**AI 助手** 使用同一套服务工具进行发现、编写测试桩、运行与三查。它可以推荐并准备工作，但无法凭自身把草稿变成一个已批准的完整 campaign。护栏、沙箱策略与人工提升记录始终具有权威性。

### 设置

设置面板是操作员配置的唯一真源：LLM 提供方、已启用的模糊测试引擎、运行默认值、沙箱化的 campaign 限制、存储清理与外部集成。强制沙箱、被封禁的模糊器联网，以及完整 campaign 前的人工提升，都以“强制保证”而非“开关”的形式展示。

![模糊测试设置 —— 引擎可用性、campaign 限制与强制保护](docs/screenshots/settings.png)

> 为便于开发，GUI 也可在浏览器中对着 REST API 运行：
> `cd crates/hf-gui && npm run dev:web`（通过 HTTP 与 `oxfuzz serve` 通信）。

---

## 安装与构建

### 先决条件

| 依赖 | 是否必需？ | 说明 |
| --- | --- | --- |
| **Rust 1.94+** | 是 | 由 `rust-toolchain.toml` 固定 |
| **Node 20.19+ 或 22.12+ / npm** | 桌面应用 | Vite 7 的要求；GitLab CI 使用 Node 22 |
| **Docker** | 是 | 测试桩构建、模糊运行与崩溃解析的强制边界 |
| **SQLite 3.35+** | 内置 | 已捆绑，无需操作 |
| **模糊测试引擎** | 已捆绑 | AFL++、honggfuzz、libFuzzer、ClusterFuzzLite 与 syzkaller 均位于沙箱镜像中 |

### CLI 二进制

```bash
git clone <your-oxfuzz-remote>
cd oxfuzz
cargo build --release
# Binary: target/release/oxfuzz

# Build and verify the versioned sandbox toolchain.
./scripts/build-sandbox.sh
```

### 下载预构建的应用

每个版本的安装包都会附在 **[Releases 页面](https://github.com/HenryCooper86/oxfuzz/releases)**：

| 平台 | 文件 |
| --- | --- |
| macOS（Apple 芯片） | `oxfuzz_*_aarch64.dmg` |
| macOS（Intel） | `oxfuzz_*_x64.dmg` |
| Linux | `oxfuzz_*.AppImage`、`.deb`、`.rpm` |
| Windows | `oxfuzz_*.msi`、`*-setup.exe` |

这些构建均未签名，因此系统在首次启动时会发出警告 —— 各平台的处理步骤见发布说明。开始任何模糊测试前，Docker 必须已安装并正在运行。

维护者通过推送版本标签来发布。`.github/workflows/release.yml` 会构建所有平台并自动发布 release —— 但只有在四个平台全部上传完成后才会公开，因此不会出现缺少某个平台的公开 release。若任一平台构建失败，release 将保持草稿状态，可重试或手动发布：

```bash
git tag v0.1.0
git push origin v0.1.0
```

### 自行构建桌面应用（macOS）

```bash
./scripts/build-app.sh
# App:  target/release/bundle/macos/oxfuzz.app
# DMG:  target/release/bundle/dmg/oxfuzz_0.1.0_aarch64.dmg
```

要安装打包好的构建，打开 `.dmg` 并把 **oxfuzz** 拖入 **Applications** 文件夹。该应用为即席签名（ad-hoc，未做公证），因此首次启动时 macOS Gatekeeper 会拦截它：右键点击该应用并选择 **打开（Open）** 一次即可（或运行 `xattr -cr /Applications/oxfuzz.app`）。完整步骤见 **[入门指南](docs/guides/GETTING_STARTED.md#installing-the-desktop-app)**。

### DefectDojo（可选的 finding 仪表盘）

oxfuzz 采用一个本地 DefectDojo，而非内置一个。`scripts/setup-defectdojo.sh`（双击 `setup-defectdojo.command`）会为你安装：它克隆 DefectDojo 上游的 compose 项目、拉取已发布镜像、在 `http://localhost:8080` 启动整套栈，并写入 `config/defectdojo.toml`。环境搭建入口（`rebuild-sandbox-image.command`、`scripts/build-app.sh`）会以尽力而为且幂等的方式运行它；设置 `HF_SKIP_DEFECTDOJO=1` 可跳过。模糊测试从不依赖它。

```bash
./scripts/setup-defectdojo.sh        # 首次运行会拉取数 GB；此后幂等
```

`scripts/health-check.sh` 委托给 `oxfuzz doctor`，后者会探测 Docker 守护进程、沙箱镜像，以及该镜像内的引擎工具。主机上的引擎二进制与可选集成不决定核心就绪度。

---

## 发布就绪度

只有当发布候选的源码门禁、沙箱健康、CLI 制品与平台安装包都从同一个提交被验证过时，它才算就绪。仓库提供了一个本地门禁运行器、用于锁定全特性覆盖的 GitLab CI 作业，以及发布构建脚本：

```bash
./scripts/tests/gates.sh
./scripts/build-sandbox.sh
./scripts/build-release.sh
target/release/oxfuzz doctor
./scripts/build-app.sh
```

在 macOS 上，`build-app.sh` 会校验 `.app` 签名与生成的 DMG。其默认的即席签名适合本地 QA，不适合公开分发；对外分发的构建仍需组织的 Developer ID 签名与公证流程。完整的证据、打包、安全与移交门禁请使用 **[发布检查清单](docs/guides/RELEASE_CHECKLIST.md)**。

---

## 快速开始（CLI）

### 1. 初始化配置

```bash
oxfuzz init
oxfuzz doctor
```

这会物化受支持的 `config/*.example.toml` 模板并创建数据库。环境变量覆盖仍显式保留在 `.env.example` 中；`init` 不会创建或修改 `.env`。

### 2. 至少配置一个 LLM 提供方

把 `config/providers.example.toml` 复制为 `config/providers.toml` 并填写，然后在启动 `oxfuzz` 的环境中导出对应的密钥：

```toml
[[providers]]
id = "openai-main"
provider_type = "openai"
model = "gpt-4o"
tags = ["reasoning", "general"]
api_key_env = "OPENAI_API_KEY"
```

`.env.example` 是一份变量参考，而不是会被自动加载的文件。如果你在 `.env` 里保存本地值，请在启动进程前导出它们（例如在 POSIX shell 中 `set -a; source .env; set +a`）。

### 3. 运行一个 campaign

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

---

## 命令参考

| 命令 | 作用 |
| --- | --- |
| `init` | 从模板搭建配置，并创建/迁移数据库。 |
| `doctor [--json]` | 探测强制的 Docker 沙箱及其捆绑引擎；当模糊测试未就绪时以非零码退出。 |
| `discover <project> --lang c [--rank]` | 扫描项目并产出排名后的目标清单。 |
| `harness <project> --target <sym> --engine <e> [--draft-only] [--repair N] [--refine] [--promote]` | 编写、编译（可选自动修复或按覆盖率精修）并冒烟资格化一个测试桩；`--promote` 是显式的审批步骤。 |
| `run <project> --target <sym> --engine <e> --duration 60m` | 用当前已提升的测试桩运行一个沙箱化 campaign（Ctrl-C 协作式取消）。 |
| `campaign <project> --target <sym> --engine <e>` | 用一个已冒烟资格化、经人工提升的测试桩运行并三查一个有界 campaign。 |
| `triage <project> --target <sym>` | 摄取、去重、分类（CASR）并为崩溃起草报告。 |
| `corpus <project> --target <sym> --op seed\|llmseed\|grow\|prune\|cprune\|minimize\|cmin\|absorb\|list` | 管理语料库（`llmseed` = LLM 编写的种子，`cprune`/`cmin` = 覆盖率引导的修剪/最小化）。 |
| `coverage <project> --target <sym>` | 汇总行/区域/函数覆盖率。 |
| `regress <project> --target <sym>` | 重跑已知崩溃复现器，验证它们是否仍然（或不再）崩溃。 |
| `ci <project> --target <sym> --engine <e> [--sarif out.sarif]` | CI 门禁：播种、运行、三查并导出 SARIF；发现崩溃时以非零码退出。 |
| `sarif <project> --target <sym> --out results.sarif` | 将三查后的崩溃导出为 SARIF 报告供代码扫描。 |
| `defectdojo <project> --target <sym>` | 将三查后的崩溃作为 finding 推送到 DefectDojo。 |
| `ingest <project> <file>` | 将一份文档（PDF/Office/HTML）摄取到知识库。 |
| `knowledge index\|search <project> [query]` | 为项目建立搜索索引，或对其执行全文（BM25）查询。 |
| `agent <project> "<message>"` | 从终端驱动对话式代理。 |
| `schedule list\|create\|history\|recovery list\|recovery acknowledge <occurrence-id>\|... ` | 管理计划化的无头模糊 campaign，并将含糊的一次性 occurrence 确认记录为已取消。 |
| `session list\|history\|new\|... ` | 管理聊天会话及其检查点。 |
| `report <project> --target <sym> --out report.md` | 渲染一份完整的 Markdown campaign 报告。 |
| `export [project] --output evidence.json` | 导出一个可复现的证据包，包含限定范围的目标、运行、测试桩、崩溃、语料库与文件系统证据。 |
| `serve --host 127.0.0.1 --port 8081` | 启动 REST + SSE API（`hf-web`）。非回环主机需要 `HF_WEB_TOKEN`。 |
| `tui <project>` | 浏览目标清单并复制准确的下一步命令。 |

引擎：`afl++`、`honggfuzz`、`libfuzzer`、`clusterfuzzlite`、`syzkaller`。

REST API 暴露发现、测试桩、用户态运行的启动/状态/取消、语料库、三查、报告与管理端点。Syzkaller 仍是一个受信任的本地桌面工作流，因为它的内核、rootfs、SSH 与虚拟机输入需要更强的边界。

#### 恢复含糊的一次性 campaign

```bash
oxfuzz schedule recovery list
oxfuzz schedule recovery acknowledge <occurrence-id>
```

确认会将先前结果未知的已过期非终态 occurrence 记录为已取消，并永久消耗该一次性计划。它不会停止、恢复或接管孤立的沙箱进程，也不证明其已终止。若要重试，请创建一个新的一次性计划，使其获得新的计划标识符和新的持久化回执。当一次性 journal 被阻塞时，循环计划仍可使用。

等效的 REST 操作是：

```text
GET  /schedule/recovery
POST /schedule/recovery/{occurrence_id}/acknowledge
```

### 可选的汽车协议工作流

`automotive-scapy` 特性新增了沙箱化的汽车抓包分析、确定性变异与回放计划生成、保留的操作证据、状态签名语料库提升，以及有证据支撑的 campaign 报告。它在产品 crate（CLI、web、桌面）中默认启用，并在运行时开箱即开，因此 CAN/UDS 工作区始终存在；用 `--no-default-features` 构建可将其移除。无论如何，物理台架访问都保持禁用并受审批门控。Rust 应用从不导入 Scapy，也不运行主机 Python；Scapy 2.7.0 与可选的 `python-can` 支持位于一个单独构建的 GPL-2.0 边车（sidecar）镜像中。

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

# Optionally append provider-neutral AI interpretation. Unknown evidence
# citations are rejected and the deterministic report remains authoritative.
target/debug/oxfuzz automotive report /path/to/project --ai
```

汽车工作区遵循一条务实的证据流水线：检查固定的适配器、分析一份不可变的抓包、生成确定性变异、构建一个带类型的回放计划、可选地执行一次单独确认的虚拟回放，并撰写一份 campaign 报告。报告会保留失败与部分完成的操作，区分“协议状态新颖性”与“源码覆盖率”，引用操作/请求/转录/状态证据，展示有效的安全姿态，并列出具体缺失的阶段与下一步动作。当配置了 LLM 提供方时，AI 可以附加一段清晰标注的解读，包含假设与建议；它不能修改计划、启用策略、批准流量或替换确定性事实。撰写好的报告会保存到共享的 Reports 工作区，并可导出为 Markdown 或 HTML，当主机具备所需文档工具时还可导出 DOCX/PDF。

离线分析使用一个禁用网络的沙箱。虚拟 CAN 另外需要一个在允许列表中的 `vcanN` 接口以及一次高风险护栏审批。物理台架模式被排除在默认策略之外，需要显式启用、精确的接口/仲裁/服务允许列表、一次全新的、以计划为范围的人工审批，以及更严格的限制。在正常的测试或构建过程中，任何生成的计划都不会在主机或车辆上执行。

---

## 配置参考

只有被生产服务消费的设置才作为可编辑配置暴露出来：

- `providers.toml` —— LLM 提供方池（路由标签、故障转移、冻结/解冻）。
- `oxfuzz.toml` —— 已启用引擎、运行默认值/资源限制、覆盖率停滞、调度/会话、覆盖率回归策略，以及可选的汽车边车策略。
- `defectdojo.toml` —— DefectDojo 连接与生命周期设置。
- `issue_tracker.toml` —— GitHub/GitLab 崩溃 issue 集成。
- `agents/*.toml` —— 子代理定义（发现、测试桩、三查）。

强制的沙箱/审批/网络策略、存储内部实现与工具注册表策略采用服务托管的安全默认值，而非可编辑的 TOML。运行时位置通过有文档记录的环境变量覆盖，例如 `HF_WORKSPACE_DIR`、`HF_DB_PATH` 与 `HF_CONFIG_DIR`；参见 `.env.example`。不受支持的旧版 section 文件会被配置 API 拒绝，而不会被当作看似可编辑的设置接受。

REST API 默认绑定回环地址，且为**失败即关闭（fail-closed）**：设置 `HF_WEB_TOKEN` 以要求 bearer token，或设置 `HF_WEB_TOKEN_OPTIONAL=1` 用于无认证的本地开发。除非配置了 token，否则非回环 `--host` 会被拒绝。浏览器来源是 `HF_WEB_CORS_ORIGINS` 中的精确允许列表；项目路径必须位于 `HF_WEB_PROJECT_ROOTS` 之下。本地 web 构建会发送来自 `VITE_API_TOKEN` 的 bearer 值（把它设为与 `HF_WEB_TOKEN` 相同的值）。

---

## 安全模型

纵深防御，不可妥协：

1. **沙箱化的构建与运行** —— 每一次测试桩构建、模糊器调用与崩溃解析都经过以 Docker 为后盾的 `hf-runtime`；引擎二进制与生成的测试桩被视为不受信任，绝不会在主机上执行。
2. **中间件拦截** —— `hf-guardrails` 为每个动作评分、强制执行权限策略，并检测代理循环。
3. **人工批准的执行** —— 生成的测试桩会经过一个 LLM 三查步骤 *以及* 一名人类的审核后才运行。冒烟证据与批准会针对那个确切的当前修订版持久化；重新生成会使批准失效。崩溃制品在沙箱内解析，绝不会触及工作区之外的主机。

**生成的测试桩绝不会在主机上运行。人工批准授权的是对那个确切已提升修订版的沙箱化运行；它绝不会削弱隔离。**

---

## 架构

严格分层；依赖朝内指向 `hf-core`。所有领域逻辑都位于 `hf-service` —— CLI、web 与桌面应用都是同一套 `ServiceContainer` 之上的薄表现层。

```
Presentation:  hf-cli (CLI+TUI)  .  hf-web (REST+SSE)  .  hf-gui (Tauri desktop)
                                  |
Service:                      hf-service          <- ALL business logic
                         /                 \
Agent loop:       hf-agent . hf-skills      Fuzzing: hf-discovery . hf-harness . hf-engine
                  . hf-tools                . hf-crash . hf-corpus . hf-coverage
                         \                 /
                                  |
Infrastructure: hf-provider . hf-session . hf-context . hf-storage . hf-knowledge . hf-runtime
                                  |
Core:                          hf-core            <- traits, types, contracts
```

---

## Crate 地图

| Crate | 职责 |
| --- | --- |
| `hf-core` | 核心类型/trait：`LlmProvider`、`Tool`、`TargetCandidate`、`Harness`、`Crash`（`EngineAdapter` trait 位于 `hf-engine`）。 |
| `hf-provider` | 带标签路由、故障转移、冻结/解冻的 LLM 提供方池。 |
| `hf-session` | 会话树、父/子委派、压缩。 |
| `hf-context` | 感知 token 预算的提示词组装流水线。 |
| `hf-tools` | 工具注册表与校验，含项目范围的 `FileRead`、`Glob` 与 `Grep`；代理额外提供服务支撑的 `KnowledgeSearch`。 |
| `hf-skills` | 技能注册表、版本化、经验捕获。 |
| `hf-prompt` | 用于发现、测试桩、三查的提示词模板。 |
| `hf-storage` | SQLite 存储（sqlx）、转录持久化。 |
| `hf-runtime` | 强制的 Docker 沙箱、资源限制与构建隔离。 |
| `hf-scheduler` | cron 式与一次性的 campaign 调度。 |
| `hf-knowledge` | 对项目源码与已摄取文档的全文（BM25）检索；`vector_qdrant` 特性下可选向量搜索。 |
| `hf-diagnostics` | 持久化的 LLM 轨迹、token 用量与成本证据。 |
| `hf-guardrails` | 权限模型、循环检测、风险评分。 |
| `hf-discovery` | 目标发现：静态分析、语义排名、可达性。 |
| `hf-harness` | 测试桩生成、编译校验、冒烟模糊。 |
| `hf-engine` | `EngineAdapter` 适配器：AFL++、honggfuzz、libFuzzer、ClusterFuzzLite、Syzkaller。 |
| `hf-crash` | 崩溃摄取、去重、最小化、缺陷报告起草。 |
| `hf-corpus` | 语料库管理：播种、扩展、修剪、合并。 |
| `hf-coverage` | 覆盖率增量跟踪、停滞检测。 |
| `hf-service` | 编排上述一切的业务逻辑，含持久的运行恢复（`ServiceContainer`）。 |
| `hf-agent` | 服务无关的 reason/act 循环与委派，位于 `AgentBackend` 端口之后。 |
| `hf-web` | REST API + SSE 流式。 |
| `hf-cli` | CLI + TUI。 |
| `hf-gui` | Tauri v2 + React 19 桌面应用。 |
| `hf-test-utils` | 共享测试夹具与辅助工具。 |

---

## 文档

- **[入门指南](docs/guides/GETTING_STARTED.md) —— 面向非专家的大白话介绍（从这里开始）。**
- [文档地图](docs/README.md) —— 按受众与任务为读者导航。
- [发布检查清单](docs/guides/RELEASE_CHECKLIST.md) —— 源码、沙箱、打包与移交门禁。
- [截图指南](docs/screenshots/README.md) —— 可复现的截图与隐私要求。
- [贡献指南](CONTRIBUTING.md) —— 贡献流程、安全要求与质量门禁。
- [安全策略](SECURITY.md) —— 受支持版本、私密报告与安全研究预期。
- [愿景](VISION.md) —— 项目愿景。
- [工程协议](AGENTS.md) —— TDD、风险分级与质量门禁。
- [设计文档](docs/design/) —— 详细的子系统设计。
- [工程标准](docs/standards/) —— 测试、测试桩、目标、引擎、数据库与工具调用标准。

---

## 致谢

oxfuzz 受到 [Gorgias (gorgiaxx)](https://github.com/gorgiaxx) 的 **[y-agent](https://github.com/gorgiaxx/y-agent)** 的启发并以之为基础 —— 这是一个模型无关的 Rust 代理框架，能把目标转化为受控、可恢复、可观测的工作。它的设计（代理编排、技能、知识检索、恢复，以及 CLI/TUI/REST/桌面多界面呈现）塑造了本项目的根基。欢迎访问并使用他这个出色的项目。

---

## 许可证

[MIT](LICENSE)
