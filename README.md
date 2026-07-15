# hobot_fuzz

> An AI fuzzing agent that discovers targets, writes harnesses, drives open-source fuzzing engines, and triages the crashes -- under human-in-the-loop supervision and sandboxed execution.

**Target Discovery** &middot; **Harness Generation** &middot; **Engine Integration** &middot; **Crash Triage** &middot; **Corpus & Coverage Loop** &middot; **Self-Evolving Skills**

<p align="center">
  <img src="docs/screenshots/hero.png" alt="hobot_fuzz desktop app -- the AI Assistant driving a fuzzing campaign" width="900">
</p>

---

## New to fuzzing? Start here

In plain language: **fuzzing** means automatically throwing millions of weird and
malformed inputs at a program to find the ones that make it crash -- each crash
is a potential bug, often a security hole. Doing this by hand takes expert work:
deciding what to test, writing test code, running it safely, and making sense of
the crashes.

**hobot_fuzz automates all of that with AI.** You point it at a codebase and it
finds the riskiest functions, writes the test code for them, runs a real fuzzing
engine inside a safe sandbox, and explains any bugs it finds -- asking for your
approval at the steps that matter.

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
- [Quick Start (CLI)](#quick-start-cli)
- [Command Reference](#command-reference)
- [Configuration Reference](#configuration-reference)
- [Safety Model](#safety-model)
- [Architecture](#architecture)
- [Crate Map](#crate-map)
- [Documentation](#documentation)
- [License](#license)

---

## Highlights

| Capability | Description |
| --- | --- |
| **Target Discovery** | Semantic + static-analysis scan of a project producing a ranked Target Inventory (fit score, input surface, complexity, call-graph reachability). |
| **Harness Generation** | LLM-authored, compile-validated, smoke-fuzzed harnesses per target. |
| **Engine Integration** | AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, and Syzkaller behind one `EngineAdapter` trait. |
| **Crash Triage** | Dedup by stack signature, CASR severity/exploitability, minimize, and LLM-drafted bug reports under human review. |
| **Corpus & Coverage** | Seed, grow, prune, and merge corpora; track coverage deltas; feed crashes back into the corpus. |
| **AI Assistant** | A conversational agent that drives the whole pipeline with tool calls, live tool-activity updates, and human approval gates. |
| **Multi-Provider LLM Pool** | Tag-based routing, automatic failover, provider freeze/thaw across OpenAI, Anthropic, Gemini, and OpenAI-compatible backends. |
| **Sandboxed Execution** | Every build and fuzz run goes through `hf-runtime` (Docker or native); nothing untrusted runs on the host without approval. |
| **Scheduled Campaigns** | Headless, budget-bounded fuzzing on an interval/cron/once schedule, rotating through a project's promoted targets. |
| **Issue & Vuln Tracking** | File crashes as GitHub/GitLab issues or push them to DefectDojo as findings; export SARIF for code scanning. |
| **Desktop, CLI & Web** | A native macOS app (Tauri v2 + React) with a built-in Help guide, a full CLI/TUI, and a REST + SSE API -- all over the same service core. |

---

## The Desktop App

The desktop app (Tauri v2 + React 19) is the primary way to drive hobot_fuzz. It
links the `hf-service` core directly, so the AI Assistant, discovery, fuzzing,
and triage all run locally with the same sandboxing and guardrails as the CLI.

```bash
./scripts/build-app.sh        # builds target/release/bundle/macos/hobot_fuzz.app + .dmg
open target/release/bundle/macos/hobot_fuzz.app
```

On first launch a short setup wizard configures your LLM provider, checks the
sandbox, and points hobot_fuzz at your first project. After that the left
sidebar is your control panel:

**AI Assistant &middot; Fuzzing Workflow &middot; Discover &middot; Harness &middot; Run &middot; Triage &middot; Corpus &middot; Projects &middot; Artifacts &middot; Agents &middot; Skills &middot; Knowledge &middot; Settings**

### A campaign, end to end

**1. Discover the attack surface.** Point hobot_fuzz at a C/C++ project and it
scans for fuzzable functions, ranking them into a Target Inventory by fit score,
input surface, complexity, and reachability from entry points.

![Discover -- ranked Target Inventory](docs/screenshots/discover.png)

**2. Generate and validate a harness.** Pick a target and the agent writes a
harness for it, compiles it in the sandbox, and runs a 60-second smoke fuzz to
prove it exercises the target. You then review and explicitly approve that
exact revision before any full campaign can start.

![Harness -- generate, compile, and seed](docs/screenshots/harness.png)

**3. Run the fuzzer.** Launch AFL++, honggfuzz, or libFuzzer against the harness.
The Run view streams live progress -- executions/sec, coverage edges, elapsed
time, and any findings -- with a Stop button that cancels the sandboxed run
cooperatively.

![Run -- live fuzzing dashboard](docs/screenshots/run.png)

**4. Triage the crashes.** Crashes are ingested, deduplicated by stack
signature, and classified with CASR for severity and exploitability. The agent
drafts a bug report for each unique finding, and you can export a full Markdown
campaign report with graphs.

![Triage -- crashes, severity, and drafted bug reports](docs/screenshots/triage.png)

**5. Browse the artifacts.** The Artifacts view collects every persisted crash
and corpus input across your targets in one place.

![Artifacts -- crashes and corpus](docs/screenshots/artifacts.png)

### Talk to it instead

Everything above is also available conversationally. The **AI Assistant** drives
discovery, harnessing, running, and triage through tool calls -- ask it to "find
the riskiest parsers in this project and fuzz the top one," approve the steps
that matter, and watch it work. Approval gates (HITL) are enforced at every
untrusted-execution point.

### Settings

The Settings panel is the single source of truth for configuration: LLM provider
pool, engines, sandbox/runtime limits, and guardrail policy.

![Settings -- provider pool configuration](docs/screenshots/settings.png)

> The GUI also runs in the browser against the REST API for development:
> `cd crates/hf-gui && npm run dev:web` (talks to `hobot-fuzz serve` over HTTP).

---

## Install & Build

### Prerequisites

| Dependency | Required? | Notes |
| --- | --- | --- |
| **Rust 1.94+** | Yes | Pinned in `rust-toolchain.toml` |
| **Node 18+ / npm** | Desktop app | For the Tauri v2 frontend (`crates/hf-gui`) |
| **Docker** | Recommended | Sandboxed builds/runs; the app brings it up on launch |
| **SQLite 3.35+** | Embedded | Bundled, no action needed |
| **AFL++ / honggfuzz** | Optional | For those engines (libFuzzer ships with clang) |

### The CLI binary

```bash
git clone <your-hobot_fuzz-remote>
cd hobot_fuzz
cargo build --release
# Binary: target/release/hobot-fuzz
```

### The desktop app (macOS)

```bash
./scripts/build-app.sh
# App:  target/release/bundle/macos/hobot_fuzz.app
# DMG:  target/release/bundle/dmg/hobot_fuzz_0.1.0_aarch64.dmg
```

`scripts/health-check.sh` verifies engine binaries and config presence.

---

## Quick Start (CLI)

### 1. Initialize configuration

```bash
hobot-fuzz init
# Or non-interactive:
hobot-fuzz init --non-interactive --provider openai
```

This materializes the supported `config/*.example.toml` templates and creates
the database. Environment overrides remain explicit in `.env.example`; `init`
does not create or modify `.env`.

### 2. Configure at least one LLM provider

Copy `config/providers.example.toml` to `config/providers.toml` and fill it in,
then export the matching key in the environment that launches `hobot-fuzz`:

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
hobot-fuzz discover /path/to/project --lang c --rank

# Generate a harness for a specific target
hobot-fuzz harness /path/to/project --target parse_value --engine afl++ --promote

# Run the fuzzer
hobot-fuzz run /path/to/project --target parse_value --engine afl++ --duration 60m

# Triage the crashes it found
hobot-fuzz triage /path/to/project --target parse_value
```

---

## Command Reference

| Command | What it does |
| --- | --- |
| `init` | Scaffold config from templates and create/migrate the database. |
| `discover <project> --lang c [--rank]` | Scan a project and produce a ranked Target Inventory. |
| `harness <project> --target <sym> --engine <e> [--draft-only] [--repair N] [--refine] [--promote]` | Write, compile (optionally auto-repair or coverage-refine), and smoke-qualify a harness; `--promote` is the explicit approval step. |
| `run <project> --target <sym> --engine <e> --duration 60m` | Run a sandboxed campaign with the active promoted harness (Ctrl-C cancels cooperatively). |
| `campaign <project> --target <sym> --engine <e>` | Autonomous loop: draft, compile (with repair), qualify, run, and triage without stopping at each gate. |
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
| `schedule list\|create\|history\|... ` | Manage scheduled headless fuzzing campaigns. |
| `session list\|history\|new\|... ` | Manage chat sessions and their checkpoints. |
| `report <project> --target <sym> --out report.md` | Render a full Markdown campaign report. |
| `export [project] --output evidence.json` | Export a reproducibility bundle containing scoped targets, runs, harnesses, crashes, corpus, and filesystem evidence. |
| `serve --host 127.0.0.1 --port 8081` | Start the REST + SSE API (`hf-web`). Non-loopback hosts require `HF_WEB_TOKEN`. |
| `tui <project>` | Terminal UI. |

Engines: `afl++`, `honggfuzz`, `libfuzzer`, `clusterfuzzlite`, `syzkaller`.

The REST API today exposes discovery, harness, corpus, triage, reporting, and
management endpoints. Launching a fuzz run is available from the CLI and the
desktop app; drive campaigns there rather than over REST.

---

## Configuration Reference

Only settings consumed by the production service are exposed as editable
configuration:

- `providers.toml` -- LLM provider pool (routing tags, failover, freeze/thaw).
- `hobot-fuzz.toml` -- coverage-stagnation and coverage-regression policy.
- `defectdojo.toml` -- DefectDojo connection and lifecycle settings.
- `issue_tracker.toml` -- GitHub/GitLab crash issue integration.
- `agents/*.toml` -- Sub-agent definitions (discovery, harness, triage).

Sandbox, engine, storage, session, and tool-registry policy currently use
service-owned safe defaults rather than editable TOML. Runtime locations are
overridden with documented environment variables such as `HF_WORKSPACE_DIR`,
`HF_DB_PATH`, and `HF_CONFIG_DIR`; see `.env.example`. Unsupported legacy
section files are rejected by the config API instead of being accepted as
apparently editable settings.

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

1. **Sandboxed build & run** -- every harness build and fuzzer invocation goes
   through `hf-runtime` (Docker or native); engine binaries and generated
   harnesses are treated as untrusted.
2. **Middleware interception** -- `hf-guardrails` scores each action, enforces a
   permission policy, and detects agent loops.
3. **Human-approved execution** -- generated harnesses are reviewed by an LLM
   triage step *and* a human before running. Smoke evidence and approval are
   persisted against the exact active revision; regenerating invalidates the
   approval. Crash artifacts are parsed in the sandbox and never touch the host
   outside the workspace.

**Generated harnesses are never run on the host without explicit approval.**

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
| `hf-hooks` | Middleware chain, event bus. |
| `hf-tools` | Tool registry and validation with project-scoped `FileRead`, `Glob`, and `Grep`; the agent adds service-backed `KnowledgeSearch`. |
| `hf-mcp` | Model Context Protocol client/server. |
| `hf-skills` | Skill registry, versioning, experience capture. |
| `hf-prompt` | Prompt templates for discovery, harness, triage. |
| `hf-storage` | SQLite storage (sqlx), transcript persistence. |
| `hf-runtime` | Sandbox (Docker/native), resource limits, build isolation. |
| `hf-scheduler` | Cron-style and one-shot campaign scheduling. |
| `hf-knowledge` | Full-text (BM25) retrieval over project source and ingested documents; optional vector search behind the `vector_qdrant` feature. |
| `hf-diagnostics` | Span-based tracing, cost intelligence, run metrics. |
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

- **`docs/guides/GETTING_STARTED.md` -- plain-language intro for non-experts (start here).**
- `VISION.md` -- project vision.
- `AGENTS.md` -- engineering protocol (TDD, risk tiers, quality gates).
- `docs/design/` -- detailed design documents.
- `docs/standards/` -- engineering, testing, harness, target, engine standards.

---

## License

MIT
