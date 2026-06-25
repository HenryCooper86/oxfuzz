# hobot_fuzz

> An AI fuzzing agent that discovers targets, writes harnesses, and drives open-source fuzzing engines.

**Target Discovery** -- **Harness Generation** -- **Engine Integration** -- **Crash Triage** -- **Corpus & Coverage Loop** -- **Self-Evolving Skills**

---

## Table of Contents

- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Configuration Reference](#configuration-reference)
- [Architecture](#architecture)
- [Crate Map](#crate-map)
- [Building from Source](#building-from-source)
- [Documentation](#documentation)
- [License](#license)

---

## Highlights

| Capability | Description |
| --- | --- |
| **Target Discovery** | Semantic + static-analysis scan of a project producing a ranked Target Inventory. |
| **Harness Generation** | LLM-authored, compile-validated, smoke-fuzzed harnesses per target. |
| **Engine Integration** | AFL++, honggfuzz, libFuzzer, oss-fuzz/ClusterFuzzLite behind one `EngineAdapter` trait. |
| **Crash Triage** | Dedup by stack signature, minimize, draft bug reports under HITL review. |
| **Corpus & Coverage** | Grow, prune, and seed corpora; monitor coverage deltas; propose new harnesses. |
| **Multi-Provider LLM Pool** | Tag-based routing, automatic failover, provider freeze/thaw. |
| **Sandboxed Execution** | All builds and fuzz runs go through `hf-runtime`; nothing runs on host without approval. |
| **Full Observability** | Span-based tracing, cost intelligence, run replay. |
| **Skill Evolution** | Git-like versioning, experience capture, self-improvement with HITL approval. |

---

## Quick Start

### 1. Prerequisites

| Dependency | Required? | Notes |
| --- | --- | --- |
| **Rust 1.94+** | Yes | Pinned in `rust-toolchain.toml` |
| **SQLite 3.35+** | Embedded | Bundled, no action needed |
| **AFL++** | Optional | For AFL++ engine |
| **honggfuzz** | Optional | For honggfuzz engine |
| **libFuzzer** | Optional | Bundled with clang |
| **Docker** | Recommended | For sandboxed builds/runs |

### 2. Build

```bash
git clone https://github.com/hobot/hobot_fuzz.git
cd hobot_fuzz
cargo build --release
# Binary: target/release/hobot-fuzz
```

### 3. Initialize Configuration

```bash
hobot-fuzz init
# Or non-interactive:
hobot-fuzz init --non-interactive --provider openai
```

This generates the configuration tree:

```
./
  .env                            # API key placeholders
  config/
    hobot-fuzz.example.toml       # Global settings
    providers.example.toml        # LLM provider pool  ** MUST configure **
    engines.example.toml          # Fuzzing engine registry
    runtime.example.toml          # Sandbox / resource limits
    guardrails.example.toml       # Permission model, loop detection
    tools.example.toml            # Tool registry limits
    storage.example.toml          # Database
    session.example.toml          # Session tree, compaction
    agents/                       # TOML-based agent definitions
    prompts/                      # System prompt templates
  data/
    transcripts/                  # Session transcripts
  fuzz_workspace/                 # Corpora, crashes, build artifacts
```

### 4. Configure at Least One LLM Provider

Copy `config/providers.example.toml` to `config/providers.toml` and edit it:

```toml
[[providers]]
id = "openai-main"
provider_type = "openai"
model = "gpt-4o"
tags = ["reasoning", "general"]
api_key_env = "OPENAI_API_KEY"
```

### 5. Run a Fuzz Campaign

```bash
# Discover targets in a project
hobot-fuzz discover /path/to/project --lang c

# Generate a harness for a specific target
hobot-fuzz harness /path/to/project --target parse_value --engine afl++

# Run the fuzzer
hobot-fuzz run /path/to/project --target parse_value --engine afl++ --duration 60m

# Triage crashes
hobot-fuzz triage /path/to/project --target parse_value
```

---

## Configuration Reference

See `config/*.example.toml` for full reference. Key files:

- `providers.toml` -- LLM provider pool.
- `engines.toml` -- Fuzzing engine registry and defaults.
- `runtime.toml` -- Sandbox configuration (Docker or native), resource limits.
- `guardrails.toml` -- Permission model, loop detection, risk scoring.
- `agents/*.toml` -- Sub-agent definitions (discovery, harness, triage).

---

## Architecture

```
                +--------------------------------------------------+
                |                  Presentation                    |
                |   hf-cli (CLI/TUI)    hf-web (REST + SSE)        |
                +--------------------------------------------------+
                                       |
                +--------------------------------------------------+
                |                   hf-service                      |
                |       (all business logic, orchestration)         |
                +--------------------------------------------------+
                                       |
        +----------+----------+--------+--------+----------+--------+
        |          |          |        |        |          |        |
   hf-discovery hf-harness hf-engine hf-crash hf-corpus hf-coverage
        |          |          |        |        |          |
        +----------+----------+--------+--------+----------+--------+
                                       |
                +--------------------------------------------------+
                |           hf-agent  -  hf-skills  -  hf-tools     |
                +--------------------------------------------------+
                                       |
        +----------+----------+--------+--------+----------+
        |          |          |        |        |          |
    hf-provider hf-session hf-context hf-storage hf-knowledge hf-runtime
        |          |          |        |        |          |
        +----------+----------+--------+--------+----------+
                                       |
                +--------------------------------------------------+
                |                    hf-core                       |
                |         (traits, types, contracts)               |
                +--------------------------------------------------+
```

---

## Crate Map

| Crate | Role |
| --- | --- |
| `hf-core` | Core types: `LlmProvider`, `Tool`, `TargetCandidate`, `Harness`, `Crash` (the `EngineAdapter` trait lives in `hf-engine`). |
| `hf-provider` | LLM provider pool with tag routing and failover. |
| `hf-session` | Session tree, parent/child delegation, compaction. |
| `hf-context` | Token-budget-aware prompt assembly pipeline. |
| `hf-hooks` | Middleware chain, event bus. |
| `hf-tools` | Tool registry: `ShellExec`, `FileRead`, `FileWrite`, `ProjectScan`, `HarnessBuild`, `FuzzRun`, `CrashMinimize`. |
| `hf-mcp` | Model Context Protocol client/server. |
| `hf-skills` | Skill registry, versioning, experience capture. |
| `hf-prompt` | Prompt templates for discovery, harness, triage. |
| `hf-storage` | SQLite storage, transcript persistence. |
| `hf-runtime` | Sandbox (Docker/native), resource limits, build isolation. |
| `hf-scheduler` | Cron-style and one-shot task scheduling. |
| `hf-knowledge` | RAG over project source, fuzzer docs, CVE patterns. |
| `hf-diagnostics` | Span-based tracing, cost intelligence, run metrics. |
| `hf-guardrails` | Permission model, content filtering, loop detection, risk scoring. |
| `hf-journal` | WAL-based run journaling and replay. |
| `hf-discovery` | Target discovery: static analysis, semantic ranking, Target Inventory. |
| `hf-harness` | Harness generation, compile validation, smoke fuzz. |
| `hf-engine` | `EngineAdapter` adapters: AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, Syzkaller. |
| `hf-crash` | Crash ingestion, dedup, minimization, bug report drafting. |
| `hf-corpus` | Corpus management: seed, grow, prune, merge. |
| `hf-coverage` | Coverage delta tracking, stagnation detection. |
| `hf-service` | Business logic orchestrating all of the above. |
| `hf-agent` | Agent loop, delegation, sub-agent pools. |
| `hf-bot` | Chat adapters (Discord, Slack, Telegram). |
| `hf-web` | REST API + SSE streaming. |
| `hf-cli` | CLI + TUI. |
| `hf-test-utils` | Shared test fixtures and helpers. |

---

## Building from Source

```bash
cargo build --release
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

---

## Documentation

- `VISION.md` -- project vision.
- `AGENTS.md` -- engineering protocol.
- `docs/design/` -- detailed design documents.
- `docs/standards/` -- engineering, testing, harness, target, engine standards.

---

## License

MIT