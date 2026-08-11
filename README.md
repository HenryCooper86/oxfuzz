# oxfuzz

**English** &middot; [中文](README.zh.md)

[![CI](https://github.com/HenryCooper86/oxfuzz/actions/workflows/ci.yml/badge.svg)](https://github.com/HenryCooper86/oxfuzz/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust 1.94](https://img.shields.io/badge/Rust-1.94-orange.svg)](rust-toolchain.toml)

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
of every term.

---

## Highlights

| Capability | Description |
| --- | --- |
| **Operational Dashboard** | Readiness, harness-review state, recent campaigns, crash handoff, and evidence counts in one operator-focused view. |
| **Target Discovery** | Semantic + static-analysis scan of a project producing a ranked Target Inventory (fit score, input surface, complexity, call-graph reachability). |
| **Optional Semgrep Enrichment** | Explicit C/C++-only enrichment adds capped, advisory static-analysis signals from a pinned offline rules snapshot without changing normal discovery. |
| **Harness Generation** | LLM-authored, compile-validated, smoke-fuzzed harnesses per target. |
| **Engine Integration** | AFL++, honggfuzz, libFuzzer, and syzkaller behind one `EngineAdapter` trait. |
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

## Quick start

The **[Getting Started guide](docs/guides/GETTING_STARTED.md)** walks through the
desktop app; the **[CLI Reference](docs/guides/CLI_REFERENCE.md)** covers every
subcommand. The short version:

```bash
git clone <your-oxfuzz-remote> && cd oxfuzz
cargo build --release                 # binary: target/release/oxfuzz
./scripts/build-sandbox.sh            # build and verify the fuzzing sandbox image

oxfuzz init                           # scaffold config/*.toml + .env
# then configure at least one LLM provider: config/providers.toml + HF_PROVIDER_API_KEY

oxfuzz discover <project> --lang c --rank
oxfuzz harness  <project> --target <symbol> --engine libfuzzer
oxfuzz run      <project> --target <symbol> --engine libfuzzer --duration 60m
oxfuzz triage   <project> --target <symbol>
```

Docker must be installed and running, and at least one LLM provider configured.
See **[Install & Build](docs/guides/INSTALL.md)** and
**[Configuration](docs/guides/CONFIGURATION.md)** for the full setup.

---

## Documentation

New here? Start with the **[Getting Started guide](docs/guides/GETTING_STARTED.md)**
-- a plain-language intro for non-experts.

**Guides**

- [Install & Build](docs/guides/INSTALL.md) -- prerequisites, CLI and desktop builds, prebuilt apps, and optional DefectDojo.
- [The Desktop App](docs/guides/DESKTOP_APP.md) -- the primary UI: a campaign end to end, the AI Assistant, and settings.
- [CLI Reference](docs/guides/CLI_REFERENCE.md) -- every subcommand, the quick-start flow, optional Semgrep enrichment, and automotive workflows.
- [Configuration](docs/guides/CONFIGURATION.md) -- the config tree, providers, and environment.
- [Safety Model](docs/guides/SAFETY_MODEL.md) -- sandboxing, guardrails, and human-in-the-loop approval.
- [Syzkaller setup](docs/guides/SYZKALLER_SETUP.md) &middot; [Release checklist](docs/guides/RELEASE_CHECKLIST.md) &middot; [Continuous integration](docs/guides/CI.md)

**Reference**

- [Architecture](docs/ARCHITECTURE.md) -- layering, the `hf-service` spine, and the crate map.
- [Documentation map](docs/README.md) -- routes readers by audience and task.
- [Design documents](docs/design/) &middot; [Engineering standards](docs/standards/)

**Project**

- [Contributing](CONTRIBUTING.md) &middot; [Security policy](SECURITY.md) &middot; [Vision](VISION.md) &middot; [Engineering protocol](AGENTS.md)

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
