# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`oxfuzz` is a Rust-first AI fuzzing agent: it discovers fuzz targets in a project, writes harnesses with an LLM, drives open-source fuzzing engines (AFL++, honggfuzz, libFuzzer, ClusterFuzzLite, Syzkaller), triages crashes, and iterates on corpus/coverage — all under human-in-the-loop supervision and sandboxed execution.

**Read `AGENTS.md` first.** It is the mandatory engineering protocol (TDD, risk tiers, quality gates, safety rules) and overrides general habits. This file covers build/run mechanics and architecture; `AGENTS.md` covers process. Before implementing in a fuzzing-domain crate, read the matching doc in `docs/design/` and the relevant `docs/standards/` file — implementation must conform to the design.

## Build, test, lint

Pinned toolchain: Rust 1.94 (`rust-toolchain.toml`). The single binary is `oxfuzz` (from `hf-cli`).

```bash
cargo build --release                          # binary: target/release/oxfuzz
cargo test --workspace                         # all tests
cargo test -p hf-engine <name>                 # single crate / filtered test
```

**Post-change quality gates — run in this order, fix everything before declaring done** (from `AGENTS.md` §4.5):

```bash
cargo fmt --all
cargo clippy --fix --allow-dirty --workspace -- -D warnings
cargo clippy --workspace -- -D warnings        # must be zero warnings
cargo check --workspace
cargo doc --workspace --no-deps
```

Clippy runs `pedantic` workspace-wide. **Do not add inline lint suppressions** (`#[allow(clippy::...)]`); fix the code or move the rule to the owning config with a justifying comment. Only sanctioned exception: `#[allow(dead_code)]` on fields/variants kept for API completeness.

When running `cargo test`, filter the noise (from `AGENTS.md` §4.6):

```bash
cargo test [args] 2>&1 | grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' | head -200
```

## Running the app

```bash
oxfuzz init                                # generate config tree (config/*.toml, .env)
oxfuzz discover <project> --lang c [--rank]
oxfuzz harness <project> --target <sym> --engine afl++ [--draft-only]
oxfuzz run <project> --target <sym> --engine afl++ --duration 60m
oxfuzz triage <project> --target <sym>
oxfuzz corpus <project> --target <sym> --op seed|grow|prune|list
oxfuzz serve --port 8081                   # REST API (hf-web::build_bootstrapped)
oxfuzz tui <project>                        # terminal UI
```

At least one LLM provider must be configured: copy `config/providers.example.toml` to `config/providers.toml` and fill it in, plus set `HF_PROVIDER_API_KEY` (see `.env.example`). `scripts/health-check.sh` verifies engine binaries and config presence.

### Desktop GUI (Tauri v2 + React 19)

The GUI lives in `crates/hf-gui` (frontend) with the Tauri shell in `crates/hf-gui/src-tauri` (a workspace crate that links `hf-service` directly — Tauri commands in `src-tauri/src/commands.rs` call the service, not the REST API).

```bash
cd crates/hf-gui
npm install
npm run dev          # Vite dev server (Tauri frontend)
npm run dev:web      # browser mode talking to hf-web over HTTP (VITE_BACKEND=http)
npm run lint         # eslint
npm run test         # vitest
```

Build the full macOS `.app`/`.dmg` with `./scripts/build-app.sh` (or double-click `rebuild-and-run.command`). Build the Docker fuzzing sandbox image with `./rebuild-sandbox-image.command`.

## Architecture

Strict layering, dependencies point inward toward `hf-core`. Every subsystem is behind a feature flag.

```
Presentation:  hf-cli (CLI+TUI) · hf-web (REST+SSE) · hf-gui (Tauri desktop)
                                  │
Service:                      hf-service          ← ALL business logic lives here
                                  │
Fuzzing domain:  hf-discovery · hf-harness · hf-engine · hf-crash · hf-corpus · hf-coverage
                                  │
Agent layer:        hf-agent · hf-skills · hf-tools
                                  │
Infrastructure: hf-provider · hf-session · hf-context · hf-storage · hf-knowledge · hf-runtime
                                  │
Core:                          hf-core            ← traits, types, contracts
```

**The single most important structural rule** (`AGENTS.md` §2.9): all domain/business logic lives in `hf-service`; `hf-cli`, `hf-web`, and `hf-gui` are thin presentation layers doing only I/O, rendering, and user interaction. `ServiceContainer` (`hf-service/src/container.rs`) is the orchestration surface — its methods (`discover`, `rank`, `harness_draft`/`_compile`/`_smoke`, `run_fuzzer`, `triage`, `corpus_*`, `chat_send`) are what every presentation layer calls. When adding a feature, the logic goes in `hf-service`; presentation crates just wire it up.

### Key crate roles (see README "Crate Map" for the full table)

- `hf-core` — shared traits/types: `LlmProvider`, `Tool`, `TargetCandidate`, `Harness`, `Crash`. (The `EngineAdapter` trait lives in `hf-engine`, not here.)
- `hf-engine` — `EngineAdapter` implementations for each fuzzer behind one trait (`docs/standards/ENGINE_ADAPTER_STANDARD.md`).
- `hf-runtime` — the sandbox. **Every harness build and fuzzer invocation goes through it** (Docker or native). Engine binaries and generated harnesses are untrusted.
- `hf-provider` — multi-provider LLM pool with tag-based routing, failover, freeze/thaw.
- `hf-guardrails` — permission model, loop detection, risk scoring (the interception layer).
- `hf-storage` — SQLite (sqlx) persistence; schema in `docs/standards/DATABASE_SCHEMA.md`.
- `hf-service::recovery` — bounded, synced run WAL and interrupted-run replay.
- `hf-skills` — user-editable skill registry (skills are authored by a human, not created by the agent at runtime); bundled skill content in `crates/hf-skills/src/builtins/*/root.md`.

### Safety model (non-negotiable — `AGENTS.md` §2.5, §2.12)

Defense in depth: sandboxed build (`hf-runtime`) → middleware interception (`hf-guardrails`) → human-approved execution. Fuzzing runs untrusted, possibly-malformed code. **Never run a generated harness on the host without explicit user approval.** Generated harness source is reviewed by an LLM triage step *and* a human before execution; crash artifacts are parsed in the sandbox and never touch the host filesystem outside the workspace.

## Conventions

- Rust casing: `snake_case` files/fns, `PascalCase` types, `SCREAMING_SNAKE_CASE` consts.
- TDD is mandatory: write the failing test first (`docs/standards/TEST_STRATEGY.md`).
- No emoji anywhere in the codebase or docs.
- Before any R&D action, write a plan to `.claude/plans/` (scope, steps, dependencies, verification) — see existing phase plans there.
- New subsystems must be feature-flagged and extend via traits/middleware, not by modifying core contracts.
