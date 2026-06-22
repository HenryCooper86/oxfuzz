# hobot_fuzz -- Vision

## Project Positioning

hobot_fuzz is not a generic chatbot or a replacement for OSS-Fuzz
infrastructure. It is an **AI fuzzing agent** -- an autonomous assistant that
collaborates with a security engineer to bring LLM-driven reasoning to the
tedious, repetitive parts of fuzzing:

1. **Finding what to fuzz** in a target codebase.
2. **Writing the harness** that exercises a chosen target.
3. **Driving a fuzzing engine** (AFL++, honggfuzz, libFuzzer, oss-fuzz /
   ClusterFuzzLite) under safe supervision.
4. **Triaging crashes** and proposing reproducers / bug reports.
5. **Iterating** on corpus and coverage to deepen the search.

## Design Philosophy

### Long-Termism

LLMs will keep improving, but the **fuzzing workflow** is stable:
identify target, build harness, run engine, triage crash. hobot_fuzz
encodes that workflow into a durable Rust architecture so that swapping
the model never requires re-architecting the agent.

### Engineering Quality First

We reject the common pattern of "AI wrote a harness, it compiled, ship it."
hobot_fuzz pursues:

- **Deep understanding of the target** before proposing a harness.
- **Model-agnostic design** -- works on GPT, Claude, DeepSeek, Qwen, local
  models. Reasoning-heavy prompts degrade gracefully on weaker models.
- **Safety-first execution** -- harnesses build and run inside a sandbox;
  nothing executes on the host without explicit human approval.
- **Reproducibility** -- every run, corpus mutation, and crash is journaled
  and replayable.

### Developer, Not Beginner

The target user is a security engineer or developer who understands fuzzing
fundamentals, build systems, and sanitizers. hobot_fuzz amplifies their
throughput; it does not replace their judgment.

## Target Users

- Security engineers running continuous fuzzing for a C/C++/Rust/Go/Python
  project.
- Library maintainers who want to add fuzzing without learning every engine.
- Researchers prototyping harness strategies at scale.

## Core Capabilities

### 1. Target Discovery (`hf-discovery`)

The agent walks a project using semantic search + static-analysis heuristics
and produces a ranked **Target Inventory**: each candidate target includes
location, complexity, input surface, sanitizers, and a fit score.

### 2. Harness Generation (`hf-harness`)

Given a target, the agent drafts a harness, validates it compiles (inside the
sandbox), runs a smoke fuzz, and iterates until the harness is stable. Harness
authoring follows `docs/standards/HARNESS_STANDARD.md`.

### 3. Engine Integration (`hf-engine`)

A single `FuzzEngine` trait fronts AFL++, honggfuzz, libFuzzer, and
ClusterFuzzLite. The agent selects an engine per target and runs it under
configurable resource limits.

### 4. Crash Triage (`hf-crash`)

Crash artifacts are ingested, deduplicated by stack signature, minimized, and
turned into a draft bug report the human reviews.

### 5. Corpus & Coverage Loop (`hf-corpus` / `hf-coverage`)

The agent grows and prunes the corpus, watches coverage deltas, and proposes
new harness variants when coverage stagnates.

### 6. Self-Evolving Skills (`hf-skills`)

Skills such as `target-triage`, `harness-author`, and `crash-triage` improve
with experience capture and HITL approval, following the same skill format as
y-agent.

## Example Workflow

User: "Fuzz the JSON parser in `src/json/`."

Agent (autonomous, with HITL gates):

1. **Discovery** -- indexes `src/json/`, ranks `parse_value`, `parse_object`,
   `parse_array` as high-fit targets.
2. **Harness author** -- drafts `fuzz_parse_value.c`, builds it with
   `-fsanitize=address,fuzzer` in the sandbox, runs a 60-second smoke fuzz.
3. **Engine run** -- launches AFL++ on the stable harness under
   `hf-runtime` limits; streams progress to the CLI/TUI.
4. **Crash triage** -- on crash, minimizes the input, classifies
   (heap-buffer-overflow), drafts a bug report.
5. **Iterate** -- adds the minimized crash to the corpus, restarts the fuzzer,
   monitors coverage; proposes a second harness for `parse_object` when
   coverage plateaus.

## Technical Vision

1. **Architectural Stability** -- core architecture supports 5-10 years of LLM
   evolution without rewrite.
2. **Model Adaptability** -- works from GPT-3.5-class to Claude Opus-class.
3. **Extensibility** -- new engines, new target languages, new triage
   strategies added via traits and config, not core changes.
4. **Engineering** -- span-based tracing, cost intelligence, run replay,
   deterministic fuzzing seeds.
5. **Performance** -- async tool dispatch, concurrent engine runs, streaming
   progress.

## Value Proposition

hobot_fuzz does not replace the security engineer's judgment. It removes the
mechanical drudgery of fuzzing -- finding targets, writing harnesses, baby-
sitting fuzzers, triaging crashes -- so the engineer spends their time on
verdicts and architecture instead of boilerplate.

---

**hobot_fuzz: AI-assisted fuzzing for engineers who already know how to fuzz.**