# Contributing to oxfuzz

Thanks for your interest in oxfuzz. Bug reports, documentation fixes, tests,
and code are all welcome. This page starts with the short path from a fresh
clone to a pull request, then covers the project rules in more depth.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). For questions, see
[SUPPORT.md](SUPPORT.md). Report security issues privately as described in
[SECURITY.md](SECURITY.md), never in a public issue or pull request.

## Quick start

### Prerequisites

- **git** and **Rust through [rustup](https://rustup.rs)**. The toolchain is
  pinned in `rust-toolchain.toml` (currently 1.94.0, with `rustfmt` and
  `clippy`). rustup normally installs it the first time you run `cargo` in
  the repository; if it does not, run `rustup toolchain install` from the
  repository root.
- **Linux only, for the desktop crate**: the workspace includes the Tauri
  desktop shell (`crates/hf-gui/src-tauri`), which needs WebKitGTK and related
  system packages. `scripts/ci/install-linux-deps.sh` installs them on
  Debian and Ubuntu. Any `--workspace` command builds that crate. If you are
  not working on the desktop app, scope commands to a package instead
  (`cargo build -p hf-cli`, `cargo test -p hf-engine`) and you do not need
  those packages. macOS and Windows need nothing extra.
- **Node 22 and npm** only if you change the desktop frontend in
  `crates/hf-gui`.
- **Docker** only to run real harness builds and fuzzing campaigns. It is not
  needed to build or to run the test suite.
- **No LLM provider key** is needed to build or test.

### Build the CLI

```bash
git clone https://github.com/HenryCooper86/oxfuzz.git
cd oxfuzz
cargo build --release -p hf-cli
./target/release/oxfuzz --help
./target/release/oxfuzz doctor     # checks Docker, the sandbox image, and engines
```

To use the tool itself, continue with
[Getting Started](docs/guides/GETTING_STARTED.md).

### Run the tests

```bash
cargo test -p <crate>              # the crates you changed
cargo test --workspace             # everything (on Linux, needs the packages above)
```

The default test suite needs no Docker daemon, no sandbox image, no LLM key,
and no Python. Tests that do need one of those, or that are manual profiling
or measurement runs, are marked `#[ignore = "..."]` with the reason, so a
plain `cargo test` skips them. Examples are the live sandbox isolation tests in
`hf-runtime`, the live provider and Docker tests in `hf-service`, the Python
restore probe in `crates/hf-storage/tests/restore_migration.rs`, and the queue
profile in `crates/hf-service/tests/finding_review.rs`, which also reads
`OXFUZZ_PERFORMANCE_RUNNER`. If you have the setup a reason names, run one
explicitly:

```bash
cargo test -p hf-runtime --test live_isolation -- --ignored
```

Some tests create throwaway git repositories, so `git` must be on your `PATH`.

`./scripts/cargo-test-filtered.sh` takes the same arguments as `cargo test` and
hides the per-test noise so failures are easier to read.

### Before you open a pull request

Run at least these for the crates you touched:

```bash
cargo fmt --all
cargo clippy -p <crate> --all-targets -- -D warnings
cargo test -p <crate>
```

For frontend changes:

```bash
npm --prefix crates/hf-gui ci
npm --prefix crates/hf-gui test
npm --prefix crates/hf-gui run lint
```

`scripts/tests/gates.sh <gate>` runs any single CI gate locally, for example
`scripts/tests/gates.sh clippy test`. Running every gate takes a while and
needs extra tools (`cargo-deny`, `cargo-llvm-cov`, Python 3, Node), so it is
not required before opening a pull request.

### What CI checks

GitHub Actions (`.github/workflows/ci.yml`) runs on every pull request. It
uses the gate definitions in `scripts/tests/gates.sh`: formatting, clippy with
`-D warnings` across all targets and feature combinations, the full workspace
tests, docs, dependency policy (`cargo deny`), a per-crate coverage baseline,
script tests, and the frontend tests and lint, on Linux. It also runs
`cargo check` and the tests on macOS and Windows. One aggregate check,
**All gates passed**, reports whether every job succeeded. If this is your
first contribution, a maintainer may need
to approve the workflow before it runs. See
[docs/guides/CI.md](docs/guides/CI.md) for details.

The coverage gate fails if a crate's line coverage drops below the recorded
baseline, so new code needs tests.

### Finding something to work on

Issues labeled
[good first issue](https://github.com/HenryCooper86/oxfuzz/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
are a good place to start. For anything larger than a small fix, open or
comment on an issue first so the approach can be agreed before you spend time
on it. This matters most for changes to the sandbox, guardrails, or approval
flow.

## Project rules

The full engineering protocol is
[docs/standards/ENGINEERING_PROTOCOL.md](docs/standards/ENGINEERING_PROTOCOL.md).
You do not need to read all of it, or every standard, before a first
contribution. The sections below are the parts that most often matter in
review, with links to the standard that applies.

### Architecture

Dependencies point inward toward `hf-core`. All business logic lives in
`hf-service`; the CLI (`hf-cli`), REST API (`hf-web`), and desktop app
(`hf-gui`) only do I/O, rendering, and user interaction, and call the service.
New subsystems go behind a feature flag and extend existing traits rather than
changing core contracts. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[docs/design/DESIGN_OVERVIEW.md](docs/design/DESIGN_OVERVIEW.md).

If you change a fuzzing-domain crate (discovery, harness, engine, crash,
corpus, coverage), read its design document in `docs/design/` first. The
implementation must match the design. If the design is wrong or impractical,
update the document in the same pull request.

### Safety

oxfuzz runs untrusted code: generated harnesses, fuzzing engines, crash
inputs, and the targets themselves. Changes must keep these rules:

- Never execute a generated harness, engine binary, or crash input on the
  host. Builds and execution go through the `hf-runtime` sandbox.
- Keep human promotion bound to the exact reviewed harness revision before a
  full campaign.
- Do not weaken network blocking, resource limits, workspace boundaries, or
  guardrail interception.
- Do not use a physical automotive interface for development or tests.
- Keep API keys, target source, runtime databases, corpora, and crash
  artifacts out of commits, logs, and screenshots.

See [docs/guides/SAFETY_MODEL.md](docs/guides/SAFETY_MODEL.md) and
[docs/standards/DEFENSIVE_PATTERNS.md](docs/standards/DEFENSIVE_PATTERNS.md).

### Tests first

Behavior changes start with a failing test, then the smallest change that makes
it pass, then refactoring with the test green. A bug fix should include a test
that fails without the fix. Never get to green by deleting, ignoring, or
weakening a test. See
[docs/standards/TEST_STRATEGY.md](docs/standards/TEST_STRATEGY.md).

### Risk tiers

The protocol sorts changes into three tiers:

- **Low**: typos and small documentation fixes.
- **Medium**: new features, targets, or sections within one area.
- **High**: shared concepts such as the permission model, sandbox policy,
  harness generation pipeline, or engine adapter contract, and changes that
  span several design documents.

When unsure, treat a change as high risk. High-risk changes should start with
an issue that states the problem, scope, and success criteria.

### Code style

- Clippy runs with the `pedantic` group workspace-wide and `-D warnings` in
  CI. Fix the code rather than adding `#[allow(clippy::...)]`. If a lint is
  genuinely wrong for this project, change the workspace configuration
  (`Cargo.toml` or `clippy.toml`) with a comment explaining why.
- Rust naming: `snake_case` files and functions, `PascalCase` types,
  `SCREAMING_SNAKE_CASE` constants.
- No emoji in code or documentation.
- See [docs/standards/ENGINEERING_STANDARDS.md](docs/standards/ENGINEERING_STANDARDS.md).

### Standards by area

| If you change | Read |
| --- | --- |
| An engine adapter | [ENGINE_ADAPTER_STANDARD.md](docs/standards/ENGINE_ADAPTER_STANDARD.md) |
| Harness generation | [HARNESS_STANDARD.md](docs/standards/HARNESS_STANDARD.md) |
| Target discovery | [TARGET_TAXONOMY.md](docs/standards/TARGET_TAXONOMY.md) |
| The database schema or migrations | [DATABASE_SCHEMA.md](docs/standards/DATABASE_SCHEMA.md) |
| Agent tools or tool calls | [TOOL_CALL_PROTOCOL.md](docs/standards/TOOL_CALL_PROTOCOL.md) |
| Agent delegation or autonomy | [AGENT_AUTONOMY.md](docs/standards/AGENT_AUTONOMY.md) |

### Documentation and screenshots

When behavior or a public contract changes, update the README, the user guides
in `docs/guides/`, and the design documents and standards that describe it.
`README.md` and `README.zh.md` are a checked translation pair: if you change
one, ask in the pull request for help with the other rather than leaving it
stale. Follow [docs/screenshots/README.md](docs/screenshots/README.md) when
refreshing product images. Documentation should not imply that AI output
overrides deterministic results, guardrails, or human approval.

### Commits and pull requests

- Keep one concern per pull request and write commit messages in English.
- Add user-visible changes to the `Unreleased` section of
  [CHANGELOG.md](CHANGELOG.md).
- In the pull request, explain the user impact, any safety impact, and how you
  verified the change.
- Pull requests are merged only with green CI and no unresolved high-risk
  review findings.

Releases are prepared by the maintainer; see
[docs/guides/RELEASE_CHECKLIST.md](docs/guides/RELEASE_CHECKLIST.md).

## License

oxfuzz is released under the [MIT License](LICENSE). By contributing, you agree
that your contributions are licensed under the same terms.
