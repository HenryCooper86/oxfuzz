# Test Strategy

Status: **active**. Scope: entire repository.

## 1. Methodology

TDD: Red -> Green -> Refactor. No production code without a preceding test.

## 2. Pyramid

- **Unit** (majority): pure functions, trait mocks. Fast, in-process.
- **Integration**: multi-crate flows with mocked LLM + mocked engine.
- **E2E**: full discover -> harness -> run -> triage loop on a fixture
  project with a stubbed engine. Run on CI only.

## 3. Tooling

- Rust: `cargo test`, `criterion` for benchmarks.
- Mocking: hand-rolled trait impls in `hf-test-utils`; avoid heavy mock
  frameworks.
- Fixtures: `tests/fixtures/` for sample projects and crash artifacts.

## 4. Coverage Target

- Domain crates (`hf-discovery`, `hf-harness`, `hf-engine`, `hf-crash`):
  >= 80% line coverage on unit tests.
- Infrastructure crates: >= 70%.
- Presentation crates: smoke tests only.

## 5. Quality Gates

Run in order before declaring a task done:

1. `cargo fmt --all`
2. `cargo clippy --fix --allow-dirty --workspace -- -D warnings`
3. `cargo clippy --workspace -- -D warnings`
4. `cargo check --workspace`
5. `cargo test --workspace`
6. `cargo doc --workspace --no-deps`
7. `cargo deny check`
8. `npm --prefix crates/hf-gui test`
9. `npm --prefix crates/hf-gui run build`
10. `npm --prefix crates/hf-gui run lint`

All `cargo test` invocations use the repository error-output filter documented
in `AGENTS.md`. GitHub Actions and GitLab CI also run an explicit sandbox and
harness-qualification contract job; it uses mocked adapters and never executes
a generated harness on the host.

## 6. Fuzzing-Specific Test Notes

- Never run a real fuzzer in unit tests. Use a `MockEngine` that streams
  canned progress and emits a fixture crash.
- Harness compile tests use a stub compiler in `hf-test-utils` that asserts
  the build command shape without invoking a real toolchain.
- Crash parsing tests use sanitized, public-domain ASan logs in
  `tests/fixtures/crashes/`.
- Harness lifecycle tests must prove persisted `Compiled -> SmokePassed ->
  Promoted` transitions and the fail-closed full-run gate.
