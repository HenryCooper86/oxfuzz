# Test Strategy

Status: **active**. Scope: entire repository.

## 1. Methodology

TDD: Red -> Green -> Refactor. No production code without a preceding test.

## 2. Pyramid

- **Unit** (majority): pure functions, trait mocks. Fast, in-process.
- **Integration**: multi-crate flows with mocked LLM + mocked engine.
- **E2E**: full discover -> harness -> run -> triage loop on a fixture
  project with a stubbed engine. Runs in the workspace `test` gate, locally and
  in CI.

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

Measured by `scripts/tests/gates.sh coverage` using structured `cargo-llvm-cov`
reports over the four domain crates, the infrastructure crates, and
`hf-service`. The report names each crate's covered and total source lines.
This is Linux/default-feature coverage; code compiled only on another OS or
under another feature selection is outside the measurement. Until a trusted
Linux baseline is committed, the job reports results and fails on missing data
without enforcing percentages. The [measurement design](../design/quality-measurement-design.md)
defines the no-regression gate and the separate 80%/70% targets.

## 5. Quality Gates

Run in order before declaring a task done:

1. `cargo fmt --all`
2. `cargo clippy --fix --allow-dirty --workspace -- -D warnings`
3. `cargo clippy --workspace -- -D warnings`
4. `cargo check --workspace`
5. `cargo test --workspace`
6. `scripts/tests/gates.sh feature-behavior`
7. `cargo doc --workspace --no-deps`
8. `cargo deny check`
9. `scripts/tests/gates.sh coverage`
10. `scripts/verify_translation_pairing.py`
11. `npm --prefix crates/hf-gui test`
12. `npm --prefix crates/hf-gui run build`
13. `npm --prefix crates/hf-gui run lint`

All `cargo test` invocations use the repository error-output filter documented
in [Engineering Protocol](ENGINEERING_PROTOCOL.md). The workspace test suite includes an explicit sandbox and
harness-qualification contract test
(`hf-service/tests/harness_qualification.rs`); it uses mocked adapters and
never executes a generated harness on the host. Both GitHub Actions and
GitLab CI run it as part of the `test` gate (`cargo test --workspace`), not
as a separate job.

## 6. Fuzzing-Specific Test Notes

- Never run a real fuzzer in unit tests. Use a `MockEngine` that streams
  canned progress and emits a fixture crash.
- Harness compile tests use a stub compiler in `hf-test-utils` that asserts
  the build command shape without invoking a real toolchain.
- Crash parsing tests use sanitized, public-domain ASan logs in
  `tests/fixtures/crashes/`.
- Harness lifecycle tests must prove persisted `Compiled -> SmokePassed ->
  Promoted` transitions and the fail-closed full-run gate.
- `hf-automotive` contract tests are pure, feature-enabled Rust tests. They
  cover stable serde names, schema rejection, validation bounds, mode/approval
  structure, replay consistency, structured errors, and canonical transcript
  and state hashes. Default-feature builds must not require Scapy or Python.
- Automotive sidecar and service tests use immutable PCAP fixtures and
  fake JSONL/runtime transcripts. Default tests never invoke Python, open CAN or
  SocketCAN interfaces, execute a real fuzzer, or contact a physical bench.
