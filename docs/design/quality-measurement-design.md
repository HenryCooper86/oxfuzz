# Coverage and feature-behavior measurement

Status: Linux baseline enforced. Owner: repository tooling and test
maintainers. This design implements A4 of the project gap assessment.

## Scope and result

The quality gate measures line coverage for the four domain crates named in
`TEST_STRATEGY.md`, the infrastructure crates in the workspace, and `hf-service`.
It runs the selected package tests with `cargo-llvm-cov` and consumes its JSON
summary. The report attributes source files under `crates/<package>/src/` to
that package. Test source, dependencies, generated code, and code compiled only
on other operating systems are outside this Linux report. The report records
that limitation and must not be presented as cross-platform coverage.

The checked-in baseline stores line counts and covered counts from the successful
Linux CI run at revision `9dd9846da166f259c954f6869a7e29d21aeffd23` on the
pinned Rust toolchain. Every required package must appear with
nonzero measured lines. Missing or malformed report data fails the job. The
current percentage must not fall below its recorded baseline percentage;
comparison uses integer counts rather than rounded displayed percentages.
Domain packages retain the 80% target and infrastructure packages the 70%
target. A baseline below its target remains an explicit gap in the report; it
does not redefine the target. `hf-service` has a no-regression baseline while
its safety paths receive focused behavioral tests.

The baseline is intentionally changed only with a reviewed explanation of the
source or test change. A deleted package fails measurement; changes to test
selection or platform-specific source require an explicit review of the
measurement definition and baseline. The JSON reports are CI artifacts, and
the human-readable result appears in the job log.

## Feature behavior

Compilation of each product feature remains in the existing feature matrix.
The test gate additionally executes the workspace without default features and
selected safety-sensitive standalone features. Its focused cases must exercise
denied service operations and disabled API responses, along with successful
feature-enabled paths. No live harness or network provider is part of these
tests. New standalone features join the selected behavior set when they add a
service operation or wire route whose absence matters to users.

## Deployment

The Linux gate now enforces `config/quality/coverage-baseline.json`; GitHub's
aggregate `All gates passed` job and GitLab's gate stage require coverage
validation and feature behavior. On other hosts the gate reports diagnostic
measurements because the measured source set differs. A missing
tool, missing report, failed test, or incomplete package measurement fails the
gate. A lower initial percentage is reported as work to close, not silently
accepted as the final standard.

The initial Linux result covers 18 crates. All four domain packages exceed
80%; `hf-runtime` is at 707/1120 lines (63.12%), below its 70% infrastructure
target. Its baseline prevents regression while focused runtime tests close
the remaining gap. No improvement to this package is claimed by enabling the
gate.

## Rejected alternatives

- A text-table parser would depend on formatting and rounded percentages; the
  JSON summary preserves exact covered and total line counts.
- Immediately enforcing 80% and 70% without a measured baseline would make the
  first gate fail without identifying the change responsible for the shortfall.
- Compiling disabled features without executing their denial paths would not
  establish user-visible fail-closed behavior.

## Verification

Parser tests cover missing packages, malformed or duplicate files, zero-line
reports, invalid baselines, and a measured regression. The same tests establish
that a complete report at or above baseline passes. Gate tests assert the
selected cargo arguments and CI invocation. A deliberately lowered report must
fail locally and in CI; the retained Linux artifact must permit recomputation
of every reported percentage.
