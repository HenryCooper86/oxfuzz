# Code Health and Continuous Integration Design

Status: **approved design**. Owner: repository tooling, `hf-service`, and
`hf-gui`.

## 1. Goal

Put an automated quality gate in front of every change, and decompose the
`hf-service` orchestration file that every future change has to touch.

This is the first of four sequenced projects agreed on 2026-07-31. The
remaining three (trust and audit trail, agent protocol modernization, Go and
Python language reach) each get their own design cycle. This one comes first
because it is the safety net the others land against.

Scope of this increment:

- a GitHub Actions workflow running the repository's mandated gates on push
  and pull request;
- `scripts/tests/gates.sh` gains selectable gate arguments so continuous
  integration and local runs share one definition;
- `crates/hf-service/src/container.rs` becomes a `container/` module tree;
- security-relevant free functions in that file become named, independently
  testable modules;
- three small corrections that belong with this work.

Out of scope: cross-platform test matrices, feature-flag matrices, sub-service
extraction from `ServiceContainer`, and any change to public service, REST, or
Tauri APIs.

## 2. Approved Product Decisions

1. Continuous integration runs on Linux only. Cross-platform coverage stays
   with `release.yml`, which already builds all four platform bundles on tag.
2. All eight gates defined by `scripts/tests/gates.sh` run in continuous
   integration. None are dropped for speed.
3. `scripts/tests/gates.sh` remains the single definition of what a gate is.
   Continuous integration invokes it rather than re-listing commands.
4. The container decomposition changes no public API. `hf-cli`, `hf-web`, and
   `hf-gui` are untouched by it.
5. Free functions with genuine boundaries are extracted into named modules with
   their own tests. `ServiceContainer` methods are relocated only.
6. Sub-service extraction (`HarnessService`, `RunService`, and similar) is
   explicitly deferred until the agent and language projects establish where
   the real seams are.
7. A move commit contains only moves. Behavior changes land separately.

## 3. Motivation and Local Gap

### 3.1 No automated gate

`.github/workflows/` contains `release.yml` and `fuzz.yml.example`. Neither
runs tests, lints, or dependency checks. `scripts/tests/gates.sh` defines the
full gate sequence but only runs when a developer remembers to invoke it. The
README refers to "GitLab CI jobs for locked all-feature coverage"; no
`.gitlab-ci.yml` exists in the repository. Every quality guarantee in
`AGENTS.md` currently depends on manual discipline.

The repository is being prepared for public release. An open repository with no
visible gate invites contributions that cannot be evaluated mechanically, and
gives a reader no evidence that the stated standards are enforced.

Cost is not an obstacle. The full suite runs in 69 seconds warm with 2534 tests
passing, and Linux runners are free for public repositories.

### 3.2 One file absorbs every feature

`crates/hf-service/src/container.rs` is 12438 lines. It holds:

- roughly 2600 lines of free functions, constants, and types before the
  `ServiceContainer` struct declaration;
- the struct and its RAII guards;
- 131 public methods spanning discovery, harness authoring, run execution,
  triage, corpus operations, chat, reporting, and integrations;
- 16 colocated `#[cfg(test)]` modules.

`AGENTS.md` requires units that have one clear purpose and can be understood
and tested independently. This file satisfies neither. It also concentrates
merge conflict risk: the next three projects all add service methods.

The security-critical portions are the most affected. Workspace boundary
enforcement, symlink refusal, approval-to-execution digest verification, and
run output budget accounting are currently free functions buried above a god
object, reachable only through the tests of whichever method happens to
exercise them.

### 3.3 A gate that fails on success

`scripts/tests/gates.sh` line 17 runs:

```
cargo test --workspace 2>&1 | grep -v '...' | head -200
```

The script sets `set -euo pipefail`. When filtered output exceeds 200 lines,
`head` closes the pipe, `grep` terminates on `SIGPIPE` with status 141, and
`pipefail` propagates that as a pipeline failure. A fully passing test run can
therefore fail the gate. Continuous integration is about to depend on this
script, so the truncation must go.

### 3.4 Stale backlog entries

Two `TODO.md` items no longer describe reality:

- Line 99 asks to complete or remove `hf-mcp` and `hf-hooks`. Neither crate
  exists in `crates/`.
- Lines 176 and 177 state that guardrail authorization decisions are only
  traced, never persisted. Migration `0018_guardrail_decisions.sql`,
  `Store::list_guardrail_decisions`, `ServiceContainer::policy_decisions`, the
  CLI `policy decisions` subcommand, and the REST `/policy/decisions` route all
  exist and are covered by tests.

### 3.5 Persisted decisions with no desktop surface

The persistence described above has no Tauri command and no desktop view.
`crates/hf-gui/src/views/AuditView.tsx` line 43 invokes `auto_revert_events`
only. An operator using the desktop app cannot see the approval chain the
service records, even though the CLI and REST API expose it. This is the
entirety of what remained of the separately scoped trust and audit project, so
it lands here rather than as its own cycle.

## 4. Architectural Ownership

| Concern | Owner |
| --- | --- |
| Gate definition | `scripts/tests/gates.sh` |
| Gate execution on push | `.github/workflows/ci.yml` |
| Service orchestration | `crates/hf-service/src/container/` |
| Decision persistence | `hf-storage` (unchanged) |
| Decision presentation | `hf-gui` Tauri command and `AuditView.tsx` |

Layering is unchanged. The decomposition moves code within `hf-service` and
introduces no new crate, no new dependency, and no new feature flag. The
desktop wiring adds a Tauri command that calls an existing service method,
consistent with the rule that presentation layers only perform input, output,
and rendering.

## 5. Continuous Integration Design

### 5.1 Trigger and concurrency

```yaml
on:
  push:
  pull_request:

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true
```

Every branch is gated, not only pull requests, so a developer sees failures
before opening a merge request. Superseded runs cancel so a rapid push sequence
does not queue redundant work.

### 5.2 Jobs

Three jobs run in parallel on `ubuntu-latest`.

**`rust`** runs the five Rust gates in the order `AGENTS.md` section 4.5
mandates: format check, Clippy with warnings denied, workspace check, workspace
test, and documentation build. The toolchain comes from `rust-toolchain.toml`;
`Swatinem/rust-cache` absorbs the cold build cost.

`cargo clippy --fix` is intentionally absent. It mutates the working tree,
which is correct locally and wrong in continuous integration. The check-only
form is what `gates.sh` already runs, and it is what gates the branch.

**`frontend`** runs `npm ci`, `npm test`, `npm run build`, and `npm run lint`
in `crates/hf-gui`. It needs no Rust toolchain, so it is fully parallel with
the `rust` job and finishes well before it.

**`supply-chain`** installs `cargo-deny` through `taiki-e/install-action` and
runs `cargo deny check` against `deny.toml`. It requires no compilation and
completes in under a minute.

Job separation exists for failure attribution: a red badge should say whether
the break is Rust, frontend, or dependency policy without opening the log.

### 5.3 Preventing definition drift

Duplicating the gate list between the shell script and the workflow guarantees
the two diverge. Instead `scripts/tests/gates.sh` accepts optional gate names:

```bash
scripts/tests/gates.sh              # every gate, in mandated order (unchanged)
scripts/tests/gates.sh fmt clippy   # named subset, same definitions
```

Gate names are `fmt`, `clippy`, `check`, `test`, `doc`, `deny`,
`frontend-test`, and `frontend-lint`. Each becomes a shell function; the
no-argument path calls them in the existing order, preserving current local
behavior exactly. An unrecognized name exits non-zero with the valid list.

Continuous integration invokes named gates one step at a time, so GitHub
annotates each gate separately while the script remains authoritative about
what each gate means.

### 5.4 The `head -200` removal

Gate `test` drops the `| head -200` truncation. The `grep -v` noise filter
stays, since it is what makes local output readable. Continuous integration
captures full output because a truncated failure log is not actionable.

## 6. Container Decomposition

`crates/hf-service/src/container.rs` becomes `crates/hf-service/src/container/`
with `mod.rs` plus submodules. Rust resolves privacy by module ancestry: a
child module can reach its parent's private items. The `ServiceContainer`
fields therefore stay private with no `pub(crate)` widening, and no consumer
outside `hf-service` observes any change.

### 6.1 Extracted modules

These carry real boundaries and receive their own module-level tests. Each is a
unit that can be described without reference to `ServiceContainer`.

**`container/workspace.rs`** — the managed workspace boundary. Root resolution
and the `HF_WORKSPACE_DIR` override, the ownership manifest with its adoption
rules, the advisory lock file, cleanup-root validation, protected path
enumeration, `workspace_dir`, `project_workspace_dir`, `document_staging_dir`,
`run_output_relative`, and the symlink-refusing `resolve_workspace_directory`.
This is the `AGENTS.md` section 2.12 guarantee that untrusted input never
touches the host filesystem outside the workspace.

**`container/staging.rs`** — approval-to-execution integrity. `RunArtifacts`,
`ReplayProvenance`, `sha256_file`, `RunContextDigests`, `run_context_digests`,
`retain_run_context`, `resolve_run_sandbox_image`, `stage_run_artifacts`,
`verify_run_artifacts`, `qualification_evidence`,
`verify_staged_qualification`, `run_output_dir`, `run_binary_path`,
`run_source_path`, `run_sandbox_options`, `minimization_sandbox_options`, and
`quarantine_corpus_entry`. The invariant this module owns is that the artifact
a human approved is byte-identical to the artifact that executes.

**`container/output_budget.rs`** — run output accounting. `OutputBudget`,
`output_budget_status`, `monitor_run_output`, `run_artifacts_within_budget`,
and the `MAX_RUN_OUTPUT_BYTES` and `MAX_RUN_OUTPUT_ENTRIES` constants. This
module owns the three-state distinction between a genuine budget overflow and
a transient read race under a live fuzzer, a distinction whose absence
previously killed valid campaigns.

**`container/crash_inputs.rs`** — crash artifact collection.
`stage_crash_inputs`, `collect_crash_inputs`, `collect_legacy_crash_inputs`,
`collect_workspace_crash_inputs`, `collect_casreps`, `collect_casreps_into`,
`casrep_input_path`, `deterministic_crash_id`, and `bucket_by_cluster`, along
with the existing colocated test module.

**`container/harness_workspace.rs`** — on-disk harness state.
`read_current_harness_source`, `read_current_harness_id`,
`write_current_harness_source`, `write_current_harness_id`,
`write_current_harness_binary`, `harness_binary_name`, `target_artifact_stem`,
`sanitize_target`, `container_input_path`, `build_workspace_dictionary`,
`read_dictionary_source_excerpt`, `generate_target_seeds`,
`copy_project_sources`, `stage_rust_crate`, and `copy_dir_recursive`.

**`container/project_identity.rs`** — project and target resolution.
`canonical_project_root`, `stored_project_matches`, `project_lookup_identity`,
`select_target_candidate`, `project_slug`, and `defectdojo_project_name`.

**`container/coverage_cache.rs`** — coverage-derived caching and parsing.
`export_cache`, `frontier_refine_lines`, `coverage_signature`, and
`parse_covered_functions`.

**`container/guards.rs`** — the RAII types. `AgentTurnGuard`, `ActiveRunGuard`,
`PersistedRunGuard`, `ProviderHealthTask`, and `StagingDirectoryGuard`, with
their `Drop` implementations and the journal helpers `ensure_run_journal_durable`
and `close_run_journal`.

### 6.2 Relocated method groups

These are moves. Each file holds one `impl ServiceContainer` block; bodies are
byte-identical to their current form and colocated test modules travel with
them.

| Module | Methods |
| --- | --- |
| `container/lifecycle.rs` | `new`, `stubbed`, `with_store`, `with_store_path`, `with_guardrails`, `with_provider_pool`, `bootstrap`, `provider_pool`, `store`, `guardrails`, `diagnostics`, `checkpoint_manager`, `session_manager`, `session_turn_lock`, `reload_providers`, `track_agent`, `clear_workspace`, `delete_project`, `clear_knowledge` |
| `container/chat.rs` | `chat_send`, `chat_history`, `create_chat_session`, `delete_chat_session`, `chat_branch`, `chat_branches`, `chat_checkpoints`, `chat_create_checkpoint`, `chat_rollback_last`, `chat_rollback_to` |
| `container/discovery.rs` | `discover`, `rank`, `schedulable_targets` |
| `container/harness.rs` | `harness_draft`, `harness_compile`, `harness_generate`, `harness_refine`, `harness_smoke`, `harness_promote`, `harness_promote_with_findings`, `harness_review_queue`, `generate_seeds`, `generate_seeds_llm` |
| `container/run.rs` | `run_campaign`, `start_fuzzer`, `run_fuzzer`, `replay_run`, `run_syzkaller`, `run_control_status`, `request_run_cancel`, `cancel_run`, `cancel_all_runs`, `active_run_ids` |
| `container/triage.rs` | `triage`, `triage_run`, `verify_crash`, `verify_crashes`, `verify_harness_source`, `verify_regressions`, `coverage_functions`, `coverage_uncovered`, `coverage_summary` |
| `container/corpus.rs` | `corpus_list`, `corpus_seed`, `corpus_grow`, `corpus_prune`, `corpus_prune_coverage`, `corpus_absorb_crashes`, `corpus_absorb_crashes_for_run`, `corpus_minimize` |
| `container/history.rs` | `run_history`, `run_coverage_series`, `run_harness_source`, `delete_run`, `clear_all_runs`, `interrupted_runs`, `dismiss_interrupted_run`, `artifact_summary`, `all_crashes`, `delete_crash`, `all_corpus_entries`, `delete_corpus_entry`, `clear_all_artifacts`, `export_project_data` |
| `container/policy.rs` | `policy_decisions`, `auto_revert_events`, `project_auto_revert_override`, `project_auto_revert_overrides`, `effective_auto_revert_view`, `set_project_auto_revert_override`, `clear_project_auto_revert_override`, `revert_harness_from_run`, `approve_agent_tool` |
| `container/export.rs` | `export_repro_bundle`, `export_repro_bundle_for_latest`, `export_sarif`, `generate_report`, `report_formats`, `export_report`, `export_markdown`, `list_report_drafts`, `save_report_draft`, `delete_report_draft`, `issue_export`, `issue_tracker_configured`, `issue_tracker_test_connection`, `file_issue`, `defectdojo_configured`, `defectdojo_url`, `defectdojo_test_connection`, `push_to_defectdojo` |
| `container/system.rs` | `system_snapshot`, `provider_statuses`, `thaw_provider`, `cost_summary`, `workbench_dashboard`, `ingest_document` |

`mod.rs` retains the `ServiceContainer` struct, its remaining private helpers
(`build_cost_map`, `build_session_managers`, `spawn_provider_health_checks`,
`bounded_guardrail_detail`, `chat_storage_error`, `fuzzing_policy_error`,
`require_fuzzing_harness_engine`, `resolve_fuzzing_run`, `resolve_internal_run`,
`run_has_crash_evidence`), the shared constants, and `pub use` re-exports so
every path currently importable from `hf_service::container` still resolves.

Target: no resulting file exceeds roughly 1500 lines.

### 6.3 Ordering

1. Create the directory module with `mod.rs` holding the entire current file
   contents, verifying the suite is green.
2. Extract one module from section 6.1 per commit, suite green after each.
3. Relocate one method group from section 6.2 per commit, suite green after
   each.
4. Add module-level tests only where extraction exposed an untested boundary.

Each step is independently revertible.

## 7. Policy Audit Desktop Surface

`crates/hf-gui/src-tauri/src/commands.rs` gains a `policy_decisions` command
taking a bounded limit and delegating to `ServiceContainer::policy_decisions`.
It mirrors the existing `auto_revert_events` command and the REST
`/policy/decisions` route; no service logic is added.

`crates/hf-gui/src/views/AuditView.tsx` renders persisted guardrail decisions
alongside auto-revert events. Each row shows the decision timestamp, action
kind, risk tier, decision outcome, originating service entry point, project
where present, and bounded policy detail where present — the full
`GuardrailDecisionRecord` shape. `crates/hf-gui/src/lib/httpTransport.ts` gains
the matching route so browser mode reaches the same data.

Retention is unchanged: the service prunes beyond `GUARDRAIL_DECISION_RETENTION`
on write, and the view requests a bounded limit.

## 8. Failure Semantics

Nothing in this increment changes runtime failure behavior.

The decomposition preserves every `ClassifiedError` construction and
propagation path exactly. No error is reclassified, wrapped, or newly
introduced. The verification in section 10 exists specifically to demonstrate
this.

The Tauri command surfaces service errors the same way its sibling commands do.
A storage read failure reaches the operator as a rendered error, not as an
empty list, consistent with the existing rule that authoritative reads
propagate typed failures rather than rendering as empty data.

Continuous integration failures are advisory to the developer and blocking to
the branch: a red gate does not alter repository state.

## 9. Security and Safety

The decomposition is the security-relevant part of this work. Extracting
`container/workspace.rs`, `container/staging.rs`, and
`container/output_budget.rs` turns three currently implicit guarantees into
named units with explicit tests:

- untrusted target and project names cannot escape the managed workspace root,
  including through symlinks or parent traversal;
- the source and binary digests recorded at human approval match the artifacts
  mounted read-only at execution;
- run output accounting distinguishes a real budget violation from a transient
  race, and fails closed on the former without killing a campaign on the
  latter.

No sandbox boundary changes. No harness build or fuzz invocation path is
touched. Guardrail evaluation is unchanged; only its already-persisted output
gains a desktop view.

Continuous integration runs on public infrastructure and therefore never
receives repository secrets. It builds and tests the workspace; it does not
build the sandbox image, pull fuzzing engines, execute a harness, or contact an
LLM provider. `cargo deny check` is the one gate that reaches the network, and
only for advisory data.

## 10. Testing Strategy

Test-driven development applies to new behavior. A relocation is not new
behavior, and writing tests to assert that moved code still exists would be
ceremony rather than verification.

**Relocations.** The existing 2534 tests are the safety net. The suite runs
after every move commit. A move commit contains no edits, so a reviewer can
confirm by inspection that the diff is a relocation.

**Extracted modules.** Colocated `#[cfg(test)]` blocks move with their code.
New focused tests are added where extraction exposes a boundary the current
suite reaches only indirectly. Two are expected:

- workspace manifest adoption, specifically that an explicit
  `HF_WORKSPACE_DIR` override without a manifest is never adopted while the
  implicit per-user default may adopt legacy artifacts;
- output budget classification, specifically that a vanishing directory entry
  yields the indeterminate state rather than a violation.

**`gates.sh`.** Failing test first. A shell test feeds the `test` gate more
than 200 lines of passing output and asserts exit status zero. It fails against
the current truncation with status 141, then passes once truncation is removed.
A second test asserts an unrecognized gate name exits non-zero, and a third
asserts the no-argument invocation still runs every gate in the mandated order.

**Policy audit surface.** Failing test first. A vitest case renders
`AuditView` against a mocked transport returning decision records and asserts
each field appears. It fails before the view change. The Tauri command follows
the existing command test pattern.

**Continuous integration.** Verified empirically: push a branch and confirm all
three jobs pass, then push a deliberate single-gate break and confirm that job
alone goes red while the others still report.

## 11. Success Criteria

1. `.github/workflows/ci.yml` runs all eight gates on push and pull request and
   passes on `main`.
2. A deliberately introduced Clippy warning, test failure, frontend lint error,
   and dependency policy violation each turn the corresponding job red.
3. `scripts/tests/gates.sh` with no arguments behaves exactly as before.
4. A passing test run producing more than 200 lines of filtered output exits
   zero.
5. No file under `crates/hf-service/src/container/` exceeds roughly 1500 lines.
6. `hf-cli`, `hf-web`, and `hf-gui/src-tauri` compile unchanged against the
   decomposed module tree.
7. Every `#[cfg(test)]` block colocated with extracted code moved with it, and
   the two boundaries named in section 10 gained new focused tests.
8. The desktop Policy Audit view shows persisted guardrail decisions with every
   `GuardrailDecisionRecord` field.
9. `TODO.md` contains no entry contradicted by the codebase.
10. The full gate sequence passes in the order `AGENTS.md` section 4.5
    mandates.

## 12. Rejected Alternatives

**Cross-platform test matrix.** Running tests on macOS and Windows would catch
path and platform assumptions, but the codebase is Unix-path oriented and
likely does not pass on Windows today. Adopting it now converts a one-session
task into an open-ended porting effort. `release.yml` already proves the four
platform bundles build on tag, which is the property that actually ships.

**Feature-flag matrix.** Building under `--all-features` and
`--no-default-features` would catch feature-gate rot across
`automotive-scapy`, `proof-carrying`, and `semgrep-enrichment`. It roughly
triples compute for a failure mode that has not yet occurred. Revisit if a
feature-gated build breaks in practice.

**Minimal fast gate.** Dropping `cargo deny`, `cargo doc`, and the frontend
gates would cut runtime, but supply-chain and desktop regressions are precisely
what a public repository needs caught, and the full suite costs 69 seconds.

**Continuous integration invoking `gates.sh` as one step.** Simplest and
drift-free, but a single opaque step gives no per-gate annotation and
serializes work that parallelizes cleanly. The gate-argument refactor achieves
the same single-source-of-truth property without that cost.

**Full sub-service extraction.** Extracting `HarnessService`, `RunService`,
`TriageService`, `CorpusService`, and `ChatService` now would create real
boundaries immediately. The boundaries would be guesses: the agent protocol
project and the Go and Python language project both add service surface, and
either could invalidate a seam chosen today. Deferring costs one additional
refactor later and buys evidence for where the cuts belong.

**Leaving the free functions in place.** A purely mechanical file split would
land faster. It would also leave workspace boundary enforcement, digest
verification, and output budget accounting as anonymous helpers above a god
object, which is the part of the file that most deserves a name and a test.
