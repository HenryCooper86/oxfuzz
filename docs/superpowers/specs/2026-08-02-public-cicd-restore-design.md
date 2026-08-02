# Public CI/CD Restoration and Open-Source Readiness Design

Status: **proposed**. Owner: repository tooling.

Follow-on to `2026-07-31-code-health-and-ci-design.md`, which authored
`scripts/tests/gates.sh` and the workflows that commit `3f63df2`
("chore: remove unused CI/CD workflows") later deleted. This design restores
that automation for the public GitHub repository and adds the open-source
hygiene a public repo is judged by on first visit.

## 1. Goal

Put an automated, always-green quality gate in front of every change on the
public repository, restore the tag-driven desktop release pipeline, and add the
open-source-readiness files (badges, dependency automation, contribution
templates) that external engineers expect. Re-enable the GitLab mirror against
an OrbStack Docker-container runner so the current `origin` is gated too.

This is the CI/CD increment of the broader "make oxfuzz production-ready as a
public open-source project" effort. Out of scope here (tracked separately): the
pre-publish git-history rewrite, the GPL sidecar-image distribution decision,
deferred-subsystem completion, and README restructuring.

## 2. Context and why this is recovery, not greenfield

Full CI existed and worked. Commit `3f63df2` removed `.github/workflows/ci.yml`,
`.github/workflows/release.yml`, `.github/workflows/fuzz.yml.example`,
`.gitlab-ci.yml`, and `scripts/ci/install-linux-deps.sh`. The commit chain
(`ci: disable CI pipelines (no runners available)`, `ci: remove GitLab CI
pipeline (no runners available)`) shows the reason was operational — the
internal OrbStack GitLab had no registered runner — not a defect in the
pipelines. The `2026-07-31` design records that the full gate suite runs in
~69 s warm with 2534 tests passing, and that GitHub-hosted runners are free for
public repositories. The suite is therefore already CI-clean: default
`cargo test --workspace` needs no Docker or engine binaries (one `#[ignore]`
test in `hf-service/src/system.rs` is the only intentional skip).

The recovered files are the design baseline. This increment restores them,
modernizes pinned action versions, resolves the "no runner" blocker for GitLab
via OrbStack, and adds the open-source hygiene files.

Repository identities (confirmed): public GitHub is `HenryCooper86/oxfuzz`
(`Cargo.toml` `repository` plus seven code/doc references); the current `origin`
is the internal `git@gitlab-ce.orb.local:hobot/oxfuzz.git`.

## 3. Approved product decisions

1. **Both hosts are gated.** `.github/workflows/ci.yml` gates the public
   repository; `.gitlab-ci.yml` gates the current `origin`. Both invoke named
   gates from `scripts/tests/gates.sh`, so the duplication is a job list, not a
   command list — the two cannot drift from the single gate definition.
2. **The GitLab runner is an OrbStack Docker container.** The "no runners"
   blocker is resolved by registering a `gitlab-runner` container in OrbStack
   using the Docker executor. This design ships a documented, idempotent
   registration helper; the pipeline's `image:`-based Docker-executor shape
   already fits.
3. **CI is Linux-only; cross-platform coverage stays with `release.yml`.** The
   workspace is platform-agnostic; the property that actually ships (the four
   desktop bundles) is what earns per-OS runners, and only on tag.
4. **All gates run in CI; none are dropped for speed.** The ten gates in
   `scripts/tests/gates.sh` (`fmt`, `clippy`, `check`, `check-no-default-features`,
   `test`, `doc`, `deny`, `script-tests`, `frontend-test`, `frontend-lint`) all
   run.
5. **`scripts/tests/gates.sh` stays the single definition of a gate.** CI
   invokes it by name and never re-lists commands.
6. **Action versions are verified at implementation, not trusted from history.**
   Every `uses:` is pinned to the current major after checking the action's
   releases, so the restore does not reintroduce a stale or yanked action.
7. **Open-source hygiene ships with the workflows:** README status/license
   badges, Dependabot, GitHub issue + PR templates, and the opt-in fuzz gate.
8. **Documentation reverts follow the code.** Commit `3f63df2` also edited
   `CONTRIBUTING.md`, `README.md`, `docs/guides/RELEASE_CHECKLIST.md`, and
   `docs/standards/TEST_STRATEGY.md` to remove CI references. Those claims
   ("No automated runner is provisioned") become false again and are corrected.

## 4. Components

### 4.1 `.github/workflows/ci.yml` (restore + modernize)

Triggers on `push` and `pull_request`; `concurrency` group per ref with
`cancel-in-progress`; `permissions: contents: read`. Three independent jobs on
`ubuntu-latest`:

- **Rust gates.** `actions/checkout`; `scripts/ci/install-linux-deps.sh` (the
  `hf-gui/src-tauri` workspace member needs WebKitGTK on Linux); run
  `script-tests` first to fail fast without a toolchain; `rustup show
  active-toolchain` to provision the `rust-toolchain.toml`-pinned 1.94.0 (no
  toolchain-installing action, which would silently override the pin);
  `Swatinem/rust-cache`; then `fmt`, `clippy`, `check`,
  `check-no-default-features`, `test`, `doc` — each `scripts/tests/gates.sh <gate>`.
- **Frontend gates.** `actions/setup-node` (Node 22, npm cache keyed on
  `crates/hf-gui/package-lock.json`); `frontend-test` (ci + vitest + build) then
  `frontend-lint`.
- **Supply chain.** `taiki-e/install-action` for `cargo-deny`; `deny` gate.

Modernization: confirm current majors for `actions/checkout`,
`actions/setup-node`, `Swatinem/rust-cache`, `taiki-e/install-action`; keep
job/step structure identical.

### 4.2 `.github/workflows/release.yml` (restore + modernize)

Triggers on `push` tags `v*` and `workflow_dispatch`; `permissions: contents:
write`. Three phases so an incomplete release is never public:
`create-release` (one draft, id as output) -> `bundle` (matrix: macOS
aarch64/x64, `ubuntu-22.04`, `windows-latest`; `fail-fast: false`; each uploads
into the shared draft via `tauri-apps/tauri-action`) -> `publish-release`
(flips the draft public only after the whole matrix succeeds). `ubuntu-22.04` is
pinned deliberately to set the glibc floor for `.deb`/`.AppImage`. No Rust
toolchain action (honor the pin); `rustup target add` per matrix target.

Modernization: confirm current majors for `tauri-apps/tauri-action`,
`actions/github-script`, and the setup actions; the unsigned-build release notes
and platform table are retained.

### 4.3 `.github/workflows/fuzz.yml.example` (restore, stays opt-in)

Copy-to-enable per-repo fuzz-on-PR gate: builds `oxfuzz` + the sandbox image,
drafts/compiles a harness, fuzzes a short budget, triages, uploads SARIF to code
scanning, and fails on any crash. Remains a `.example` (needs Docker on the
runner + `HF_PROVIDER_API_KEY`); `permissions: security-events: write`. Modernize
the toolchain/checkout/codeql-upload action pins.

### 4.4 `scripts/ci/install-linux-deps.sh` (restore verbatim)

`sudo`-aware `apt-get` install of the WebKitGTK/Tauri Linux build dependencies.
Restored unchanged; `release.yml`'s Linux bundle job installs the same list —
they must stay in step.

### 4.5 `.gitlab-ci.yml` + OrbStack runner (restore + unblock)

Restore the four Docker-executor jobs (`rust` on `rust:1.94`, `frontend` on
`node:22`, `script-tests` on `python:3.12-slim`, `supply-chain` on `rust:1.94`),
each invoking named gates, with `CARGO_HOME`/npm caches keyed on lockfiles.

New: `scripts/ci/register-gitlab-runner.sh` — an idempotent helper that runs a
`gitlab-runner` Docker container in OrbStack and registers it against the
project with the Docker executor (default image `rust:1.94`, `--docker-privileged`
off, host Docker socket mounted only if a job needs it — the gate jobs do not).
The helper takes the registration token via env/arg (never committed) and a
`docs/guides/CI.md` section documents obtaining the token and verifying the
runner appears in the project's CI settings. The helper is invoked by the user
(needs their token + GitLab access); this design does not execute it.

### 4.6 Open-source hygiene files

- **README badges.** A badge row under the title: GitHub Actions CI status
  (`HenryCooper86/oxfuzz` `ci.yml`) and MIT license. Added to both the English
  and Chinese header regions so the bilingual README stays symmetric.
- **`.github/dependabot.yml`.** Weekly update PRs for three ecosystems:
  `cargo` (root workspace), `npm` (`crates/hf-gui`), and `github-actions`
  (`/`). Grouped minor/patch updates to limit PR noise; open-PR limit set.
- **`.github/ISSUE_TEMPLATE/`.** `bug_report.md` and `feature_request.md` plus
  `config.yml` routing security reports to `SECURITY.md` (not public issues).
- **`.github/PULL_REQUEST_TEMPLATE.md`.** GitHub twin of
  `.gitlab/merge_request_templates/Default.md`, keeping the same architecture,
  safety, verification, and documentation checklist aligned to `AGENTS.md`.

### 4.7 Documentation reverts

Restore the CI-referencing text that `3f63df2` stripped from `CONTRIBUTING.md`
("No automated runner is provisioned" -> the gate set now runs in CI on every
push/PR, with the local script as the pre-push mirror),
`docs/guides/RELEASE_CHECKLIST.md`, `docs/standards/TEST_STRATEGY.md`, and the
README CI reference — describing the *current* two-host arrangement, not the
pre-removal one.

## 5. Data flow

```
developer push / PR
      |
      +--> GitHub Actions (public repo, ubuntu-latest)
      |        ci.yml -> scripts/tests/gates.sh <gate> (10 gates, 3 jobs)
      |        status -> README badge, PR check
      |
      +--> GitLab CI (origin, OrbStack Docker runner)
               .gitlab-ci.yml -> scripts/tests/gates.sh <gate> (same gates)

git tag v* --> release.yml --> draft -> per-OS Tauri bundles -> publish
```

`scripts/tests/gates.sh` is the one authority both CI hosts and local runs call;
neither workflow re-lists a command.

## 6. Testing and verification

- The gate suite verifies itself: a green `ci.yml` is proof the gates pass on a
  clean runner. Before declaring done, run `scripts/tests/gates.sh` locally
  end-to-end (all ten gates) and record the result — the workflows must not be
  the first place the suite runs.
- **YAML validity.** Lint each workflow (`actionlint` if available, else a YAML
  parse) so a malformed workflow is caught before push.
- **Action-version check.** For every `uses:`, confirm the pinned major is the
  current released major before commit.
- **Dependabot config validity.** Validate `dependabot.yml` against the schema
  (parseable, all three ecosystems present with valid directories).
- **No secret is required by `ci.yml`.** Confirm the workflow references no
  secret (only the opt-in `fuzz.yml.example` needs `HF_PROVIDER_API_KEY`).
- **GitLab runner.** Out-of-band: after the user registers the OrbStack runner
  and pushes, confirm the pipeline picks up a runner and goes green. Not gated
  by this design's local verification.

## 7. Risks and mitigations

- **Restored actions may have moved major versions since removal.** Mitigation:
  decision 6 — verify every pin at implementation.
- **The GitLab pipeline is inert until a runner is registered.** Mitigation: the
  registration helper + `docs/guides/CI.md` make the runner setup explicit and
  repeatable; until then only GitHub Actions gates, which is acceptable.
- **`release.yml` publishes to whatever repo it runs in.** It uses only the
  automatic `GITHUB_TOKEN` and no signing secrets; unsigned-build guidance is in
  the release notes. No behavior change from the recovered version.
- **Bilingual README badge drift.** Mitigation: add the badge row to both header
  regions in the same change and note the pairing in the contributing docs'
  screenshot/README guidance.

## 8. Out of scope (tracked elsewhere)

Git-history rewrite for the leaked internal author field; GPL Scapy
sidecar-image distribution decision; independent `gitleaks` confirmation;
deferred-subsystem completion (`hf-context` working memory, `hf-scheduler`
triggers, `hf-skills`, sub-agent pools); expanded crash/triage and end-to-end
test coverage; README restructuring. Each is its own increment in the
production-readiness effort.
